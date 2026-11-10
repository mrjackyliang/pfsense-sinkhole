<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use InvalidArgumentException;
use JsonException;
use PfSense\Sinkhole\Domain\IpNetwork;
use PfSense\Sinkhole\Domain\ScopeConfiguration;
use RuntimeException;
use Throwable;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/ClientSource.php');
require_once(__DIR__ . '/FileLock.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/IpNetwork.php');
require_once(__DIR__ . '/PackagePaths.php');
require_once(__DIR__ . '/ScopeConfiguration.php');
require_once(__DIR__ . '/StateStore.php');

/**
 * Client Map.
 *
 * Builds deterministic network and device address assignments from local pfSense
 * state and publishes them independently from compiled block-list generations.
 *
 * @since 1.0.0
 */
final class ClientMap
{
    /**
     * Client Map - Schema Version.
     *
     * @since 1.0.0
     */
    public const SCHEMA_VERSION = 2;

    /**
     * Client Map - Maximum Bytes.
     *
     * Bounds both PHP status reads and Unbound's watched document.
     *
     * @since 1.0.0
     */
    public const MAXIMUM_BYTES = 4_194_304;

    /**
     * Client Map - Constructor.
     *
     * The source is intentionally separate from compiler locking and downloads.
     *
     * @param PackagePaths $paths - Paths.
     * @param ClientSource $source - Source.
     * @param StateStore $stateStore - State store.
     *
     * @since 1.0.0
     */
    public function __construct(
        private readonly PackagePaths $paths,
        private readonly ClientSource $source,
        private readonly StateStore $stateStore,
    ) {
    }

    /**
     * Client Map - Refresh.
     *
     * A concurrent refresh returns immediately; failures keep the last good file and
     * are recorded for the Status page.
     *
     * @return array{status: string, networks?: int, devices?: int, conflicts?: int, error?: string}
     *
     * @since 1.0.0
     */
    public function refresh(): array
    {
        $lock = new FileLock($this->paths->clientLockFile);

        if ($lock->acquire(0) === false) {
            return ['status' => 'skipped'];
        }

        try {
            $map = $this->build(
                $this->source->getNetworks(),
                $this->source->getDevices(),
                $this->source->getInterfaceSubnets(),
                $this->source->getStaticMappings(),
                $this->source->getArpEntries(),
                $this->source->getNdpOutput(),
                $this->source->getDhcpLeases(),
                $this->source->getDhcpLeaseContext(),
                $this->source->getBypassInterfaces(),
                $this->source->getInterfaceAddresses(),
            );
            $refreshedAt = gmdate('c');
            $existing = $this->readExistingMap($this->paths->runtimeClientMapFile);
            $changed = !is_array($existing)
                || ($existing['content_digest'] ?? null) !== $map['content_digest'];

            if ($changed) {
                $map['generated_at'] = $refreshedAt;
                $contents = $this->encode($map, true);

                if (strlen($contents) > self::MAXIMUM_BYTES) {
                    throw new RuntimeException('The Sinkhole client map exceeds its size limit.');
                }

                $this->writeMap($this->paths->runtimeClientDirectory, $contents);
            } else {
                $map['generated_at'] = (string) $existing['generated_at'];
                $contents = $this->encode($map, true);
            }

            if ($this->source->usesMemoryFileSystem()) {
                $mirror = $this->readExistingMap($this->paths->mirrorClientMapFile);

                if (
                    !is_array($mirror)
                    || ($mirror['content_digest'] ?? null) !== $map['content_digest']
                ) {
                    $this->writeMap($this->paths->mirrorClientDirectory, $contents);
                }
            }

            $previousConflictsDigest = $this->stateStore->clientMapStatus()['conflicts_digest'];
            $conflictsDigest = hash('sha256', $this->encode($map['conflicts'], false));
            $conflictsChanged = $this->stateStore->recordClientMapSuccess(
                $refreshedAt,
                (string) $map['generated_at'],
                $conflictsDigest,
            );

            if ($conflictsChanged && count($map['conflicts']) > 0) {
                $this->source->log(sprintf(
                    'Sinkhole client map has %d address conflict(s); the first device wins.',
                    count($map['conflicts']),
                ));
            } elseif ($conflictsChanged && $previousConflictsDigest !== null) {
                $this->source->log('Sinkhole client map address conflicts were cleared.');
            }

            return [
                'status' => $changed ? 'updated' : 'unchanged',
                'networks' => count($map['networks']),
                'interfaces' => count($map['interfaces']),
                'devices' => count((array) $map['devices']),
                'conflicts' => count($map['conflicts']),
            ];
        } catch (Throwable $exception) {
            $message = 'Sinkhole client map refresh failed: ' . $exception->getMessage();
            $previousError = null;

            try {
                $previousError = $this->stateStore->clientMapStatus()['error'];
                $this->stateStore->recordClientMapError($message);
            } catch (Throwable) {
                // The original refresh error remains the useful diagnostic.
            }

            if ($previousError !== $message) {
                $this->source->log($message);
            }

            return ['status' => 'error', 'error' => $message];
        } finally {
            $lock->release();
        }
    }

    /**
     * Client Map - Build.
     *
     * Converts fixture-friendly local source arrays into the exact runtime schema.
     *
     * @param array<string, array> $networks - Enabled normalized networks.
     * @param array<string, array> $devices - Enabled normalized devices in precedence order.
     * @param array<string, list<string>> $interfaceSubnets - CIDRs by interface.
     * @param list<array> $staticMappings - DHCP static mappings.
     * @param list<array> $arpEntries - ARP helper rows.
     * @param string $ndpOutput - Fixed-command NDP output.
     * @param array $leases - DHCP lease helper result.
     * @param array{times_local: bool, active: string, expired: string, reserved: string, never: string} $leaseContext - pfSense lease timestamp and label context.
     * @param list<string> $bypassInterfaces - Shared Bypass interface selection.
     * @param array<string, list<string>> $interfaceAddresses - Firewall addresses by interface.
     *
     * @return array{schema_version: int, generated_at: string, content_digest: string, networks: list<array{id: string, cidrs: list<string>}>, interfaces: list<array{name: string, cidrs: list<string>}>, devices: array<string, string>, conflicts: list<array{address: string, winner: string, devices: list<string>}>}
     *
     * @since 1.0.0
     */
    public function build(
        array $networks,
        array $devices,
        array $interfaceSubnets,
        array $staticMappings,
        array $arpEntries,
        string $ndpOutput,
        array $leases,
        array $leaseContext,
        array $bypassInterfaces = [],
        array $interfaceAddresses = [],
    ): array {
        $networkRows = [];

        foreach ($networks as $network) {
            if (!is_array($network) || ($network['enabled'] ?? false) !== true) {
                continue;
            }

            $identifier = (string) ($network['id'] ?? '');
            $interface = (string) ($network['interface'] ?? '');

            if (preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1) {
                continue;
            }

            $cidrs = [];

            foreach ($interfaceSubnets[$interface] ?? [] as $cidr) {
                if (is_string($cidr) && self::validCidr($cidr)) {
                    $cidrs[$cidr] = true;
                }
            }

            $normalizedCidrs = array_keys($cidrs);
            sort($normalizedCidrs, SORT_STRING);
            $networkRows[] = ['id' => $identifier, 'cidrs' => $normalizedCidrs];
        }

        $interfaceRows = [];
        $uniqueInterfaces = [];
        $protectedInterfaceAddresses = [];

        foreach ($interfaceAddresses as $addresses) {
            if (!is_array($addresses)) {
                continue;
            }

            foreach ($addresses as $address) {
                if (
                    is_string($address)
                    && filter_var($address, FILTER_VALIDATE_IP) !== false
                ) {
                    $protectedInterfaceAddresses[] = $address;
                }
            }
        }

        foreach ($bypassInterfaces as $interface) {
            if (!is_string($interface) || $interface === '') {
                continue;
            }

            $uniqueInterfaces[$interface] = true;
        }

        $interfaceNames = array_keys($uniqueInterfaces);
        sort($interfaceNames, SORT_STRING);

        foreach ($interfaceNames as $interface) {
            $cidrs = [];

            foreach ($interfaceSubnets[$interface] ?? [] as $cidr) {
                if (is_string($cidr) && self::validCidr($cidr)) {
                    $cidrs[$cidr] = true;
                }
            }

            $normalizedCidrs = IpNetwork::subtract(
                array_keys($cidrs),
                $protectedInterfaceAddresses,
            );
            sort($normalizedCidrs, SORT_STRING);
            $interfaceRows[] = ['name' => $interface, 'cidrs' => $normalizedCidrs];
        }

        $observed = self::observedAddresses(
            $arpEntries,
            self::parseNdpOutput($ndpOutput),
            $leases,
            $leaseContext,
        );
        $mappingAddresses = self::mappingAddresses($staticMappings);
        $addressOwners = [];
        $conflictOwners = [];

        foreach ($devices as $device) {
            if (!is_array($device) || ($device['enabled'] ?? false) !== true) {
                continue;
            }

            $deviceIdentifier = (string) ($device['id'] ?? '');

            if (preg_match('/^[a-f0-9]{32}$/D', $deviceIdentifier) !== 1) {
                continue;
            }

            $addresses = [];
            $type = (string) ($device['identifier_type'] ?? '');
            $identifier = (string) ($device['identifier'] ?? '');

            try {
                if ($type === ScopeConfiguration::DEVICE_IP) {
                    $addresses[ScopeConfiguration::normalizeIpAddress($identifier)] = true;
                } elseif (
                    $type === ScopeConfiguration::DEVICE_MAC
                    || $type === ScopeConfiguration::DEVICE_STATIC_MAPPING
                ) {
                    $mac = ScopeConfiguration::normalizeMacAddress($identifier);

                    foreach ($observed[$mac] ?? [] as $address) {
                        $addresses[$address] = true;
                    }

                    if ($type === ScopeConfiguration::DEVICE_STATIC_MAPPING) {
                        $mappingKey = (string) ($device['interface'] ?? '') . ':' . $mac;

                        foreach ($mappingAddresses[$mappingKey] ?? [] as $address) {
                            $addresses[$address] = true;
                        }
                    }
                }
            } catch (InvalidArgumentException) {
                continue;
            }

            $sortedAddresses = array_keys($addresses);
            sort($sortedAddresses, SORT_STRING);

            foreach ($sortedAddresses as $address) {
                if (!isset($addressOwners[$address])) {
                    $addressOwners[$address] = $deviceIdentifier;

                    continue;
                }

                if ($addressOwners[$address] === $deviceIdentifier) {
                    continue;
                }

                $conflictOwners[$address][$addressOwners[$address]] = true;
                $conflictOwners[$address][$deviceIdentifier] = true;
            }
        }

        ksort($addressOwners, SORT_STRING);
        ksort($conflictOwners, SORT_STRING);
        $conflicts = [];

        foreach ($conflictOwners as $address => $owners) {
            $winner = $addressOwners[$address];
            $otherOwners = array_values(array_diff(array_keys($owners), [$winner]));
            $conflicts[] = [
                'address' => $address,
                'winner' => $winner,
                'devices' => array_merge([$winner], $otherOwners),
            ];
        }

        $deviceMap = ($addressOwners === []) ? (object) [] : $addressOwners;
        $semantic = [
            'networks' => $networkRows,
            'interfaces' => $interfaceRows,
            'devices' => $deviceMap,
            'conflicts' => $conflicts,
        ];

        return [
            'schema_version' => self::SCHEMA_VERSION,
            'generated_at' => '',
            'content_digest' => hash('sha256', $this->encode($semantic, false)),
            'networks' => $networkRows,
            'interfaces' => $interfaceRows,
            'devices' => $deviceMap,
            'conflicts' => $conflicts,
        ];
    }

    /**
     * Client Map - Parse NDP Output.
     *
     * Accepts only rows emitted by the fixed ``ndp -na`` column layout and drops
     * incomplete neighbors.
     *
     * @param string $output - Command output.
     *
     * @return list<array{ip: string, mac: string, interface: string}>
     *
     * @since 1.0.0
     */
    public static function parseNdpOutput(string $output): array
    {
        $entries = [];
        $lines = preg_split('/\R/', $output);

        foreach (is_array($lines) ? $lines : [] as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with(strtolower($line), 'neighbor')) {
                continue;
            }

            $fields = preg_split('/\s+/', $line);

            if (!is_array($fields) || count($fields) < 5 || count($fields) > 6) {
                continue;
            }

            [$address, $mac, $interface, $expiry, $state] = array_slice($fields, 0, 5);
            $flags = $fields[5] ?? '';

            if (
                $mac === '(incomplete)'
                || preg_match('/^[a-z0-9_.:-]+$/Di', $interface) !== 1
                || preg_match('/^(?:permanent|[0-9]+[smhd](?:[0-9]+[smhd])*)$/Di', $expiry) !== 1
                || preg_match('/^[a-z?]+$/Di', $state) !== 1
                || preg_match('/^[a-z0-9,]*$/Di', $flags) !== 1
            ) {
                continue;
            }

            $zonePosition = strpos($address, '%');

            if ($zonePosition !== false) {
                if (substr($address, $zonePosition + 1) !== $interface) {
                    continue;
                }

                $address = substr($address, 0, $zonePosition);
            }

            try {
                $normalizedAddress = ScopeConfiguration::normalizeIpAddress($address);
                $normalizedMac = ScopeConfiguration::normalizeMacAddress($mac);
            } catch (InvalidArgumentException) {
                continue;
            }

            if (!str_contains($normalizedAddress, ':')) {
                continue;
            }

            $entries[] = [
                'ip' => $normalizedAddress,
                'mac' => $normalizedMac,
                'interface' => $interface,
            ];
        }

        return $entries;
    }

    /**
     * Client Map - Observed Addresses.
     *
     * Combines complete ARP/NDP neighbors with unexpired DHCP leases by lowercase
     * MAC address.
     *
     * @param list<array> $arpEntries - ARP entries.
     * @param list<array> $ndpEntries - NDP entries.
     * @param array $leases - DHCP leases.
     * @param array{times_local: bool, active: string, expired: string, reserved: string, never: string} $leaseContext - pfSense lease timestamp and label context.
     *
     * @return array<string, list<string>>
     *
     * @since 1.0.0
     * @private
     */
    private static function observedAddresses(
        array $arpEntries,
        array $ndpEntries,
        array $leases,
        array $leaseContext,
    ): array {
        $observed = [];

        foreach ($arpEntries as $entry) {
            if (!is_array($entry) || self::flagEnabled($entry['incomplete'] ?? false)) {
                continue;
            }

            self::addObservation(
                $observed,
                $entry['mac-address'] ?? $entry['mac'] ?? null,
                $entry['ip-address'] ?? $entry['ip'] ?? null,
            );
        }

        foreach ($ndpEntries as $entry) {
            self::addObservation($observed, $entry['mac'] ?? null, $entry['ip'] ?? null);
        }

        $leaseRows = is_array($leases['lease'] ?? null) ? $leases['lease'] : $leases;

        foreach ($leaseRows as $lease) {
            if (!is_array($lease) || !self::leaseIsActive($lease, $leaseContext)) {
                continue;
            }

            self::addObservation(
                $observed,
                $lease['mac'] ?? $lease['hwaddr'] ?? null,
                $lease['ip'] ?? $lease['ip-address'] ?? null,
            );
        }

        foreach ($observed as &$addresses) {
            $addresses = array_keys($addresses);
            sort($addresses, SORT_STRING);
        }
        unset($addresses);

        return $observed;
    }

    /**
     * Client Map - Add Observation.
     *
     * Invalid source fields are discarded instead of entering the runtime map.
     *
     * @param array $observed - Mutable observations.
     * @param mixed $mac - Raw MAC address.
     * @param mixed $address - Raw IP address.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private static function addObservation(array &$observed, mixed $mac, mixed $address): void
    {
        if (!is_string($mac) || !is_string($address)) {
            return;
        }

        try {
            $mac = ScopeConfiguration::normalizeMacAddress($mac);
            $address = ScopeConfiguration::normalizeIpAddress($address);
        } catch (InvalidArgumentException) {
            return;
        }

        $observed[$mac][$address] = true;
    }

    /**
     * Client Map - Mapping Addresses.
     *
     * Indexes configured static addresses by stable interface-plus-MAC identity.
     *
     * @param list<array> $mappings - Static mappings.
     *
     * @return array<string, list<string>>
     *
     * @since 1.0.0
     * @private
     */
    private static function mappingAddresses(array $mappings): array
    {
        $addresses = [];

        foreach ($mappings as $mapping) {
            if (!is_array($mapping)) {
                continue;
            }

            try {
                $mac = ScopeConfiguration::normalizeMacAddress((string) ($mapping['mac'] ?? ''));
                $address = ScopeConfiguration::normalizeIpAddress((string) ($mapping['ipaddr'] ?? ''));
            } catch (InvalidArgumentException) {
                continue;
            }

            $interface = (string) ($mapping['interface'] ?? '');

            if ($interface === '') {
                continue;
            }

            $addresses[$interface . ':' . $mac][$address] = true;
        }

        foreach ($addresses as &$mappingAddresses) {
            $mappingAddresses = array_keys($mappingAddresses);
        }
        unset($mappingAddresses);

        return $addresses;
    }

    /**
     * Client Map - Lease Is Active.
     *
     * Uses the lease end time when available and rejects known inactive states.
     *
     * @param array $lease - Lease row.
     * @param array{times_local: bool, active: string, expired: string, reserved: string, never: string} $context - pfSense lease timestamp and label context.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function leaseIsActive(array $lease, array $context): bool
    {
        $state = trim((string) ($lease['act'] ?? $lease['state'] ?? ''));

        if ($state === $context['expired'] || $state === $context['reserved']) {
            return false;
        }

        if ($state !== $context['active']) {
            return false;
        }

        $ends = $lease['ends'] ?? $lease['expire'] ?? null;

        if (is_int($ends) || (is_string($ends) && ctype_digit($ends))) {
            return (int) $ends > time();
        }

        if (is_string($ends) && trim($ends) !== '') {
            $ends = trim($ends);

            if ($ends === $context['never']) {
                return true;
            }

            $timestamp = strtotime($ends . ($context['times_local'] ? '' : ' GMT'));

            return $timestamp !== false && $timestamp > time();
        }

        return true;
    }

    /**
     * Client Map - Flag Enabled.
     *
     * Interprets libxo boolean flag representations conservatively.
     *
     * @param mixed $value - Flag value.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function flagEnabled(mixed $value): bool
    {
        return $value === true || $value === 1 || $value === '1' || $value === 'true';
    }

    /**
     * Client Map - Validate CIDR.
     *
     * Ensures a canonical address and family-appropriate prefix are present.
     *
     * @param string $cidr - Network CIDR.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function validCidr(string $cidr): bool
    {
        $parts = explode('/', $cidr);

        if (count($parts) !== 2 || !ctype_digit($parts[1])) {
            return false;
        }

        try {
            $address = ScopeConfiguration::normalizeIpAddress($parts[0]);
        } catch (InvalidArgumentException) {
            return false;
        }

        $maximum = str_contains($address, ':') ? 128 : 32;

        return (int) $parts[1] <= $maximum;
    }

    /**
     * Client Map - Read Existing Map.
     *
     * Reads only regular bounded files when deciding whether content changed.
     *
     * @param string $path - Map path.
     *
     * @return array|null
     *
     * @since 1.0.0
     * @private
     */
    private function readExistingMap(string $path): ?array
    {
        $status = @lstat($path);

        if (
            !is_array($status)
            || ($status['mode'] & 0170000) !== 0100000
            || $status['size'] > self::MAXIMUM_BYTES
        ) {
            return null;
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            return null;
        }

        try {
            $map = json_decode($contents, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (
            !is_array($map)
            || ($map['schema_version'] ?? null) !== self::SCHEMA_VERSION
            || !is_string($map['generated_at'] ?? null)
            || $map['generated_at'] === ''
            || !is_string($map['content_digest'] ?? null)
            || preg_match('/^[a-f0-9]{64}$/D', $map['content_digest']) !== 1
            || !is_array($map['networks'] ?? null)
            || !is_array($map['interfaces'] ?? null)
            || (!is_array($map['devices'] ?? null) && !is_object($map['devices'] ?? null))
            || !is_array($map['conflicts'] ?? null)
        ) {
            return null;
        }

        $semantic = [
            'networks' => $map['networks'],
            'interfaces' => $map['interfaces'],
            'devices' => ($map['devices'] === []) ? (object) [] : $map['devices'],
            'conflicts' => $map['conflicts'],
        ];

        if (hash('sha256', $this->encode($semantic, false)) !== $map['content_digest']) {
            return null;
        }

        return $map;
    }

    /**
     * Client Map - Write Map.
     *
     * Atomically replaces one root-owned, world-readable map in its final directory.
     *
     * @param string $directory - Client map directory.
     * @param string $contents - Encoded map.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function writeMap(string $directory, string $contents): void
    {
        FileSystem::ensureReplaceableOwnedDirectory(
            $directory,
            0755,
            $this->paths->storageUser,
            $this->paths->storageGroup,
        );

        if (chmod($directory, 0755) === false) {
            throw new RuntimeException('Unable to set the client map directory mode.');
        }

        if (
            $this->paths->storageUser !== ''
            && lchown($directory, $this->paths->storageUser) === false
        ) {
            throw new RuntimeException('Unable to set the client map directory owner.');
        }

        if (
            $this->paths->storageGroup !== ''
            && lchgrp($directory, $this->paths->storageGroup) === false
        ) {
            throw new RuntimeException('Unable to set the client map directory group.');
        }

        $path = $directory . '/clients.json';
        AtomicFile::write($path, $contents, 0644);

        if ($this->paths->storageUser !== '' && lchown($path, $this->paths->storageUser) === false) {
            throw new RuntimeException('Unable to set the client map owner.');
        }

        if ($this->paths->storageGroup !== '' && lchgrp($path, $this->paths->storageGroup) === false) {
            throw new RuntimeException('Unable to set the client map group.');
        }
    }

    /**
     * Client Map - Encode.
     *
     * Uses stable compact JSON for digests and optional readable final documents.
     *
     * @param mixed $value - JSON value.
     * @param bool $pretty - Whether to indent the document.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private function encode(mixed $value, bool $pretty): string
    {
        try {
            $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

            if ($pretty) {
                $flags |= JSON_PRETTY_PRINT;
            }

            $encoded = json_encode($value, $flags);
        } catch (JsonException $exception) {
            throw new RuntimeException('Unable to encode the Sinkhole client map.', 0, $exception);
        }

        return $encoded . ($pretty ? PHP_EOL : '');
    }
}
