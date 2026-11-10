<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use InvalidArgumentException;

require_once(__DIR__ . '/DomainParser.php');
require_once(__DIR__ . '/ValidationException.php');

/**
 * Scope Configuration.
 *
 * Validates network and device policy rows while retaining malformed saved rows
 * for repair in the WebGUI.
 *
 * @since 1.0.0
 */
final class ScopeConfiguration
{
    /**
     * Scope Configuration - IP Device Type.
     *
     * @since 1.0.0
     */
    public const DEVICE_IP = 'ip';

    /**
     * Scope Configuration - Static Mapping Device Type.
     *
     * @since 1.0.0
     */
    public const DEVICE_STATIC_MAPPING = 'static_mapping';

    /**
     * Scope Configuration - MAC Device Type.
     *
     * @since 1.0.0
     */
    public const DEVICE_MAC = 'mac';

    /**
     * Scope Configuration - Generate Identifier.
     *
     * Scope identifiers share the list identifier format but remain independent.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function generateIdentifier(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Scope Configuration - Partition Networks.
     *
     * Only one valid network row may own each configured interface.
     *
     * @param mixed $value - Persisted network rows.
     * @param array<string, string> $interfaces - Interface names and descriptions.
     * @param array<string, array> $lists - Configured lists by stable ID.
     *
     * @return array{networks: array<string, array>, invalid_rows: list<array>}
     *
     * @since 1.0.0
     */
    public static function partitionNetworks(mixed $value, array $interfaces, array $lists): array
    {
        if ($value === null || $value === '') {
            return ['networks' => [], 'invalid_rows' => []];
        }

        if (!is_array($value)) {
            return [
                'networks' => [],
                'invalid_rows' => [self::invalidRow(
                    0,
                    $value,
                    new ValidationException('saved_networks_invalid'),
                )],
            ];
        }

        $networks = [];
        $usedInterfaces = [];
        $invalidRows = [];

        foreach (array_values($value) as $position => $row) {
            try {
                if (!is_array($row)) {
                    throw new ValidationException('saved_network_invalid');
                }

                $network = self::normalizeNetworkRow($row, $interfaces, $lists);

                if (isset($networks[$network['id']])) {
                    throw new ValidationException('saved_network_identifier_duplicated');
                }

                if (isset($usedInterfaces[$network['interface']])) {
                    throw new ValidationException('network_interface_duplicated');
                }

                $networks[$network['id']] = $network;
                $usedInterfaces[$network['interface']] = true;
            } catch (ValidationException $exception) {
                $invalidRows[] = self::invalidRow($position, $row, $exception);
            }
        }

        return ['networks' => $networks, 'invalid_rows' => $invalidRows];
    }

    /**
     * Scope Configuration - Partition Devices.
     *
     * Device order is preserved because the first device wins an address conflict.
     *
     * @param mixed $value - Persisted device rows.
     * @param list<array> $staticMappings - Current DHCP static mappings.
     * @param array<string, array> $lists - Configured lists by stable ID.
     *
     * @return array{devices: array<string, array>, invalid_rows: list<array>}
     *
     * @since 1.0.0
     */
    public static function partitionDevices(
        mixed $value,
        array $staticMappings,
        array $lists,
    ): array {
        if ($value === null || $value === '') {
            return ['devices' => [], 'invalid_rows' => []];
        }

        if (!is_array($value)) {
            return [
                'devices' => [],
                'invalid_rows' => [self::invalidRow(
                    0,
                    $value,
                    new ValidationException('saved_devices_invalid'),
                )],
            ];
        }

        $devices = [];
        $usedIdentifiers = [];
        $invalidRows = [];

        foreach (array_values($value) as $position => $row) {
            try {
                if (!is_array($row)) {
                    throw new ValidationException('saved_device_invalid');
                }

                $device = self::normalizeDeviceRow($row, $staticMappings, $lists);

                if (isset($devices[$device['id']])) {
                    throw new ValidationException('saved_device_identifier_duplicated');
                }

                $identifierKey = self::deviceIdentifierKey($device);

                if (isset($usedIdentifiers[$identifierKey])) {
                    throw new ValidationException('device_identifier_duplicated');
                }

                $devices[$device['id']] = $device;
                $usedIdentifiers[$identifierKey] = true;
            } catch (ValidationException $exception) {
                $invalidRows[] = self::invalidRow($position, $row, $exception);
            }
        }

        return ['devices' => $devices, 'invalid_rows' => $invalidRows];
    }

    /**
     * Scope Configuration - Normalize Network Row.
     *
     * Reuses one validation contract for saved rows and WebGUI submissions.
     *
     * @param array $row - Network row.
     * @param array<string, string> $interfaces - Interface names and descriptions.
     * @param array<string, array> $lists - Configured lists by stable ID.
     *
     * @return array{id: string, interface: string, lists: list<string>, allowed_domains: list<string>, enabled: bool}
     *
     * @since 1.0.0
     */
    public static function normalizeNetworkRow(array $row, array $interfaces, array $lists): array
    {
        $identifier = self::normalizeIdentifier($row['id'] ?? null, 'network');
        $interface = is_string($row['interface'] ?? null) ? trim($row['interface']) : '';

        if (
            preg_match('/^[\x21-\x7e]+$/D', $interface) !== 1
            || !array_key_exists($interface, $interfaces)
        ) {
            throw new ValidationException('network_interface_not_configured');
        }

        return [
            'id' => $identifier,
            'interface' => $interface,
            'lists' => self::normalizeListSelection($row['lists'] ?? [], $lists),
            'allowed_domains' => self::normalizeAllowedDomains($row['allowed_domains'] ?? []),
            'enabled' => self::enabled($row['enabled'] ?? null),
        ];
    }

    /**
     * Scope Configuration - Normalize Device Row.
     *
     * Static mappings are identified by interface and normalized MAC, never by a
     * mutable array index.
     *
     * @param array $row - Device row.
     * @param list<array> $staticMappings - Current DHCP static mappings.
     * @param array<string, array> $lists - Configured lists by stable ID.
     *
     * @return array{id: string, name: string, identifier_type: string, identifier: string, interface: string, lists: list<string>, allowed_domains: list<string>, enabled: bool}
     *
     * @since 1.0.0
     */
    public static function normalizeDeviceRow(array $row, array $staticMappings, array $lists): array
    {
        $identifier = self::normalizeIdentifier($row['id'] ?? null, 'device');
        $name = is_string($row['descr'] ?? null) ? trim($row['descr']) : '';

        if (
            $name === ''
            || strlen($name) > 128
            || preg_match('//u', $name) !== 1
            || preg_match('/[\x00-\x1f\x7f]/', $name) === 1
        ) {
            throw new ValidationException('device_name_invalid');
        }

        $type = is_string($row['identifier_type'] ?? null)
            ? $row['identifier_type']
            : '';
        $rawIdentifier = is_string($row['identifier'] ?? null) ? $row['identifier'] : '';
        $interface = is_string($row['interface'] ?? null) ? trim($row['interface']) : '';

        if ($type === self::DEVICE_IP) {
            $rawIdentifier = self::normalizeIpAddress($rawIdentifier);
            $interface = '';
        } elseif ($type === self::DEVICE_MAC) {
            $rawIdentifier = self::normalizeMacAddress($rawIdentifier);
            $interface = '';
        } elseif ($type === self::DEVICE_STATIC_MAPPING) {
            $rawIdentifier = self::normalizeMacAddress($rawIdentifier);

            if (preg_match('/^[\x21-\x7e]+$/D', $interface) !== 1 || !self::staticMappingExists(
                $staticMappings,
                $interface,
                $rawIdentifier,
            )) {
                throw new ValidationException('dhcp_static_mapping_missing');
            }
        } else {
            throw new ValidationException('device_identification_method_invalid');
        }

        return [
            'id' => $identifier,
            'name' => $name,
            'identifier_type' => $type,
            'identifier' => $rawIdentifier,
            'interface' => $interface,
            'lists' => self::normalizeListSelection($row['lists'] ?? [], $lists),
            'allowed_domains' => self::normalizeAllowedDomains($row['allowed_domains'] ?? []),
            'enabled' => self::enabled($row['enabled'] ?? null),
        ];
    }

    /**
     * Scope Configuration - List Usage Counts.
     *
     * Counts configured network and device assignments regardless of scope
     * enablement so the Lists page describes every saved relationship.
     *
     * @param array<string, array> $lists - Configured lists.
     * @param array<string, array> $networks - Valid networks.
     * @param array<string, array> $devices - Valid devices.
     *
     * @return array<string, int>
     *
     * @since 1.0.0
     */
    public static function listUsageCounts(array $lists, array $networks, array $devices): array
    {
        $counts = array_fill_keys(array_keys($lists), 0);

        foreach (array_merge(array_values($networks), array_values($devices)) as $scope) {
            foreach ($scope['lists'] ?? [] as $listIdentifier) {
                if (is_string($listIdentifier) && isset($counts[$listIdentifier])) {
                    $counts[$listIdentifier]++;
                }
            }
        }

        return $counts;
    }

    /**
     * Scope Configuration - Device Identifier Key.
     *
     * Produces the canonical key used for duplicate detection.
     *
     * @param array $device - Normalized device row.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function deviceIdentifierKey(array $device): string
    {
        $type = (string) ($device['identifier_type'] ?? '');
        $identifier = (string) ($device['identifier'] ?? '');

        if ($type === self::DEVICE_STATIC_MAPPING) {
            return $type . ':' . (string) ($device['interface'] ?? '') . ':' . $identifier;
        }

        return $type . ':' . $identifier;
    }

    /**
     * Scope Configuration - Normalize IP Address.
     *
     * Canonicalizes IPv4 and IPv6 and collapses IPv4-mapped IPv6 to IPv4.
     *
     * @param string $value - Address text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function normalizeIpAddress(string $value): string
    {
        $value = trim($value);
        $packed = filter_var($value, FILTER_VALIDATE_IP) === false ? false : inet_pton($value);

        if ($packed === false) {
            throw new ValidationException('device_ip_address_invalid');
        }

        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $packed = substr($packed, 12);
        }

        $normalized = inet_ntop($packed);

        if ($normalized === false) {
            throw new ValidationException('device_ip_address_invalid');
        }

        return strtolower($normalized);
    }

    /**
     * Scope Configuration - Normalize MAC Address.
     *
     * Accepts colon or hyphen separators and stores lowercase colon notation.
     *
     * @param string $value - MAC address text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function normalizeMacAddress(string $value): string
    {
        $value = strtolower(trim($value));

        if (preg_match('/^[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}$/D', $value) !== 1) {
            throw new ValidationException('device_mac_address_invalid');
        }

        return str_replace('-', ':', $value);
    }

    /**
     * Scope Configuration - Normalize Identifier.
     *
     * Validates one stable 32-hex scope identifier.
     *
     * @param mixed $value - Raw identifier.
     * @param string $kind - Scope kind for the error message.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeIdentifier(mixed $value, string $kind): string
    {
        if (!is_string($value) || preg_match('/^[a-f0-9]{32}$/D', $value) !== 1) {
            throw new ValidationException(match ($kind) {
                'network' => 'network_identifier_invalid',
                'device' => 'device_identifier_invalid',
                default => 'scope_identifier_invalid',
            });
        }

        return $value;
    }

    /**
     * Scope Configuration - Normalize List Selection.
     *
     * Rejects unknown list IDs and produces a unique selection in configured order.
     *
     * @param mixed $value - Selected identifiers.
     * @param array<string, array> $lists - Configured lists.
     *
     * @return list<string>
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeListSelection(mixed $value, array $lists): array
    {
        $value = self::unwrapRepeatedItems($value);

        if ($value === null || $value === '') {
            return [];
        }

        if (!is_array($value)) {
            throw new ValidationException('selected_block_lists_invalid');
        }

        $selected = [];

        foreach ($value as $listIdentifier) {
            if (!is_string($listIdentifier) || !isset($lists[$listIdentifier])) {
                throw new ValidationException('selected_block_list_missing');
            }

            $selected[$listIdentifier] = true;
        }

        return array_keys($selected);
    }

    /**
     * Scope Configuration - Normalize Allowed Domains.
     *
     * Rejects an entire scope row when any saved domain is malformed.
     *
     * @param mixed $value - Persisted allowed domains.
     *
     * @return list<string>
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeAllowedDomains(mixed $value): array
    {
        $value = self::unwrapRepeatedItems($value);
        $result = DomainParser::normalizeAllowedDomainValues($value);

        if (count($result['invalid_positions']) > 0) {
            throw new ValidationException('saved_allowed_domain_invalid');
        }

        return $result['domains'];
    }

    /**
     * Scope Configuration - Unwrap Repeated Items.
     *
     * pfSense parses repeated ``item`` elements into an array while form submissions
     * still provide their list values directly.
     *
     * @param mixed $value - Stored wrapper or direct form value.
     *
     * @return mixed
     *
     * @since 1.0.0
     */
    public static function unwrapRepeatedItems(mixed $value): mixed
    {
        if (
            is_array($value)
            && count($value) === 1
            && array_key_exists('item', $value)
        ) {
            $value = $value['item'];
        }

        return ($value === null || $value === '') ? [] : $value;
    }

    /**
     * Scope Configuration - Static Mapping Exists.
     *
     * Looks up mappings by interface and MAC so pfSense sorting cannot change the
     * selected identity.
     *
     * @param list<array> $mappings - Current mappings.
     * @param string $interface - Interface name.
     * @param string $mac - Normalized MAC address.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function staticMappingExists(array $mappings, string $interface, string $mac): bool
    {
        foreach ($mappings as $mapping) {
            if (!is_array($mapping) || ($mapping['interface'] ?? null) !== $interface) {
                continue;
            }

            try {
                if (self::normalizeMacAddress((string) ($mapping['mac'] ?? '')) === $mac) {
                    return true;
                }
            } catch (InvalidArgumentException) {
                continue;
            }
        }

        return false;
    }

    /**
     * Scope Configuration - Enabled Flag.
     *
     * Accepts only pfSense's checkbox representation or an explicit boolean.
     *
     * @param mixed $value - Raw flag.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function enabled(mixed $value): bool
    {
        return $value === 'on' || $value === true;
    }

    /**
     * Scope Configuration - Invalid Row.
     *
     * Preserves the original value and extracts only scalar display fields.
     *
     * @param int $position - Persisted row position.
     * @param mixed $row - Original row.
     * @param ValidationException $exception - Validation failure.
     *
     * @return array
     *
     * @since 1.0.0
     * @private
     */
    private static function invalidRow(
        int $position,
        mixed $row,
        ValidationException $exception,
    ): array
    {
        return [
            'position' => $position,
            'id' => is_array($row) && is_string($row['id'] ?? null) ? $row['id'] : '',
            'name' => is_array($row) && is_string($row['descr'] ?? null) ? $row['descr'] : '',
            'interface' => is_array($row) && is_string($row['interface'] ?? null)
                ? $row['interface']
                : '',
            'reason' => $exception->getMessage(),
            'reason_key' => $exception->messageKey(),
            'reason_arguments' => $exception->messageArguments(),
            'row' => $row,
        ];
    }
}
