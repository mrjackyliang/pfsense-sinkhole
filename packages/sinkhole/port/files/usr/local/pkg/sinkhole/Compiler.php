<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use JsonException;
use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\ListConfiguration;
use PfSense\Sinkhole\Domain\ServiceConfiguration;
use PfSense\Sinkhole\Domain\ServiceRegistry;
use RuntimeException;
use Throwable;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/BypassConfiguration.php');
require_once(__DIR__ . '/BypassListStore.php');
require_once(__DIR__ . '/DomainParser.php');
require_once(__DIR__ . '/FileLock.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/ListConfiguration.php');
require_once(__DIR__ . '/PackagePaths.php');
require_once(__DIR__ . '/SavedListStore.php');
require_once(__DIR__ . '/ServiceConfiguration.php');
require_once(__DIR__ . '/ServiceRegistry.php');
require_once(__DIR__ . '/ServiceRegistryCache.php');
require_once(__DIR__ . '/StateStore.php');

/**
 * Compiler.
 *
 * Builds bounded scope-ready generations and atomically activates them without
 * replacing the prior working data until every output file is complete.
 *
 * @since 1.0.0
 */
final class Compiler
{
    /**
     * Compiler - Manifest Schema Version.
     *
     * Version 3 adds interface-scoped bypass-answer metadata and domain data.
     *
     * @since 1.0.0
     */
    public const MANIFEST_SCHEMA_VERSION = 3;

    /**
     * Compiler - Maximum Unique Names.
     *
     * Both compiler and Unbound module enforce this hard memory-safety boundary.
     *
     * @since 1.0.0
     */
    public const MAXIMUM_UNIQUE_NAMES = 2000000;

    /**
     * Compiler - Runtime Lock Timeout Seconds.
     *
     * Background compilation remains bounded below pfSense's package-sync request
     * limit while still allowing a short lifecycle operation to finish.
     *
     * @since 1.0.0
     */
    public const RUNTIME_LOCK_TIMEOUT_SECONDS = 120;

    /**
     * Compiler - Chunk Record Limit.
     *
     * Sorting fixed-size chunks avoids a million-domain PHP array while keeping merge
     * overhead modest on pfSense hardware.
     *
     * @since 1.0.0
     * @private
     */
    private const CHUNK_RECORD_LIMIT = 50000;

    /**
     * Compiler - State Store.
     *
     * Compile intent and failures persist so later updater runs retry them.
     *
     * @var StateStore
     *
     * @since 1.0.0
     * @private
     */
    private readonly StateStore $stateStore;

    /**
     * Compiler - Constructor.
     *
     * The store supplies validated saved-list paths and state retains retry intent
     * across updater runs and package synchronization.
     *
     * @param PackagePaths    $paths      - Package paths.
     * @param SavedListStore  $store      - Saved list store.
     * @param StateStore|null $stateStore - State store.
     * @param int|null $availableSpaceOverride - Test-only available-byte override.
     * @param BypassListStore|null $bypassStore - Saved mixed Bypass Lists.
     *
     * @since 1.0.0
     */
    public function __construct(
        private readonly PackagePaths $paths,
        private readonly SavedListStore $store,
        ?StateStore $stateStore = null,
        private readonly ?int $availableSpaceOverride = null,
        private readonly ?BypassListStore $bypassStore = null,
    ) {
        $this->stateStore = $stateStore ?? new StateStore(
            $this->paths->stateFile,
            $this->paths->statusFile,
        );
    }

    /**
     * Compiler - Mark Needed.
     *
     * Download and configuration changes call this before attempting a generation.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function markNeeded(): void
    {
        $this->stateStore->markCompileNeeded();
    }

    /**
     * Compiler - Is Needed.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function isNeeded(): bool
    {
        return $this->stateStore->compileNeeded();
    }

    /**
     * Compiler - Deployment Is Needed.
     *
     * Active jobs redeploy compiled content after an inactive compile or missing
     * runtime generation even when no newer compile request exists.
     *
     * @param bool $runtimeMissing - Whether validated runtime data is absent.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function deploymentIsNeeded(bool $runtimeMissing): bool
    {
        return $this->stateStore->deploymentStatus($runtimeMissing)['needed'];
    }

    /**
     * Compiler - Apply Pending Synchronization.
     *
     * Update jobs call this outside compilation as well, so a Sync that reaches its
     * bounded wait at the edge of a runtime-lock release cannot leave integration
     * work stranded when no content compile is otherwise needed.
     *
     * @param callable(): void $handler - Locked integration synchronizer.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function applyPendingSynchronization(callable $handler): bool
    {
        if ($this->stateStore->syncPending() === false) {
            return false;
        }

        $lock = new FileLock($this->paths->runtimeLockFile);

        if ($lock->acquire(self::RUNTIME_LOCK_TIMEOUT_SECONDS) === false) {
            throw new RuntimeException('Timed out waiting for the Sinkhole runtime lock.');
        }

        try {
            return $this->applyPendingSynchronizationUnderLock($handler);
        } finally {
            $lock->release();
        }
    }

    /**
     * Compiler - Compile.
     *
     * Revalidates saved data, writes list bit numbers, enforces the unique-name cap,
     * and records success or a retryable failure. One runtime lock serializes the
     * complete build with Resolver lifecycle changes and generation activation.
     *
     * @param mixed $configuredLists - Untrusted configured lists.
     * @param mixed $allowedDomains  - Untrusted allowed-domain elements.
     * @param bool  $mirrorRuntime   - Whether RAM-disk boot data is required.
     * @param bool|callable(): bool $deployRuntime - Active state or locked check.
     * @param null|callable(): array{lists: mixed, allowed_domains: mixed, networks?: mixed, devices?: mixed, alerts?: mixed, services?: mixed, bypass?: mixed} $inputProvider
     *     - Locked current-input provider.
     * @param bool $runtimeLockHeld - Whether the caller already owns the runtime lock.
     * @param null|callable(): void $pendingSyncHandler - Locked pending-Sync handler.
     * @param mixed $configuredNetworks - Valid configured network scopes.
     * @param mixed $configuredDevices - Valid configured device scopes.
     * @param mixed $configuredAlerts - Valid configured alert rules.
     * @param mixed $configuredServices - Per-scope blocked-service selections.
     * @param array|null $serviceRegistry - Parsed test registry or cached production registry.
     * @param mixed $configuredBypass - Partitioned Bypass Protection settings.
     *
     * @return array{
     *     generation: string,
     *     domains: int,
     *     lists: int,
     *     generated_at: string,
     *     content_digest: string,
     *     changed: bool,
     *     deployed: bool,
     *     added_names: int
     * }
     *
     * @throws Throwable When valid data cannot be compiled or activated.
     *
     * @since 1.0.0
     */
    public function compile(
        mixed $configuredLists,
        mixed $allowedDomains,
        bool $mirrorRuntime = false,
        bool|callable $deployRuntime = true,
        ?callable $inputProvider = null,
        bool $runtimeLockHeld = false,
        ?callable $pendingSyncHandler = null,
        mixed $configuredNetworks = [],
        mixed $configuredDevices = [],
        mixed $configuredAlerts = [],
        mixed $configuredServices = [],
        ?array $serviceRegistry = null,
        mixed $configuredBypass = [],
    ): array {
        $lock = new FileLock($this->paths->runtimeLockFile);
        $acquiredRuntimeLock = false;
        $hasRuntimeLock = $runtimeLockHeld;

        try {
            if (
                $runtimeLockHeld === false
                && $lock->acquire(self::RUNTIME_LOCK_TIMEOUT_SECONDS) === false
            ) {
                throw new RuntimeException('Timed out waiting for the Sinkhole runtime lock.');
            }

            if ($runtimeLockHeld === false) {
                $acquiredRuntimeLock = true;
                $hasRuntimeLock = true;
            }

            $this->stateStore->sweepTemporaryFiles();

            $compileRequest = $this->stateStore->compileRequest();

            if ($inputProvider !== null) {
                $inputs = $inputProvider();

                if (
                    !is_array($inputs)
                    || !array_key_exists('lists', $inputs)
                    || !array_key_exists('allowed_domains', $inputs)
                ) {
                    throw new RuntimeException('The compiler input snapshot is invalid.');
                }

                $configuredLists = $inputs['lists'];
                $allowedDomains = $inputs['allowed_domains'];
                $configuredNetworks = $inputs['networks'] ?? [];
                $configuredDevices = $inputs['devices'] ?? [];
                $configuredAlerts = $inputs['alerts'] ?? [];
                $configuredServices = $inputs['services'] ?? [];
                $configuredBypass = $inputs['bypass'] ?? [];
            }

            $serviceRegistry ??= ServiceRegistryCache::cachedRegistry($this->paths);

            $result = $this->compileGeneration(
                $configuredLists,
                $allowedDomains,
                $mirrorRuntime,
                $deployRuntime,
                $configuredNetworks,
                $configuredDevices,
                $configuredAlerts,
                $configuredServices,
                $serviceRegistry,
                $configuredBypass,
            );

            $this->stateStore->recordCompileSuccess(
                $result['generation'],
                $compileRequest,
                $result['content_digest'],
            );

            if ($result['deployment_current']) {
                $this->stateStore->recordDeployment(
                    $result['generation'],
                    $result['content_digest'],
                );
            }

            if ($result['deployed'] && $result['added_names'] > 0) {
                $this->stateStore->markCacheClearOwed($result['generation']);
            }

            unset($result['deployment_current']);

            return $result;
        } catch (Throwable $throwable) {
            $this->stateStore->recordCompileFailure($throwable->getMessage());

            throw $throwable;
        } finally {
            try {
                if ($hasRuntimeLock && $pendingSyncHandler !== null) {
                    $this->applyPendingSynchronizationUnderLock(
                        $pendingSyncHandler,
                    );
                }
            } finally {
                if ($acquiredRuntimeLock) {
                    $lock->release();
                }
            }
        }
    }

    /**
     * Compiler - Apply Pending Synchronization Under Lock.
     *
     * Re-checks after each integration pass so multiple timed-out Sync callers are
     * collapsed without releasing the runtime lock between them.
     *
     * @param callable(): void $handler - Locked integration synchronizer.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function applyPendingSynchronizationUnderLock(callable $handler): bool
    {
        $applied = false;

        while ($this->stateStore->consumeSyncPending()) {
            try {
                $handler();
                $applied = true;
            } catch (Throwable $throwable) {
                $this->stateStore->markSyncPending();

                throw $throwable;
            }
        }

        return $applied;
    }

    /**
     * Compiler - Compile Generation.
     *
     * Builds and activates one generation while the public method owns the runtime
     * lock and compile-needed state transitions.
     *
     * @param mixed $configuredLists - Untrusted configured lists.
     * @param mixed $allowedDomains  - Untrusted allowed-domain elements.
     * @param bool  $mirrorRuntime   - Whether RAM-disk boot data is required.
     * @param bool|callable(): bool $deployRuntime - Locked deployment eligibility.
     * @param mixed $configuredNetworks - Valid configured network scopes.
     * @param mixed $configuredDevices - Valid configured device scopes.
     * @param mixed $configuredAlerts - Valid configured alert rules.
     * @param mixed $configuredServices - Per-scope blocked-service selections.
     * @param array $serviceRegistry - Parsed cached registry.
     * @param mixed $configuredBypass - Partitioned Bypass Protection settings.
     *
     * @return array{
     *     generation: string,
     *     domains: int,
     *     lists: int,
     *     generated_at: string,
     *     content_digest: string,
     *     changed: bool,
     *     deployed: bool,
     *     added_names: int,
     *     deployment_current: bool
     * }
     *
     * @since 1.0.0
     * @private
     */
    private function compileGeneration(
        mixed $configuredLists,
        mixed $allowedDomains,
        bool $mirrorRuntime,
        bool|callable $deployRuntime,
        mixed $configuredNetworks,
        mixed $configuredDevices,
        mixed $configuredAlerts,
        mixed $configuredServices,
        array $serviceRegistry,
        mixed $configuredBypass,
    ): array {
        $lists = ListConfiguration::normalizeLists($configuredLists);
        $allowResult = DomainParser::normalizeAllowedDomainValues($allowedDomains);

        if (count($allowResult['invalid_positions']) > 0) {
            $positions = implode(', ', $allowResult['invalid_positions']);

            throw new RuntimeException('Allowed domains contain invalid entries: ' . $positions . '.');
        }

        $scopeData = $this->normalizeScopes(
            $lists,
            $allowResult['domains'],
            $configuredNetworks,
            $configuredDevices,
        );
        $scopeData = $this->addBlockedServicesToScopes(
            $scopeData,
            $configuredServices,
            $serviceRegistry,
            $lists,
        );
        $bypass = $this->normalizeBypassConfiguration($configuredBypass);

        FileSystem::ensureDirectory($this->paths->persistentDirectory, 0700);
        FileSystem::sweepStaleEntries(
            $this->paths->persistentDirectory,
            ['.compile-'],
        );

        $buildDirectory = FileSystem::createTemporaryDirectory(
            $this->paths->persistentDirectory,
            '.compile-',
            0700,
        );

        try {
            $chunkDirectory = $buildDirectory . '/chunks';

            FileSystem::ensureDirectory($chunkDirectory, 0700);

            $manifestLists = [];
            $records = [];
            $chunkPaths = [];
            $bit = 0;

            ksort($lists, SORT_STRING);

            foreach ($lists as $identifier => $list) {
                if (!isset($scopeData['used_lists'][$identifier])) {
                    continue;
                }

                $listBit = $bit;
                $manifestLists[$identifier] = [
                    'name' => $list['name'],
                    'bit' => $listBit,
                ];
                $bit++;

                $handle = fopen($this->store->savedCopyPath($identifier), 'rb');

                if ($handle === false) {
                    throw new RuntimeException('Unable to read a saved block list.');
                }

                try {
                    while (($line = fgets($handle)) !== false) {
                        $entry = DomainParser::parseNormalizedLine($line);

                        if ($entry === null) {
                            throw new RuntimeException('A saved block list is invalid.');
                        }

                        $records[] = $entry['domain']
                            . "\t"
                            . $entry['semantic']
                            . "\t"
                            . $listBit;

                        if (count($records) >= self::CHUNK_RECORD_LIMIT) {
                            $chunkPaths[] = $this->writeChunk($chunkDirectory, $records);
                            $records = [];
                        }
                    }

                    if (!feof($handle)) {
                        throw new RuntimeException('Unable to finish reading a saved block list.');
                    }
                } finally {
                    fclose($handle);
                }
            }

            foreach ($scopeData['service_lists'] as $identifier => $serviceList) {
                $listBit = $bit;
                $manifestLists[$identifier] = [
                    'name' => $serviceList['name'],
                    'bit' => $listBit,
                ];
                $bit++;

                foreach ($serviceList['rules'] as $entry) {
                    $records[] = $entry['domain']
                        . "\t"
                        . $entry['semantic']
                        . "\t"
                        . $listBit;

                    if (count($records) >= self::CHUNK_RECORD_LIMIT) {
                        $chunkPaths[] = $this->writeChunk($chunkDirectory, $records);
                        $records = [];
                    }
                }
            }

            if (count($records) > 0) {
                $chunkPaths[] = $this->writeChunk($chunkDirectory, $records);
            }

            $manifestAlerts = $this->normalizeAlerts(
                $configuredAlerts,
                $lists,
                $manifestLists,
                (array) $scopeData['scopes']['networks'],
                (array) $scopeData['scopes']['devices'],
            );

            $domainCount = $this->mergeChunks($chunkPaths, $buildDirectory . '/domains.tsv');
            $bypassDomainCount = $this->compileBypassDomains(
                $bypass,
                $chunkDirectory,
                $buildDirectory . '/bypass.tsv',
            );

            if ($domainCount + $bypassDomainCount > self::MAXIMUM_UNIQUE_NAMES) {
                throw new RuntimeException(
                    'The compile exceeds the 2,000,000 unique-name limit.',
                );
            }

            foreach ($scopeData['allow_files'] as $allowFile => $domains) {
                $allowContents = (count($domains) > 0)
                    ? implode(PHP_EOL, $domains) . PHP_EOL
                    : '';

                AtomicFile::write($buildDirectory . '/' . $allowFile, $allowContents);
            }

            $generatedAt = gmdate('c');
            $generation = gmdate('Ymd\THis\Z') . '-' . bin2hex(random_bytes(8));
            $digestManifest = [
                'schema_version' => self::MANIFEST_SCHEMA_VERSION,
                'lists' => (object) $manifestLists,
                'scopes' => $scopeData['scopes'],
                'alerts' => (object) $manifestAlerts,
                'bypass' => $bypass['manifest'],
            ];
            $contentDigest = $this->contentDigest($buildDirectory, $digestManifest);
            $manifest = [
                'schema_version' => self::MANIFEST_SCHEMA_VERSION,
                'generation' => $generation,
                'generated_at' => $generatedAt,
                'content_digest' => $contentDigest,
                'domains_file' => 'domains.tsv',
                'bypass_file' => 'bypass.tsv',
                'allow_file' => 'allow.txt',
                'domain_count' => $domainCount,
                'bypass_domain_count' => $bypassDomainCount,
                'lists' => $digestManifest['lists'],
                'scopes' => $digestManifest['scopes'],
                'alerts' => $digestManifest['alerts'],
                'bypass' => $digestManifest['bypass'],
            ];

            try {
                $manifestContents = json_encode(
                    $manifest,
                    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
                );
            } catch (JsonException $exception) {
                throw new RuntimeException('Unable to encode the compiled manifest.', 0, $exception);
            }

            AtomicFile::write($buildDirectory . '/manifest.json', $manifestContents . PHP_EOL);
            AtomicFile::write($buildDirectory . '/generation', $generation . PHP_EOL);

            FileSystem::removeDirectory($chunkDirectory);

            $deploy = is_callable($deployRuntime)
                ? $deployRuntime()
                : $deployRuntime;
            $deployment = $deploy
                ? $this->deployGeneration($buildDirectory, $contentDigest, $mirrorRuntime)
                : [
                    'generation' => $generation,
                    'changed' => true,
                    'deployed' => false,
                    'added_names' => 0,
                    'deployment_current' => false,
                ];

            return [
                'generation' => $deployment['generation'],
                'domains' => $domainCount,
                'lists' => count($manifestLists),
                'generated_at' => $generatedAt,
                'content_digest' => $contentDigest,
                'changed' => $deployment['changed'],
                'deployed' => $deployment['deployed'],
                'added_names' => $deployment['added_names'],
                'deployment_current' => $deployment['deployment_current'],
            ];
        } finally {
            if (is_dir($buildDirectory)) {
                FileSystem::removeDirectory($buildDirectory);
            }
        }
    }

    /**
     * Compiler - Normalize Bypass Configuration.
     *
     * The adapter normally supplies an already partitioned record. Direct compiler
     * callers may supply the persisted shape, which remains disabled when absent.
     *
     * @param mixed $value - Bypass configuration input.
     *
     * @return array{configuration: array, lists: array<string, array>, manifest: array}
     *
     * @since 1.0.0
     * @private
     */
    private function normalizeBypassConfiguration(mixed $value): array
    {
        if (is_array($value) && array_key_exists('dns_enabled', $value)) {
            $configuration = $value;
        } else {
            $interfaces = is_array($value) && is_array($value['interfaces'] ?? null)
                ? array_values(array_filter($value['interfaces'], 'is_string'))
                : [];
            $configuration = BypassConfiguration::partition($value, $interfaces);
        }

        $configurationWarning = null;

        if (($configuration['invalid_values'] ?? []) !== []) {
            $firstInvalid = $configuration['invalid_values'][0] ?? [];
            $reasonKey = is_array($firstInvalid) && is_string($firstInvalid['reason_key'] ?? null)
                ? $firstInvalid['reason_key']
                : 'saved_bypass_settings_invalid';
            $configurationWarning = 'Bypass protection is inactive because its saved settings '
                . 'need repair (' . $reasonKey . ').';

            foreach (BypassConfiguration::BOOLEAN_FIELDS as $field) {
                $configuration[$field] = false;
            }

            $configuration['discovery'] = BypassConfiguration::DISCOVERY_OFF;
            $configuration['interfaces'] = [];
            $configuration['enabled'] = false;
            $configuration['dns_enabled'] = false;
            $configuration['firewall_enabled'] = false;
        }

        $interfaces = [];

        foreach (is_array($configuration['interfaces'] ?? null) ? $configuration['interfaces'] : [] as $interface) {
            if (
                is_string($interface)
                && preg_match('/^[a-z0-9_.:-]{1,64}$/Di', $interface) === 1
            ) {
                $interfaces[$interface] = true;
            }
        }

        $interfaces = array_keys($interfaces);
        sort($interfaces, SORT_STRING);
        $discovery = is_string($configuration['discovery'] ?? null)
            && in_array($configuration['discovery'], BypassConfiguration::DISCOVERY_MODES, true)
                ? $configuration['discovery']
                : BypassConfiguration::DISCOVERY_OFF;
        $hostname = '';

        if ($discovery === BypassConfiguration::DISCOVERY_ADVERTISE) {
            $candidate = is_string($configuration['discovery_hostname'] ?? null)
                ? $configuration['discovery_hostname']
                : '';
            $hostname = DomainParser::normalizeDomain($candidate) ?? '';

            if (
                $hostname === ''
                || $hostname !== strtolower(rtrim($candidate, '.'))
                || ($configuration['discovery_port'] ?? null) !== 853
            ) {
                $configurationWarning = 'Bypass Discovery is inactive because DNS Resolver '
                    . 'SSL/TLS is not enabled on port 853 with a valid certificate hostname.';
                $configuration['discovery'] = BypassConfiguration::DISCOVERY_OFF;
                $discovery = BypassConfiguration::DISCOVERY_OFF;
                $hostname = '';
            }
        }

        $configuration['dns_enabled'] = BypassConfiguration::dnsEnabled($configuration);
        $configuration['firewall_enabled'] = BypassConfiguration::firewallEnabled($configuration);
        $configuration['enabled'] = $configuration['dns_enabled']
            || $configuration['firewall_enabled'];

        $this->recordBypassConfigurationWarning($configurationWarning);

        $manifest = [
            'interfaces' => $interfaces,
            'block_encrypted_dns' => ($configuration['block_encrypted_dns'] ?? false) === true,
            'disable_firefox_doh' => ($configuration['disable_firefox_doh'] ?? false) === true,
            'disable_private_relay' => ($configuration['disable_private_relay'] ?? false) === true,
            'discovery' => $discovery,
            'discovery_hostname' => $hostname,
            'discovery_port' => ($discovery === BypassConfiguration::DISCOVERY_ADVERTISE)
                ? 853
                : 0,
            'block_tor' => ($configuration['block_tor'] ?? false) === true,
            'block_vpn' => ($configuration['block_vpn'] ?? false) === true,
        ];

        return [
            'configuration' => $configuration,
            'lists' => is_array($configuration['lists'] ?? null)
                ? $configuration['lists']
                : [],
            'manifest' => $manifest,
        ];
    }

    /**
     * Compiler - Record Bypass Configuration Warning.
     *
     * A state-file problem must not restore the compile failure this fallback is
     * designed to isolate.
     *
     * @param string|null $warning - Current compiler fallback reason.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function recordBypassConfigurationWarning(?string $warning): void
    {
        try {
            $this->stateStore->recordBypassConfigurationWarning($warning);
        } catch (Throwable) {
            // The generation remains usable even when its persistent warning cannot be written.
        }
    }

    /**
     * Compiler - Compile Bypass Domains.
     *
     * @param array $bypass - Normalized Bypass compiler input.
     * @param string $chunkDirectory - Existing private chunk directory.
     * @param string $outputPath - Compiled Bypass domain file.
     *
     * @return int
     *
     * @since 1.0.0
     * @private
     */
    private function compileBypassDomains(
        array $bypass,
        string $chunkDirectory,
        string $outputPath,
    ): int {
        $records = [];
        $chunkPaths = [];
        $lists = $bypass['lists'];
        ksort($lists, SORT_STRING);

        foreach ($lists as $identifier => $list) {
            if (
                !is_array($list)
                || ($list['enabled'] ?? false) !== true
                || !is_string($list['kind'] ?? null)
                || !BypassConfiguration::kindEnabled(
                    $bypass['configuration'],
                    $list['kind'],
                )
                || $this->bypassStore === null
                || !$this->bypassStore->hasSavedCopy((string) $identifier)
            ) {
                continue;
            }

            $handle = fopen($this->bypassStore->savedCopyPath((string) $identifier), 'rb');

            if ($handle === false) {
                throw new RuntimeException('Unable to read a saved Bypass List.');
            }

            try {
                while (($line = fgets($handle)) !== false) {
                    $entry = BypassListStore::parseNormalizedLine($line);

                    if ($entry === null) {
                        throw new RuntimeException('A saved Bypass List is invalid.');
                    }

                    if ($entry['type'] !== 'domain') {
                        continue;
                    }

                    $records[] = $entry['domain']
                        . "\t"
                        . $entry['semantic']
                        . "\t"
                        . $list['kind'];

                    if (count($records) >= self::CHUNK_RECORD_LIMIT) {
                        $chunkPaths[] = $this->writeChunk($chunkDirectory, $records);
                        $records = [];
                    }
                }

                if (!feof($handle)) {
                    throw new RuntimeException('Unable to finish reading a saved Bypass List.');
                }
            } finally {
                fclose($handle);
            }
        }

        if ($records !== []) {
            $chunkPaths[] = $this->writeChunk($chunkDirectory, $records);
        }

        return $this->mergeBypassChunks($chunkPaths, $outputPath);
    }

    /**
     * Compiler - Merge Bypass Chunks.
     *
     * Writes one sorted row per name with exact and subtree kind columns.
     *
     * @param list<string> $chunkPaths - Sorted Bypass chunk paths.
     * @param string $outputPath - Bypass data path.
     *
     * @return int
     *
     * @since 1.0.0
     * @private
     */
    private function mergeBypassChunks(array $chunkPaths, string $outputPath): int
    {
        $previousMask = umask(0177);

        try {
            $output = fopen($outputPath, 'x+b');
        } finally {
            umask($previousMask);
        }

        if ($output === false) {
            throw new RuntimeException('Unable to create compiled Bypass data.');
        }

        $handles = [];
        $currentRecords = [];
        $domainCount = 0;
        $currentDomain = null;
        $exactKinds = [];
        $subtreeKinds = [];

        try {
            foreach ($chunkPaths as $index => $chunkPath) {
                $handle = fopen($chunkPath, 'rb');

                if ($handle === false) {
                    throw new RuntimeException('Unable to read a Bypass compiler chunk.');
                }

                $handles[$index] = $handle;
                $record = fgets($handle);

                if ($record !== false) {
                    $currentRecords[$index] = rtrim($record, "\r\n");
                }
            }

            while ($currentRecords !== []) {
                $smallestIndex = null;
                $smallestRecord = null;

                foreach ($currentRecords as $index => $record) {
                    if ($smallestRecord === null || strcmp($record, $smallestRecord) < 0) {
                        $smallestIndex = $index;
                        $smallestRecord = $record;
                    }
                }

                if ($smallestIndex === null || $smallestRecord === null) {
                    throw new RuntimeException('Unable to merge Bypass compiler chunks.');
                }

                $fields = explode("\t", $smallestRecord);

                if (
                    count($fields) !== 3
                    || DomainParser::normalizeDomain($fields[0]) !== $fields[0]
                    || !in_array($fields[2], BypassConfiguration::KINDS, true)
                ) {
                    throw new RuntimeException('A Bypass compiler record is invalid.');
                }

                if ($currentDomain !== null && $fields[0] !== $currentDomain) {
                    $this->writeBypassDomainRow(
                        $output,
                        $currentDomain,
                        $exactKinds,
                        $subtreeKinds,
                    );
                    $domainCount++;
                    $exactKinds = [];
                    $subtreeKinds = [];
                }

                $currentDomain = $fields[0];

                if ($fields[1] === DomainParser::EXACT) {
                    $exactKinds[$fields[2]] = true;
                } elseif ($fields[1] === DomainParser::SUBTREE) {
                    $subtreeKinds[$fields[2]] = true;
                } else {
                    throw new RuntimeException('A Bypass compiler semantic is invalid.');
                }

                $nextRecord = fgets($handles[$smallestIndex]);

                if ($nextRecord === false) {
                    unset($currentRecords[$smallestIndex]);
                } else {
                    $currentRecords[$smallestIndex] = rtrim($nextRecord, "\r\n");
                }
            }

            if ($currentDomain !== null) {
                $this->writeBypassDomainRow(
                    $output,
                    $currentDomain,
                    $exactKinds,
                    $subtreeKinds,
                );
                $domainCount++;
            }

            if (fflush($output) === false) {
                throw new RuntimeException('Unable to flush compiled Bypass data.');
            }
        } finally {
            foreach ($handles as $handle) {
                fclose($handle);
            }

            fclose($output);
        }

        return $domainCount;
    }

    /** @since 1.0.0 */
    private function writeBypassDomainRow(
        mixed $handle,
        string $domain,
        array $exactKinds,
        array $subtreeKinds,
    ): void {
        $exact = array_keys($exactKinds);
        $subtree = array_keys($subtreeKinds);
        sort($exact, SORT_STRING);
        sort($subtree, SORT_STRING);
        $row = implode("\t", [$domain, implode(',', $exact), implode(',', $subtree)])
            . PHP_EOL;

        if (fwrite($handle, $row) !== strlen($row)) {
            throw new RuntimeException('Unable to write compiled Bypass data.');
        }
    }

    /**
     * Compiler - Normalize Scopes.
     *
     * Selects only enabled scopes and lists with saved copies, then prepares one
     * independently normalized allow file per effective scope.
     *
     * @param array<string, array> $lists - Normalized configured lists.
     * @param list<string> $globalAllowedDomains - Normalized global allowed domains.
     * @param mixed $configuredNetworks - Configured network scopes.
     * @param mixed $configuredDevices - Configured device scopes.
     *
     * @return array{
     *     used_lists: array<string, true>,
     *     allow_files: array<string, list<string>>,
     *     scopes: array{global: array, networks: object, devices: object}
     * }
     *
     * @since 1.0.0
     * @private
     */
    private function normalizeScopes(
        array $lists,
        array $globalAllowedDomains,
        mixed $configuredNetworks,
        mixed $configuredDevices,
    ): array {
        $availableLists = [];

        foreach ($lists as $identifier => $list) {
            if ($list['enabled'] && $this->store->hasSavedCopy($identifier)) {
                $availableLists[$identifier] = true;
            }
        }

        $globalLists = [];

        foreach ($lists as $identifier => $list) {
            if (($list['global'] ?? true) && isset($availableLists[$identifier])) {
                $globalLists[] = $identifier;
            }
        }

        sort($globalLists, SORT_STRING);
        $usedLists = array_fill_keys($globalLists, true);
        $allowFiles = ['allow.txt' => $globalAllowedDomains];
        $networkScopes = $this->normalizeScopeRows(
            $configuredNetworks,
            'network',
            $lists,
            $availableLists,
            $usedLists,
            $allowFiles,
        );
        $deviceScopes = $this->normalizeScopeRows(
            $configuredDevices,
            'device',
            $lists,
            $availableLists,
            $usedLists,
            $allowFiles,
        );

        return [
            'used_lists' => $usedLists,
            'allow_files' => $allowFiles,
            'scopes' => [
                'global' => [
                    'lists' => $globalLists,
                    'allow' => 'allow.txt',
                ],
                'networks' => (object) $networkScopes,
                'devices' => (object) $deviceScopes,
            ],
        ];
    }

    /**
     * Compiler - Add Blocked Services To Scopes.
     *
     * Each selected service becomes a stable synthetic list. The ordinary scope
     * hierarchy can then apply its rules without changing Resolver decision order.
     * Unknown saved IDs remain in configuration but contribute no compiled rules.
     *
     * @param array $scopeData - Normalized ordinary-list scope data.
     * @param mixed $configuredServices - Per-scope selections.
     * @param array $registry - Parsed cached service registry.
     * @param array<string, array> $configuredLists - Ordinary configured lists.
     *
     * @return array
     *
     * @since 1.0.0
     * @private
     */
    private function addBlockedServicesToScopes(
        array $scopeData,
        mixed $configuredServices,
        array $registry,
        array $configuredLists,
    ): array {
        $configuration = ServiceConfiguration::partition($configuredServices);
        $services = is_array($registry['services'] ?? null)
            ? $registry['services']
            : [];
        $serviceLists = [];
        $applySelection = static function (array &$scopeLists, array $selection) use (
            &$serviceLists,
            $services,
            $configuredLists,
        ): void {
            foreach ($selection as $serviceIdentifier) {
                $service = $services[$serviceIdentifier] ?? null;

                if (
                    !is_array($service)
                    || !is_string($service['name'] ?? null)
                    || !is_array($service['rules'] ?? null)
                    || $service['rules'] === []
                ) {
                    continue;
                }

                $identifier = ServiceRegistry::syntheticListIdentifier($serviceIdentifier);

                if (isset($configuredLists[$identifier])) {
                    throw new RuntimeException(
                        'A blocked-service identifier conflicts with a configured list.',
                    );
                }

                if (
                    isset($serviceLists[$identifier])
                    && $serviceLists[$identifier]['service_id'] !== $serviceIdentifier
                ) {
                    throw new RuntimeException('Two blocked services have the same compiled identifier.');
                }

                $serviceLists[$identifier] ??= [
                    'service_id' => $serviceIdentifier,
                    'name' => $service['name'],
                    'rules' => $service['rules'],
                ];
                $scopeLists[] = $identifier;
            }

            $scopeLists = array_values(array_unique($scopeLists));
            sort($scopeLists, SORT_STRING);
        };

        $applySelection(
            $scopeData['scopes']['global']['lists'],
            $configuration['global'],
        );
        $networkScopes = (array) $scopeData['scopes']['networks'];

        foreach ($configuration['networks'] as $identifier => $selection) {
            if (isset($networkScopes[$identifier])) {
                $applySelection($networkScopes[$identifier]['lists'], $selection);
            }
        }

        $deviceScopes = (array) $scopeData['scopes']['devices'];

        foreach ($configuration['devices'] as $identifier => $selection) {
            if (isset($deviceScopes[$identifier])) {
                $applySelection($deviceScopes[$identifier]['lists'], $selection);
            }
        }

        $scopeData['scopes']['networks'] = (object) $networkScopes;
        $scopeData['scopes']['devices'] = (object) $deviceScopes;
        ksort($serviceLists, SORT_STRING);
        $scopeData['service_lists'] = $serviceLists;

        return $scopeData;
    }

    /**
     * Compiler - Normalize Scope Rows.
     *
     * Produces manifest records and registers every referenced list and allow file.
     *
     * @param mixed $value - Configured rows.
     * @param string $kind - ``network`` or ``device``.
     * @param array<string, array> $configuredLists - Every configured list.
     * @param array<string, true> $availableLists - Enabled lists with saved copies.
     * @param array<string, true> $usedLists - Mutable effective-list set.
     * @param array<string, list<string>> $allowFiles - Mutable allow-file map.
     *
     * @return array<string, array>
     *
     * @since 1.0.0
     * @private
     */
    private function normalizeScopeRows(
        mixed $value,
        string $kind,
        array $configuredLists,
        array $availableLists,
        array &$usedLists,
        array &$allowFiles,
    ): array {
        if ($value === null || $value === '') {
            return [];
        }

        if (!is_array($value)) {
            throw new RuntimeException('Configured ' . $kind . ' scopes are invalid.');
        }

        $scopes = [];

        foreach ($value as $row) {
            if (!is_array($row)) {
                throw new RuntimeException('A configured ' . $kind . ' scope is invalid.');
            }

            $enabled = ($row['enabled'] ?? false) === true || ($row['enabled'] ?? '') === 'on';

            if ($enabled === false) {
                continue;
            }

            $identifier = is_string($row['id'] ?? null) ? $row['id'] : '';

            if (preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1 || isset($scopes[$identifier])) {
                throw new RuntimeException('A configured ' . $kind . ' scope identifier is invalid.');
            }

            $selectedLists = $row['lists'] ?? [];

            if (!is_array($selectedLists)) {
                throw new RuntimeException('A configured scope list selection is invalid.');
            }

            $effectiveLists = [];

            foreach ($selectedLists as $listIdentifier) {
                if (!is_string($listIdentifier) || !isset($configuredLists[$listIdentifier])) {
                    throw new RuntimeException('A configured scope references an unknown block list.');
                }

                if (isset($availableLists[$listIdentifier])) {
                    $effectiveLists[$listIdentifier] = true;
                    $usedLists[$listIdentifier] = true;
                }
            }

            $effectiveListIdentifiers = array_keys($effectiveLists);
            sort($effectiveListIdentifiers, SORT_STRING);
            $allowResult = DomainParser::normalizeAllowedDomainValues(
                $row['allowed_domains'] ?? [],
            );

            if (count($allowResult['invalid_positions']) > 0) {
                throw new RuntimeException('A configured scope contains an invalid allowed domain.');
            }

            $allowFile = 'allow-' . $kind . '-' . $identifier . '.txt';
            $allowFiles[$allowFile] = $allowResult['domains'];
            $scope = [
                'lists' => $effectiveListIdentifiers,
                'allow' => $allowFile,
            ];

            if ($kind === 'network') {
                $interface = is_string($row['interface'] ?? null) ? $row['interface'] : '';

                if ($interface === '') {
                    throw new RuntimeException('A configured network scope interface is invalid.');
                }

                $scope = [
                    'interface' => $interface,
                    'lists' => $effectiveListIdentifiers,
                    'allow' => $allowFile,
                ];
            }

            $scopes[$identifier] = $scope;
        }

        ksort($scopes, SORT_STRING);

        return $scopes;
    }

    /**
     * Compiler - Normalize Alerts.
     *
     * Alert rules refer only to lists and client scopes already present in the
     * effective blocking manifest. They never make an otherwise unused list part of
     * a generation.
     *
     * @param mixed $value - Configured alert rules.
     * @param array<string, array> $configuredLists - Every configured list.
     * @param array<string, array{name: string, bit: int}> $manifestLists - Effective lists.
     * @param array<string, array> $networkScopes - Effective network scopes.
     * @param array<string, array> $deviceScopes - Effective device scopes.
     *
     * @return array<string, array{id: string, lists: string|list<int>, networks: string|list<string>, devices: string|list<string>}>
     *
     * @since 1.0.0
     * @private
     */
    private function normalizeAlerts(
        mixed $value,
        array $configuredLists,
        array $manifestLists,
        array $networkScopes,
        array $deviceScopes,
    ): array {
        if ($value === null || $value === '') {
            return [];
        }

        if (!is_array($value)) {
            throw new RuntimeException('Configured alert rules are invalid.');
        }

        $alerts = [];

        foreach ($value as $row) {
            if (!is_array($row)) {
                throw new RuntimeException('A configured alert rule is invalid.');
            }

            $enabled = ($row['enabled'] ?? false) === true || ($row['enabled'] ?? '') === 'on';

            if ($enabled === false) {
                continue;
            }

            $identifier = is_string($row['id'] ?? null) ? $row['id'] : '';

            if (preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1 || isset($alerts[$identifier])) {
                throw new RuntimeException('A configured alert rule identifier is invalid.');
            }

            $anyList = ($row['any_list'] ?? false) === true
                || ($row['lists_any'] ?? false) === true
                || ($row['lists_any'] ?? '') === 'on';

            if ($anyList) {
                if (count($manifestLists) === 0) {
                    continue;
                }

                $alertLists = 'any';
            } else {
                $selectedLists = $row['lists'] ?? [];

                if (!is_array($selectedLists)) {
                    throw new RuntimeException('A configured alert list selection is invalid.');
                }

                $bits = [];

                foreach ($selectedLists as $listIdentifier) {
                    if (!is_string($listIdentifier) || !isset($configuredLists[$listIdentifier])) {
                        throw new RuntimeException('A configured alert references an unknown block list.');
                    }

                    if (isset($manifestLists[$listIdentifier])) {
                        $bits[$manifestLists[$listIdentifier]['bit']] = true;
                    }
                }

                $alertLists = array_keys($bits);
                sort($alertLists, SORT_NUMERIC);

                if (count($alertLists) === 0) {
                    continue;
                }
            }

            $everyone = ($row['everyone'] ?? false) === true
                || ($row['clients_everyone'] ?? false) === true
                || ($row['clients_everyone'] ?? '') === 'on';

            if ($everyone) {
                $alertNetworks = 'any';
                $alertDevices = 'any';
            } else {
                $alertNetworks = $this->effectiveAlertScopeIdentifiers(
                    $row['networks'] ?? [],
                    $networkScopes,
                );
                $alertDevices = $this->effectiveAlertScopeIdentifiers(
                    $row['devices'] ?? [],
                    $deviceScopes,
                );

                if (count($alertNetworks) === 0 && count($alertDevices) === 0) {
                    continue;
                }
            }

            $alerts[$identifier] = [
                'id' => $identifier,
                'lists' => $alertLists,
                'networks' => $alertNetworks,
                'devices' => $alertDevices,
            ];
        }

        ksort($alerts, SORT_STRING);

        return $alerts;
    }

    /**
     * Compiler - Effective Alert Scope Identifiers.
     *
     * @param mixed $value - Selected scope IDs.
     * @param array<string, array> $effectiveScopes - Effective compiled scopes.
     *
     * @return list<string>
     *
     * @since 1.0.0
     * @private
     */
    private function effectiveAlertScopeIdentifiers(mixed $value, array $effectiveScopes): array
    {
        if (!is_array($value)) {
            throw new RuntimeException('A configured alert client selection is invalid.');
        }

        $identifiers = [];

        foreach ($value as $identifier) {
            if (!is_string($identifier) || preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1) {
                throw new RuntimeException('A configured alert client selection is invalid.');
            }

            if (isset($effectiveScopes[$identifier])) {
                $identifiers[$identifier] = true;
            }
        }

        $identifiers = array_keys($identifiers);
        sort($identifiers, SORT_STRING);

        return $identifiers;
    }

    /**
     * Compiler - Content Digest.
     *
     * Hashes only effective domain, allow, list, and scope content. Generation IDs
     * and timestamps are intentionally excluded so identical output is a no-op.
     *
     * @param string $buildDirectory - Complete compiler output directory.
     * @param array  $digestManifest - Lists and scopes manifest fragment.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private function contentDigest(string $buildDirectory, array $digestManifest): string
    {
        try {
            $manifestContents = json_encode(
                $digestManifest,
                JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $exception) {
            throw new RuntimeException('Unable to encode the compiled digest.', 0, $exception);
        }

        $context = hash_init('sha256');
        hash_update($context, "domains.tsv\0");

        if (hash_update_file($context, $buildDirectory . '/domains.tsv') === false) {
            throw new RuntimeException('Unable to hash compiled domains data.');
        }

        hash_update($context, "\0bypass.tsv\0");

        if (hash_update_file($context, $buildDirectory . '/bypass.tsv') === false) {
            throw new RuntimeException('Unable to hash compiled Bypass data.');
        }

        $allowFiles = ['allow.txt' => true];

        foreach (['networks', 'devices'] as $scopeType) {
            $scopes = $digestManifest['scopes'][$scopeType] ?? [];

            foreach ((array) $scopes as $scope) {
                if (is_array($scope) && is_string($scope['allow'] ?? null)) {
                    $allowFiles[$scope['allow']] = true;
                }
            }
        }

        $allowFileNames = array_keys($allowFiles);
        sort($allowFileNames, SORT_STRING);

        foreach ($allowFileNames as $allowFile) {
            hash_update($context, "\0" . $allowFile . "\0");

            if (hash_update_file($context, $buildDirectory . '/' . $allowFile) === false) {
                throw new RuntimeException('Unable to hash compiled allow data.');
            }
        }

        hash_update($context, "\0manifest\0" . $manifestContents);

        return hash_final($context);
    }

    /**
     * Compiler - Deploy Generation.
     *
     * Serializes runtime mutations, removes fixed crash leftovers, verifies every
     * target has room for the new copy plus headroom, and skips identical output.
     *
     * @param string $buildDirectory - Complete compiler output.
     * @param string $contentDigest  - Effective-content digest.
     * @param bool   $mirrorRuntime  - Whether a persistent boot mirror is required.
     *
     * @return array{
     *     generation: string,
     *     changed: bool,
     *     deployed: bool,
     *     added_names: int,
     *     deployment_current: bool
     * }
     *
     * @since 1.0.0
     * @private
     */
    private function deployGeneration(
        string $buildDirectory,
        string $contentDigest,
        bool $mirrorRuntime,
    ): array {
        FileSystem::ensureOwnedDirectoryIfMissing(
            $this->paths->runtimeRootDirectory,
            0755,
            $this->paths->runtimeUser,
            $this->paths->runtimeGroup,
        );
        FileSystem::ensureOwnedDirectory(
            $this->paths->runtimeStorageDirectory,
            0755,
            $this->paths->storageUser,
            $this->paths->storageGroup,
        );
        $this->sweepDeploymentLeftovers($this->paths->runtimeStorageDirectory);

        if ($mirrorRuntime) {
            FileSystem::ensureDirectory($this->paths->mirrorRootDirectory, 0700);
            FileSystem::ensureOwnedDirectory(
                $this->paths->mirrorStorageDirectory,
                0700,
                $this->paths->storageUser,
                $this->paths->storageGroup,
            );
            $this->sweepDeploymentLeftovers($this->paths->mirrorStorageDirectory);
            FileSystem::sweepStaleEntries(
                $this->paths->mirrorRootDirectory,
                ['.sinkhole-atomic-'],
            );
        }

        $runtimeManifest = $this->activeManifest(
            $this->paths->runtimeDataDirectory,
            $this->paths->runtimeStorageDirectory,
        );
        $mirrorManifest = $mirrorRuntime
            ? $this->activeManifest(
                $this->paths->mirrorDataDirectory,
                $this->paths->mirrorStorageDirectory,
            )
            : null;
        $runtimeMatches = ($runtimeManifest['content_digest'] ?? null) === $contentDigest;
        $mirrorMatches = $mirrorRuntime === false
            || ($mirrorManifest['content_digest'] ?? null) === $contentDigest;

        if ($runtimeMatches) {
            if ($mirrorRuntime && $mirrorMatches === false) {
                $runtimeGenerationPath = FileSystem::resolveManagedGeneration(
                    $this->paths->runtimeDataDirectory,
                    $this->paths->runtimeStorageDirectory,
                );

                if ($runtimeGenerationPath === null) {
                    throw new RuntimeException('The active runtime generation is invalid.');
                }

                $runtimeSize = FileSystem::directorySize($runtimeGenerationPath);
                $this->assertDeploymentSpace(
                    $this->paths->mirrorStorageDirectory,
                    $runtimeSize,
                );
                $this->deploy(
                    $runtimeGenerationPath,
                    $this->paths->mirrorStorageDirectory,
                    $this->paths->mirrorDataDirectory,
                    0700,
                    0600,
                );
            } elseif ($mirrorRuntime === false) {
                FileSystem::removeDirectory($this->paths->mirrorRootDirectory);
            }

            return [
                'generation' => (string) $runtimeManifest['generation'],
                'changed' => false,
                'deployed' => false,
                'added_names' => 0,
                'deployment_current' => true,
            ];
        }

        $runtimeGenerationPath = FileSystem::resolveManagedGeneration(
            $this->paths->runtimeDataDirectory,
            $this->paths->runtimeStorageDirectory,
        );
        $previousDomainsPath = ($runtimeGenerationPath === null)
            ? null
            : $runtimeGenerationPath . '/domains.tsv';
        $previousBypassPath = ($runtimeGenerationPath === null)
            ? null
            : $runtimeGenerationPath . '/bypass.tsv';
        $addedNames = $this->countAddedNames(
            $buildDirectory . '/domains.tsv',
            $previousDomainsPath,
        );
        $addedNames += $this->countAddedNames(
            $buildDirectory . '/bypass.tsv',
            $previousBypassPath,
        );
        $buildSize = FileSystem::directorySize($buildDirectory);
        $this->assertDeploymentSpace($this->paths->runtimeStorageDirectory, $buildSize);

        if ($mirrorRuntime) {
            $this->assertDeploymentSpace($this->paths->mirrorStorageDirectory, $buildSize);
            $this->deploy(
                $buildDirectory,
                $this->paths->mirrorStorageDirectory,
                $this->paths->mirrorDataDirectory,
                0700,
                0600,
            );
        }

        $this->deploy(
            $buildDirectory,
            $this->paths->runtimeStorageDirectory,
            $this->paths->runtimeDataDirectory,
            0755,
            0644,
        );

        if ($mirrorRuntime === false) {
            FileSystem::removeDirectory($this->paths->mirrorRootDirectory);
        }

        $generationContents = file_get_contents($buildDirectory . '/generation');

        if ($generationContents === false) {
            throw new RuntimeException('Unable to read the compiled generation.');
        }

        return [
            'generation' => trim($generationContents),
            'changed' => true,
            'deployed' => true,
            'added_names' => $addedNames,
            'deployment_current' => true,
        ];
    }

    /**
     * Compiler - Active Manifest.
     *
     * Reads only a regular manifest below a validated managed generation link.
     *
     * @param string $activePath  - Active generation link.
     * @param string $storagePath - Root-owned generation storage.
     *
     * @return array|null
     *
     * @since 1.0.0
     * @private
     */
    private function activeManifest(string $activePath, string $storagePath): ?array
    {
        $generationPath = FileSystem::resolveManagedGeneration($activePath, $storagePath);

        if ($generationPath === null) {
            return null;
        }

        $generationStatus = @lstat($generationPath);
        $manifestPath = $generationPath . '/manifest.json';

        if (
            !is_array($generationStatus)
            || ($generationStatus['mode'] & 0170000) !== 0040000
            || FileSystem::isRegularFile($manifestPath) === false
        ) {
            return null;
        }

        $contents = file_get_contents($manifestPath);

        if ($contents === false) {
            return null;
        }

        try {
            $manifest = json_decode($contents, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (
            !is_array($manifest)
            || !is_string($manifest['generation'] ?? null)
            || preg_match('/^[a-f0-9]{64}$/D', $manifest['content_digest'] ?? '') !== 1
        ) {
            return null;
        }

        return $manifest;
    }

    /**
     * Compiler - Count Added Names.
     *
     * Both compiler files are sorted, so a streaming merge reports names absent from
     * the previous runtime and rows whose subtree column became nonempty without
     * loading either generation into memory or comparing generation-specific bits.
     *
     * @param string      $newPath      - New compiled domains path.
     * @param string|null $previousPath - Previous runtime domains path.
     *
     * @return int
     *
     * @since 1.0.0
     * @private
     */
    private function countAddedNames(string $newPath, ?string $previousPath): int
    {
        if (
            $previousPath === null
            || FileSystem::isRegularFile($previousPath) === false
        ) {
            return $this->countCompiledNames($newPath);
        }

        $newHandle = fopen($newPath, 'rb');
        $previousHandle = fopen($previousPath, 'rb');

        if ($newHandle === false || $previousHandle === false) {
            if (is_resource($newHandle)) {
                fclose($newHandle);
            }

            if (is_resource($previousHandle)) {
                fclose($previousHandle);
            }

            return $this->countCompiledNames($newPath);
        }

        try {
            $addedNames = 0;
            $newRow = $this->readCompiledRow($newHandle);
            $previousRow = $this->readCompiledRow($previousHandle);

            while ($newRow !== null) {
                while (
                    $previousRow !== null
                    && strcmp($previousRow['domain'], $newRow['domain']) < 0
                ) {
                    $previousRow = $this->readCompiledRow($previousHandle);
                }

                if (
                    $previousRow === null
                    || $previousRow['domain'] !== $newRow['domain']
                    || (
                        $newRow['subtree']
                        && $previousRow['subtree'] === false
                    )
                ) {
                    $addedNames++;
                }

                $newRow = $this->readCompiledRow($newHandle);
            }

            return $addedNames;
        } catch (RuntimeException) {
            return $this->countCompiledNames($newPath);
        } finally {
            fclose($newHandle);
            fclose($previousHandle);
        }
    }

    /**
     * Compiler - Count Compiled Names.
     *
     * A missing or unreadable previous generation makes every new name an addition,
     * which safely requests a cache clear after runtime recovery.
     *
     * @param string $path - Compiled domains path.
     *
     * @return int
     *
     * @since 1.0.0
     * @private
     */
    private function countCompiledNames(string $path): int
    {
        $handle = fopen($path, 'rb');

        if ($handle === false) {
            throw new RuntimeException('Unable to count compiled domain names.');
        }

        $count = 0;

        try {
            while ($this->readCompiledRow($handle) !== null) {
                $count++;
            }
        } finally {
            fclose($handle);
        }

        return $count;
    }

    /**
     * Compiler - Read Compiled Row.
     *
     * Reads the sorted owner and subtree-column presence needed by the deployment
     * comparison, without comparing generation-specific list bit numbers.
     *
     * @param mixed $handle - Open domains file.
     *
     * @return array{domain: string, subtree: bool}|null
     *
     * @since 1.0.0
     * @private
     */
    private function readCompiledRow(mixed $handle): ?array
    {
        $line = fgets($handle);

        if ($line === false) {
            if (feof($handle)) {
                return null;
            }

            throw new RuntimeException('Unable to read compiled domain names.');
        }

        $fields = explode("\t", rtrim($line, "\r\n"));

        if (count($fields) !== 3 || $fields[0] === '') {
            throw new RuntimeException('A compiled domain row is invalid.');
        }

        return [
            'domain' => $fields[0],
            'subtree' => $fields[2] !== '',
        ];
    }

    /**
     * Compiler - Assert Deployment Space.
     *
     * @param string $targetPath - Target filesystem path.
     * @param int    $buildSize  - New generation size in bytes.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function assertDeploymentSpace(string $targetPath, int $buildSize): void
    {
        $available = $this->availableSpaceOverride ?? disk_free_space($targetPath);

        if (!is_int($available) && !is_float($available)) {
            throw new RuntimeException('Unable to determine available deployment space.');
        }

        $required = $buildSize + (10 * 1024 * 1024);

        if ($available < $required) {
            throw new RuntimeException(sprintf(
                'Not enough deployment space: %.2f MiB required, %.2f MiB available.',
                $required / 1048576,
                $available / 1048576,
            ));
        }
    }

    /**
     * Compiler - Sweep Deployment Leftovers.
     *
     * @param string $storagePath - Package-owned generation storage.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function sweepDeploymentLeftovers(string $storagePath): void
    {
        FileSystem::sweepStaleEntries(
            $storagePath,
            [
                '.sinkhole-new-',
                '.sinkhole-restore-',
                '.sinkhole-link-',
                '.sinkhole-module-',
                '.sinkhole-atomic-',
            ],
        );
    }

    /**
     * Compiler - Write Chunk.
     *
     * Sorts and deduplicates one bounded record batch before the k-way merge.
     *
     * @param string       $directory - Chunk directory.
     * @param list<string> $records   - Unsorted records.
     *
     * @return string
     *
     * @throws RuntimeException When the chunk cannot be written.
     *
     * @since 1.0.0
     * @private
     */
    private function writeChunk(string $directory, array $records): string
    {
        sort($records, SORT_STRING);
        $records = array_values(array_unique($records));
        $path = FileSystem::createTemporaryFile($directory, 'chunk-', 0600);
        $contents = implode(PHP_EOL, $records) . PHP_EOL;

        if (file_put_contents($path, $contents, LOCK_EX) !== strlen($contents)) {
            throw new RuntimeException('Unable to write a compiler chunk.');
        }

        return $path;
    }

    /**
     * Compiler - Merge Chunks.
     *
     * Streams sorted chunks into one row per unique domain with separate exact and
     * subtree list-bit columns.
     *
     * @param list<string> $chunkPaths - Sorted chunk paths.
     * @param string       $outputPath - Domains output path.
     *
     * @return int
     *
     * @throws RuntimeException When a chunk or output cannot be processed.
     *
     * @since 1.0.0
     * @private
     */
    private function mergeChunks(array $chunkPaths, string $outputPath): int
    {
        $previousMask = umask(0177);

        try {
            $outputHandle = fopen($outputPath, 'x+b');
        } finally {
            umask($previousMask);
        }

        if ($outputHandle === false) {
            throw new RuntimeException('Unable to create compiled domains data.');
        }

        $handles = [];
        $currentRecords = [];
        $domainCount = 0;
        $currentDomain = null;
        $exactBits = [];
        $subtreeBits = [];

        try {
            foreach ($chunkPaths as $index => $chunkPath) {
                $handle = fopen($chunkPath, 'rb');

                if ($handle === false) {
                    throw new RuntimeException('Unable to read a compiler chunk.');
                }

                $handles[$index] = $handle;
                $record = fgets($handle);

                if ($record !== false) {
                    $currentRecords[$index] = rtrim($record, "\r\n");
                }
            }

            while (count($currentRecords) > 0) {
                $smallestIndex = null;
                $smallestRecord = null;

                foreach ($currentRecords as $index => $record) {
                    if ($smallestRecord === null || strcmp($record, $smallestRecord) < 0) {
                        $smallestIndex = $index;
                        $smallestRecord = $record;
                    }
                }

                if ($smallestIndex === null || $smallestRecord === null) {
                    throw new RuntimeException('Unable to merge compiler chunks.');
                }

                $fields = explode("\t", $smallestRecord);

                if (
                    count($fields) !== 3
                    || preg_match('/^(?:0|[1-9][0-9]*)$/D', $fields[2]) !== 1
                ) {
                    throw new RuntimeException('A compiler record is invalid.');
                }

                $domain = $fields[0];
                $semantic = $fields[1];
                $bit = $fields[2];

                if ($currentDomain !== null && $domain !== $currentDomain) {
                    if ($domainCount >= self::MAXIMUM_UNIQUE_NAMES) {
                        throw new RuntimeException(
                            'The compile exceeds the 2,000,000 unique-name limit.',
                        );
                    }

                    $this->writeDomainRow($outputHandle, $currentDomain, $exactBits, $subtreeBits);
                    $domainCount++;
                    $exactBits = [];
                    $subtreeBits = [];
                }

                $currentDomain = $domain;

                if ($semantic === DomainParser::EXACT) {
                    $exactBits[$bit] = true;
                } elseif ($semantic === DomainParser::SUBTREE) {
                    $subtreeBits[$bit] = true;
                } else {
                    throw new RuntimeException('A compiler semantic is invalid.');
                }

                $nextRecord = fgets($handles[$smallestIndex]);

                if ($nextRecord === false) {
                    unset($currentRecords[$smallestIndex]);
                } else {
                    $currentRecords[$smallestIndex] = rtrim($nextRecord, "\r\n");
                }
            }

            if ($currentDomain !== null) {
                if ($domainCount >= self::MAXIMUM_UNIQUE_NAMES) {
                    throw new RuntimeException(
                        'The compile exceeds the 2,000,000 unique-name limit.',
                    );
                }

                $this->writeDomainRow($outputHandle, $currentDomain, $exactBits, $subtreeBits);
                $domainCount++;
            }

            if (fflush($outputHandle) === false) {
                throw new RuntimeException('Unable to flush compiled domains data.');
            }
        } finally {
            foreach ($handles as $handle) {
                fclose($handle);
            }

            fclose($outputHandle);
        }

        return $domainCount;
    }

    /**
     * Compiler - Write Domain Row.
     *
     * Sorts numeric memberships so deterministic input produces deterministic TSV.
     *
     * @param mixed               $handle      - Open output resource.
     * @param string              $domain      - Normalized domain.
     * @param array<string, bool> $exactBits   - Exact memberships.
     * @param array<string, bool> $subtreeBits - Subtree memberships.
     *
     * @return void
     *
     * @throws RuntimeException When the row cannot be written.
     *
     * @since 1.0.0
     * @private
     */
    private function writeDomainRow(
        mixed $handle,
        string $domain,
        array $exactBits,
        array $subtreeBits,
    ): void {
        $exact = array_keys($exactBits);
        $subtree = array_keys($subtreeBits);

        sort($exact, SORT_NUMERIC);
        sort($subtree, SORT_NUMERIC);

        $row = implode("\t", [$domain, implode(',', $exact), implode(',', $subtree)]) . PHP_EOL;

        if (fwrite($handle, $row) !== strlen($row)) {
            throw new RuntimeException('Unable to write compiled domains data.');
        }
    }

    /**
     * Compiler - Deploy.
     *
     * Copies build output into the root-owned generation area and atomically replaces
     * the relative active link visible from Unbound's chroot.
     *
     * @param string $buildDirectory - Complete compiler output.
     * @param string $storagePath    - Generation storage directory.
     * @param string $targetPath     - Active target link.
     * @param int    $directoryMode  - Target directory mode.
     * @param int    $fileMode       - Target file mode.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function deploy(
        string $buildDirectory,
        string $storagePath,
        string $targetPath,
        int $directoryMode,
        int $fileMode,
    ): void {
        $temporaryPath = FileSystem::createTemporaryDirectory(
            $storagePath,
            '.sinkhole-new-',
            $directoryMode,
        );

        try {
            FileSystem::copyDirectory(
                $buildDirectory,
                $temporaryPath,
                $directoryMode,
                $fileMode,
            );

            FileSystem::activateDirectory($temporaryPath, $storagePath, $targetPath);
        } finally {
            if (is_dir($temporaryPath)) {
                FileSystem::removeDirectory($temporaryPath);
            }
        }
    }
}
