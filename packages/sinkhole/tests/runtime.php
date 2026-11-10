<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\IpNetwork;
use PfSense\Sinkhole\Runtime\AtomicFile;
use PfSense\Sinkhole\Runtime\ClientMap;
use PfSense\Sinkhole\Runtime\ClientSource;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\DownloadClient;
use PfSense\Sinkhole\Runtime\FileLock;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\PlatformAdapter;
use PfSense\Sinkhole\Runtime\SavedListStore;
use PfSense\Sinkhole\Runtime\StateStore;
use PfSense\Sinkhole\Runtime\UpdateLockRunner;
use PfSense\Sinkhole\Runtime\Updater;
use PfSense\Sinkhole\Domain\ScopeConfiguration;

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/AtomicFile.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ClientSource.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ClientMap.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Compiler.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/DomainParser.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/DownloadClient.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/FileSystem.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/PackagePaths.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/PlatformAdapter.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/SavedListStore.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/StateStore.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Updater.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ScopeConfiguration.php');

/**
 * Sinkhole Runtime Test - Platform Adapter.
 *
 * @since 1.0.0
 */
final class SinkholeRuntimeTestPlatformAdapter implements PlatformAdapter
{
    /**
     * Sinkhole Runtime Test - Reloaded Generations.
     *
     * @var list<string>
     *
     * @since 1.0.0
     */
    public array $reloadedGenerations = [];

    /**
     * Sinkhole Runtime Test - Synchronization Count.
     *
     * @var int
     *
     * @since 1.0.0
     */
    public int $synchronizationCount = 0;

    /**
     * Sinkhole Runtime Test - Refresh Count.
     *
     * @var int
     *
     * @since 1.0.0
     */
    public int $refreshCount = 0;

    /**
     * Sinkhole Runtime Test - Reload Failures Remaining.
     *
     * @var int
     *
     * @since 1.0.0
     */
    public int $reloadFailuresRemaining = 0;

    /**
     * Sinkhole Runtime Test - Log Messages.
     *
     * @var list<string>
     *
     * @since 1.0.0
     */
    public array $logs = [];

    /**
     * Sinkhole Runtime Test - Platform Adapter Constructor.
     *
     * @param array $settings - General settings.
     * @param array $lists - Configured lists.
     * @param array $allowedDomains - Allowed domains.
     * @param bool $integrationActive - Whether deployment is active.
     * @param bool $runtimeMissing - Whether active runtime data is missing.
     * @param bool $stopRequested - Whether package removal requested a stop.
     * @param array|null $refreshedLists - Lists exposed after a configuration refresh.
     * @param array $networks - Valid network scopes.
     * @param array $devices - Valid device scopes.
     * @param array $alerts - Valid alert rules.
     * @param array $services - Per-scope blocked services.
     *
     * @since 1.0.0
     */
    public function __construct(
        private array $settings,
        private array $lists,
        private readonly array $allowedDomains = [],
        private readonly bool $integrationActive = true,
        private readonly bool $runtimeMissing = false,
        private readonly bool $stopRequested = false,
        private readonly ?array $refreshedLists = null,
        private readonly array $networks = [],
        private readonly array $devices = [],
        private readonly array $alerts = [],
        private readonly array $services = [],
    ) {
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function assertEnvironment(): void
    {
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function getSettings(): array
    {
        return $this->settings;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function getLists(): mixed
    {
        return $this->lists;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function getAllowedDomains(): array
    {
        return $this->allowedDomains;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function getBypassConfiguration(): array
    {
        return [
            'enabled' => false,
            'dns_enabled' => false,
            'firewall_enabled' => false,
            'interfaces' => [],
            'block_tls_quic' => false,
            'block_encrypted_dns' => false,
            'disable_firefox_doh' => false,
            'disable_private_relay' => false,
            'discovery' => 'off',
            'block_tor' => false,
            'block_vpn' => false,
            'block_vpn_ports' => false,
            'lists' => [],
            'invalid_values' => [],
            'invalid_lists' => [],
            'discovery_hostname' => '',
            'discovery_port' => 0,
        ];
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function getNetworks(): array
    {
        return $this->networks;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function getDevices(): array
    {
        return $this->devices;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function getAlerts(): array
    {
        return $this->alerts;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function getBlockedServices(): array
    {
        return $this->services;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function refreshConfiguration(): void
    {
        $this->refreshCount++;

        if ($this->refreshedLists !== null) {
            $this->lists = $this->refreshedLists;
        }
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function usesMemoryFileSystem(): bool
    {
        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function isIntegrationActive(): bool
    {
        return $this->integrationActive;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function runtimeGenerationMissing(): bool
    {
        return $this->runtimeMissing;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function updateShouldStop(): bool
    {
        return $this->stopRequested;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function synchronizeIntegrationUnderLock(): void
    {
        $this->synchronizationCount++;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function reloadUnboundAfterDeploy(string $generation): void
    {
        if ($this->reloadFailuresRemaining > 0) {
            $this->reloadFailuresRemaining--;

            throw new RuntimeException('Simulated Unbound reload failure.');
        }

        $this->reloadedGenerations[] = $generation;
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function log(string $message): void
    {
        $this->logs[] = $message;
    }
}

/**
 * Sinkhole Runtime Test - Client Source.
 *
 * Supplies deterministic local fixtures without pfSense or network access.
 *
 * @since 1.0.0
 */
final class SinkholeRuntimeTestClientSource implements ClientSource
{
    /** @var list<string> @since 1.0.0 */
    public array $logs = [];

    /** @since 1.0.0 */
    public function __construct(
        public array $networks = [],
        public array $devices = [],
        public array $subnets = [],
        public array $mappings = [],
        public array $arp = [],
        public string $ndp = '',
        public array $leases = [],
        public bool $memoryFileSystem = false,
        public array $leaseContext = [
            'times_local' => false,
            'active' => 'active',
            'expired' => 'expired',
            'reserved' => 'reserved',
            'never' => 'Never',
        ],
        public array $bypassInterfaces = [],
        public array $interfaceAddresses = [],
    ) {
    }

    /** @inheritDoc @since 1.0.0 */
    public function getNetworks(): array
    {
        return $this->networks;
    }

    /** @inheritDoc @since 1.0.0 */
    public function getDevices(): array
    {
        return $this->devices;
    }

    /** @inheritDoc @since 1.0.0 */
    public function getInterfaceSubnets(): array
    {
        return $this->subnets;
    }

    /** @inheritDoc @since 1.0.0 */
    public function getInterfaceAddresses(): array
    {
        return $this->interfaceAddresses;
    }

    /** @inheritDoc @since 1.0.0 */
    public function getBypassInterfaces(): array
    {
        return $this->bypassInterfaces;
    }

    /** @inheritDoc @since 1.0.0 */
    public function getStaticMappings(): array
    {
        return $this->mappings;
    }

    /** @inheritDoc @since 1.0.0 */
    public function getArpEntries(): array
    {
        return $this->arp;
    }

    /** @inheritDoc @since 1.0.0 */
    public function getNdpOutput(): string
    {
        return $this->ndp;
    }

    /** @inheritDoc @since 1.0.0 */
    public function getDhcpLeases(): array
    {
        return $this->leases;
    }

    /** @inheritDoc @since 1.0.0 */
    public function getDhcpLeaseContext(): array
    {
        return $this->leaseContext;
    }

    /** @inheritDoc @since 1.0.0 */
    public function usesMemoryFileSystem(): bool
    {
        return $this->memoryFileSystem;
    }

    /** @inheritDoc @since 1.0.0 */
    public function log(string $message): void
    {
        $this->logs[] = $message;
    }
}

/**
 * Sinkhole Runtime Test - Download Client.
 *
 * @since 1.0.0
 */
final class SinkholeRuntimeTestDownloadClient implements DownloadClient
{
    /**
     * Sinkhole Runtime Test - Calls.
     *
     * @var int
     *
     * @since 1.0.0
     */
    public int $calls = 0;

    /**
     * Sinkhole Runtime Test - Download Client Constructor.
     *
     * @param string $mode - Failure mode.
     *
     * @since 1.0.0
     */
    public function __construct(private readonly string $mode)
    {
    }

    /**
     * {@inheritDoc}
     *
     * @since 1.0.0
     */
    public function download(
        string $url,
        string $destinationPath,
        int $maximumBytes,
        ?string $username = null,
        ?string $password = null,
    ): array {
        unset($url);
        $this->calls++;

        if ($this->mode === 'failed') {
            return [
                'success' => false,
                'bytes' => 0,
                'error' => 'Simulated failure.',
            ];
        }

        if ($this->mode === 'empty') {
            file_put_contents($destinationPath, '');

            return [
                'success' => true,
                'bytes' => 0,
                'error' => null,
            ];
        }

        if ($this->mode === 'success') {
            $contents = "0.0.0.0 downloaded.example.test\n";

            file_put_contents($destinationPath, $contents);

            return [
                'success' => true,
                'bytes' => strlen($contents),
                'error' => null,
            ];
        }

        file_put_contents($destinationPath, 'oversized');

        return [
            'success' => true,
            'bytes' => $maximumBytes + 1,
            'error' => null,
        ];
    }
}

/**
 * Sinkhole Runtime Test - Paths.
 *
 * @param string $root - Test root.
 *
 * @return PackagePaths
 *
 * @since 1.0.0
 */
function sinkholeRuntimeTestPaths(string $root): PackagePaths
{
    return new PackagePaths([
        'persistent_directory' => $root . '/persistent',
        'runtime_root_directory' => $root . '/runtime',
        'module_source_file' => $root . '/source/sinkhole_unbound.py',
        'update_lock_file' => $root . '/sinkhole-update.lock',
        'runtime_lock_file' => $root . '/sinkhole-runtime.lock',
        'client_lock_file' => $root . '/sinkhole-clients.lock',
        'alert_lock_file' => $root . '/sinkhole-alerts.lock',
        'alert_repeat_state_file' => $root . '/sinkhole-alerts.json',
        'command' => '/usr/local/sbin/sinkhole',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/**
 * Sinkhole Runtime Test - Save Normalized List.
 *
 * @param SavedListStore $store - Store.
 * @param string $identifier - Stable identifier.
 * @param string $contents - Normalized contents.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeRuntimeTestSaveList(
    SavedListStore $store,
    string $identifier,
    string $contents,
): void {
    $temporaryPath = $store->createTemporaryFile('.test-list-');
    file_put_contents($temporaryPath, $contents);
    $store->commitSuccessfulDownload(
        $identifier,
        $temporaryPath,
        [
            'url' => 'https://lists.example.invalid/' . $identifier . '.test',
            'fetched_at' => '2026-01-01T00:00:00+00:00',
            'entries' => substr_count($contents, "\n"),
            'sha256' => hash('sha256', $contents),
            'last_attempt' => '2026-01-01T00:00:00+00:00',
            'last_error' => null,
        ],
    );
}

/**
 * Sinkhole Runtime Test - Load Compiled Rows.
 *
 * @param string $path - Compiled TSV path.
 *
 * @return array<string, array{exact: list<string>, subtree: list<string>}>
 *
 * @since 1.0.0
 */
function sinkholeRuntimeTestLoadRows(string $path): array
{
    $rows = [];
    $handle = fopen($path, 'rb');

    if ($handle === false) {
        throw new RuntimeException('Unable to open compiled test output.');
    }

    try {
        while (($line = fgets($handle)) !== false) {
            $fields = explode("\t", rtrim($line, "\r\n"));

            $rows[$fields[0]] = [
                'exact' => ($fields[1] === '') ? [] : explode(',', $fields[1]),
                'subtree' => ($fields[2] === '') ? [] : explode(',', $fields[2]),
            ];
        }
    } finally {
        fclose($handle);
    }

    return $rows;
}

/**
 * Sinkhole Runtime Test - Match Compiled Policy.
 *
 * @param string $name - Query name.
 * @param array<string, array{exact: list<string>, subtree: list<string>}> $rows - Rows.
 * @param list<string> $allowed - Allowed roots.
 *
 * @return bool
 *
 * @since 1.0.0
 */
function sinkholeRuntimeTestIsBlocked(string $name, array $rows, array $allowed): bool
{
    $labels = explode('.', $name);
    $parents = [];

    foreach (array_keys($labels) as $index) {
        $parents[] = implode('.', array_slice($labels, $index));
    }

    foreach ($parents as $parent) {
        if (in_array($parent, $allowed, true)) {
            return false;
        }
    }

    if (count($rows[$name]['exact'] ?? []) > 0) {
        return true;
    }

    foreach ($parents as $parent) {
        if (count($rows[$parent]['subtree'] ?? []) > 0) {
            return true;
        }
    }

    return false;
}

sinkholeTestRun([
    'atomic file replacement' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $path = $directory . '/value.txt';
            file_put_contents($path, 'old');
            AtomicFile::write($path, 'new');

            sinkholeTestAssertSame('new', file_get_contents($path), 'The complete value must replace the old one.');
            sinkholeTestAssertSame(
                ['.', '..', 'value.txt'],
                scandir($directory),
                'No temporary sibling may remain after replacement.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'compile output exact subtree and allow semantics' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $firstIdentifier = '11111111111111111111111111111111';
            $secondIdentifier = '22222222222222222222222222222222';
            sinkholeRuntimeTestSaveList(
                $store,
                $firstIdentifier,
                "E\texact.example.test\nS\ttree.example.test\n",
            );
            sinkholeRuntimeTestSaveList(
                $store,
                $secondIdentifier,
                "E\texact.example.test\n",
            );
            $lists = [
                $firstIdentifier => [
                    'id' => $firstIdentifier,
                    'descr' => 'First Example',
                    'url' => 'https://lists.example.invalid/first.test',
                    'enabled' => 'on',
                ],
                $secondIdentifier => [
                    'id' => $secondIdentifier,
                    'descr' => 'Second Example',
                    'url' => 'https://lists.example.invalid/second.test',
                    'enabled' => 'on',
                ],
            ];
            $result = (new Compiler($paths, $store))->compile(
                $lists,
                ['allowed.tree.example.test'],
                true,
            );
            $runtimeRows = sinkholeRuntimeTestLoadRows($paths->runtimeDataDirectory . '/domains.tsv');
            $mirrorRows = sinkholeRuntimeTestLoadRows($paths->mirrorDataDirectory . '/domains.tsv');
            $manifest = json_decode(
                (string) file_get_contents($paths->runtimeDataDirectory . '/manifest.json'),
                true,
                16,
                JSON_THROW_ON_ERROR,
            );

            sinkholeTestAssertSame(2, $result['domains'], 'The compiler must emit unique domains.');
            sinkholeTestAssertSame(
                2,
                $result['added_names'],
                'The first deployment must report every compiled name as added.',
            );
            sinkholeTestAssertTrue(
                is_link($paths->runtimeDataDirectory),
                'Runtime data must activate through an atomic symlink swap.',
            );
            sinkholeTestAssertTrue(
                is_link($paths->mirrorDataDirectory),
                'Mirrored data must activate through an atomic symlink swap.',
            );
            sinkholeTestAssertSame($runtimeRows, $mirrorRows, 'Runtime and persistent data must match.');
            sinkholeTestAssertSame(
                ['0', '1'],
                $runtimeRows['exact.example.test']['exact'],
                'Exact memberships must include both list bits.',
            );
            sinkholeTestAssertSame(
                [$firstIdentifier, $secondIdentifier],
                $manifest['scopes']['global']['lists'],
                'The manifest must retain scope-ready list membership.',
            );
            sinkholeTestAssertSame(
                "allowed.tree.example.test\n",
                file_get_contents($paths->runtimeDataDirectory . '/allow.txt'),
                'The compiler must emit the normalized allowlist.',
            );
            sinkholeTestAssertTrue(
                sinkholeRuntimeTestIsBlocked('exact.example.test', $runtimeRows, []),
                'The exact name must be blocked.',
            );
            sinkholeTestAssertSame(
                false,
                sinkholeRuntimeTestIsBlocked('child.exact.example.test', $runtimeRows, []),
                'An exact entry must not cover descendants.',
            );
            sinkholeTestAssertTrue(
                sinkholeRuntimeTestIsBlocked('child.tree.example.test', $runtimeRows, []),
                'A subtree entry must cover descendants.',
            );
            sinkholeTestAssertSame(
                false,
                sinkholeRuntimeTestIsBlocked(
                    'child.allowed.tree.example.test',
                    $runtimeRows,
                    ['allowed.tree.example.test'],
                ),
                'An allowed domain must cover descendants.',
            );
            sinkholeTestAssertSame(
                trim((string) file_get_contents($paths->runtimeDataDirectory . '/generation')),
                $manifest['generation'],
                'The generation stamp must match the manifest.',
            );
            sinkholeTestAssertSame(
                [],
                glob($paths->persistentDirectory . '/.compile-*') ?: [],
                'The compiler must remove its build directory.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'zero lists activate an object map and empty policy' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $compiler = new Compiler($paths, $store);
            $identifier = '44444444444444444444444444444444';
            sinkholeRuntimeTestSaveList($store, $identifier, "E\tprevious.example.test\n");
            $compiler->compile([
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Previous Example',
                    'url' => 'https://lists.example.invalid/previous.test',
                    'enabled' => 'on',
                ],
            ], []);
            $previousGeneration = trim(
                (string) file_get_contents($paths->runtimeDataDirectory . '/generation'),
            );
            $compiler->markNeeded();
            $result = $compiler->compile([], []);
            $manifestContents = (string) file_get_contents(
                $paths->runtimeDataDirectory . '/manifest.json',
            );
            $generationDirectories = glob(
                $paths->runtimeStorageDirectory . '/.sinkhole-generation-*',
                GLOB_ONLYDIR,
            );

            sinkholeTestAssertSame(0, $result['domains'], 'Zero lists must compile zero names.');
            sinkholeTestAssertSame(0, $result['lists'], 'Zero lists must compile zero list records.');
            sinkholeTestAssertSame(
                0,
                $result['added_names'],
                'Removing the final name must report no cache-clear additions.',
            );
            sinkholeTestAssertTrue(
                str_contains($manifestContents, '"lists": {}'),
                'The empty list map must be encoded as a JSON object.',
            );
            sinkholeTestAssertSame(
                '',
                file_get_contents($paths->runtimeDataDirectory . '/domains.tsv'),
                'The empty generation must contain no blocking rows.',
            );
            sinkholeTestAssertTrue(
                $previousGeneration !== $result['generation'],
                'Removing the final list must activate a new generation.',
            );
            sinkholeTestAssertSame(
                1,
                is_array($generationDirectories) ? count($generationDirectories) : 0,
                'Only the active runtime generation may remain after a swap.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'compile failure retains generation and pending retry' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $compiler = new Compiler($paths, $store, $stateStore);
            $successful = $compiler->compile([], []);
            $compiler->markNeeded();
            $threw = false;

            try {
                $compiler->compile([], ['invalid-.example.test']);
            } catch (RuntimeException) {
                $threw = true;
            }

            $status = $stateStore->compileStatus();

            sinkholeTestAssertTrue($threw, 'An invalid allow element must fail compilation.');
            sinkholeTestAssertSame(true, $status['needed'], 'A failed compile must remain pending.');
            sinkholeTestAssertTrue(
                is_string($status['error']) && $status['error'] !== '',
                'A failed compile must retain its Status-page reason.',
            );
            sinkholeTestAssertSame(
                $successful['generation'],
                trim((string) file_get_contents($paths->runtimeDataDirectory . '/generation')),
                'A failed compile must preserve the previous active generation.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'unknown state schema versions are invalid' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            mkdir(dirname($paths->stateFile), 0700, true);
            file_put_contents($paths->stateFile, "{\"schema_version\":2}\n");
            $threw = false;

            try {
                (new StateStore($paths->stateFile))->read();
            } catch (RuntimeException) {
                $threw = true;
            }

            sinkholeTestAssertTrue($threw, 'An unknown state schema must be rejected.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'widening an existing row counts as an added name' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $compiler = new Compiler($paths, $store, $stateStore);
            $identifier = '12121212121212121212121212121212';
            $lists = [
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Widening Example',
                    'url' => 'https://lists.example.invalid/widening.test',
                    'enabled' => 'on',
                ],
            ];
            sinkholeRuntimeTestSaveList(
                $store,
                $identifier,
                "E\twidened.example.test\n",
            );
            $initial = $compiler->compile($lists, []);
            $stateStore->clearCacheClearOwed($initial['generation']);
            sinkholeRuntimeTestSaveList(
                $store,
                $identifier,
                "S\twidened.example.test\n",
            );
            $compiler->markNeeded();
            $widened = $compiler->compile($lists, []);

            sinkholeTestAssertSame(
                1,
                $widened['added_names'],
                'Adding subtree coverage to an existing row must count as added.',
            );
            sinkholeTestAssertSame(
                $widened['generation'],
                $stateStore->cacheClearOwedGeneration(),
                'A widened deployment must leave a durable cache-clear handoff.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'updater success downloads compiles and activates' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $identifier = '55555555555555555555555555555555';
            $lists = [
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Downloaded Example',
                    'url' => 'https://lists.example.invalid/downloaded.test',
                    'enabled' => 'on',
                ],
            ];
            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                $lists,
            );
            $stateStore = new StateStore($paths->stateFile);
            $compiler = new Compiler($paths, $store, $stateStore);
            $result = (new Updater(
                $platform,
                new SinkholeRuntimeTestDownloadClient('success'),
                new DomainParser(),
                $store,
                $compiler,
                $stateStore,
            ))->run(true);
            $rows = sinkholeRuntimeTestLoadRows($paths->runtimeDataDirectory . '/domains.tsv');

            sinkholeTestAssertSame(1, $result['attempted'], 'The enabled list must be attempted.');
            sinkholeTestAssertSame(1, $result['updated'], 'The fake download must succeed.');
            sinkholeTestAssertSame(true, $result['compiled'], 'Pending data must compile.');
            sinkholeTestAssertSame(false, $compiler->isNeeded(), 'Successful compilation must clear retry state.');
            sinkholeTestAssertSame(
                ['0'],
                $rows['downloaded.example.test']['exact'],
                'The downloaded entry must use its list bit.',
            );
            sinkholeTestAssertTrue(
                is_link($paths->runtimeDataDirectory),
                'An active updater must deploy the compiled generation.',
            );
            sinkholeTestAssertSame(
                [$result['compiled'] ? trim((string) file_get_contents(
                    $paths->runtimeDataDirectory . '/generation',
                )) : ''],
                $platform->reloadedGenerations,
                'A deployment that adds a name must request one Unbound reload.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'failed empty and oversized downloads keep last good copy' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $identifier = '33333333333333333333333333333333';
            $original = "E\tprevious.example.test\n";
            sinkholeRuntimeTestSaveList($store, $identifier, $original);
            $lists = [
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Fallback Example',
                    'url' => 'https://lists.example.invalid/fallback.test',
                    'enabled' => 'on',
                ],
            ];
            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                $lists,
            );
            $stateStore = new StateStore($paths->stateFile);

            foreach (['failed', 'empty', 'oversized'] as $mode) {
                $updater = new Updater(
                    $platform,
                    new SinkholeRuntimeTestDownloadClient($mode),
                    new DomainParser(),
                    $store,
                    new Compiler($paths, $store, $stateStore),
                    $stateStore,
                );
                $result = $updater->run(true);

                sinkholeTestAssertSame(1, $result['failed'], 'The simulated ' . $mode . ' update must fail.');
                sinkholeTestAssertSame(
                    $original,
                    file_get_contents($store->savedCopyPath($identifier)),
                    'The ' . $mode . ' update must retain the last-good copy.',
                );
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'identical compile keeps the active generation' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $compiler = new Compiler($paths, $store);
            $first = $compiler->compile([], []);
            $stamp = file_get_contents($paths->runtimeDataDirectory . '/generation');
            $compiler->markNeeded();
            $second = $compiler->compile([], []);
            $compiler->markNeeded();
            $withMirror = $compiler->compile([], [], true);

            sinkholeTestAssertSame(
                $first['generation'],
                $second['generation'],
                'Identical effective content must retain the active generation.',
            );
            sinkholeTestAssertSame(false, $second['changed'], 'A no-op compile must report no swap.');
            sinkholeTestAssertSame(false, $second['deployed'], 'A no-op compile must not deploy.');
            sinkholeTestAssertSame(0, $second['added_names'], 'A no-op compile adds no names.');
            sinkholeTestAssertSame(
                $stamp,
                file_get_contents($paths->runtimeDataDirectory . '/generation'),
                'A no-op compile must leave the generation stamp unchanged.',
            );
            sinkholeTestAssertSame(
                $first['generation'],
                $withMirror['generation'],
                'Creating a missing boot mirror must retain the active runtime generation.',
            );
            sinkholeTestAssertSame(
                $stamp,
                file_get_contents($paths->mirrorDataDirectory . '/generation'),
                'A missing mirror must copy the active stamp instead of inventing one.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'compile request arriving during work remains pending' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $store = new SavedListStore($paths);
            $compiler = new Compiler($paths, $store, $stateStore);
            $capturedRequest = $stateStore->compileRequest();
            $newRequest = 0;

            $compiler->compile(
                [],
                [],
                false,
                false,
                static function () use ($stateStore, &$newRequest): array {
                    $newRequest = $stateStore->markCompileNeeded();

                    return [
                        'lists' => [],
                        'allowed_domains' => [],
                    ];
                },
            );
            $status = $stateStore->compileStatus();

            sinkholeTestAssertTrue(
                $newRequest > $capturedRequest,
                'Every change must increment the request counter.',
            );
            sinkholeTestAssertSame(true, $status['needed'], 'The newer request must remain pending.');
            sinkholeTestAssertSame(
                $capturedRequest,
                $status['compiled_request'],
                'Success may record only the counter captured at compile start.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'inactive compilation never touches runtime storage' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $result = (new Compiler($paths, $store))->compile([], [], false, false);

            sinkholeTestAssertSame(false, $result['deployed'], 'Inactive integration must not deploy.');
            sinkholeTestAssertSame(0, $result['added_names'], 'Inactive compilation adds no runtime names.');
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeRootDirectory),
                'Inactive compilation must not create anything under the Unbound root.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'deployment space failure preserves the active generation' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $first = (new Compiler($paths, $store, $stateStore))->compile([], []);
            $stateStore->markCompileNeeded();
            $threw = false;

            try {
                (new Compiler($paths, $store, $stateStore, 0))->compile(
                    [],
                    ['allowed.example.net'],
                );
            } catch (RuntimeException $exception) {
                $threw = true;
                sinkholeTestAssertContains(
                    'MiB required',
                    $exception->getMessage(),
                    'The space error must report required and available MiB.',
                );
            }

            sinkholeTestAssertTrue($threw, 'Insufficient target space must fail deployment.');
            sinkholeTestAssertSame(
                $first['generation'],
                trim((string) file_get_contents($paths->runtimeDataDirectory . '/generation')),
                'A space failure must keep the previous active generation.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'compile sweeps fixed leftovers and replaces a live link directly' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $compiler = new Compiler($paths, $store);
            $compiler->compile([], []);
            mkdir($paths->persistentDirectory . '/.compile-stale');

            foreach (
                [
                    '.sinkhole-new-stale',
                    '.sinkhole-restore-stale',
                    '.sinkhole-link-stale',
                    '.sinkhole-module-stale',
                    '.sinkhole-atomic-stale',
                ] as $entry
            ) {
                mkdir($paths->runtimeStorageDirectory . '/' . $entry);
            }

            $compiler->markNeeded();
            $result = $compiler->compile([], ['allowed.example.net']);

            sinkholeTestAssertSame(true, $result['deployed'], 'Changed content must deploy.');
            sinkholeTestAssertSame(
                [],
                glob($paths->persistentDirectory . '/.compile-*') ?: [],
                'Compile leftovers must be swept.',
            );

            foreach (
                [
                    '.sinkhole-new-*',
                    '.sinkhole-restore-*',
                    '.sinkhole-link-*',
                    '.sinkhole-module-*',
                    '.sinkhole-atomic-*',
                ] as $pattern
            ) {
                sinkholeTestAssertSame(
                    [],
                    glob($paths->runtimeStorageDirectory . '/' . $pattern) ?: [],
                    'The active-link swap must leave no fixed-prefix backup or temporary.',
                );
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'apply downloads only missing or URL changed copies' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $identifier = '77777777777777777777777777777777';
            $lists = [
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Apply Example',
                    'url' => 'https://lists.example.invalid/' . $identifier . '.test',
                    'enabled' => 'on',
                ],
            ];
            $client = new SinkholeRuntimeTestDownloadClient('success');
            $stateStore = new StateStore($paths->stateFile);
            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                $lists,
            );
            $updater = new Updater(
                $platform,
                $client,
                new DomainParser(),
                $store,
                new Compiler($paths, $store, $stateStore),
                $stateStore,
            );
            $first = $updater->run(false, true);
            $second = $updater->run(false, true);

            sinkholeTestAssertSame(1, $first['attempted'], 'A missing saved copy must download.');
            sinkholeTestAssertSame(0, $second['attempted'], 'A matching saved URL must be reused.');
            sinkholeTestAssertSame(1, $client->calls, 'The second apply must make no network call.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'inactive compile redeploys by digest when integration returns' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $identifier = '88888888888888888888888888888888';
            sinkholeRuntimeTestSaveList(
                $store,
                $identifier,
                "E\tredeploy.example.test\n",
            );
            $lists = [
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Redeploy Example',
                    'url' => 'https://lists.example.invalid/' . $identifier . '.test',
                    'enabled' => 'on',
                ],
            ];
            $compiler = new Compiler($paths, $store, $stateStore);
            $inactive = $compiler->compile($lists, [], false, false);

            sinkholeTestAssertSame(false, $inactive['deployed'], 'Inactive work must stay undeployed.');
            sinkholeTestAssertSame(
                null,
                $stateStore->compileStatus()['deployed_digest'],
                'Inactive compilation must not record a runtime digest.',
            );

            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                $lists,
                [],
                true,
                true,
            );
            $client = new SinkholeRuntimeTestDownloadClient('success');
            $result = (new Updater(
                $platform,
                $client,
                new DomainParser(),
                $store,
                $compiler,
                $stateStore,
            ))->run(false, true);
            $status = $stateStore->deploymentStatus(false);

            sinkholeTestAssertSame(0, $client->calls, 'A saved matching copy must not download again.');
            sinkholeTestAssertSame(true, $result['compiled'], 'Digest mismatch must force redeployment.');
            sinkholeTestAssertSame(false, $status['needed'], 'The deployed digest must become current.');
            sinkholeTestAssertSame(
                1,
                count($platform->reloadedGenerations),
                'The recovered deployment adds one name and must request a reload.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'deployment that only removes names does not reload Unbound' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $identifier = '99999999999999999999999999999999';
            sinkholeRuntimeTestSaveList(
                $store,
                $identifier,
                "E\tremoved.example.test\n",
            );
            $lists = [
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Removal Example',
                    'url' => 'https://lists.example.invalid/' . $identifier . '.test',
                    'enabled' => 'on',
                ],
            ];
            $compiler = new Compiler($paths, $store, $stateStore);
            $initial = $compiler->compile($lists, []);
            $stateStore->clearCacheClearOwed($initial['generation']);
            $compiler->markNeeded();
            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                [],
            );
            $result = (new Updater(
                $platform,
                new SinkholeRuntimeTestDownloadClient('success'),
                new DomainParser(),
                $store,
                $compiler,
                $stateStore,
            ))->run(false, true);

            sinkholeTestAssertSame(true, $result['compiled'], 'The removal must deploy.');
            sinkholeTestAssertSame(0, $result['added_names'], 'The removal adds no names.');
            sinkholeTestAssertSame(
                [],
                $platform->reloadedGenerations,
                'A removal-only deployment must not reload Unbound.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'background jobs carry out and retry a cache clear owed by Sync' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $identifier = '34343434343434343434343434343434';
            sinkholeRuntimeTestSaveList(
                $store,
                $identifier,
                "E\tcache-clear-debt.example.test\n",
            );
            $lists = [
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Cache Clear Debt Example',
                    'url' => 'https://lists.example.invalid/' . $identifier . '.test',
                    'enabled' => 'on',
                ],
            ];
            $compiler = new Compiler($paths, $store, $stateStore);
            $deployed = $compiler->compile($lists, []);
            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                $lists,
            );
            $platform->reloadFailuresRemaining = 1;
            $updater = new Updater(
                $platform,
                new SinkholeRuntimeTestDownloadClient('success'),
                new DomainParser(),
                $store,
                $compiler,
                $stateStore,
            );

            $updater->run(false, true);
            sinkholeTestAssertSame(
                $deployed['generation'],
                $stateStore->cacheClearOwedGeneration(),
                'A failed reload must retain the deployed generation as owed.',
            );
            sinkholeTestAssertSame(
                [],
                $platform->reloadedGenerations,
                'A failed reload must not be recorded as complete.',
            );

            $updater->run(false, true);
            sinkholeTestAssertSame(
                [$deployed['generation']],
                $platform->reloadedGenerations,
                'The next background job must retry the same owed generation.',
            );
            sinkholeTestAssertSame(
                null,
                $stateStore->cacheClearOwedGeneration(),
                'A successful retry must clear the durable handoff.',
            );
            sinkholeTestAssertTrue(
                count(array_filter(
                    $platform->logs,
                    static fn(string $message): bool => str_contains(
                        $message,
                        'Cache clear remains pending for generation',
                    ),
                )) === 1,
                'A failed reload must log one warning naming its generation.',
            );
            sinkholeTestAssertTrue(
                in_array(
                    'Reloaded Unbound to clear its cache for generation '
                    . $deployed['generation']
                    . '.',
                    $platform->logs,
                    true,
                ),
                'A successful reload must log the cleared generation.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'update lock runner closes the post-release apply race' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $lock = new FileLock($paths->updateLockFile);
            $runner = new UpdateLockRunner($lock, $stateStore);
            $applyRuns = [];
            $result = $runner->run(
                false,
                static function (bool $apply) use ($stateStore, &$applyRuns): array {
                    $applyRuns[] = $apply;

                    if (count($applyRuns) === 1) {
                        $stateStore->markApplyPending();
                    }

                    return ['apply' => $apply];
                },
                static function (): void {
                },
            );

            sinkholeTestAssertSame([false, true], $applyRuns, 'Pending work must reacquire and run.');
            sinkholeTestAssertSame(2, count($result['runs']), 'Both locked runs must be returned.');
            sinkholeTestAssertSame(false, $stateStore->applyPending(), 'The handoff must be consumed.');
            sinkholeTestAssertSame(
                '',
                (string) file_get_contents($paths->updateLockFile),
                'Releasing the update lock must truncate its PID.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'update lock reruns refresh configuration and preserve every failure' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $identifier = '56565656565656565656565656565656';
            $newLists = [
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Refreshed Example',
                    'url' => 'https://lists.example.invalid/' . $identifier . '.test',
                    'enabled' => 'on',
                ],
            ];
            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                [],
                [],
                true,
                false,
                false,
                $newLists,
            );
            $client = new SinkholeRuntimeTestDownloadClient('success');
            $updater = new Updater(
                $platform,
                $client,
                new DomainParser(),
                $store,
                new Compiler($paths, $store, $stateStore),
                $stateStore,
            );
            $runner = new UpdateLockRunner(
                new FileLock($paths->updateLockFile),
                $stateStore,
            );
            $operationCount = 0;
            $result = $runner->run(
                false,
                static function (bool $apply) use (
                    &$operationCount,
                    $platform,
                    $stateStore,
                    $updater,
                ): array {
                    $operationCount++;

                    if ($operationCount === 1) {
                        $stateStore->markApplyPending();

                        throw new RuntimeException('Simulated first-run failure.');
                    }

                    sinkholeTestAssertTrue(
                        $platform->refreshCount > 0,
                        'The rerun must refresh configuration before its downloads.',
                    );

                    return $updater->run(false, $apply);
                },
                static function () use ($platform): void {
                    $platform->refreshConfiguration();
                },
            );

            sinkholeTestAssertSame(2, $operationCount, 'The failed first run must not hide pending work.');
            sinkholeTestAssertSame(1, $client->calls, 'The rerun must download the newly configured list.');
            sinkholeTestAssertSame(
                $newLists[$identifier]['url'],
                $store->metadata($identifier)['url'],
                'The rerun must save the newly configured list.',
            );
            sinkholeTestAssertSame(1, count($result['runs']), 'The later successful result must be retained.');
            sinkholeTestAssertSame(1, count($result['failures']), 'The earlier failure must be retained.');
            sinkholeTestAssertSame(
                'Simulated first-run failure.',
                $result['failures'][0]->getMessage(),
                'Failure reporting must preserve the original run error.',
            );
            sinkholeTestAssertSame(
                1,
                UpdateLockRunner::exitCode($result['failures'], 0),
                'Any failed run must produce CLI exit code 1.',
            );
            sinkholeTestAssertSame(
                2,
                UpdateLockRunner::exitCode([], 1),
                'Download-only warnings must retain CLI exit code 2.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'runtime lock owner applies pending synchronization before release' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                [],
            );
            $stateStore->markSyncPending();
            (new Compiler($paths, $store, $stateStore))->compile(
                [],
                [],
                false,
                true,
                null,
                false,
                static function () use ($platform): void {
                    $platform->synchronizeIntegrationUnderLock();
                },
            );

            sinkholeTestAssertSame(
                1,
                $platform->synchronizationCount,
                'The lock owner must apply one pending synchronization.',
            );
            sinkholeTestAssertSame(false, $stateStore->syncPending(), 'Pending Sync must clear.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'updater applies pending synchronization without a content compile' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $compiler = new Compiler($paths, $store, $stateStore);
            $compiler->compile([], []);
            $stateStore->markSyncPending();
            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                [],
            );
            $result = (new Updater(
                $platform,
                new SinkholeRuntimeTestDownloadClient('success'),
                new DomainParser(),
                $store,
                $compiler,
                $stateStore,
            ))->run(false, true);

            sinkholeTestAssertSame(
                1,
                $platform->synchronizationCount,
                'Pending lifecycle work must run even when content is current.',
            );
            sinkholeTestAssertSame(false, $result['compiled'], 'No content compile is needed.');
            sinkholeTestAssertSame(false, $stateStore->syncPending(), 'Pending Sync must clear.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'compiled scopes exclude unused lists and preserve added-name semantics' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $stateStore = new StateStore($paths->stateFile);
            $compiler = new Compiler($paths, $store, $stateStore);
            $globalList = '11111111111111111111111111111111';
            $sameNameList = '22222222222222222222222222222222';
            $newNameList = '33333333333333333333333333333333';
            $networkIdentifier = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
            $deviceIdentifier = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
            $disabledNetworkIdentifier = 'cccccccccccccccccccccccccccccccc';
            $disabledDeviceIdentifier = 'dddddddddddddddddddddddddddddddd';
            sinkholeRuntimeTestSaveList($store, $globalList, "E\tshared.example.test\n");
            sinkholeRuntimeTestSaveList($store, $sameNameList, "E\tshared.example.test\n");
            sinkholeRuntimeTestSaveList($store, $newNameList, "E\tnew.example.test\n");
            $lists = [
                $globalList => [
                    'id' => $globalList,
                    'descr' => 'Global',
                    'url' => 'https://lists.example.invalid/global.test',
                    'enabled' => 'on',
                    'global' => 'on',
                ],
                $sameNameList => [
                    'id' => $sameNameList,
                    'descr' => 'Same Name',
                    'url' => 'https://lists.example.invalid/same.test',
                    'enabled' => 'on',
                    'global' => '',
                ],
                $newNameList => [
                    'id' => $newNameList,
                    'descr' => 'New Name',
                    'url' => 'https://lists.example.invalid/new.test',
                    'enabled' => 'on',
                    'global' => '',
                ],
            ];
            $first = $compiler->compile($lists, []);
            $firstManifest = json_decode(
                (string) file_get_contents($paths->runtimeDataDirectory . '/manifest.json'),
                true,
                32,
                JSON_THROW_ON_ERROR,
            );

            sinkholeTestAssertSame(1, $first['lists'], 'Only the global list must compile initially.');
            sinkholeTestAssertSame(
                [$globalList],
                array_keys($firstManifest['lists']),
                'Unused enabled lists must remain outside compiled data.',
            );

            $networks = [
                $networkIdentifier => [
                    'id' => $networkIdentifier,
                    'interface' => 'lan',
                    'lists' => [$sameNameList],
                    'allowed_domains' => ['network-allowed.example.test'],
                    'enabled' => true,
                ],
                $disabledNetworkIdentifier => [
                    'id' => $disabledNetworkIdentifier,
                    'interface' => 'opt1',
                    'lists' => [$newNameList],
                    'allowed_domains' => ['disabled-network.example.test'],
                    'enabled' => false,
                ],
            ];
            $devices = [
                $deviceIdentifier => [
                    'id' => $deviceIdentifier,
                    'lists' => [$globalList],
                    'allowed_domains' => ['device-allowed.example.test'],
                    'enabled' => true,
                ],
                $disabledDeviceIdentifier => [
                    'id' => $disabledDeviceIdentifier,
                    'lists' => [$newNameList],
                    'allowed_domains' => ['disabled-device.example.test'],
                    'enabled' => false,
                ],
            ];
            $compiler->markNeeded();
            $second = $compiler->compile(
                $lists,
                [],
                false,
                true,
                null,
                false,
                null,
                $networks,
                $devices,
            );
            $secondManifest = json_decode(
                (string) file_get_contents($paths->runtimeDataDirectory . '/manifest.json'),
                true,
                32,
                JSON_THROW_ON_ERROR,
            );

            sinkholeTestAssertSame(
                0,
                $second['added_names'],
                'Assigning an already-listed name to another scope must add no names.',
            );
            sinkholeTestAssertSame(
                [$globalList, $sameNameList],
                array_keys($secondManifest['lists']),
                'A newly used list must receive a compiled bit.',
            );
            sinkholeTestAssertSame(
                "network-allowed.example.test\n",
                file_get_contents(
                    $paths->runtimeDataDirectory
                    . '/allow-network-'
                    . $networkIdentifier
                    . '.txt',
                ),
                'Each network must receive its own allow file.',
            );
            sinkholeTestAssertSame(
                "device-allowed.example.test\n",
                file_get_contents(
                    $paths->runtimeDataDirectory
                    . '/allow-device-'
                    . $deviceIdentifier
                    . '.txt',
                ),
                'Each device must receive its own allow file.',
            );
            sinkholeTestAssertSame(
                'lan',
                $secondManifest['scopes']['networks'][$networkIdentifier]['interface'],
                'The network manifest must retain its interface.',
            );
            sinkholeTestAssertSame(
                false,
                isset($secondManifest['scopes']['networks'][$disabledNetworkIdentifier])
                    || isset($secondManifest['scopes']['devices'][$disabledDeviceIdentifier]),
                'Disabled scopes must be absent from the manifest and list-bit selection.',
            );

            $alertIdentifier = '44444444444444444444444444444444';
            $disabledAlertIdentifier = '55555555555555555555555555555555';
            $ineffectiveAlertIdentifier = '66666666666666666666666666666666';
            $alerts = [
                $alertIdentifier => [
                    'id' => $alertIdentifier,
                    'any_list' => false,
                    'lists' => [$sameNameList],
                    'everyone' => false,
                    'networks' => [$networkIdentifier],
                    'devices' => [$deviceIdentifier],
                    'enabled' => true,
                ],
                $disabledAlertIdentifier => [
                    'id' => $disabledAlertIdentifier,
                    'any_list' => true,
                    'lists' => [],
                    'everyone' => true,
                    'networks' => [],
                    'devices' => [],
                    'enabled' => false,
                ],
                $ineffectiveAlertIdentifier => [
                    'id' => $ineffectiveAlertIdentifier,
                    'any_list' => false,
                    'lists' => [$newNameList],
                    'everyone' => false,
                    'networks' => [$disabledNetworkIdentifier],
                    'devices' => [],
                    'enabled' => true,
                ],
            ];
            $owedBeforeAlert = $stateStore->cacheClearOwedGeneration();
            $compiler->markNeeded();
            $alertCompile = $compiler->compile(
                $lists,
                [],
                false,
                true,
                null,
                false,
                null,
                $networks,
                $devices,
                $alerts,
            );
            $alertManifest = json_decode(
                (string) file_get_contents($paths->runtimeDataDirectory . '/manifest.json'),
                true,
                32,
                JSON_THROW_ON_ERROR,
            );
            sinkholeTestAssertSame(0, $alertCompile['added_names'], 'Alert-only changes add no names.');
            sinkholeTestAssertSame(
                $owedBeforeAlert,
                $stateStore->cacheClearOwedGeneration(),
                'Alert-only changes must not create cache-reload debt.',
            );
            sinkholeTestAssertSame(
                [$alertIdentifier],
                array_keys($alertManifest['alerts']),
                'Disabled and ineffective alert rules must be omitted.',
            );

            $networks[$networkIdentifier]['lists'][] = $newNameList;
            $compiler->markNeeded();
            $third = $compiler->compile(
                $lists,
                [],
                false,
                true,
                null,
                false,
                null,
                $networks,
                $devices,
            );
            sinkholeTestAssertSame(
                1,
                $third['added_names'],
                'Assigning a previously unused list must add its unique name.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'client map builds local sources detects conflicts mirrors and skips its lock' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $networkIdentifier = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
            $firstDevice = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
            $secondDevice = 'cccccccccccccccccccccccccccccccc';
            $ipDevice = 'dddddddddddddddddddddddddddddddd';
            $source = new SinkholeRuntimeTestClientSource(
                networks: [$networkIdentifier => [
                    'id' => $networkIdentifier,
                    'interface' => 'lan',
                    'enabled' => true,
                ]],
                devices: [
                    $firstDevice => [
                        'id' => $firstDevice,
                        'identifier_type' => ScopeConfiguration::DEVICE_STATIC_MAPPING,
                        'identifier' => '00:11:22:33:44:55',
                        'interface' => 'lan',
                        'enabled' => true,
                    ],
                    $secondDevice => [
                        'id' => $secondDevice,
                        'identifier_type' => ScopeConfiguration::DEVICE_MAC,
                        'identifier' => '00-11-22-33-44-55',
                        'interface' => '',
                        'enabled' => true,
                    ],
                    $ipDevice => [
                        'id' => $ipDevice,
                        'identifier_type' => ScopeConfiguration::DEVICE_IP,
                        'identifier' => '::ffff:198.51.100.9',
                        'interface' => '',
                        'enabled' => true,
                    ],
                ],
                subnets: ['lan' => ['192.0.2.0/24', '2001:db8:1::/64']],
                mappings: [[
                    'interface' => 'lan',
                    'mac' => '00:11:22:33:44:55',
                    'ipaddr' => '192.0.2.20',
                ]],
                arp: [
                    [
                        'ip-address' => '192.0.2.21',
                        'mac-address' => '00:11:22:33:44:55',
                        'interface' => 'em0',
                    ],
                    [
                        'ip-address' => '192.0.2.99',
                        'mac-address' => '00:11:22:33:44:55',
                        'incomplete' => true,
                    ],
                ],
                ndp: "Neighbor Linklayer Address Netif Expire S Flags\n"
                    . "2001:db8::21 00:11:22:33:44:55 em0 23h59m59s S R\n"
                    . "2001:db8::99 (incomplete) em0 1m N\n",
                leases: ['lease' => [
                    [
                        'ip' => '192.0.2.22',
                        'mac' => '00:11:22:33:44:55',
                        'ends' => time() + 3600,
                        'act' => 'active',
                    ],
                    [
                        'ip' => '192.0.2.98',
                        'mac' => '00:11:22:33:44:55',
                        'ends' => time() - 3600,
                        'act' => 'expired',
                    ],
                ]],
                memoryFileSystem: true,
                bypassInterfaces: ['lan'],
                interfaceAddresses: [
                    'lan' => ['192.0.2.1', '2001:db8:1::1'],
                    'opt1' => ['192.0.2.2'],
                ],
            );
            $clientMap = new ClientMap($paths, $source, $stateStore);
            $result = $clientMap->refresh();
            $map = json_decode(
                (string) file_get_contents($paths->runtimeClientMapFile),
                true,
                32,
                JSON_THROW_ON_ERROR,
            );

            sinkholeTestAssertSame('updated', $result['status'], 'The first map must publish.');
            sinkholeTestAssertSame(
                [
                    ['id' => $networkIdentifier, 'cidrs' => [
                        '192.0.2.0/24',
                        '2001:db8:1::/64',
                    ]],
                ],
                $map['networks'],
                'IPv4 and IPv6 interface subnets must be retained.',
            );
            $interfaceContains = static function (string $address) use ($map): bool {
                foreach ($map['interfaces'][0]['cidrs'] ?? [] as $cidr) {
                    if (IpNetwork::contains($cidr, $address)) {
                        return true;
                    }
                }

                return false;
            };
            sinkholeTestAssertSame(
                false,
                $interfaceContains('192.0.2.1'),
                'A firewall IPv4 address must not receive Bypass answers.',
            );
            sinkholeTestAssertSame(
                false,
                $interfaceContains('2001:db8:1::1'),
                'A firewall IPv6 address must not receive Bypass answers.',
            );
            sinkholeTestAssertSame(
                false,
                $interfaceContains('192.0.2.2'),
                'Every firewall interface address must be excluded from an overlapping client CIDR.',
            );
            sinkholeTestAssertSame(
                true,
                $interfaceContains('192.0.2.20'),
                'Other IPv4 clients in the selected interface subnet must remain included.',
            );
            sinkholeTestAssertSame(
                true,
                $interfaceContains('2001:db8:1::20'),
                'Other IPv6 clients in the selected interface subnet must remain included.',
            );
            sinkholeTestAssertSame(
                $firstDevice,
                $map['devices']['192.0.2.21'],
                'The first static-mapping device must win a shared ARP address.',
            );
            sinkholeTestAssertSame(
                $firstDevice,
                $map['devices']['2001:db8::21'],
                'A complete NDP address must join the static mapping device.',
            );
            sinkholeTestAssertSame(
                $firstDevice,
                $map['devices']['192.0.2.22'],
                'An active lease must join the static mapping device.',
            );
            sinkholeTestAssertSame(
                $ipDevice,
                $map['devices']['198.51.100.9'],
                'IPv4-mapped device identifiers must normalize to IPv4.',
            );
            sinkholeTestAssertSame(
                false,
                isset($map['devices']['192.0.2.98']) || isset($map['devices']['192.0.2.99']),
                'Expired leases and incomplete neighbors must be dropped.',
            );
            sinkholeTestAssertSame(3, count($map['conflicts']), 'Each shared address must conflict.');
            sinkholeTestAssertSame(1, count($source->logs), 'A changed conflict set logs once.');
            sinkholeTestAssertSame(
                file_get_contents($paths->runtimeClientMapFile),
                file_get_contents($paths->mirrorClientMapFile),
                'RAM-disk client maps must be mirrored byte for byte.',
            );
            sinkholeTestAssertSame(
                0644,
                fileperms($paths->runtimeClientMapFile) & 0777,
                'The client map must be world-readable.',
            );
            sinkholeTestAssertSame(
                0755,
                fileperms($paths->runtimeClientDirectory) & 0777,
                'The client map directory must have the fixed mode.',
            );

            $unchanged = $clientMap->refresh();
            sinkholeTestAssertSame('unchanged', $unchanged['status'], 'Equal content must not rewrite.');
            sinkholeTestAssertSame(1, count($source->logs), 'An unchanged conflict set must not log.');

            $heldLock = fopen($paths->clientLockFile, 'c+b');
            sinkholeTestAssertTrue(
                $heldLock !== false && flock($heldLock, LOCK_EX | LOCK_NB),
                'The lock fixture must acquire.',
            );

            try {
                sinkholeTestAssertSame(
                    'skipped',
                    $clientMap->refresh()['status'],
                    'A concurrent refresh must exit without waiting.',
                );
            } finally {
                flock($heldLock, LOCK_UN);
                fclose($heldLock);
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'client map parses translated ISC lease states in GMT and local time' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();
        $originalTimezone = date_default_timezone_get();

        try {
            $contexts = [
                ['timezone' => 'Pacific/Kiritimati', 'times_local' => false],
                ['timezone' => 'Pacific/Kiritimati', 'times_local' => true],
                ['timezone' => 'America/New_York', 'times_local' => false],
                ['timezone' => 'America/New_York', 'times_local' => true],
            ];

            foreach ($contexts as $position => $context) {
                date_default_timezone_set($context['timezone']);
                $caseDirectory = $directory . '/case-' . $position;
                mkdir($caseDirectory, 0700);
                $future = time() + 7200;
                $past = time() - 7200;
                $formatEnd = static fn(int $timestamp): string => $context['times_local']
                    ? date('Y/m/d H:i:s', $timestamp)
                    : gmdate('Y/m/d H:i:s', $timestamp);
                $devices = [];

                foreach (
                    [
                        '11111111111111111111111111111111' => '00:11:22:33:44:51',
                        '22222222222222222222222222222222' => '00:11:22:33:44:52',
                        '33333333333333333333333333333333' => '00:11:22:33:44:53',
                        '44444444444444444444444444444444' => '00:11:22:33:44:54',
                        '55555555555555555555555555555555' => '00:11:22:33:44:55',
                    ] as $identifier => $mac
                ) {
                    $devices[$identifier] = [
                        'id' => $identifier,
                        'identifier_type' => ScopeConfiguration::DEVICE_MAC,
                        'identifier' => $mac,
                        'interface' => '',
                        'enabled' => true,
                    ];
                }

                $source = new SinkholeRuntimeTestClientSource(
                    devices: $devices,
                    leases: ['lease' => [
                        [
                            'ip' => '192.0.2.31',
                            'mac' => '00:11:22:33:44:51',
                            'ends' => $formatEnd($future),
                            'act' => 'aktiv',
                        ],
                        [
                            'ip' => '192.0.2.32',
                            'mac' => '00:11:22:33:44:52',
                            'ends' => $formatEnd($past),
                            'act' => 'aktiv',
                        ],
                        [
                            'ip' => '192.0.2.33',
                            'mac' => '00:11:22:33:44:53',
                            'ends' => $formatEnd($future),
                            'act' => 'abgelaufen',
                        ],
                        [
                            'ip' => '192.0.2.34',
                            'mac' => '00:11:22:33:44:54',
                            'ends' => $formatEnd($future),
                            'act' => 'reserviert',
                        ],
                        [
                            'ip' => '192.0.2.35',
                            'mac' => '00:11:22:33:44:55',
                            'ends' => 'Niemals',
                            'act' => 'aktiv',
                        ],
                    ]],
                    leaseContext: [
                        'times_local' => $context['times_local'],
                        'active' => 'aktiv',
                        'expired' => 'abgelaufen',
                        'reserved' => 'reserviert',
                        'never' => 'Niemals',
                    ],
                );
                $paths = sinkholeRuntimeTestPaths($caseDirectory);
                $result = (new ClientMap(
                    $paths,
                    $source,
                    new StateStore($paths->stateFile),
                ))->refresh();
                $map = json_decode(
                    (string) file_get_contents($paths->runtimeClientMapFile),
                    true,
                    32,
                    JSON_THROW_ON_ERROR,
                );

                sinkholeTestAssertSame('updated', $result['status'], 'The lease map must publish.');
                sinkholeTestAssertSame(
                    true,
                    isset($map['devices']['192.0.2.31']),
                    'A future translated active lease must remain assigned.',
                );
                sinkholeTestAssertSame(
                    true,
                    isset($map['devices']['192.0.2.35']),
                    'A translated never-ending lease must remain assigned.',
                );
                sinkholeTestAssertSame(
                    false,
                    isset($map['devices']['192.0.2.32'])
                        || isset($map['devices']['192.0.2.33'])
                        || isset($map['devices']['192.0.2.34']),
                    'Past, translated expired, and translated reserved leases must be dropped.',
                );
            }
        } finally {
            date_default_timezone_set($originalTimezone);
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'removal stop flag prevents downloads and compilation' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeRuntimeTestPaths($directory);
            $store = new SavedListStore($paths);
            $identifier = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
            $lists = [
                $identifier => [
                    'id' => $identifier,
                    'descr' => 'Stop Example',
                    'url' => 'https://lists.example.invalid/stop.test',
                    'enabled' => 'on',
                ],
            ];
            $client = new SinkholeRuntimeTestDownloadClient('success');
            $stateStore = new StateStore($paths->stateFile);
            $platform = new SinkholeRuntimeTestPlatformAdapter(
                ['enabled' => 'on', 'update_frequency' => 'daily'],
                $lists,
                [],
                true,
                false,
                true,
            );
            $result = (new Updater(
                $platform,
                $client,
                new DomainParser(),
                $store,
                new Compiler($paths, $store, $stateStore),
                $stateStore,
            ))->run(true);

            sinkholeTestAssertSame('stopped', $result['status'], 'The update must stop.');
            sinkholeTestAssertSame(0, $client->calls, 'No list may download after the stop flag.');
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeRootDirectory),
                'A stopped update must not compile or deploy.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
]);
