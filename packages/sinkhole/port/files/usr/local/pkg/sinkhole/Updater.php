<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\ListConfiguration;
use PfSense\Sinkhole\Domain\Settings;
use RuntimeException;
use Throwable;

require_once(__DIR__ . '/Compiler.php');
require_once(__DIR__ . '/BypassUpdater.php');
require_once(__DIR__ . '/ClientMap.php');
require_once(__DIR__ . '/DomainParser.php');
require_once(__DIR__ . '/DownloadClient.php');
require_once(__DIR__ . '/FileLock.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/IpUpdater.php');
require_once(__DIR__ . '/ListConfiguration.php');
require_once(__DIR__ . '/PlatformAdapter.php');
require_once(__DIR__ . '/SavedListStore.php');
require_once(__DIR__ . '/Settings.php');
require_once(__DIR__ . '/StateStore.php');

/**
 * Updater.
 *
 * Downloads enabled lists into temporary files, preserves every last-good copy
 * on failure, and retries every pending compile even without a content change.
 *
 * @since 1.0.0
 */
final class Updater
{
    /**
     * Updater - Maximum Download Bytes.
     *
     * Every transport and updater result is bounded to 64 MiB.
     *
     * @since 1.0.0
     */
    public const MAXIMUM_DOWNLOAD_BYTES = 67108864;

    /**
     * Updater - Constructor.
     *
     * Injected boundaries keep fallback, parsing, and compile behavior testable without
     * pfSense or network access.
     *
     * @param PlatformAdapter $platformAdapter - Platform adapter.
     * @param DownloadClient  $downloadClient  - Download client.
     * @param DomainParser    $parser          - Domain parser.
     * @param SavedListStore $store           - Saved list store.
     * @param Compiler       $compiler        - Compiler.
     * @param StateStore     $stateStore       - Persistent handoff state.
     * @param ClientMap|null $clientMap - Optional production client-map refresher.
     * @param IpUpdater|null $ipUpdater - Optional IP and country updater.
     * @param BypassUpdater|null $bypassUpdater - Optional Bypass List and anchor updater.
     *
     * @since 1.0.0
     */
    public function __construct(
        private readonly PlatformAdapter $platformAdapter,
        private readonly DownloadClient $downloadClient,
        private readonly DomainParser $parser,
        private readonly SavedListStore $store,
        private readonly Compiler $compiler,
        private readonly StateStore $stateStore,
        private readonly ?ClientMap $clientMap = null,
        private readonly ?IpUpdater $ipUpdater = null,
        private readonly ?BypassUpdater $bypassUpdater = null,
    ) {
    }

    /**
     * Updater - Run.
     *
     * A scheduled disabled run exits before network access. Apply runs fetch only
     * missing or URL-mismatched saved copies; manual and scheduled runs remain full
     * refreshes. Compilation deploys only while Resolver integration is active.
     *
     * @param bool $manual - Whether the Status page requested the run.
     * @param bool $apply  - Whether configuration requested background apply work.
     *
     * @return array{
     *     status: string,
     *     attempted: int,
     *     updated: int,
     *     failed: int,
     *     compiled: bool,
     *     added_names: int
     * }
     *
     * @throws Throwable When configuration or compilation fails.
     *
     * @since 1.0.0
     */
    public function run(bool $manual = false, bool $apply = false): array
    {
        try {
            $bypassResult = null;

            if (
                $this->bypassUpdater !== null
                && !$this->platformAdapter->updateShouldStop()
            ) {
                try {
                    $bypassResult = $this->bypassUpdater->run($apply && !$manual);
                    $this->recordBypassUpdateWarning(null);
                } catch (Throwable $throwable) {
                    $warning = 'Bypass update failed; DNS and IP updates continued: '
                        . substr(str_replace(["\r", "\n"], ' ', $throwable->getMessage()), 0, 500);
                    $this->platformAdapter->log($warning);
                    $this->recordBypassUpdateWarning($warning);
                    $bypassResult = [
                        'status' => 'warning',
                        'attempted' => 0,
                        'updated' => 0,
                        'failed' => 1,
                        'dns_active' => true,
                        'firewall_active' => false,
                        'changed' => false,
                    ];
                }
            }

            $result = $this->runUpdate(
                $manual,
                $apply,
                ($bypassResult['dns_active'] ?? false) === true,
            );

            if (is_array($bypassResult)) {
                $result['attempted'] += $bypassResult['attempted'];
                $result['updated'] += $bypassResult['updated'];
                $result['failed'] += $bypassResult['failed'];

                if ($bypassResult['status'] === 'stopped') {
                    $result['status'] = 'stopped';
                } elseif ($bypassResult['status'] === 'warning') {
                    $result['status'] = 'warning';
                } elseif (
                    $result['status'] === 'disabled'
                    && ($bypassResult['dns_active'] || $bypassResult['firewall_active'])
                ) {
                    $result['status'] = 'completed';
                }
            }

            if ($this->ipUpdater === null || $this->platformAdapter->updateShouldStop()) {
                return $result;
            }

            $ipResult = $this->ipUpdater->run($apply && !$manual);
            $result['attempted'] += $ipResult['attempted'];
            $result['updated'] += $ipResult['updated'];
            $result['failed'] += $ipResult['failed'];

            if ($ipResult['status'] === 'stopped') {
                $result['status'] = 'stopped';
            } elseif ($ipResult['status'] === 'warning') {
                $result['status'] = 'warning';
            } elseif (
                $result['status'] === 'disabled'
                && $ipResult['status'] === 'completed'
            ) {
                $result['status'] = 'completed';
            }

            return $result;
        } finally {
            if (
                $this->clientMap !== null
                && $this->platformAdapter->updateShouldStop() === false
            ) {
                $this->clientMap->refresh();
            }
        }
    }

    /**
     * Updater - Record Bypass Update Warning.
     *
     * Status recording must never turn an isolated Bypass failure into a DNS or IP
     * update failure.
     *
     * @param string|null $warning - Current warning, or null after recovery.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function recordBypassUpdateWarning(?string $warning): void
    {
        try {
            $this->stateStore->recordBypassUpdateWarning($warning);
        } catch (Throwable $throwable) {
            $this->platformAdapter->log(
                'Unable to record the Bypass update warning: ' . $throwable->getMessage(),
            );
        }
    }

    /**
     * Updater - Run Update.
     *
     * Performs the existing update transaction while the public boundary guarantees
     * a client-map refresh after every outcome.
     *
     * @param bool $manual - Whether the Status page requested the run.
     * @param bool $apply - Whether configuration requested apply work.
     *
     * @return array
     *
     * @since 1.0.0
     * @private
     */
    private function runUpdate(bool $manual, bool $apply, bool $bypassDnsActive = false): array
    {
        if ($this->platformAdapter->updateShouldStop()) {
            return [
                'status' => 'stopped',
                'attempted' => 0,
                'updated' => 0,
                'failed' => 0,
                'compiled' => false,
                'added_names' => 0,
            ];
        }

        $this->applyPendingSynchronization();
        $settings = Settings::fromStorage($this->platformAdapter->getSettings());

        if (
            $settings['enabled'] === false
            && !$bypassDnsActive
            && $manual === false
            && $apply === false
        ) {
            return [
                'status' => 'disabled',
                'attempted' => 0,
                'updated' => 0,
                'failed' => 0,
                'compiled' => false,
                'added_names' => 0,
            ];
        }

        $configuredLists = ListConfiguration::normalizeLists(
            $this->platformAdapter->getLists(),
        );
        $lists = $settings['enabled'] ? $configuredLists : [];
        $downloadLists = ($settings['enabled'] || $manual) ? $configuredLists : [];
        $attempted = 0;
        $updated = 0;
        $failed = 0;
        $changed = false;

        foreach ($downloadLists as $identifier => $list) {
            if ($this->platformAdapter->updateShouldStop()) {
                break;
            }

            if ($list['enabled'] === false) {
                continue;
            }

            if ($apply && $this->requiresApplyDownload($identifier, $list['url']) === false) {
                continue;
            }

            $attempted++;
            $attemptedAt = gmdate('c');
            $hadSavedCopy = $this->store->hasSavedCopy($identifier);
            $downloadPath = $this->store->createTemporaryFile('.download-');
            $normalizedPath = $this->store->createTemporaryFile('.normalized-');

            try {
                $download = $this->downloadClient->download(
                    $list['url'],
                    $downloadPath,
                    self::MAXIMUM_DOWNLOAD_BYTES,
                );

                if ($download['success'] === false) {
                    throw new RuntimeException($download['error'] ?? 'The download failed.');
                }

                $downloadSize = filesize($downloadPath);

                if (
                    $download['bytes'] <= 0
                    || $download['bytes'] > self::MAXIMUM_DOWNLOAD_BYTES
                    || FileSystem::isRegularFile($downloadPath) === false
                    || !is_int($downloadSize)
                    || $downloadSize <= 0
                    || $downloadSize > self::MAXIMUM_DOWNLOAD_BYTES
                ) {
                    throw new RuntimeException('The download is empty or exceeds the 64 MiB size limit.');
                }

                $parseResult = $this->parser->parseFile($downloadPath, $normalizedPath);

                if ($parseResult['accepted'] === 0) {
                    throw new RuntimeException('The download contains no valid domain entries.');
                }

                $sha256 = hash_file('sha256', $normalizedPath);

                if (!is_string($sha256)) {
                    throw new RuntimeException('Unable to hash the normalized block list.');
                }

                $previousMetadata = $this->store->metadata($identifier);
                $changed = $hadSavedCopy === false
                    || ($previousMetadata['sha256'] ?? null) !== $sha256
                    || $changed;
                $fetchedAt = gmdate('c');

                $this->store->commitSuccessfulDownload(
                    $identifier,
                    $normalizedPath,
                    [
                        'url' => $list['url'],
                        'fetched_at' => $fetchedAt,
                        'entries' => $parseResult['accepted'],
                        'ignored' => $parseResult['ignored'],
                        'sha256' => $sha256,
                        'last_attempt' => $attemptedAt,
                        'last_error' => null,
                    ],
                );
                $updated++;
            } catch (Throwable $throwable) {
                $failed++;

                try {
                    $this->store->recordFailure(
                        $identifier,
                        $list['url'],
                        $attemptedAt,
                        $throwable->getMessage(),
                    );
                } catch (Throwable $metadataThrowable) {
                    $this->platformAdapter->log(
                        'Unable to record a list update failure: ' . $metadataThrowable->getMessage(),
                    );
                }

                $this->platformAdapter->log(
                    'List update failed for ID ' . $identifier . ': ' . $throwable->getMessage(),
                );
            } finally {
                foreach ([$downloadPath, $normalizedPath] as $temporaryPath) {
                    if (file_exists($temporaryPath) || is_link($temporaryPath)) {
                        unlink($temporaryPath);
                    }
                }
            }
        }

        if ($this->platformAdapter->updateShouldStop()) {
            $this->platformAdapter->log('Update stopped for package removal.');

            return [
                'status' => 'stopped',
                'attempted' => $attempted,
                'updated' => $updated,
                'failed' => $failed,
                'compiled' => false,
                'added_names' => 0,
            ];
        }

        $this->store->removeUnconfigured(array_keys($configuredLists));

        $compiled = false;
        $addedNames = 0;

        if ($changed) {
            $this->compiler->markNeeded();
        }

        $integrationActive = $this->platformAdapter->isIntegrationActive();

        if (
            $this->compiler->isNeeded()
            || (
                $integrationActive
                && $this->compiler->deploymentIsNeeded(
                    $this->platformAdapter->runtimeGenerationMissing(),
                )
            )
        ) {
            if ($this->platformAdapter->updateShouldStop()) {
                $this->platformAdapter->log('Update stopped before compilation for package removal.');

                return [
                    'status' => 'stopped',
                    'attempted' => $attempted,
                    'updated' => $updated,
                    'failed' => $failed,
                    'compiled' => false,
                    'added_names' => 0,
                ];
            }

            $compileResult = $this->compiler->compile(
                $lists,
                $this->platformAdapter->getAllowedDomains(),
                $this->platformAdapter->usesMemoryFileSystem(),
                fn(): bool => $this->platformAdapter->isIntegrationActive(),
                function (): array {
                    $this->platformAdapter->refreshConfiguration();
                    $dnsBlockingEnabled = Settings::fromStorage(
                        $this->platformAdapter->getSettings(),
                    )['enabled'];

                    return [
                        'lists' => $dnsBlockingEnabled
                            ? $this->platformAdapter->getLists()
                            : [],
                        'allowed_domains' => $this->platformAdapter->getAllowedDomains(),
                        'networks' => $dnsBlockingEnabled
                            ? $this->platformAdapter->getNetworks()
                            : [],
                        'devices' => $dnsBlockingEnabled
                            ? $this->platformAdapter->getDevices()
                            : [],
                        'alerts' => $dnsBlockingEnabled
                            ? $this->platformAdapter->getAlerts()
                            : [],
                        'services' => $dnsBlockingEnabled
                            ? $this->platformAdapter->getBlockedServices()
                            : [],
                        'bypass' => $this->platformAdapter->getBypassConfiguration(),
                    ];
                },
                false,
                function (): void {
                    $this->platformAdapter->synchronizeIntegrationUnderLock();
                },
            );
            $compiled = true;
            $addedNames = $compileResult['added_names'];
        }

        $this->applyPendingSynchronization();
        $this->clearOwedCache();

        $this->platformAdapter->log(sprintf(
            'Update finished: %d attempted, %d successful, %d failed.',
            $attempted,
            $updated,
            $failed,
        ));

        return [
            'status' => ($failed > 0) ? 'warning' : 'completed',
            'attempted' => $attempted,
            'updated' => $updated,
            'failed' => $failed,
            'compiled' => $compiled,
            'added_names' => $addedNames,
        ];
    }

    /**
     * Updater - Apply Pending Synchronization.
     *
     * The compiler handles handoffs that arrive while it owns the runtime lock;
     * these boundary checks close the release edge even when no compile is needed.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function applyPendingSynchronization(): void
    {
        if ($this->platformAdapter->updateShouldStop()) {
            return;
        }

        $this->compiler->applyPendingSynchronization(
            function (): void {
                $this->platformAdapter->synchronizeIntegrationUnderLock();
            },
        );
    }

    /**
     * Updater - Clear Owed Cache.
     *
     * Background jobs complete a durable post-deploy handoff only while integration
     * is active, retaining it for the next job after any wait or command failure.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function clearOwedCache(): void
    {
        $generation = $this->stateStore->cacheClearOwedGeneration();

        if (
            $generation === null
            || $this->platformAdapter->isIntegrationActive() === false
        ) {
            return;
        }

        try {
            $this->platformAdapter->reloadUnboundAfterDeploy($generation);
            $this->platformAdapter->log(
                'Reloaded Unbound to clear its cache for generation ' . $generation . '.',
            );
            $this->stateStore->clearCacheClearOwed($generation);
        } catch (Throwable $throwable) {
            $this->platformAdapter->log(
                'Cache clear remains pending for generation '
                . $generation
                . ': '
                . $throwable->getMessage(),
            );
        }
    }

    /**
     * Updater - Requires Apply Download.
     *
     * @param string $identifier - Stable configured-list identifier.
     * @param string $url        - Current validated URL.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function requiresApplyDownload(string $identifier, string $url): bool
    {
        if ($this->store->hasSavedCopy($identifier) === false) {
            return true;
        }

        try {
            $metadata = $this->store->metadata($identifier);
        } catch (Throwable $throwable) {
            $this->platformAdapter->log(
                'Saved-list metadata requires refresh for ID '
                . $identifier
                . ': '
                . $throwable->getMessage(),
            );

            return true;
        }

        return ($metadata['url'] ?? null) !== $url;
    }
}

/**
 * Update Lock Runner.
 *
 * Owns the nonblocking update lock across one run at a time and closes the final
 * apply-handoff race by checking persistent pending state only after each release.
 *
 * @since 1.0.0
 */
final class UpdateLockRunner
{
    /**
     * Update Lock Runner - Exit Code.
     *
     * Any failed locked run takes precedence over per-list download warnings, even
     * when a later pending run succeeds.
     *
     * @param list<Throwable> $failures - Locked run failures.
     * @param int $failedDownloads - Per-list download failures.
     *
     * @return int
     *
     * @since 1.0.0
     */
    public static function exitCode(array $failures, int $failedDownloads): int
    {
        if ($failures !== []) {
            return 1;
        }

        return ($failedDownloads > 0) ? 2 : 0;
    }

    /**
     * Update Lock Runner - Constructor.
     *
     * The reusable lock carries the running PID while state retains apply handoffs
     * from WebGUI processes that collide with the current owner.
     *
     * @param FileLock  $lock       - Update lock.
     * @param StateStore $stateStore - State store.
     *
     * @since 1.0.0
     */
    public function __construct(
        private readonly FileLock $lock,
        private readonly StateStore $stateStore,
    ) {
    }

    /**
     * Update Lock Runner - Run.
     *
     * Releases before every pending re-check, then reacquires for another apply run.
     * A competing process that wins that reacquire becomes the next pending owner.
     *
     * @param bool $apply - Whether the initial invocation is an apply handoff.
     * @param callable(bool): array $operation - One locked update operation.
     * @param callable(): void $refreshConfiguration - Configuration refresher.
     *
     * @return array{acquired: bool, runs: list<array>, failures: list<Throwable>}
     *
     * @since 1.0.0
     */
    public function run(
        bool $apply,
        callable $operation,
        callable $refreshConfiguration,
    ): array {
        if ($apply) {
            $this->stateStore->markApplyPending();
        }

        $runs = [];
        $failures = [];
        $acquired = false;
        $runApply = $apply;
        $firstRun = true;

        while (true) {
            if ($this->lock->acquire() === false) {
                return [
                    'acquired' => $acquired,
                    'runs' => $runs,
                    'failures' => $failures,
                ];
            }

            $acquired = true;

            try {
                if ($runApply) {
                    $this->stateStore->consumeApplyPending();
                }

                if ($firstRun === false) {
                    $refreshConfiguration();
                }

                $runs[] = $operation($runApply);
            } catch (Throwable $throwable) {
                $failures[] = $throwable;
            } finally {
                $this->lock->release();
            }

            $firstRun = false;

            if ($this->stateStore->applyPending() === false) {
                break;
            }

            $runApply = true;
        }

        return [
            'acquired' => $acquired,
            'runs' => $runs,
            'failures' => $failures,
        ];
    }
}
