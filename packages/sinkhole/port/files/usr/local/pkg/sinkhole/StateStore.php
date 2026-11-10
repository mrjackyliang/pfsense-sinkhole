<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use JsonException;
use RuntimeException;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/FileLock.php');
require_once(__DIR__ . '/FileSystem.php');

/**
 * State Store.
 *
 * Persists integration recovery, compile requests, cron jitter, and apply handoff
 * state while keeping frequently changing job status on the runtime filesystem.
 *
 * @since 1.0.0
 */
final class StateStore
{
    /** @since 1.0.0 */
    private const STATUS_SCHEMA_VERSION = 1;

    /** @since 1.0.0 */
    private const MAXIMUM_STATUS_BYTES = 65536;

    /**
     * State Store - Removing Paths.
     *
     * Keeps the durable marker visible to every store instance in the current
     * process after final persistent cleanup. A later install explicitly clears it.
     *
     * @var array<string, true>
     *
     * @since 1.0.0
     * @private
     */
    private static array $removingPaths = [];

    /** @var string @since 1.0.0 */
    private readonly string $statusPath;

    /**
     * State Store - Constructor.
     *
     * Production uses the package-owned persistent directory while tests provide a
     * disposable path.
     *
     * @param string $path - State file path.
     * @param string|null $statusPath - Runtime status file path.
     *
     * @since 1.0.0
     */
    public function __construct(
        private readonly string $path,
        ?string $statusPath = null,
    ) {
        $this->statusPath = $statusPath ?? $this->path . '.status';
    }

    /**
     * State Store - Read.
     *
     * Missing state returns the initial schema, while every unknown schema is rejected
     * because no development build state is part of the package contract.
     *
     * @return array{
     *     schema_version: int,
     *     unbound_previous: array|null,
     *     compile_request: int,
     *     compiled_request: int,
     *     compile_error: string|null,
     *     compiled_generation: string|null,
     *     content_digest: string|null,
     *     deployed_generation: string|null,
     *     deployed_digest: string|null,
     *     flush_owed_generation: string|null,
     *     bypass_configuration_warning: string|null,
     *     bypass_update_warning: string|null,
     *     apply_pending: bool,
     *     sync_pending: bool,
     *     stop_requested: bool,
     *     removing: bool,
     *     cron_minute: int|null
     * }
     *
     * @throws RuntimeException When state cannot be decoded or validated.
     *
     * @since 1.0.0
     */
    public function read(): array
    {
        if (file_exists($this->path) === false) {
            return self::emptyState();
        }

        $contents = file_get_contents($this->path);

        if ($contents === false) {
            throw new RuntimeException('Unable to read Sinkhole state.');
        }

        try {
            $state = json_decode($contents, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('Sinkhole state is invalid.', 0, $exception);
        }

        if (!is_array($state)) {
            throw new RuntimeException('Sinkhole state is invalid.');
        }

        if (($state['schema_version'] ?? null) !== 1) {
            throw new RuntimeException('Sinkhole state is invalid.');
        }

        $previous = $state['unbound_previous'] ?? null;
        $compileRequest = $state['compile_request'] ?? null;
        $compiledRequest = $state['compiled_request'] ?? null;
        $compileError = $state['compile_error'] ?? null;
        $compiledGeneration = $state['compiled_generation'] ?? null;
        $contentDigest = $state['content_digest'] ?? null;
        $deployedGeneration = $state['deployed_generation'] ?? null;
        $deployedDigest = $state['deployed_digest'] ?? null;
        $flushOwedGeneration = $state['flush_owed_generation'] ?? null;
        $bypassConfigurationWarning = $state['bypass_configuration_warning'] ?? null;
        $bypassUpdateWarning = $state['bypass_update_warning'] ?? null;
        $applyPending = $state['apply_pending'] ?? false;
        $syncPending = $state['sync_pending'] ?? false;
        $stopRequested = $state['stop_requested'] ?? false;
        $removing = $state['removing'] ?? false;
        $cronMinute = $state['cron_minute'] ?? null;

        if (
            ($previous !== null && !is_array($previous))
            || !is_int($compileRequest)
            || $compileRequest < 1
            || !is_int($compiledRequest)
            || $compiledRequest < 0
            || $compiledRequest > $compileRequest
            || ($compileError !== null && !is_string($compileError))
            || ($compiledGeneration !== null && !is_string($compiledGeneration))
            || (
                $contentDigest !== null
                && (!is_string($contentDigest) || preg_match('/^[a-f0-9]{64}$/D', $contentDigest) !== 1)
            )
            || ($deployedGeneration !== null && !is_string($deployedGeneration))
            || (
                $deployedDigest !== null
                && (!is_string($deployedDigest) || preg_match('/^[a-f0-9]{64}$/D', $deployedDigest) !== 1)
            )
            || ($flushOwedGeneration !== null && !is_string($flushOwedGeneration))
            || (
                $bypassConfigurationWarning !== null
                && !is_string($bypassConfigurationWarning)
            )
            || ($bypassUpdateWarning !== null && !is_string($bypassUpdateWarning))
            || !is_bool($applyPending)
            || !is_bool($syncPending)
            || !is_bool($stopRequested)
            || !is_bool($removing)
            || ($cronMinute !== null && (!is_int($cronMinute) || $cronMinute < 0 || $cronMinute > 59))
        ) {
            throw new RuntimeException('Sinkhole state is invalid.');
        }

        return [
            'schema_version' => 1,
            'unbound_previous' => $previous,
            'compile_request' => $compileRequest,
            'compiled_request' => $compiledRequest,
            'compile_error' => $compileError,
            'compiled_generation' => $compiledGeneration,
            'content_digest' => $contentDigest,
            'deployed_generation' => $deployedGeneration,
            'deployed_digest' => $deployedDigest,
            'flush_owed_generation' => $flushOwedGeneration,
            'bypass_configuration_warning' => $bypassConfigurationWarning,
            'bypass_update_warning' => $bypassUpdateWarning,
            'apply_pending' => $applyPending,
            'sync_pending' => $syncPending,
            'stop_requested' => $stopRequested,
            'removing' => $removing,
            'cron_minute' => $cronMinute,
        ];
    }

    /**
     * State Store - Save Previous Unbound Settings Once.
     *
     * The first successful enable captures the three Resolver values. Repeated saves
     * while Sinkhole remains active never overwrite that recovery point.
     *
     * @param array{
     *     python: array{present: bool, value: mixed},
     *     python_order: array{present: bool, value: mixed},
     *     python_script: array{present: bool, value: mixed}
     * } $settings - Resolver settings.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function savePreviousUnboundSettingsOnce(array $settings): void
    {
        $this->mutate(static function (array $state) use ($settings): array {
            if ($state['unbound_previous'] !== null) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['unbound_previous'] = $settings;

            return [
                'state' => $state,
                'value' => null,
            ];
        });
    }

    /**
     * State Store - Previous Unbound Settings.
     *
     * Returns the saved recovery point or null when Sinkhole has never owned the slot.
     *
     * @return array|null
     *
     * @since 1.0.0
     */
    public function previousUnboundSettings(): ?array
    {
        return $this->read()['unbound_previous'];
    }

    /**
     * State Store - Clear Previous Unbound Settings.
     *
     * Clearing after restoration lets a later enable capture administrator changes
     * made while Sinkhole was disabled.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function clearPreviousUnboundSettings(): void
    {
        if ($this->removalCleanupComplete()) {
            return;
        }

        $this->mutate(static function (array $state): array {
            if ($state['unbound_previous'] === null) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['unbound_previous'] = null;

            return [
                'state' => $state,
                'value' => null,
            ];
        }, true);
    }

    /**
     * State Store - Mark Compile Needed.
     *
     * Every configuration or saved-list change receives its own monotonic request so
     * a change arriving during a compile remains pending afterward.
     *
     * @return int
     *
     * @since 1.0.0
     */
    public function markCompileNeeded(): int
    {
        return $this->mutate(static function (array $state): array {
            $state['compile_request']++;

            return [
                'state' => $state,
                'value' => $state['compile_request'],
            ];
        });
    }

    /**
     * State Store - Compile Needed.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function compileNeeded(): bool
    {
        $state = $this->read();

        return $state['compiled_request'] < $state['compile_request'];
    }

    /**
     * State Store - Compile Request.
     *
     * A compiler snapshots this counter before reading input and records only that
     * value on success.
     *
     * @return int
     *
     * @since 1.0.0
     */
    public function compileRequest(): int
    {
        return $this->read()['compile_request'];
    }

    /**
     * State Store - Record Compile Success.
     *
     * Records the request captured at compile start without clearing a newer request
     * that arrived while output was being built.
     *
     * @param string $generation     - Compiled generation.
     * @param int    $compileRequest - Captured compile request.
     * @param string $contentDigest  - Compiled content digest.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function recordCompileSuccess(
        string $generation,
        int $compileRequest,
        string $contentDigest,
    ): void {
        if (
            $compileRequest < 1
            || preg_match('/^[a-f0-9]{64}$/D', $contentDigest) !== 1
        ) {
            throw new RuntimeException('The compile result is invalid.');
        }

        $this->mutate(static function (array $state) use (
            $generation,
            $compileRequest,
            $contentDigest,
        ): array {
            $recordedRequest = min($compileRequest, $state['compile_request']);
            $state['compiled_request'] = max($state['compiled_request'], $recordedRequest);
            $state['compile_error'] = null;
            $state['compiled_generation'] = $generation;
            $state['content_digest'] = $contentDigest;

            return [
                'state' => $state,
                'value' => null,
            ];
        });
    }

    /**
     * State Store - Record Deployment.
     *
     * Only a validated generation present in the Unbound runtime updates these
     * fields, keeping inactive compiles distinct from deployed policy.
     *
     * @param string $generation    - Runtime generation.
     * @param string $contentDigest - Runtime content digest.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function recordDeployment(string $generation, string $contentDigest): void
    {
        if (
            $generation === ''
            || preg_match('/^[a-f0-9]{64}$/D', $contentDigest) !== 1
        ) {
            throw new RuntimeException('The deployment result is invalid.');
        }

        $this->mutate(static function (array $state) use ($generation, $contentDigest): array {
            $state['deployed_generation'] = $generation;
            $state['deployed_digest'] = $contentDigest;

            return [
                'state' => $state,
                'value' => null,
            ];
        });
    }

    /**
     * State Store - Clear Deployment.
     *
     * Resolver disablement removes the runtime generation, so later enablement must
     * compare compiled policy against an explicitly absent deployment.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function clearDeployment(): void
    {
        if ($this->removalCleanupComplete()) {
            return;
        }

        $this->mutate(static function (array $state): array {
            if (
                $state['deployed_generation'] === null
                && $state['deployed_digest'] === null
                && $state['flush_owed_generation'] === null
            ) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['deployed_generation'] = null;
            $state['deployed_digest'] = null;
            $state['flush_owed_generation'] = null;

            return [
                'state' => $state,
                'value' => null,
            ];
        }, true);
    }

    /**
     * State Store - Mark Cache Clear Owed.
     *
     * Deployment records this generation while holding the runtime lock so a
     * different background owner can complete the cache handoff later.
     *
     * @param string $generation - Deployed generation.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function markCacheClearOwed(string $generation): void
    {
        if ($generation === '') {
            throw new RuntimeException('The cache-clear generation is invalid.');
        }

        $this->mutate(static function (array $state) use ($generation): array {
            if ($state['flush_owed_generation'] === $generation) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['flush_owed_generation'] = $generation;

            return [
                'state' => $state,
                'value' => null,
            ];
        });
    }

    /**
     * State Store - Cache Clear Owed Generation.
     *
     * Background jobs inspect this durable handoff before deciding whether a cache
     * clear must be retried.
     *
     * @return string|null
     *
     * @since 1.0.0
     */
    public function cacheClearOwedGeneration(): ?string
    {
        return $this->read()['flush_owed_generation'];
    }

    /**
     * State Store - Clear Cache Clear Owed.
     *
     * A successful cache clear removes only the generation it handled, preserving a
     * newer deployment that may have recorded another obligation concurrently.
     *
     * @param string $generation - Cleared generation.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function clearCacheClearOwed(string $generation): void
    {
        $this->mutate(static function (array $state) use ($generation): array {
            if ($state['flush_owed_generation'] !== $generation) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['flush_owed_generation'] = null;

            return [
                'state' => $state,
                'value' => null,
            ];
        });
    }

    /**
     * State Store - Deployment Status.
     *
     * Active jobs use the same digest comparison and reason that the Status page
     * reports, while a missing runtime generation always requires deployment.
     *
     * @param bool $runtimeMissing - Whether validated runtime data is absent.
     *
     * @return array{
     *     needed: bool,
     *     reason: string,
     *     compiled_digest: string|null,
     *     deployed_digest: string|null,
     *     deployed_generation: string|null
     * }
     *
     * @since 1.0.0
     */
    public function deploymentStatus(bool $runtimeMissing): array
    {
        $state = $this->read();
        $reason = '';

        if ($runtimeMissing) {
            $reason = 'The runtime generation is missing.';
        } elseif ($state['content_digest'] === null) {
            $reason = 'No compiled content digest is recorded.';
        } elseif ($state['deployed_digest'] === null) {
            $reason = 'The compiled generation has not been deployed.';
        } elseif ($state['content_digest'] !== $state['deployed_digest']) {
            $reason = 'The deployed content digest differs from the compiled content digest.';
        }

        return [
            'needed' => $reason !== '',
            'reason' => $reason,
            'compiled_digest' => $state['content_digest'],
            'deployed_digest' => $state['deployed_digest'],
            'deployed_generation' => $state['deployed_generation'],
        ];
    }

    /**
     * State Store - Record Compile Failure.
     *
     * The bounded reason remains visible while the unrecorded request forces a later
     * updater or apply job to retry.
     *
     * @param string $message - Safe failure reason.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function recordCompileFailure(string $message): void
    {
        $this->mutate(static function (array $state) use ($message): array {
            $state['compile_error'] = substr(
                str_replace(["\r", "\n"], ' ', $message),
                0,
                1000,
            );

            return [
                'state' => $state,
                'value' => null,
            ];
        });
    }

    /**
     * State Store - Compile Status.
     *
     * @return array{
     *     needed: bool,
     *     error: string|null,
     *     generation: string|null,
     *     digest: string|null,
     *     deployed_generation: string|null,
     *     deployed_digest: string|null,
     *     request: int,
     *     compiled_request: int
     * }
     *
     * @since 1.0.0
     */
    public function compileStatus(): array
    {
        $state = $this->read();

        return [
            'needed' => $state['compiled_request'] < $state['compile_request'],
            'error' => $state['compile_error'],
            'generation' => $state['compiled_generation'],
            'digest' => $state['content_digest'],
            'deployed_generation' => $state['deployed_generation'],
            'deployed_digest' => $state['deployed_digest'],
            'request' => $state['compile_request'],
            'compiled_request' => $state['compiled_request'],
        ];
    }

    /**
     * State Store - Mark Apply Pending.
     *
     * A colliding WebGUI apply records handoff work for the running update job.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function markApplyPending(): void
    {
        $this->mutate(static function (array $state): array {
            if ($state['apply_pending']) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['apply_pending'] = true;

            return [
                'state' => $state,
                'value' => null,
            ];
        });
    }

    /**
     * State Store - Consume Apply Pending.
     *
     * The update-lock owner clears and returns one pending handoff before release.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function consumeApplyPending(): bool
    {
        return $this->mutate(static function (array $state): array {
            $pending = $state['apply_pending'];

            if ($pending) {
                $state['apply_pending'] = false;
            }

            return [
                'state' => ($pending) ? $state : null,
                'value' => $pending,
            ];
        });
    }

    /**
     * State Store - Apply Pending.
     *
     * Update-lock owners re-check this read-only flag only after releasing the lock,
     * closing the final handoff window without probing the advisory lock.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function applyPending(): bool
    {
        return $this->read()['apply_pending'];
    }

    /**
     * State Store - Mark Synchronization Pending.
     *
     * A bounded Sync timeout leaves integration work for the update job currently
     * compiling under the runtime lock.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function markSyncPending(): void
    {
        $this->mutate(static function (array $state): array {
            if ($state['sync_pending']) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['sync_pending'] = true;

            return [
                'state' => $state,
                'value' => null,
            ];
        });
    }

    /**
     * State Store - Consume Synchronization Pending.
     *
     * The runtime-lock owner clears the flag immediately before applying the latest
     * Resolver integration state under that same lock.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function consumeSyncPending(): bool
    {
        if ($this->removalCleanupComplete()) {
            return false;
        }

        return $this->mutate(static function (array $state): array {
            $pending = $state['sync_pending'];

            if ($pending) {
                $state['sync_pending'] = false;
            }

            return [
                'state' => ($pending) ? $state : null,
                'value' => $pending,
            ];
        }, true);
    }

    /**
     * State Store - Synchronization Pending.
     *
     * Status and tests can inspect pending lifecycle work without acquiring the
     * runtime lock.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function syncPending(): bool
    {
        return $this->read()['sync_pending'];
    }

    /**
     * State Store - Request Stop.
     *
     * Keep Settings off uses this durable flag to stop an update between lists or
     * before compilation before persistent files are considered for deletion.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function requestStop(): void
    {
        if ($this->removalCleanupComplete()) {
            return;
        }

        $this->mutate(static function (array $state): array {
            if ($state['stop_requested']) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['stop_requested'] = true;

            return [
                'state' => $state,
                'value' => null,
            ];
        }, true);
    }

    /**
     * State Store - Clear Stop Request.
     *
     * A later installed-package synchronization starts a new lifecycle and permits
     * its background jobs to use retained data again.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function clearStopRequest(): void
    {
        $this->mutate(static function (array $state): array {
            if ($state['stop_requested'] === false) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['stop_requested'] = false;

            return [
                'state' => $state,
                'value' => null,
            ];
        }, true);
    }

    /**
     * State Store - Stop Requested.
     *
     * Update jobs use a read-only check between bounded units of work.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function stopRequested(): bool
    {
        return $this->read()['stop_requested'];
    }

    /**
     * State Store - Mark Removing.
     *
     * Removal records durable lifecycle intent before any cleanup so a concurrent
     * package Sync cannot restore transient integration.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function markRemoving(): void
    {
        if ($this->removalCleanupComplete()) {
            return;
        }

        $this->mutate(static function (array $state): array {
            if ($state['removing']) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['removing'] = true;

            return [
                'state' => $state,
                'value' => null,
            ];
        }, true);

        self::$removingPaths[$this->path] = true;
    }

    /**
     * State Store - Clear Removing.
     *
     * Only the install hook starts a new installed lifecycle and clears this marker.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function clearRemoving(): void
    {
        $this->mutate(static function (array $state): array {
            if ($state['removing'] === false) {
                return [
                    'state' => null,
                    'value' => null,
                ];
            }

            $state['removing'] = false;

            return [
                'state' => $state,
                'value' => null,
            ];
        }, true);

        unset(self::$removingPaths[$this->path]);
    }

    /**
     * State Store - Removing.
     *
     * Sync, update, and Status callers use this read-only lifecycle marker.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function removing(): bool
    {
        return isset(self::$removingPaths[$this->path]) || $this->read()['removing'];
    }

    /**
     * State Store - Record Client Map Success.
     *
     * Stores the last completed rebuild independently from the map file's last
     * content change and reports whether the conflict set changed.
     *
     * @param string $refreshedAt - Completed rebuild time.
     * @param string $generatedAt - Current map content generation time.
     * @param string $conflictsDigest - Digest of the current conflict set.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function recordClientMapSuccess(
        string $refreshedAt,
        string $generatedAt,
        string $conflictsDigest,
    ): bool {
        if (preg_match('/^[a-f0-9]{64}$/D', $conflictsDigest) !== 1) {
            throw new RuntimeException('The Sinkhole client conflict digest is invalid.');
        }

        return $this->mutateStatus(static function (array $status) use (
            $refreshedAt,
            $generatedAt,
            $conflictsDigest,
        ): array {
            $changed = $status['client_conflicts_digest'] !== $conflictsDigest;
            $status['client_map_refreshed_at'] = $refreshedAt;
            $status['client_map_generated_at'] = $generatedAt;
            $status['client_map_error'] = null;
            $status['client_conflicts_digest'] = $conflictsDigest;

            return ['status' => $status, 'value' => $changed];
        });
    }

    /**
     * State Store - Record Client Map Error.
     *
     * Retains the last good timestamps while exposing the latest refresh failure.
     *
     * @param string $message - Failure message.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function recordClientMapError(string $message): void
    {
        $this->mutateStatus(static function (array $status) use ($message): array {
            if ($status['client_map_error'] === $message) {
                return ['status' => null, 'value' => null];
            }

            $status['client_map_error'] = $message;

            return ['status' => $status, 'value' => null];
        });
    }

    /**
     * State Store - Client Map Status.
     *
     * Returns the timestamps and error displayed on the Status page.
     *
     * @return array{
     *     refreshed_at: string|null,
     *     generated_at: string|null,
     *     error: string|null,
     *     conflicts_digest: string|null
     * }
     *
     * @since 1.0.0
     */
    public function clientMapStatus(): array
    {
        $status = $this->readStatus();

        return [
            'refreshed_at' => $status['client_map_refreshed_at'],
            'generated_at' => $status['client_map_generated_at'],
            'error' => $status['client_map_error'],
            'conflicts_digest' => $status['client_conflicts_digest'],
        ];
    }

    /**
     * State Store - Record Bypass Configuration Warning.
     *
     * Compiler fallback reasons survive reboot with the package recovery state and
     * never create a path inside the DNS Resolver's runtime root.
     *
     * @param string|null $message - Current compiler fallback reason.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function recordBypassConfigurationWarning(?string $message): void
    {
        $this->mutate(static function (array $state) use ($message): array {
            if ($state['bypass_configuration_warning'] === $message) {
                return ['state' => null, 'value' => null];
            }

            $state['bypass_configuration_warning'] = $message;

            return ['state' => $state, 'value' => null];
        });
    }

    /**
     * State Store - Record Bypass Update Warning.
     *
     * Independent update failures remain visible across reboot without coupling
     * package status to the DNS Resolver's runtime storage.
     *
     * @param string|null $message - Current independent update failure.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function recordBypassUpdateWarning(?string $message): void
    {
        $this->mutate(static function (array $state) use ($message): array {
            if ($state['bypass_update_warning'] === $message) {
                return ['state' => null, 'value' => null];
            }

            $state['bypass_update_warning'] = $message;

            return ['state' => $state, 'value' => null];
        });
    }

    /**
     * State Store - Bypass Status.
     *
     * The Status page reads durable compiler and updater warnings independently
     * from high-frequency client-map and alert counters.
     *
     * @return array{configuration_warning: string|null, update_warning: string|null}
     *
     * @since 1.0.0
     */
    public function bypassStatus(): array
    {
        $state = $this->read();

        return [
            'configuration_warning' => $state['bypass_configuration_warning'],
            'update_warning' => $state['bypass_update_warning'],
        ];
    }

    /**
     * State Store - Record Alert Status.
     *
     * @param string $lastRun - Completed run time.
     * @param int $eventsRead - Event lines read.
     * @param int $eventsStale - Stale block events discarded.
     * @param int $notificationsSent - Logical notifications delivered.
     * @param int $notificationsHeldBack - Notifications held by a delivery cap.
     * @param int $eventsDropped - Module drop counter.
     * @param string|null $lastError - Last run error summary.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function recordAlertStatus(
        string $lastRun,
        int $eventsRead,
        int $eventsStale,
        int $notificationsSent,
        int $notificationsHeldBack,
        int $eventsDropped,
        ?string $lastError,
    ): void {
        if (
            $eventsRead < 0
            || $eventsStale < 0
            || $notificationsSent < 0
            || $notificationsHeldBack < 0
            || $eventsDropped < 0
        ) {
            throw new RuntimeException('Sinkhole alert status is invalid.');
        }

        $this->mutateStatus(static function (array $status) use (
            $lastRun,
            $eventsRead,
            $eventsStale,
            $notificationsSent,
            $notificationsHeldBack,
            $eventsDropped,
            $lastError,
        ): array {
            $status['alert_last_run'] = $lastRun;
            $status['alert_events_read'] = $eventsRead;
            $status['alert_events_stale'] = $eventsStale;
            $status['alert_notifications_sent'] = $notificationsSent;
            $status['alert_notifications_held_back'] = $notificationsHeldBack;
            $status['alert_events_dropped'] = $eventsDropped;
            $status['alert_last_error'] = $lastError;

            return ['status' => $status, 'value' => null];
        });
    }

    /**
     * State Store - Alert Status.
     *
     * @return array{
     *     last_run: string|null,
     *     events_read: int,
     *     events_stale: int,
     *     notifications_sent: int,
     *     notifications_held_back: int,
     *     events_dropped: int,
     *     last_error: string|null
     * }
     *
     * @since 1.0.0
     */
    public function alertStatus(): array
    {
        $status = $this->readStatus();

        return [
            'last_run' => $status['alert_last_run'],
            'events_read' => $status['alert_events_read'],
            'events_stale' => $status['alert_events_stale'],
            'notifications_sent' => $status['alert_notifications_sent'],
            'notifications_held_back' => $status['alert_notifications_held_back'],
            'events_dropped' => $status['alert_events_dropped'],
            'last_error' => $status['alert_last_error'],
        ];
    }

    /**
     * State Store - Cron Minute.
     *
     * Chooses one installation-specific minute and persists it across every boot and
     * WAN-triggered package synchronization.
     *
     * @return int
     *
     * @since 1.0.0
     */
    public function cronMinute(): int
    {
        return $this->mutate(static function (array $state): array {
            if ($state['cron_minute'] !== null) {
                return [
                    'state' => null,
                    'value' => $state['cron_minute'],
                ];
            }

            $state['cron_minute'] = random_int(0, 59);

            return [
                'state' => $state,
                'value' => $state['cron_minute'],
            ];
        });
    }

    /**
     * State Store - Sweep Temporary Files.
     *
     * Removes interrupted atomic replacements while holding the same short lock as
     * live state writes.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function sweepTemporaryFiles(): void
    {
        if ($this->removalCleanupComplete()) {
            return;
        }

        $this->mutate(static fn(array $state): array => [
            'state' => null,
            'value' => null,
        ], true);
    }

    /**
     * State Store - Read Status.
     *
     * Missing runtime status is expected after a reboot. The document contains
     * only timestamps, counts, errors, and a conflict digest, never client data.
     *
     * @return array
     *
     * @throws RuntimeException When runtime status cannot be decoded or validated.
     *
     * @since 1.0.0
     * @private
     */
    private function readStatus(): array
    {
        $fileStatus = @lstat($this->statusPath);

        if (!is_array($fileStatus)) {
            return self::emptyStatus();
        }

        if (
            ($fileStatus['mode'] & 0170000) !== 0100000
            || ($fileStatus['mode'] & 0777) !== 0644
            || $fileStatus['size'] > self::MAXIMUM_STATUS_BYTES
        ) {
            throw new RuntimeException('Sinkhole runtime status is unsafe.');
        }

        $contents = file_get_contents($this->statusPath);

        if (!is_string($contents)) {
            throw new RuntimeException('Unable to read Sinkhole runtime status.');
        }

        try {
            $status = json_decode($contents, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('Sinkhole runtime status is invalid.', 0, $exception);
        }

        if (
            !is_array($status)
            || ($status['schema_version'] ?? null) !== self::STATUS_SCHEMA_VERSION
        ) {
            throw new RuntimeException('Sinkhole runtime status is invalid.');
        }

        $clientMapRefreshedAt = $status['client_map_refreshed_at'] ?? null;
        $clientMapGeneratedAt = $status['client_map_generated_at'] ?? null;
        $clientMapError = $status['client_map_error'] ?? null;
        $clientConflictsDigest = $status['client_conflicts_digest'] ?? null;
        $alertLastRun = $status['alert_last_run'] ?? null;
        $alertEventsRead = $status['alert_events_read'] ?? 0;
        $alertEventsStale = $status['alert_events_stale'] ?? 0;
        $alertNotificationsSent = $status['alert_notifications_sent'] ?? 0;
        $alertNotificationsHeldBack = $status['alert_notifications_held_back'] ?? 0;
        $alertEventsDropped = $status['alert_events_dropped'] ?? 0;
        $alertLastError = $status['alert_last_error'] ?? null;

        if (
            ($clientMapRefreshedAt !== null && !is_string($clientMapRefreshedAt))
            || ($clientMapGeneratedAt !== null && !is_string($clientMapGeneratedAt))
            || ($clientMapError !== null && !is_string($clientMapError))
            || (
                $clientConflictsDigest !== null
                && (
                    !is_string($clientConflictsDigest)
                    || preg_match('/^[a-f0-9]{64}$/D', $clientConflictsDigest) !== 1
                )
            )
            || ($alertLastRun !== null && !is_string($alertLastRun))
            || !is_int($alertEventsRead)
            || $alertEventsRead < 0
            || !is_int($alertEventsStale)
            || $alertEventsStale < 0
            || !is_int($alertNotificationsSent)
            || $alertNotificationsSent < 0
            || !is_int($alertNotificationsHeldBack)
            || $alertNotificationsHeldBack < 0
            || !is_int($alertEventsDropped)
            || $alertEventsDropped < 0
            || ($alertLastError !== null && !is_string($alertLastError))
        ) {
            throw new RuntimeException('Sinkhole runtime status is invalid.');
        }

        return [
            'schema_version' => self::STATUS_SCHEMA_VERSION,
            'client_map_refreshed_at' => $clientMapRefreshedAt,
            'client_map_generated_at' => $clientMapGeneratedAt,
            'client_map_error' => $clientMapError,
            'client_conflicts_digest' => $clientConflictsDigest,
            'alert_last_run' => $alertLastRun,
            'alert_events_read' => $alertEventsRead,
            'alert_events_stale' => $alertEventsStale,
            'alert_notifications_sent' => $alertNotificationsSent,
            'alert_notifications_held_back' => $alertNotificationsHeldBack,
            'alert_events_dropped' => $alertEventsDropped,
            'alert_last_error' => $alertLastError,
        ];
    }

    /**
     * State Store - Mutate Status.
     *
     * Runtime status has its own lock and atomic replacement so minute jobs never
     * contend with persistent compile or lifecycle state.
     *
     * @param callable(array): array{status: array|null, value: mixed} $mutation - Mutation.
     *
     * @return mixed
     *
     * @since 1.0.0
     * @private
     */
    private function mutateStatus(callable $mutation): mixed
    {
        if ($this->removing()) {
            throw new RuntimeException('Sinkhole removal is in progress.');
        }

        FileSystem::ensureDirectory(dirname($this->statusPath), 0755);

        $lock = new FileLock($this->statusPath . '.lock');

        if ($lock->acquire(30) === false) {
            throw new RuntimeException('Timed out waiting for the Sinkhole status lock.');
        }

        try {
            FileSystem::sweepStaleEntries(
                dirname($this->statusPath),
                ['.sinkhole-atomic-'],
            );
            $currentStatus = $this->readStatus();
            $result = $mutation($currentStatus);
            $status = $result['status'];

            if (is_array($status) && $status !== $currentStatus) {
                $this->writeStatus($status);
            }

            return $result['value'];
        } finally {
            $lock->release();
        }
    }

    /**
     * State Store - Removal Cleanup Complete.
     *
     * Once the current process has deleted persistent storage, cleanup-only
     * mutations become no-ops so a late Sync cannot recreate the directory.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function removalCleanupComplete(): bool
    {
        return isset(self::$removingPaths[$this->path])
            && @lstat($this->path) === false;
    }

    /**
     * State Store - Write Status.
     *
     * The root-run package jobs publish a world-readable, client-data-free status
     * document for the WebGUI and replace it atomically at mode 0644.
     *
     * @param array $status - Runtime status.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function writeStatus(array $status): void
    {
        try {
            $contents = json_encode(
                $status,
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $exception) {
            throw new RuntimeException('Unable to encode Sinkhole runtime status.', 0, $exception);
        }

        AtomicFile::write($this->statusPath, $contents . PHP_EOL, 0644);
    }

    /**
     * State Store - Mutate.
     *
     * Serializes each read-modify-write transition so concurrent WebGUI changes and
     * compiler completions cannot overwrite one another's request counters. Ordinary
     * writers stop before directory or lock creation while removal is in progress.
     *
     * @param callable(array): array{state: array|null, value: mixed} $mutation - Mutation.
     * @param bool $allowWhileRemoving - Whether lifecycle cleanup may update retained state.
     *
     * @return mixed
     *
     * @throws RuntimeException When the short state lock cannot be acquired.
     *
     * @since 1.0.0
     * @private
     */
    private function mutate(callable $mutation, bool $allowWhileRemoving = false): mixed
    {
        if ($allowWhileRemoving === false && $this->removing()) {
            throw new RuntimeException('Sinkhole removal is in progress.');
        }

        FileSystem::ensureDirectory(dirname($this->path), 0700);

        $lock = new FileLock($this->path . '.lock');

        if ($lock->acquire(30) === false) {
            throw new RuntimeException('Timed out waiting for the Sinkhole state lock.');
        }

        try {
            FileSystem::sweepStaleEntries(
                dirname($this->path),
                ['.sinkhole-atomic-'],
            );
            $currentState = $this->read();

            if ($allowWhileRemoving === false && $currentState['removing']) {
                throw new RuntimeException('Sinkhole removal is in progress.');
            }

            $result = $mutation($currentState);
            $state = $result['state'];

            if (is_array($state)) {
                $this->write($state);
            }

            return $result['value'];
        } finally {
            $lock->release();
        }
    }

    /**
     * State Store - Write.
     *
     * Encodes a complete state document and replaces the old file atomically.
     *
     * @param array $state - State.
     *
     * @return void
     *
     * @throws RuntimeException When encoding fails.
     *
     * @since 1.0.0
     * @private
     */
    private function write(array $state): void
    {
        try {
            $contents = json_encode(
                $state,
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $exception) {
            throw new RuntimeException('Unable to encode Sinkhole state.', 0, $exception);
        }

        AtomicFile::write($this->path, $contents . PHP_EOL);
    }

    /**
     * State Store - Empty State.
     *
     * The initial request guarantees a fresh install compiles saved data once.
     *
     * @return array
     *
     * @since 1.0.0
     * @private
     */
    private static function emptyState(): array
    {
        return [
            'schema_version' => 1,
            'unbound_previous' => null,
            'compile_request' => 1,
            'compiled_request' => 0,
            'compile_error' => null,
            'compiled_generation' => null,
            'content_digest' => null,
            'deployed_generation' => null,
            'deployed_digest' => null,
            'flush_owed_generation' => null,
            'bypass_configuration_warning' => null,
            'bypass_update_warning' => null,
            'apply_pending' => false,
            'sync_pending' => false,
            'stop_requested' => false,
            'removing' => false,
            'cron_minute' => null,
        ];
    }

    /**
     * State Store - Empty Status.
     *
     * Reboot loss is harmless, so missing runtime status starts with empty display
     * values and zero counts without creating a file.
     *
     * @return array
     *
     * @since 1.0.0
     * @private
     */
    private static function emptyStatus(): array
    {
        return [
            'schema_version' => self::STATUS_SCHEMA_VERSION,
            'client_map_refreshed_at' => null,
            'client_map_generated_at' => null,
            'client_map_error' => null,
            'client_conflicts_digest' => null,
            'alert_last_run' => null,
            'alert_events_read' => 0,
            'alert_events_stale' => 0,
            'alert_notifications_sent' => 0,
            'alert_notifications_held_back' => 0,
            'alert_events_dropped' => 0,
            'alert_last_error' => null,
        ];
    }
}
