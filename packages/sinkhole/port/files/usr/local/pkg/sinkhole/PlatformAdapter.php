<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

/**
 * Platform Adapter.
 *
 * Keeps pfSense configuration and logging APIs outside the updater's pure download,
 * parsing, storage, and compilation flow.
 *
 * @since 1.0.0
 */
interface PlatformAdapter
{
    /**
     * Platform Adapter - Assert Environment.
     *
     * Production loads and verifies the required fixed pfSense APIs before work begins.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function assertEnvironment(): void;

    /**
     * Platform Adapter - Settings.
     *
     * Returns the untrusted general settings record for runtime validation.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getSettings(): array;

    /**
     * Platform Adapter - Lists.
     *
     * Returns the untrusted configured list map for runtime validation.
     *
     * @return mixed
     *
     * @since 1.0.0
     */
    public function getLists(): mixed;

    /**
     * Platform Adapter - Allowed Domains.
     *
     * Returns the untrusted repeated global allowlist elements as persisted.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getAllowedDomains(): array;

    /**
     * Platform Adapter - Networks.
     *
     * Returns validated network scopes for compilation.
     *
     * @return array<string, array>
     *
     * @since 1.0.0
     */
    public function getNetworks(): array;

    /**
     * Platform Adapter - Devices.
     *
     * Returns validated device scopes in precedence order for compilation.
     *
     * @return array<string, array>
     *
     * @since 1.0.0
     */
    public function getDevices(): array;

    /**
     * Platform Adapter - Alerts.
     *
     * Returns validated alert rules for compilation.
     *
     * @return array<string, array>
     *
     * @since 1.0.0
     */
    public function getAlerts(): array;

    /**
     * Platform Adapter - Blocked Services.
     *
     * Returns normalized per-scope service identifiers for compilation.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getBlockedServices(): array;

    /**
     * Platform Adapter - Bypass Configuration.
     *
     * Returns partitioned Bypass Protection settings and the current DDR endpoint.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getBypassConfiguration(): array;

    /**
     * Platform Adapter - Refresh Configuration.
     *
     * Command-line adapters re-read configuration before a compiler snapshots its
     * inputs; adapters inside pfSense-owned processes leave live state untouched.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function refreshConfiguration(): void;

    /**
     * Platform Adapter - Uses Memory File System.
     *
     * Selects whether the compiler must maintain persistent boot mirror data.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function usesMemoryFileSystem(): bool;

    /**
     * Platform Adapter - Is Integration Active.
     *
     * Deployment is allowed only when the package and Resolver are enabled and
     * Sinkhole owns the configured Python slot.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function isIntegrationActive(): bool;

    /**
     * Platform Adapter - Runtime Generation Missing.
     *
     * An active integration recompiles when its validated generation disappeared,
     * including after a RAM-disk reset before the boot restore could complete.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function runtimeGenerationMissing(): bool;

    /**
     * Platform Adapter - Update Should Stop.
     *
     * Removal can stop a long update between lists and before compilation without
     * deleting persistent data out from under the running process.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function updateShouldStop(): bool;

    /**
     * Platform Adapter - Synchronize Integration Under Lock.
     *
     * A runtime-lock owner applies pending Resolver lifecycle state before releasing
     * the lock, including compile-before-enable recovery after reinstall.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function synchronizeIntegrationUnderLock(): void;

    /**
     * Platform Adapter - Reload Unbound After Deploy.
     *
     * Background jobs wait for the deployed generation marker and then execute the
     * platform's fixed Unbound reload command when names were added.
     *
     * @param string $generation - Deployed generation.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function reloadUnboundAfterDeploy(string $generation): void;

    /**
     * Platform Adapter - Log.
     *
     * Writes a safe operational summary without list contents or full configuration.
     *
     * @param string $message - Safe message.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function log(string $message): void;
}
