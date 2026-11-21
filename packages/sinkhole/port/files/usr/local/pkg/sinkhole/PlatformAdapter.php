<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

/**
 * Platform Adapter.
 *
 * Keeps pfSense configuration, notice, cron, filter, and logging APIs outside the
 * updater's pure flow and every other package class, so a pfSense API change
 * touches only the adapter.
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
     * Platform Adapter - SafeSearch.
     *
     * Returns normalized per-scope SafeSearch choices for compilation.
     *
     * @return array
     *
     * @since 1.1.0
     */
    public function getSafeSearch(): array;

    /**
     * Platform Adapter - Refresh SafeSearch Targets.
     *
     * Looks up the safe hosts of every choice in use and keeps last good addresses.
     *
     * @return bool Whether any compiled address changed.
     *
     * @since 1.1.0
     */
    public function refreshSafeSearchTargets(): bool;

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

    /**
     * Platform Adapter - Can Read Configuration.
     *
     * Domain helpers run in tests and tooling without pfSense, so they check this
     * before reading saved configuration.
     *
     * @return bool
     *
     * @since 1.3.3
     */
    public function canReadConfiguration(): bool;

    /**
     * Platform Adapter - Can Write Configuration.
     *
     * Domain helpers check this before staging a configuration change.
     *
     * @return bool
     *
     * @since 1.3.3
     */
    public function canWriteConfiguration(): bool;

    /**
     * Platform Adapter - Read Configuration Path.
     *
     * Returns one saved configuration value, or the default when the path is missing.
     *
     * @param string $path - Configuration path.
     * @param mixed $default - Value for a missing path.
     *
     * @return mixed
     *
     * @since 1.3.3
     */
    public function readConfigurationPath(string $path, mixed $default = null): mixed;

    /**
     * Platform Adapter - Write Configuration Path.
     *
     * Stages one in-memory configuration value; saveConfiguration() persists it.
     *
     * @param string $path - Configuration path.
     * @param mixed $value - New value.
     *
     * @return void
     *
     * @since 1.3.3
     */
    public function writeConfigurationPath(string $path, mixed $value): void;

    /**
     * Platform Adapter - Remove Configuration Path.
     *
     * Stages the removal of one configuration path.
     *
     * @param string $path - Configuration path.
     *
     * @return void
     *
     * @since 1.3.3
     */
    public function removeConfigurationPath(string $path): void;

    /**
     * Platform Adapter - Configuration Path Enabled.
     *
     * Reports whether a configuration section carries its enable flag.
     *
     * @param string $path - Configuration path.
     * @param string $enableKey - Flag name.
     *
     * @return bool
     *
     * @since 1.3.3
     */
    public function configurationPathEnabled(string $path, string $enableKey = 'enable'): bool;

    /**
     * Platform Adapter - Save Configuration.
     *
     * Persists staged configuration with the platform's default backup and revision
     * handling.
     *
     * @param string $description - Revision description.
     *
     * @return void
     *
     * @since 1.3.3
     */
    public function saveConfiguration(string $description): void;

    /**
     * Platform Adapter - Install Cron Job.
     *
     * Adds, replaces, or removes one cron job by its command. Defaults match the
     * platform's own, so a removal passes only the command and false.
     *
     * @param string $command - Command the job runs.
     * @param bool $active - Whether the job is installed or removed.
     * @param string $minute - Minute field.
     * @param string $hour - Hour field.
     * @param string $monthDay - Day-of-month field.
     * @param string $month - Month field.
     * @param string $weekDay - Day-of-week field.
     * @param string $who - User the job runs as.
     *
     * @return void
     *
     * @since 1.3.3
     */
    public function installCronJob(
        string $command,
        bool $active,
        string $minute = '0',
        string $hour = '*',
        string $monthDay = '*',
        string $month = '*',
        string $weekDay = '*',
        string $who = 'root',
    ): void;

    /**
     * Platform Adapter - Regenerate Crontab.
     *
     * Rewrites the system crontab from saved configuration.
     *
     * @return void
     *
     * @since 1.3.3
     */
    public function regenerateCrontab(): void;

    /**
     * Platform Adapter - Require Notice API.
     *
     * Loads the notice functions when needed and names the first one still missing,
     * or returns null when they are all available.
     *
     * @param bool $includeFiling - Whether filing notices is also required.
     *
     * @return string|null
     *
     * @since 1.3.3
     */
    public function requireNoticeApi(bool $includeFiling): ?string;

    /**
     * Platform Adapter - Get Notices.
     *
     * Returns the notice queue keyed by queue key, false when it is empty or the API
     * is unavailable, or another value the caller must reject.
     *
     * @param string|null $category - Optional notice category.
     *
     * @return mixed
     *
     * @since 1.3.3
     */
    public function getNotices(?string $category = null): mixed;

    /**
     * Platform Adapter - Close Notice.
     *
     * Closes one notice by queue key or stored identifier when the API is available.
     *
     * @param int|string $identifier - Queue key or stored identifier.
     *
     * @return void
     *
     * @since 1.3.3
     */
    public function closeNotice(int|string $identifier): void;

    /**
     * Platform Adapter - File Notice.
     *
     * Files one notice with every field given exactly and returns the platform result.
     *
     * @param string $identifier - Notice identifier.
     * @param string $message - Notice text.
     * @param string $category - Notice category.
     * @param string $url - Notice link.
     * @param int $priority - Notice priority.
     * @param bool $localOnly - Whether remote delivery is disabled.
     *
     * @return mixed
     *
     * @since 1.3.3
     */
    public function fileNotice(
        string $identifier,
        string $message,
        string $category,
        string $url,
        int $priority,
        bool $localOnly,
    ): mixed;

    /**
     * Platform Adapter - Notify Remote.
     *
     * Sends one message through every configured remote notification channel.
     *
     * @param string $message - Notification text.
     *
     * @return mixed
     *
     * @since 1.3.3
     */
    public function notifyRemote(string $message): mixed;

    /**
     * Platform Adapter - Product Label.
     *
     * Returns the product label the platform shows, an empty string for a malformed
     * value, or null when the platform globals are unavailable.
     *
     * @return string|null
     *
     * @since 1.3.3
     */
    public function productLabel(): ?string;

    /**
     * Platform Adapter - Translate Platform Text.
     *
     * Translates one platform source string through the platform's own catalog, so
     * notice matching sees the exact wording the platform wrote.
     *
     * @param string $text - Platform source text.
     *
     * @return string
     *
     * @since 1.3.3
     */
    public function translatePlatformText(string $text): string;

    /**
     * Platform Adapter - System Log.
     *
     * Writes one complete line to the system log exactly as given, and reports false
     * when the platform logger is unavailable.
     *
     * @param string $line - Complete log line.
     *
     * @return bool
     *
     * @since 1.3.3
     */
    public function systemLog(string $line): bool;

    /**
     * Platform Adapter - Process ID File Running.
     *
     * Reports whether the process named by a PID file is still running.
     *
     * @param string $pidFile - PID file path.
     *
     * @return bool
     *
     * @since 1.3.3
     */
    public function processIdFileRunning(string $pidFile): bool;

    /**
     * Platform Adapter - Configured Interface Descriptions.
     *
     * Returns assigned interfaces keyed by friendly name with their descriptions, or
     * an empty list when the interface API is unavailable.
     *
     * @return array<string, string>
     *
     * @since 1.3.3
     */
    public function configuredInterfaceDescriptions(): array;

    /**
     * Platform Adapter - Reconfigure Filter.
     *
     * Reloads the firewall filter when the platform's filter functions are already
     * loaded, and does nothing otherwise, as package pages always have.
     *
     * @return void
     *
     * @since 1.3.3
     */
    public function reconfigureFilter(): void;

    /**
     * Platform Adapter - Assert Update Environment.
     *
     * Release checks and self-updates load only configuration, proxy, notice, and
     * logging includes, never the integration side effects.
     *
     * @return void
     *
     * @since 1.3.3
     */
    public function assertUpdateEnvironment(): void;

    /**
     * Platform Adapter - Installed Packages.
     *
     * Returns installed-package records, or an empty list without a configuration API.
     *
     * @return array
     *
     * @since 1.3.3
     */
    public function installedPackages(): array;

    /**
     * Platform Adapter - Parse Package XML.
     *
     * Parses one package XML file, or returns null when no parser can be loaded.
     *
     * @param string $path - XML file path.
     * @param string $rootElement - Expected root element.
     *
     * @return mixed
     *
     * @since 1.3.3
     */
    public function parsePackageXml(string $path, string $rootElement): mixed;

    /**
     * Platform Adapter - Configured Language.
     *
     * Returns the selected platform language, or null without a configuration API.
     *
     * @return string|null
     *
     * @since 1.3.3
     */
    public function configuredLanguage(): ?string;
}
