<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\AlertConfiguration;
use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\ListConfiguration;
use PfSense\Sinkhole\Domain\IpConfiguration;
use PfSense\Sinkhole\Domain\ScopeConfiguration;
use PfSense\Sinkhole\Domain\ServiceConfiguration;
use PfSense\Sinkhole\Domain\Settings;
use PfSense\Sinkhole\Domain\ValidationException;
use PfSense\Sinkhole\Runtime\CatalogCache;
use PfSense\Sinkhole\Runtime\BypassListStore;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\FileLock;
use PfSense\Sinkhole\Runtime\FileSystem;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\PfSenseAdapter;
use PfSense\Sinkhole\Runtime\SavedListStore;
use PfSense\Sinkhole\Runtime\ServiceRegistryCache;
use PfSense\Sinkhole\Runtime\StateStore;
use PfSense\Sinkhole\Runtime\Translator;
use PfSense\Sinkhole\Runtime\UpdateManager;

require_once('config.inc');
require_once('pfsense-utils.inc');
require_once('services.inc');
require_once('util.inc');
require_once(__DIR__ . '/sinkhole/Compiler.php');
require_once(__DIR__ . '/sinkhole/BypassConfiguration.php');
require_once(__DIR__ . '/sinkhole/BypassListStore.php');
require_once(__DIR__ . '/sinkhole/CatalogCache.php');
require_once(__DIR__ . '/sinkhole/AlertConfiguration.php');
require_once(__DIR__ . '/sinkhole/FileLock.php');
require_once(__DIR__ . '/sinkhole/FileSystem.php');
require_once(__DIR__ . '/sinkhole/ListConfiguration.php');
require_once(__DIR__ . '/sinkhole/IpConfiguration.php');
require_once(__DIR__ . '/sinkhole/RedirectConfiguration.php');
require_once(__DIR__ . '/sinkhole/ScopeConfiguration.php');
require_once(__DIR__ . '/sinkhole/ServiceConfiguration.php');
require_once(__DIR__ . '/sinkhole/ServiceRegistryCache.php');
require_once(__DIR__ . '/sinkhole/PackagePaths.php');
require_once(__DIR__ . '/sinkhole/PfSenseAdapter.php');
require_once(__DIR__ . '/sinkhole/SavedListStore.php');
require_once(__DIR__ . '/sinkhole/Settings.php');
require_once(__DIR__ . '/sinkhole/StateStore.php');
require_once(__DIR__ . '/sinkhole/Translator.php');
require_once(__DIR__ . '/sinkhole/UpdateManager.php');
require_once(__DIR__ . '/sinkhole/ValidationException.php');

/**
 * pfSense Package Sinkhole - Translate.
 *
 * @param string $key - Stable package catalog key.
 * @param array<int, scalar|null> $arguments - Positional message arguments.
 *
 * @return string
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeTranslate(string $key, array $arguments = []): string
{
    return Translator::translate($key, $arguments);
}

/**
 * pfSense Package Sinkhole - Translate Mapped Value.
 *
 * @param string $map - Translation mapping name.
 * @param string $value - Runtime value to map.
 * @param array<int, scalar|null> $arguments - Positional message arguments.
 * @param string|null $fallbackValue - Fixed mapped value used for unknown runtime values.
 *
 * @return string
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeTranslateMapped(
    string $map,
    string $value,
    array $arguments = [],
    ?string $fallbackValue = null,
): string {
    return Translator::translateMapped($map, $value, $arguments, $fallbackValue);
}

/**
 * pfSense Package Sinkhole - Throwable Message.
 *
 * Translates validation failures from their stable key. Unexpected runtime failures
 * retain their technical English detail inside a translated wrapper.
 *
 * @param Throwable $throwable - User-visible failure.
 *
 * @return string
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeThrowableMessage(Throwable $throwable): string
{
    if ($throwable instanceof ValidationException) {
        return pfsensePackageSinkholeTranslateMapped(
            'validation',
            $throwable->messageKey(),
            $throwable->messageArguments(),
        );
    }

    return pfsensePackageSinkholeTranslate('unexpected_error', [$throwable->getMessage()]);
}

/**
 * pfSense Package Sinkhole - Invalid Reason.
 *
 * @param array $invalidValue - Invalid saved row or value.
 *
 * @return string
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeInvalidReason(array $invalidValue): string
{
    $key = $invalidValue['reason_key'] ?? null;
    $arguments = $invalidValue['reason_arguments'] ?? [];

    if (is_string($key) && is_array($arguments)) {
        return pfsensePackageSinkholeTranslateMapped(
            'validation',
            $key,
            array_values($arguments),
        );
    }

    return is_string($invalidValue['reason'] ?? null)
        ? $invalidValue['reason']
        : pfsensePackageSinkholeTranslate('unknown');
}

/**
 * pfSense Package Sinkhole - Localize Package GUI.
 *
 * Translates the generic package editor's parsed XML before it builds the General
 * form. pfSense-owned wording stays in pfSense's gettext domain.
 *
 * @param array $package - Parsed package GUI definition.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeLocalizePackageGui(array &$package): void
{
    $package['title'] = gettext('Firewall') . '/Sinkhole';
    $package['aftersaveredirect'] = sprintf(
        '/pkg_edit.php?xml=sinkhole.xml&id=0&savemsg=%s',
        rawurlencode(pfsensePackageSinkholeTranslate('settings_saved_applying')),
    );
    $sourceValues = [
        'General',
        'Lists',
        'Services',
        'Scopes',
        'Alerts',
        'Bypass',
        'IP',
        'Status',
        'About',
        'Enable',
        'Enable scheduled list updates and DNS Resolver integration.',
        'Update Frequency',
        'Hourly',
        'Every 6 hours',
        'Daily',
        'Weekly',
        'Choose how often enabled block lists update.',
        'Keep Settings',
        'Keep lists and settings when the package is removed.',
        'Package Updates',
        'Update Checks',
        'Monthly',
        'Never',
        'Check GitHub for new Sinkhole releases on a stable randomized schedule.',
        'Remote Notifications',
        'Also send each new-version notice through configured pfSense remote notification services.',
    ];

    if (isset($package['tabs']['tab']) && is_array($package['tabs']['tab'])) {
        foreach ($package['tabs']['tab'] as &$tab) {
            if (
                is_array($tab)
                && is_string($tab['text'] ?? null)
                && in_array($tab['text'], $sourceValues, true)
            ) {
                $tab['text'] = pfsensePackageSinkholeTranslateMapped(
                    'package_gui',
                    $tab['text'],
                );
            }
        }
        unset($tab);
    }

    if (!isset($package['fields']['field']) || !is_array($package['fields']['field'])) {
        return;
    }

    foreach ($package['fields']['field'] as &$field) {
        if (!is_array($field)) {
            continue;
        }

        foreach (['name', 'fielddescr', 'description'] as $property) {
            if (
                is_string($field[$property] ?? null)
                && in_array($field[$property], $sourceValues, true)
            ) {
                $field[$property] = pfsensePackageSinkholeTranslateMapped(
                    'package_gui',
                    $field[$property],
                );
            }
        }

        if (!isset($field['options']['option']) || !is_array($field['options']['option'])) {
            continue;
        }

        foreach ($field['options']['option'] as &$option) {
            if (
                is_array($option)
                && is_string($option['name'] ?? null)
                && in_array($option['name'], $sourceValues, true)
            ) {
                $option['name'] = pfsensePackageSinkholeTranslateMapped(
                    'package_gui',
                    $option['name'],
                );
            }
        }
        unset($option);
    }
    unset($field);
}

/**
 * pfSense Package Sinkhole - Adapter.
 *
 * Reuses one adapter per WebGUI request while command-line runs construct their own
 * runtime boundary.
 *
 * @param PfSenseAdapter|null $replacement - Test-only request adapter replacement.
 *
 * @return PfSenseAdapter
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeAdapter(?PfSenseAdapter $replacement = null): PfSenseAdapter
{
    static $adapter = null;

    if ($replacement instanceof PfSenseAdapter) {
        $adapter = $replacement;
    }

    if (!$adapter instanceof PfSenseAdapter) {
        $adapter = new PfSenseAdapter();
    }

    return $adapter;
}

/**
 * pfSense Package Sinkhole - Tabs.
 *
 * The generic General page and eight custom pages share this ordered tab definition.
 *
 * @param string $active - Active tab.
 *
 * @return list<array{0: string, 1: bool, 2: string}>
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeTabs(string $active): array
{
    $tabs = [
        'general' => '/pkg_edit.php?xml=sinkhole.xml&id=0',
        'lists' => '/sinkhole-lists.php',
        'services' => '/sinkhole-services.php',
        'scopes' => '/sinkhole-scopes.php',
        'alerts' => '/sinkhole-alerts.php',
        'bypass' => '/sinkhole-bypass.php',
        'ip' => '/sinkhole-ip.php',
        'status' => '/sinkhole-status.php',
        'about' => '/sinkhole-about.php',
    ];
    $result = [];

    foreach ($tabs as $key => $url) {
        $result[] = [
            pfsensePackageSinkholeTranslateMapped('tab', $key),
            $key === $active,
            $url,
        ];
    }

    return $result;
}

/**
 * pfSense Package Sinkhole - Update Running.
 *
 * pfSense validates the PID recorded in a reusable lock by receiving the lock file
 * path, rather than a parsed PID value from the caller.
 *
 * @param PackagePaths $paths - Package paths.
 *
 * @return bool
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeUpdateRunning(PackagePaths $paths): bool
{
    return FileSystem::isRegularFile($paths->updateLockFile)
        && isvalidpid($paths->updateLockFile);
}

/**
 * pfSense Package Sinkhole - Status Presentation.
 *
 * Keeps inactive deployment and loaded-generation text consistent with the same
 * Resolver reason shown in the Sinkhole summary row.
 *
 * @param array{active: bool, owner: string, reason: string, reason_key?: string, reason_arguments?: array} $resolverStatus - Resolver status.
 * @param bool $sinkholeEnabled - Whether Sinkhole is deliberately enabled.
 * @param bool $deploymentNeeded - Digest-based deployment state.
 * @param string $deploymentReason - Digest-based deployment reason.
 * @param string $loadedGeneration - Last loaded marker value.
 *
 * @return array{
 *     status_text: string,
 *     deployment_needed: bool,
 *     deployment_reason: string,
 *     loaded_generation: string
 * }
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeStatusPresentation(
    array $resolverStatus,
    bool $sinkholeEnabled,
    bool $deploymentNeeded,
    string $deploymentReason,
    string $loadedGeneration,
): array {
    $statusText = pfsensePackageSinkholeTranslateMapped(
        'resolver_state',
        ($resolverStatus['active']) ? 'active' : 'inactive',
    );
    $reason = $resolverStatus['reason'];
    $reasonKey = $resolverStatus['reason_key'] ?? '';
    $reasonArguments = $resolverStatus['reason_arguments'] ?? [];

    if (is_string($reasonKey) && $reasonKey !== '' && is_array($reasonArguments)) {
        $reason = pfsensePackageSinkholeTranslateMapped(
            'resolver_reason',
            $reasonKey,
            array_values($reasonArguments),
        );
    }

    if ($reason !== '') {
        $statusText = pfsensePackageSinkholeTranslate(
            'status_with_reason',
            [$statusText, $reason],
        );
    }

    if (!$sinkholeEnabled) {
        return [
            'status_text' => $statusText,
            'deployment_needed' => false,
            'deployment_reason' => '',
            'loaded_generation' => pfsensePackageSinkholeTranslate('module_not_loaded'),
        ];
    }

    if ($resolverStatus['active'] === false) {
        return [
            'status_text' => $statusText,
            'deployment_needed' => true,
            'deployment_reason' => $statusText,
            'loaded_generation' => pfsensePackageSinkholeTranslate('module_not_loaded'),
        ];
    }

    return [
        'status_text' => $statusText,
        'deployment_needed' => $deploymentNeeded,
        'deployment_reason' => $deploymentReason,
        'loaded_generation' => ($loadedGeneration === '')
            ? pfsensePackageSinkholeTranslate('none')
            : $loadedGeneration,
    ];
}

/**
 * pfSense Package Sinkhole - Get Settings.
 *
 * Returns the untrusted general settings record for form display and validation.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetSettings(): array
{
    return pfsensePackageSinkholeAdapter()->getSettings();
}

/**
 * pfSense Package Sinkhole - Get Lists.
 *
 * Normalizes saved custom-page rows before the WebGUI or compiler uses them.
 *
 * @return array<string, array{id: string, name: string, url: string, enabled: bool, global: bool}>
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetLists(): array
{
    return ListConfiguration::normalizeLists(pfsensePackageSinkholeAdapter()->getLists());
}

/**
 * pfSense Package Sinkhole - Get List Configuration.
 *
 * Returns valid rows for runtime work and invalid rows for WebGUI repair without one
 * malformed saved entry interrupting the package.
 *
 * @return array{lists: array, invalid_rows: list<array>}
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetListConfiguration(): array
{
    return ListConfiguration::partitionLists(pfsensePackageSinkholeAdapter()->getLists());
}

/**
 * pfSense Package Sinkhole - Get Allowed Domains.
 *
 * Returns repeated allowlist configuration elements exactly as stored.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetAllowedDomains(): array
{
    return pfsensePackageSinkholeAdapter()->getAllowedDomains();
}

/**
 * pfSense Package Sinkhole - Get Blocked Services.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetBlockedServices(): array
{
    return pfsensePackageSinkholeAdapter()->getBlockedServices();
}

/**
 * pfSense Package Sinkhole - Save Blocked Services.
 *
 * @param array $configuration - Canonical per-scope selections.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeSaveBlockedServices(array $configuration): void
{
    pfsensePackageSinkholeAdapter()->saveBlockedServices($configuration);
}

/**
 * pfSense Package Sinkhole - Save Lists.
 *
 * Converts normalized boolean flags to pfSense checkbox storage and writes one
 * configuration revision.
 *
 * @param array<string, array{id: string, name: string, url: string, enabled: bool, global: bool}> $lists - Lists.
 * @param list<string> $allowedDomains - Normalized allowed domains.
 * @param list<array> $invalidRows - Invalid rows to preserve for repair.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeSaveLists(
    array $lists,
    array $allowedDomains,
    array $invalidRows = [],
): void
{
    $storageLists = [];

    foreach ($lists as $identifier => $list) {
        $storageLists[$identifier] = [
            'id' => $identifier,
            'descr' => $list['name'],
            'url' => $list['url'],
            'enabled' => ($list['enabled']) ? 'on' : '',
            'global' => ($list['global']) ? 'on' : '',
        ];
    }

    pfsensePackageSinkholeAdapter()->saveListConfiguration(
        $storageLists,
        $allowedDomains,
        $invalidRows,
    );
}

/**
 * pfSense Package Sinkhole - Get Scope Configuration.
 *
 * Returns valid scopes and preserved malformed rows for the custom page.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetScopeConfiguration(): array
{
    return pfsensePackageSinkholeAdapter()->getScopePartitions();
}

/**
 * pfSense Package Sinkhole - List Usage Counts.
 *
 * Counts valid network and device assignments for the Lists table.
 *
 * @return array<string, int>
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeListUsageCounts(): array
{
    $lists = pfsensePackageSinkholeGetLists();
    $scopes = pfsensePackageSinkholeGetScopeConfiguration();

    return ScopeConfiguration::listUsageCounts(
        $lists,
        $scopes['networks'],
        $scopes['devices'],
    );
}

/**
 * pfSense Package Sinkhole - Save Scopes.
 *
 * Converts normalized boolean flags to pfSense checkbox storage before one save.
 *
 * @param array<string, array> $networks - Valid networks.
 * @param array<string, array> $devices - Valid devices in precedence order.
 * @param list<array> $invalidNetworks - Preserved invalid networks.
 * @param list<array> $invalidDevices - Preserved invalid devices.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeSaveScopes(
    array $networks,
    array $devices,
    array $invalidNetworks = [],
    array $invalidDevices = [],
): void {
    $storageNetworks = [];
    $storageDevices = [];

    foreach ($networks as $identifier => $network) {
        $storageNetworks[$identifier] = [
            'id' => $identifier,
            'interface' => $network['interface'],
            'lists' => [
                'item' => array_values($network['lists']),
            ],
            'allowed_domains' => [
                'item' => array_values($network['allowed_domains']),
            ],
            'enabled' => $network['enabled'] ? 'on' : '',
        ];
    }

    foreach ($devices as $identifier => $device) {
        $storageDevices[$identifier] = [
            'id' => $identifier,
            'descr' => $device['name'],
            'identifier_type' => $device['identifier_type'],
            'identifier' => $device['identifier'],
            'interface' => $device['interface'],
            'lists' => [
                'item' => array_values($device['lists']),
            ],
            'allowed_domains' => [
                'item' => array_values($device['allowed_domains']),
            ],
            'enabled' => $device['enabled'] ? 'on' : '',
        ];
    }

    pfsensePackageSinkholeAdapter()->saveScopeConfiguration(
        $storageNetworks,
        $storageDevices,
        $invalidNetworks,
        $invalidDevices,
    );
}

/**
 * pfSense Package Sinkhole - Get Alert Configuration.
 *
 * Returns valid rules and malformed repair rows together.
 *
 * @return array{alerts: array<string, array>, invalid_rows: list<array>}
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetAlertConfiguration(): array
{
    return pfsensePackageSinkholeAdapter()->getAlertPartitions();
}

/**
 * pfSense Package Sinkhole - Save Alerts.
 *
 * @param array<string, array> $alerts - Valid alert rules.
 * @param list<array> $invalidRows - Invalid rows retained for repair.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeSaveAlerts(
    array $alerts,
    array $invalidRows = [],
): void {
    pfsensePackageSinkholeAdapter()->saveAlertConfiguration($alerts, $invalidRows);
}

/**
 * pfSense Package Sinkhole - Get Redirect Configuration.
 *
 * Returns valid settings and preserved malformed values for the redirect page and
 * NAT rule hook.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetRedirectConfiguration(): array
{
    return pfsensePackageSinkholeAdapter()->getRedirectConfiguration();
}

/**
 * pfSense Package Sinkhole - Save Redirect Configuration.
 *
 * Persists one validated record before pfSense reloads its filter asynchronously.
 *
 * @param array{enabled: bool, interfaces: list<string>, exempt_sources: list<string>, exempt_destinations?: list<string>} $configuration - Redirect configuration.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeSaveRedirect(array $configuration): void
{
    pfsensePackageSinkholeAdapter()->saveRedirectConfiguration($configuration);
    pfsensePackageSinkholeInstallCron();
}

/**
 * pfSense Package Sinkhole - Get Bypass Configuration.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetBypassConfiguration(): array
{
    return pfsensePackageSinkholeAdapter()->getBypassConfiguration();
}

/**
 * pfSense Package Sinkhole - Bypass Storage.
 *
 * @param array $configuration - Partitioned Bypass configuration.
 * @param array<string, array> $lists - Valid Bypass Lists.
 * @param list<array> $invalidRows - Malformed rows retained for repair.
 * @param array|null $settings - Optional submitted setting overrides.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeBypassStorage(
    array $configuration,
    array $lists,
    array $invalidRows,
    ?array $settings = null,
): array {
    $rows = [];

    foreach ($lists as $list) {
        $rows[] = [
            'id' => $list['id'],
            'descr' => $list['name'],
            'kind' => $list['kind'],
            'url' => $list['url'],
            'enabled' => $list['enabled'] ? 'on' : '',
        ];
    }

    foreach ($invalidRows as $invalidRow) {
        if (is_array($invalidRow) && array_key_exists('row', $invalidRow)) {
            $rows[] = $invalidRow['row'];
        }
    }

    $settings ??= $configuration;
    $storage = ['lists' => ['item' => $rows]];

    foreach (BypassConfiguration::BOOLEAN_FIELDS as $field) {
        $storage[$field] = ($settings[$field] ?? false) === true ? 'on' : '';
    }

    $storage['discovery'] = is_string($settings['discovery'] ?? null)
        ? $settings['discovery']
        : BypassConfiguration::DISCOVERY_OFF;

    return $storage;
}

/**
 * pfSense Package Sinkhole - Save Bypass Configuration.
 *
 * @param array $storage - Complete Bypass storage record.
 * @param array $redirectConfiguration - Existing redirect settings with shared interfaces.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeSaveBypass(
    array $storage,
    array $redirectConfiguration,
): void {
    pfsensePackageSinkholeAdapter()->saveBypassConfiguration(
        $storage,
        $redirectConfiguration,
    );
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
}

/**
 * pfSense Package Sinkhole - Get IP Configuration.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetIpConfiguration(): array
{
    return pfsensePackageSinkholeAdapter()->getIpConfiguration();
}

/**
 * pfSense Package Sinkhole - Save IP Configuration.
 *
 * @param array $storage - Complete validated storage record.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeSaveIp(array $storage): void
{
    pfsensePackageSinkholeAdapter()->saveIpConfiguration($storage);
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
}

/**
 * pfSense Package Sinkhole - Filter Rules.
 *
 * Supplies independent IP and Bypass anchor references to pfearly, nothing to filter, and keeps
 * DNS redirect text isolated to the NAT pass.
 *
 * @param string $ruleType - pfSense rule-discovery type.
 *
 * @return string
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeFilterRules(string $ruleType): string
{
    if (!in_array($ruleType, ['pfearly', 'filter', 'nat'], true)) {
        return '';
    }

    if ($ruleType === 'filter') {
        return '';
    }

    $adapter = pfsensePackageSinkholeAdapter();

    if ($ruleType === 'pfearly') {
        $ruleText = '';

        try {
            $ruleText .= $adapter->ipRuleText();
        } catch (Throwable $throwable) {
            $adapter->log('IP blocking rules were omitted: ' . $throwable->getMessage());
        }

        try {
            $ruleText .= $adapter->bypassRuleText();
        } catch (Throwable $throwable) {
            $adapter->log('Bypass blocking rules were omitted: ' . $throwable->getMessage());
        }

        if ($ruleText !== '') {
            try {
                $adapter->clearRedirectRuleError();
            } catch (Throwable $throwable) {
                $adapter->log(
                    'Unable to clear the package-rule error after loading early rules: '
                    . $throwable->getMessage(),
                );
            }
        }

        return $ruleText;
    }

    try {
        $adapter->clearRedirectRuleError();

        return $adapter->redirectRuleText();
    } catch (Throwable $throwable) {
        $adapter->log(
            'DNS redirect rules were omitted: ' . $throwable->getMessage(),
        );

        return '';
    }
}

/**
 * pfSense Package Sinkhole - Redirect Status.
 *
 * Detects the generated comment in pfSense's loaded-rule source and reports the
 * package parse file that discover_pkg_rules() keeps after a failure.
 *
 * @param string $rulesPath - pfSense generated rules path.
 * @param string $errorPath - pfSense package parse-error path.
 *
 * @return array{loaded: bool, comment_present: bool, out_of_date: bool, parse_error: string, rejected_text: string}
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeRedirectStatus(
    string $rulesPath = '/tmp/rules.debug',
    string $errorPath = '/tmp/rules.packages.sinkhole',
): array {
    return pfsensePackageSinkholeAdapter()->redirectRuleStatus($rulesPath, $errorPath);
}

/**
 * pfSense Package Sinkhole - IP Rule Status.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeIpRuleStatus(): array
{
    return pfsensePackageSinkholeAdapter()->ipRuleStatus();
}

/**
 * pfSense Package Sinkhole - Bypass Rule Status.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeBypassRuleStatus(): array
{
    return pfsensePackageSinkholeAdapter()->bypassRuleStatus();
}

/**
 * pfSense Package Sinkhole - Get Cron Fields.
 *
 * Maps only validated fixed schedule names to pfSense cron fields.
 *
 * @param string   $frequency - Update frequency.
 * @param int|null $minute    - Installation-specific randomized minute.
 *
 * @return array{string, string, string, string, string}
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetCronFields(string $frequency, ?int $minute = null): array
{
    $minute ??= 0;
    $minuteField = (string) $minute;

    return match ($frequency) {
        'hourly' => [$minuteField, '*', '*', '*', '*'],
        'every_six_hours' => [$minuteField, '*/6', '*', '*', '*'],
        'weekly' => [$minuteField, '0', '*', '*', '0'],
        'daily' => [$minuteField, '0', '*', '*', '*'],
        default => [$minuteField, '0', '*', '*', '*'],
    };
}

/**
 * pfSense Package Sinkhole - Get Update Schedule.
 *
 * Generates invalid or absent randomized components once and persists them beside
 * the package settings so frequency changes and resynchronization remain stable.
 * Removal may still reach this getter through a config callback, so the durable
 * marker suppresses every write once teardown begins.
 *
 * @return array{minute: int, hour: int, weekday: int, monthday: int}
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeGetUpdateSchedule(): array
{
    $storedSchedule = config_get_path(PackagePaths::UPDATE_SCHEDULE_PATH, []);
    $storedSchedule = is_array($storedSchedule) ? $storedSchedule : [];
    $schedule = UpdateManager::stableCronSchedule($storedSchedule);
    $normalizedStoredSchedule = [];
    $paths = pfsensePackageSinkholeAdapter()->packagePaths();
    $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
    $removing = true;

    try {
        $removing = $stateStore->removing();
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to read the removal marker; not saving the update schedule: '
            . $throwable->getMessage(),
        );
    }

    foreach (array_keys($schedule) as $key) {
        $storedValue = $storedSchedule[$key] ?? null;

        if (is_int($storedValue) || (is_string($storedValue) && ctype_digit($storedValue))) {
            $normalizedStoredSchedule[$key] = (int) $storedValue;
        }
    }

    if ($removing === false && $normalizedStoredSchedule !== $schedule) {
        config_set_path(PackagePaths::UPDATE_SCHEDULE_PATH, $schedule);
        write_config(pfsensePackageSinkholeTranslate('stable_update_schedule_saved'));
    }

    return $schedule;
}

/**
 * pfSense Package Sinkhole - Install Update Cron.
 *
 * Reconciles the independent GitHub release check. Never removes only scheduled
 * checks; the About page's manual check remains available.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeInstallUpdateCron(): void
{
    install_cron_job(PackagePaths::UPDATE_CHECK_COMMAND, false);

    if (UpdateManager::isAvailable() === false) {
        return;
    }

    $settings = pfsensePackageSinkholeGetSettings();
    $frequency = (string) ($settings['update_check_frequency'] ?? 'weekly');

    if ($frequency === 'never') {
        return;
    }

    $fields = UpdateManager::cronFields(
        $frequency,
        pfsensePackageSinkholeGetUpdateSchedule(),
    );

    if ($fields === null) {
        return;
    }

    install_cron_job(
        PackagePaths::UPDATE_CHECK_COMMAND,
        true,
        $fields[0],
        $fields[1],
        $fields[2],
        $fields[3],
        $fields[4],
        'root',
    );
}

/**
 * pfSense Package Sinkhole - Compile.
 *
 * Builds current scope-ready data after list configuration changes and during package
 * synchronization.
 *
 * @return array
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeCompile(): array
{
    $paths = pfsensePackageSinkholeAdapter()->packagePaths();
    $store = new SavedListStore($paths);
    $compiler = new Compiler(
        $paths,
        $store,
        null,
        null,
        new BypassListStore($paths),
    );
    $dnsBlockingEnabled = Settings::fromStorage(
        pfsensePackageSinkholeAdapter()->getSettings(),
    )['enabled'];

    return $compiler->compile(
        $dnsBlockingEnabled ? pfsensePackageSinkholeAdapter()->getLists() : [],
        pfsensePackageSinkholeAdapter()->getAllowedDomains(),
        pfsensePackageSinkholeAdapter()->usesMemoryFileSystem(),
        static fn(): bool => pfsensePackageSinkholeAdapter()->isIntegrationActive(),
        static function (): array {
            pfsensePackageSinkholeAdapter()->refreshConfiguration();
            $dnsBlockingEnabled = Settings::fromStorage(
                pfsensePackageSinkholeAdapter()->getSettings(),
            )['enabled'];

            return [
                'lists' => $dnsBlockingEnabled
                    ? pfsensePackageSinkholeAdapter()->getLists()
                    : [],
                'allowed_domains' => pfsensePackageSinkholeAdapter()->getAllowedDomains(),
                'networks' => $dnsBlockingEnabled
                    ? pfsensePackageSinkholeAdapter()->getNetworks()
                    : [],
                'devices' => $dnsBlockingEnabled
                    ? pfsensePackageSinkholeAdapter()->getDevices()
                    : [],
                'alerts' => $dnsBlockingEnabled
                    ? pfsensePackageSinkholeAdapter()->getAlerts()
                    : [],
                'services' => $dnsBlockingEnabled
                    ? pfsensePackageSinkholeAdapter()->getBlockedServices()
                    : [],
                'bypass' => pfsensePackageSinkholeAdapter()->getBypassConfiguration(),
            ];
        },
        false,
        static function (): void {
            pfsensePackageSinkholeAdapter()->synchronizeIntegrationUnderLock();
        },
    );
}

/**
 * pfSense Package Sinkhole - Install Cron.
 *
 * Reconciles the update, client refresh, alert, and Bypass-check entries. Native
 * code updates each fixed command in place only when its desired state differs.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeInstallCron(): void
{
    $enabled = false;
    $ipEnabled = false;
    $bypassEnabled = false;
    $bypassUpdateEnabled = false;
    $bypassConfiguration = [
        'dns_enabled' => false,
        'firewall_enabled' => false,
        'lists' => [],
    ];
    $updateEnabled = false;
    $clientRefreshEnabled = false;
    $alertsEnabled = false;
    $redirectCheckEnabled = false;
    $fields = ['0', '0', '*', '*', '*'];

    try {
        $settings = Settings::fromStorage(pfsensePackageSinkholeGetSettings());
        $enabled = $settings['enabled'];
        $ipConfiguration = pfsensePackageSinkholeGetIpConfiguration();
        $ipEnabled = $ipConfiguration['enabled'];
        $bypassConfiguration = pfsensePackageSinkholeGetBypassConfiguration();
        $bypassEnabled = $bypassConfiguration['enabled'];
        $bypassUpdateEnabled = $bypassEnabled || count(array_filter(
            $bypassConfiguration['lists'],
            static fn(array $list): bool => ($list['enabled'] ?? false) === true
                && is_string($list['kind'] ?? null)
                && BypassConfiguration::kindEnabled(
                    $bypassConfiguration,
                    $list['kind'],
                ),
        )) > 0;
        $updateEnabled = $enabled || $ipEnabled || $bypassUpdateEnabled;

        if ($updateEnabled) {
            $minute = pfsensePackageSinkholeAdapter()->cronMinute();
            $fields = pfsensePackageSinkholeGetCronFields(
                $settings['update_frequency'],
                $minute,
            );
        }

        $clientRefreshEnabled = pfsensePackageSinkholeClientRefreshEnabled(
            $enabled,
            $bypassConfiguration,
        );

        if ($enabled) {
            $alertsEnabled = count(array_filter(
                pfsensePackageSinkholeAdapter()->getAlerts(),
                static fn(array $alert): bool => ($alert['enabled'] ?? false) === true,
            )) > 0;
            $redirectConfiguration = pfsensePackageSinkholeAdapter()
                ->getRedirectConfiguration();
            $redirectCheckEnabled = $redirectConfiguration['enabled'];
        }

        $redirectCheckEnabled = $redirectCheckEnabled
            || $ipEnabled
            || $bypassConfiguration['firewall_enabled'];
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log($throwable->getMessage());
    }

    install_cron_job(
        PackagePaths::COMMAND . ' --update',
        $updateEnabled,
        $fields[0],
        $fields[1],
        $fields[2],
        $fields[3],
        $fields[4],
        'root',
    );
    install_cron_job(
        PackagePaths::COMMAND . ' --refresh-clients',
        $clientRefreshEnabled,
        '*',
        '*',
        '*',
        '*',
        '*',
        'root',
    );
    install_cron_job(
        PackagePaths::COMMAND . ' --alerts',
        $enabled && $alertsEnabled,
        '*',
        '*',
        '*',
        '*',
        '*',
        'root',
    );
    install_cron_job(
        PackagePaths::COMMAND . ' --redirect-check',
        $redirectCheckEnabled,
        '*',
        '*',
        '*',
        '*',
        '*',
        'root',
    );

    if (!$enabled || !$alertsEnabled) {
        pfsensePackageSinkholeClearAlertHistory(
            pfsensePackageSinkholeAdapter()->packagePaths(),
        );
    }

    if (!$redirectCheckEnabled) {
        pfsensePackageSinkholeClearRedirectCheckFiles(5);
    }
}

/**
 * pfSense Package Sinkhole - Client Refresh Enabled.
 *
 * Client discovery is needed only when DNS blocking has an enabled network or
 * device scope, or when Bypass DNS protection resolves selected interfaces.
 *
 * @param bool  $dnsBlockingEnabled - Whether ordinary DNS blocking is enabled.
 * @param array $bypassConfiguration - Validated Bypass configuration.
 *
 * @return bool
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeClientRefreshEnabled(
    bool $dnsBlockingEnabled,
    array $bypassConfiguration,
): bool {
    if (($bypassConfiguration['dns_enabled'] ?? false) === true) {
        return true;
    }

    if ($dnsBlockingEnabled === false) {
        return false;
    }

    $scopes = array_merge(
        array_values(pfsensePackageSinkholeAdapter()->getNetworks()),
        array_values(pfsensePackageSinkholeAdapter()->getDevices()),
    );

    return count(array_filter(
        $scopes,
        static fn(array $scope): bool => ($scope['enabled'] ?? false) === true,
    )) > 0;
}

/**
 * pfSense Package Sinkhole - Clear Redirect Check Files.
 *
 * Removes the transient previous observation and reusable lock after its fixed
 * schedule is absent, without placing minute-changing state under "/cf/conf".
 *
 * @param int $lockTimeoutSeconds - Maximum redirect-check lock wait.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeClearRedirectCheckFiles(
    int $lockTimeoutSeconds = 0,
): void {
    try {
        $cleared = pfsensePackageSinkholeAdapter()->clearRedirectCheckFiles(
            $lockTimeoutSeconds,
        );

        if ($cleared === false) {
            pfsensePackageSinkholeAdapter()->log(
                'Redirect check is still running; transient cleanup is pending.',
            );
        }
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to clear redirect check files: ' . $throwable->getMessage(),
        );
    }
}

/**
 * pfSense Package Sinkhole - Clear Alert History.
 *
 * Once the alert schedule is absent, remove every queued or repeated block record
 * by fixed name. A lock timeout does not leave history behind indefinitely.
 *
 * @param PackagePaths $paths - Package paths.
 * @param int $lockTimeoutSeconds - Maximum alert-lock wait.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeClearAlertHistory(
    PackagePaths $paths,
    int $lockTimeoutSeconds = 40,
): void {
    $lock = new FileLock($paths->alertLockFile);
    $locked = false;

    try {
        $locked = $lock->acquire($lockTimeoutSeconds);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Alert history lock failed; clearing fixed files now: '
            . $throwable->getMessage(),
        );
    }

    if (!$locked) {
        pfsensePackageSinkholeAdapter()->log(sprintf(
            'Alert job is still running after %d seconds; clearing fixed history files now.',
            $lockTimeoutSeconds,
        ));
    }

    try {
        foreach ([
            $paths->eventsFile,
            $paths->eventsProcessingFile,
            $paths->eventsDroppedFile,
            $paths->alertRepeatStateFile,
        ] as $path) {
            try {
                FileSystem::removeFixedFile($path);
            } catch (Throwable $throwable) {
                pfsensePackageSinkholeAdapter()->log(
                    'Unable to clear alert history file: ' . $throwable->getMessage(),
                );
            }
        }
    } finally {
        if ($locked) {
            $lock->release();
        }
    }
}

/**
 * pfSense Package Sinkhole - Disable Cron.
 *
 * Removes all fixed schedule entries during disablement and removal.
 *
 * @param bool $clearAlertHistory - Whether to remove queued and repeated blocks.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeDisableCron(bool $clearAlertHistory = true): void
{
    install_cron_job(PackagePaths::COMMAND . ' --update', false);
    install_cron_job(PackagePaths::COMMAND . ' --refresh-clients', false);
    install_cron_job(PackagePaths::COMMAND . ' --alerts', false);
    install_cron_job(PackagePaths::COMMAND . ' --redirect-check', false);
    install_cron_job(PackagePaths::UPDATE_CHECK_COMMAND, false);

    pfsensePackageSinkholeClearRedirectCheckFiles(40);

    if ($clearAlertHistory) {
        pfsensePackageSinkholeClearAlertHistory(
            pfsensePackageSinkholeAdapter()->packagePaths(),
        );
    }
}

/**
 * pfSense Package Sinkhole - Install.
 *
 * Starts a new installed lifecycle by clearing removal and stop markers before the
 * ordinary package synchronization evaluates current settings.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeInstall(): void
{
    $paths = pfsensePackageSinkholeAdapter()->packagePaths();
    $stateStore = new StateStore($paths->stateFile, $paths->statusFile);

    try {
        $stateStore->clearRemoving();
        $stateStore->clearStopRequest();
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to start the installed lifecycle: ' . $throwable->getMessage(),
        );
    }

    write_config(pfsensePackageSinkholeTranslate('revision_registered_redirect_hook'));
    pfsensePackageSinkholeSync();

    try {
        $redirectConfiguration = pfsensePackageSinkholeGetRedirectConfiguration();
        $ipConfiguration = pfsensePackageSinkholeGetIpConfiguration();
        $bypassConfiguration = pfsensePackageSinkholeGetBypassConfiguration();

        if (
            $redirectConfiguration['enabled'] === false
            && $ipConfiguration['enabled'] === false
            && $bypassConfiguration['firewall_enabled'] === false
        ) {
            return;
        }

        pfsensePackageSinkholeAdapter()->reloadFilter();
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to apply Sinkhole package rules after install or upgrade: '
            . $throwable->getMessage(),
        );
    }
}

/**
 * pfSense Package Sinkhole - Clear Removal Runtime Files.
 *
 * Removes fixed transient status and lock names only after their locks are no
 * longer held, matching the redirect-check cleanup's unlink-after-release order.
 *
 * @param PackagePaths $paths - Package-owned paths.
 * @param int $lockTimeoutSeconds - Maximum client and status lock wait.
 * @param bool $alertLockReleased - Whether removal acquired and released the alert lock.
 * @param bool $runtimeLockReleased - Whether removal acquired and released the runtime lock.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeClearRemovalRuntimeFiles(
    PackagePaths $paths,
    int $lockTimeoutSeconds,
    bool $alertLockReleased,
    bool $runtimeLockReleased,
): void {
    $releasedLockFiles = [];

    if ($alertLockReleased) {
        $releasedLockFiles[] = $paths->alertLockFile;
    }

    if ($runtimeLockReleased) {
        $releasedLockFiles[] = $paths->runtimeLockFile;
    }

    foreach ($releasedLockFiles as $releasedLockFile) {
        try {
            FileSystem::removeFixedFile($releasedLockFile);
        } catch (Throwable $throwable) {
            pfsensePackageSinkholeAdapter()->log(
                'Unable to remove a released Sinkhole lock file: '
                . $throwable->getMessage(),
            );
        }
    }

    $clientLock = new FileLock($paths->clientLockFile);

    try {
        if ($clientLock->acquire($lockTimeoutSeconds)) {
            $clientLock->release();
            FileSystem::removeFixedFile($paths->clientLockFile);
        }
    } catch (Throwable $throwable) {
        $clientLock->release();
        pfsensePackageSinkholeAdapter()->log(
            'Unable to remove the Sinkhole client lock file: ' . $throwable->getMessage(),
        );
    }

    $statusLock = new FileLock($paths->statusLockFile);

    try {
        if ($statusLock->acquire($lockTimeoutSeconds)) {
            FileSystem::removeFixedFile($paths->statusFile);
            $statusLock->release();
            FileSystem::removeFixedFile($paths->statusLockFile);
        }
    } catch (Throwable $throwable) {
        $statusLock->release();
        pfsensePackageSinkholeAdapter()->log(
            'Unable to remove Sinkhole status files: ' . $throwable->getMessage(),
        );
    }
}

/**
 * pfSense Package Sinkhole - Synchronize.
 *
 * Runs on install, upgrade, and General-page saves to keep cron, compiled local data,
 * the Python slot, runtime files, and RAM-disk boot restoration consistent.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeSync(
    int $lockTimeoutSeconds = Compiler::RUNTIME_LOCK_TIMEOUT_SECONDS,
): void
{
    $paths = pfsensePackageSinkholeAdapter()->packagePaths();
    $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
    $removing = true;

    try {
        $removing = $stateStore->removing();
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to read the removal marker; disabling integration: '
            . $throwable->getMessage(),
        );
    }

    if ($removing) {
        pfsensePackageSinkholeDisableCron();
    } else {
        pfsensePackageSinkholeInstallCron();
        pfsensePackageSinkholeInstallUpdateCron();
    }

    $lock = new FileLock($paths->runtimeLockFile);
    $locked = false;
    $applyCurrentSynchronization = true;

    try {
        $locked = $lock->acquire($lockTimeoutSeconds);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Runtime lock failed; synchronization is pending: ' . $throwable->getMessage(),
        );
    }

    if ($locked === false) {
        $applyCurrentSynchronization = false;

        try {
            $stateStore->markSyncPending();
        } catch (Throwable $throwable) {
            pfsensePackageSinkholeAdapter()->log(
                'Unable to record pending synchronization: ' . $throwable->getMessage(),
            );
        }

        pfsensePackageSinkholeAdapter()->log(sprintf(
            'Runtime lock timed out after %d seconds; synchronization is pending.',
            $lockTimeoutSeconds,
        ));

        try {
            $locked = $lock->acquire();
        } catch (Throwable $throwable) {
            pfsensePackageSinkholeAdapter()->log(
                'Runtime lock retry failed; synchronization remains pending: '
                . $throwable->getMessage(),
            );
        }
    }

    if ($locked) {
        try {
            if ($applyCurrentSynchronization) {
                pfsensePackageSinkholeAdapter()->synchronizeIntegrationUnderLock();
            }

            while ($stateStore->consumeSyncPending()) {
                try {
                    pfsensePackageSinkholeAdapter()->synchronizeIntegrationUnderLock();
                } catch (Throwable $throwable) {
                    $stateStore->markSyncPending();

                    throw $throwable;
                }
            }
        } catch (Throwable $throwable) {
            pfsensePackageSinkholeAdapter()->log(
                'Synchronization failed: ' . $throwable->getMessage(),
            );
        } finally {
            $lock->release();
        }
    }

    try {
        pfsensePackageSinkholeAdapter()->applyIpAnchor();
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'IP anchor synchronization failed: ' . $throwable->getMessage(),
        );
    }

    try {
        pfsensePackageSinkholeAdapter()->applyBypassAnchor();
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Bypass anchor synchronization failed: ' . $throwable->getMessage(),
        );
    }

    if ($removing) {
        return;
    }

    try {
        if ($stateStore->removing()) {
            pfsensePackageSinkholeDisableCron();

            return;
        }

        $settings = Settings::fromStorage(pfsensePackageSinkholeGetSettings());
        $ipConfiguration = pfsensePackageSinkholeGetIpConfiguration();
        $bypassConfiguration = pfsensePackageSinkholeGetBypassConfiguration();
        $hasEnabledBypassList = count(array_filter(
            $bypassConfiguration['lists'],
            static fn(array $list): bool => ($list['enabled'] ?? false) === true
                && is_string($list['kind'] ?? null)
                && BypassConfiguration::kindEnabled(
                    $bypassConfiguration,
                    $list['kind'],
                ),
        )) > 0;

        if (
            $settings['enabled']
            || $ipConfiguration['enabled']
            || $bypassConfiguration['enabled']
            || $hasEnabledBypassList
        ) {
            pfsensePackageSinkholeAdapter()->runApplyInBackground();
        }
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Background apply handoff failed: ' . $throwable->getMessage(),
        );
    }

    try {
        $settings = Settings::fromStorage(pfsensePackageSinkholeGetSettings());
        $bypassConfiguration = pfsensePackageSinkholeGetBypassConfiguration();

        if (pfsensePackageSinkholeClientRefreshEnabled(
            $settings['enabled'],
            $bypassConfiguration,
        )) {
            pfsensePackageSinkholeAdapter()->runClientRefreshInBackground();
        }
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Background client refresh handoff failed: ' . $throwable->getMessage(),
        );
    }
}

/**
 * pfSense Package Sinkhole - Mark Removing.
 *
 * Package removal entry points record durable intent before schedules, runtime
 * files, settings, or Resolver configuration can change.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeMarkRemoving(): void
{
    $paths = pfsensePackageSinkholeAdapter()->packagePaths();
    $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
    $wasRemoving = false;
    $markedRemoving = false;

    try {
        $wasRemoving = $stateStore->removing();
        $stateStore->markRemoving();
        $markedRemoving = true;
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to record package removal: ' . $throwable->getMessage(),
        );
    }

    try {
        pfsensePackageSinkholeAdapter()->flushIpAnchor();
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to flush the Sinkhole IP anchor during removal: '
            . $throwable->getMessage(),
        );
    }

    try {
        pfsensePackageSinkholeAdapter()->flushBypassAnchor();
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to flush the Sinkhole Bypass anchor during removal: '
            . $throwable->getMessage(),
        );
    }

    if ($markedRemoving === true && $wasRemoving === false) {
        try {
            pfsensePackageSinkholeAdapter()->reloadFilter();
        } catch (Throwable $throwable) {
            pfsensePackageSinkholeAdapter()->log(
                'Unable to remove Sinkhole package rules: ' . $throwable->getMessage(),
            );
        }
    }
}

/**
 * pfSense Package Sinkhole - Deinstall.
 *
 * Stops scheduling, restores Resolver settings, and removes runtime files and boot
 * state. Persistent data remains available across package upgrades.
 *
 * @param int $lockTimeoutSeconds - Maximum runtime-lock wait.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeDeinstall(
    int $lockTimeoutSeconds = Compiler::RUNTIME_LOCK_TIMEOUT_SECONDS,
): void
{
    pfsensePackageSinkholeDisableCron();
    $paths = pfsensePackageSinkholeAdapter()->packagePaths();
    $lock = new FileLock($paths->runtimeLockFile);
    $locked = false;

    try {
        $locked = $lock->acquire($lockTimeoutSeconds);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Runtime lock failed during deinstall: ' . $throwable->getMessage(),
        );
    }

    if ($locked === false) {
        pfsensePackageSinkholeAdapter()->log(sprintf(
            'Runtime lock timed out after %d seconds; restoring the Resolver now.',
            $lockTimeoutSeconds,
        ));
    }

    try {
        pfsensePackageSinkholeAdapter()->disableDnsResolverIntegration(true);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log('Deinstall failed: ' . $throwable->getMessage());
    } finally {
        if ($locked) {
            $lock->release();
        }
    }
}

/**
 * pfSense Package Sinkhole - Delete Configuration Entry.
 *
 * A package-GUI delete request disables transient integration but preserves lists,
 * compiler state, and saved data for an explicit package removal decision.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeDelete(): void
{
    pfsensePackageSinkholeDeinstall();
}

/**
 * pfSense Package Sinkhole - Package Deinstall.
 *
 * FreeBSD sets "PKG_UPGRADE" while replacing a package. Upgrade deinstalls retain
 * schedules, integration, runtime files, settings, and saved data while the removal
 * marker protects the gap until the install hook clears it. An ordinary package
 * removal performs the complete removal flow.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholePackageDeinstall(): void
{
    $packageUpgrade = getenv('PKG_UPGRADE');

    if (is_string($packageUpgrade) && $packageUpgrade !== '') {
        pfsensePackageSinkholeMarkRemoving();

        return;
    }

    pfsensePackageSinkholeRemove();
}

/**
 * pfSense Package Sinkhole - Remove.
 *
 * Performs deinstall cleanup and deletes package-owned persistent data only for a
 * package removal, not for the upgrade deinstall hook.
 *
 * @param int $lockTimeoutSeconds - Maximum runtime and update lock wait.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeRemove(
    int $lockTimeoutSeconds = Compiler::RUNTIME_LOCK_TIMEOUT_SECONDS,
): void
{
    $paths = pfsensePackageSinkholeAdapter()->packagePaths();

    // A repeated pre-deinstall callback must not recreate the deleted state store.
    if (
        config_get_path('installedpackages/sinkhole', null) === null
        && file_exists($paths->persistentDirectory) === false
        && is_link($paths->persistentDirectory) === false
    ) {
        return;
    }

    pfsensePackageSinkholeMarkRemoving();
    pfsensePackageSinkholeDisableCron(false);

    if (function_exists('close_notice')) {
        close_notice(UpdateManager::NOTICE_ID);
    } elseif (is_readable('/etc/inc/notices.inc')) {
        require_once('/etc/inc/notices.inc');

        if (function_exists('close_notice')) {
            close_notice(UpdateManager::NOTICE_ID);
        }
    }

    $keepSettings = true;

    try {
        $settings = Settings::fromStorage(pfsensePackageSinkholeGetSettings());
        $keepSettings = $settings['keep_settings'];
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Invalid removal settings; keeping saved data: ' . $throwable->getMessage(),
        );
    }

    $stateStore = new StateStore($paths->stateFile, $paths->statusFile);

    if ($keepSettings === false) {
        try {
            $stateStore->requestStop();
        } catch (Throwable $throwable) {
            $keepSettings = true;
            pfsensePackageSinkholeAdapter()->log(
                'Unable to stop update jobs; keeping saved data: ' . $throwable->getMessage(),
            );
        }
    }

    $alertLock = new FileLock($paths->alertLockFile);
    $alertLocked = false;

    try {
        $alertLocked = $alertLock->acquire($lockTimeoutSeconds);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Alert lock failed during removal: ' . $throwable->getMessage(),
        );
    }

    if ($alertLocked === false) {
        pfsensePackageSinkholeAdapter()->log(sprintf(
            'Alert job is still running after %d seconds; restoring the Resolver now.',
            $lockTimeoutSeconds,
        ));
        $keepSettings = true;
    }

    $runtimeLock = new FileLock($paths->runtimeLockFile);
    $runtimeLocked = false;

    try {
        $runtimeLocked = $runtimeLock->acquire($lockTimeoutSeconds);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Runtime lock failed during removal: ' . $throwable->getMessage(),
        );
    }

    if ($runtimeLocked === false) {
        pfsensePackageSinkholeAdapter()->log(sprintf(
            'Runtime lock timed out after %d seconds; restoring the Resolver now.',
            $lockTimeoutSeconds,
        ));
    }

    try {
        pfsensePackageSinkholeAdapter()->uninstall(
            true,
            true,
            $lockTimeoutSeconds,
            false,
        );
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log('Removal failed: ' . $throwable->getMessage());
    } finally {
        if ($runtimeLocked) {
            $runtimeLock->release();
        }

        if ($alertLocked) {
            $alertLock->release();
        }
    }

    try {
        pfsensePackageSinkholeAdapter()->clearRedirectRuleError();
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to remove the DNS redirect rule error file: '
            . $throwable->getMessage(),
        );
    }

    pfsensePackageSinkholeClearRemovalRuntimeFiles(
        $paths,
        $lockTimeoutSeconds,
        $alertLocked,
        $runtimeLocked,
    );

    try {
        CatalogCache::removeCacheFiles($paths);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to remove the popular-list catalog cache: '
            . $throwable->getMessage(),
        );
    }

    try {
        ServiceRegistryCache::removeCacheFile($paths);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Unable to remove the blocked-services registry cache: '
            . $throwable->getMessage(),
        );
    }

    $updateLock = new FileLock($paths->updateLockFile);
    $updateLocked = false;

    try {
        $updateLocked = $updateLock->acquire($lockTimeoutSeconds);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Update lock failed during removal; keeping saved data: '
            . $throwable->getMessage(),
        );
    }

    if ($updateLocked === false) {
        pfsensePackageSinkholeAdapter()->log(sprintf(
            $keepSettings
                ? 'Update lock is still held after %d seconds; runtime cleanup is pending.'
                : 'Update lock is still held after %d seconds; keeping saved data.',
            $lockTimeoutSeconds,
        ));

        return;
    }

    try {
        pfsensePackageSinkholeAdapter()->clearIpRuntimeData(0, true);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'IP removal cleanup failed: ' . $throwable->getMessage(),
        );
    }

    try {
        pfsensePackageSinkholeAdapter()->clearBypassRuntimeData(0, true);
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Bypass removal cleanup failed: ' . $throwable->getMessage(),
        );
    }

    try {
        if (!$keepSettings) {
            pfsensePackageSinkholeAdapter()->removePersistentData();
        }
    } catch (Throwable $throwable) {
        pfsensePackageSinkholeAdapter()->log(
            'Persistent removal cleanup failed; keeping saved data: '
            . $throwable->getMessage(),
        );
    } finally {
        $updateLock->release();
    }
}

/**
 * pfSense Package Sinkhole - Validate.
 *
 * Gives immediate form errors for unsupported schedules and a Python slot owned by
 * another package; runtime code repeats the same validation before side effects.
 *
 * @param array    $post        - Submitted values.
 * @param string[] $inputErrors - Validation errors.
 *
 * @return void
 *
 * @since 1.0.0
 */
function pfsensePackageSinkholeValidate(array $post, array &$inputErrors): void
{
    try {
        Settings::fromStorage($post);
    } catch (Throwable $throwable) {
        $inputErrors[] = pfsensePackageSinkholeThrowableMessage($throwable);
    }

    $updateCheckFrequency = (string) ($post['update_check_frequency'] ?? 'weekly');

    if (!in_array($updateCheckFrequency, ['daily', 'weekly', 'monthly', 'never'], true)) {
        $inputErrors[] = pfsensePackageSinkholeTranslate('update_check_frequency_invalid');
    } elseif (UpdateManager::isAvailable() === false && $updateCheckFrequency !== 'never') {
        $inputErrors[] = pfsensePackageSinkholeTranslate(
            'update_checks_unavailable_repository',
        );
    }

    if (($post['enabled'] ?? '') !== 'on') {
        return;
    }

    if (config_path_enabled('unbound') === false) {
        $inputErrors[] = pfsensePackageSinkholeTranslate('dns_resolver_disabled');

        return;
    }

    $owner = pfsensePackageSinkholeAdapter()->pythonScriptOwner();

    if ($owner !== '' && $owner !== 'sinkhole') {
        $inputErrors[] = pfsensePackageSinkholeTranslate(
            'dns_resolver_python_slot_owned',
            [htmlspecialchars($owner, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')],
        );
    }
}
