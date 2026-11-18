<?php

declare(strict_types=1);

/*
 * Sinkhole bypass protection configuration page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-bypass
##|*NAME=Firewall: Sinkhole: Bypass
##|*DESCR=Allow access to Sinkhole bypass protection settings and lists.
##|*MATCH=sinkhole-bypass.php*
##|-PRIV

use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\Catalog;
use PfSense\Sinkhole\Domain\RedirectConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;
use PfSense\Sinkhole\Runtime\BypassListStore;
use PfSense\Sinkhole\Runtime\CatalogCache;
use PfSense\Sinkhole\Runtime\Context;
use PfSense\Sinkhole\Runtime\CurlDownloadClient;
use PfSense\Sinkhole\Web\CatalogPresentation;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/BypassConfiguration.php');
require_once('/usr/local/pkg/sinkhole/BypassListStore.php');
require_once('/usr/local/pkg/sinkhole/Catalog.php');
require_once('/usr/local/pkg/sinkhole/CatalogCache.php');
require_once('/usr/local/pkg/sinkhole/CatalogPresentation.php');
require_once('/usr/local/pkg/sinkhole/Context.php');
require_once('/usr/local/pkg/sinkhole/CurlDownloadClient.php');
require_once('/usr/local/pkg/sinkhole/RedirectConfiguration.php');

/**
 * Sinkhole Bypass - Require Repair.
 *
 * @param array $bypass - Partitioned Bypass configuration.
 * @param array $redirect - Partitioned redirect configuration.
 *
 * @return void
 *
 * @since 1.0.0
 * @since 1.2.0
 */
function sinkholeBypassRequireRepair(array $bypass, array $redirect): void
{
    $invalidValues = array_merge(
        $redirect['invalid_values'],
        $redirect['invalid_exemptions'],
        $bypass['invalid_values'],
        $bypass['invalid_exemptions'],
    );

    if ($invalidValues === []) {
        return;
    }

    $invalid = $invalidValues[0];

    throw new ValidationException(
        $invalid['reason_key'],
        $invalid['reason_arguments'] ?? [],
    );
}

/** @since 1.0.0 */
function sinkholeBypassRedirectRecord(array $configuration): array
{
    return [
        'enabled' => $configuration['enabled'],
        'interfaces' => $configuration['interfaces'],
        'exempt_sources' => $configuration['exempt_sources'],
        'exempt_destinations' => $configuration['exempt_destinations'],
    ];
}

/**
 * Sinkhole Bypass - Context Rows.
 *
 * @return array
 *
 * @since 1.3.0
 */
function sinkholeBypassContextRows(): array
{
    $contextRows = config_get_path('installedpackages/sinkhole/bypass_contexts/item', []);

    return is_array($contextRows) ? $contextRows : [];
}

/**
 * Sinkhole Bypass - Context Settings.
 *
 * Reads the exact settings saved for one context through the Bypass API, so a
 * network or device without its own row returns null instead of inherited values.
 *
 * @param array $configuration - Partitioned Global Bypass configuration.
 * @param string $context - Context key.
 *
 * @return array|null
 *
 * @since 1.3.0
 */
function sinkholeBypassContextSettings(array $configuration, string $context): ?array
{
    $settings = BypassConfiguration::forContext(
        $configuration,
        sinkholeBypassContextRows(),
        $context,
    );

    if ($settings === null || $context === Context::GLOBAL) {
        return $settings;
    }

    foreach (sinkholeBypassContextRows() as $contextRow) {
        if (is_array($contextRow) && ($contextRow['context'] ?? null) === $context) {
            $storedEnabled = $contextRow['enabled'] ?? '';
            $settings['stored_enabled'] = $storedEnabled === 'on' || $storedEnabled === true;
        }
    }

    return $settings;
}

/**
 * Sinkhole Bypass - Persist.
 *
 * Writes the configuration changed through the Bypass API in one revision, then
 * applies it in the background.
 *
 * @return void
 *
 * @since 1.3.0
 */
function sinkholeBypassPersist(): void
{
    write_config(pfsensePackageSinkholeTranslate('revision_saved_bypass'));
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
}

/**
 * Sinkhole Bypass - Store Lists.
 *
 * Bypass List sources are package-wide and live in the Global section, which
 * the existing Bypass save keeps together with its migration marker.
 *
 * @param array $configuration - Partitioned Global Bypass configuration.
 * @param array $redirect - Partitioned redirect configuration.
 * @param array<string, array> $lists - Valid Bypass Lists.
 * @param list<array> $invalidRows - Malformed rows retained for repair.
 *
 * @return void
 *
 * @since 1.3.0
 */
function sinkholeBypassStoreLists(
    array $configuration,
    array $redirect,
    array $lists,
    array $invalidRows,
): void {
    pfsensePackageSinkholeSaveBypass(
        pfsensePackageSinkholeBypassStorage(
            $configuration,
            $lists,
            $invalidRows,
        ),
        sinkholeBypassRedirectRecord($redirect),
    );
}

/**
 * Sinkhole Bypass - Error Message.
 *
 * @param array $errors - Errors returned by the Bypass submission.
 *
 * @return string
 *
 * @since 1.3.0
 */
function sinkholeBypassErrorMessage(array $errors): string
{
    $messages = [];

    foreach ($errors as $error) {
        if (is_array($error)) {
            $messages[] = pfsensePackageSinkholeInvalidReason($error);

            continue;
        }

        if ($error instanceof Throwable) {
            $messages[] = pfsensePackageSinkholeThrowableMessage($error);

            continue;
        }

        $errorText = (string) $error;

        try {
            $messages[] = pfsensePackageSinkholeTranslateMapped('validation', $errorText);
        } catch (Throwable) {
            $messages[] = $errorText;
        }
    }

    return implode(' ', $messages);
}

/**
 * Sinkhole Bypass - Field Label.
 *
 * Network and device rows can report fields that the shared field map does not
 * name, so an unknown key is shown as saved instead of failing the page.
 *
 * @param string $fieldKey - Invalid value field key.
 *
 * @return string
 *
 * @since 1.3.0
 */
function sinkholeBypassFieldLabel(string $fieldKey): string
{
    try {
        return pfsensePackageSinkholeTranslateMapped('field', $fieldKey);
    } catch (Throwable) {
        return $fieldKey;
    }
}

/**
 * Sinkhole Bypass - Lines.
 *
 * @param mixed $value - Posted textarea value.
 *
 * @return list<string>
 *
 * @since 1.3.0
 */
function sinkholeBypassLines(mixed $value): array
{
    if (!is_string($value)) {
        return [];
    }

    $lines = preg_split('/\r\n|\r|\n/', $value);

    if (!is_array($lines)) {
        return [];
    }

    return array_values(array_filter(
        array_map('trim', $lines),
        static fn(string $line): bool => $line !== '',
    ));
}

/**
 * Sinkhole Bypass - List Selection.
 *
 * @param mixed $value - Saved or posted list identifiers.
 *
 * @return list<string>
 *
 * @since 1.3.0
 */
function sinkholeBypassListSelection(mixed $value): array
{
    if (!is_array($value)) {
        return [];
    }

    if (count($value) === 1 && array_key_exists('item', $value)) {
        $value = is_array($value['item']) ? $value['item'] : [$value['item']];
    }

    $selection = [];

    foreach ($value as $key => $entry) {
        if (is_string($entry)) {
            $selection[] = $entry;
        } elseif (is_array($entry) && is_string($key)) {
            $selection[] = $key;
        }
    }

    return array_values(array_unique($selection));
}

/**
 * Sinkhole Bypass - Broader Label.
 *
 * Names the context whose settings apply while a network or device has none of
 * its own: a device follows the network it is on, and a network follows Global.
 *
 * @param string $context - Context key.
 * @param array $networks - Valid networks keyed by identifier.
 * @param array $devices - Valid devices keyed by identifier.
 * @param list<string> $contextKeys - Contexts with their own settings.
 *
 * @return string
 *
 * @since 1.3.0
 */
function sinkholeBypassBroaderLabel(
    string $context,
    array $networks,
    array $devices,
    array $contextKeys,
): string {
    $parsed = Context::parse($context);

    if ($parsed !== null && $parsed['type'] === 'device') {
        $device = $devices[$parsed['id']] ?? [];
        $deviceInterfaces = [];

        foreach ($device['identifiers'] ?? [] as $identifier) {
            if (is_array($identifier) && (string) ($identifier['interface'] ?? '') !== '') {
                $deviceInterfaces[] = (string) $identifier['interface'];
            }
        }

        foreach ($networks as $networkIdentifier => $network) {
            $networkKey = 'network:' . $networkIdentifier;

            if (
                ($network['enabled'] ?? true) === true
                && in_array((string) ($network['interface'] ?? ''), $deviceInterfaces, true)
                && in_array($networkKey, $contextKeys, true)
            ) {
                return Context::label($networkKey, $networks, $devices);
            }
        }
    }

    return Context::label(Context::GLOBAL, $networks, $devices);
}

$adapter = pfsensePackageSinkholeAdapter();
$interfaces = $adapter->getConfiguredInterfaces();
$aliases = $adapter->getHostNetworkAliases();
$scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
$networks = $scopeConfiguration['networks'];
$devices = $scopeConfiguration['devices'];
$context = Context::current($networks, $devices, true);

Context::remember($context);

$contextType = Context::parse($context)['type'] ?? 'global';
$isAll = $context === Context::ALL;
$isGlobal = $context === Context::GLOBAL;
$redirect = pfsensePackageSinkholeGetRedirectConfiguration();
$configuration = pfsensePackageSinkholeGetBypassConfiguration();
$lists = $configuration['lists'];
$invalidRows = $configuration['invalid_lists'];
$contextSettings = ($isAll) ? null : sinkholeBypassContextSettings($configuration, $context);
$contextFields = ($isAll) ? [] : BypassConfiguration::fieldsForContext($context);
$actionMessage = ((string) ($_GET['saved'] ?? '') === '1')
    ? pfsensePackageSinkholeTranslate('bypass_saved_applying')
    : null;
$actionClass = 'info';
$displayInterfaces = $redirect['stored_interfaces'];
$displayRedirectEnabled = $redirect['enabled'];
$displayExemptSources = $redirect['stored_exempt_sources'];
$displayExemptDestinations = $redirect['stored_exempt_destinations'];
$displaySettings = $contextSettings ?? [];
$displayBlockExemptSources = $displaySettings['stored_exempt_sources']
    ?? $displaySettings['exempt_sources']
    ?? [];
$displayBlockExemptDestinations = $displaySettings['stored_exempt_destinations']
    ?? $displaySettings['exempt_destinations']
    ?? [];
$displaySettings['enabled'] = $displaySettings['stored_enabled'] ?? $displaySettings['enabled'] ?? false;
$displayListSelection = ($isGlobal)
    ? []
    : sinkholeBypassListSelection($displaySettings['selected_lists'] ?? []);
$catalogOpen = $isGlobal && (
    (string) ($_GET['catalog'] ?? '') === '1'
    || isset($_POST['refresh_catalog'])
    || isset($_POST['add_catalog_list'])
);
$catalogQuery = Catalog::normalizeSearchQuery((string) (
    $_POST['catalog_query'] ?? $_GET['catalog_query'] ?? ''
));
$catalogSource = Catalog::normalizeSourceFilter((string) (
    $_POST['catalog_source'] ?? $_GET['catalog_source'] ?? ''
));
$catalogMaintainer = Catalog::normalizeMaintainerFilter((string) (
    $_POST['catalog_maintainer'] ?? $_GET['catalog_maintainer'] ?? ''
));
$catalogKind = Catalog::normalizeBypassKindFilter((string) (
    $_POST['catalog_kind'] ?? $_GET['catalog_kind'] ?? ''
));
$catalogCache = new CatalogCache($adapter->packagePaths(), new CurlDownloadClient());
$catalogLoad = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $isAll === false) {
    try {
        if (isset($_POST['remove_context_settings'])) {
            if ($isGlobal === false) {
                BypassConfiguration::removeContext($context);

                sinkholeBypassPersist();

                $actionMessage = pfsensePackageSinkholeTranslate('bxpage_bypass_removed');
                $actionClass = 'success';
            }
        } elseif (isset($_POST['save_bypass'])) {
            $redirectSubmission = null;
            $postedBlockExemptSources = $_POST['block_exempt_sources'] ?? '';
            $postedBlockExemptDestinations = $_POST['block_exempt_destinations'] ?? '';
            $displayBlockExemptSources = sinkholeBypassLines($postedBlockExemptSources);
            $displayBlockExemptDestinations = sinkholeBypassLines($postedBlockExemptDestinations);
            $displayListSelection = sinkholeBypassListSelection($_POST['bypass_lists'] ?? []);
            $displaySettings = array_replace($displaySettings, [
                'enabled' => isset($_POST['bypass_enabled']),
                'block_tls_quic' => isset($_POST['block_tls_quic']),
                'block_encrypted_dns' => isset($_POST['block_encrypted_dns']),
                'disable_firefox_doh' => isset($_POST['disable_firefox_doh']),
                'disable_private_relay' => isset($_POST['disable_private_relay']),
                'discovery' => is_string($_POST['discovery'] ?? null)
                    ? $_POST['discovery']
                    : BypassConfiguration::DISCOVERY_OFF,
                'block_tor' => isset($_POST['block_tor']),
                'block_vpn' => isset($_POST['block_vpn']),
                'block_vpn_ports' => isset($_POST['block_vpn_ports']),
            ]);

            if (!is_string($postedBlockExemptSources)) {
                throw new ValidationException('exempt_sources_invalid');
            }

            if (!is_string($postedBlockExemptDestinations)) {
                throw new ValidationException('exempt_destinations_invalid');
            }

            if ($isGlobal) {
                $postedInterfaces = $_POST['bypass_interfaces'] ?? [];
                $postedExemptSources = $_POST['redirect_exempt_sources'] ?? '';
                $postedExemptDestinations = $_POST['redirect_exempt_destinations'] ?? '';
                $displayInterfaces = is_array($postedInterfaces)
                    ? array_values(array_filter($postedInterfaces, 'is_string'))
                    : [];
                $displayRedirectEnabled = isset($_POST['redirect_enabled']);
                $displayExemptSources = sinkholeBypassLines($postedExemptSources);
                $displayExemptDestinations = sinkholeBypassLines($postedExemptDestinations);

                if (!is_string($postedExemptSources)) {
                    throw new ValidationException('exempt_sources_invalid');
                }

                if (!is_string($postedExemptDestinations)) {
                    throw new ValidationException('exempt_destinations_invalid');
                }

                $redirectSubmission = RedirectConfiguration::normalizeSubmission(
                    $displayRedirectEnabled,
                    $postedInterfaces,
                    $postedExemptSources,
                    $interfaces,
                    $aliases,
                    $postedExemptDestinations,
                );
            }

            $submission = BypassConfiguration::submitContext(
                $context,
                $_POST,
                $interfaces,
                $aliases,
            );

            if ($submission['errors'] !== []) {
                $actionMessage = sinkholeBypassErrorMessage($submission['errors']);
                $actionClass = 'danger';
            } elseif (is_array($redirectSubmission)) {
                pfsensePackageSinkholeSaveBypass(
                    pfsensePackageSinkholeBypassStorage(
                        $configuration,
                        $lists,
                        $invalidRows,
                        $submission['settings'],
                    ),
                    $redirectSubmission,
                );

                $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
                $actionClass = 'success';
            } else {
                BypassConfiguration::storeContext($context, $submission['settings']);

                sinkholeBypassPersist();

                $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
                $actionClass = 'success';
            }
        } elseif (
            $isGlobal
            && (isset($_POST['toggle_bypass_list']) || isset($_POST['delete_bypass_list']))
        ) {
            sinkholeBypassRequireRepair($configuration, $redirect);
            $identifier = (string) ($_POST['list_id'] ?? '');

            if (!isset($lists[$identifier])) {
                throw new ValidationException('bypass_list_missing');
            }

            if (isset($_POST['delete_bypass_list'])) {
                unset($lists[$identifier]);
            } else {
                $lists[$identifier]['enabled'] = !$lists[$identifier]['enabled'];
            }

            sinkholeBypassStoreLists($configuration, $redirect, $lists, $invalidRows);

            $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
            $actionClass = 'success';
        } elseif ($isGlobal && isset($_POST['delete_invalid_bypass_list'])) {
            sinkholeBypassRequireRepair(
                array_replace($configuration, ['invalid_lists' => []]),
                $redirect,
            );
            $position = (int) ($_POST['invalid_position'] ?? -1);
            $originalCount = count($invalidRows);
            $invalidRows = array_values(array_filter(
                $invalidRows,
                static fn(array $row): bool => $row['position'] !== $position,
            ));

            if (count($invalidRows) === $originalCount) {
                throw new ValidationException('invalid_bypass_list_row_missing');
            }

            sinkholeBypassStoreLists($configuration, $redirect, $lists, $invalidRows);

            $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
            $actionClass = 'success';
        } elseif ($isGlobal && isset($_POST['refresh_catalog'])) {
            $catalogLoad = $catalogCache->loadBypass(true);
            $hasCatalogError = false;

            foreach ($catalogLoad['statuses'] as $catalogStatus) {
                if ($catalogStatus['last_error'] !== '') {
                    $hasCatalogError = true;
                    break;
                }
            }

            $actionMessage = pfsensePackageSinkholeTranslate('catalog_refresh_finished');
            $actionClass = ($hasCatalogError) ? 'warning' : 'success';
        } elseif ($isGlobal && isset($_POST['add_catalog_list'])) {
            sinkholeBypassRequireRepair($configuration, $redirect);
            $catalogLoad = $catalogCache->loadBypass();
            $lists = Catalog::addBypassList(
                $catalogLoad['entries'],
                $lists,
                (string) ($_POST['catalog_entry'] ?? ''),
            );

            sinkholeBypassStoreLists($configuration, $redirect, $lists, $invalidRows);

            $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
            $actionClass = 'success';
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }

    if ($actionClass === 'success') {
        $redirect = pfsensePackageSinkholeGetRedirectConfiguration();
        $configuration = pfsensePackageSinkholeGetBypassConfiguration();
        $lists = $configuration['lists'];
        $invalidRows = $configuration['invalid_lists'];
        $contextSettings = sinkholeBypassContextSettings($configuration, $context);
        $displayInterfaces = $redirect['stored_interfaces'];
        $displayRedirectEnabled = $redirect['enabled'];
        $displayExemptSources = $redirect['stored_exempt_sources'];
        $displayExemptDestinations = $redirect['stored_exempt_destinations'];
        $displaySettings = $contextSettings ?? [];
        $displayBlockExemptSources = $displaySettings['stored_exempt_sources']
            ?? $displaySettings['exempt_sources']
            ?? [];
        $displayBlockExemptDestinations = $displaySettings['stored_exempt_destinations']
            ?? $displaySettings['exempt_destinations']
            ?? [];
        $displaySettings['enabled'] = $displaySettings['stored_enabled'] ?? $displaySettings['enabled'] ?? false;
        $displayListSelection = ($isGlobal)
            ? []
            : sinkholeBypassListSelection($displaySettings['selected_lists'] ?? []);
    }
}

$hasOwnSettings = $isGlobal || $contextSettings !== null;
$contextKeys = BypassConfiguration::contextKeys();
$redirectInactiveReason = null;

try {
    $redirectInactiveReason = pfsensePackageSinkholeAdapter()->redirectInactiveReason();
} catch (Throwable $throwable) {
    if ($actionMessage === null) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }
}

$catalogResults = [];
$catalogGroups = [];
$catalogKindCounts = array_fill_keys(
    array_merge([''], BypassConfiguration::KINDS),
    0,
);
$catalogMaintainers = [];
$catalogStatuses = [];

if ($catalogOpen) {
    try {
        $catalogLoad ??= $catalogCache->loadBypass();
        $catalogStatuses = $catalogLoad['statuses'];
        $catalogView = Catalog::bypassFacetedView(
            $catalogLoad['entries'],
            $catalogQuery,
            $catalogSource,
            $catalogMaintainer,
            $catalogKind,
        );
        $matchingCatalogEntries = Catalog::markAdded($catalogView['entries'], $lists);
        $catalogKindCounts = $catalogView['kind_counts'];
        $catalogMaintainers = $catalogView['maintainers'];

        foreach ($matchingCatalogEntries as $matchingCatalogEntry) {
            $catalogResults[] = CatalogPresentation::entry($matchingCatalogEntry);
        }

        foreach ($catalogView['groups'] as $catalogGroup) {
            $groupEntries = Catalog::markAdded($catalogGroup['entries'], $lists);
            $catalogGroups[] = [
                'key' => $catalogGroup['key'],
                'count' => $catalogGroup['count'],
                'entries' => array_map(
                    static fn(array $entry): array => CatalogPresentation::entry($entry),
                    $groupEntries,
                ),
            ];
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }
}

$interfaceOptions = $interfaces;

foreach ($displayInterfaces as $interface) {
    if (!isset($interfaceOptions[$interface])) {
        $interfaceOptions[$interface] = pfsensePackageSinkholeTranslate('unavailable_interface')
            . ' — '
            . $interface;
    }
}

$rows = [];

if ($isGlobal) {
    $store = new BypassListStore($adapter->packagePaths());

    foreach ($lists as $identifier => $list) {
        $metadata = [];

        try {
            $metadata = $store->metadata($identifier);
        } catch (Throwable $throwable) {
            $metadata['last_error'] = pfsensePackageSinkholeThrowableMessage($throwable);
        }

        $rows[$identifier] = [
            'list' => $list,
            'entries' => is_int($metadata['entries'] ?? null) ? $metadata['entries'] : 0,
            'fetched_at' => is_string($metadata['fetched_at'] ?? null)
                ? $metadata['fetched_at']
                : '',
            'last_error' => is_string($metadata['last_error'] ?? null)
                ? $metadata['last_error']
                : '',
        ];
    }
}

$overviewRows = [];

if ($isAll) {
    $protectionLabels = [
        'block_tls_quic' => pfsensePackageSinkholeTranslate('tls_and_quic'),
        'block_encrypted_dns' => pfsensePackageSinkholeTranslate('providers'),
        'disable_firefox_doh' => pfsensePackageSinkholeTranslate('firefox'),
        'disable_private_relay' => pfsensePackageSinkholeTranslate('private_relay'),
        'block_tor' => pfsensePackageSinkholeTranslate('tor'),
        'block_vpn' => pfsensePackageSinkholeTranslate('vpn'),
        'block_vpn_ports' => pfsensePackageSinkholeTranslate('bxpage_vpn_ports'),
    ];
    $overviewKeys = array_values(array_unique(array_merge([Context::GLOBAL], $contextKeys)));

    foreach ($overviewKeys as $overviewKey) {
        if (Context::parse($overviewKey) === null) {
            continue;
        }

        $overviewSettings = sinkholeBypassContextSettings($configuration, $overviewKey);

        if ($overviewSettings === null) {
            continue;
        }

        $overviewProtections = [];

        foreach ($protectionLabels as $protectionField => $protectionLabel) {
            if (($overviewSettings[$protectionField] ?? false) === true) {
                $overviewProtections[] = $protectionLabel;
            }
        }

        if (($overviewSettings['discovery'] ?? BypassConfiguration::DISCOVERY_OFF) !== BypassConfiguration::DISCOVERY_OFF) {
            $overviewProtections[] = pfsensePackageSinkholeTranslate('discovery');
        }

        $overviewEnabled = ($overviewSettings['enabled'] ?? false) === true;
        $overviewRows[] = [
            'key' => $overviewKey,
            'label' => Context::label($overviewKey, $networks, $devices),
            'enabled' => $overviewEnabled,
            'protections' => ($overviewProtections === [])
                ? pfsensePackageSinkholeTranslate('none')
                : implode(', ', $overviewProtections),
        ];
    }
}

$exemptSourcesText = implode(PHP_EOL, $displayExemptSources);
$exemptDestinationsText = implode(PHP_EOL, $displayExemptDestinations);
$blockExemptSourcesText = implode(PHP_EOL, $displayBlockExemptSources);
$blockExemptDestinationsText = implode(PHP_EOL, $displayBlockExemptDestinations);
$tlsStatus = $configuration['discovery_tls'];
$tlsServiceStatus = $tlsStatus['service_enabled']
    ? pfsensePackageSinkholeTranslate('on')
    : pfsensePackageSinkholeTranslate('off');
$discoveryHelp = pfsensePackageSinkholeTranslate(
    'bypass_discovery_help',
    [$tlsServiceStatus],
);
$contextUrl = 'sinkhole-bypass.php?context=' . rawurlencode($context);
$pgtitle = [gettext('Firewall'), 'Sinkhole', pfsensePackageSinkholeTranslate('bypass')];
$pglinks = ['', '/pkg_edit.php?xml=sinkhole.xml&id=0', '@self'];

include('head.inc');
?>
<link rel="stylesheet" href="/css/sinkhole.css">
<?php

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

display_top_tabs(pfsensePackageSinkholeTabs('bypass'));

print(Context::renderRow('sinkhole-bypass.php', $context, $networks, $devices, true));

if ($isAll):
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bxpage_bypass_overview'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead><tr>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bxpage_applies_to'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bxpage_protections'))?></th>
				<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
			</tr></thead>
			<tbody>
<?php foreach ($overviewRows as $overviewRow): ?>
<?php $overviewUrl = 'sinkhole-bypass.php?context=' . rawurlencode($overviewRow['key']); ?>
				<tr<?=($overviewRow['enabled']) ? '' : ' class="disabled"'?>>
					<td><a href="<?=htmlspecialchars($overviewUrl)?>"><?=htmlspecialchars($overviewRow['label'])?></a></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $overviewRow['enabled'] ? 'true' : 'false'))?></td>
					<td><?=htmlspecialchars($overviewRow['protections'])?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>" href="<?=htmlspecialchars($overviewUrl)?>"></a>
					</td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php
include('foot.inc');

return;
endif;

if ($hasOwnSettings === false) {
    $broaderLabel = sinkholeBypassBroaderLabel($context, $networks, $devices, $contextKeys);

    print_info_box(
        htmlspecialchars(($contextType === 'device')
            ? pfsensePackageSinkholeTranslate('bxpage_not_set_device', [$broaderLabel])
            : pfsensePackageSinkholeTranslate('bxpage_not_set_network', [$broaderLabel])),
        'info',
        false,
    );
}

$invalidValues = array_merge(
    ($isGlobal) ? $redirect['invalid_values'] : [],
    ($isGlobal) ? $configuration['invalid_values'] : ($displaySettings['invalid_values'] ?? []),
    ($isGlobal) ? $configuration['invalid_exemptions'] : ($displaySettings['invalid_exemptions'] ?? []),
);

if ($invalidValues !== []):
?>
<div class="panel panel-danger">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_saved_values'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead><tr>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('field'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('value'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('reason'))?></th>
			</tr></thead>
			<tbody>
<?php foreach ($invalidValues as $invalidValue): ?>
				<tr>
					<td><?=htmlspecialchars(sinkholeBypassFieldLabel((string) $invalidValue['field_key']))?></td>
					<td><?=htmlspecialchars($invalidValue['value'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeInvalidReason($invalidValue))?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php
endif;

$showField = static fn(string $field): bool => in_array($field, $contextFields, true);
$saveButton = new Form_Button(
    'save_bypass',
    pfsensePackageSinkholeTranslate('save'),
    null,
    'fa-solid fa-save',
);
$saveButton->addClass('btn-primary');
$form = new Form($saveButton);
$form->setAction($contextUrl);
$form->addGlobal(new Form_Input('context', null, 'hidden', $context));

$removeLabel = ($contextType === 'device')
    ? pfsensePackageSinkholeTranslate('bxpage_remove_device')
    : pfsensePackageSinkholeTranslate('bxpage_remove_network');

if ($isGlobal === false && $hasOwnSettings) {
    $removeButton = new Form_Button(
        'remove_context_settings',
        $removeLabel,
        null,
        'fa-solid fa-trash-can',
    );
    $removeButton->addClass('btn-danger');
    $form->addGlobal($removeButton);
}

if ($isGlobal) {
    $interfacesSection = new Form_Section(pfsensePackageSinkholeTranslate('interfaces'));
    $interfaceInput = new Form_Select(
        'bypass_interfaces',
        pfsensePackageSinkholeTranslate('apply_to'),
        $displayInterfaces,
        $interfaceOptions,
        true,
    );
    $interfaceInput->setHelp(pfsensePackageSinkholeTranslate('bypass_interfaces_help'));
    $interfacesSection->addInput($interfaceInput);
    $form->add($interfacesSection);

    $plainSection = new Form_Section(pfsensePackageSinkholeTranslate('plain_dns'));
    $plainSection->addInput(new Form_Checkbox(
        'redirect_enabled',
        pfsensePackageSinkholeTranslate('redirect'),
        pfsensePackageSinkholeTranslate('bypass_redirect_help'),
        $displayRedirectEnabled,
    ));

    if (is_string($redirectInactiveReason)) {
        $plainSection->addInput(new Form_StaticText(
            pfsensePackageSinkholeTranslate('bypass_warning'),
            '<span class="text-danger"><i class="fa-solid fa-triangle-exclamation"></i> '
                . htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
                    'redirect_inactive_reason',
                    $redirectInactiveReason,
                ))
                . '</span>',
        ));
    }

    $sourceInput = new Form_Textarea(
        'redirect_exempt_sources',
        pfsensePackageSinkholeTranslate('exempt_sources'),
        $exemptSourcesText,
    );
    $sourceInput->setRows(4);
    $sourceInput->setHelp(pfsensePackageSinkholeTranslate('redirect_exemptions_help'));
    $plainSection->addInput($sourceInput);
    $destinationInput = new Form_Textarea(
        'redirect_exempt_destinations',
        pfsensePackageSinkholeTranslate('exempt_destinations'),
        $exemptDestinationsText,
    );
    $destinationInput->setRows(4);
    $destinationInput->setHelp(pfsensePackageSinkholeTranslate('redirect_exemptions_help'));
    $plainSection->addInput($destinationInput);
    $form->add($plainSection);
}

if ($isGlobal === false) {
    $contextSection = new Form_Section(pfsensePackageSinkholeTranslate('bypass'));
    $contextSectionInputs = 0;

    if ($showField('enabled') || $showField('bypass_enabled')) {
        $contextSection->addInput(new Form_Checkbox(
            'bypass_enabled',
            pfsensePackageSinkholeTranslate('enable'),
            pfsensePackageSinkholeTranslate('bxpage_bypass_enable_help'),
            ($displaySettings['enabled'] ?? false) === true,
        ));
        $contextSectionInputs++;
    }

    if ($showField('bypass_lists')) {
        $listOptions = [];

        foreach ($lists as $listIdentifier => $list) {
            $listOptions[$listIdentifier] = $list['name']
                . ' ('
                . pfsensePackageSinkholeTranslateMapped('bypass_kind', $list['kind'])
                . ')';
        }

        $listInput = new Form_Select(
            'bypass_lists',
            pfsensePackageSinkholeTranslate('bypass_lists'),
            array_values(array_intersect($displayListSelection, array_keys($listOptions))),
            $listOptions,
            true,
        );
        $listInput->setHelp(pfsensePackageSinkholeTranslate('bxpage_bypass_lists_help'));
        $contextSection->addInput($listInput);
        $contextSectionInputs++;
    }

    if ($contextSectionInputs > 0) {
        $form->add($contextSection);
    }
}

$encryptedSection = new Form_Section(pfsensePackageSinkholeTranslate('encrypted_dns'));
$encryptedSectionInputs = 0;
$encryptedCheckboxes = [
    'block_tls_quic' => [
        pfsensePackageSinkholeTranslate('tls_and_quic'),
        pfsensePackageSinkholeTranslate('block_tls_quic_help'),
    ],
    'block_encrypted_dns' => [
        pfsensePackageSinkholeTranslate('providers'),
        pfsensePackageSinkholeTranslate('block_encrypted_dns_help'),
    ],
    'disable_firefox_doh' => [
        pfsensePackageSinkholeTranslate('firefox'),
        pfsensePackageSinkholeTranslate('disable_firefox_doh_help'),
    ],
    'disable_private_relay' => [
        pfsensePackageSinkholeTranslate('private_relay'),
        pfsensePackageSinkholeTranslate('disable_private_relay_help'),
    ],
];

foreach ($encryptedCheckboxes as $checkboxField => $checkboxLabels) {
    if ($showField($checkboxField) === false && $isGlobal === false) {
        continue;
    }

    $encryptedSection->addInput(new Form_Checkbox(
        $checkboxField,
        $checkboxLabels[0],
        $checkboxLabels[1],
        ($displaySettings[$checkboxField] ?? false) === true,
    ));
    $encryptedSectionInputs++;
}

if ($showField('discovery') || $isGlobal) {
    $discoveryInput = new Form_Select(
        'discovery',
        pfsensePackageSinkholeTranslate('discovery'),
        (string) ($displaySettings['discovery'] ?? BypassConfiguration::DISCOVERY_OFF),
        [
            BypassConfiguration::DISCOVERY_OFF => pfsensePackageSinkholeTranslate('off'),
            BypassConfiguration::DISCOVERY_ADVERTISE => pfsensePackageSinkholeTranslate('discovery_advertise'),
            BypassConfiguration::DISCOVERY_NODATA => pfsensePackageSinkholeTranslate('discovery_nodata'),
        ],
    );
    $discoveryInput->setHelp($discoveryHelp);
    $encryptedSection->addInput($discoveryInput);
    $encryptedSectionInputs++;
}

if ($encryptedSectionInputs > 0) {
    $form->add($encryptedSection);
}

$tunnelSection = new Form_Section(pfsensePackageSinkholeTranslate('tunnels'));
$tunnelSectionInputs = 0;
$tunnelCheckboxes = [
    'block_tor' => [
        pfsensePackageSinkholeTranslate('tor'),
        pfsensePackageSinkholeTranslate('block_tor_help'),
    ],
    'block_vpn' => [
        pfsensePackageSinkholeTranslate('vpn'),
        pfsensePackageSinkholeTranslate('block_vpn_help'),
    ],
    'block_vpn_ports' => [
        pfsensePackageSinkholeTranslate('vpn'),
        pfsensePackageSinkholeTranslate('block_vpn_ports_help'),
    ],
];

foreach ($tunnelCheckboxes as $checkboxField => $checkboxLabels) {
    if ($showField($checkboxField) === false && $isGlobal === false) {
        continue;
    }

    $tunnelSection->addInput(new Form_Checkbox(
        $checkboxField,
        $checkboxLabels[0],
        $checkboxLabels[1],
        ($displaySettings[$checkboxField] ?? false) === true,
    ));
    $tunnelSectionInputs++;
}

if ($tunnelSectionInputs > 0) {
    $form->add($tunnelSection);
}

$blockExemptionsSection = new Form_Section(pfsensePackageSinkholeTranslate('block_exemptions'));
$blockExemptionsSectionInputs = 0;

if ($showField('block_exempt_sources') || $isGlobal) {
    $blockSourceInput = new Form_Textarea(
        'block_exempt_sources',
        pfsensePackageSinkholeTranslate('exempt_sources'),
        $blockExemptSourcesText,
    );
    $blockSourceInput->setRows(4);
    $blockSourceInput->setHelp(pfsensePackageSinkholeTranslate('block_exempt_sources_help'));
    $blockExemptionsSection->addInput($blockSourceInput);
    $blockExemptionsSectionInputs++;
}

if ($showField('block_exempt_destinations') || $isGlobal) {
    $blockDestinationInput = new Form_Textarea(
        'block_exempt_destinations',
        pfsensePackageSinkholeTranslate('exempt_destinations'),
        $blockExemptDestinationsText,
    );
    $blockDestinationInput->setRows(4);
    $blockDestinationInput->setHelp(pfsensePackageSinkholeTranslate('block_exempt_destinations_help'));
    $blockExemptionsSection->addInput($blockDestinationInput);
    $blockExemptionsSectionInputs++;
}

if ($blockExemptionsSectionInputs > 0) {
    $form->add($blockExemptionsSection);
}

print($form);

if ($isGlobal):
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bypass_lists'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead><tr>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('kind'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('url'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('entries'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_fetch'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
				<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
			</tr></thead>
			<tbody>
<?php if ($rows === []): ?>
				<tr><td colspan="7" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_bypass_lists_configured'))?></td></tr>
<?php else: ?>
<?php foreach ($rows as $identifier => $row): $list = $row['list']; ?>
				<tr<?=($list['enabled']) ? '' : ' class="disabled"'?>>
					<td><?=htmlspecialchars($list['name'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('bypass_kind', $list['kind']))?></td>
					<td><a href="<?=htmlspecialchars($list['url'])?>" target="_blank" rel="noopener noreferrer"><?=htmlspecialchars($list['url'])?></a></td>
					<td><?=htmlspecialchars((string) $row['entries'])?></td>
					<td>
						<?=htmlspecialchars($row['fetched_at'] === '' ? pfsensePackageSinkholeTranslate('never') : $row['fetched_at'])?>
<?php if ($row['last_error'] !== ''): ?>
						<br><span class="text-danger"><?=htmlspecialchars($row['last_error'])?></span>
<?php endif; ?>
					</td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $list['enabled'] ? 'true' : 'false'))?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>" href="sinkhole-bypass_edit.php?id=<?=urlencode($identifier)?>"></a>
						<a class="<?=$list['enabled'] ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', $list['enabled'] ? 'enabled' : 'disabled'))?>" href="sinkhole-bypass.php?context=global&amp;toggle_bypass_list=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-bypass.php?context=global&amp;delete_bypass_list=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
					</td>
				</tr>
<?php endforeach; ?>
<?php endif; ?>
			</tbody>
		</table>
	</div>
</div>
<nav class="action-buttons">
	<a href="sinkhole-bypass_edit.php" role="button" class="btn btn-success btn-sm">
		<i class="fa-solid fa-plus icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add'))?>
	</a>
<?php if ($catalogOpen === false): ?>
	<a href="sinkhole-bypass.php?context=global&amp;catalog=1" role="button" class="btn btn-primary btn-sm">
		<i class="fa-solid fa-search icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add_from_catalog'))?>
	</a>
<?php endif; ?>
</nav>
<?php endif; ?>
<?php if ($catalogOpen === true): ?>
<?php
$catalogStateParameters = [
    'catalog' => '1',
    'catalog_query' => $catalogQuery,
    'catalog_source' => $catalogSource,
    'catalog_maintainer' => $catalogMaintainer,
    'catalog_kind' => $catalogKind,
];
$catalogSourceOptions = [
    '' => pfsensePackageSinkholeTranslate('all_sources'),
];

foreach (Catalog::sourceLabels() as $catalogSourceLabel) {
    $catalogSourceOptions[$catalogSourceLabel] = $catalogSourceLabel;
}
$catalogMaintainerOptions = [
    '' => pfsensePackageSinkholeTranslate('all_maintainers'),
];

foreach ($catalogMaintainers as $catalogMaintainerOption) {
    $catalogMaintainerName = $catalogMaintainerOption['name'];
    $catalogMaintainerOptions[$catalogMaintainerName] = sprintf(
        '%s (%d)',
        ($catalogMaintainerName === '')
            ? pfsensePackageSinkholeTranslate('unknown')
            : $catalogMaintainerName,
        $catalogMaintainerOption['count'],
    );
}
$catalogSearchButton = new Form_Button(
    'search_catalog',
    pfsensePackageSinkholeTranslate('search'),
    null,
    'fa-solid fa-search',
);
$catalogSearchButton->addClass('btn-primary', 'btn-sm');
$catalogRefreshButton = new Form_Button(
    'refresh_catalog',
    pfsensePackageSinkholeTranslate('refresh'),
    null,
    'fa-solid fa-arrows-rotate',
);
$catalogRefreshButton->addClass('btn-info', 'btn-sm');
$catalogRefreshButton->setAttribute('form', 'sinkhole-bypass-refresh-form');
$catalogFilterForm = new Form(false);
$catalogFilterForm->setMethod('get');
$catalogFilterForm->setAction('sinkhole-bypass.php');
$catalogFilterSection = new Form_Section(
    pfsensePackageSinkholeTranslate('add_from_catalog'),
);
$catalogFilterGroup = new Form_Group(pfsensePackageSinkholeTranslate('search'));
$catalogQueryInput = new Form_Input('catalog_query', null, 'text', $catalogQuery);
$catalogQueryInput->setAttribute('maxlength', Catalog::MAXIMUM_SEARCH_BYTES);
$catalogQueryInput->setWidth(3);
$catalogQueryInput->setHelp(pfsensePackageSinkholeTranslate('search'));
$catalogSourceInput = new Form_Select(
    'catalog_source',
    null,
    $catalogSource,
    $catalogSourceOptions,
);
$catalogSourceInput->setWidth(2);
$catalogSourceInput->setHelp(pfsensePackageSinkholeTranslate('source'));
$catalogMaintainerInput = new Form_Select(
    'catalog_maintainer',
    null,
    $catalogMaintainer,
    $catalogMaintainerOptions,
);
$catalogMaintainerInput->setWidth(2);
$catalogMaintainerInput->setHelp(pfsensePackageSinkholeTranslate('maintainer'));
$catalogButtonInput = new Form_StaticText(
    '',
    (string) $catalogSearchButton . ' ' . (string) $catalogRefreshButton,
);
$catalogButtonInput->setWidth(3);
$catalogFilterGroup->add($catalogQueryInput);
$catalogFilterGroup->add($catalogSourceInput);
$catalogFilterGroup->add($catalogMaintainerInput);
$catalogFilterGroup->add($catalogButtonInput);
$catalogFilterGroup->setHelp(pfsensePackageSinkholeTranslate('catalog_search_help'));
$catalogFilterSection->add($catalogFilterGroup);
$catalogShowGroup = new Form_Group(pfsensePackageSinkholeTranslate('show'));
$catalogKindLinks = '<div class="sinkhole-catalog-chips">';

foreach (array_merge([''], BypassConfiguration::KINDS) as $catalogKindKey) {
    $catalogKindUrl = 'sinkhole-bypass.php?' . http_build_query(array_merge(
        $catalogStateParameters,
        ['catalog_kind' => $catalogKindKey],
    ));
    $catalogKindLabel = ($catalogKindKey === '')
        ? pfsensePackageSinkholeTranslate('all')
        : pfsensePackageSinkholeTranslateMapped('bypass_kind', $catalogKindKey);
    $catalogKindLinks .= sprintf(
        '<a class="btn btn-xs %s" href="%s">%s (%d)</a>',
        ($catalogKind === $catalogKindKey) ? 'btn-primary' : 'btn-default',
        htmlspecialchars($catalogKindUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
        htmlspecialchars($catalogKindLabel),
        $catalogKindCounts[$catalogKindKey] ?? 0,
    );
}
$catalogKindLinks .= '</div>';
$catalogKindInput = new Form_StaticText('', $catalogKindLinks);
$catalogKindInput->setWidth(10);
$catalogShowGroup->add($catalogKindInput);
$catalogFilterSection->add($catalogShowGroup);
$catalogFilterForm->add($catalogFilterSection);
$catalogFilterForm->addGlobal(new Form_Input('catalog', null, 'hidden', '1'));
$catalogFilterForm->addGlobal(new Form_Input(
    'catalog_kind',
    null,
    'hidden',
    $catalogKind,
));
print($catalogFilterForm);
?>
<form id="sinkhole-bypass-refresh-form" method="post" action="sinkhole-bypass.php?context=global">
	<input type="hidden" name="catalog_query" value="<?=htmlspecialchars($catalogQuery, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<input type="hidden" name="catalog_source" value="<?=htmlspecialchars($catalogSource, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<input type="hidden" name="catalog_maintainer" value="<?=htmlspecialchars($catalogMaintainer, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<input type="hidden" name="catalog_kind" value="<?=htmlspecialchars($catalogKind, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
</form>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('popular_list_catalogs'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('source'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_fetch'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_error'))?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($catalogStatuses as $catalogStatus): ?>
<?php
$catalogFetchedAt = is_int($catalogStatus['fetched_at'])
    ? gmdate('Y-m-d H:i:s \U\T\C', $catalogStatus['fetched_at'])
    : pfsensePackageSinkholeTranslate('never');
$catalogLastError = ($catalogStatus['last_error'] === '')
    ? pfsensePackageSinkholeTranslate('none')
    : $catalogStatus['last_error'];
?>
				<tr>
					<td><?=htmlspecialchars($catalogStatus['source'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?></td>
					<td><?=htmlspecialchars($catalogFetchedAt, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?></td>
					<td><?=htmlspecialchars($catalogLastError, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php if (count($catalogResults) === 0): ?>
<?php print_info_box(htmlspecialchars(pfsensePackageSinkholeTranslate('no_catalog_results')), 'warning', false); ?>
<?php else: ?>
<?php foreach ($catalogGroups as $catalogGroup): ?>
<?php
$catalogGroupTitle = pfsensePackageSinkholeTranslateMapped(
    'bypass_kind',
    $catalogGroup['key'],
);
?>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars($catalogGroupTitle, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?> (<?=htmlspecialchars((string) $catalogGroup['count'])?>)</h2></div>
		<div class="panel-body">
			<div class="form-group">
				<div class="col-sm-12">
					<div class="sinkhole-catalog-grid">
<?php foreach ($catalogGroup['entries'] as $catalogResult): ?>
						<article class="sinkhole-catalog-card">
							<h4><?=$catalogResult['name']?></h4>
							<div class="sinkhole-catalog-meta">
								<?=htmlspecialchars(pfsensePackageSinkholeTranslate('maintainer'))?>: <?=($catalogResult['maintainer'] === '') ? htmlspecialchars(pfsensePackageSinkholeTranslate('unknown')) : $catalogResult['maintainer']?>
								<br><?=htmlspecialchars(pfsensePackageSinkholeTranslate('source'))?>: <?=$catalogResult['source']?>
								<br><?=htmlspecialchars(pfsensePackageSinkholeTranslate('contents'))?>: <?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('catalog_contents', html_entity_decode($catalogResult['contents'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')))?>
							</div>
							<p class="sinkhole-catalog-description"><?=$catalogResult['description']?></p>
							<div class="sinkhole-catalog-actions">
<?php if ($catalogResult['homepage'] === ''): ?>
								<span><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_homepage'))?></span>
<?php else: ?>
								<a href="<?=$catalogResult['homepage']?>" target="_blank" rel="noopener noreferrer"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('homepage'))?></a>
<?php endif; ?>
<?php if ($catalogResult['added']): ?>
								<button class="btn btn-xs btn-default" type="button" disabled><?=htmlspecialchars(pfsensePackageSinkholeTranslate('added'))?></button>
<?php else: ?>
								<form method="post" action="sinkhole-bypass.php?context=global">
									<input type="hidden" name="catalog_entry" value="<?=$catalogResult['identifier']?>">
									<input type="hidden" name="catalog_query" value="<?=htmlspecialchars($catalogQuery, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
									<input type="hidden" name="catalog_source" value="<?=htmlspecialchars($catalogSource, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
									<input type="hidden" name="catalog_maintainer" value="<?=htmlspecialchars($catalogMaintainer, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
									<input type="hidden" name="catalog_kind" value="<?=htmlspecialchars($catalogKind, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
									<button class="btn btn-xs btn-success" type="submit" name="add_catalog_list" value="1"><i class="fa-solid fa-plus icon-embed-btn"></i> <?=htmlspecialchars(pfsensePackageSinkholeTranslate('add'))?></button>
								</form>
<?php endif; ?>
							</div>
						</article>
<?php endforeach; ?>
					</div>
				</div>
			</div>
		</div>
	</div>
<?php endforeach; ?>
<?php endif; ?>
<?php endif; ?>
<?php if ($isGlobal && $invalidRows !== []): ?>
<div class="panel panel-danger">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_saved_rows'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead><tr>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('reason'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
			</tr></thead>
			<tbody>
<?php foreach ($invalidRows as $invalidRow): ?>
				<tr>
					<td><?=htmlspecialchars($invalidRow['name'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeInvalidReason($invalidRow))?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('fix'))?>" href="sinkhole-bypass_edit.php?invalid_position=<?=urlencode((string) $invalidRow['position'])?>"></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-bypass.php?context=global&amp;delete_invalid_bypass_list=1&amp;invalid_position=<?=urlencode((string) $invalidRow['position'])?>" usepost></a>
					</td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php endif; ?>
<?php if ($isGlobal): ?>
<script>
events.push(function () {
	function toggleRedirectFields() {
		var hidden = !document.getElementById('redirect_enabled').checked;
		hideInput('redirect_exempt_sources', hidden);
		hideInput('redirect_exempt_destinations', hidden);
	}

	document.getElementById('redirect_enabled').addEventListener('change', toggleRedirectFields);
	toggleRedirectFields();
});
</script>
<?php elseif ($hasOwnSettings): ?>
<script>
events.push(function () {
	$('#remove_context_settings').on('click', function () {
		return confirm(<?=json_encode($removeLabel . '?', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)?>);
	});
});
</script>
<?php endif; ?>
<?php
include('foot.inc');
