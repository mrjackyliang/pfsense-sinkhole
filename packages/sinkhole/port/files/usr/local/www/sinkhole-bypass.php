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
use PfSense\Sinkhole\Runtime\CurlDownloadClient;
use PfSense\Sinkhole\Web\CatalogPresentation;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/BypassConfiguration.php');
require_once('/usr/local/pkg/sinkhole/BypassListStore.php');
require_once('/usr/local/pkg/sinkhole/Catalog.php');
require_once('/usr/local/pkg/sinkhole/CatalogCache.php');
require_once('/usr/local/pkg/sinkhole/CatalogPresentation.php');
require_once('/usr/local/pkg/sinkhole/CurlDownloadClient.php');
require_once('/usr/local/pkg/sinkhole/RedirectConfiguration.php');

/** @since 1.0.0 */
function sinkholeBypassRequireRepair(array $bypass, array $redirect): void
{
    $invalidValues = array_merge(
        $redirect['invalid_values'],
        $redirect['invalid_exemptions'],
        $bypass['invalid_values'],
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

$adapter = pfsensePackageSinkholeAdapter();
$interfaces = $adapter->getConfiguredInterfaces();
$aliases = $adapter->getHostNetworkAliases();
$redirect = pfsensePackageSinkholeGetRedirectConfiguration();
$configuration = pfsensePackageSinkholeGetBypassConfiguration();
$lists = $configuration['lists'];
$invalidRows = $configuration['invalid_lists'];
$actionMessage = ((string) ($_GET['saved'] ?? '') === '1')
    ? pfsensePackageSinkholeTranslate('bypass_saved_applying')
    : null;
$actionClass = 'info';
$displayInterfaces = $redirect['stored_interfaces'];
$displayRedirectEnabled = $redirect['enabled'];
$displayExemptSources = $redirect['stored_exempt_sources'];
$displayExemptDestinations = $redirect['stored_exempt_destinations'];
$displaySettings = $configuration;
$catalogOpen = (string) ($_GET['catalog'] ?? '') === '1'
    || isset($_POST['refresh_catalog'])
    || isset($_POST['add_catalog_list']);
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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['save_bypass'])) {
            $postedInterfaces = $_POST['bypass_interfaces'] ?? [];
            $postedExemptSources = $_POST['redirect_exempt_sources'] ?? '';
            $postedExemptDestinations = $_POST['redirect_exempt_destinations'] ?? '';
            $displayInterfaces = is_array($postedInterfaces)
                ? array_values(array_filter($postedInterfaces, 'is_string'))
                : [];
            $displayRedirectEnabled = isset($_POST['redirect_enabled']);
            $displayExemptSources = is_string($postedExemptSources)
                ? (preg_split('/\r\n|\r|\n/', $postedExemptSources) ?: [])
                : [];
            $displayExemptDestinations = is_string($postedExemptDestinations)
                ? (preg_split('/\r\n|\r|\n/', $postedExemptDestinations) ?: [])
                : [];

            if (!is_string($postedExemptSources)) {
                throw new ValidationException('exempt_sources_invalid');
            }

            if (!is_string($postedExemptDestinations)) {
                throw new ValidationException('exempt_destinations_invalid');
            }

            $postedDiscovery = $_POST['discovery'] ?? BypassConfiguration::DISCOVERY_OFF;

            if (!is_string($postedDiscovery)) {
                throw new ValidationException('bypass_discovery_value_invalid');
            }

            $redirectSubmission = RedirectConfiguration::normalizeSubmission(
                $displayRedirectEnabled,
                $postedInterfaces,
                $postedExemptSources,
                $interfaces,
                $aliases,
                $postedExemptDestinations,
            );
            $settings = [
                'block_tls_quic' => isset($_POST['block_tls_quic']),
                'block_encrypted_dns' => isset($_POST['block_encrypted_dns']),
                'disable_firefox_doh' => isset($_POST['disable_firefox_doh']),
                'disable_private_relay' => isset($_POST['disable_private_relay']),
                'discovery' => $postedDiscovery,
                'block_tor' => isset($_POST['block_tor']),
                'block_vpn' => isset($_POST['block_vpn']),
                'block_vpn_ports' => isset($_POST['block_vpn_ports']),
            ];
            $displaySettings = array_replace($displaySettings, $settings);
            pfsensePackageSinkholeSaveBypass(
                pfsensePackageSinkholeBypassStorage(
                    $configuration,
                    $lists,
                    $invalidRows,
                    $settings,
                ),
                $redirectSubmission,
            );
            $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['toggle_bypass_list']) || isset($_POST['delete_bypass_list'])) {
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

            pfsensePackageSinkholeSaveBypass(
                pfsensePackageSinkholeBypassStorage(
                    $configuration,
                    $lists,
                    $invalidRows,
                ),
                sinkholeBypassRedirectRecord($redirect),
            );
            $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['delete_invalid_bypass_list'])) {
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

            pfsensePackageSinkholeSaveBypass(
                pfsensePackageSinkholeBypassStorage(
                    $configuration,
                    $lists,
                    $invalidRows,
                ),
                sinkholeBypassRedirectRecord($redirect),
            );
            $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['refresh_catalog'])) {
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
        } elseif (isset($_POST['add_catalog_list'])) {
            sinkholeBypassRequireRepair($configuration, $redirect);
            $catalogLoad = $catalogCache->loadBypass();
            $lists = Catalog::addBypassList(
                $catalogLoad['entries'],
                $lists,
                (string) ($_POST['catalog_entry'] ?? ''),
            );
            pfsensePackageSinkholeSaveBypass(
                pfsensePackageSinkholeBypassStorage(
                    $configuration,
                    $lists,
                    $invalidRows,
                ),
                sinkholeBypassRedirectRecord($redirect),
            );
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
        $displayInterfaces = $redirect['stored_interfaces'];
        $displayRedirectEnabled = $redirect['enabled'];
        $displayExemptSources = $redirect['stored_exempt_sources'];
        $displayExemptDestinations = $redirect['stored_exempt_destinations'];
        $displaySettings = $configuration;
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

$store = new BypassListStore($adapter->packagePaths());
$rows = [];

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

$exemptSourcesText = implode(PHP_EOL, $displayExemptSources);
$exemptDestinationsText = implode(PHP_EOL, $displayExemptDestinations);
$tlsStatus = $configuration['discovery_tls'];
$tlsServiceStatus = $tlsStatus['service_enabled']
    ? pfsensePackageSinkholeTranslate('on')
    : pfsensePackageSinkholeTranslate('off');
$discoveryHelp = pfsensePackageSinkholeTranslate(
    'bypass_discovery_help',
    [$tlsServiceStatus],
);
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

$invalidValues = array_merge($redirect['invalid_values'], $configuration['invalid_values']);

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
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('field', $invalidValue['field_key']))?></td>
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

$saveButton = new Form_Button(
    'save_bypass',
    pfsensePackageSinkholeTranslate('save'),
    null,
    'fa-solid fa-save',
);
$saveButton->addClass('btn-primary');
$form = new Form($saveButton);
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

$encryptedSection = new Form_Section(pfsensePackageSinkholeTranslate('encrypted_dns'));
$encryptedSection->addInput(new Form_Checkbox(
    'block_tls_quic',
    pfsensePackageSinkholeTranslate('tls_and_quic'),
    pfsensePackageSinkholeTranslate('block_tls_quic_help'),
    ($displaySettings['block_tls_quic'] ?? false) === true,
));
$encryptedSection->addInput(new Form_Checkbox(
    'block_encrypted_dns',
    pfsensePackageSinkholeTranslate('providers'),
    pfsensePackageSinkholeTranslate('block_encrypted_dns_help'),
    ($displaySettings['block_encrypted_dns'] ?? false) === true,
));
$encryptedSection->addInput(new Form_Checkbox(
    'disable_firefox_doh',
    pfsensePackageSinkholeTranslate('firefox'),
    pfsensePackageSinkholeTranslate('disable_firefox_doh_help'),
    ($displaySettings['disable_firefox_doh'] ?? false) === true,
));
$encryptedSection->addInput(new Form_Checkbox(
    'disable_private_relay',
    pfsensePackageSinkholeTranslate('private_relay'),
    pfsensePackageSinkholeTranslate('disable_private_relay_help'),
    ($displaySettings['disable_private_relay'] ?? false) === true,
));
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
$form->add($encryptedSection);

$tunnelSection = new Form_Section(pfsensePackageSinkholeTranslate('tunnels'));
$tunnelSection->addInput(new Form_Checkbox(
    'block_tor',
    pfsensePackageSinkholeTranslate('tor'),
    pfsensePackageSinkholeTranslate('block_tor_help'),
    ($displaySettings['block_tor'] ?? false) === true,
));
$tunnelSection->addInput(new Form_Checkbox(
    'block_vpn',
    pfsensePackageSinkholeTranslate('vpn'),
    pfsensePackageSinkholeTranslate('block_vpn_help'),
    ($displaySettings['block_vpn'] ?? false) === true,
));
$tunnelSection->addInput(new Form_Checkbox(
    'block_vpn_ports',
    pfsensePackageSinkholeTranslate('vpn'),
    pfsensePackageSinkholeTranslate('block_vpn_ports_help'),
    ($displaySettings['block_vpn_ports'] ?? false) === true,
));
$form->add($tunnelSection);
print($form);
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
						<a class="<?=$list['enabled'] ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', $list['enabled'] ? 'enabled' : 'disabled'))?>" href="sinkhole-bypass.php?toggle_bypass_list=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-bypass.php?delete_bypass_list=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
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
</nav>
<?php if ($catalogOpen === false): ?>
<?php
$catalogOpenButton = '<a class="btn btn-primary btn-sm" href="sinkhole-bypass.php?catalog=1" role="button">'
    . '<i class="fa-solid fa-search icon-embed-btn"></i> '
    . htmlspecialchars(pfsensePackageSinkholeTranslate('open_catalog'))
    . '</a>';
$catalogIntroForm = new Form(false);
$catalogIntroSection = new Form_Section(
    pfsensePackageSinkholeTranslate('add_from_catalog'),
);
$catalogIntroSection->addInput(new Form_StaticText(
    '',
    '<span class="help-block">'
        . htmlspecialchars(pfsensePackageSinkholeTranslate('catalog_search_help'))
        . '</span>',
));
$catalogIntroSection->addInput(new Form_StaticText('', $catalogOpenButton));
$catalogIntroForm->add($catalogIntroSection);
print($catalogIntroForm);
?>
<?php else: ?>
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
<form id="sinkhole-bypass-refresh-form" method="post" action="sinkhole-bypass.php">
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
								<form method="post" action="sinkhole-bypass.php">
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
<?php if ($invalidRows !== []): ?>
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
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-bypass.php?delete_invalid_bypass_list=1&amp;invalid_position=<?=urlencode((string) $invalidRow['position'])?>" usepost></a>
					</td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php endif; ?>
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
<?php
include('foot.inc');
