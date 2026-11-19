<?php

declare(strict_types=1);

/*
 * Sinkhole list-source configuration page: DNS block lists, Bypass Lists and IP lists.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-lists
##|*NAME=Firewall: Sinkhole: Lists
##|*DESCR=Allow access to Sinkhole block-list configuration.
##|*MATCH=sinkhole-lists.php*
##|-PRIV

use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\Catalog;
use PfSense\Sinkhole\Domain\ListConfiguration;
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
require_once('/usr/local/pkg/sinkhole/ListConfiguration.php');

/**
 * Sinkhole Lists - Apply Configuration.
 *
 * Persists one configuration revision and enqueues a fixed background apply command.
 *
 * @param array<string, array{id: string, name: string, url: string, enabled: bool, global: bool}> $lists - Lists.
 * @param list<string> $allowedDomains - Normalized allowed domains.
 * @param list<array> $invalidRows - Invalid rows retained for repair.
 * @return void
 *
 * @throws Throwable When persistence or background handoff fails.
 *
 * @since 1.0.0
 */
function sinkholeListsApply(
    array $lists,
    array $allowedDomains,
    array $invalidRows,
): void {
    pfsensePackageSinkholeSaveLists($lists, $allowedDomains, $invalidRows);
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
}

/**
 * Sinkhole Lists - Bypass Require Repair.
 *
 * @param array $bypass - Partitioned Bypass configuration.
 * @param array $redirect - Partitioned redirect configuration.
 *
 * @return void
 *
 * @throws ValidationException When a saved Bypass or redirect value needs repair.
 *
 * @since 1.3.1
 */
function sinkholeListsBypassRequireRepair(array $bypass, array $redirect): void
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

/**
 * Sinkhole Lists - Bypass Store.
 *
 * Bypass List sources live in the Global Bypass section, which the Bypass save
 * keeps together with Global's list selection and the migration markers.
 *
 * @param array $configuration - Partitioned Global Bypass configuration.
 * @param array $redirect - Partitioned redirect configuration.
 * @param array<string, array> $lists - Valid Bypass Lists.
 * @param list<array> $invalidRows - Malformed rows retained for repair.
 *
 * @return void
 *
 * @since 1.3.1
 */
function sinkholeListsBypassStore(
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
        [
            'enabled' => $redirect['enabled'],
            'interfaces' => $redirect['interfaces'],
            'exempt_sources' => $redirect['exempt_sources'],
            'exempt_destinations' => $redirect['exempt_destinations'],
        ],
    );
}

/**
 * Sinkhole Lists - IP Require Repair.
 *
 * @param array $configuration - Partitioned Global IP configuration.
 *
 * @return void
 *
 * @throws ValidationException When a saved IP value needs repair.
 *
 * @since 1.3.1
 */
function sinkholeListsIpRequireRepair(array $configuration): void
{
    if ($configuration['invalid_values'] === []) {
        return;
    }

    $invalidValue = $configuration['invalid_values'][0];

    throw new ValidationException(
        $invalidValue['reason_key'],
        $invalidValue['reason_arguments'] ?? [],
    );
}

/**
 * Sinkhole Lists - IP Store.
 *
 * IP List sources live in the Global IP section; the IP save keeps the Global
 * list selection and migration marker beside them.
 *
 * @param array $configuration - Partitioned Global IP configuration.
 * @param array<string, array> $lists - Valid IP lists.
 * @param list<array> $invalidRows - Malformed rows retained for repair.
 *
 * @return void
 *
 * @since 1.3.1
 */
function sinkholeListsIpStore(array $configuration, array $lists, array $invalidRows): void
{
    $rows = [];

    foreach ($lists as $list) {
        $rows[] = [
            'id' => $list['id'],
            'descr' => $list['name'],
            'url' => $list['url'],
            'family' => $list['family'],
            'enabled' => $list['enabled'] ? 'on' : '',
        ];
    }

    foreach ($invalidRows as $invalidRow) {
        if (is_array($invalidRow) && array_key_exists('row', $invalidRow)) {
            $rows[] = $invalidRow['row'];
        }
    }

    pfsensePackageSinkholeSaveIp([
        'enabled' => $configuration['enabled'] ? 'on' : '',
        'interfaces' => ['item' => array_values($configuration['stored_interfaces'])],
        'directions' => ['item' => array_values($configuration['stored_directions'])],
        'lists' => ['item' => $rows],
        'countries' => ['item' => array_values($configuration['stored_countries'])],
        'account_id' => $configuration['account_id'],
        'license_key' => $configuration['license_key'],
        'allowlist' => ['item' => array_values($configuration['stored_allowlist'])],
    ]);
}

/**
 * Sinkhole Lists - Bypass Rows.
 *
 * Adds each Bypass List's saved copy details for the Entries and Last Fetch columns.
 *
 * @param array<string, array> $lists - Valid Bypass Lists.
 *
 * @return array<string, array{list: array, entries: int, fetched_at: string, last_error: string}>
 *
 * @since 1.3.1
 */
function sinkholeListsBypassRows(array $lists): array
{
    $store = new BypassListStore(pfsensePackageSinkholeAdapter()->packagePaths());
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

    return $rows;
}

$kindLabels = [
    'dns' => pfsensePackageSinkholeTranslate('dns'),
    'bypass' => pfsensePackageSinkholeTranslate('bypass'),
    'ip' => pfsensePackageSinkholeTranslate('ip'),
];
$kind = (string) ($_GET['kind'] ?? $_POST['kind'] ?? 'dns');

if (!isset($kindLabels[$kind])) {
    $kind = 'dns';
}

$savedMessages = [
    'dns' => pfsensePackageSinkholeTranslate('settings_saved_applying'),
    'bypass' => pfsensePackageSinkholeTranslate('bypass_saved_applying'),
    'ip' => pfsensePackageSinkholeTranslate('ip_saved_applying'),
];
$savedMessage = $savedMessages[$kind];
$kindUrl = 'sinkhole-lists.php?kind=' . rawurlencode($kind);
$adapter = pfsensePackageSinkholeAdapter();
$allowedDomains = [];
$bypassConfiguration = [];
$redirect = [];
$ipConfiguration = [];
$lists = [];
$invalidRows = [];
$usageCounts = [];

/**
 * Sinkhole Lists - Load.
 *
 * Reads the sources, repair rows and Used By counts of the selected kind.
 *
 * @since 1.3.1
 */
$loadKind = static function () use (
    $kind,
    &$allowedDomains,
    &$bypassConfiguration,
    &$redirect,
    &$ipConfiguration,
    &$lists,
    &$invalidRows,
    &$usageCounts,
): void {
    if ($kind === 'bypass') {
        $bypassConfiguration = pfsensePackageSinkholeGetBypassConfiguration();
        $redirect = pfsensePackageSinkholeGetRedirectConfiguration();
        $lists = $bypassConfiguration['lists'];
        $invalidRows = $bypassConfiguration['invalid_lists'];
        $usageCounts = BypassConfiguration::listUsageCounts($bypassConfiguration);

        return;
    }

    if ($kind === 'ip') {
        $ipConfiguration = pfsensePackageSinkholeGetIpConfiguration();
        $lists = $ipConfiguration['lists'];
        $invalidRows = $ipConfiguration['invalid_lists'];
        $usageCounts = pfsensePackageSinkholeIpListUsageCounts($lists);

        return;
    }

    $listConfiguration = pfsensePackageSinkholeGetListConfiguration();
    $lists = $listConfiguration['lists'];
    $invalidRows = $listConfiguration['invalid_rows'];
    $allowedDomains = pfsensePackageSinkholeGetAllowedDomains();
    $usageCounts = pfsensePackageSinkholeListUsageCounts();

    foreach ($lists as $identifier => $list) {
        $usageCounts[$identifier] = ($usageCounts[$identifier] ?? 0) + (($list['global']) ? 1 : 0);
    }
};

$loadKind();

$actionClass = 'info';
$actionMessage = ((string) ($_GET['saved'] ?? '') === '1') ? $savedMessage : null;
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
$catalogCategory = Catalog::normalizeCategoryFilter((string) (
    $_POST['catalog_category'] ?? $_GET['catalog_category'] ?? ''
));
$catalogGroupBy = Catalog::normalizeGroupBy((string) (
    $_POST['catalog_group_by'] ?? $_GET['catalog_group_by'] ?? ''
));
$catalogKind = Catalog::normalizeBypassKindFilter((string) (
    $_POST['catalog_kind'] ?? $_GET['catalog_kind'] ?? ''
));

if ($kind === 'ip') {
    $catalogSource = '';
}

$catalogCache = new CatalogCache(
    $adapter->packagePaths(),
    new CurlDownloadClient(),
);
$catalogLoad = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['refresh_catalog'])) {
            $catalogLoad = match ($kind) {
                'bypass' => $catalogCache->loadBypass(true),
                'ip' => $catalogCache->loadIp(true),
                default => $catalogCache->load(true),
            };
            $hasCatalogError = false;

            foreach ($catalogLoad['statuses'] as $catalogStatus) {
                if (($catalogStatus['last_error'] ?? '') !== '') {
                    $hasCatalogError = true;
                    break;
                }
            }

            $actionMessage = pfsensePackageSinkholeTranslate('catalog_refresh_finished');
            $actionClass = ($hasCatalogError) ? 'warning' : 'success';
        } elseif (isset($_POST['add_catalog_list'])) {
            $catalogEntry = (string) ($_POST['catalog_entry'] ?? '');

            if ($kind === 'bypass') {
                sinkholeListsBypassRequireRepair($bypassConfiguration, $redirect);
                $catalogLoad = $catalogCache->loadBypass();
                $lists = Catalog::addBypassList($catalogLoad['entries'], $lists, $catalogEntry);

                sinkholeListsBypassStore($bypassConfiguration, $redirect, $lists, $invalidRows);
            } elseif ($kind === 'ip') {
                sinkholeListsIpRequireRepair($ipConfiguration);
                $catalogLoad = $catalogCache->loadIp();
                $lists = Catalog::addIpList($catalogLoad['entries'], $lists, $catalogEntry);

                sinkholeListsIpStore($ipConfiguration, $lists, $invalidRows);
            } else {
                $catalogLoad = $catalogCache->load();
                $lists = Catalog::addList($catalogLoad['entries'], $lists, $catalogEntry);

                sinkholeListsApply($lists, $allowedDomains, $invalidRows);
            }

            $actionMessage = $savedMessage;
            $actionClass = 'success';
        } elseif (isset($_POST['toggle']) || isset($_POST['delete'])) {
            $identifier = (string) ($_POST['list_id'] ?? '');
            $missingKeys = [
                'dns' => 'block_list_missing',
                'bypass' => 'bypass_list_missing',
                'ip' => 'ip_list_missing',
            ];

            if ($kind === 'bypass') {
                sinkholeListsBypassRequireRepair($bypassConfiguration, $redirect);
            } elseif ($kind === 'ip') {
                sinkholeListsIpRequireRepair($ipConfiguration);
            }

            if (!isset($lists[$identifier])) {
                throw new ValidationException($missingKeys[$kind]);
            }

            if (isset($_POST['delete'])) {
                unset($lists[$identifier]);
            } else {
                $lists[$identifier]['enabled'] = !$lists[$identifier]['enabled'];
            }

            if ($kind === 'bypass') {
                sinkholeListsBypassStore($bypassConfiguration, $redirect, $lists, $invalidRows);
            } elseif ($kind === 'ip') {
                sinkholeListsIpStore($ipConfiguration, $lists, $invalidRows);
            } else {
                if (isset($lists[$identifier])) {
                    $lists[$identifier] = ListConfiguration::normalizeRow(
                        $identifier,
                        $lists[$identifier]['name'],
                        $lists[$identifier]['url'],
                        $lists[$identifier]['enabled'],
                        $lists[$identifier]['global'],
                    );
                }

                sinkholeListsApply($lists, $allowedDomains, $invalidRows);
            }

            $actionMessage = $savedMessage;
            $actionClass = 'success';
        } elseif (isset($_POST['delete_invalid'])) {
            $invalidPosition = (int) ($_POST['invalid_position'] ?? -1);
            $originalCount = count($invalidRows);
            $invalidMissingKeys = [
                'dns' => 'invalid_block_list_row_missing',
                'bypass' => 'invalid_bypass_list_row_missing',
                'ip' => 'invalid_ip_list_row_missing',
            ];

            if ($kind === 'bypass') {
                sinkholeListsBypassRequireRepair($bypassConfiguration, $redirect);
            } elseif ($kind === 'ip') {
                sinkholeListsIpRequireRepair($ipConfiguration);
            }

            $invalidRows = array_values(array_filter(
                $invalidRows,
                static fn(array $invalidRow): bool => $invalidRow['position'] !== $invalidPosition,
            ));

            if (count($invalidRows) === $originalCount) {
                throw new ValidationException($invalidMissingKeys[$kind]);
            }

            if ($kind === 'bypass') {
                sinkholeListsBypassStore($bypassConfiguration, $redirect, $lists, $invalidRows);
            } elseif ($kind === 'ip') {
                sinkholeListsIpStore($ipConfiguration, $lists, $invalidRows);
            } else {
                sinkholeListsApply($lists, $allowedDomains, $invalidRows);
            }

            $actionMessage = $savedMessage;
            $actionClass = 'success';
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }

    if ($actionClass === 'success') {
        $loadKind();
    }
}

$bypassRows = ($kind === 'bypass') ? sinkholeListsBypassRows($lists) : [];
$catalogResults = [];
$catalogGroups = [];
$catalogCategoryCounts = array_fill_keys(array_merge([''], Catalog::categoryKeys()), 0);
$catalogKindCounts = array_fill_keys(array_merge([''], BypassConfiguration::KINDS), 0);
$catalogMaintainers = [];
$catalogStatuses = [];

if ($catalogOpen) {
    try {
        if ($kind === 'bypass') {
            $catalogLoad ??= $catalogCache->loadBypass();
            $catalogView = Catalog::bypassFacetedView(
                $catalogLoad['entries'],
                $catalogQuery,
                $catalogSource,
                $catalogMaintainer,
                $catalogKind,
            );
            $catalogKindCounts = $catalogView['kind_counts'];
        } else {
            $catalogLoad ??= ($kind === 'ip') ? $catalogCache->loadIp() : $catalogCache->load();
            $catalogView = Catalog::facetedView(
                $catalogLoad['entries'],
                $catalogQuery,
                $catalogSource,
                $catalogMaintainer,
                $catalogCategory,
                $catalogGroupBy,
            );
            $catalogCategoryCounts = $catalogView['category_counts'];
        }

        $catalogStatuses = $catalogLoad['statuses'];
        $catalogMaintainers = $catalogView['maintainers'];

        foreach (Catalog::markAdded($catalogView['entries'], $lists) as $matchingCatalogEntry) {
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

$pgtitle = [
    gettext('Firewall'),
    'Sinkhole',
    pfsensePackageSinkholeTranslate('lists'),
];
$pglinks = [
    '',
    '/pkg_edit.php?xml=sinkhole.xml&id=0',
    '@self',
];

include('head.inc');
?>
<link rel="stylesheet" href="/css/sinkhole.css">
<?php

display_top_tabs(pfsensePackageSinkholeTabs('lists'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}
?>
<div class="sinkhole-context">
	<ul class="nav nav-pills sinkhole-context-kinds sinkhole-list-kinds" role="tablist">
<?php foreach ($kindLabels as $kindKey => $kindLabel): ?>
		<li role="presentation"<?=($kindKey === $kind) ? ' class="active"' : ''?>><a href="sinkhole-lists.php?kind=<?=htmlspecialchars(rawurlencode($kindKey))?>"><?=htmlspecialchars($kindLabel)?></a></li>
<?php endforeach; ?>
	</ul>
</div>
<?php if ($kind === 'bypass'): ?>
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
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('used_by'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
				<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
			</tr></thead>
			<tbody>
<?php if ($bypassRows === []): ?>
				<tr><td colspan="8" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_bypass_lists_configured'))?></td></tr>
<?php else: ?>
<?php foreach ($bypassRows as $identifier => $row): $list = $row['list']; ?>
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
					<td><?=htmlspecialchars((string) ($usageCounts[$identifier] ?? 0))?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $list['enabled'] ? 'true' : 'false'))?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>" href="sinkhole-bypass_edit.php?id=<?=urlencode($identifier)?>"></a>
						<a class="<?=$list['enabled'] ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', $list['enabled'] ? 'enabled' : 'disabled'))?>" href="sinkhole-lists.php?kind=bypass&amp;toggle=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-lists.php?kind=bypass&amp;delete=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
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
	<a href="sinkhole-lists.php?kind=bypass&amp;catalog=1" role="button" class="btn btn-primary btn-sm">
		<i class="fa-solid fa-search icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add_from_catalog'))?>
	</a>
<?php endif; ?>
</nav>
<?php elseif ($kind === 'ip'): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('ip_lists'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('family'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('url'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('used_by'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
					<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
				</tr>
			</thead>
			<tbody>
<?php if ($lists === []): ?>
				<tr><td colspan="6" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_ip_lists_configured'))?></td></tr>
<?php else: ?>
<?php foreach ($lists as $identifier => $list): ?>
				<tr<?=($list['enabled']) ? '' : ' class="disabled"'?>>
					<td><?=htmlspecialchars($list['name'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('ip_family', $list['family']))?></td>
					<td><a href="<?=htmlspecialchars($list['url'])?>" target="_blank" rel="noopener noreferrer"><?=htmlspecialchars($list['url'])?></a></td>
					<td><?=htmlspecialchars((string) ($usageCounts[$identifier] ?? 0))?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $list['enabled'] ? 'true' : 'false'))?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>" href="sinkhole-ip_edit.php?id=<?=urlencode($identifier)?>"></a>
						<a class="<?=$list['enabled'] ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', $list['enabled'] ? 'enabled' : 'disabled'))?>" href="sinkhole-lists.php?kind=ip&amp;toggle=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-lists.php?kind=ip&amp;delete=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
					</td>
				</tr>
<?php endforeach; ?>
<?php endif; ?>
			</tbody>
		</table>
	</div>
</div>
<nav class="action-buttons">
	<a href="sinkhole-ip_edit.php" role="button" class="btn btn-success btn-sm">
		<i class="fa-solid fa-plus icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add'))?>
	</a>
<?php if ($catalogOpen === false): ?>
	<a href="sinkhole-lists.php?kind=ip&amp;catalog=1" role="button" class="btn btn-primary btn-sm">
		<i class="fa-solid fa-search icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add_from_catalog'))?>
	</a>
<?php endif; ?>
</nav>
<?php else: ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('block_lists'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
				<thead>
					<tr>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('url'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('used_by'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
						<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
					</tr>
				</thead>
				<tbody>
<?php if ($lists === []): ?>
					<tr><td colspan="5" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_block_lists_configured'))?></td></tr>
<?php else: ?>
<?php foreach ($lists as $identifier => $list): ?>
					<tr<?=($list['enabled']) ? '' : ' class="disabled"'?>>
						<td><?=htmlspecialchars($list['name'])?></td>
						<td>
							<a href="<?=htmlspecialchars($list['url'])?>" target="_blank" rel="noopener noreferrer">
								<?=htmlspecialchars($list['url'])?>
							</a>
						</td>
						<td><?=htmlspecialchars((string) ($usageCounts[$identifier] ?? 0))?></td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', ($list['enabled']) ? 'true' : 'false'))?></td>
						<td class="text-nowrap">
							<a class="fa-solid fa-pencil"
								title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>"
								href="sinkhole-lists_edit.php?id=<?=urlencode($identifier)?>"></a>
							<a class="<?=($list['enabled']) ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>"
								title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', ($list['enabled']) ? 'enabled' : 'disabled'))?>"
								href="sinkhole-lists.php?kind=dns&amp;toggle=1&amp;list_id=<?=urlencode($identifier)?>"
								usepost></a>
							<a class="fa-solid fa-trash-can"
								title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>"
								href="sinkhole-lists.php?kind=dns&amp;delete=1&amp;list_id=<?=urlencode($identifier)?>"
								usepost></a>
						</td>
					</tr>
<?php endforeach; ?>
<?php endif; ?>
				</tbody>
			</table>
	</div>
</div>
<nav class="action-buttons">
	<a href="sinkhole-lists_edit.php" role="button" class="btn btn-success btn-sm">
		<i class="fa-solid fa-plus icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add'))?>
	</a>
<?php if ($catalogOpen === false): ?>
	<a href="sinkhole-lists.php?kind=dns&amp;catalog=1" role="button" class="btn btn-primary btn-sm">
		<i class="fa-solid fa-search icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add_from_catalog'))?>
	</a>
<?php endif; ?>
</nav>
<?php endif; ?>
<?php if ($catalogOpen === true): ?>
<?php
$catalogStateParameters = [
    'kind' => $kind,
    'catalog' => '1',
    'catalog_query' => $catalogQuery,
    'catalog_maintainer' => $catalogMaintainer,
];

if ($kind !== 'ip') {
    $catalogStateParameters['catalog_source'] = $catalogSource;
}

if ($kind === 'bypass') {
    $catalogStateParameters['catalog_kind'] = $catalogKind;
} else {
    $catalogStateParameters['catalog_category'] = $catalogCategory;
    $catalogStateParameters['catalog_group_by'] = $catalogGroupBy;
}

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
$catalogRefreshButton->setAttribute('form', 'sinkhole-lists-refresh-form');
$catalogFilterForm = new Form(false);
$catalogFilterForm->setMethod('get');
$catalogFilterForm->setAction('sinkhole-lists.php');
$catalogFilterSection = new Form_Section(
    pfsensePackageSinkholeTranslate('add_from_catalog'),
);
$catalogFilterGroup = new Form_Group(pfsensePackageSinkholeTranslate('search'));
$catalogQueryInput = new Form_Input('catalog_query', null, 'text', $catalogQuery);
$catalogQueryInput->setAttribute('maxlength', Catalog::MAXIMUM_SEARCH_BYTES);
$catalogQueryInput->setWidth(($kind === 'ip') ? 4 : 3);
$catalogQueryInput->setHelp(pfsensePackageSinkholeTranslate('search'));
$catalogFilterGroup->add($catalogQueryInput);

if ($kind !== 'ip') {
    $catalogSourceInput = new Form_Select(
        'catalog_source',
        null,
        $catalogSource,
        $catalogSourceOptions,
    );
    $catalogSourceInput->setWidth(2);
    $catalogSourceInput->setHelp(pfsensePackageSinkholeTranslate('source'));
    $catalogFilterGroup->add($catalogSourceInput);
}

$catalogMaintainerInput = new Form_Select(
    'catalog_maintainer',
    null,
    $catalogMaintainer,
    $catalogMaintainerOptions,
);
$catalogMaintainerInput->setWidth(($kind === 'ip') ? 3 : 2);
$catalogMaintainerInput->setHelp(pfsensePackageSinkholeTranslate('maintainer'));
$catalogButtonInput = new Form_StaticText(
    '',
    (string) $catalogSearchButton . ' ' . (string) $catalogRefreshButton,
);
$catalogButtonInput->setWidth(3);
$catalogFilterGroup->add($catalogMaintainerInput);
$catalogFilterGroup->add($catalogButtonInput);
$catalogFilterGroup->setHelp(pfsensePackageSinkholeTranslate('catalog_search_help'));
$catalogFilterSection->add($catalogFilterGroup);
$catalogShowGroup = new Form_Group(pfsensePackageSinkholeTranslate('show'));

if ($kind === 'bypass') {
    $catalogKindLinks = '<div class="sinkhole-catalog-chips">';

    foreach (array_merge([''], BypassConfiguration::KINDS) as $catalogKindKey) {
        $catalogKindUrl = 'sinkhole-lists.php?' . http_build_query(array_merge(
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
} else {
    $catalogGroupByLabel = new Form_StaticText(
        '',
        '<strong>' . htmlspecialchars(pfsensePackageSinkholeTranslate('group_by')) . '</strong>',
    );
    $catalogGroupByLabel->setWidth(2);
    $catalogGroupByInput = new Form_Select(
        'catalog_group_by',
        null,
        $catalogGroupBy,
        [
            Catalog::GROUP_BY_CATEGORY => pfsensePackageSinkholeTranslateMapped(
                'catalog_group',
                Catalog::GROUP_BY_CATEGORY,
            ),
            Catalog::GROUP_BY_MAINTAINER => pfsensePackageSinkholeTranslateMapped(
                'catalog_group',
                Catalog::GROUP_BY_MAINTAINER,
            ),
        ],
    );
    $catalogGroupByInput->setWidth(2);
    $catalogCategoryLinks = '<div class="sinkhole-catalog-chips">';

    foreach (array_merge([''], Catalog::categoryKeys()) as $catalogCategoryKey) {
        $catalogCategoryUrl = 'sinkhole-lists.php?' . http_build_query(array_merge(
            $catalogStateParameters,
            ['catalog_category' => $catalogCategoryKey],
        ));
        $catalogCategoryLabel = ($catalogCategoryKey === '')
            ? pfsensePackageSinkholeTranslate('all')
            : pfsensePackageSinkholeTranslateMapped('catalog_category', $catalogCategoryKey);
        $catalogCategoryLinks .= sprintf(
            '<a class="btn btn-xs %s" href="%s">%s (%d)</a>',
            ($catalogCategory === $catalogCategoryKey) ? 'btn-primary' : 'btn-default',
            htmlspecialchars($catalogCategoryUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
            htmlspecialchars($catalogCategoryLabel),
            $catalogCategoryCounts[$catalogCategoryKey] ?? 0,
        );
    }

    $catalogCategoryLinks .= '</div>';
    $catalogCategoryInput = new Form_StaticText('', $catalogCategoryLinks);
    $catalogCategoryInput->setWidth(6);
    $catalogShowGroup->add($catalogGroupByLabel);
    $catalogShowGroup->add($catalogGroupByInput);
    $catalogShowGroup->add($catalogCategoryInput);
}

$catalogFilterSection->add($catalogShowGroup);
$catalogFilterForm->add($catalogFilterSection);
$catalogFilterForm->addGlobal(new Form_Input('kind', null, 'hidden', $kind));
$catalogFilterForm->addGlobal(new Form_Input('catalog', null, 'hidden', '1'));

if ($kind === 'bypass') {
    $catalogFilterForm->addGlobal(new Form_Input('catalog_kind', null, 'hidden', $catalogKind));
} else {
    $catalogFilterForm->addGlobal(new Form_Input('catalog_category', null, 'hidden', $catalogCategory));
}

print($catalogFilterForm);

$catalogHiddenFields = $catalogStateParameters;
unset($catalogHiddenFields['catalog']);
?>
<form id="sinkhole-lists-refresh-form" method="post" action="<?=htmlspecialchars($kindUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
<?php foreach ($catalogHiddenFields as $catalogHiddenName => $catalogHiddenValue): ?>
	<input type="hidden" name="<?=htmlspecialchars($catalogHiddenName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>" value="<?=htmlspecialchars($catalogHiddenValue, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
<?php endforeach; ?>
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
$catalogFetchedAt = is_int($catalogStatus['fetched_at'] ?? null)
    ? gmdate('Y-m-d H:i:s \U\T\C', $catalogStatus['fetched_at'])
    : pfsensePackageSinkholeTranslate('never');
$catalogLastError = (is_string($catalogStatus['last_error'] ?? null) && $catalogStatus['last_error'] !== '')
    ? $catalogStatus['last_error']
    : pfsensePackageSinkholeTranslate('none');
?>
				<tr>
					<td><?=htmlspecialchars((string) ($catalogStatus['source'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?></td>
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
if ($kind === 'bypass') {
    $catalogGroupTitle = pfsensePackageSinkholeTranslateMapped('bypass_kind', $catalogGroup['key']);
} elseif ($catalogGroupBy === Catalog::GROUP_BY_CATEGORY) {
    $catalogGroupTitle = pfsensePackageSinkholeTranslateMapped('catalog_category', $catalogGroup['key']);
} else {
    $catalogGroupTitle = ($catalogGroup['key'] === '')
        ? pfsensePackageSinkholeTranslate('unknown')
        : $catalogGroup['key'];
}
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
<?php if ($kind === 'bypass' || $catalogGroupBy === Catalog::GROUP_BY_CATEGORY): ?>
								<?=htmlspecialchars(pfsensePackageSinkholeTranslate('maintainer'))?>: <?=($catalogResult['maintainer'] === '') ? htmlspecialchars(pfsensePackageSinkholeTranslate('unknown')) : $catalogResult['maintainer']?>
<?php else: ?>
								<?=htmlspecialchars(pfsensePackageSinkholeTranslate('category'))?>: <?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('catalog_category', html_entity_decode($catalogResult['category'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')))?>
<?php endif; ?>
								<br><?=htmlspecialchars(pfsensePackageSinkholeTranslate('source'))?>: <?=$catalogResult['source']?>
								<br><?=htmlspecialchars(pfsensePackageSinkholeTranslate('contents'))?>: <?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('catalog_contents', html_entity_decode($catalogResult['contents'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')))?>
<?php if ($kind === 'ip'): ?>
								<br><?=htmlspecialchars(pfsensePackageSinkholeTranslate('family'))?>: <?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('ip_family', html_entity_decode($catalogResult['family'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')))?>
<?php endif; ?>
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
								<form method="post" action="<?=htmlspecialchars($kindUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
									<input type="hidden" name="catalog_entry" value="<?=$catalogResult['identifier']?>">
<?php foreach ($catalogHiddenFields as $catalogHiddenName => $catalogHiddenValue): ?>
									<input type="hidden" name="<?=htmlspecialchars($catalogHiddenName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>" value="<?=htmlspecialchars($catalogHiddenValue, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
<?php endforeach; ?>
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
<?php
$invalidEditors = [
    'dns' => 'sinkhole-lists_edit.php',
    'bypass' => 'sinkhole-bypass_edit.php',
    'ip' => 'sinkhole-ip_edit.php',
];
$invalidEditor = $invalidEditors[$kind];
?>
<?php if (count($invalidRows) > 0): ?>
<div class="panel panel-danger">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_saved_rows'))?></h2></div>
	<div class="panel-body table-responsive">
			<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
				<thead>
					<tr>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('url'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('reason'))?></th>
						<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
					</tr>
				</thead>
				<tbody>
<?php foreach ($invalidRows as $invalidRow): ?>
					<tr>
						<td><?=htmlspecialchars($invalidRow['name'])?></td>
						<td><?=htmlspecialchars($invalidRow['url'])?></td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeInvalidReason($invalidRow))?></td>
						<td class="text-nowrap">
							<a class="fa-solid fa-pencil"
								title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('fix'))?>"
								href="<?=htmlspecialchars($invalidEditor)?>?invalid_position=<?=urlencode((string) $invalidRow['position'])?>"></a>
							<a class="fa-solid fa-trash-can"
								title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>"
								href="sinkhole-lists.php?kind=<?=htmlspecialchars(rawurlencode($kind))?>&amp;delete_invalid=1&amp;invalid_position=<?=urlencode((string) $invalidRow['position'])?>"
								usepost></a>
						</td>
					</tr>
<?php endforeach; ?>
				</tbody>
			</table>
	</div>
</div>
<?php endif; ?>
<?php
include('foot.inc');
