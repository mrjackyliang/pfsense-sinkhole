<?php

declare(strict_types=1);

/*
 * Sinkhole IP and country blocking configuration page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-ip
##|*NAME=Firewall: Sinkhole: IP
##|*DESCR=Allow access to Sinkhole IP and country blocking settings.
##|*MATCH=sinkhole-ip.php*
##|-PRIV

use PfSense\Sinkhole\Domain\Catalog;
use PfSense\Sinkhole\Domain\ValidationException;
use PfSense\Sinkhole\Runtime\CatalogCache;
use PfSense\Sinkhole\Runtime\CurlDownloadClient;
use PfSense\Sinkhole\Web\CatalogPresentation;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/Catalog.php');
require_once('/usr/local/pkg/sinkhole/CatalogCache.php');
require_once('/usr/local/pkg/sinkhole/CatalogPresentation.php');
require_once('/usr/local/pkg/sinkhole/CurlDownloadClient.php');

/** @since 1.0.0 */
function sinkholeIpLines(mixed $value, string $errorKey): array
{
    if (!is_string($value)) {
        throw new ValidationException($errorKey);
    }

    $lines = preg_split('/\r\n|\r|\n/', $value);

    if (!is_array($lines)) {
        throw new ValidationException($errorKey);
    }

    return array_values(array_filter(
        array_map('trim', $lines),
        static fn(string $line): bool => $line !== '',
    ));
}

/** @since 1.0.0 */
function sinkholeIpRequireSettingsRepair(array $configuration): void
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

/** @since 1.0.0 */
function sinkholeIpStorage(
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

    $settings ??= [
        'enabled' => $configuration['enabled'],
        'interfaces' => $configuration['stored_interfaces'],
        'directions' => $configuration['stored_directions'],
        'countries' => $configuration['stored_countries'],
        'account_id' => $configuration['account_id'],
        'license_key' => $configuration['license_key'],
        'allowlist' => $configuration['stored_allowlist'],
    ];

    return [
        'enabled' => $settings['enabled'] ? 'on' : '',
        'interfaces' => ['item' => array_values($settings['interfaces'])],
        'directions' => ['item' => array_values($settings['directions'])],
        'lists' => ['item' => $rows],
        'countries' => ['item' => array_values($settings['countries'])],
        'account_id' => $settings['account_id'],
        'license_key' => $settings['license_key'],
        'allowlist' => ['item' => array_values($settings['allowlist'])],
    ];
}

$adapter = pfsensePackageSinkholeAdapter();
$interfaces = $adapter->getConfiguredInterfaces();
$configuration = pfsensePackageSinkholeGetIpConfiguration();
$lists = $configuration['lists'];
$invalidRows = $configuration['invalid_lists'];
$actionMessage = ((string) ($_GET['saved'] ?? '') === '1')
    ? pfsensePackageSinkholeTranslate('ip_saved_applying')
    : null;
$actionClass = 'info';
$catalogOpen = (string) ($_GET['catalog'] ?? '') === '1'
    || isset($_POST['refresh_catalog'])
    || isset($_POST['add_catalog_list']);
$catalogQuery = Catalog::normalizeSearchQuery((string) (
    $_POST['catalog_query'] ?? $_GET['catalog_query'] ?? ''
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
$catalogCache = new CatalogCache($adapter->packagePaths(), new CurlDownloadClient());
$catalogLoad = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['save_ip_settings'])) {
            $licenseKey = is_string($_POST['maxmind_license_key'] ?? null)
                ? (string) $_POST['maxmind_license_key']
                : '';

            if (isset($_POST['clear_maxmind_license_key'])) {
                $licenseKey = '';
            } elseif ($licenseKey === '') {
                $licenseKey = $configuration['license_key'];
            }

            $settings = [
                'enabled' => isset($_POST['ip_enabled']),
                'interfaces' => is_array($_POST['ip_interfaces'] ?? null)
                    ? array_values($_POST['ip_interfaces'])
                    : [],
                'directions' => is_array($_POST['ip_directions'] ?? null)
                    ? array_values($_POST['ip_directions'])
                    : [],
                'countries' => sinkholeIpLines($_POST['ip_countries'] ?? '', 'ip_countries_invalid'),
                'account_id' => is_string($_POST['maxmind_account_id'] ?? null)
                    ? $_POST['maxmind_account_id']
                    : '',
                'license_key' => $licenseKey,
                'allowlist' => sinkholeIpLines($_POST['ip_allowlist'] ?? '', 'ip_allowlist_invalid'),
            ];
            $configuration['enabled'] = $settings['enabled'];
            $configuration['stored_interfaces'] = $settings['interfaces'];
            $configuration['stored_directions'] = $settings['directions'];
            $configuration['stored_countries'] = $settings['countries'];
            $configuration['account_id'] = $settings['account_id'];
            $configuration['stored_allowlist'] = $settings['allowlist'];
            pfsensePackageSinkholeSaveIp(
                sinkholeIpStorage($configuration, $lists, $invalidRows, $settings),
            );
            $actionMessage = pfsensePackageSinkholeTranslate('ip_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['toggle_ip_list']) || isset($_POST['delete_ip_list'])) {
            sinkholeIpRequireSettingsRepair($configuration);
            $identifier = (string) ($_POST['list_id'] ?? '');

            if (!isset($lists[$identifier])) {
                throw new ValidationException('ip_list_missing');
            }

            if (isset($_POST['delete_ip_list'])) {
                unset($lists[$identifier]);
            } else {
                $lists[$identifier]['enabled'] = !$lists[$identifier]['enabled'];
            }

            pfsensePackageSinkholeSaveIp(sinkholeIpStorage($configuration, $lists, $invalidRows));
            $actionMessage = pfsensePackageSinkholeTranslate('ip_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['delete_invalid_ip_list'])) {
            sinkholeIpRequireSettingsRepair($configuration);
            $position = (int) ($_POST['invalid_position'] ?? -1);
            $originalCount = count($invalidRows);
            $invalidRows = array_values(array_filter(
                $invalidRows,
                static fn(array $invalidRow): bool => $invalidRow['position'] !== $position,
            ));

            if (count($invalidRows) === $originalCount) {
                throw new ValidationException('invalid_ip_list_row_missing');
            }

            pfsensePackageSinkholeSaveIp(sinkholeIpStorage($configuration, $lists, $invalidRows));
            $actionMessage = pfsensePackageSinkholeTranslate('ip_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['refresh_catalog'])) {
            $catalogLoad = $catalogCache->loadIp(true);
            $actionMessage = pfsensePackageSinkholeTranslate('catalog_refresh_finished');
            $actionClass = (($catalogLoad['statuses'][Catalog::SOURCE_PFBLOCKERNG]['last_error']
                ?? '') === '') ? 'success' : 'warning';
        } elseif (isset($_POST['add_catalog_list'])) {
            sinkholeIpRequireSettingsRepair($configuration);
            $catalogLoad = $catalogCache->loadIp();
            $lists = Catalog::addIpList(
                $catalogLoad['entries'],
                $lists,
                (string) ($_POST['catalog_entry'] ?? ''),
            );
            pfsensePackageSinkholeSaveIp(sinkholeIpStorage($configuration, $lists, $invalidRows));
            $actionMessage = pfsensePackageSinkholeTranslate('ip_saved_applying');
            $actionClass = 'success';
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }

    if ($actionClass === 'success') {
        $configuration = pfsensePackageSinkholeGetIpConfiguration();
        $lists = $configuration['lists'];
        $invalidRows = $configuration['invalid_lists'];
    }
}

$catalogResults = [];
$catalogGroups = [];
$catalogCategoryCounts = array_fill_keys(array_merge([''], Catalog::categoryKeys()), 0);
$catalogMaintainers = [];
$catalogStatuses = [];

if ($catalogOpen) {
    try {
        $catalogLoad ??= $catalogCache->loadIp();
        $catalogStatuses = $catalogLoad['statuses'];
        $catalogView = Catalog::facetedView(
            $catalogLoad['entries'],
            $catalogQuery,
            '',
            $catalogMaintainer,
            $catalogCategory,
            $catalogGroupBy,
        );
        $matches = Catalog::markAdded($catalogView['entries'], $lists);
        $catalogCategoryCounts = $catalogView['category_counts'];
        $catalogMaintainers = $catalogView['maintainers'];
        $catalogResults = array_map(
            static fn(array $entry): array => CatalogPresentation::entry($entry),
            $matches,
        );

        foreach ($catalogView['groups'] as $catalogGroup) {
            $catalogGroups[] = [
                'key' => $catalogGroup['key'],
                'count' => $catalogGroup['count'],
                'entries' => array_map(
                    static fn(array $entry): array => CatalogPresentation::entry($entry),
                    Catalog::markAdded($catalogGroup['entries'], $lists),
                ),
            ];
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }
}

$pgtitle = [gettext('Firewall'), 'Sinkhole', pfsensePackageSinkholeTranslate('ip')];
$pglinks = ['', '/pkg_edit.php?xml=sinkhole.xml&id=0', '@self'];
include('head.inc');
?>
<link rel="stylesheet" href="/css/sinkhole.css">
<?php
display_top_tabs(pfsensePackageSinkholeTabs('ip'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

if ($configuration['invalid_values'] !== []):
?>
<div class="panel panel-danger">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_saved_values'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('field'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('value'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('reason'))?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($configuration['invalid_values'] as $invalidValue): ?>
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
<?php endif; ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('ip_lists'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('family'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('url'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
					<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
				</tr>
			</thead>
			<tbody>
<?php if ($lists === []): ?>
				<tr><td colspan="5" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_ip_lists_configured'))?></td></tr>
<?php else: ?>
<?php foreach ($lists as $identifier => $list): ?>
				<tr<?=($list['enabled']) ? '' : ' class="disabled"'?>>
					<td><?=htmlspecialchars($list['name'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('ip_family', $list['family']))?></td>
					<td><a href="<?=htmlspecialchars($list['url'])?>" target="_blank" rel="noopener noreferrer"><?=htmlspecialchars($list['url'])?></a></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $list['enabled'] ? 'true' : 'false'))?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>" href="sinkhole-ip_edit.php?id=<?=urlencode($identifier)?>"></a>
						<a class="<?=$list['enabled'] ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', $list['enabled'] ? 'enabled' : 'disabled'))?>" href="sinkhole-ip.php?toggle_ip_list=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-ip.php?delete_ip_list=1&amp;list_id=<?=urlencode($identifier)?>" usepost></a>
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
</nav>
<?php if ($invalidRows !== []): ?>
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
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('fix'))?>" href="sinkhole-ip_edit.php?invalid_position=<?=urlencode((string) $invalidRow['position'])?>"></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" usepost href="sinkhole-ip.php?delete_invalid_ip_list=1&amp;invalid_position=<?=urlencode((string) $invalidRow['position'])?>"></a>
					</td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php endif; ?>
<?php if (!$catalogOpen): ?>
<?php
$catalogOpenButton = '<a class="btn btn-primary btn-sm" href="sinkhole-ip.php?catalog=1" role="button">'
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
    'catalog_maintainer' => $catalogMaintainer,
    'catalog_category' => $catalogCategory,
    'catalog_group_by' => $catalogGroupBy,
];
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
$catalogRefreshButton->setAttribute('form', 'sinkhole-ip-refresh-form');
$catalogFilterForm = new Form(false);
$catalogFilterForm->setMethod('get');
$catalogFilterForm->setAction('sinkhole-ip.php');
$catalogFilterSection = new Form_Section(
    pfsensePackageSinkholeTranslate('add_from_catalog'),
);
$catalogFilterGroup = new Form_Group(pfsensePackageSinkholeTranslate('search'));
$catalogQueryInput = new Form_Input('catalog_query', null, 'text', $catalogQuery);
$catalogQueryInput->setAttribute('maxlength', Catalog::MAXIMUM_SEARCH_BYTES);
$catalogQueryInput->setWidth(4);
$catalogQueryInput->setHelp(pfsensePackageSinkholeTranslate('search'));
$catalogMaintainerInput = new Form_Select(
    'catalog_maintainer',
    null,
    $catalogMaintainer,
    $catalogMaintainerOptions,
);
$catalogMaintainerInput->setWidth(3);
$catalogMaintainerInput->setHelp(pfsensePackageSinkholeTranslate('maintainer'));
$catalogButtonInput = new Form_StaticText(
    '',
    (string) $catalogSearchButton . ' ' . (string) $catalogRefreshButton,
);
$catalogButtonInput->setWidth(3);
$catalogFilterGroup->add($catalogQueryInput);
$catalogFilterGroup->add($catalogMaintainerInput);
$catalogFilterGroup->add($catalogButtonInput);
$catalogFilterGroup->setHelp(pfsensePackageSinkholeTranslate('catalog_search_help'));
$catalogFilterSection->add($catalogFilterGroup);
$catalogShowGroup = new Form_Group(pfsensePackageSinkholeTranslate('show'));
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
    $catalogCategoryUrl = 'sinkhole-ip.php?' . http_build_query(array_merge(
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
$catalogFilterSection->add($catalogShowGroup);
$catalogFilterForm->add($catalogFilterSection);
$catalogFilterForm->addGlobal(new Form_Input('catalog', null, 'hidden', '1'));
$catalogFilterForm->addGlobal(new Form_Input(
    'catalog_category',
    null,
    'hidden',
    $catalogCategory,
));
print($catalogFilterForm);
?>
<form id="sinkhole-ip-refresh-form" method="post" action="sinkhole-ip.php">
	<input type="hidden" name="catalog_query" value="<?=htmlspecialchars($catalogQuery, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<input type="hidden" name="catalog_maintainer" value="<?=htmlspecialchars($catalogMaintainer, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<input type="hidden" name="catalog_category" value="<?=htmlspecialchars($catalogCategory, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<input type="hidden" name="catalog_group_by" value="<?=htmlspecialchars($catalogGroupBy, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
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
$catalogLastError = is_string($catalogStatus['last_error'] ?? null)
    && $catalogStatus['last_error'] !== ''
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
<?php if ($catalogResults === []): ?>
<?php print_info_box(htmlspecialchars(pfsensePackageSinkholeTranslate('no_catalog_results')), 'warning', false); ?>
<?php else: ?>
<?php foreach ($catalogGroups as $catalogGroup): ?>
<?php
$catalogGroupTitle = ($catalogGroupBy === Catalog::GROUP_BY_CATEGORY)
    ? pfsensePackageSinkholeTranslateMapped('catalog_category', $catalogGroup['key'])
    : (($catalogGroup['key'] === '') ? pfsensePackageSinkholeTranslate('unknown') : $catalogGroup['key']);
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
<?php if ($catalogGroupBy === Catalog::GROUP_BY_CATEGORY): ?>
							<?=htmlspecialchars(pfsensePackageSinkholeTranslate('maintainer'))?>: <?=($catalogResult['maintainer'] === '') ? htmlspecialchars(pfsensePackageSinkholeTranslate('unknown')) : $catalogResult['maintainer']?>
<?php else: ?>
							<?=htmlspecialchars(pfsensePackageSinkholeTranslate('category'))?>: <?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('catalog_category', html_entity_decode($catalogResult['category'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')))?>
<?php endif; ?>
							<br><?=htmlspecialchars(pfsensePackageSinkholeTranslate('source'))?>: <?=$catalogResult['source']?>
							<br><?=htmlspecialchars(pfsensePackageSinkholeTranslate('contents'))?>: <?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('catalog_contents', html_entity_decode($catalogResult['contents'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')))?>
							<br><?=htmlspecialchars(pfsensePackageSinkholeTranslate('family'))?>: <?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('ip_family', html_entity_decode($catalogResult['family'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')))?>
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
							<form method="post" action="sinkhole-ip.php">
								<input type="hidden" name="catalog_entry" value="<?=$catalogResult['identifier']?>">
								<input type="hidden" name="catalog_query" value="<?=htmlspecialchars($catalogQuery, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
								<input type="hidden" name="catalog_maintainer" value="<?=htmlspecialchars($catalogMaintainer, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
								<input type="hidden" name="catalog_category" value="<?=htmlspecialchars($catalogCategory, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
								<input type="hidden" name="catalog_group_by" value="<?=htmlspecialchars($catalogGroupBy, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
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
$settingsButton = new Form_Button(
    'save_ip_settings',
    pfsensePackageSinkholeTranslate('save'),
    null,
    'fa-solid fa-save',
);
$settingsButton->addClass('btn-primary');
$settingsForm = new Form($settingsButton);
$settingsSection = new Form_Section(pfsensePackageSinkholeTranslate('ip_country_blocking'));
$settingsSection->addInput(new Form_Checkbox(
    'ip_enabled',
    pfsensePackageSinkholeTranslate('enable'),
    pfsensePackageSinkholeTranslate('ip_enable_help'),
    $configuration['enabled'],
));
$interfaceOptions = $interfaces;

foreach ($configuration['stored_interfaces'] as $storedInterface) {
    if (!isset($interfaceOptions[$storedInterface])) {
        $interfaceOptions[$storedInterface] = pfsensePackageSinkholeTranslate(
            'unavailable_interface',
        ) . ' — ' . $storedInterface;
    }
}

$interfaceInput = new Form_Select(
    'ip_interfaces',
    pfsensePackageSinkholeTranslate('interfaces'),
    $configuration['stored_interfaces'],
    $interfaceOptions,
    true,
);
$interfaceInput->setHelp(pfsensePackageSinkholeTranslate('ip_interfaces_help'));
$settingsSection->addInput($interfaceInput);
$directionOptions = [
    'inbound' => pfsensePackageSinkholeTranslate('inbound'),
    'outbound' => pfsensePackageSinkholeTranslate('outbound'),
];

foreach ($configuration['stored_directions'] as $storedDirection) {
    if (!isset($directionOptions[$storedDirection])) {
        $directionOptions[$storedDirection] = pfsensePackageSinkholeTranslate(
            'unavailable_direction',
        ) . ' — ' . $storedDirection;
    }
}

$directionInput = new Form_Select(
    'ip_directions',
    pfsensePackageSinkholeTranslate('directions'),
    $configuration['stored_directions'],
    $directionOptions,
    true,
);
$directionInput->setHelp(pfsensePackageSinkholeTranslate('ip_directions_help'));
$settingsSection->addInput($directionInput);
$countriesInput = new Form_Textarea(
    'ip_countries',
    pfsensePackageSinkholeTranslate('countries'),
    implode(PHP_EOL, $configuration['stored_countries']),
);
$countriesInput->setHelp(pfsensePackageSinkholeTranslate('countries_help'));
$settingsSection->addInput($countriesInput);
$accountInput = new Form_Input(
    'maxmind_account_id',
    pfsensePackageSinkholeTranslate('maxmind_account_id'),
    'text',
    $configuration['account_id'],
);
$accountInput->setHelp(pfsensePackageSinkholeTranslate('maxmind_account_id_help'));
$settingsSection->addInput($accountInput);
$settingsSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('maxmind_license_key_status'),
    pfsensePackageSinkholeTranslateMapped(
        'secret_state',
        $configuration['license_key_set'] ? 'set' : 'unset',
    ),
));
$licenseInput = new Form_Input(
    'maxmind_license_key',
    pfsensePackageSinkholeTranslate('maxmind_license_key'),
    'password',
    '',
);
$licenseInput->setHelp(pfsensePackageSinkholeTranslate('maxmind_license_key_help'));
$settingsSection->addInput($licenseInput);
$settingsSection->addInput(new Form_Checkbox(
    'clear_maxmind_license_key',
    pfsensePackageSinkholeTranslate('clear_license_key'),
    pfsensePackageSinkholeTranslate('clear_license_key_help'),
    false,
));
$allowlistInput = new Form_Textarea(
    'ip_allowlist',
    pfsensePackageSinkholeTranslate('ip_allowlist'),
    implode(PHP_EOL, $configuration['stored_allowlist']),
);
$allowlistInput->setHelp(pfsensePackageSinkholeTranslate('ip_allowlist_help'));
$settingsSection->addInput($allowlistInput);
$settingsForm->add($settingsSection);
print($settingsForm);

include('foot.inc');
