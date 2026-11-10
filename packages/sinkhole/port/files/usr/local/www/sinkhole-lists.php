<?php

declare(strict_types=1);

/*
 * Sinkhole block-list configuration page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-lists
##|*NAME=Firewall: Sinkhole: Lists
##|*DESCR=Allow access to Sinkhole block-list configuration.
##|*MATCH=sinkhole-lists.php*
##|-PRIV

use PfSense\Sinkhole\Domain\Catalog;
use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\ListConfiguration;
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
require_once('/usr/local/pkg/sinkhole/DomainParser.php');
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

$listConfiguration = pfsensePackageSinkholeGetListConfiguration();
$lists = $listConfiguration['lists'];
$invalidRows = $listConfiguration['invalid_rows'];
$allowedDomains = pfsensePackageSinkholeGetAllowedDomains();
$usageCounts = pfsensePackageSinkholeListUsageCounts();
$actionClass = 'info';
$actionMessage = ((string) ($_GET['saved'] ?? '') === '1')
    ? pfsensePackageSinkholeTranslate('settings_saved_applying')
    : null;
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
$catalogCache = new CatalogCache(
    pfsensePackageSinkholeAdapter()->packagePaths(),
    new CurlDownloadClient(),
);
$catalogLoad = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['refresh_catalog'])) {
            $catalogLoad = $catalogCache->load(true);
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
            $catalogLoad = $catalogCache->load();
            $updatedLists = Catalog::addList(
                $catalogLoad['entries'],
                $lists,
                (string) ($_POST['catalog_entry'] ?? ''),
            );

            sinkholeListsApply($updatedLists, $allowedDomains, $invalidRows);
            $lists = $updatedLists;

            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['toggle'])) {
            $identifier = (string) ($_POST['list_id'] ?? '');

            if (isset($lists[$identifier]) === false) {
                throw new ValidationException('block_list_missing');
            }

            $lists[$identifier]['enabled'] = !$lists[$identifier]['enabled'];
            $lists[$identifier] = ListConfiguration::normalizeRow(
                $identifier,
                $lists[$identifier]['name'],
                $lists[$identifier]['url'],
                $lists[$identifier]['enabled'],
                $lists[$identifier]['global'],
            );

            sinkholeListsApply($lists, $allowedDomains, $invalidRows);

            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['delete'])) {
            $identifier = (string) ($_POST['list_id'] ?? '');

            if (isset($lists[$identifier]) === false) {
                throw new ValidationException('block_list_missing');
            }

            unset($lists[$identifier]);
            sinkholeListsApply($lists, $allowedDomains, $invalidRows);

            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['delete_invalid'])) {
            $invalidPosition = (int) ($_POST['invalid_position'] ?? -1);
            $originalCount = count($invalidRows);
            $invalidRows = array_values(array_filter(
                $invalidRows,
                static fn(array $invalidRow): bool => $invalidRow['position'] !== $invalidPosition,
            ));

            if (count($invalidRows) === $originalCount) {
                throw new ValidationException('invalid_block_list_row_missing');
            }

            sinkholeListsApply($lists, $allowedDomains, $invalidRows);

            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['save_allowed'])) {
            $allowedResult = DomainParser::normalizeAllowedDomains(
                (string) ($_POST['allowed_domains'] ?? ''),
            );

            if (count($allowedResult['invalid_lines']) > 0) {
                throw new ValidationException(
                    'allowed_domains_invalid_lines',
                    [implode(', ', $allowedResult['invalid_lines'])],
                );
            }

            $allowedDomains = $allowedResult['domains'];
            sinkholeListsApply($lists, $allowedDomains, $invalidRows);
            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }

    if ($actionClass === 'success') {
        $listConfiguration = pfsensePackageSinkholeGetListConfiguration();
        $lists = $listConfiguration['lists'];
        $invalidRows = $listConfiguration['invalid_rows'];
        $allowedDomains = pfsensePackageSinkholeGetAllowedDomains();
        $usageCounts = pfsensePackageSinkholeListUsageCounts();
    }
}

$catalogResults = [];
$catalogGroups = [];
$catalogCategoryCounts = array_fill_keys(array_merge([''], Catalog::categoryKeys()), 0);
$catalogMaintainers = [];
$catalogStatuses = [];

if ($catalogOpen) {
    try {
        $catalogLoad ??= $catalogCache->load();
        $catalogStatuses = $catalogLoad['statuses'];
        $catalogView = Catalog::facetedView(
            $catalogLoad['entries'],
            $catalogQuery,
            $catalogSource,
            $catalogMaintainer,
            $catalogCategory,
            $catalogGroupBy,
        );
        $matchingCatalogEntries = Catalog::markAdded($catalogView['entries'], $lists);
        $catalogCategoryCounts = $catalogView['category_counts'];
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
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('block_lists'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
				<thead>
					<tr>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('url'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('global'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('used_by'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
						<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
					</tr>
				</thead>
				<tbody>
<?php if ($lists === []): ?>
					<tr><td colspan="6" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_block_lists_configured'))?></td></tr>
<?php else: ?>
<?php foreach ($lists as $identifier => $list): ?>
					<tr<?=($list['enabled']) ? '' : ' class="disabled"'?>>
						<td><?=htmlspecialchars($list['name'])?></td>
						<td>
							<a href="<?=htmlspecialchars($list['url'])?>" target="_blank" rel="noopener noreferrer">
								<?=htmlspecialchars($list['url'])?>
							</a>
						</td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', ($list['global']) ? 'true' : 'false'))?></td>
						<td><?=htmlspecialchars((string) ($usageCounts[$identifier] ?? 0))?></td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', ($list['enabled']) ? 'true' : 'false'))?></td>
						<td class="text-nowrap">
							<a class="fa-solid fa-pencil"
								title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>"
								href="sinkhole-lists_edit.php?id=<?=urlencode($identifier)?>"></a>
							<a class="<?=($list['enabled']) ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>"
								title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', ($list['enabled']) ? 'enabled' : 'disabled'))?>"
								href="sinkhole-lists.php?toggle=1&amp;list_id=<?=urlencode($identifier)?>"
								usepost></a>
							<a class="fa-solid fa-trash-can"
								title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>"
								href="sinkhole-lists.php?delete=1&amp;list_id=<?=urlencode($identifier)?>"
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
</nav>
<?php if ($catalogOpen === false): ?>
<?php
$catalogOpenButton = '<a class="btn btn-primary btn-sm" href="sinkhole-lists.php?catalog=1" role="button">'
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
    'catalog_category' => $catalogCategory,
    'catalog_group_by' => $catalogGroupBy,
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
<form id="sinkhole-lists-refresh-form" method="post" action="sinkhole-lists.php">
	<input type="hidden" name="catalog_query" value="<?=htmlspecialchars($catalogQuery, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<input type="hidden" name="catalog_source" value="<?=htmlspecialchars($catalogSource, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
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
$catalogGroupTitle = ($catalogGroupBy === Catalog::GROUP_BY_CATEGORY)
    ? pfsensePackageSinkholeTranslateMapped('catalog_category', $catalogGroup['key'])
    : (($catalogGroup['key'] === '')
        ? pfsensePackageSinkholeTranslate('unknown')
        : $catalogGroup['key']);
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
								<form method="post" action="sinkhole-lists.php">
									<input type="hidden" name="catalog_entry" value="<?=$catalogResult['identifier']?>">
									<input type="hidden" name="catalog_query" value="<?=htmlspecialchars($catalogQuery, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
									<input type="hidden" name="catalog_source" value="<?=htmlspecialchars($catalogSource, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
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
								href="sinkhole-lists_edit.php?invalid_position=<?=urlencode((string) $invalidRow['position'])?>"></a>
							<a class="fa-solid fa-trash-can"
								title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>"
								href="sinkhole-lists.php?delete_invalid=1&amp;invalid_position=<?=urlencode((string) $invalidRow['position'])?>"
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
$allowedButton = new Form_Button(
    'save_allowed',
    pfsensePackageSinkholeTranslate('save'),
    null,
    'fa-solid fa-save',
);
$allowedButton->addClass('btn-primary');
$allowedForm = new Form($allowedButton);
$allowedSection = new Form_Section(pfsensePackageSinkholeTranslate('allowed_domains'));
$allowedInput = new Form_Textarea(
    'allowed_domains',
    pfsensePackageSinkholeTranslate('domains'),
    (count($allowedDomains) > 0) ? implode(PHP_EOL, $allowedDomains) . PHP_EOL : '',
);
$allowedInput->setRows(6);
$allowedInput->setHelp(pfsensePackageSinkholeTranslate('allowed_domains_help'));
$allowedSection->addInput($allowedInput);
$allowedForm->add($allowedSection);

print($allowedForm);

include('foot.inc');
