<?php

declare(strict_types=1);

/*
 * Sinkhole blocked-services configuration page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-services
##|*NAME=Firewall: Sinkhole: Services
##|*DESCR=Allow access to Sinkhole blocked-service configuration.
##|*MATCH=sinkhole-services.php*
##|-PRIV

use PfSense\Sinkhole\Domain\ServiceConfiguration;
use PfSense\Sinkhole\Domain\ServiceRegistry;
use PfSense\Sinkhole\Runtime\CurlDownloadClient;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\SavedListStore;
use PfSense\Sinkhole\Runtime\ServiceRegistryCache;
use PfSense\Sinkhole\Web\ServicePresentation;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/CurlDownloadClient.php');
require_once('/usr/local/pkg/sinkhole/ServiceConfiguration.php');
require_once('/usr/local/pkg/sinkhole/ServicePresentation.php');
require_once('/usr/local/pkg/sinkhole/ServiceRegistry.php');
require_once('/usr/local/pkg/sinkhole/ServiceRegistryCache.php');

$adapter = pfsensePackageSinkholeAdapter();
$interfaces = $adapter->getConfiguredInterfaces();
$scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
$serviceConfiguration = pfsensePackageSinkholeGetBlockedServices();
$scopeOptions = [
    'global' => pfsensePackageSinkholeTranslate('global'),
];

foreach ($scopeConfiguration['networks'] as $identifier => $network) {
    $scopeOptions['network:' . $identifier] = pfsensePackageSinkholeTranslate(
        'service_network_scope',
        [$interfaces[$network['interface']] ?? $network['interface']],
    );
}

foreach ($scopeConfiguration['devices'] as $identifier => $device) {
    $scopeOptions['device:' . $identifier] = pfsensePackageSinkholeTranslate(
        'service_device_scope',
        [$device['name']],
    );
}

$selectedScope = (string) ($_POST['service_scope'] ?? $_GET['service_scope'] ?? 'global');

if (!isset($scopeOptions[$selectedScope])) {
    $selectedScope = 'global';
}

$serviceQuery = ServiceRegistry::normalizeSearchQuery((string) (
    $_POST['service_query'] ?? $_GET['service_query'] ?? ''
));
$requestedGroup = (string) ($_POST['service_group'] ?? $_GET['service_group'] ?? '');
$actionMessage = null;
$actionClass = 'info';
$registryCache = new ServiceRegistryCache($adapter->packagePaths(), new CurlDownloadClient());
$registryLoad = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['refresh_services'])) {
            $registryLoad = $registryCache->load(true);
            $actionMessage = pfsensePackageSinkholeTranslate('service_registry_refresh_finished');
            $actionClass = ($registryLoad['status']['last_error'] === '') ? 'success' : 'warning';
        } elseif (isset($_POST['save_services'])) {
            $currentSelection = ServiceConfiguration::scopeSelection(
                $serviceConfiguration,
                $selectedScope,
            );
            $visibleSelection = is_array($_POST['visible_services'] ?? null)
                ? ServiceConfiguration::replaceScopeSelection(
                    ['global' => []],
                    'global',
                    $_POST['visible_services'],
                )['global']
                : [];
            $postedSelection = is_array($_POST['service_ids'] ?? null)
                ? ServiceConfiguration::replaceScopeSelection(
                    ['global' => []],
                    'global',
                    $_POST['service_ids'],
                )['global']
                : [];
            $postedSelection = array_values(array_intersect($postedSelection, $visibleSelection));
            $selection = array_values(array_unique(array_merge(
                array_values(array_diff($currentSelection, $visibleSelection)),
                $postedSelection,
            )));
            $serviceConfiguration = ServiceConfiguration::replaceScopeSelection(
                $serviceConfiguration,
                $selectedScope,
                $selection,
            );
            pfsensePackageSinkholeSaveBlockedServices($serviceConfiguration);
            pfsensePackageSinkholeInstallCron();
            $adapter->runApplyInBackground();
            $serviceConfiguration = pfsensePackageSinkholeGetBlockedServices();
            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }
}

try {
    $registryLoad ??= $registryCache->load();
} catch (Throwable $throwable) {
    $registryLoad = [
        'registry' => ServiceRegistry::emptyRegistry(),
        'status' => ['fetched_at' => null, 'last_error' => $throwable->getMessage()],
        'changed' => false,
    ];
    $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
    $actionClass = 'danger';
}

$serviceCounts = ServiceConfiguration::counts($serviceConfiguration);
$hasSelectedServices = $serviceCounts['global'] > 0
    || array_sum($serviceCounts['networks']) > 0
    || array_sum($serviceCounts['devices']) > 0;

if (($registryLoad['changed'] ?? false) === true && $hasSelectedServices) {
    try {
        (new Compiler(
            $adapter->packagePaths(),
            new SavedListStore($adapter->packagePaths()),
        ))->markNeeded();
        $adapter->runApplyInBackground();
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }
}

$registry = $registryLoad['registry'];
$selectedServices = ServiceConfiguration::scopeSelection($serviceConfiguration, $selectedScope);
$unknownServices = [];

foreach ($selectedServices as $serviceIdentifier) {
    if (!isset($registry['services'][$serviceIdentifier])) {
        $unknownServices[] = $serviceIdentifier;
    }
}

$serviceGroup = isset($registry['groups'][$requestedGroup]) || $requestedGroup === 'repair'
    ? $requestedGroup
    : '';
$registryView = ServiceRegistry::facetedView(
    $registry,
    $serviceQuery,
    ($serviceGroup === 'repair') ? '' : $serviceGroup,
);
$matchingUnknownServices = array_values(array_filter(
    $unknownServices,
    static fn(string $identifier): bool => $serviceQuery === ''
        || stripos($identifier, $serviceQuery) !== false,
));
$serviceGroups = [];

if ($serviceGroup !== 'repair') {
    foreach ($registryView['services'] as $service) {
        $serviceGroupName = ServicePresentation::groupName($service['group']);
        $serviceGroups[$serviceGroupName][] = ServicePresentation::service($service);
    }
}

if (($serviceGroup === '' || $serviceGroup === 'repair') && $matchingUnknownServices !== []) {
    foreach ($matchingUnknownServices as $identifier) {
        $serviceGroups[pfsensePackageSinkholeTranslate('needs_repair')][] =
            ServicePresentation::service([
                'id' => $identifier,
                'name' => $identifier,
                'group' => 'repair',
                'icon_svg' => '',
                'unknown' => true,
            ]);
    }
}

$groupCounts = $registryView['group_counts'];
$groupCounts['repair'] = count($matchingUnknownServices);
$groupCounts[''] = ($groupCounts[''] ?? 0) + count($matchingUnknownServices);
$registryFetchedAt = is_int($registryLoad['status']['fetched_at'])
    ? gmdate('Y-m-d H:i:s \U\T\C', $registryLoad['status']['fetched_at'])
    : pfsensePackageSinkholeTranslate('never');
$registryLastError = $registryLoad['status']['last_error'] === ''
    ? pfsensePackageSinkholeTranslate('none')
    : $registryLoad['status']['last_error'];
$stateParameters = [
    'service_scope' => $selectedScope,
    'service_query' => $serviceQuery,
    'service_group' => $serviceGroup,
];
$pgtitle = [gettext('Firewall'), 'Sinkhole', pfsensePackageSinkholeTranslate('services')];
$pglinks = ['', '/pkg_edit.php?xml=sinkhole.xml&id=0', '@self'];

include('head.inc');
?>
<link rel="stylesheet" href="/css/sinkhole.css">
<?php

display_top_tabs(pfsensePackageSinkholeTabs('services'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}
?>
<?php
$serviceSearchButton = new Form_Button(
    'search_services',
    pfsensePackageSinkholeTranslate('search'),
    null,
    'fa-solid fa-search',
);
$serviceSearchButton->addClass('btn-primary', 'btn-sm');
$serviceRefreshButton = new Form_Button(
    'refresh_services',
    pfsensePackageSinkholeTranslate('refresh'),
    null,
    'fa-solid fa-arrows-rotate',
);
$serviceRefreshButton->addClass('btn-info', 'btn-sm');
$serviceRefreshButton->setAttribute('form', 'sinkhole-services-refresh-form');
$serviceFilterForm = new Form(false);
$serviceFilterForm->setMethod('get');
$serviceFilterForm->setAction('sinkhole-services.php');
$serviceFilterSection = new Form_Section(
    pfsensePackageSinkholeTranslate('blocked_services'),
);
$serviceFilterGroup = new Form_Group(pfsensePackageSinkholeTranslate('search'));
$serviceScopeInput = new Form_Select(
    'service_scope',
    null,
    $selectedScope,
    $scopeOptions,
);
$serviceScopeInput->setWidth(4);
$serviceScopeInput->setHelp(pfsensePackageSinkholeTranslate('scope'));
$serviceQueryInput = new Form_Input('service_query', null, 'text', $serviceQuery);
$serviceQueryInput->setAttribute('maxlength', ServiceRegistry::MAXIMUM_SEARCH_BYTES);
$serviceQueryInput->setWidth(3);
$serviceQueryInput->setHelp(pfsensePackageSinkholeTranslate('search'));
$serviceButtonInput = new Form_StaticText(
    '',
    (string) $serviceSearchButton . ' ' . (string) $serviceRefreshButton,
);
$serviceButtonInput->setWidth(3);
$serviceFilterGroup->add($serviceScopeInput);
$serviceFilterGroup->add($serviceQueryInput);
$serviceFilterGroup->add($serviceButtonInput);
$serviceFilterGroup->setHelp(pfsensePackageSinkholeTranslate('blocked_services_help'));
$serviceFilterSection->add($serviceFilterGroup);
$serviceGroupLinks = '<div class="sinkhole-service-chips">';
$allGroupUrl = 'sinkhole-services.php?' . http_build_query(array_merge($stateParameters, ['service_group' => '']));
$serviceGroupLinks .= sprintf(
    '<a class="btn btn-xs %s" href="%s">%s (%d)</a>',
    ($serviceGroup === '') ? 'btn-primary' : 'btn-default',
    htmlspecialchars($allGroupUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
    htmlspecialchars(pfsensePackageSinkholeTranslate('all')),
    $groupCounts[''] ?? 0,
);

foreach ($registryView['groups'] as $group) {
    $groupUrl = 'sinkhole-services.php?' . http_build_query(array_merge(
        $stateParameters,
        ['service_group' => $group['id']],
    ));
    $serviceGroupLinks .= sprintf(
        '<a class="btn btn-xs %s" href="%s">%s (%d)</a>',
        ($serviceGroup === $group['id']) ? 'btn-primary' : 'btn-default',
        htmlspecialchars($groupUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
        htmlspecialchars(ServicePresentation::groupName($group['id'])),
        $group['count'],
    );
}

if (($groupCounts['repair'] ?? 0) > 0) {
    $repairUrl = 'sinkhole-services.php?' . http_build_query(array_merge(
        $stateParameters,
        ['service_group' => 'repair'],
    ));
    $serviceGroupLinks .= sprintf(
        '<a class="btn btn-xs %s" href="%s">%s (%d)</a>',
        ($serviceGroup === 'repair') ? 'btn-primary' : 'btn-warning',
        htmlspecialchars($repairUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
        htmlspecialchars(pfsensePackageSinkholeTranslate('needs_repair')),
        $groupCounts['repair'],
    );
}
$serviceGroupLinks .= '</div>';
$serviceShowGroup = new Form_Group(pfsensePackageSinkholeTranslate('show'));
$serviceGroupInput = new Form_StaticText('', $serviceGroupLinks);
$serviceGroupInput->setWidth(10);
$serviceShowGroup->add($serviceGroupInput);
$serviceFilterSection->add($serviceShowGroup);
$serviceFilterForm->add($serviceFilterSection);
$serviceFilterForm->addGlobal(new Form_Input(
    'service_group',
    null,
    'hidden',
    $serviceGroup,
));
print($serviceFilterForm);
?>
<form id="sinkhole-services-refresh-form" method="post" action="sinkhole-services.php">
	<input type="hidden" name="service_scope" value="<?=htmlspecialchars($selectedScope, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<input type="hidden" name="service_query" value="<?=htmlspecialchars($serviceQuery, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
	<input type="hidden" name="service_group" value="<?=htmlspecialchars($serviceGroup, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>">
</form>
<?php

$saveServicesButton = new Form_Button(
    'save_services',
    pfsensePackageSinkholeTranslate('save'),
    null,
    'fa-solid fa-save',
);
$saveServicesButton->addClass('btn-primary', 'btn-sm');
$serviceSelectionForm = new Form($saveServicesButton);
$serviceSelectionForm->setAction('sinkhole-services.php');
$serviceSelectionForm->addGlobal(new Form_Input(
    'service_scope',
    null,
    'hidden',
    $selectedScope,
));
$serviceSelectionForm->addGlobal(new Form_Input(
    'service_query',
    null,
    'hidden',
    $serviceQuery,
));
$serviceSelectionForm->addGlobal(new Form_Input(
    'service_group',
    null,
    'hidden',
    $serviceGroup,
));

if ($serviceGroups === []) {
    $emptyServicesSection = new Form_Section(
        pfsensePackageSinkholeTranslate('services'),
    );
    $emptyServicesSection->addInput(new Form_StaticText(
        '',
        '<span class="help-block">'
            . htmlspecialchars(pfsensePackageSinkholeTranslate('no_services_found'))
            . '</span>',
    ));
    $serviceSelectionForm->add($emptyServicesSection);
} else {
    foreach ($serviceGroups as $groupName => $services) {
        $serviceGrid = '<div class="sinkhole-service-grid">';

        foreach ($services as $service) {
            $serviceIdentifier = html_entity_decode(
                $service['id'],
                ENT_QUOTES | ENT_SUBSTITUTE,
                'UTF-8',
            );
            $serviceGrid .= '<input type="hidden" name="visible_services[]" value="'
                . $service['id']
                . '">';
            $serviceGrid .= '<div class="sinkhole-service-tile">'
                . '<img class="sinkhole-service-icon" src="'
                . $service['icon']
                . '" alt="">'
                . '<label class="chkboxlbl sinkhole-service-choice">'
                . '<input type="checkbox" name="service_ids[]" value="'
                . $service['id']
                . '"'
                . (in_array($serviceIdentifier, $selectedServices, true) ? ' checked' : '')
                . '> <strong>'
                . $service['name']
                . '</strong>';

            if ($service['unknown']) {
                $serviceGrid .= '<span class="text-warning sinkhole-service-repair">'
                    . htmlspecialchars(pfsensePackageSinkholeTranslate('unknown_service_help'))
                    . '</span>';
            }
            $serviceGrid .= '</label></div>';
        }
        $serviceGrid .= '</div>';
        $serviceSection = new Form_Section(sprintf(
            '%s (%d)',
            $groupName,
            count($services),
        ));
        $serviceSection->addInput(new Form_StaticText('', $serviceGrid));
        $serviceSelectionForm->add($serviceSection);
    }
}
print($serviceSelectionForm);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('service_registry_status'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<tbody>
				<tr><th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_fetch'))?></th><td><?=htmlspecialchars($registryFetchedAt, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?></td></tr>
				<tr><th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_error'))?></th><td><?=htmlspecialchars($registryLastError, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?></td></tr>
			</tbody>
		</table>
	</div>
</div>
<?php include('foot.inc');
