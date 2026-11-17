<?php

declare(strict_types=1);

/*
 * Sinkhole status and manual-update page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-status
##|*NAME=Firewall: Sinkhole: Status
##|*DESCR=Allow access to Sinkhole status and manual list updates.
##|*MATCH=sinkhole-status.php*
##|-PRIV

use PfSense\Sinkhole\Domain\SafeSearchConfiguration;
use PfSense\Sinkhole\Domain\Settings;
use PfSense\Sinkhole\Domain\ServiceConfiguration;
use PfSense\Sinkhole\Runtime\CatalogCache;
use PfSense\Sinkhole\Runtime\BypassListStore;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\ClientMap;
use PfSense\Sinkhole\Runtime\CurlDownloadClient;
use PfSense\Sinkhole\Runtime\FileSystem;
use PfSense\Sinkhole\Runtime\IpListStore;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\SavedListStore;
use PfSense\Sinkhole\Runtime\StateStore;
use PfSense\Sinkhole\Runtime\ServiceRegistryCache;
use PfSense\Sinkhole\Runtime\UpdateLog;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/CatalogCache.php');
require_once('/usr/local/pkg/sinkhole/BypassListStore.php');
require_once('/usr/local/pkg/sinkhole/CurlDownloadClient.php');
require_once('/usr/local/pkg/sinkhole/FileSystem.php');
require_once('/usr/local/pkg/sinkhole/IpListStore.php');
require_once('/usr/local/pkg/sinkhole/ClientMap.php');
require_once('/usr/local/pkg/sinkhole/PackagePaths.php');
require_once('/usr/local/pkg/sinkhole/SavedListStore.php');
require_once('/usr/local/pkg/sinkhole/Settings.php');
require_once('/usr/local/pkg/sinkhole/ServiceConfiguration.php');
require_once('/usr/local/pkg/sinkhole/ServiceRegistryCache.php');
require_once('/usr/local/pkg/sinkhole/StateStore.php');
require_once('/usr/local/pkg/sinkhole/UpdateLog.php');

$paths = new PackagePaths();

// The Update Log poller: read-only JSON behind the same Status privilege as the page.
if (isset($_GET['update_log'])) {
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');

    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
        $updateLogResponse = pfsensePackageSinkholeUpdateLogResponse($paths, $_GET);
    } else {
        header('Allow: GET');
        $updateLogResponse = [
            'status' => 405,
            'body' => ['error' => 'Only GET is allowed.'],
        ];
    }

    http_response_code($updateLogResponse['status']);
    echo json_encode(
        $updateLogResponse['body'],
        JSON_HEX_TAG
            | JSON_HEX_AMP
            | JSON_HEX_APOS
            | JSON_HEX_QUOT
            | JSON_INVALID_UTF8_SUBSTITUTE
            | JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE,
    );
    exit;
}

$actionMessage = null;
$actionClass = 'info';
$updateStarted = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_now'])) {
    try {
        pfsensePackageSinkholeAdapter()->runUpdaterInBackground();
        $actionMessage = pfsensePackageSinkholeTranslate('update_started');
        $actionClass = 'success';
        $updateStarted = true;
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }
}

$store = new SavedListStore($paths);
$bypassStore = new BypassListStore($paths);
$ipStore = new IpListStore($paths);
$catalogStatuses = (new CatalogCache($paths, new CurlDownloadClient()))->status();
$serviceRegistryStatus = (new ServiceRegistryCache($paths, new CurlDownloadClient()))->status();
$lists = [];
$invalidRows = [];
$configurationError = null;
$totalEntries = 0;
$compiledNames = null;
$lastCompile = '';
$compiledGeneration = '';
$compiledDigest = '';
$deployedGeneration = '';
$deployedDigest = '';
$loadedGeneration = '';
$compileNeeded = true;
$compileError = '';
$deploymentNeeded = true;
$deploymentReason = pfsensePackageSinkholeTranslate('runtime_generation_missing');
$sinkholeEnabled = false;
$updateRunning = false;
$removing = false;
$scopeNetworks = [];
$scopeDevices = [];
$blockedServiceCounts = ['global' => 0, 'networks' => [], 'devices' => []];
$safeSearchCounts = ['global' => 0, 'networks' => [], 'devices' => []];
$safeSearchHosts = [];
$safeSearchTargets = [];
$clientNetworkCidrs = [];
$clientDeviceAddresses = [];
$clientConflicts = [];
$clientMapRefreshedAt = '';
$clientMapError = '';
$interfaceLabels = [];
$alertLastRun = '';
$alertEventsRead = 0;
$alertEventsStale = 0;
$alertNotificationsSent = 0;
$alertNotificationsHeldBack = 0;
$alertEventsDropped = 0;
$alertLastError = '';
$redirectEnabled = false;
$redirectPaused = false;
$redirectInactiveReason = null;
$redirectInterfaces = [];
$redirectInvalidExemptions = [];
$redirectTargets = [];
$redirectRuleStatus = [
    'loaded' => false,
    'comment_present' => false,
    'out_of_date' => false,
    'parse_error' => '',
];
$bypassConfiguration = [
    'block_tls_quic' => false,
    'block_encrypted_dns' => false,
    'disable_firefox_doh' => false,
    'disable_private_relay' => false,
    'discovery' => 'off',
    'discovery_zone_present' => false,
    'block_tor' => false,
    'block_vpn' => false,
    'block_vpn_ports' => false,
    'lists' => [],
];
$bypassRows = [];
$bypassWarnings = [];
$bypassRuleStatus = [
    'loaded' => false,
    'anchor_loaded' => false,
    'out_of_date' => false,
    'rule_count' => 0,
    'ipv4_entries' => 0,
    'ipv6_entries' => 0,
];
$ipConfiguration = [
    'enabled' => false,
    'interfaces' => [],
    'directions' => [],
    'lists' => [],
    'countries' => [],
    'license_key_set' => false,
    'invalid_values' => [],
    'invalid_lists' => [],
];
$ipStatus = [];
$ipRows = [];
$ipRuleStatus = [
    'loaded' => false,
    'anchor_loaded' => false,
    'out_of_date' => false,
    'rule_count' => 0,
    'ipv4_entries' => 0,
    'ipv6_entries' => 0,
];

try {
    $listConfiguration = pfsensePackageSinkholeGetListConfiguration();
    $lists = $listConfiguration['lists'];
    $invalidRows = $listConfiguration['invalid_rows'];
    $scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
    $scopeNetworks = $scopeConfiguration['networks'];
    $scopeDevices = $scopeConfiguration['devices'];
    $blockedServiceCounts = ServiceConfiguration::counts(
        pfsensePackageSinkholeGetBlockedServices(),
    );
    $safeSearchCounts = SafeSearchConfiguration::counts(
        pfsensePackageSinkholeGetSafeSearch(),
    );
    $safeSearchHosts = pfsensePackageSinkholeAdapter()->safeSearchHostsInUse();
    $safeSearchTargets = pfsensePackageSinkholeAdapter()->safeSearchTargets();
    $interfaceLabels = pfsensePackageSinkholeAdapter()->getConfiguredInterfaces();
    $redirectConfiguration = pfsensePackageSinkholeGetRedirectConfiguration();
    $redirectEnabled = $redirectConfiguration['enabled'];
    $redirectPaused = count($redirectConfiguration['invalid_exemptions']) > 0;
    $redirectInvalidExemptions = $redirectConfiguration['invalid_exemptions'];
    $bypassConfiguration = pfsensePackageSinkholeGetBypassConfiguration();

    $invalidBypassValues = array_merge(
        $bypassConfiguration['invalid_values'] ?? [],
        $bypassConfiguration['invalid_exemptions'] ?? [],
    );

    foreach ($invalidBypassValues as $invalidBypassValue) {
        if (is_array($invalidBypassValue)) {
            $bypassWarnings[] = pfsensePackageSinkholeInvalidReason($invalidBypassValue);
        }
    }

    if (
        ($bypassConfiguration['discovery'] ?? '') === 'advertise'
        && ($bypassConfiguration['discovery_tls']['enabled'] ?? false) !== true
    ) {
        $tlsReason = is_string($bypassConfiguration['discovery_tls']['reason'] ?? null)
            ? $bypassConfiguration['discovery_tls']['reason']
            : '';
        $bypassWarnings[] = pfsensePackageSinkholeTranslate(
            'bypass_discovery_tls_required',
            [$tlsReason],
        );
    }

    $ipConfiguration = pfsensePackageSinkholeGetIpConfiguration();
    $ipStatus = pfsensePackageSinkholeAdapter()->ipStatus();

    foreach ($redirectConfiguration['interfaces'] as $redirectInterface) {
        $redirectInterfaces[] = $interfaceLabels[$redirectInterface] ?? $redirectInterface;
    }

    foreach (
        pfsensePackageSinkholeAdapter()->getRedirectInterfaceDetails(
            $redirectConfiguration['interfaces'],
        ) as $redirectInterfaceDetail
    ) {
        $interfaceLabel = $interfaceLabels[$redirectInterfaceDetail['interface']]
            ?? $redirectInterfaceDetail['interface'];

        foreach (['ipv4', 'ipv6'] as $familyKey) {
            $target = $redirectInterfaceDetail[$familyKey . '_target'];
            $reason = $redirectInterfaceDetail[$familyKey . '_reason'];

            if ($target === '' && $reason === 'no_address') {
                $target = pfsensePackageSinkholeTranslate('redirect_no_family_address');
            } elseif ($target === '') {
                $target = pfsensePackageSinkholeTranslate('redirect_resolver_not_listening');
            }

            $redirectTargets[] = [
                'interface' => $interfaceLabel,
                'family' => pfsensePackageSinkholeTranslateMapped('ip_family', $familyKey),
                'target' => $target,
            ];
        }
    }
} catch (Throwable $throwable) {
    $configurationError = pfsensePackageSinkholeThrowableMessage($throwable);
}

try {
    $redirectRuleStatus = pfsensePackageSinkholeRedirectStatus();
    $bypassRuleStatus = pfsensePackageSinkholeBypassRuleStatus();
    $ipRuleStatus = pfsensePackageSinkholeIpRuleStatus();
} catch (Throwable $throwable) {
    $configurationError = $configurationError
        ?? pfsensePackageSinkholeThrowableMessage($throwable);
}

try {
    $redirectInactiveReason = pfsensePackageSinkholeAdapter()->redirectInactiveReason();
} catch (Throwable $throwable) {
    $configurationError = $configurationError
        ?? pfsensePackageSinkholeThrowableMessage($throwable);
}

foreach ($ipConfiguration['lists'] as $identifier => $list) {
    $metadata = [];

    try {
        $metadata = $ipStore->metadata($identifier);
    } catch (Throwable $throwable) {
        $metadata['last_error'] = pfsensePackageSinkholeThrowableMessage($throwable);
    }

    $ipRows[] = [
        'name' => $list['name'],
        'family' => $list['family'],
        'enabled' => $list['enabled'],
        'entries' => is_int($metadata['entries'] ?? null) ? $metadata['entries'] : 0,
        'skipped' => is_int($metadata['skipped'] ?? null) ? $metadata['skipped'] : 0,
        'fetched_at' => is_string($metadata['fetched_at'] ?? null) ? $metadata['fetched_at'] : '',
        'last_error' => is_string($metadata['last_error'] ?? null) ? $metadata['last_error'] : '',
    ];
}

foreach ($bypassConfiguration['lists'] as $identifier => $list) {
    $metadata = [];

    try {
        $metadata = $bypassStore->metadata($identifier);
    } catch (Throwable $throwable) {
        $metadata['last_error'] = pfsensePackageSinkholeThrowableMessage($throwable);
    }

    $bypassRows[] = [
        'name' => $list['name'],
        'kind' => $list['kind'],
        'enabled' => $list['enabled'],
        'entries' => is_int($metadata['entries'] ?? null) ? $metadata['entries'] : 0,
        'fetched_at' => is_string($metadata['fetched_at'] ?? null) ? $metadata['fetched_at'] : '',
        'last_error' => is_string($metadata['last_error'] ?? null) ? $metadata['last_error'] : '',
    ];
}

$rows = [];

foreach ($lists as $identifier => $list) {
    $metadata = [];
    $metadataError = null;

    try {
        $metadata = $store->metadata($identifier);
    } catch (Throwable $throwable) {
        $metadataError = pfsensePackageSinkholeThrowableMessage($throwable);
    }

    $entries = is_int($metadata['entries'] ?? null) ? $metadata['entries'] : 0;
    $totalEntries += $entries;
    $rows[] = [
        'name' => $list['name'],
        'url' => $list['url'],
        'enabled' => $list['enabled'],
        'entries' => $entries,
        'fetched_at' => is_string($metadata['fetched_at'] ?? null) ? $metadata['fetched_at'] : '',
        'last_error' => $metadataError ?? (
            is_string($metadata['last_error'] ?? null) ? $metadata['last_error'] : ''
        ),
    ];
}

$generationPath = FileSystem::resolveManagedGeneration(
    $paths->runtimeDataDirectory,
    $paths->runtimeStorageDirectory,
);
$manifestPath = ($generationPath === null) ? '' : $generationPath . '/manifest.json';

if ($manifestPath !== '' && FileSystem::isRegularFile($manifestPath)) {
    try {
        $manifestContents = file_get_contents($manifestPath);

        if ($manifestContents !== false) {
            $manifest = json_decode($manifestContents, true, 16, JSON_THROW_ON_ERROR);

            if (is_array($manifest) && is_string($manifest['generated_at'] ?? null)) {
                $lastCompile = $manifest['generated_at'];
            }

            if (is_array($manifest) && is_string($manifest['generation'] ?? null)) {
                $deployedGeneration = $manifest['generation'];
            }

            if (is_array($manifest) && is_string($manifest['content_digest'] ?? null)) {
                $deployedDigest = $manifest['content_digest'];
            }

            if (
                is_array($manifest)
                && is_int($manifest['domain_count'] ?? null)
                && is_int($manifest['bypass_domain_count'] ?? null)
            ) {
                $compiledNames = $manifest['domain_count'] + $manifest['bypass_domain_count'];
            }
        }
    } catch (Throwable $throwable) {
        $configurationError = $configurationError
            ?? pfsensePackageSinkholeThrowableMessage($throwable);
    }
}

try {
    $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
    $compileStatus = $stateStore->compileStatus();
    $compileNeeded = $compileStatus['needed'];
    $compileError = is_string($compileStatus['error']) ? $compileStatus['error'] : '';
    $compiledGeneration = is_string($compileStatus['generation'])
        ? $compileStatus['generation']
        : '';
    $compiledDigest = is_string($compileStatus['digest'])
        ? $compileStatus['digest']
        : '';
    $removing = $stateStore->removing();
    $clientMapStatus = $stateStore->clientMapStatus();
    $clientMapRefreshedAt = is_string($clientMapStatus['refreshed_at'])
        ? $clientMapStatus['refreshed_at']
        : '';
    $clientMapError = is_string($clientMapStatus['error']) ? $clientMapStatus['error'] : '';
    $bypassStatus = $stateStore->bypassStatus();

    foreach (['configuration_warning', 'update_warning'] as $warningKey) {
        if (is_string($bypassStatus[$warningKey] ?? null)) {
            $bypassWarnings[] = $bypassStatus[$warningKey];
        }
    }

    $alertStatus = $stateStore->alertStatus();
    $alertLastRun = is_string($alertStatus['last_run']) ? $alertStatus['last_run'] : '';
    $alertEventsRead = $alertStatus['events_read'];
    $alertEventsStale = $alertStatus['events_stale'];
    $alertNotificationsSent = $alertStatus['notifications_sent'];
    $alertNotificationsHeldBack = $alertStatus['notifications_held_back'];
    $alertEventsDropped = $alertStatus['events_dropped'];
    $alertLastError = is_string($alertStatus['last_error']) ? $alertStatus['last_error'] : '';
} catch (Throwable $throwable) {
    $configurationError = $configurationError
        ?? pfsensePackageSinkholeThrowableMessage($throwable);
}

$clientMapStatus = @lstat($paths->runtimeClientMapFile);

if (
    is_array($clientMapStatus)
    && ($clientMapStatus['mode'] & 0170000) === 0100000
    && $clientMapStatus['size'] <= ClientMap::MAXIMUM_BYTES
) {
    try {
        $clientMapContents = file_get_contents($paths->runtimeClientMapFile);
        $clientMap = is_string($clientMapContents)
            ? json_decode($clientMapContents, true, 32, JSON_THROW_ON_ERROR)
            : null;

        if (is_array($clientMap)) {
            foreach (is_array($clientMap['networks'] ?? null) ? $clientMap['networks'] : [] as $network) {
                if (is_array($network) && is_string($network['id'] ?? null)) {
                    $clientNetworkCidrs[$network['id']] = array_values(array_filter(
                        is_array($network['cidrs'] ?? null) ? $network['cidrs'] : [],
                        'is_string',
                    ));
                }
            }

            foreach (is_array($clientMap['devices'] ?? null) ? $clientMap['devices'] : [] as $address => $deviceIdentifier) {
                if (is_string($address) && is_string($deviceIdentifier)) {
                    $clientDeviceAddresses[$deviceIdentifier][] = $address;
                }
            }

            foreach (is_array($clientMap['conflicts'] ?? null) ? $clientMap['conflicts'] : [] as $conflict) {
                if (!is_array($conflict) || !is_string($conflict['address'] ?? null)) {
                    continue;
                }

                foreach (is_array($conflict['devices'] ?? null) ? $conflict['devices'] : [] as $deviceIdentifier) {
                    if (is_string($deviceIdentifier)) {
                        $clientDeviceAddresses[$deviceIdentifier][] = $conflict['address'];
                        $clientConflicts[$deviceIdentifier][] = $conflict['address'];
                    }
                }
            }
        }
    } catch (Throwable $throwable) {
        $clientMapError = $clientMapError !== ''
            ? $clientMapError
            : pfsensePackageSinkholeThrowableMessage($throwable);
    }
}

foreach ($clientDeviceAddresses as &$deviceAddresses) {
    $deviceAddresses = array_values(array_unique($deviceAddresses));
    sort($deviceAddresses, SORT_STRING);
}
unset($deviceAddresses);

foreach ($clientConflicts as &$deviceConflicts) {
    $deviceConflicts = array_values(array_unique($deviceConflicts));
    sort($deviceConflicts, SORT_STRING);
}
unset($deviceConflicts);

if (FileSystem::isRegularFile($paths->loadedGenerationFile)) {
    $loadedContents = file_get_contents($paths->loadedGenerationFile);

    if (is_string($loadedContents)) {
        $loadedGeneration = trim($loadedContents);
    }
}

if ($generationPath === null) {
    $deploymentReason = pfsensePackageSinkholeTranslate('runtime_generation_missing');
} elseif ($compiledDigest === '') {
    $deploymentReason = pfsensePackageSinkholeTranslate('compiled_digest_missing');
} elseif ($deployedDigest === '') {
    $deploymentReason = pfsensePackageSinkholeTranslate('runtime_digest_missing');
} elseif ($compiledDigest !== $deployedDigest) {
    $deploymentReason = pfsensePackageSinkholeTranslate('deployed_digest_mismatch');
} else {
    $deploymentNeeded = false;
    $deploymentReason = '';
}

$updateRunning = pfsensePackageSinkholeUpdateRunning($paths);
$updateLogState = UpdateLog::read($paths->updateLogFile, 0, null, UpdateLog::MAXIMUM_BYTES);
$dnsIntegrationWanted = false;

try {
    $settings = Settings::fromStorage(pfsensePackageSinkholeGetSettings());
    $sinkholeEnabled = $settings['enabled'];
    $dnsIntegrationWanted = pfsensePackageSinkholeAdapter()->dnsIntegrationWanted();
    $resolverStatus = pfsensePackageSinkholeAdapter()->dnsResolverStatus($dnsIntegrationWanted);
} catch (Throwable $throwable) {
    $resolverStatus = [
        'active' => false,
        'owner' => '',
        'reason' => pfsensePackageSinkholeThrowableMessage($throwable),
    ];
}

$owner = ($resolverStatus['owner'] === '')
    ? pfsensePackageSinkholeTranslate('none')
    : $resolverStatus['owner'];
$statusPresentation = pfsensePackageSinkholeStatusPresentation(
    $resolverStatus,
    $dnsIntegrationWanted,
    $deploymentNeeded,
    $deploymentReason,
    $loadedGeneration,
);
$statusText = $statusPresentation['status_text'];
$deploymentNeeded = $statusPresentation['deployment_needed'];
$deploymentReason = $statusPresentation['deployment_reason'];
$loadedGeneration = $statusPresentation['loaded_generation'];

$pgtitle = [
    gettext('Firewall'),
    'Sinkhole',
    pfsensePackageSinkholeTranslate('status'),
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

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

if (is_string($configurationError)) {
    print_info_box(htmlspecialchars($configurationError), 'danger', false);
}

display_top_tabs(pfsensePackageSinkholeTabs('status'));

if ($dnsIntegrationWanted && $compileError !== '') {
    print_info_box(htmlspecialchars(pfsensePackageSinkholeTranslate(
        'compile_pending',
        [$compileError],
    )), 'warning', false);
}

if ($deploymentNeeded) {
    print_info_box(htmlspecialchars(pfsensePackageSinkholeTranslate(
        'deployment_pending',
        [$deploymentReason],
    )), 'warning', false);
}

if (is_string($redirectInactiveReason)) {
    print_info_box(htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
        'redirect_inactive_reason',
        $redirectInactiveReason,
    )), 'danger', false);
}

$updateButton = new Form_Button(
    'update_now',
    pfsensePackageSinkholeTranslate('update_now'),
    null,
    'fa-solid fa-arrows-rotate',
);
$updateButton->addClass('btn-success', 'btn-sm');
$summaryForm = new Form(false);
$summaryForm->addGlobal($updateButton);
$summarySection = new Form_Section(pfsensePackageSinkholeTranslate('summary'));
$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('configured_lists'),
    htmlspecialchars((string) count($rows)),
));
$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('total_entries'),
    htmlspecialchars((string) $totalEntries),
));
$compiledNamesText = ($compiledNames === null)
    ? pfsensePackageSinkholeTranslate('none')
    : pfsensePackageSinkholeTranslate(
        'compiled_names_value',
        [
            number_format($compiledNames),
            number_format(Compiler::MAXIMUM_UNIQUE_NAMES),
        ],
    );
$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('compiled_names'),
    htmlspecialchars($compiledNamesText),
));
$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('last_compile'),
    htmlspecialchars(($lastCompile === '') ? pfsensePackageSinkholeTranslate('never') : $lastCompile),
));
$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('compile_needed'),
    '<span id="sinkhole-compile-needed">'
        . htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
            'boolean',
            ($compileNeeded) ? 'true' : 'false',
        ))
        . '</span>',
));
$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('compiled_generation'),
    '<span id="sinkhole-compiled-generation">'
        . htmlspecialchars(($compiledGeneration === '') ? pfsensePackageSinkholeTranslate('none') : $compiledGeneration)
        . '</span>',
));
$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('deployment_needed'),
    '<span id="sinkhole-deployment-needed">'
        . htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
            'boolean',
            ($deploymentNeeded) ? 'true' : 'false',
        ))
        . '</span>',
));
$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('deployed_generation'),
    '<span id="sinkhole-deployed-generation">'
        . htmlspecialchars(($deployedGeneration === '') ? pfsensePackageSinkholeTranslate('none') : $deployedGeneration)
        . '</span>',
));
$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('loaded_generation'),
    '<span id="sinkhole-loaded-generation">' . htmlspecialchars($loadedGeneration) . '</span>',
));

// The row stays in the markup while hidden, so the Update Log poller can show it mid-run.
$updateRunningGroup = new Form_Group(pfsensePackageSinkholeTranslate('update_running'));
$updateRunningGroup->add(new Form_StaticText(
    pfsensePackageSinkholeTranslate('update_running'),
    '<span id="sinkhole-update-running">'
        . htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', 'true'))
        . '</span>',
));
$updateRunningGroup->setAttribute('id', 'sinkhole-update-running-row');

if (!$updateRunning) {
    $updateRunningGroup->addClass('hidden');
}

$summarySection->add($updateRunningGroup);

if ($removing) {
    $summarySection->addInput(new Form_StaticText(
        pfsensePackageSinkholeTranslate('removal_in_progress'),
        htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', 'true')),
    ));
}

$summarySection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('dns_resolver_python_script_owner'),
    htmlspecialchars($owner),
));
$summarySection->addInput(new Form_StaticText('Sinkhole', htmlspecialchars($statusText)));
$summaryForm->add($summarySection);
print($summaryForm);

$updateLogTitle = pfsensePackageSinkholeTranslate('update_log');
?>
<div class="panel panel-default" id="sinkhole-update-log" data-run="<?=htmlspecialchars($updateLogState['run'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>" data-offset="<?=htmlspecialchars((string) $updateLogState['offset'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>" data-running="<?=($updateRunning) ? '1' : '0'?>" data-started="<?=($updateStarted) ? '1' : '0'?>">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars($updateLogTitle, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?></h2></div>
	<div class="panel-body">
		<div class="form-group sinkhole-update-log-row">
			<textarea id="sinkhole-update-log-text" class="form-control sinkhole-update-log" rows="15" readonly="readonly" spellcheck="false" wrap="off" aria-label="<?=htmlspecialchars($updateLogTitle, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>" placeholder="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('update_log_empty'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?>"><?=htmlspecialchars($updateLogState['text'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')?></textarea>
		</div>
	</div>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('lists'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
				<thead>
					<tr>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('url'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('entries'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_successful_update'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_error'))?></th>
					</tr>
				</thead>
				<tbody>
<?php if ($rows === []): ?>
					<tr><td colspan="5" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_block_lists_configured'))?></td></tr>
<?php else: ?>
<?php foreach ($rows as $row): ?>
					<tr<?=($row['enabled']) ? '' : ' class="disabled"'?>>
						<td><?=htmlspecialchars($row['name'])?></td>
						<td><?=htmlspecialchars($row['url'])?></td>
						<td><?=htmlspecialchars((string) $row['entries'])?></td>
						<td><?=htmlspecialchars(($row['fetched_at'] === '') ? pfsensePackageSinkholeTranslate('never') : $row['fetched_at'])?></td>
						<td><?=htmlspecialchars($row['last_error'])?></td>
					</tr>
<?php endforeach; ?>
<?php endif; ?>
				</tbody>
		</table>
	</div>
</div>
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
<?php
$servicesForm = new Form(false);
$servicesSection = new Form_Section(pfsensePackageSinkholeTranslate('services'));
$servicesSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('last_fetch'),
    htmlspecialchars(is_int($serviceRegistryStatus['fetched_at'])
        ? gmdate('Y-m-d H:i:s \U\T\C', $serviceRegistryStatus['fetched_at'])
        : pfsensePackageSinkholeTranslate('never')),
));
$servicesSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('last_error'),
    htmlspecialchars($serviceRegistryStatus['last_error'] === ''
        ? pfsensePackageSinkholeTranslate('none')
        : $serviceRegistryStatus['last_error']),
));
$servicesForm->add($servicesSection);
print($servicesForm);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('blocked_services'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('scope'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('blocked_services'))?></th>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslate('global'))?></td>
					<td><?=htmlspecialchars((string) $blockedServiceCounts['global'])?></td>
				</tr>
<?php foreach ($scopeNetworks as $identifier => $network): ?>
				<tr>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslate('service_network_scope', [$interfaceLabels[$network['interface']] ?? $network['interface']]))?></td>
					<td><?=htmlspecialchars((string) ($blockedServiceCounts['networks'][$identifier] ?? 0))?></td>
				</tr>
<?php endforeach; ?>
<?php foreach ($scopeDevices as $identifier => $device): ?>
				<tr>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslate('service_device_scope', [$device['name']]))?></td>
					<td><?=htmlspecialchars((string) ($blockedServiceCounts['devices'][$identifier] ?? 0))?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('scope'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_engines'))?></th>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslate('global'))?></td>
					<td><?=htmlspecialchars((string) $safeSearchCounts['global'])?></td>
				</tr>
<?php foreach ($scopeNetworks as $identifier => $network): ?>
				<tr>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslate('service_network_scope', [$interfaceLabels[$network['interface']] ?? $network['interface']]))?></td>
					<td><?=htmlspecialchars((string) ($safeSearchCounts['networks'][$identifier] ?? 0))?></td>
				</tr>
<?php endforeach; ?>
<?php foreach ($scopeDevices as $identifier => $device): ?>
				<tr>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslate('service_device_scope', [$device['name']]))?></td>
					<td><?=htmlspecialchars((string) ($safeSearchCounts['devices'][$identifier] ?? 0))?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
		<table class="table table-striped table-hover table-condensed">
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_safe_host'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('ipv4'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('ipv6'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_checked'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_error'))?></th>
				</tr>
			</thead>
			<tbody>
<?php if ($safeSearchHosts === []): ?>
				<tr><td colspan="5"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_not_in_use'))?></td></tr>
<?php endif; ?>
<?php foreach ($safeSearchHosts as $safeSearchHost): ?>
<?php $safeSearchRecord = $safeSearchTargets[$safeSearchHost] ?? null; ?>
				<tr>
					<td><?=htmlspecialchars($safeSearchHost)?></td>
					<td><?=htmlspecialchars(($safeSearchRecord['ipv4'] ?? []) === [] ? pfsensePackageSinkholeTranslate('none') : implode(', ', $safeSearchRecord['ipv4']))?></td>
					<td><?=htmlspecialchars(($safeSearchRecord['ipv6'] ?? []) === [] ? pfsensePackageSinkholeTranslate('none') : implode(', ', $safeSearchRecord['ipv6']))?></td>
					<td><?=htmlspecialchars(is_int($safeSearchRecord['checked_at'] ?? null) ? gmdate('Y-m-d H:i:s \U\T\C', $safeSearchRecord['checked_at']) : pfsensePackageSinkholeTranslate('safesearch_not_looked_up'))?></td>
					<td><?=htmlspecialchars(($safeSearchRecord['last_error'] ?? '') === '' ? pfsensePackageSinkholeTranslate('none') : $safeSearchRecord['last_error'])?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
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
					</tr>
				</thead>
				<tbody>
<?php foreach ($invalidRows as $invalidRow): ?>
					<tr>
						<td><?=htmlspecialchars($invalidRow['name'])?></td>
						<td><?=htmlspecialchars($invalidRow['url'])?></td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeInvalidReason($invalidRow))?></td>
					</tr>
<?php endforeach; ?>
				</tbody>
			</table>
	</div>
</div>
<?php endif; ?>
<?php
$scopesForm = new Form(false);
$scopesSection = new Form_Section(pfsensePackageSinkholeTranslate('scopes'));
$scopesSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('client_map_rebuilt'),
    htmlspecialchars($clientMapRefreshedAt === ''
        ? pfsensePackageSinkholeTranslate('never')
        : $clientMapRefreshedAt),
));
$scopesSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('last_error'),
    htmlspecialchars($clientMapError === ''
        ? pfsensePackageSinkholeTranslate('none')
        : $clientMapError),
));
$scopesForm->add($scopesSection);
print($scopesForm);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('networks'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('interface'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('current_subnets'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
				</tr>
			</thead>
				<tbody>
<?php if ($scopeNetworks === []): ?>
					<tr><td colspan="3" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_networks_configured'))?></td></tr>
<?php endif; ?>
<?php foreach ($scopeNetworks as $identifier => $network): ?>
<?php $cidrs = $clientNetworkCidrs[$identifier] ?? []; ?>
					<tr<?=($network['enabled']) ? '' : ' class="disabled"'?>>
						<td><?=htmlspecialchars($interfaceLabels[$network['interface']] ?? $network['interface'])?></td>
						<td><?=htmlspecialchars($cidrs === [] ? pfsensePackageSinkholeTranslate('none') : implode(', ', $cidrs))?></td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $network['enabled'] ? 'true' : 'false'))?></td>
					</tr>
<?php endforeach; ?>
				</tbody>
		</table>
	</div>
</div>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('devices'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('current_addresses'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('conflict'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
				</tr>
			</thead>
				<tbody>
<?php if ($scopeDevices === []): ?>
					<tr><td colspan="4" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_devices_configured'))?></td></tr>
<?php endif; ?>
<?php foreach ($scopeDevices as $identifier => $device): ?>
<?php
    $addresses = $clientDeviceAddresses[$identifier] ?? [];
    $conflicts = $clientConflicts[$identifier] ?? [];
    $deviceRowClasses = [];

    if ($conflicts !== []) {
        $deviceRowClasses[] = 'warning';
    }

    if (!$device['enabled']) {
        $deviceRowClasses[] = 'disabled';
    }
?>
					<tr<?=($deviceRowClasses === []) ? '' : ' class="' . implode(' ', $deviceRowClasses) . '"'?>>
						<td><?=htmlspecialchars($device['name'])?></td>
						<td><?=htmlspecialchars($addresses === [] ? pfsensePackageSinkholeTranslate('none') : implode(', ', $addresses))?></td>
						<td><?=htmlspecialchars($conflicts === [] ? pfsensePackageSinkholeTranslate('none') : implode(', ', $conflicts))?></td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $device['enabled'] ? 'true' : 'false'))?></td>
					</tr>
<?php endforeach; ?>
				</tbody>
		</table>
	</div>
</div>
<?php
$alertsForm = new Form(false);
$alertsSection = new Form_Section(pfsensePackageSinkholeTranslate('alerts'));
$alertsSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('last_job_run'),
    htmlspecialchars($alertLastRun === '' ? pfsensePackageSinkholeTranslate('never') : $alertLastRun),
));
$alertsSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('events_read'),
    htmlspecialchars((string) $alertEventsRead),
));
$alertsSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('stale_events_discarded'),
    htmlspecialchars((string) $alertEventsStale),
));
$alertsSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('notifications_sent'),
    htmlspecialchars((string) $alertNotificationsSent),
));
$alertsSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('notifications_held_back'),
    htmlspecialchars((string) $alertNotificationsHeldBack),
));
$alertsSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('events_dropped_by_module'),
    htmlspecialchars((string) $alertEventsDropped),
));
$alertsSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('last_error'),
    htmlspecialchars($alertLastError === '' ? pfsensePackageSinkholeTranslate('none') : $alertLastError),
));
$alertsForm->add($alertsSection);
print($alertsForm);
?>
<?php
$discoveryLabel = match ($bypassConfiguration['discovery']) {
    'advertise' => pfsensePackageSinkholeTranslate('discovery_advertise'),
    'nodata' => pfsensePackageSinkholeTranslate('discovery_nodata'),
    default => pfsensePackageSinkholeTranslate('off'),
};
$redirectForm = new Form(false);
$redirectSection = new Form_Section(pfsensePackageSinkholeTranslate('bypass'));
$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('plain_dns_redirect'),
    htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
        'redirect_state',
        ($redirectEnabled) ? (($redirectPaused) ? 'paused' : 'on') : 'off',
    )),
));
$bypassStates = [
    [pfsensePackageSinkholeTranslate('tls_and_quic'), $bypassConfiguration['block_tls_quic']],
    [pfsensePackageSinkholeTranslate('providers'), $bypassConfiguration['block_encrypted_dns']],
    [pfsensePackageSinkholeTranslate('firefox'), $bypassConfiguration['disable_firefox_doh']],
    [pfsensePackageSinkholeTranslate('private_relay'), $bypassConfiguration['disable_private_relay']],
    [pfsensePackageSinkholeTranslate('tor'), $bypassConfiguration['block_tor']],
    [pfsensePackageSinkholeTranslate('vpn_providers'), $bypassConfiguration['block_vpn']],
    [pfsensePackageSinkholeTranslate('vpn_ports'), $bypassConfiguration['block_vpn_ports']],
];

foreach ($bypassStates as [$label, $enabled]) {
    $redirectSection->addInput(new Form_StaticText(
        $label,
        htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
            'redirect_state',
            $enabled ? 'on' : 'off',
        )),
    ));
}

$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('discovery'),
    htmlspecialchars($discoveryLabel),
));

if ($bypassConfiguration['discovery'] !== 'off') {
    $discoveryZoneLabel = ($bypassConfiguration['discovery_zone_present'] ?? false)
        ? pfsensePackageSinkholeTranslate('present')
        : pfsensePackageSinkholeTranslate('missing');
    $redirectSection->addInput(new Form_StaticText(
        pfsensePackageSinkholeTranslate('discovery_zone'),
        htmlspecialchars($discoveryZoneLabel),
    ));
}

$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('bypass_warning'),
    htmlspecialchars(($bypassWarnings === [])
        ? pfsensePackageSinkholeTranslate('none')
        : implode(' ', array_values(array_unique($bypassWarnings)))),
));
$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('interfaces'),
    htmlspecialchars(($redirectInterfaces === [])
        ? pfsensePackageSinkholeTranslate('none')
        : implode(', ', $redirectInterfaces)),
));
$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('pfsense_loaded_rules'),
    htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
        'rule_state',
        ($redirectRuleStatus['out_of_date'] ?? false)
            ? 'out_of_date'
            : (($redirectRuleStatus['loaded']) ? 'loaded' : 'missing'),
    )),
));
$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('firewall_rules_loaded'),
    htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
        'boolean',
        ($bypassRuleStatus['anchor_loaded'] ?? false) ? 'true' : 'false',
    )),
));
$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('firewall_rules_current'),
    htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
        'boolean',
        ($bypassRuleStatus['out_of_date'] ?? false) ? 'false' : 'true',
    )),
));
$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('firewall_rule_count'),
    htmlspecialchars((string) ($bypassRuleStatus['rule_count'] ?? 0)),
));
$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('ipv4_table_entries'),
    htmlspecialchars((string) ($bypassRuleStatus['ipv4_entries'] ?? 0)),
));
$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('ipv6_table_entries'),
    htmlspecialchars((string) ($bypassRuleStatus['ipv6_entries'] ?? 0)),
));
$redirectSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('last_parse_error'),
    htmlspecialchars(($redirectRuleStatus['parse_error'] === '')
        ? pfsensePackageSinkholeTranslate('none')
        : $redirectRuleStatus['parse_error']),
));
$redirectForm->add($redirectSection);
print($redirectForm);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bypass_lists'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('kind'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('entries'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_fetch'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_error'))?></th>
				</tr>
			</thead>
			<tbody>
<?php if ($bypassRows === []): ?>
				<tr><td colspan="6" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_bypass_lists_configured'))?></td></tr>
<?php endif; ?>
<?php foreach ($bypassRows as $bypassRow): ?>
				<tr<?=($bypassRow['enabled']) ? '' : ' class="disabled"'?>>
					<td><?=htmlspecialchars($bypassRow['name'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('bypass_kind', $bypassRow['kind']))?></td>
					<td><?=htmlspecialchars((string) $bypassRow['entries'])?></td>
					<td><?=htmlspecialchars($bypassRow['fetched_at'] === '' ? pfsensePackageSinkholeTranslate('never') : $bypassRow['fetched_at'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $bypassRow['enabled'] ? 'true' : 'false'))?></td>
					<td><?=htmlspecialchars($bypassRow['last_error'])?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php if ($redirectInvalidExemptions !== []): ?>
	<div class="panel panel-danger">
		<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_saved_values'))?></h2></div>
		<div class="panel-body table-responsive">
			<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
				<thead>
					<tr>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_exemption'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('value'))?></th>
						<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('reason'))?></th>
					</tr>
				</thead>
				<tbody>
<?php foreach ($redirectInvalidExemptions as $invalidExemption): ?>
					<tr class="warning">
						<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('field', $invalidExemption['field_key']))?></td>
						<td><?=htmlspecialchars($invalidExemption['value'])?></td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeInvalidReason($invalidExemption))?></td>
					</tr>
<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>
<?php endif; ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('redirect_targets'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('interface'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('family'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('redirect_target'))?></th>
				</tr>
			</thead>
				<tbody>
<?php if ($redirectTargets === []): ?>
					<tr><td colspan="3" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_redirect_interfaces_active'))?></td></tr>
<?php endif; ?>
<?php foreach ($redirectTargets as $redirectTarget): ?>
				<tr>
					<td><?=htmlspecialchars($redirectTarget['interface'])?></td>
					<td><?=htmlspecialchars($redirectTarget['family'])?></td>
					<td><?=htmlspecialchars($redirectTarget['target'])?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php

$ipInterfaceLabels = [];

foreach ($ipConfiguration['interfaces'] as $ipInterface) {
    $ipInterfaceLabels[] = $interfaceLabels[$ipInterface] ?? $ipInterface;
}
$ipDirectionLabels = array_map(
    static fn(string $direction): string => pfsensePackageSinkholeTranslateMapped(
        'direction',
        $direction,
    ),
    $ipConfiguration['directions'],
);

$ipForm = new Form(false);
$ipSection = new Form_Section(pfsensePackageSinkholeTranslate('ip_country_blocking'));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('state'),
    htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
        'redirect_state',
        $ipConfiguration['enabled'] ? 'on' : 'off',
    )),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('interfaces'),
    htmlspecialchars($ipInterfaceLabels === []
        ? pfsensePackageSinkholeTranslate('none')
        : implode(', ', $ipInterfaceLabels)),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('directions'),
    htmlspecialchars($ipDirectionLabels === []
        ? pfsensePackageSinkholeTranslate('none')
        : implode(', ', $ipDirectionLabels)),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('countries'),
    htmlspecialchars($ipConfiguration['countries'] === []
        ? pfsensePackageSinkholeTranslate('none')
        : implode(', ', $ipConfiguration['countries'])),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('maxmind_license_key_status'),
    htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
        'secret_state',
        $ipConfiguration['license_key_set'] ? 'set' : 'unset',
    )),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('ipv4_table_entries'),
    htmlspecialchars((string) ($ipRuleStatus['ipv4_entries'] ?? 0)),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('ipv6_table_entries'),
    htmlspecialchars((string) ($ipRuleStatus['ipv6_entries'] ?? 0)),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('skipped_lines'),
    htmlspecialchars((string) ($ipStatus['skipped_lines'] ?? 0)),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('last_successful_update'),
    htmlspecialchars(is_string($ipStatus['last_success'] ?? null)
        ? $ipStatus['last_success']
        : pfsensePackageSinkholeTranslate('never')),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('geolite2_last_update'),
    htmlspecialchars(is_int($ipStatus['geolite_updated_at'] ?? null)
        ? gmdate('Y-m-d H:i:s \U\T\C', $ipStatus['geolite_updated_at'])
        : pfsensePackageSinkholeTranslate('never')),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('ip_anchor'),
    htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
        'rule_state',
        ($ipRuleStatus['out_of_date'] ?? false)
            ? 'out_of_date'
            : (($ipRuleStatus['loaded'] ?? false) ? 'loaded' : 'missing'),
    )),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('anchor_rule_count'),
    htmlspecialchars((string) ($ipRuleStatus['rule_count'] ?? 0)),
));
$ipSection->addInput(new Form_StaticText(
    pfsensePackageSinkholeTranslate('last_error'),
    htmlspecialchars(is_string($ipStatus['last_error'] ?? null) && $ipStatus['last_error'] !== ''
        ? $ipStatus['last_error']
        : pfsensePackageSinkholeTranslate('none')),
));
$ipForm->add($ipSection);
print($ipForm);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('ip_lists'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('family'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('entries'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('skipped_lines'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_fetch'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_error'))?></th>
				</tr>
			</thead>
			<tbody>
<?php if ($ipRows === []): ?>
				<tr><td colspan="6" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_ip_lists_configured'))?></td></tr>
<?php endif; ?>
<?php foreach ($ipRows as $ipRow): ?>
				<tr<?=($ipRow['enabled']) ? '' : ' class="disabled"'?>>
					<td><?=htmlspecialchars($ipRow['name'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('ip_family', $ipRow['family']))?></td>
					<td><?=htmlspecialchars((string) $ipRow['entries'])?></td>
					<td><?=htmlspecialchars((string) $ipRow['skipped'])?></td>
					<td><?=htmlspecialchars($ipRow['fetched_at'] === '' ? pfsensePackageSinkholeTranslate('never') : $ipRow['fetched_at'])?></td>
					<td><?=htmlspecialchars($ipRow['last_error'])?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<script>
events.push(function () {
	var panel = document.getElementById('sinkhole-update-log');
	var output = document.getElementById('sinkhole-update-log-text');

	if (!panel || !output) {
		return;
	}

	output.scrollTop = output.scrollHeight;

	if (typeof window.fetch !== 'function') {
		return;
	}

	var offset = parseInt(panel.getAttribute('data-offset'), 10) || 0;
	var run = panel.getAttribute('data-run') || '';
	var startingRun = run;
	var waitingForStart = panel.getAttribute('data-started') === '1';
	var startPollsLeft = 15;
	var finalFetchPending = false;
	var failuresLeft = 5;
	var summaryCells = {
		update_running: 'sinkhole-update-running',
		compile_needed: 'sinkhole-compile-needed',
		compiled_generation: 'sinkhole-compiled-generation',
		deployment_needed: 'sinkhole-deployment-needed',
		deployed_generation: 'sinkhole-deployed-generation',
		loaded_generation: 'sinkhole-loaded-generation'
	};

	function followingEnd() {
		return 4 > output.scrollHeight - output.scrollTop - output.clientHeight;
	}

	function showSummary(summary, running) {
		var runningRow = document.getElementById('sinkhole-update-running-row');

		if (runningRow) {
			runningRow.classList.toggle('hidden', !running);
		}

		if (!summary) {
			return;
		}

		Object.keys(summaryCells).forEach(function (key) {
			var cell = document.getElementById(summaryCells[key]);

			if (cell && typeof summary[key] === 'string') {
				cell.textContent = summary[key];
			}
		});
	}

	function schedulePoll() {
		window.setTimeout(poll, 2000);
	}

	function showUpdate(update) {
		var following = followingEnd();
		var running = update.running === true;

		if (update.reset === true) {
			output.value = '';
		}

		if (typeof update.text === 'string' && update.text !== '') {
			output.value += update.text;
		}

		offset = (typeof update.offset === 'number') ? update.offset : 0;
		run = (typeof update.run === 'string') ? update.run : '';

		if (following) {
			output.scrollTop = output.scrollHeight;
		}

		showSummary(update.summary, running);

		if (running) {
			waitingForStart = false;
			finalFetchPending = true;
			schedulePoll();

			return;
		}

		if (waitingForStart && run !== '' && run !== startingRun) {
			waitingForStart = false;
			finalFetchPending = true;
		}

		if (waitingForStart) {
			startPollsLeft -= 1;

			if (startPollsLeft > 0) {
				schedulePoll();
			}

			return;
		}

		if (finalFetchPending) {
			finalFetchPending = false;
			schedulePoll();
		}
	}

	function poll() {
		var url = 'sinkhole-status.php?update_log=1&offset='
			+ encodeURIComponent(String(offset))
			+ '&run='
			+ encodeURIComponent(run);

		window.fetch(url, {
			credentials: 'same-origin',
			cache: 'no-store',
			headers: { Accept: 'application/json' }
		}).then(function (response) {
			if (!response.ok) {
				throw new Error('update log');
			}

			return response.json();
		}).then(function (update) {
			failuresLeft = 5;
			showUpdate(update);
		}).catch(function () {
			failuresLeft -= 1;

			if (failuresLeft > 0) {
				schedulePoll();
			}
		});
	}

	if (panel.getAttribute('data-running') === '1' || waitingForStart) {
		poll();
	}
});
</script>
<?php include('foot.inc');
