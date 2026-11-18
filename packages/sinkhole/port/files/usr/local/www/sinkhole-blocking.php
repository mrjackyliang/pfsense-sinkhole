<?php

declare(strict_types=1);

/*
 * Sinkhole Blocking page: the lists and allowed domains of each context.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-blocking
##|*NAME=Firewall: Sinkhole: Blocking
##|*DESCR=Allow access to the Sinkhole lists and allowed domains of each context.
##|*MATCH=sinkhole-blocking.php*
##|-PRIV

use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\ListConfiguration;
use PfSense\Sinkhole\Domain\ScopeConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;
use PfSense\Sinkhole\Runtime\Context;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/Context.php');
require_once('/usr/local/pkg/sinkhole/DomainParser.php');
require_once('/usr/local/pkg/sinkhole/ListConfiguration.php');
require_once('/usr/local/pkg/sinkhole/ScopeConfiguration.php');

/**
 * Sinkhole Blocking - Posted Allowed Domains.
 *
 * @param string $value - Textarea value.
 *
 * @return list<string>
 *
 * @throws ValidationException When a line is not a domain.
 *
 * @since 1.3.0
 */
function sinkholeBlockingAllowedDomains(string $value): array
{
    $result = DomainParser::normalizeAllowedDomains($value);

    if (count($result['invalid_lines']) > 0) {
        throw new ValidationException(
            'allowed_domains_invalid_lines',
            [implode(', ', $result['invalid_lines'])],
        );
    }

    return $result['domains'];
}

/**
 * Sinkhole Blocking - List Names.
 *
 * @param list<string> $identifiers - List IDs.
 * @param array<string, array> $lists - Configured lists.
 *
 * @return string
 *
 * @since 1.3.0
 */
function sinkholeBlockingListNames(array $identifiers, array $lists): string
{
    $names = [];

    foreach ($identifiers as $identifier) {
        if (isset($lists[$identifier])) {
            $names[] = $lists[$identifier]['name'];
        }
    }

    return ($names === []) ? pfsensePackageSinkholeTranslate('none') : implode(', ', $names);
}

$adapter = pfsensePackageSinkholeAdapter();
$listConfiguration = pfsensePackageSinkholeGetListConfiguration();
$lists = $listConfiguration['lists'];
$invalidListRows = $listConfiguration['invalid_rows'];
$globalAllowedDomains = pfsensePackageSinkholeGetAllowedDomains();
$interfaces = $adapter->getConfiguredInterfaces();
$staticMappings = $adapter->getStaticMappings();
$scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
$networks = $scopeConfiguration['networks'];
$devices = $scopeConfiguration['devices'];
$context = Context::current($networks, $devices, true);
Context::remember($context);
$parsedContext = Context::parse($context) ?? ['type' => Context::GLOBAL, 'id' => ''];
$actionMessage = null;
$actionClass = 'info';
$postedLists = null;
$postedAllowed = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_blocking']) && $context !== Context::ALL) {
    try {
        $selectedLists = is_array($_POST['blocking_lists'] ?? null)
            ? array_values(array_filter($_POST['blocking_lists'], 'is_string'))
            : [];
        $allowedDomains = sinkholeBlockingAllowedDomains(
            (string) ($_POST['blocking_allowed_domains'] ?? ''),
        );

        if ($parsedContext['type'] === Context::GLOBAL) {
            foreach ($lists as $listIdentifier => $list) {
                $lists[$listIdentifier] = ListConfiguration::normalizeRow(
                    $listIdentifier,
                    $list['name'],
                    $list['url'],
                    $list['enabled'],
                    in_array($listIdentifier, $selectedLists, true),
                );
            }

            pfsensePackageSinkholeSaveLists($lists, $allowedDomains, $invalidListRows);
        } elseif ($parsedContext['type'] === 'network') {
            $network = $networks[$parsedContext['id']];
            $networks[$parsedContext['id']] = ScopeConfiguration::normalizeNetworkRow([
                'id' => $parsedContext['id'],
                'interface' => $network['interface'],
                'lists' => $selectedLists,
                'allowed_domains' => $allowedDomains,
                'enabled' => $network['enabled'],
            ], $interfaces, $lists);
            pfsensePackageSinkholeSaveScopes(
                $networks,
                $devices,
                $scopeConfiguration['invalid_networks'],
                $scopeConfiguration['invalid_devices'],
            );
        } else {
            $device = $devices[$parsedContext['id']];
            $devices[$parsedContext['id']] = ScopeConfiguration::normalizeDeviceRow([
                'id' => $parsedContext['id'],
                'descr' => $device['name'],
                'identifiers' => $device['identifiers'],
                'lists' => $selectedLists,
                'allowed_domains' => $allowedDomains,
                'enabled' => $device['enabled'],
            ], $staticMappings, $lists);
            pfsensePackageSinkholeSaveScopes(
                $networks,
                $devices,
                $scopeConfiguration['invalid_networks'],
                $scopeConfiguration['invalid_devices'],
            );
        }

        pfsensePackageSinkholeInstallCron();
        $adapter->runApplyInBackground();
        $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
        $actionClass = 'success';
        $listConfiguration = pfsensePackageSinkholeGetListConfiguration();
        $lists = $listConfiguration['lists'];
        $globalAllowedDomains = pfsensePackageSinkholeGetAllowedDomains();
        $scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
        $networks = $scopeConfiguration['networks'];
        $devices = $scopeConfiguration['devices'];
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
        $postedLists = is_array($_POST['blocking_lists'] ?? null) ? $_POST['blocking_lists'] : [];
        $postedAllowed = (string) ($_POST['blocking_allowed_domains'] ?? '');
    }
}

$contextLists = [];
$contextAllowed = [];

if ($parsedContext['type'] === Context::GLOBAL) {
    foreach ($lists as $listIdentifier => $list) {
        if ($list['global']) {
            $contextLists[] = $listIdentifier;
        }
    }

    $contextAllowed = $globalAllowedDomains;
} elseif ($parsedContext['type'] === 'network') {
    $contextLists = $networks[$parsedContext['id']]['lists'] ?? [];
    $contextAllowed = $networks[$parsedContext['id']]['allowed_domains'] ?? [];
} elseif ($parsedContext['type'] === 'device') {
    $contextLists = $devices[$parsedContext['id']]['lists'] ?? [];
    $contextAllowed = $devices[$parsedContext['id']]['allowed_domains'] ?? [];
}

$overviewRows = [];

if ($context === Context::ALL) {
    $globalLists = [];

    foreach ($lists as $listIdentifier => $list) {
        if ($list['global']) {
            $globalLists[] = $listIdentifier;
        }
    }

    $candidates = [Context::GLOBAL => [$globalLists, $globalAllowedDomains]];

    foreach ($networks as $networkIdentifier => $network) {
        $candidates['network:' . $networkIdentifier] = [$network['lists'], $network['allowed_domains']];
    }

    foreach ($devices as $deviceIdentifier => $device) {
        $candidates['device:' . $deviceIdentifier] = [$device['lists'], $device['allowed_domains']];
    }

    foreach ($candidates as $candidateKey => [$candidateLists, $candidateAllowed]) {
        if ($candidateLists === [] && $candidateAllowed === []) {
            continue;
        }

        $overviewRows[] = [
            'key' => $candidateKey,
            'label' => Context::label($candidateKey, $networks, $devices),
            'lists' => sinkholeBlockingListNames($candidateLists, $lists),
            'allowed' => count($candidateAllowed),
        ];
    }
}

$pgtitle = [gettext('Firewall'), 'Sinkhole', pfsensePackageSinkholeTranslate('blocking_tab')];
$pglinks = ['', '/pkg_edit.php?xml=sinkhole.xml&id=0', '@self'];

include('head.inc');
?>
<link rel="stylesheet" href="/css/sinkhole.css">
<?php
display_top_tabs(pfsensePackageSinkholeTabs('blocking'));
print(Context::renderRow('sinkhole-blocking.php', $context, $networks, $devices, true));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

if ($context === Context::ALL) {
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('blocking_tab'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead><tr>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('context_column'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('lists'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('allowed_domains'))?></th>
			</tr></thead>
			<tbody>
<?php if ($overviewRows === []): ?>
				<tr><td colspan="3" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('context_overview_empty'))?></td></tr>
<?php endif; ?>
<?php foreach ($overviewRows as $overviewRow): ?>
				<tr>
					<td><a href="<?=htmlspecialchars(Context::link('sinkhole-blocking.php', $overviewRow['key']))?>"><?=htmlspecialchars($overviewRow['label'])?></a></td>
					<td><?=htmlspecialchars($overviewRow['lists'])?></td>
					<td><?=htmlspecialchars((string) $overviewRow['allowed'])?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php
} else {
    $listOptions = [];

    foreach ($lists as $listIdentifier => $list) {
        $listOptions[$listIdentifier] = $list['name'];
    }

    $selectedLists = is_array($postedLists) ? array_values($postedLists) : $contextLists;
    $allowedText = is_string($postedAllowed)
        ? $postedAllowed
        : implode(PHP_EOL, $contextAllowed);
    $saveButton = new Form_Button(
        'save_blocking',
        pfsensePackageSinkholeTranslate('save'),
        null,
        'fa-solid fa-save',
    );
    $saveButton->addClass('btn-primary');
    $form = new Form($saveButton);
    $form->setAction('sinkhole-blocking.php');
    $form->addGlobal(new Form_Input('context', null, 'hidden', $context));
    $listSection = new Form_Section(pfsensePackageSinkholeTranslate('block_lists'));

    if ($listOptions === []) {
        $listSection->addInput(new Form_StaticText(
            '',
            '<span class="help-block">'
                . htmlspecialchars(pfsensePackageSinkholeTranslate('no_block_lists_configured'))
                . '</span>',
        ));
    } else {
        $listInput = new Form_Select(
            'blocking_lists',
            pfsensePackageSinkholeTranslate('lists'),
            $selectedLists,
            $listOptions,
            true,
        );

        if ($parsedContext['type'] === 'network') {
            $listInput->setHelp(pfsensePackageSinkholeTranslate('blocking_network_lists_help'));
        } elseif ($parsedContext['type'] === 'device') {
            $listInput->setHelp(pfsensePackageSinkholeTranslate('blocking_device_lists_help'));
        } else {
            $listInput->setHelp(pfsensePackageSinkholeTranslate('block_list_global_help'));
        }

        $listSection->addInput($listInput);
    }

    $form->add($listSection);
    $allowedSection = new Form_Section(pfsensePackageSinkholeTranslate('allowed_domains'));
    $allowedInput = new Form_Textarea(
        'blocking_allowed_domains',
        pfsensePackageSinkholeTranslate('domains'),
        $allowedText,
    );
    $allowedInput->setRows(6);
    $allowedInput->setHelp(pfsensePackageSinkholeTranslate('allowed_domains_help'));
    $allowedSection->addInput($allowedInput);
    $form->add($allowedSection);
    print($form);
}

include('foot.inc');
