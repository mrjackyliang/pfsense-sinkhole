<?php

declare(strict_types=1);

/*
 * Sinkhole network and device scope configuration page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-scopes
##|*NAME=Firewall: Sinkhole: Scopes
##|*DESCR=Allow access to Sinkhole network and device scope configuration.
##|*MATCH=sinkhole-scopes.php*
##|-PRIV

use PfSense\Sinkhole\Domain\ScopeConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;
use PfSense\Sinkhole\Runtime\ClientMap;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/ClientMap.php');
require_once('/usr/local/pkg/sinkhole/ScopeConfiguration.php');

/**
 * Sinkhole Scopes - Apply Configuration.
 *
 * Persists one revision and hands all downloads and compilation to the background.
 *
 * @param array<string, array> $networks - Networks.
 * @param array<string, array> $devices - Devices.
 * @param list<array> $invalidNetworks - Invalid networks.
 * @param list<array> $invalidDevices - Invalid devices.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeScopesApply(
    array $networks,
    array $devices,
    array $invalidNetworks,
    array $invalidDevices,
): void {
    pfsensePackageSinkholeSaveScopes(
        $networks,
        $devices,
        $invalidNetworks,
        $invalidDevices,
    );
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
    pfsensePackageSinkholeAdapter()->runClientRefreshInBackground();
}

/**
 * Sinkhole Scopes - Client Presentation.
 *
 * Reads only the bounded regular client map and groups addresses and conflicts by
 * configured device ID.
 *
 * @return array{addresses: array<string, list<string>>, conflicts: array<string, list<string>>}
 *
 * @since 1.0.0
 */
function sinkholeScopesClientPresentation(): array
{
    $path = pfsensePackageSinkholeAdapter()->packagePaths()->runtimeClientMapFile;
    $status = @lstat($path);

    if (
        !is_array($status)
        || ($status['mode'] & 0170000) !== 0100000
        || $status['size'] > ClientMap::MAXIMUM_BYTES
    ) {
        return ['addresses' => [], 'conflicts' => []];
    }

    $contents = file_get_contents($path);

    if ($contents === false) {
        return ['addresses' => [], 'conflicts' => []];
    }

    try {
        $map = json_decode($contents, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        return ['addresses' => [], 'conflicts' => []];
    }

    if (!is_array($map) || !is_array($map['devices'] ?? null)) {
        return ['addresses' => [], 'conflicts' => []];
    }

    $addresses = [];
    $conflicts = [];

    foreach ($map['devices'] as $address => $deviceIdentifier) {
        if (is_string($address) && is_string($deviceIdentifier)) {
            $addresses[$deviceIdentifier][] = $address;
        }
    }

    foreach (is_array($map['conflicts'] ?? null) ? $map['conflicts'] : [] as $conflict) {
        if (!is_array($conflict) || !is_string($conflict['address'] ?? null)) {
            continue;
        }

        foreach (is_array($conflict['devices'] ?? null) ? $conflict['devices'] : [] as $deviceIdentifier) {
            if (is_string($deviceIdentifier)) {
                $addresses[$deviceIdentifier][] = $conflict['address'];
                $conflicts[$deviceIdentifier][] = $conflict['address'];
            }
        }
    }

    foreach ($addresses as &$deviceAddresses) {
        $deviceAddresses = array_values(array_unique($deviceAddresses));
        sort($deviceAddresses, SORT_STRING);
    }
    unset($deviceAddresses);

    foreach ($conflicts as &$deviceConflicts) {
        $deviceConflicts = array_values(array_unique($deviceConflicts));
        sort($deviceConflicts, SORT_STRING);
    }
    unset($deviceConflicts);

    return ['addresses' => $addresses, 'conflicts' => $conflicts];
}

/**
 * Sinkhole Scopes - List Labels.
 *
 * Maps assigned stable IDs to escaped-at-render display labels.
 *
 * @param list<string> $identifiers - Assigned list IDs.
 * @param array<string, array> $lists - Configured lists.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeScopesListLabels(array $identifiers, array $lists): string
{
    $labels = [];

    foreach ($identifiers as $identifier) {
        if (isset($lists[$identifier])) {
            $labels[] = $lists[$identifier]['name'];
        }
    }

    return ($labels === [])
        ? pfsensePackageSinkholeTranslate('none')
        : implode(', ', $labels);
}

$adapter = pfsensePackageSinkholeAdapter();
$lists = pfsensePackageSinkholeGetLists();
$interfaces = $adapter->getConfiguredInterfaces();
$scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
$networks = $scopeConfiguration['networks'];
$devices = $scopeConfiguration['devices'];
$invalidNetworks = $scopeConfiguration['invalid_networks'];
$invalidDevices = $scopeConfiguration['invalid_devices'];
$actionMessage = ((string) ($_GET['saved'] ?? '') === '1')
    ? pfsensePackageSinkholeTranslate('settings_saved_applying')
    : null;
$actionClass = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['toggle_network']) || isset($_POST['delete_network'])) {
            $identifier = (string) ($_POST['scope_id'] ?? '');

            if (!isset($networks[$identifier])) {
                throw new ValidationException('network_missing');
            }

            if (isset($_POST['toggle_network'])) {
                $networks[$identifier]['enabled'] = !$networks[$identifier]['enabled'];
            } else {
                unset($networks[$identifier]);
            }

            sinkholeScopesApply($networks, $devices, $invalidNetworks, $invalidDevices);
            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['toggle_device']) || isset($_POST['delete_device'])) {
            $identifier = (string) ($_POST['scope_id'] ?? '');

            if (!isset($devices[$identifier])) {
                throw new ValidationException('device_missing');
            }

            if (isset($_POST['toggle_device'])) {
                $devices[$identifier]['enabled'] = !$devices[$identifier]['enabled'];
            } else {
                unset($devices[$identifier]);
            }

            sinkholeScopesApply($networks, $devices, $invalidNetworks, $invalidDevices);
            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['delete_invalid'])) {
            $kind = (string) ($_POST['invalid_kind'] ?? '');
            $position = (int) ($_POST['invalid_position'] ?? -1);

            if ($kind === 'network') {
                $before = count($invalidNetworks);
                $invalidNetworks = array_values(array_filter(
                    $invalidNetworks,
                    static fn(array $row): bool => $row['position'] !== $position,
                ));

                if ($before === count($invalidNetworks)) {
                    throw new ValidationException('invalid_network_row_missing');
                }
            } elseif ($kind === 'device') {
                $before = count($invalidDevices);
                $invalidDevices = array_values(array_filter(
                    $invalidDevices,
                    static fn(array $row): bool => $row['position'] !== $position,
                ));

                if ($before === count($invalidDevices)) {
                    throw new ValidationException('invalid_device_row_missing');
                }
            } else {
                throw new ValidationException('invalid_scope_type_unknown');
            }

            sinkholeScopesApply($networks, $devices, $invalidNetworks, $invalidDevices);
            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }

    if ($actionClass === 'success') {
        $scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
        $networks = $scopeConfiguration['networks'];
        $devices = $scopeConfiguration['devices'];
        $invalidNetworks = $scopeConfiguration['invalid_networks'];
        $invalidDevices = $scopeConfiguration['invalid_devices'];
    }
}

$clientPresentation = sinkholeScopesClientPresentation();

$pgtitle = [gettext('Firewall'), 'Sinkhole', pfsensePackageSinkholeTranslate('scopes')];
$pglinks = ['', '/pkg_edit.php?xml=sinkhole.xml&id=0', '@self'];

include('head.inc');
display_top_tabs(pfsensePackageSinkholeTabs('scopes'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('networks'))?></h2></div>
	<div class="panel-body table-responsive">
			<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
				<thead><tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('interface'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('lists'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('allowed_domains'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
					<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
				</tr></thead>
				<tbody>
<?php if ($networks === []): ?>
					<tr><td colspan="5" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_networks_configured'))?></td></tr>
<?php endif; ?>
<?php foreach ($networks as $identifier => $network): ?>
					<tr<?=($network['enabled']) ? '' : ' class="disabled"'?>>
						<td><?=htmlspecialchars($interfaces[$network['interface']] ?? $network['interface'])?></td>
						<td><?=htmlspecialchars(sinkholeScopesListLabels($network['lists'], $lists))?></td>
						<td><?=htmlspecialchars((string) count($network['allowed_domains']))?></td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $network['enabled'] ? 'true' : 'false'))?></td>
						<td class="text-nowrap">
							<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>" href="sinkhole-scopes_edit.php?type=network&amp;id=<?=urlencode($identifier)?>"></a>
							<a class="<?=$network['enabled'] ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', $network['enabled'] ? 'enabled' : 'disabled'))?>" href="sinkhole-scopes.php?toggle_network=1&amp;scope_id=<?=urlencode($identifier)?>" usepost></a>
							<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-scopes.php?delete_network=1&amp;scope_id=<?=urlencode($identifier)?>" usepost></a>
						</td>
					</tr>
<?php endforeach; ?>
				</tbody>
			</table>
	</div>
</div>
<nav class="action-buttons">
	<a href="sinkhole-scopes_edit.php?type=network" role="button" class="btn btn-success btn-sm">
		<i class="fa-solid fa-plus icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add'))?>
	</a>
</nav>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('devices'))?></h2></div>
	<div class="panel-body table-responsive">
			<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
				<thead><tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('identified_by'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('identifier'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('current_addresses'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('lists'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
					<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
				</tr></thead>
				<tbody>
<?php if ($devices === []): ?>
					<tr><td colspan="7" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_devices_configured'))?></td></tr>
<?php endif; ?>
<?php foreach ($devices as $identifier => $device): ?>
<?php
    $typeLabels = [
        ScopeConfiguration::DEVICE_IP => pfsensePackageSinkholeTranslate('ip_address'),
        ScopeConfiguration::DEVICE_STATIC_MAPPING => pfsensePackageSinkholeTranslate('dhcp_static_mapping'),
        ScopeConfiguration::DEVICE_MAC => pfsensePackageSinkholeTranslate('mac_address'),
    ];
    $identifierText = ($device['identifier_type'] === ScopeConfiguration::DEVICE_STATIC_MAPPING)
        ? ($interfaces[$device['interface']] ?? $device['interface']) . ' / ' . $device['identifier']
        : $device['identifier'];
    $deviceAddresses = $clientPresentation['addresses'][$identifier] ?? [];
    $deviceConflicts = $clientPresentation['conflicts'][$identifier] ?? [];
?>
<?php
    $deviceRowClasses = [];

    if ($deviceConflicts !== []) {
        $deviceRowClasses[] = 'warning';
    }

    if (!$device['enabled']) {
        $deviceRowClasses[] = 'disabled';
    }
?>
					<tr<?=($deviceRowClasses === []) ? '' : ' class="' . implode(' ', $deviceRowClasses) . '"'?>>
						<td>
							<?=htmlspecialchars($device['name'])?>
<?php if ($deviceConflicts !== []): ?>
							<span class="fa-solid fa-triangle-exclamation" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('address_conflict', [implode(', ', $deviceConflicts)]))?>"></span>
<?php endif; ?>
						</td>
						<td><?=htmlspecialchars($typeLabels[$device['identifier_type']] ?? $device['identifier_type'])?></td>
						<td><?=htmlspecialchars($identifierText)?></td>
						<td><?=htmlspecialchars(($deviceAddresses === []) ? pfsensePackageSinkholeTranslate('none') : implode(', ', $deviceAddresses))?></td>
						<td><?=htmlspecialchars(sinkholeScopesListLabels($device['lists'], $lists))?></td>
						<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $device['enabled'] ? 'true' : 'false'))?></td>
						<td class="text-nowrap">
							<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>" href="sinkhole-scopes_edit.php?type=device&amp;id=<?=urlencode($identifier)?>"></a>
							<a class="<?=$device['enabled'] ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', $device['enabled'] ? 'enabled' : 'disabled'))?>" href="sinkhole-scopes.php?toggle_device=1&amp;scope_id=<?=urlencode($identifier)?>" usepost></a>
							<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-scopes.php?delete_device=1&amp;scope_id=<?=urlencode($identifier)?>" usepost></a>
						</td>
					</tr>
<?php endforeach; ?>
				</tbody>
			</table>
	</div>
</div>
<p class="help-block"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('device_order_help'))?></p>
<nav class="action-buttons">
	<a href="sinkhole-scopes_edit.php?type=device" role="button" class="btn btn-success btn-sm">
		<i class="fa-solid fa-plus icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add'))?>
	</a>
</nav>

<?php if ($invalidNetworks !== [] || $invalidDevices !== []): ?>
<div class="panel panel-danger">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_saved_rows'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead><tr><th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('type'))?></th><th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('name_or_interface'))?></th><th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('reason'))?></th><th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th></tr></thead>
			<tbody>
<?php foreach (['network' => $invalidNetworks, 'device' => $invalidDevices] as $kind => $rows): ?>
<?php foreach ($rows as $invalidRow): ?>
				<tr>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('scope_kind', $kind, [], 'unknown'))?></td>
					<td><?=htmlspecialchars($invalidRow['name'] !== '' ? $invalidRow['name'] : $invalidRow['interface'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeInvalidReason($invalidRow))?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('fix'))?>" href="sinkhole-scopes_edit.php?type=<?=urlencode($kind)?>&amp;invalid_position=<?=urlencode((string) $invalidRow['position'])?>"></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-scopes.php?delete_invalid=1&amp;invalid_kind=<?=urlencode($kind)?>&amp;invalid_position=<?=urlencode((string) $invalidRow['position'])?>" usepost></a>
					</td>
				</tr>
<?php endforeach; ?>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php endif; ?>
<?php
include('foot.inc');
