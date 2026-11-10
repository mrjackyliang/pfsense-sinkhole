<?php

declare(strict_types=1);

/*
 * Sinkhole alert-rule configuration page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-alerts
##|*NAME=Firewall: Sinkhole: Alerts
##|*DESCR=Allow access to Sinkhole alert-rule configuration.
##|*MATCH=sinkhole-alerts.php*
##|-PRIV

use PfSense\Sinkhole\Domain\ValidationException;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');

/**
 * Sinkhole Alerts - Apply Configuration.
 *
 * Saves one revision, reconciles cron, and compiles in the background.
 *
 * @param array<string, array> $alerts - Valid alert rules.
 * @param list<array> $invalidRows - Invalid rows retained for repair.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeAlertsApply(array $alerts, array $invalidRows): void
{
    pfsensePackageSinkholeSaveAlerts($alerts, $invalidRows);
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
}

/**
 * Sinkhole Alerts - Selected Labels.
 *
 * @param list<string> $identifiers - Selected IDs.
 * @param array<string, string> $labels - Available labels.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeAlertsSelectedLabels(array $identifiers, array $labels): string
{
    $selected = [];

    foreach ($identifiers as $identifier) {
        if (isset($labels[$identifier])) {
            $selected[] = $labels[$identifier];
        }
    }

    return ($selected === [])
        ? pfsensePackageSinkholeTranslate('none')
        : implode(', ', $selected);
}

$adapter = pfsensePackageSinkholeAdapter();
$lists = pfsensePackageSinkholeGetLists();
$scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
$networks = $scopeConfiguration['networks'];
$devices = $scopeConfiguration['devices'];
$interfaces = $adapter->getConfiguredInterfaces();
$alertConfiguration = pfsensePackageSinkholeGetAlertConfiguration();
$alerts = $alertConfiguration['alerts'];
$invalidRows = $alertConfiguration['invalid_rows'];
$actionMessage = ((string) ($_GET['saved'] ?? '') === '1')
    ? pfsensePackageSinkholeTranslate('settings_saved_applying')
    : null;
$actionClass = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['toggle']) || isset($_POST['delete'])) {
            $identifier = (string) ($_POST['alert_id'] ?? '');

            if (!isset($alerts[$identifier])) {
                throw new ValidationException('alert_rule_missing');
            }

            if (isset($_POST['toggle'])) {
                $alerts[$identifier]['enabled'] = !$alerts[$identifier]['enabled'];
            } else {
                unset($alerts[$identifier]);
            }

            sinkholeAlertsApply($alerts, $invalidRows);
            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        } elseif (isset($_POST['delete_invalid'])) {
            $position = (int) ($_POST['invalid_position'] ?? -1);
            $before = count($invalidRows);
            $invalidRows = array_values(array_filter(
                $invalidRows,
                static fn(array $row): bool => $row['position'] !== $position,
            ));

            if ($before === count($invalidRows)) {
                throw new ValidationException('invalid_alert_rule_missing');
            }

            sinkholeAlertsApply($alerts, $invalidRows);
            $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
            $actionClass = 'success';
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }

    if ($actionClass === 'success') {
        $alertConfiguration = pfsensePackageSinkholeGetAlertConfiguration();
        $alerts = $alertConfiguration['alerts'];
        $invalidRows = $alertConfiguration['invalid_rows'];
    }
}

$listOptions = [];

foreach ($lists as $identifier => $list) {
    $listOptions[$identifier] = $list['name'];
}

$networkOptions = [];

foreach ($networks as $identifier => $network) {
    $interface = $network['interface'];
    $networkOptions[$identifier] = $interfaces[$interface] ?? $interface;
}

$deviceOptions = [];

foreach ($devices as $identifier => $device) {
    $deviceOptions[$identifier] = $device['name'];
}

$pgtitle = [gettext('Firewall'), 'Sinkhole', pfsensePackageSinkholeTranslate('alerts')];
$pglinks = ['', '/pkg_edit.php?xml=sinkhole.xml&id=0', '@self'];

include('head.inc');
display_top_tabs(pfsensePackageSinkholeTabs('alerts'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('alert_rules'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead><tr>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('description'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('lists'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('clients'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('repeat_after'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('notice'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('remote'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
				<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
			</tr></thead>
			<tbody>
<?php if ($alerts === []): ?>
				<tr><td colspan="8" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('no_alert_rules_configured'))?></td></tr>
<?php endif; ?>
<?php foreach ($alerts as $identifier => $alert): ?>
<?php
    $listText = $alert['any_list']
        ? pfsensePackageSinkholeTranslate('any')
        : sinkholeAlertsSelectedLabels($alert['lists'], $listOptions);
    $clientLabels = [];

    if ($alert['everyone']) {
        $clientText = pfsensePackageSinkholeTranslate('everyone');
    } else {
        foreach ($alert['networks'] as $networkIdentifier) {
            if (isset($networkOptions[$networkIdentifier])) {
                $clientLabels[] = pfsensePackageSinkholeTranslate(
                    'scope_label',
                    [pfsensePackageSinkholeTranslate('network'), $networkOptions[$networkIdentifier]],
                );
            }
        }

        foreach ($alert['devices'] as $deviceIdentifier) {
            if (isset($deviceOptions[$deviceIdentifier])) {
                $clientLabels[] = pfsensePackageSinkholeTranslate(
                    'scope_label',
                    [pfsensePackageSinkholeTranslate('device'), $deviceOptions[$deviceIdentifier]],
                );
            }
        }

        $clientText = implode(', ', $clientLabels);
    }
?>
				<tr<?=($alert['enabled']) ? '' : ' class="disabled"'?>>
					<td><?=htmlspecialchars($alert['description'])?></td>
					<td><?=htmlspecialchars($listText)?></td>
					<td><?=htmlspecialchars($clientText)?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslate('minutes_count', [$alert['repeat_minutes']]))?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $alert['notice'] ? 'true' : 'false'))?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $alert['remote'] ? 'true' : 'false'))?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $alert['enabled'] ? 'true' : 'false'))?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>" href="sinkhole-alerts_edit.php?id=<?=urlencode($identifier)?>"></a>
						<a class="<?=$alert['enabled'] ? 'fa-solid fa-ban' : 'fa-regular fa-square-check'?>" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('toggle_action', $alert['enabled'] ? 'enabled' : 'disabled'))?>" href="sinkhole-alerts.php?toggle=1&amp;alert_id=<?=urlencode($identifier)?>" usepost></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-alerts.php?delete=1&amp;alert_id=<?=urlencode($identifier)?>" usepost></a>
					</td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<nav class="action-buttons">
	<a href="sinkhole-alerts_edit.php" role="button" class="btn btn-success btn-sm">
		<i class="fa-solid fa-plus icon-embed-btn"></i>
		<?=htmlspecialchars(pfsensePackageSinkholeTranslate('add'))?>
	</a>
</nav>

<?php if ($invalidRows !== []): ?>
<div class="panel panel-danger">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_saved_rows'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead><tr><th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('description'))?></th><th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('reason'))?></th><th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th></tr></thead>
			<tbody>
<?php foreach ($invalidRows as $invalidRow): ?>
				<tr>
					<td><?=htmlspecialchars($invalidRow['description'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeInvalidReason($invalidRow))?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('fix'))?>" href="sinkhole-alerts_edit.php?invalid_position=<?=urlencode((string) $invalidRow['position'])?>"></a>
						<a class="fa-solid fa-trash-can" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('delete'))?>" href="sinkhole-alerts.php?delete_invalid=1&amp;invalid_position=<?=urlencode((string) $invalidRow['position'])?>" usepost></a>
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
