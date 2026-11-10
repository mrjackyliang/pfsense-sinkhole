<?php

declare(strict_types=1);

/*
 * Sinkhole alert-rule editor.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-alerts-edit
##|*NAME=Firewall: Sinkhole: Alerts: Edit
##|*DESCR=Allow access to the Sinkhole alert-rule editor.
##|*MATCH=sinkhole-alerts_edit.php*
##|-PRIV

use PfSense\Sinkhole\Domain\AlertConfiguration;
use PfSense\Sinkhole\Domain\ScopeConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/AlertConfiguration.php');
require_once('/usr/local/pkg/sinkhole/ScopeConfiguration.php');

/**
 * Sinkhole Alert Editor - Apply Configuration.
 *
 * @param array<string, array> $alerts - Valid alert rules.
 * @param list<array> $invalidRows - Invalid rows retained for repair.
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeAlertEditorApply(array $alerts, array $invalidRows): void
{
    pfsensePackageSinkholeSaveAlerts($alerts, $invalidRows);
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
}

$adapter = pfsensePackageSinkholeAdapter();
$lists = pfsensePackageSinkholeGetLists();
$scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
$networks = $scopeConfiguration['networks'];
$devices = $scopeConfiguration['devices'];
$interfaces = $adapter->getConfiguredInterfaces();
$configuration = pfsensePackageSinkholeGetAlertConfiguration();
$alerts = $configuration['alerts'];
$invalidRows = $configuration['invalid_rows'];
$identifier = trim((string) ($_POST['alert_id'] ?? $_GET['id'] ?? ''));
$invalidPosition = isset($_POST['invalid_position'])
    && (string) $_POST['invalid_position'] !== ''
    ? (int) $_POST['invalid_position']
    : (isset($_GET['invalid_position']) ? (int) $_GET['invalid_position'] : null);
$actionMessage = null;
$actionClass = 'info';
$editing = null;

try {
    if ($invalidPosition !== null) {
        $matches = array_values(array_filter(
            $invalidRows,
            static fn(array $row): bool => $row['position'] === $invalidPosition,
        ));

        if (count($matches) !== 1 || !is_array($matches[0]['row'])) {
            throw new ValidationException('invalid_alert_rule_missing');
        }

        $editing = $matches[0]['row'];
        $identifier = '';
    } elseif ($identifier !== '') {
        $editing = $alerts[$identifier] ?? null;

        if ($editing === null) {
            throw new ValidationException('alert_rule_missing');
        }
    }
} catch (Throwable $throwable) {
    $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
    $actionClass = 'danger';
    $identifier = '';
    $invalidPosition = null;
}

$isEditMode = $identifier !== '' || $invalidPosition !== null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_alert'])) {
    $submittedIdentifier = $identifier;

    try {
        $repairing = $invalidPosition !== null;

        if ($repairing) {
            $matches = array_values(array_filter(
                $invalidRows,
                static fn(array $row): bool => $row['position'] === $invalidPosition,
            ));

            if (count($matches) !== 1) {
                throw new ValidationException('invalid_alert_rule_missing');
            }
        }

        if (
            $identifier === ''
            || preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1
            || ($repairing && isset($alerts[$identifier]))
        ) {
            $identifier = AlertConfiguration::generateIdentifier();
        } elseif (!isset($alerts[$identifier])) {
            throw new ValidationException('alert_rule_missing');
        }

        $candidate = AlertConfiguration::normalizeRow([
            'id' => $identifier,
            'descr' => (string) ($_POST['alert_description'] ?? ''),
            'lists_any' => isset($_POST['alert_lists_any']),
            'lists' => is_array($_POST['alert_lists'] ?? null) ? $_POST['alert_lists'] : [],
            'clients_everyone' => isset($_POST['alert_clients_everyone']),
            'networks' => is_array($_POST['alert_networks'] ?? null) ? $_POST['alert_networks'] : [],
            'devices' => is_array($_POST['alert_devices'] ?? null) ? $_POST['alert_devices'] : [],
            'repeat_minutes' => (string) ($_POST['alert_repeat_minutes'] ?? ''),
            'notice' => isset($_POST['alert_notice']),
            'remote' => isset($_POST['alert_remote']),
            'enabled' => isset($_POST['alert_enabled']),
        ], $lists, $networks, $devices);

        if ($repairing) {
            $invalidRows = array_values(array_filter(
                $invalidRows,
                static fn(array $row): bool => $row['position'] !== $invalidPosition,
            ));
        }

        $alerts[$identifier] = $candidate;
        sinkholeAlertEditorApply($alerts, $invalidRows);
        header('Location: sinkhole-alerts.php?saved=1');
        exit;
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
        $identifier = (
            $invalidPosition === null
            && isset($alerts[$submittedIdentifier])
        ) ? $submittedIdentifier : '';
        $editing = [
            'id' => $identifier,
            'descr' => (string) ($_POST['alert_description'] ?? ''),
            'lists_any' => isset($_POST['alert_lists_any']) ? 'on' : '',
            'lists' => is_array($_POST['alert_lists'] ?? null) ? $_POST['alert_lists'] : [],
            'clients_everyone' => isset($_POST['alert_clients_everyone']) ? 'on' : '',
            'networks' => is_array($_POST['alert_networks'] ?? null) ? $_POST['alert_networks'] : [],
            'devices' => is_array($_POST['alert_devices'] ?? null) ? $_POST['alert_devices'] : [],
            'repeat_minutes' => (string) ($_POST['alert_repeat_minutes'] ?? '60'),
            'notice' => isset($_POST['alert_notice']) ? 'on' : '',
            'remote' => isset($_POST['alert_remote']) ? 'on' : '',
            'enabled' => isset($_POST['alert_enabled']) ? 'on' : '',
        ];
    }
}

$listOptions = [];

foreach ($lists as $listIdentifier => $list) {
    $listOptions[$listIdentifier] = $list['name'];
}

$networkOptions = [];

foreach ($networks as $networkIdentifier => $network) {
    $interface = $network['interface'];
    $networkOptions[$networkIdentifier] = $interfaces[$interface] ?? $interface;
}

$deviceOptions = [];

foreach ($devices as $deviceIdentifier => $device) {
    $deviceOptions[$deviceIdentifier] = $device['name'];
}

$editingLists = ScopeConfiguration::unwrapRepeatedItems($editing['lists'] ?? []);
$editingLists = is_array($editingLists) ? array_values($editingLists) : [];
$editingNetworks = ScopeConfiguration::unwrapRepeatedItems($editing['networks'] ?? []);
$editingNetworks = is_array($editingNetworks) ? array_values($editingNetworks) : [];
$editingDevices = ScopeConfiguration::unwrapRepeatedItems($editing['devices'] ?? []);
$editingDevices = is_array($editingDevices) ? array_values($editingDevices) : [];

foreach ($editingLists as $listIdentifier) {
    if (is_string($listIdentifier) && !isset($listOptions[$listIdentifier])) {
        $listOptions[$listIdentifier] = pfsensePackageSinkholeTranslate('unavailable_list')
            . ' — ' . $listIdentifier;
    }
}

foreach ($editingNetworks as $networkIdentifier) {
    if (is_string($networkIdentifier) && !isset($networkOptions[$networkIdentifier])) {
        $networkOptions[$networkIdentifier] = pfsensePackageSinkholeTranslate('unavailable_network')
            . ' — ' . $networkIdentifier;
    }
}

foreach ($editingDevices as $deviceIdentifier) {
    if (is_string($deviceIdentifier) && !isset($deviceOptions[$deviceIdentifier])) {
        $deviceOptions[$deviceIdentifier] = pfsensePackageSinkholeTranslate('unavailable_device')
            . ' — ' . $deviceIdentifier;
    }
}

$isEditing = $isEditMode;
$pgtitle = [
    gettext('Firewall'),
    'Sinkhole',
    pfsensePackageSinkholeTranslate('alerts'),
    $isEditing ? pfsensePackageSinkholeTranslate('edit') : pfsensePackageSinkholeTranslate('add'),
];
$pglinks = [
    '',
    '/pkg_edit.php?xml=sinkhole.xml&id=0',
    '/sinkhole-alerts.php',
    '@self',
];

include('head.inc');
display_top_tabs(pfsensePackageSinkholeTabs('alerts'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

$button = new Form_Button(
    'save_alert',
    pfsensePackageSinkholeTranslateMapped('form_action', $isEditing ? 'edit' : 'add'),
    null,
    'fa-solid fa-save',
);
$button->addClass('btn-primary');
$form = new Form($button);
$section = new Form_Section(pfsensePackageSinkholeTranslateMapped(
    'alert_form',
    $isEditing ? 'edit' : 'add',
));
$form->addGlobal(new Form_Input(
    'alert_id',
    null,
    'hidden',
    is_array($editing) && is_string($editing['id'] ?? null) ? $editing['id'] : '',
));
$form->addGlobal(new Form_Input(
    'invalid_position',
    null,
    'hidden',
    ($invalidPosition === null) ? '' : (string) $invalidPosition,
));
$section->addInput(new Form_Input(
    'alert_description',
    '*' . pfsensePackageSinkholeTranslate('description'),
    'text',
    is_array($editing) ? (string) ($editing['description'] ?? $editing['descr'] ?? '') : '',
));
$section->addInput(new Form_Checkbox(
    'alert_lists_any',
    pfsensePackageSinkholeTranslate('lists'),
    pfsensePackageSinkholeTranslate('any_block_list'),
    !$isEditing
        || ($editing['any_list'] ?? false) === true
        || ($editing['lists_any'] ?? '') === 'on',
));
$section->addInput(new Form_Select(
    'alert_lists',
    pfsensePackageSinkholeTranslate('chosen_block_lists'),
    $editingLists,
    $listOptions,
    true,
));
$section->addInput(new Form_Checkbox(
    'alert_clients_everyone',
    pfsensePackageSinkholeTranslate('clients'),
    pfsensePackageSinkholeTranslate('everyone_help'),
    !$isEditing
        || ($editing['everyone'] ?? false) === true
        || ($editing['clients_everyone'] ?? '') === 'on',
));
$section->addInput(new Form_Select(
    'alert_networks',
    pfsensePackageSinkholeTranslate('chosen_networks'),
    $editingNetworks,
    $networkOptions,
    true,
));
$section->addInput(new Form_Select(
    'alert_devices',
    pfsensePackageSinkholeTranslate('chosen_devices'),
    $editingDevices,
    $deviceOptions,
    true,
));
$repeatInput = new Form_Input(
    'alert_repeat_minutes',
    '*' . pfsensePackageSinkholeTranslate('repeat_after'),
    'number',
    is_array($editing) ? (string) ($editing['repeat_minutes'] ?? 60) : '60',
);
$repeatInput->setHelp(pfsensePackageSinkholeTranslate('repeat_minutes_help'));
$section->addInput($repeatInput);
$section->addInput(new Form_Checkbox(
    'alert_notice',
    pfsensePackageSinkholeTranslate('webgui_notice'),
    pfsensePackageSinkholeTranslate('webgui_notice_help'),
    !$isEditing
        || !array_key_exists('notice', $editing)
        || ($editing['notice'] ?? false) === true
        || ($editing['notice'] ?? '') === 'on',
));
$section->addInput(new Form_Checkbox(
    'alert_remote',
    pfsensePackageSinkholeTranslate('remote_notifications'),
    pfsensePackageSinkholeTranslate('remote_notifications_help'),
    !$isEditing
        || !array_key_exists('remote', $editing)
        || ($editing['remote'] ?? false) === true
        || ($editing['remote'] ?? '') === 'on',
));
$section->addInput(new Form_Checkbox(
    'alert_enabled',
    pfsensePackageSinkholeTranslate('enabled'),
    pfsensePackageSinkholeTranslate('alert_enabled_help'),
    !$isEditing
        || ($editing['enabled'] ?? false) === true
        || ($editing['enabled'] ?? '') === 'on',
));
$form->add($section);
print($form);
?>
<script type="text/javascript">
//<![CDATA[
events.push(function() {
	function updateAlertInputs() {
		var anyList = $('#alert_lists_any').prop('checked');
		var everyone = $('#alert_clients_everyone').prop('checked');

		hideInput('alert_lists\\[\\]', anyList);
		hideInput('alert_networks\\[\\]', everyone);
		hideInput('alert_devices\\[\\]', everyone);
	}

	updateAlertInputs();
	$('#alert_lists_any, #alert_clients_everyone').change(updateAlertInputs);
});
//]]>
</script>
<?php

include('foot.inc');
