<?php

declare(strict_types=1);

/*
 * Sinkhole network and device scope editor.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-scopes-edit
##|*NAME=Firewall: Sinkhole: Scopes: Edit
##|*DESCR=Allow access to the Sinkhole network and device scope editor.
##|*MATCH=sinkhole-scopes_edit.php*
##|-PRIV

use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\ScopeConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/DomainParser.php');
require_once('/usr/local/pkg/sinkhole/ScopeConfiguration.php');

/**
 * Sinkhole Scope Editor - Normalize Allowed Text.
 *
 * @param string $value - Textarea value.
 * @return list<string>
 *
 * @since 1.0.0
 */
function sinkholeScopeEditorAllowedDomains(string $value): array
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
 * Sinkhole Scope Editor - Apply Configuration.
 *
 * @param array<string, array> $networks - Networks.
 * @param array<string, array> $devices - Devices.
 * @param list<array> $invalidNetworks - Invalid networks.
 * @param list<array> $invalidDevices - Invalid devices.
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeScopeEditorApply(
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

$adapter = pfsensePackageSinkholeAdapter();
$lists = pfsensePackageSinkholeGetLists();
$interfaces = $adapter->getConfiguredInterfaces();
$staticMappings = $adapter->getStaticMappings();
$configuration = pfsensePackageSinkholeGetScopeConfiguration();
$networks = $configuration['networks'];
$devices = $configuration['devices'];
$invalidNetworks = $configuration['invalid_networks'];
$invalidDevices = $configuration['invalid_devices'];
$scopeType = (string) ($_POST['scope_type'] ?? $_GET['type'] ?? 'network');
$scopeType = in_array($scopeType, ['network', 'device'], true) ? $scopeType : 'network';
$identifier = trim((string) ($_POST['scope_id'] ?? $_GET['id'] ?? ''));
$invalidPosition = isset($_POST['invalid_position'])
    && (string) $_POST['invalid_position'] !== ''
    ? (int) $_POST['invalid_position']
    : (isset($_GET['invalid_position']) ? (int) $_GET['invalid_position'] : null);
$actionMessage = null;
$actionClass = 'info';
$editing = null;

try {
    if ($invalidPosition !== null) {
        $invalidRows = ($scopeType === 'network') ? $invalidNetworks : $invalidDevices;
        $matches = array_values(array_filter(
            $invalidRows,
            static fn(array $row): bool => $row['position'] === $invalidPosition,
        ));

        if (count($matches) !== 1 || !is_array($matches[0]['row'])) {
            throw new ValidationException('invalid_scope_row_missing');
        }

        $editing = $matches[0]['row'];
        $identifier = '';

        if ($scopeType === 'device') {
            $editing['name'] = is_string($editing['descr'] ?? null)
                ? $editing['descr']
                : '';
        }
    } elseif ($identifier !== '') {
        $editing = ($scopeType === 'network')
            ? ($networks[$identifier] ?? null)
            : ($devices[$identifier] ?? null);

        if ($editing === null) {
            throw new ValidationException(($scopeType === 'network') ? 'network_missing' : 'device_missing');
        }
    }
} catch (Throwable $throwable) {
    $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
    $actionClass = 'danger';
    $identifier = '';
    $invalidPosition = null;
}

$isEditMode = $identifier !== '' || $invalidPosition !== null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedIdentifier = $identifier;

    try {
        $repairing = $invalidPosition !== null;

        if ($scopeType === 'network' && isset($_POST['save_network'])) {
            if (
                $identifier === ''
                || preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1
                || ($repairing && isset($networks[$identifier]))
            ) {
                $identifier = ScopeConfiguration::generateIdentifier();
            } elseif (!isset($networks[$identifier])) {
                throw new ValidationException('network_missing');
            }

            $candidate = ScopeConfiguration::normalizeNetworkRow([
                'id' => $identifier,
                'interface' => (string) ($_POST['network_interface'] ?? ''),
                'lists' => is_array($_POST['network_lists'] ?? null)
                    ? $_POST['network_lists']
                    : [],
                'allowed_domains' => sinkholeScopeEditorAllowedDomains(
                    (string) ($_POST['network_allowed_domains'] ?? ''),
                ),
                'enabled' => isset($_POST['network_enabled']),
            ], $interfaces, $lists);

            foreach ($networks as $otherIdentifier => $network) {
                if (
                    $otherIdentifier !== $identifier
                    && $network['interface'] === $candidate['interface']
                ) {
                    throw new ValidationException('network_interface_duplicated');
                }
            }

            if ($repairing) {
                $invalidNetworks = array_values(array_filter(
                    $invalidNetworks,
                    static fn(array $row): bool => $row['position'] !== $invalidPosition,
                ));
            }

            $networks[$identifier] = $candidate;
        } elseif ($scopeType === 'device' && isset($_POST['save_device'])) {
            if (
                $identifier === ''
                || preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1
                || ($repairing && isset($devices[$identifier]))
            ) {
                $identifier = ScopeConfiguration::generateIdentifier();
            } elseif (!isset($devices[$identifier])) {
                throw new ValidationException('device_missing');
            }

            $type = (string) ($_POST['device_identifier_type'] ?? '');
            $deviceIdentifier = (string) ($_POST['device_identifier'] ?? '');
            $mappingInterface = '';

            if ($type === ScopeConfiguration::DEVICE_STATIC_MAPPING) {
                $mappingParts = explode('|', (string) ($_POST['device_static_mapping'] ?? ''), 2);

                if (count($mappingParts) !== 2) {
                    throw new ValidationException('select_dhcp_static_mapping');
                }

                [$mappingInterface, $deviceIdentifier] = $mappingParts;
            }

            $candidate = ScopeConfiguration::normalizeDeviceRow([
                'id' => $identifier,
                'descr' => (string) ($_POST['device_name'] ?? ''),
                'identifier_type' => $type,
                'identifier' => $deviceIdentifier,
                'interface' => $mappingInterface,
                'lists' => is_array($_POST['device_lists'] ?? null)
                    ? $_POST['device_lists']
                    : [],
                'allowed_domains' => sinkholeScopeEditorAllowedDomains(
                    (string) ($_POST['device_allowed_domains'] ?? ''),
                ),
                'enabled' => isset($_POST['device_enabled']),
            ], $staticMappings, $lists);
            $candidateKey = ScopeConfiguration::deviceIdentifierKey($candidate);

            foreach ($devices as $otherIdentifier => $device) {
                if (
                    $otherIdentifier !== $identifier
                    && ScopeConfiguration::deviceIdentifierKey($device) === $candidateKey
                ) {
                    throw new ValidationException('device_identifier_duplicated');
                }
            }

            if ($repairing) {
                $invalidDevices = array_values(array_filter(
                    $invalidDevices,
                    static fn(array $row): bool => $row['position'] !== $invalidPosition,
                ));
            }

            $devices[$identifier] = $candidate;
        } else {
            throw new ValidationException('invalid_scope_type_unknown');
        }

        sinkholeScopeEditorApply($networks, $devices, $invalidNetworks, $invalidDevices);
        header('Location: sinkhole-scopes.php?saved=1');
        exit;
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
        $knownIdentifiers = ($scopeType === 'network') ? $networks : $devices;
        $identifier = (
            $invalidPosition === null
            && isset($knownIdentifiers[$submittedIdentifier])
        ) ? $submittedIdentifier : '';

        if ($scopeType === 'network') {
            $editing = [
                'id' => $identifier,
                'interface' => (string) ($_POST['network_interface'] ?? ''),
                'lists' => is_array($_POST['network_lists'] ?? null) ? $_POST['network_lists'] : [],
                'allowed_domains' => preg_split('/\R/u', (string) ($_POST['network_allowed_domains'] ?? '')) ?: [],
                'enabled' => isset($_POST['network_enabled']),
            ];
        } else {
            $postedType = (string) (
                $_POST['device_identifier_type'] ?? ScopeConfiguration::DEVICE_IP
            );
            $postedIdentifier = (string) ($_POST['device_identifier'] ?? '');
            $postedInterface = '';

            if ($postedType === ScopeConfiguration::DEVICE_STATIC_MAPPING) {
                $mappingParts = explode(
                    '|',
                    (string) ($_POST['device_static_mapping'] ?? ''),
                    2,
                );

                if (count($mappingParts) === 2) {
                    [$postedInterface, $postedIdentifier] = $mappingParts;
                }
            }

            $editing = [
                'id' => $identifier,
                'name' => (string) ($_POST['device_name'] ?? ''),
                'identifier_type' => $postedType,
                'identifier' => $postedIdentifier,
                'interface' => $postedInterface,
                'lists' => is_array($_POST['device_lists'] ?? null) ? $_POST['device_lists'] : [],
                'allowed_domains' => preg_split('/\R/u', (string) ($_POST['device_allowed_domains'] ?? '')) ?: [],
                'enabled' => isset($_POST['device_enabled']),
            ];
        }
    }
}

$listOptions = [];

foreach ($lists as $listIdentifier => $list) {
    $listOptions[$listIdentifier] = $list['name'];
}

$mappingOptions = [];

foreach ($staticMappings as $mapping) {
    try {
        $mac = ScopeConfiguration::normalizeMacAddress((string) ($mapping['mac'] ?? ''));
    } catch (InvalidArgumentException) {
        continue;
    }

    $mappingInterface = (string) ($mapping['interface'] ?? '');
    $mappingName = trim((string) ($mapping['hostname'] ?? ''));

    if ($mappingName === '') {
        $mappingName = trim((string) ($mapping['descr'] ?? ''));
    }

    $mappingLabel = ($interfaces[$mappingInterface] ?? $mappingInterface) . ' — '
        . $mappingName
        . ' — ' . (string) ($mapping['ipaddr'] ?? '')
        . ' — ' . $mac;
    $mappingOptions[$mappingInterface . '|' . $mac] = $mappingLabel;
}

$isEditing = $isEditMode;
$pgtitle = [
    gettext('Firewall'),
    'Sinkhole',
    pfsensePackageSinkholeTranslate('scopes'),
    $isEditing ? pfsensePackageSinkholeTranslate('edit') : pfsensePackageSinkholeTranslate('add'),
];
$pglinks = [
    '',
    '/pkg_edit.php?xml=sinkhole.xml&id=0',
    '/sinkhole-scopes.php',
    '@self',
];

include('head.inc');
display_top_tabs(pfsensePackageSinkholeTabs('scopes'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

if ($scopeType === 'network') {
    $networkIdentifier = is_array($editing) && is_string($editing['id'] ?? null)
        ? $editing['id']
        : '';
    $networkInterface = is_array($editing) && is_string($editing['interface'] ?? null)
        ? $editing['interface']
        : '';
    $interfaceOptions = [];

    foreach ($interfaces as $interfaceKey => $interfaceDescription) {
        $assignedElsewhere = false;

        foreach ($networks as $otherIdentifier => $network) {
            if ($otherIdentifier !== $networkIdentifier && $network['interface'] === $interfaceKey) {
                $assignedElsewhere = true;
                break;
            }
        }

        if (!$assignedElsewhere || $interfaceKey === $networkInterface) {
            $interfaceOptions[$interfaceKey] = $interfaceDescription;
        }
    }

    if ($networkInterface === '' || !isset($interfaceOptions[$networkInterface])) {
        if (isset($interfaceOptions['lan'])) {
            $networkInterface = 'lan';
        } else {
            foreach (array_keys($interfaceOptions) as $interfaceKey) {
                if (strtolower($interfaceKey) !== 'wan') {
                    $networkInterface = $interfaceKey;
                    break;
                }
            }

            $networkInterface = ($networkInterface !== '')
                ? $networkInterface
                : (string) (array_key_first($interfaceOptions) ?? '');
        }
    }

    $networkLists = ScopeConfiguration::unwrapRepeatedItems($editing['lists'] ?? []);
    $networkLists = is_array($networkLists) ? array_values($networkLists) : [];
    $networkAllowed = ScopeConfiguration::unwrapRepeatedItems($editing['allowed_domains'] ?? []);
    $networkAllowed = is_array($networkAllowed) ? array_values($networkAllowed) : [];
    $saveButton = new Form_Button(
        'save_network',
        pfsensePackageSinkholeTranslateMapped('form_action', $isEditing ? 'edit' : 'add'),
        null,
        'fa-solid fa-save',
    );
    $saveButton->addClass('btn-primary');
    $form = new Form($saveButton);
    $section = new Form_Section(pfsensePackageSinkholeTranslateMapped(
        'network_form',
        $isEditing ? 'edit' : 'add',
    ));
    $form->addGlobal(new Form_Input('scope_type', null, 'hidden', 'network'));
    $form->addGlobal(new Form_Input('scope_id', null, 'hidden', $networkIdentifier));
    $form->addGlobal(new Form_Input(
        'invalid_position',
        null,
        'hidden',
        ($invalidPosition === null) ? '' : (string) $invalidPosition,
    ));
    $section->addInput(new Form_Select(
        'network_interface',
        '*' . pfsensePackageSinkholeTranslate('interface'),
        $networkInterface,
        $interfaceOptions,
    ));
    $section->addInput(new Form_Select(
        'network_lists',
        pfsensePackageSinkholeTranslate('lists'),
        $networkLists,
        $listOptions,
        true,
    ));
    $allowedInput = new Form_Textarea(
        'network_allowed_domains',
        pfsensePackageSinkholeTranslate('allowed_domains'),
        ($networkAllowed === []) ? '' : implode(PHP_EOL, $networkAllowed) . PHP_EOL,
    );
    $allowedInput->setRows(6);
    $allowedInput->setHelp(pfsensePackageSinkholeTranslate('allowed_domains_help'));
    $section->addInput($allowedInput);
    $section->addInput(new Form_Checkbox(
        'network_enabled',
        pfsensePackageSinkholeTranslate('enabled'),
        pfsensePackageSinkholeTranslate('use_network_scope'),
        !$isEditing || (($editing['enabled'] ?? '') === true || ($editing['enabled'] ?? '') === 'on'),
    ));
    $form->add($section);
    print($form);
} else {
    $deviceType = is_array($editing) && is_string($editing['identifier_type'] ?? null)
        ? $editing['identifier_type']
        : ScopeConfiguration::DEVICE_IP;
    $deviceIdentifier = is_array($editing) && is_string($editing['identifier'] ?? null)
        ? $editing['identifier']
        : '';
    $deviceInterface = is_array($editing) && is_string($editing['interface'] ?? null)
        ? $editing['interface']
        : '';
    $mappingSelection = ($deviceType === ScopeConfiguration::DEVICE_STATIC_MAPPING)
        ? $deviceInterface . '|' . $deviceIdentifier
        : '';

    if ($mappingSelection !== '' && !isset($mappingOptions[$mappingSelection])) {
        $mappingOptions[$mappingSelection] = pfsensePackageSinkholeTranslate('unavailable_mapping')
            . ' — ' . ($interfaces[$deviceInterface] ?? $deviceInterface)
            . ' — ' . $deviceIdentifier;
    }

    $deviceLists = ScopeConfiguration::unwrapRepeatedItems($editing['lists'] ?? []);
    $deviceLists = is_array($deviceLists) ? array_values($deviceLists) : [];
    $deviceAllowed = ScopeConfiguration::unwrapRepeatedItems($editing['allowed_domains'] ?? []);
    $deviceAllowed = is_array($deviceAllowed) ? array_values($deviceAllowed) : [];
    $saveButton = new Form_Button(
        'save_device',
        pfsensePackageSinkholeTranslateMapped('form_action', $isEditing ? 'edit' : 'add'),
        null,
        'fa-solid fa-save',
    );
    $saveButton->addClass('btn-primary');
    $form = new Form($saveButton);
    $section = new Form_Section(pfsensePackageSinkholeTranslateMapped(
        'device_form',
        $isEditing ? 'edit' : 'add',
    ));
    $form->addGlobal(new Form_Input('scope_type', null, 'hidden', 'device'));
    $form->addGlobal(new Form_Input(
        'scope_id',
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
        'device_name',
        '*' . pfsensePackageSinkholeTranslate('name'),
        'text',
        is_array($editing) ? (string) ($editing['name'] ?? '') : '',
    ));
    $section->addInput(new Form_Select(
        'device_identifier_type',
        '*' . pfsensePackageSinkholeTranslate('identified_by'),
        $deviceType,
        [
            ScopeConfiguration::DEVICE_IP => pfsensePackageSinkholeTranslate('ip_address'),
            ScopeConfiguration::DEVICE_STATIC_MAPPING => pfsensePackageSinkholeTranslate('dhcp_static_mapping'),
            ScopeConfiguration::DEVICE_MAC => pfsensePackageSinkholeTranslate('mac_address'),
        ],
    ));
    $identifierInput = new Form_Input(
        'device_identifier',
        ($deviceType === ScopeConfiguration::DEVICE_MAC)
            ? '*' . pfsensePackageSinkholeTranslate('mac_address')
            : '*' . pfsensePackageSinkholeTranslate('ip_address'),
        'text',
        ($deviceType === ScopeConfiguration::DEVICE_STATIC_MAPPING) ? '' : $deviceIdentifier,
    );
    $identifierInput->setHelp(pfsensePackageSinkholeTranslate('device_identifier_help'));
    $section->addInput($identifierInput);
    $section->addInput(new Form_Select(
        'device_static_mapping',
        '*' . pfsensePackageSinkholeTranslate('dhcp_static_mapping'),
        $mappingSelection,
        $mappingOptions,
    ));
    $section->addInput(new Form_Select(
        'device_lists',
        pfsensePackageSinkholeTranslate('lists'),
        $deviceLists,
        $listOptions,
        true,
    ));
    $allowedInput = new Form_Textarea(
        'device_allowed_domains',
        pfsensePackageSinkholeTranslate('allowed_domains'),
        ($deviceAllowed === []) ? '' : implode(PHP_EOL, $deviceAllowed) . PHP_EOL,
    );
    $allowedInput->setRows(6);
    $allowedInput->setHelp(pfsensePackageSinkholeTranslate('allowed_domains_help'));
    $section->addInput($allowedInput);
    $section->addInput(new Form_Checkbox(
        'device_enabled',
        pfsensePackageSinkholeTranslate('enabled'),
        pfsensePackageSinkholeTranslate('use_device_scope'),
        !$isEditing || (($editing['enabled'] ?? '') === true || ($editing['enabled'] ?? '') === 'on'),
    ));
    $form->add($section);
    print($form);
?>
<script type="text/javascript">
//<![CDATA[
events.push(function() {
	function updateDeviceIdentifierInputs() {
		var identifierType = $('#device_identifier_type').val();
		var usesStaticMapping = identifierType === <?=json_encode(ScopeConfiguration::DEVICE_STATIC_MAPPING)?>;
		var identifierLabel = identifierType === <?=json_encode(ScopeConfiguration::DEVICE_MAC)?>
			? <?=json_encode(pfsensePackageSinkholeTranslate('mac_address'))?>
			: <?=json_encode(pfsensePackageSinkholeTranslate('ip_address'))?>;

		hideInput('device_identifier', usesStaticMapping);
		hideInput('device_static_mapping', !usesStaticMapping);
		$('#device_identifier').closest('.form-group').find('.element-required').first().text(identifierLabel);
	}

	updateDeviceIdentifierInputs();
	$('#device_identifier_type').change(updateDeviceIdentifierInputs);
});
//]]>
</script>
<?php
}

include('foot.inc');
