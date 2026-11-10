<?php

declare(strict_types=1);

/*
 * Sinkhole IP-list editor.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-ip-edit
##|*NAME=Firewall: Sinkhole: IP: Edit
##|*DESCR=Allow access to the Sinkhole IP-list editor.
##|*MATCH=sinkhole-ip_edit.php*
##|-PRIV

use PfSense\Sinkhole\Domain\IpConfiguration;
use PfSense\Sinkhole\Domain\ListConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/IpConfiguration.php');
require_once('/usr/local/pkg/sinkhole/ListConfiguration.php');

/** @since 1.0.0 */
function sinkholeIpEditorRequireSettingsRepair(array $configuration): void
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
function sinkholeIpEditorStorage(
    array $configuration,
    array $lists,
    array $invalidRows,
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

    return [
        'enabled' => $configuration['enabled'] ? 'on' : '',
        'interfaces' => ['item' => array_values($configuration['stored_interfaces'])],
        'directions' => ['item' => array_values($configuration['stored_directions'])],
        'lists' => ['item' => $rows],
        'countries' => ['item' => array_values($configuration['stored_countries'])],
        'account_id' => $configuration['account_id'],
        'license_key' => $configuration['license_key'],
        'allowlist' => ['item' => array_values($configuration['stored_allowlist'])],
    ];
}

$configuration = pfsensePackageSinkholeGetIpConfiguration();
$lists = $configuration['lists'];
$invalidRows = $configuration['invalid_lists'];
$identifier = trim((string) ($_POST['list_id'] ?? $_GET['id'] ?? ''));
$invalidPosition = isset($_POST['invalid_position'])
    && (string) $_POST['invalid_position'] !== ''
    ? (int) $_POST['invalid_position']
    : (isset($_GET['invalid_position']) ? (int) $_GET['invalid_position'] : null);
$actionMessage = null;
$actionClass = 'info';
$editing = null;

try {
    if ($invalidPosition !== null) {
        foreach ($invalidRows as $invalidRow) {
            if ($invalidRow['position'] === $invalidPosition) {
                $editing = [
                    'id' => $invalidRow['id'],
                    'name' => $invalidRow['name'],
                    'url' => $invalidRow['url'],
                    'family' => $invalidRow['family'],
                    'enabled' => $invalidRow['enabled'],
                ];
                $identifier = '';
                break;
            }
        }

        if ($editing === null) {
            throw new ValidationException('invalid_ip_list_row_missing');
        }
    } elseif ($identifier !== '') {
        $editing = $lists[$identifier] ?? null;

        if ($editing === null) {
            throw new ValidationException('ip_list_missing');
        }
    }
} catch (Throwable $throwable) {
    $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
    $actionClass = 'danger';
    $identifier = '';
    $invalidPosition = null;
}

$isEditMode = $identifier !== '' || $invalidPosition !== null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_ip_list'])) {
    $submittedIdentifier = $identifier;

    try {
        sinkholeIpEditorRequireSettingsRepair($configuration);
        $isInvalidEdit = $invalidPosition !== null;
        $isNew = $identifier === '' && !$isInvalidEdit;

        if ($isInvalidEdit) {
            $matchingRows = array_values(array_filter(
                $invalidRows,
                static fn(array $invalidRow): bool => $invalidRow['position'] === $invalidPosition,
            ));

            if (count($matchingRows) !== 1) {
                throw new ValidationException('invalid_ip_list_row_missing');
            }
        }

        if (
            $identifier === ''
            || preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1
            || ($isInvalidEdit && isset($lists[$identifier]))
        ) {
            $identifier = ListConfiguration::generateIdentifier();
        }

        if (!$isNew && !$isInvalidEdit && !isset($lists[$identifier])) {
            throw new ValidationException('ip_list_missing');
        }

        $family = (string) ($_POST['list_family'] ?? '');

        if (!in_array($family, IpConfiguration::FAMILIES, true)) {
            throw new ValidationException('ip_list_family_invalid');
        }

        $row = ListConfiguration::normalizeRow(
            $identifier,
            (string) ($_POST['list_name'] ?? ''),
            (string) ($_POST['list_url'] ?? ''),
            isset($_POST['list_enabled']),
        );
        unset($row['global']);
        $row['family'] = $family;
        $lists[$identifier] = $row;

        if ($isInvalidEdit) {
            $invalidRows = array_values(array_filter(
                $invalidRows,
                static fn(array $invalidRow): bool => $invalidRow['position'] !== $invalidPosition,
            ));
        }

        pfsensePackageSinkholeSaveIp(sinkholeIpEditorStorage($configuration, $lists, $invalidRows));
        header('Location: sinkhole-ip.php?saved=1');
        exit;
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
        $identifier = (
            $invalidPosition === null
            && isset($lists[$submittedIdentifier])
        ) ? $submittedIdentifier : '';
        $editing = [
            'id' => $identifier,
            'name' => (string) ($_POST['list_name'] ?? ''),
            'url' => (string) ($_POST['list_url'] ?? ''),
            'family' => (string) ($_POST['list_family'] ?? 'both'),
            'enabled' => isset($_POST['list_enabled']),
        ];
    }
}

$isEditing = $isEditMode;
$pgtitle = [
    gettext('Firewall'),
    'Sinkhole',
    pfsensePackageSinkholeTranslate('ip'),
    $isEditing ? pfsensePackageSinkholeTranslate('edit') : pfsensePackageSinkholeTranslate('add'),
];
$pglinks = [
    '',
    '/pkg_edit.php?xml=sinkhole.xml&id=0',
    '/sinkhole-ip.php',
    '@self',
];

include('head.inc');
display_top_tabs(pfsensePackageSinkholeTabs('ip'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

$button = new Form_Button(
    'save_ip_list',
    pfsensePackageSinkholeTranslateMapped('form_action', $isEditing ? 'edit' : 'add'),
    null,
    'fa-solid fa-save',
);
$button->addClass('btn-primary');
$form = new Form($button);
$section = new Form_Section(pfsensePackageSinkholeTranslateMapped(
    'ip_list_form',
    $isEditing ? 'edit' : 'add',
));
$form->addGlobal(new Form_Input(
    'list_id',
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
$nameInput = new Form_Input(
    'list_name',
    '*' . pfsensePackageSinkholeTranslate('name'),
    'text',
    is_array($editing) ? (string) ($editing['name'] ?? '') : '',
);
$nameInput->setHelp(pfsensePackageSinkholeTranslate('block_list_name_help'));
$section->addInput($nameInput);
$urlInput = new Form_Input(
    'list_url',
    '*' . pfsensePackageSinkholeTranslate('url'),
    'url',
    is_array($editing) ? (string) ($editing['url'] ?? '') : '',
);
$urlInput->setHelp(pfsensePackageSinkholeTranslate('block_list_url_help'));
$section->addInput($urlInput);
$section->addInput(new Form_Select(
    'list_family',
    '*' . pfsensePackageSinkholeTranslate('family'),
    is_array($editing) ? (string) ($editing['family'] ?? 'both') : 'both',
    [
        'ipv4' => pfsensePackageSinkholeTranslate('ipv4'),
        'ipv6' => pfsensePackageSinkholeTranslate('ipv6'),
        'both' => pfsensePackageSinkholeTranslate('both_families'),
    ],
));
$section->addInput(new Form_Checkbox(
    'list_enabled',
    pfsensePackageSinkholeTranslate('enabled'),
    pfsensePackageSinkholeTranslate('ip_list_enabled_help'),
    !$isEditing || ($editing['enabled'] ?? false) === true || ($editing['enabled'] ?? '') === 'on',
));
$form->add($section);
print($form);

include('foot.inc');
