<?php

declare(strict_types=1);

/*
 * Sinkhole Bypass List editor.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-bypass-edit
##|*NAME=Firewall: Sinkhole: Bypass: Edit
##|*DESCR=Allow access to the Sinkhole Bypass List editor.
##|*MATCH=sinkhole-bypass_edit.php*
##|-PRIV

use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\ListConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/BypassConfiguration.php');
require_once('/usr/local/pkg/sinkhole/ListConfiguration.php');

/** @since 1.0.0 */
function sinkholeBypassEditorRequireRepair(array $bypass, array $redirect): void
{
    $invalidValues = array_merge(
        $redirect['invalid_values'],
        $redirect['invalid_exemptions'],
        $bypass['invalid_values'],
    );

    if ($invalidValues === []) {
        return;
    }

    $invalid = $invalidValues[0];

    throw new ValidationException(
        $invalid['reason_key'],
        $invalid['reason_arguments'] ?? [],
    );
}

/** @since 1.0.0 */
function sinkholeBypassEditorRedirectRecord(array $configuration): array
{
    return [
        'enabled' => $configuration['enabled'],
        'interfaces' => $configuration['interfaces'],
        'exempt_sources' => $configuration['exempt_sources'],
        'exempt_destinations' => $configuration['exempt_destinations'],
    ];
}

$configuration = pfsensePackageSinkholeGetBypassConfiguration();
$redirect = pfsensePackageSinkholeGetRedirectConfiguration();
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
                    'kind' => $invalidRow['kind'],
                    'enabled' => $invalidRow['enabled'],
                ];
                $identifier = '';
                break;
            }
        }

        if ($editing === null) {
            throw new ValidationException('invalid_bypass_list_row_missing');
        }
    } elseif ($identifier !== '') {
        $editing = $lists[$identifier] ?? null;

        if ($editing === null) {
            throw new ValidationException('bypass_list_missing');
        }
    }
} catch (Throwable $throwable) {
    $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
    $actionClass = 'danger';
    $identifier = '';
    $invalidPosition = null;
}

$isEditMode = $identifier !== '' || $invalidPosition !== null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_bypass_list'])) {
    $submittedIdentifier = $identifier;

    try {
        sinkholeBypassEditorRequireRepair($configuration, $redirect);
        $isInvalidEdit = $invalidPosition !== null;
        $isNew = $identifier === '' && !$isInvalidEdit;

        if ($isInvalidEdit) {
            $matchingRows = array_values(array_filter(
                $invalidRows,
                static fn(array $invalidRow): bool => $invalidRow['position'] === $invalidPosition,
            ));

            if (count($matchingRows) !== 1) {
                throw new ValidationException('invalid_bypass_list_row_missing');
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
            throw new ValidationException('bypass_list_missing');
        }

        $row = BypassConfiguration::normalizeListRow(
            $identifier,
            (string) ($_POST['list_name'] ?? ''),
            (string) ($_POST['list_url'] ?? ''),
            isset($_POST['list_enabled']),
            (string) ($_POST['list_kind'] ?? ''),
        );
        $lists[$identifier] = $row;

        if ($isInvalidEdit) {
            $invalidRows = array_values(array_filter(
                $invalidRows,
                static fn(array $invalidRow): bool => $invalidRow['position'] !== $invalidPosition,
            ));
        }

        pfsensePackageSinkholeSaveBypass(
            pfsensePackageSinkholeBypassStorage(
                $configuration,
                $lists,
                $invalidRows,
            ),
            sinkholeBypassEditorRedirectRecord($redirect),
        );
        header('Location: sinkhole-bypass.php?saved=1');
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
            'kind' => (string) ($_POST['list_kind'] ?? BypassConfiguration::KIND_ENCRYPTED_DNS),
            'enabled' => isset($_POST['list_enabled']),
        ];
    }
}

$isEditing = $isEditMode;
$pgtitle = [
    gettext('Firewall'),
    'Sinkhole',
    pfsensePackageSinkholeTranslate('bypass'),
    $isEditing ? pfsensePackageSinkholeTranslate('edit') : pfsensePackageSinkholeTranslate('add'),
];
$pglinks = [
    '',
    '/pkg_edit.php?xml=sinkhole.xml&id=0',
    '/sinkhole-bypass.php',
    '@self',
];

include('head.inc');

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

display_top_tabs(pfsensePackageSinkholeTabs('bypass'));

$button = new Form_Button(
    'save_bypass_list',
    pfsensePackageSinkholeTranslateMapped('form_action', $isEditing ? 'edit' : 'add'),
    null,
    'fa-solid fa-save',
);
$button->addClass('btn-primary');
$form = new Form($button);
$section = new Form_Section(pfsensePackageSinkholeTranslateMapped(
    'bypass_list_form',
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
$section->addInput(new Form_Select(
    'list_kind',
    '*' . pfsensePackageSinkholeTranslate('kind'),
    is_array($editing)
        ? (string) ($editing['kind'] ?? BypassConfiguration::KIND_ENCRYPTED_DNS)
        : BypassConfiguration::KIND_ENCRYPTED_DNS,
    [
        BypassConfiguration::KIND_ENCRYPTED_DNS => pfsensePackageSinkholeTranslate('encrypted_dns'),
        BypassConfiguration::KIND_TOR => pfsensePackageSinkholeTranslate('tor'),
        BypassConfiguration::KIND_VPN => pfsensePackageSinkholeTranslate('vpn'),
    ],
));
$urlInput = new Form_Input(
    'list_url',
    '*' . pfsensePackageSinkholeTranslate('url'),
    'url',
    is_array($editing) ? (string) ($editing['url'] ?? '') : '',
);
$urlInput->setHelp(pfsensePackageSinkholeTranslate('bypass_list_url_help'));
$section->addInput($urlInput);
$section->addInput(new Form_Checkbox(
    'list_enabled',
    pfsensePackageSinkholeTranslate('enabled'),
    pfsensePackageSinkholeTranslate('bypass_list_enabled_help'),
    $isEditing
        && (($editing['enabled'] ?? false) === true || ($editing['enabled'] ?? '') === 'on'),
));
$form->add($section);
print($form);

include('foot.inc');
