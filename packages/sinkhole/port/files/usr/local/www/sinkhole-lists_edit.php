<?php

declare(strict_types=1);

/*
 * Sinkhole block-list editor.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-lists-edit
##|*NAME=Firewall: Sinkhole: Lists: Edit
##|*DESCR=Allow access to the Sinkhole block-list editor.
##|*MATCH=sinkhole-lists_edit.php*
##|-PRIV

use PfSense\Sinkhole\Domain\ListConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/ListConfiguration.php');

/**
 * Sinkhole List Editor - Apply Configuration.
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
function sinkholeListEditorApply(
    array $lists,
    array $allowedDomains,
    array $invalidRows,
): void {
    pfsensePackageSinkholeSaveLists($lists, $allowedDomains, $invalidRows);
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
}

$configuration = pfsensePackageSinkholeGetListConfiguration();
$lists = $configuration['lists'];
$invalidRows = $configuration['invalid_rows'];
$allowedDomains = pfsensePackageSinkholeGetAllowedDomains();
$actionMessage = null;
$actionClass = 'info';
$identifier = trim((string) ($_POST['list_id'] ?? $_GET['id'] ?? ''));
$invalidPosition = isset($_POST['invalid_position'])
    && (string) $_POST['invalid_position'] !== ''
    ? (int) $_POST['invalid_position']
    : (isset($_GET['invalid_position']) ? (int) $_GET['invalid_position'] : null);
$editing = null;

try {
    if ($invalidPosition !== null) {
        $matchingRows = array_values(array_filter(
            $invalidRows,
            static fn(array $invalidRow): bool => $invalidRow['position'] === $invalidPosition,
        ));

        if (count($matchingRows) !== 1) {
            throw new ValidationException('invalid_block_list_row_missing');
        }

        $editing = $matchingRows[0];
        $identifier = '';
    } elseif ($identifier !== '') {
        $editing = $lists[$identifier] ?? null;

        if ($editing === null) {
            throw new ValidationException('block_list_missing');
        }
    }
} catch (Throwable $throwable) {
    $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
    $actionClass = 'danger';
    $identifier = '';
    $invalidPosition = null;
}

$isEditMode = $identifier !== '' || $invalidPosition !== null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_list'])) {
    $submittedIdentifier = $identifier;

    try {
        $isInvalidEdit = $invalidPosition !== null;
        $isNew = $identifier === '' && $isInvalidEdit === false;

        if ($isInvalidEdit) {
            $matchingRows = array_values(array_filter(
                $invalidRows,
                static fn(array $invalidRow): bool => $invalidRow['position'] === $invalidPosition,
            ));

            if (count($matchingRows) !== 1) {
                throw new ValidationException('invalid_block_list_row_missing');
            }
        }

        if (
            $identifier === ''
            || preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1
            || ($isInvalidEdit && isset($lists[$identifier]))
        ) {
            $identifier = ListConfiguration::generateIdentifier();
        }

        if ($isNew === false && $isInvalidEdit === false && isset($lists[$identifier]) === false) {
            throw new ValidationException('block_list_missing');
        }

        $row = ListConfiguration::normalizeRow(
            $identifier,
            (string) ($_POST['list_name'] ?? ''),
            (string) ($_POST['list_url'] ?? ''),
            isset($_POST['list_enabled']),
            isset($_POST['list_global']),
        );

        if ($isInvalidEdit) {
            $invalidRows = array_values(array_filter(
                $invalidRows,
                static fn(array $invalidRow): bool => $invalidRow['position'] !== $invalidPosition,
            ));
        }

        $lists[$identifier] = $row;
        sinkholeListEditorApply($lists, $allowedDomains, $invalidRows);
        header('Location: sinkhole-lists.php?saved=1');
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
            'enabled' => isset($_POST['list_enabled']),
            'global' => isset($_POST['list_global']),
        ];
    }
}

$pgtitle = [
    gettext('Firewall'),
    'Sinkhole',
    pfsensePackageSinkholeTranslate('lists'),
    $isEditMode ? pfsensePackageSinkholeTranslate('edit') : pfsensePackageSinkholeTranslate('add'),
];
$pglinks = [
    '',
    '/pkg_edit.php?xml=sinkhole.xml&id=0',
    '/sinkhole-lists.php',
    '@self',
];

include('head.inc');

display_top_tabs(pfsensePackageSinkholeTabs('lists'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

$saveButton = new Form_Button(
    'save_list',
    pfsensePackageSinkholeTranslateMapped(
        'form_action',
        $isEditMode ? 'edit' : 'add',
    ),
    null,
    'fa-solid fa-save',
);
$saveButton->addClass('btn-primary');
$form = new Form($saveButton);
$section = new Form_Section(pfsensePackageSinkholeTranslateMapped(
    'list_form',
    $isEditMode ? 'edit' : 'add',
));
$identifierInput = new Form_Input(
    'list_id',
    null,
    'hidden',
    ($editing === null) ? '' : (string) ($editing['id'] ?? ''),
);
$invalidPositionInput = new Form_Input(
    'invalid_position',
    null,
    'hidden',
    ($invalidPosition === null) ? '' : (string) $invalidPosition,
);
$nameInput = new Form_Input(
    'list_name',
    '*' . pfsensePackageSinkholeTranslate('name'),
    'text',
    ($editing === null) ? '' : $editing['name'],
);
$urlInput = new Form_Input(
    'list_url',
    '*' . pfsensePackageSinkholeTranslate('url'),
    'url',
    ($editing === null) ? '' : $editing['url'],
);
$enabledInput = new Form_Checkbox(
    'list_enabled',
    pfsensePackageSinkholeTranslate('enabled'),
    pfsensePackageSinkholeTranslate('block_list_enabled_help'),
    ($editing === null) ? true : $editing['enabled'],
);
$globalInput = new Form_Checkbox(
    'list_global',
    pfsensePackageSinkholeTranslate('global'),
    pfsensePackageSinkholeTranslate('block_list_global_help'),
    ($editing === null) ? true : $editing['global'],
);

$nameInput->setHelp(pfsensePackageSinkholeTranslate('block_list_name_help'));
$urlInput->setHelp(pfsensePackageSinkholeTranslate('block_list_url_help'));
$section->addInput($nameInput);
$section->addInput($urlInput);
$section->addInput($enabledInput);
$section->addInput($globalInput);
$form->addGlobal($identifierInput);
$form->addGlobal($invalidPositionInput);
$form->add($section);

print($form);

include('foot.inc');
