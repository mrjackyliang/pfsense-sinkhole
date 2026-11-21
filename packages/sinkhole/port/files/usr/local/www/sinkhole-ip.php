<?php

declare(strict_types=1);

/*
 * Sinkhole IP and country blocking configuration page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-ip
##|*NAME=Firewall: Sinkhole: IP
##|*DESCR=Allow access to Sinkhole IP and country blocking settings.
##|*MATCH=sinkhole-ip.php*
##|-PRIV

use PfSense\Sinkhole\Domain\IpConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;
use PfSense\Sinkhole\Runtime\Context;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/Context.php');
require_once('/usr/local/pkg/sinkhole/IpConfiguration.php');

/** @since 1.0.0 */
function sinkholeIpLines(mixed $value, string $errorKey): array
{
    if (!is_string($value)) {
        throw new ValidationException($errorKey);
    }

    $lines = preg_split('/\r\n|\r|\n/', $value);

    if (!is_array($lines)) {
        throw new ValidationException($errorKey);
    }

    return array_values(array_filter(
        array_map('trim', $lines),
        static fn(string $line): bool => $line !== '',
    ));
}

/**
 * Sinkhole IP - Context Settings.
 *
 * Reads the exact settings saved for one context through the IP API, so a
 * network or device without its own row returns null instead of inherited values.
 *
 * @param string $context - Context key.
 *
 * @return array|null
 *
 * @since 1.3.0
 */
function sinkholeIpContextSettings(string $context): ?array
{
    $section = pfsensePackageSinkholeAdapter()->readConfigurationPath('installedpackages/sinkhole/ip', []);
    $contextRows = pfsensePackageSinkholeAdapter()->readConfigurationPath(
        'installedpackages/sinkhole/ip_contexts/item',
        [],
    );

    return IpConfiguration::forContext(
        is_array($section) ? $section : [],
        is_array($contextRows) ? $contextRows : [],
        $context,
    );
}

/**
 * Sinkhole IP - Persist.
 *
 * Writes the configuration changed through the IP API in one revision, then
 * applies it in the background.
 *
 * @return void
 *
 * @since 1.3.0
 */
function sinkholeIpPersist(): void
{
    pfsensePackageSinkholeAdapter()->saveConfiguration(pfsensePackageSinkholeTranslate('revision_saved_ip_blocking'));
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
}

/**
 * Sinkhole IP - Error Message.
 *
 * @param array $errors - Errors returned by the IP submission.
 *
 * @return string
 *
 * @since 1.3.0
 */
function sinkholeIpErrorMessage(array $errors): string
{
    $messages = [];

    foreach ($errors as $error) {
        if (is_array($error)) {
            $messages[] = pfsensePackageSinkholeInvalidReason($error);

            continue;
        }

        if ($error instanceof Throwable) {
            $messages[] = pfsensePackageSinkholeThrowableMessage($error);

            continue;
        }

        $errorText = (string) $error;

        try {
            $messages[] = pfsensePackageSinkholeTranslateMapped('validation', $errorText);
        } catch (Throwable) {
            $messages[] = $errorText;
        }
    }

    return implode(' ', $messages);
}

/**
 * Sinkhole IP - Field Label.
 *
 * Network and device rows can report fields that the shared field map does not
 * name, so an unknown key is shown as saved instead of failing the page.
 *
 * @param string $fieldKey - Invalid value field key.
 *
 * @return string
 *
 * @since 1.3.0
 */
function sinkholeIpFieldLabel(string $fieldKey): string
{
    try {
        return pfsensePackageSinkholeTranslateMapped('field', $fieldKey);
    } catch (Throwable) {
        return $fieldKey;
    }
}

/**
 * Sinkhole IP - List Selection.
 *
 * @param mixed $value - Saved or posted list identifiers.
 *
 * @return list<string>
 *
 * @since 1.3.0
 */
function sinkholeIpListSelection(mixed $value): array
{
    if (!is_array($value)) {
        return [];
    }

    if (count($value) === 1 && array_key_exists('item', $value)) {
        $value = is_array($value['item']) ? $value['item'] : [$value['item']];
    }

    $selection = [];

    foreach ($value as $key => $entry) {
        if (is_string($entry)) {
            $selection[] = $entry;
        } elseif (is_array($entry) && is_string($key)) {
            $selection[] = $key;
        }
    }

    return array_values(array_unique($selection));
}

/**
 * Sinkhole IP - Display Settings.
 *
 * @param array $settings - Settings returned by the IP API for one context.
 *
 * @return array{enabled: bool, interfaces: list<string>, directions: list<string>, countries: list<string>, account_id: string, license_key_set: bool, allowlist: list<string>, lists: list<string>}
 *
 * @since 1.3.0
 */
function sinkholeIpDisplaySettings(array $settings): array
{
    $accountIdentifier = $settings['account_id'] ?? '';

    return [
        'enabled' => ($settings['enabled'] ?? false) === true,
        'interfaces' => array_values($settings['stored_interfaces'] ?? $settings['interfaces'] ?? []),
        'directions' => array_values($settings['stored_directions'] ?? $settings['directions'] ?? []),
        'countries' => array_values($settings['stored_countries'] ?? $settings['countries'] ?? []),
        'account_id' => is_string($accountIdentifier) ? $accountIdentifier : '',
        'license_key_set' => ($settings['license_key_set'] ?? false) === true,
        'allowlist' => array_values($settings['stored_allowlist'] ?? $settings['allowlist'] ?? []),
        'lists' => sinkholeIpListSelection(
            $settings['stored_list_ids'] ?? $settings['list_ids'] ?? [],
        ),
    ];
}

/**
 * Sinkhole IP - Broader Label.
 *
 * Names the context whose settings apply while a network or device has none of
 * its own: a device follows the network it is on, and a network follows Global.
 *
 * @param string $context - Context key.
 * @param array $networks - Valid networks keyed by identifier.
 * @param array $devices - Valid devices keyed by identifier.
 * @param list<string> $contextKeys - Contexts with their own settings.
 *
 * @return string
 *
 * @since 1.3.0
 */
function sinkholeIpBroaderLabel(
    string $context,
    array $networks,
    array $devices,
    array $contextKeys,
): string {
    $parsed = Context::parse($context);

    if ($parsed !== null && $parsed['type'] === 'device') {
        $device = $devices[$parsed['id']] ?? [];
        $deviceInterfaces = [];

        foreach ($device['identifiers'] ?? [] as $identifier) {
            if (is_array($identifier) && (string) ($identifier['interface'] ?? '') !== '') {
                $deviceInterfaces[] = (string) $identifier['interface'];
            }
        }

        foreach ($networks as $networkIdentifier => $network) {
            $networkKey = 'network:' . $networkIdentifier;

            if (
                ($network['enabled'] ?? true) === true
                && in_array((string) ($network['interface'] ?? ''), $deviceInterfaces, true)
                && in_array($networkKey, $contextKeys, true)
            ) {
                return Context::label($networkKey, $networks, $devices);
            }
        }
    }

    return Context::label(Context::GLOBAL, $networks, $devices);
}

$adapter = pfsensePackageSinkholeAdapter();
$interfaces = $adapter->getConfiguredInterfaces();
$aliases = $adapter->getHostNetworkAliases();
$scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
$networks = $scopeConfiguration['networks'];
$devices = $scopeConfiguration['devices'];
$context = Context::current($networks, $devices, true);

Context::remember($context);

$contextType = Context::parse($context)['type'] ?? 'global';
$isAll = $context === Context::ALL;
$isGlobal = $context === Context::GLOBAL;
$configuration = pfsensePackageSinkholeGetIpConfiguration();
$lists = $configuration['lists'];
$contextSettings = ($isAll) ? null : sinkholeIpContextSettings($context);
$contextFields = ($isAll) ? [] : IpConfiguration::fieldsForContext($context);
$displaySettings = sinkholeIpDisplaySettings($contextSettings ?? []);
$actionMessage = ((string) ($_GET['saved'] ?? '') === '1')
    ? pfsensePackageSinkholeTranslate('ip_saved_applying')
    : null;
$actionClass = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $isAll === false) {
    try {
        if (isset($_POST['remove_context_settings'])) {
            if ($isGlobal === false) {
                IpConfiguration::removeContext($context);

                sinkholeIpPersist();

                $actionMessage = pfsensePackageSinkholeTranslate('bxpage_ip_removed');
                $actionClass = 'success';
            }
        } elseif (isset($_POST['save_ip_settings'])) {
            $displaySettings = array_replace($displaySettings, [
                'enabled' => isset($_POST['ip_enabled']),
                'interfaces' => is_array($_POST['ip_interfaces'] ?? null)
                    ? array_values(array_filter($_POST['ip_interfaces'], 'is_string'))
                    : [],
                'directions' => is_array($_POST['ip_directions'] ?? null)
                    ? array_values(array_filter($_POST['ip_directions'], 'is_string'))
                    : [],
                'countries' => sinkholeIpLines($_POST['ip_countries'] ?? '', 'ip_countries_invalid'),
                'allowlist' => sinkholeIpLines($_POST['ip_allowlist'] ?? '', 'ip_allowlist_invalid'),
                'lists' => sinkholeIpListSelection($_POST['ip_lists'] ?? []),
            ]);

            if ($isGlobal) {
                $displaySettings['account_id'] = is_string($_POST['maxmind_account_id'] ?? null)
                    ? $_POST['maxmind_account_id']
                    : '';
            }

            $submission = IpConfiguration::submitContext(
                $context,
                $_POST,
                $interfaces,
                $aliases,
            );

            if ($submission['errors'] !== []) {
                $actionMessage = sinkholeIpErrorMessage($submission['errors']);
                $actionClass = 'danger';
            } else {
                IpConfiguration::storeContext($context, $submission['settings']);

                sinkholeIpPersist();

                $actionMessage = pfsensePackageSinkholeTranslate('ip_saved_applying');
                $actionClass = 'success';
            }
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }

    if ($actionClass === 'success') {
        $configuration = pfsensePackageSinkholeGetIpConfiguration();
        $lists = $configuration['lists'];
        $contextSettings = sinkholeIpContextSettings($context);
        $displaySettings = sinkholeIpDisplaySettings($contextSettings ?? []);
    }
}

$hasOwnSettings = $isGlobal || $contextSettings !== null;
$contextKeys = IpConfiguration::contextKeys();
$overviewRows = [];

if ($isAll) {
    $overviewKeys = array_values(array_unique(array_merge([Context::GLOBAL], $contextKeys)));

    foreach ($overviewKeys as $overviewKey) {
        if (Context::parse($overviewKey) === null) {
            continue;
        }

        $overviewSettings = sinkholeIpContextSettings($overviewKey);

        if ($overviewSettings === null) {
            continue;
        }

        $overviewDisplay = sinkholeIpDisplaySettings($overviewSettings);
        $overviewDirections = array_map(
            static fn(string $overviewDirection): string => in_array($overviewDirection, IpConfiguration::DIRECTIONS, true)
                ? (($overviewDirection === 'inbound')
                    ? pfsensePackageSinkholeTranslate('inbound')
                    : pfsensePackageSinkholeTranslate('outbound'))
                : $overviewDirection,
            array_values(array_filter($overviewDisplay['directions'], 'is_string')),
        );
        $overviewRows[] = [
            'key' => $overviewKey,
            'label' => Context::label($overviewKey, $networks, $devices),
            'enabled' => $overviewDisplay['enabled'],
            'directions' => ($overviewDirections === [])
                ? pfsensePackageSinkholeTranslate('none')
                : implode(', ', $overviewDirections),
            'countries' => ($overviewDisplay['countries'] === [])
                ? pfsensePackageSinkholeTranslate('none')
                : implode(', ', $overviewDisplay['countries']),
            'lists' => count($overviewDisplay['lists']),
        ];
    }
}

$pgtitle = [gettext('Firewall'), 'Sinkhole', pfsensePackageSinkholeTranslate('ip')];
$pglinks = ['', '/pkg_edit.php?xml=sinkhole.xml&id=0', '@self'];
include('head.inc');
?>
<link rel="stylesheet" href="/css/sinkhole.css">
<?php
display_top_tabs(pfsensePackageSinkholeTabs('ip'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

print(Context::renderRow('sinkhole-ip.php', $context, $networks, $devices, true));

if ($isAll):
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bxpage_ip_overview'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bxpage_applies_to'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('directions'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('countries'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('ip_lists'))?></th>
					<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($overviewRows as $overviewRow): ?>
<?php $overviewUrl = 'sinkhole-ip.php?context=' . rawurlencode($overviewRow['key']); ?>
				<tr<?=($overviewRow['enabled']) ? '' : ' class="disabled"'?>>
					<td><a href="<?=htmlspecialchars($overviewUrl)?>"><?=htmlspecialchars($overviewRow['label'])?></a></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $overviewRow['enabled'] ? 'true' : 'false'))?></td>
					<td><?=htmlspecialchars($overviewRow['directions'])?></td>
					<td><?=htmlspecialchars($overviewRow['countries'])?></td>
					<td><?=htmlspecialchars((string) $overviewRow['lists'])?></td>
					<td class="text-nowrap">
						<a class="fa-solid fa-pencil" title="<?=htmlspecialchars(pfsensePackageSinkholeTranslate('edit'))?>" href="<?=htmlspecialchars($overviewUrl)?>"></a>
					</td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php
include('foot.inc');

return;
endif;

$enabledContextKeys = array_values(array_filter(
    $contextKeys,
    static fn(string $contextKey): bool => (sinkholeIpContextSettings($contextKey)['enabled'] ?? false) === true,
));

if ($hasOwnSettings === false) {
    $broaderLabel = sinkholeIpBroaderLabel($context, $networks, $devices, $enabledContextKeys);

    print_info_box(
        htmlspecialchars(($contextType === 'device')
            ? pfsensePackageSinkholeTranslate('bxpage_not_set_device', [$broaderLabel])
            : pfsensePackageSinkholeTranslate('bxpage_not_set_network', [$broaderLabel])),
        'info',
        false,
    );
} elseif ($isGlobal === false && ($contextSettings['enabled'] ?? false) !== true) {
    $broaderLabel = sinkholeIpBroaderLabel($context, $networks, $devices, $enabledContextKeys);

    print_info_box(
        htmlspecialchars(pfsensePackageSinkholeTranslate('context_turned_off', [$broaderLabel])),
        'info',
        false,
    );
}

$invalidValues = ($isGlobal)
    ? $configuration['invalid_values']
    : ($contextSettings['invalid_values'] ?? []);

if ($invalidValues !== []):
?>
<div class="panel panel-danger">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_saved_values'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('field'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('value'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('reason'))?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($invalidValues as $invalidValue): ?>
				<tr>
					<td><?=htmlspecialchars(sinkholeIpFieldLabel((string) $invalidValue['field_key']))?></td>
					<td><?=htmlspecialchars($invalidValue['value'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeInvalidReason($invalidValue))?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php endif; ?>
<?php
$settingsButton = new Form_Button(
    'save_ip_settings',
    pfsensePackageSinkholeTranslate('save'),
    null,
    'fa-solid fa-save',
);
$settingsButton->addClass('btn-primary');
$settingsForm = new Form($settingsButton);
$settingsForm->setAction('sinkhole-ip.php?context=' . rawurlencode($context));
$settingsForm->addGlobal(new Form_Input('context', null, 'hidden', $context));
$removeLabel = ($contextType === 'device')
    ? pfsensePackageSinkholeTranslate('bxpage_remove_device')
    : pfsensePackageSinkholeTranslate('bxpage_remove_network');

if ($isGlobal === false && $hasOwnSettings) {
    $removeButton = new Form_Button(
        'remove_context_settings',
        $removeLabel,
        null,
        'fa-solid fa-trash-can',
    );
    $removeButton->addClass('btn-danger');
    $settingsForm->addGlobal($removeButton);
}

$showField = static fn(string $field): bool => $isGlobal || in_array($field, $contextFields, true);
$settingsSection = new Form_Section(pfsensePackageSinkholeTranslate('ip_country_blocking'));

if ($showField('ip_enabled')) {
    $settingsSection->addInput(new Form_Checkbox(
        'ip_enabled',
        pfsensePackageSinkholeTranslate('enable'),
        pfsensePackageSinkholeTranslate('ip_enable_help'),
        $displaySettings['enabled'],
    ));
}

if ($isGlobal) {
    $interfaceOptions = $interfaces;

    foreach ($displaySettings['interfaces'] as $storedInterface) {
        if (!isset($interfaceOptions[$storedInterface])) {
            $interfaceOptions[$storedInterface] = pfsensePackageSinkholeTranslate(
                'unavailable_interface',
            ) . ' — ' . $storedInterface;
        }
    }

    $interfaceInput = new Form_Select(
        'ip_interfaces',
        pfsensePackageSinkholeTranslate('interfaces'),
        $displaySettings['interfaces'],
        $interfaceOptions,
        true,
    );
    $interfaceInput->setHelp(pfsensePackageSinkholeTranslate('ip_interfaces_help'));
    $settingsSection->addInput($interfaceInput);
}

if ($showField('ip_directions')) {
    $directionOptions = [
        'inbound' => pfsensePackageSinkholeTranslate('inbound'),
        'outbound' => pfsensePackageSinkholeTranslate('outbound'),
    ];

    foreach ($displaySettings['directions'] as $storedDirection) {
        if (!isset($directionOptions[$storedDirection])) {
            $directionOptions[$storedDirection] = pfsensePackageSinkholeTranslate(
                'unavailable_direction',
            ) . ' — ' . $storedDirection;
        }
    }

    $directionInput = new Form_Select(
        'ip_directions',
        pfsensePackageSinkholeTranslate('directions'),
        $displaySettings['directions'],
        $directionOptions,
        true,
    );
    $directionInput->setHelp(pfsensePackageSinkholeTranslate('ip_directions_help'));
    $settingsSection->addInput($directionInput);
}

if ($showField('ip_list_ids')) {
    $listOptions = [];
    $hiddenListSelection = [];

    foreach ($lists as $listIdentifier => $list) {
        if ($list['enabled'] !== true) {
            // A disabled source stays selected until a context deselects it.
            if (in_array($listIdentifier, $displaySettings['lists'], true)) {
                $hiddenListSelection[] = $listIdentifier;
            }

            continue;
        }

        $listOptions[$listIdentifier] = $list['name']
            . ' ('
            . pfsensePackageSinkholeTranslateMapped('ip_family', $list['family'])
            . ')';
    }

    if ($listOptions === []) {
        $settingsSection->addInput(new Form_StaticText(
            pfsensePackageSinkholeTranslate('ip_lists'),
            htmlspecialchars(pfsensePackageSinkholeTranslate('no_enabled_ip_lists'))
                . ' <a href="sinkhole-lists.php?kind=ip">'
                . htmlspecialchars(pfsensePackageSinkholeTranslate('open_lists'))
                . '</a>',
        ));
    } else {
        $listInput = new Form_Select(
            'ip_lists',
            pfsensePackageSinkholeTranslate('ip_lists'),
            array_values(array_intersect($displaySettings['lists'], array_keys($listOptions))),
            $listOptions,
            true,
        );
        $listInput->setHelp(pfsensePackageSinkholeTranslate('bxpage_ip_lists_help'));
        $settingsSection->addInput($listInput);
    }

    foreach ($hiddenListSelection as $hiddenListPosition => $hiddenListIdentifier) {
        $settingsForm->addGlobal(new Form_Input(
            'ip_lists[]',
            null,
            'hidden',
            $hiddenListIdentifier,
            ['id' => 'ip_lists_kept_' . $hiddenListPosition],
        ));
    }
}

if ($showField('ip_countries')) {
    $countriesInput = new Form_Textarea(
        'ip_countries',
        pfsensePackageSinkholeTranslate('countries'),
        implode(PHP_EOL, $displaySettings['countries']),
    );
    $countriesInput->setHelp(pfsensePackageSinkholeTranslate('countries_help'));
    $settingsSection->addInput($countriesInput);
}

if ($isGlobal) {
    $accountInput = new Form_Input(
        'maxmind_account_id',
        pfsensePackageSinkholeTranslate('maxmind_account_id'),
        'text',
        $displaySettings['account_id'],
    );
    $accountInput->setHelp(pfsensePackageSinkholeTranslate('maxmind_account_id_help'));
    $settingsSection->addInput($accountInput);
    $settingsSection->addInput(new Form_StaticText(
        pfsensePackageSinkholeTranslate('maxmind_license_key_status'),
        pfsensePackageSinkholeTranslateMapped(
            'secret_state',
            $configuration['license_key_set'] ? 'set' : 'unset',
        ),
    ));
    $licenseInput = new Form_Input(
        'maxmind_license_key',
        pfsensePackageSinkholeTranslate('maxmind_license_key'),
        'password',
        '',
    );
    $licenseInput->setHelp(pfsensePackageSinkholeTranslate('maxmind_license_key_help'));
    $settingsSection->addInput($licenseInput);
    $settingsSection->addInput(new Form_Checkbox(
        'clear_maxmind_license_key',
        pfsensePackageSinkholeTranslate('clear_license_key'),
        pfsensePackageSinkholeTranslate('clear_license_key_help'),
        false,
    ));
}

if ($showField('ip_allowlist')) {
    $allowlistInput = new Form_Textarea(
        'ip_allowlist',
        pfsensePackageSinkholeTranslate('ip_allowlist'),
        implode(PHP_EOL, $displaySettings['allowlist']),
    );
    $allowlistInput->setHelp(pfsensePackageSinkholeTranslate('ip_allowlist_help'));
    $settingsSection->addInput($allowlistInput);
}

$settingsForm->add($settingsSection);
print($settingsForm);

if ($isGlobal === false && $hasOwnSettings):
?>
<script>
events.push(function () {
	$('#remove_context_settings').on('click', function () {
		return confirm(<?=json_encode($removeLabel . '?', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)?>);
	});
});
</script>
<?php
endif;

include('foot.inc');
