<?php

declare(strict_types=1);

/*
 * Sinkhole bypass protection configuration page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-bypass
##|*NAME=Firewall: Sinkhole: Bypass
##|*DESCR=Allow access to Sinkhole bypass protection settings and lists.
##|*MATCH=sinkhole-bypass.php*
##|-PRIV

use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\RedirectConfiguration;
use PfSense\Sinkhole\Domain\ValidationException;
use PfSense\Sinkhole\Runtime\Context;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/BypassConfiguration.php');
require_once('/usr/local/pkg/sinkhole/Context.php');
require_once('/usr/local/pkg/sinkhole/RedirectConfiguration.php');

/**
 * Sinkhole Bypass - Context Rows.
 *
 * @return array
 *
 * @since 1.3.0
 */
function sinkholeBypassContextRows(): array
{
    $contextRows = pfsensePackageSinkholeAdapter()->readConfigurationPath(
        'installedpackages/sinkhole/bypass_contexts/item',
        [],
    );

    return is_array($contextRows) ? $contextRows : [];
}

/**
 * Sinkhole Bypass - Context Settings.
 *
 * Reads the exact settings saved for one context through the Bypass API, so a
 * network or device without its own row returns null instead of inherited values.
 *
 * @param array $configuration - Partitioned Global Bypass configuration.
 * @param string $context - Context key.
 *
 * @return array|null
 *
 * @since 1.3.0
 */
function sinkholeBypassContextSettings(array $configuration, string $context): ?array
{
    $settings = BypassConfiguration::forContext(
        $configuration,
        sinkholeBypassContextRows(),
        $context,
    );

    if ($settings === null || $context === Context::GLOBAL) {
        return $settings;
    }

    foreach (sinkholeBypassContextRows() as $contextRow) {
        if (is_array($contextRow) && ($contextRow['context'] ?? null) === $context) {
            $storedEnabled = $contextRow['enabled'] ?? '';
            $settings['stored_enabled'] = $storedEnabled === 'on' || $storedEnabled === true;
        }
    }

    return $settings;
}

/**
 * Sinkhole Bypass - Persist.
 *
 * Writes the configuration changed through the Bypass API in one revision, then
 * applies it in the background.
 *
 * @return void
 *
 * @since 1.3.0
 */
function sinkholeBypassPersist(): void
{
    pfsensePackageSinkholeAdapter()->saveConfiguration(pfsensePackageSinkholeTranslate('revision_saved_bypass'));
    pfsensePackageSinkholeInstallCron();
    pfsensePackageSinkholeAdapter()->runApplyInBackground();
}

/**
 * Sinkhole Bypass - Error Message.
 *
 * @param array $errors - Errors returned by the Bypass submission.
 *
 * @return string
 *
 * @since 1.3.0
 */
function sinkholeBypassErrorMessage(array $errors): string
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
 * Sinkhole Bypass - Field Label.
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
function sinkholeBypassFieldLabel(string $fieldKey): string
{
    try {
        return pfsensePackageSinkholeTranslateMapped('field', $fieldKey);
    } catch (Throwable) {
        return $fieldKey;
    }
}

/**
 * Sinkhole Bypass - Lines.
 *
 * @param mixed $value - Posted textarea value.
 *
 * @return list<string>
 *
 * @since 1.3.0
 */
function sinkholeBypassLines(mixed $value): array
{
    if (!is_string($value)) {
        return [];
    }

    $lines = preg_split('/\r\n|\r|\n/', $value);

    if (!is_array($lines)) {
        return [];
    }

    return array_values(array_filter(
        array_map('trim', $lines),
        static fn(string $line): bool => $line !== '',
    ));
}

/**
 * Sinkhole Bypass - List Selection.
 *
 * @param mixed $value - Saved or posted list identifiers.
 *
 * @return list<string>
 *
 * @since 1.3.0
 */
function sinkholeBypassListSelection(mixed $value): array
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
 * Sinkhole Bypass - Broader Label.
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
function sinkholeBypassBroaderLabel(
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
$redirect = pfsensePackageSinkholeGetRedirectConfiguration();
$configuration = pfsensePackageSinkholeGetBypassConfiguration();
$lists = $configuration['lists'];
$invalidRows = $configuration['invalid_lists'];
$contextSettings = ($isAll) ? null : sinkholeBypassContextSettings($configuration, $context);
$contextFields = ($isAll) ? [] : BypassConfiguration::fieldsForContext($context);
$actionMessage = ((string) ($_GET['saved'] ?? '') === '1')
    ? pfsensePackageSinkholeTranslate('bypass_saved_applying')
    : null;
$actionClass = 'info';
$displayInterfaces = $redirect['stored_interfaces'];
$displayRedirectEnabled = $redirect['enabled'];
$displayExemptSources = $redirect['stored_exempt_sources'];
$displayExemptDestinations = $redirect['stored_exempt_destinations'];
$displaySettings = $contextSettings ?? [];
$displayBlockExemptSources = $displaySettings['stored_exempt_sources']
    ?? $displaySettings['exempt_sources']
    ?? [];
$displayBlockExemptDestinations = $displaySettings['stored_exempt_destinations']
    ?? $displaySettings['exempt_destinations']
    ?? [];
$displaySettings['enabled'] = $displaySettings['stored_enabled'] ?? $displaySettings['enabled'] ?? false;
$displayListSelection = sinkholeBypassListSelection($displaySettings['selected_lists'] ?? []);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $isAll === false) {
    try {
        if (isset($_POST['remove_context_settings'])) {
            if ($isGlobal === false) {
                BypassConfiguration::removeContext($context);

                sinkholeBypassPersist();

                $actionMessage = pfsensePackageSinkholeTranslate('bxpage_bypass_removed');
                $actionClass = 'success';
            }
        } elseif (isset($_POST['save_bypass'])) {
            $redirectSubmission = null;
            $postedBlockExemptSources = $_POST['block_exempt_sources'] ?? '';
            $postedBlockExemptDestinations = $_POST['block_exempt_destinations'] ?? '';
            $displayBlockExemptSources = sinkholeBypassLines($postedBlockExemptSources);
            $displayBlockExemptDestinations = sinkholeBypassLines($postedBlockExemptDestinations);
            $displayListSelection = sinkholeBypassListSelection($_POST['bypass_lists'] ?? []);
            $displaySettings = array_replace($displaySettings, [
                'enabled' => isset($_POST['bypass_enabled']),
                'block_tls_quic' => isset($_POST['block_tls_quic']),
                'block_encrypted_dns' => isset($_POST['block_encrypted_dns']),
                'disable_firefox_doh' => isset($_POST['disable_firefox_doh']),
                'disable_private_relay' => isset($_POST['disable_private_relay']),
                'discovery' => is_string($_POST['discovery'] ?? null)
                    ? $_POST['discovery']
                    : BypassConfiguration::DISCOVERY_OFF,
                'block_tor' => isset($_POST['block_tor']),
                'block_vpn' => isset($_POST['block_vpn']),
                'block_vpn_ports' => isset($_POST['block_vpn_ports']),
            ]);

            if (!is_string($postedBlockExemptSources)) {
                throw new ValidationException('exempt_sources_invalid');
            }

            if (!is_string($postedBlockExemptDestinations)) {
                throw new ValidationException('exempt_destinations_invalid');
            }

            if ($isGlobal) {
                $postedInterfaces = $_POST['bypass_interfaces'] ?? [];
                $postedExemptSources = $_POST['redirect_exempt_sources'] ?? '';
                $postedExemptDestinations = $_POST['redirect_exempt_destinations'] ?? '';
                $displayInterfaces = is_array($postedInterfaces)
                    ? array_values(array_filter($postedInterfaces, 'is_string'))
                    : [];
                $displayRedirectEnabled = isset($_POST['redirect_enabled']);
                $displayExemptSources = sinkholeBypassLines($postedExemptSources);
                $displayExemptDestinations = sinkholeBypassLines($postedExemptDestinations);

                if (!is_string($postedExemptSources)) {
                    throw new ValidationException('exempt_sources_invalid');
                }

                if (!is_string($postedExemptDestinations)) {
                    throw new ValidationException('exempt_destinations_invalid');
                }

                $redirectSubmission = RedirectConfiguration::normalizeSubmission(
                    $displayRedirectEnabled,
                    $postedInterfaces,
                    $postedExemptSources,
                    $interfaces,
                    $aliases,
                    $postedExemptDestinations,
                );
            }

            $submission = BypassConfiguration::submitContext(
                $context,
                $_POST,
                $interfaces,
                $aliases,
            );

            if ($submission['errors'] !== []) {
                $actionMessage = sinkholeBypassErrorMessage($submission['errors']);
                $actionClass = 'danger';
            } elseif (is_array($redirectSubmission)) {
                pfsensePackageSinkholeSaveBypass(
                    pfsensePackageSinkholeBypassStorage(
                        $configuration,
                        $lists,
                        $invalidRows,
                        $submission['settings'],
                    ),
                    $redirectSubmission,
                );

                $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
                $actionClass = 'success';
            } else {
                BypassConfiguration::storeContext($context, $submission['settings']);

                sinkholeBypassPersist();

                $actionMessage = pfsensePackageSinkholeTranslate('bypass_saved_applying');
                $actionClass = 'success';
            }
        }
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }

    if ($actionClass === 'success') {
        $redirect = pfsensePackageSinkholeGetRedirectConfiguration();
        $configuration = pfsensePackageSinkholeGetBypassConfiguration();
        $lists = $configuration['lists'];
        $invalidRows = $configuration['invalid_lists'];
        $contextSettings = sinkholeBypassContextSettings($configuration, $context);
        $displayInterfaces = $redirect['stored_interfaces'];
        $displayRedirectEnabled = $redirect['enabled'];
        $displayExemptSources = $redirect['stored_exempt_sources'];
        $displayExemptDestinations = $redirect['stored_exempt_destinations'];
        $displaySettings = $contextSettings ?? [];
        $displayBlockExemptSources = $displaySettings['stored_exempt_sources']
            ?? $displaySettings['exempt_sources']
            ?? [];
        $displayBlockExemptDestinations = $displaySettings['stored_exempt_destinations']
            ?? $displaySettings['exempt_destinations']
            ?? [];
        $displaySettings['enabled'] = $displaySettings['stored_enabled'] ?? $displaySettings['enabled'] ?? false;
        $displayListSelection = sinkholeBypassListSelection($displaySettings['selected_lists'] ?? []);
    }
}

$hasOwnSettings = $isGlobal || $contextSettings !== null;
$contextKeys = BypassConfiguration::contextKeys();
$redirectInactiveReason = null;

try {
    $redirectInactiveReason = pfsensePackageSinkholeAdapter()->redirectInactiveReason();
} catch (Throwable $throwable) {
    if ($actionMessage === null) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }
}

$interfaceOptions = $interfaces;

foreach ($displayInterfaces as $interface) {
    if (!isset($interfaceOptions[$interface])) {
        $interfaceOptions[$interface] = pfsensePackageSinkholeTranslate('unavailable_interface')
            . ' — '
            . $interface;
    }
}

$overviewRows = [];

if ($isAll) {
    $protectionLabels = [
        'block_tls_quic' => pfsensePackageSinkholeTranslate('tls_and_quic'),
        'block_encrypted_dns' => pfsensePackageSinkholeTranslate('providers'),
        'disable_firefox_doh' => pfsensePackageSinkholeTranslate('firefox'),
        'disable_private_relay' => pfsensePackageSinkholeTranslate('private_relay'),
        'block_tor' => pfsensePackageSinkholeTranslate('tor'),
        'block_vpn' => pfsensePackageSinkholeTranslate('vpn'),
        'block_vpn_ports' => pfsensePackageSinkholeTranslate('bxpage_vpn_ports'),
    ];
    $overviewKeys = array_values(array_unique(array_merge([Context::GLOBAL], $contextKeys)));

    foreach ($overviewKeys as $overviewKey) {
        if (Context::parse($overviewKey) === null) {
            continue;
        }

        $overviewSettings = sinkholeBypassContextSettings($configuration, $overviewKey);

        if ($overviewSettings === null) {
            continue;
        }

        $overviewProtections = [];

        foreach ($protectionLabels as $protectionField => $protectionLabel) {
            if (($overviewSettings[$protectionField] ?? false) === true) {
                $overviewProtections[] = $protectionLabel;
            }
        }

        if (($overviewSettings['discovery'] ?? BypassConfiguration::DISCOVERY_OFF) !== BypassConfiguration::DISCOVERY_OFF) {
            $overviewProtections[] = pfsensePackageSinkholeTranslate('discovery');
        }

        $overviewEnabled = ($overviewSettings['enabled'] ?? false) === true;
        $overviewRows[] = [
            'key' => $overviewKey,
            'label' => Context::label($overviewKey, $networks, $devices),
            'enabled' => $overviewEnabled,
            'protections' => ($overviewProtections === [])
                ? pfsensePackageSinkholeTranslate('none')
                : implode(', ', $overviewProtections),
        ];
    }
}

$exemptSourcesText = implode(PHP_EOL, $displayExemptSources);
$exemptDestinationsText = implode(PHP_EOL, $displayExemptDestinations);
$blockExemptSourcesText = implode(PHP_EOL, $displayBlockExemptSources);
$blockExemptDestinationsText = implode(PHP_EOL, $displayBlockExemptDestinations);
$tlsStatus = $configuration['discovery_tls'];
$tlsServiceStatus = $tlsStatus['service_enabled']
    ? pfsensePackageSinkholeTranslate('on')
    : pfsensePackageSinkholeTranslate('off');
$discoveryHelp = pfsensePackageSinkholeTranslate(
    'bypass_discovery_help',
    [$tlsServiceStatus],
);
$contextUrl = 'sinkhole-bypass.php?context=' . rawurlencode($context);
$pgtitle = [gettext('Firewall'), 'Sinkhole', pfsensePackageSinkholeTranslate('bypass')];
$pglinks = ['', '/pkg_edit.php?xml=sinkhole.xml&id=0', '@self'];

include('head.inc');
?>
<link rel="stylesheet" href="/css/sinkhole.css">
<?php

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

display_top_tabs(pfsensePackageSinkholeTabs('bypass'));

print(Context::renderRow('sinkhole-bypass.php', $context, $networks, $devices, true));

if ($isAll):
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bxpage_bypass_overview'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap table-rowdblclickedit" data-sortable>
			<thead><tr>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bxpage_applies_to'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('enabled'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('bxpage_protections'))?></th>
				<th data-sortable="false"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('actions'))?></th>
			</tr></thead>
			<tbody>
<?php foreach ($overviewRows as $overviewRow): ?>
<?php $overviewUrl = 'sinkhole-bypass.php?context=' . rawurlencode($overviewRow['key']); ?>
				<tr<?=($overviewRow['enabled']) ? '' : ' class="disabled"'?>>
					<td><a href="<?=htmlspecialchars($overviewUrl)?>"><?=htmlspecialchars($overviewRow['label'])?></a></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeTranslateMapped('boolean', $overviewRow['enabled'] ? 'true' : 'false'))?></td>
					<td><?=htmlspecialchars($overviewRow['protections'])?></td>
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
    static fn(string $contextKey): bool => $contextKey === Context::GLOBAL
        || (sinkholeBypassContextSettings($configuration, $contextKey)['stored_enabled'] ?? false) === true,
));

if ($hasOwnSettings === false) {
    $broaderLabel = sinkholeBypassBroaderLabel($context, $networks, $devices, $enabledContextKeys);

    print_info_box(
        htmlspecialchars(($contextType === 'device')
            ? pfsensePackageSinkholeTranslate('bxpage_not_set_device', [$broaderLabel])
            : pfsensePackageSinkholeTranslate('bxpage_not_set_network', [$broaderLabel])),
        'info',
        false,
    );
} elseif ($isGlobal === false && ($contextSettings['stored_enabled'] ?? false) !== true) {
    $broaderLabel = sinkholeBypassBroaderLabel($context, $networks, $devices, $enabledContextKeys);

    print_info_box(
        htmlspecialchars(pfsensePackageSinkholeTranslate('context_turned_off', [$broaderLabel])),
        'info',
        false,
    );
}

$invalidValues = array_merge(
    ($isGlobal) ? $redirect['invalid_values'] : [],
    ($isGlobal) ? $configuration['invalid_values'] : ($displaySettings['invalid_values'] ?? []),
    ($isGlobal) ? $configuration['invalid_exemptions'] : ($displaySettings['invalid_exemptions'] ?? []),
);

if ($invalidValues !== []):
?>
<div class="panel panel-danger">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('invalid_saved_values'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead><tr>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('field'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('value'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('reason'))?></th>
			</tr></thead>
			<tbody>
<?php foreach ($invalidValues as $invalidValue): ?>
				<tr>
					<td><?=htmlspecialchars(sinkholeBypassFieldLabel((string) $invalidValue['field_key']))?></td>
					<td><?=htmlspecialchars($invalidValue['value'])?></td>
					<td><?=htmlspecialchars(pfsensePackageSinkholeInvalidReason($invalidValue))?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php
endif;

$showField = static fn(string $field): bool => in_array($field, $contextFields, true);
$saveButton = new Form_Button(
    'save_bypass',
    pfsensePackageSinkholeTranslate('save'),
    null,
    'fa-solid fa-save',
);
$saveButton->addClass('btn-primary');
$form = new Form($saveButton);
$form->setAction($contextUrl);
$form->addGlobal(new Form_Input('context', null, 'hidden', $context));

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
    $form->addGlobal($removeButton);
}

if ($isGlobal) {
    $interfacesSection = new Form_Section(pfsensePackageSinkholeTranslate('interfaces'));
    $interfaceInput = new Form_Select(
        'bypass_interfaces',
        pfsensePackageSinkholeTranslate('apply_to'),
        $displayInterfaces,
        $interfaceOptions,
        true,
    );
    $interfaceInput->setHelp(pfsensePackageSinkholeTranslate('bypass_interfaces_help'));
    $interfacesSection->addInput($interfaceInput);
    $form->add($interfacesSection);

    $plainSection = new Form_Section(pfsensePackageSinkholeTranslate('plain_dns'));
    $plainSection->addInput(new Form_Checkbox(
        'redirect_enabled',
        pfsensePackageSinkholeTranslate('redirect'),
        pfsensePackageSinkholeTranslate('bypass_redirect_help'),
        $displayRedirectEnabled,
    ));

    if (is_string($redirectInactiveReason)) {
        $plainSection->addInput(new Form_StaticText(
            pfsensePackageSinkholeTranslate('bypass_warning'),
            '<span class="text-danger"><i class="fa-solid fa-triangle-exclamation"></i> '
                . htmlspecialchars(pfsensePackageSinkholeTranslateMapped(
                    'redirect_inactive_reason',
                    $redirectInactiveReason,
                ))
                . '</span>',
        ));
    }

    $sourceInput = new Form_Textarea(
        'redirect_exempt_sources',
        pfsensePackageSinkholeTranslate('exempt_sources'),
        $exemptSourcesText,
    );
    $sourceInput->setRows(4);
    $sourceInput->setHelp(pfsensePackageSinkholeTranslate('redirect_exemptions_help'));
    $plainSection->addInput($sourceInput);
    $destinationInput = new Form_Textarea(
        'redirect_exempt_destinations',
        pfsensePackageSinkholeTranslate('exempt_destinations'),
        $exemptDestinationsText,
    );
    $destinationInput->setRows(4);
    $destinationInput->setHelp(pfsensePackageSinkholeTranslate('redirect_exemptions_help'));
    $plainSection->addInput($destinationInput);
    $form->add($plainSection);
}

$contextSection = new Form_Section(pfsensePackageSinkholeTranslate('bypass'));
$contextSectionInputs = 0;

if ($isGlobal === false && ($showField('enabled') || $showField('bypass_enabled'))) {
    $contextSection->addInput(new Form_Checkbox(
        'bypass_enabled',
        pfsensePackageSinkholeTranslate('enable'),
        pfsensePackageSinkholeTranslate('bxpage_bypass_enable_help'),
        ($displaySettings['enabled'] ?? false) === true,
    ));
    $contextSectionInputs++;
}

if ($showField('bypass_lists')) {
    $listOptions = [];
    $hiddenListSelection = [];

    foreach ($lists as $listIdentifier => $list) {
        if ($list['enabled'] !== true) {
            // A disabled source stays selected until a context deselects it.
            if (in_array($listIdentifier, $displayListSelection, true)) {
                $hiddenListSelection[] = $listIdentifier;
            }

            continue;
        }

        $listOptions[$listIdentifier] = $list['name']
            . ' ('
            . pfsensePackageSinkholeTranslateMapped('bypass_kind', $list['kind'])
            . ')';
    }

    if ($listOptions === []) {
        $contextSection->addInput(new Form_StaticText(
            pfsensePackageSinkholeTranslate('bypass_lists'),
            htmlspecialchars(pfsensePackageSinkholeTranslate('no_enabled_bypass_lists'))
                . ' <a href="sinkhole-lists.php?kind=bypass">'
                . htmlspecialchars(pfsensePackageSinkholeTranslate('open_lists'))
                . '</a>',
        ));
    } else {
        $listInput = new Form_Select(
            'bypass_lists',
            pfsensePackageSinkholeTranslate('bypass_lists'),
            array_values(array_intersect($displayListSelection, array_keys($listOptions))),
            $listOptions,
            true,
        );
        $listInput->setHelp(pfsensePackageSinkholeTranslate('bxpage_bypass_lists_help'));
        $contextSection->addInput($listInput);
    }

    foreach ($hiddenListSelection as $hiddenListPosition => $hiddenListIdentifier) {
        $form->addGlobal(new Form_Input(
            'bypass_lists[]',
            null,
            'hidden',
            $hiddenListIdentifier,
            ['id' => 'bypass_lists_kept_' . $hiddenListPosition],
        ));
    }

    $contextSectionInputs++;
}

if ($contextSectionInputs > 0) {
    $form->add($contextSection);
}

$encryptedSection = new Form_Section(pfsensePackageSinkholeTranslate('encrypted_dns'));
$encryptedSectionInputs = 0;
$encryptedCheckboxes = [
    'block_tls_quic' => [
        pfsensePackageSinkholeTranslate('tls_and_quic'),
        pfsensePackageSinkholeTranslate('block_tls_quic_help'),
    ],
    'block_encrypted_dns' => [
        pfsensePackageSinkholeTranslate('providers'),
        pfsensePackageSinkholeTranslate('block_encrypted_dns_help'),
    ],
    'disable_firefox_doh' => [
        pfsensePackageSinkholeTranslate('firefox'),
        pfsensePackageSinkholeTranslate('disable_firefox_doh_help'),
    ],
    'disable_private_relay' => [
        pfsensePackageSinkholeTranslate('private_relay'),
        pfsensePackageSinkholeTranslate('disable_private_relay_help'),
    ],
];

foreach ($encryptedCheckboxes as $checkboxField => $checkboxLabels) {
    if ($showField($checkboxField) === false && $isGlobal === false) {
        continue;
    }

    $encryptedSection->addInput(new Form_Checkbox(
        $checkboxField,
        $checkboxLabels[0],
        $checkboxLabels[1],
        ($displaySettings[$checkboxField] ?? false) === true,
    ));
    $encryptedSectionInputs++;
}

if ($showField('discovery') || $isGlobal) {
    $discoveryInput = new Form_Select(
        'discovery',
        pfsensePackageSinkholeTranslate('discovery'),
        (string) ($displaySettings['discovery'] ?? BypassConfiguration::DISCOVERY_OFF),
        [
            BypassConfiguration::DISCOVERY_OFF => pfsensePackageSinkholeTranslate('off'),
            BypassConfiguration::DISCOVERY_ADVERTISE => pfsensePackageSinkholeTranslate('discovery_advertise'),
            BypassConfiguration::DISCOVERY_NODATA => pfsensePackageSinkholeTranslate('discovery_nodata'),
        ],
    );
    $discoveryInput->setHelp($discoveryHelp);
    $encryptedSection->addInput($discoveryInput);
    $encryptedSectionInputs++;
}

if ($encryptedSectionInputs > 0) {
    $form->add($encryptedSection);
}

$tunnelSection = new Form_Section(pfsensePackageSinkholeTranslate('tunnels'));
$tunnelSectionInputs = 0;
$tunnelCheckboxes = [
    'block_tor' => [
        pfsensePackageSinkholeTranslate('tor'),
        pfsensePackageSinkholeTranslate('block_tor_help'),
    ],
    'block_vpn' => [
        pfsensePackageSinkholeTranslate('vpn'),
        pfsensePackageSinkholeTranslate('block_vpn_help'),
    ],
    'block_vpn_ports' => [
        pfsensePackageSinkholeTranslate('vpn'),
        pfsensePackageSinkholeTranslate('block_vpn_ports_help'),
    ],
];

foreach ($tunnelCheckboxes as $checkboxField => $checkboxLabels) {
    if ($showField($checkboxField) === false && $isGlobal === false) {
        continue;
    }

    $tunnelSection->addInput(new Form_Checkbox(
        $checkboxField,
        $checkboxLabels[0],
        $checkboxLabels[1],
        ($displaySettings[$checkboxField] ?? false) === true,
    ));
    $tunnelSectionInputs++;
}

if ($tunnelSectionInputs > 0) {
    $form->add($tunnelSection);
}

$blockExemptionsSection = new Form_Section(pfsensePackageSinkholeTranslate('block_exemptions'));
$blockExemptionsSectionInputs = 0;

if ($showField('block_exempt_sources') || $isGlobal) {
    $blockSourceInput = new Form_Textarea(
        'block_exempt_sources',
        pfsensePackageSinkholeTranslate('exempt_sources'),
        $blockExemptSourcesText,
    );
    $blockSourceInput->setRows(4);
    $blockSourceInput->setHelp(pfsensePackageSinkholeTranslate('block_exempt_sources_help'));
    $blockExemptionsSection->addInput($blockSourceInput);
    $blockExemptionsSectionInputs++;
}

if ($showField('block_exempt_destinations') || $isGlobal) {
    $blockDestinationInput = new Form_Textarea(
        'block_exempt_destinations',
        pfsensePackageSinkholeTranslate('exempt_destinations'),
        $blockExemptDestinationsText,
    );
    $blockDestinationInput->setRows(4);
    $blockDestinationInput->setHelp(pfsensePackageSinkholeTranslate('block_exempt_destinations_help'));
    $blockExemptionsSection->addInput($blockDestinationInput);
    $blockExemptionsSectionInputs++;
}

if ($blockExemptionsSectionInputs > 0) {
    $form->add($blockExemptionsSection);
}

print($form);
?>
<?php if ($isGlobal): ?>
<script>
events.push(function () {
	function toggleRedirectFields() {
		var hidden = !document.getElementById('redirect_enabled').checked;
		hideInput('redirect_exempt_sources', hidden);
		hideInput('redirect_exempt_destinations', hidden);
	}

	document.getElementById('redirect_enabled').addEventListener('change', toggleRedirectFields);
	toggleRedirectFields();
});
</script>
<?php elseif ($hasOwnSettings): ?>
<script>
events.push(function () {
	$('#remove_context_settings').on('click', function () {
		return confirm(<?=json_encode($removeLabel . '?', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)?>);
	});
});
</script>
<?php endif; ?>
<?php
include('foot.inc');
