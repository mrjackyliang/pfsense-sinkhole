<?php

declare(strict_types=1);

/*
 * Sinkhole SafeSearch configuration page.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-safesearch
##|*NAME=Firewall: Sinkhole: SafeSearch
##|*DESCR=Allow access to Sinkhole SafeSearch configuration.
##|*MATCH=sinkhole-safesearch.php*
##|-PRIV

use PfSense\Sinkhole\Domain\SafeSearchConfiguration;
use PfSense\Sinkhole\Domain\SafeSearchEngines;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\SavedListStore;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/SafeSearchConfiguration.php');
require_once('/usr/local/pkg/sinkhole/SafeSearchEngines.php');

$adapter = pfsensePackageSinkholeAdapter();
$interfaces = $adapter->getConfiguredInterfaces();
$scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
$safeSearchConfiguration = pfsensePackageSinkholeGetSafeSearch();
$scopeOptions = [
    'global' => pfsensePackageSinkholeTranslate('global'),
];

foreach ($scopeConfiguration['networks'] as $identifier => $network) {
    $scopeOptions['network:' . $identifier] = pfsensePackageSinkholeTranslate(
        'service_network_scope',
        [$interfaces[$network['interface']] ?? $network['interface']],
    );
}

foreach ($scopeConfiguration['devices'] as $identifier => $device) {
    $scopeOptions['device:' . $identifier] = pfsensePackageSinkholeTranslate(
        'service_device_scope',
        [$device['name']],
    );
}

$selectedScope = (string) ($_POST['safesearch_scope'] ?? $_GET['safesearch_scope'] ?? 'global');

if (!isset($scopeOptions[$selectedScope])) {
    $selectedScope = 'global';
}

$engineNames = [
    'google' => 'Google',
    'youtube' => 'YouTube',
    'bing' => 'Bing',
    'duckduckgo' => 'DuckDuckGo',
    'brave' => 'Brave Search',
    'startpage' => 'Startpage',
    'ecosia' => 'Ecosia',
    'yandex' => 'Yandex',
    'pixabay' => 'Pixabay',
    'qwant' => 'Qwant',
];
$actionMessage = null;
$actionClass = 'info';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_safesearch'])) {
    try {
        $posted = is_array($_POST['engines'] ?? null) ? $_POST['engines'] : [];

        if (in_array($_POST['youtube'] ?? '', [
            SafeSearchEngines::YOUTUBE_MODERATE,
            SafeSearchEngines::YOUTUBE_STRICT,
        ], true)) {
            $posted[] = $_POST['youtube'];
        }

        $safeSearchConfiguration = SafeSearchConfiguration::replaceScopeSelection(
            $safeSearchConfiguration,
            $selectedScope,
            array_values(array_filter(
                $posted,
                static fn(mixed $value): bool => !in_array($value, [
                    SafeSearchEngines::YOUTUBE_MODERATE,
                    SafeSearchEngines::YOUTUBE_STRICT,
                ], true) || $value === ($_POST['youtube'] ?? ''),
            )),
        );
        pfsensePackageSinkholeSaveSafeSearch($safeSearchConfiguration);
        $actionMessage = pfsensePackageSinkholeTranslate('settings_saved_applying');
        $actionClass = 'success';

        try {
            $adapter->refreshSafeSearchTargets();
        } catch (Throwable $throwable) {
            $actionMessage = pfsensePackageSinkholeTranslate(
                'safesearch_lookup_failed',
                [pfsensePackageSinkholeThrowableMessage($throwable)],
            );
            $actionClass = 'warning';
        }

        (new Compiler(
            $adapter->packagePaths(),
            new SavedListStore($adapter->packagePaths()),
        ))->markNeeded();
        pfsensePackageSinkholeInstallCron();
        $adapter->runApplyInBackground();
        $safeSearchConfiguration = pfsensePackageSinkholeGetSafeSearch();
    } catch (Throwable $throwable) {
        $actionMessage = pfsensePackageSinkholeThrowableMessage($throwable);
        $actionClass = 'danger';
    }
}

$selectedChoices = SafeSearchConfiguration::scopeSelection($safeSearchConfiguration, $selectedScope);
$targets = $adapter->safeSearchTargets();
$hostsInUse = $adapter->safeSearchHostsInUse();
$pgtitle = [gettext('Firewall'), 'Sinkhole', pfsensePackageSinkholeTranslate('safesearch')];
$pglinks = ['', '/pkg_edit.php?xml=sinkhole.xml&id=0', '@self'];

include('head.inc');
?>
<link rel="stylesheet" href="/css/sinkhole.css">
<?php

display_top_tabs(pfsensePackageSinkholeTabs('safesearch'));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

$scopeForm = new Form(false);
$scopeForm->setMethod('get');
$scopeForm->setAction('sinkhole-safesearch.php');
$scopeSection = new Form_Section(pfsensePackageSinkholeTranslate('safesearch'));
$scopeInput = new Form_Select(
    'safesearch_scope',
    pfsensePackageSinkholeTranslate('scope'),
    $selectedScope,
    $scopeOptions,
);
$scopeInput->setOnchange('this.form.submit()');
$scopeInput->setHelp(pfsensePackageSinkholeTranslate('safesearch_help'));
$scopeSection->addInput($scopeInput);
$scopeForm->add($scopeSection);
print($scopeForm);

$saveButton = new Form_Button(
    'save_safesearch',
    pfsensePackageSinkholeTranslate('save'),
    null,
    'fa-solid fa-save',
);
$saveButton->addClass('btn-primary', 'btn-sm');
$engineForm = new Form($saveButton);
$engineForm->setAction('sinkhole-safesearch.php');
$engineForm->addGlobal(new Form_Input('safesearch_scope', null, 'hidden', $selectedScope));
$engineSection = new Form_Section(sprintf(
    '%s: %s',
    pfsensePackageSinkholeTranslate('safesearch_engines'),
    $scopeOptions[$selectedScope],
));

foreach ($engineNames as $engine => $engineName) {
    if ($engine === 'youtube') {
        $youtubeChoice = in_array(SafeSearchEngines::YOUTUBE_STRICT, $selectedChoices, true)
            ? SafeSearchEngines::YOUTUBE_STRICT
            : (in_array(SafeSearchEngines::YOUTUBE_MODERATE, $selectedChoices, true)
                ? SafeSearchEngines::YOUTUBE_MODERATE
                : '');
        $youtubeGroup = new Form_Group($engineName);
        $youtubeGroup->add(new Form_Checkbox(
            'youtube',
            null,
            pfsensePackageSinkholeTranslate('off'),
            $youtubeChoice === '',
            '',
        ))->displayAsRadio();
        $youtubeGroup->add(new Form_Checkbox(
            'youtube',
            null,
            pfsensePackageSinkholeTranslate('safesearch_moderate'),
            $youtubeChoice === SafeSearchEngines::YOUTUBE_MODERATE,
            SafeSearchEngines::YOUTUBE_MODERATE,
        ))->displayAsRadio();
        $youtubeGroup->add(new Form_Checkbox(
            'youtube',
            null,
            pfsensePackageSinkholeTranslate('safesearch_strict'),
            $youtubeChoice === SafeSearchEngines::YOUTUBE_STRICT,
            SafeSearchEngines::YOUTUBE_STRICT,
        ))->displayAsRadio();
        $youtubeGroup->setHelp(sprintf(
            '%s / %s',
            SafeSearchEngines::target(SafeSearchEngines::YOUTUBE_MODERATE),
            SafeSearchEngines::target(SafeSearchEngines::YOUTUBE_STRICT),
        ));
        $engineSection->add($youtubeGroup);

        continue;
    }

    $target = SafeSearchEngines::target($engine);
    $engineCheckbox = new Form_Checkbox(
        'engines[]',
        $engineName,
        ($target === '')
            ? pfsensePackageSinkholeTranslate('safesearch_qwant_blocked')
            : pfsensePackageSinkholeTranslate('safesearch_answers_with', [$target]),
        in_array($engine, $selectedChoices, true),
        $engine,
    );
    $engineCheckbox->setAttribute('id', 'safesearch-' . $engine);
    $engineSection->addInput($engineCheckbox);
}

$engineForm->add($engineSection);
print($engineForm);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_addresses'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead>
				<tr>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_safe_host'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('ipv4'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('ipv6'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_checked'))?></th>
					<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('last_error'))?></th>
				</tr>
			</thead>
			<tbody>
<?php if ($hostsInUse === []): ?>
				<tr><td colspan="5"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_not_in_use'))?></td></tr>
<?php endif; ?>
<?php foreach ($hostsInUse as $host): ?>
<?php $record = $targets[$host] ?? null; ?>
				<tr>
					<td><?=htmlspecialchars($host)?></td>
					<td><?=htmlspecialchars(($record['ipv4'] ?? []) === [] ? pfsensePackageSinkholeTranslate('none') : implode(', ', $record['ipv4']))?></td>
					<td><?=htmlspecialchars(($record['ipv6'] ?? []) === [] ? pfsensePackageSinkholeTranslate('none') : implode(', ', $record['ipv6']))?></td>
					<td><?=htmlspecialchars(is_int($record['checked_at'] ?? null) ? gmdate('Y-m-d H:i:s \U\T\C', $record['checked_at']) : pfsensePackageSinkholeTranslate('safesearch_not_looked_up'))?></td>
					<td><?=htmlspecialchars(($record['last_error'] ?? '') === '' ? pfsensePackageSinkholeTranslate('none') : $record['last_error'])?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
		<p class="help-block"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_unresolved_help'))?></p>
	</div>
</div>
<?php include('foot.inc');
