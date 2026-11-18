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
use PfSense\Sinkhole\Runtime\Context;
use PfSense\Sinkhole\Runtime\SavedListStore;

require_once('guiconfig.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/Context.php');
require_once('/usr/local/pkg/sinkhole/SafeSearchConfiguration.php');
require_once('/usr/local/pkg/sinkhole/SafeSearchEngines.php');

$adapter = pfsensePackageSinkholeAdapter();
$scopeConfiguration = pfsensePackageSinkholeGetScopeConfiguration();
$networks = $scopeConfiguration['networks'];
$devices = $scopeConfiguration['devices'];
$safeSearchConfiguration = pfsensePackageSinkholeGetSafeSearch();
$context = Context::current($networks, $devices, true);
Context::remember($context);
$selectedScope = ($context === Context::ALL) ? Context::GLOBAL : $context;

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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_safesearch']) && $context !== Context::ALL) {
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
print(Context::renderRow('sinkhole-safesearch.php', $context, $networks, $devices, true));

if (is_string($actionMessage)) {
    print_info_box(htmlspecialchars($actionMessage), $actionClass, false);
}

if ($context === Context::ALL) {
    $overviewSelections = [Context::GLOBAL => SafeSearchConfiguration::scopeSelection($safeSearchConfiguration, Context::GLOBAL)];

    foreach (array_keys($networks) as $networkIdentifier) {
        $overviewSelections['network:' . $networkIdentifier] = SafeSearchConfiguration::scopeSelection(
            $safeSearchConfiguration,
            'network:' . $networkIdentifier,
        );
    }

    foreach (array_keys($devices) as $deviceIdentifier) {
        $overviewSelections['device:' . $deviceIdentifier] = SafeSearchConfiguration::scopeSelection(
            $safeSearchConfiguration,
            'device:' . $deviceIdentifier,
        );
    }

    $choiceNames = $engineNames + [
        SafeSearchEngines::YOUTUBE_MODERATE => $engineNames['youtube'] . ' (' . pfsensePackageSinkholeTranslate('safesearch_moderate') . ')',
        SafeSearchEngines::YOUTUBE_STRICT => $engineNames['youtube'] . ' (' . pfsensePackageSinkholeTranslate('safesearch_strict') . ')',
    ];
    $overviewRows = [];

    foreach ($overviewSelections as $overviewKey => $overviewChoices) {
        if ($overviewChoices === []) {
            continue;
        }

        $overviewRows[] = [
            'key' => $overviewKey,
            'label' => Context::label($overviewKey, $networks, $devices),
            'engines' => implode(', ', array_map(
                static fn(string $choice): string => $choiceNames[$choice] ?? $choice,
                $overviewChoices,
            )),
        ];
    }
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_engines'))?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead><tr>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('context_column'))?></th>
				<th><?=htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_engines'))?></th>
			</tr></thead>
			<tbody>
<?php if ($overviewRows === []): ?>
				<tr><td colspan="2" class="text-muted"><?=htmlspecialchars(pfsensePackageSinkholeTranslate('context_overview_empty'))?></td></tr>
<?php endif; ?>
<?php foreach ($overviewRows as $overviewRow): ?>
				<tr>
					<td><a href="<?=htmlspecialchars(Context::link('sinkhole-safesearch.php', $overviewRow['key']))?>"><?=htmlspecialchars($overviewRow['label'])?></a></td>
					<td><?=htmlspecialchars($overviewRow['engines'])?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>
<?php
} else {
$saveButton = new Form_Button(
    'save_safesearch',
    pfsensePackageSinkholeTranslate('save'),
    null,
    'fa-solid fa-save',
);
$saveButton->addClass('btn-primary', 'btn-sm');
$engineForm = new Form($saveButton);
$engineForm->setAction('sinkhole-safesearch.php');
$engineForm->addGlobal(new Form_Input('context', null, 'hidden', $context));
$engineSection = new Form_Section(pfsensePackageSinkholeTranslate('safesearch_engines'));
$engineHelp = new Form_StaticText(
    '',
    '<span class="help-block">'
        . htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_help'))
        . '</span>',
);
$engineSection->addInput($engineHelp);

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
}
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
	</div>
</div>
<?php
print_info_box(htmlspecialchars(pfsensePackageSinkholeTranslate('safesearch_unresolved_help')), 'info', false);

include('foot.inc');
