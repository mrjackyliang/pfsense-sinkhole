<?php

declare(strict_types=1);

/*
 * Sinkhole package information.
 * SPDX-License-Identifier: MIT
 */

##|+PRIV
##|*IDENT=page-firewall-sinkhole-about
##|*NAME=Firewall: Sinkhole: About
##|*DESCR=Allow access to the Sinkhole package information page.
##|*MATCH=sinkhole-about.php*
##|-PRIV

use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\TestedReleases;
use PfSense\Sinkhole\Runtime\UpdateManager;

require_once('guiconfig.inc');
require_once('pfsense-utils.inc');
require_once('/usr/local/pkg/sinkhole.inc');
require_once('/usr/local/pkg/sinkhole/PackagePaths.php');
require_once('/usr/local/pkg/sinkhole/TestedReleases.php');
require_once('/usr/local/pkg/sinkhole/UpdateManager.php');

$escape = static fn (string $value): string => htmlspecialchars(
    $value,
    ENT_QUOTES | ENT_SUBSTITUTE,
    'UTF-8',
);
$paths = new PackagePaths();
$packageDataPath = '/usr/local/share/pfSense-pkg-Sinkhole';
$packageLogoPath = $packageDataPath . '/logo.svg';
$packageName = 'Sinkhole';
$installedPackageVersion = UpdateManager::installedVersion();
$packageVersion = $installedPackageVersion
    ?? pfsensePackageSinkholeTranslate('unknown');
$updatesAvailable = UpdateManager::isAvailable();
$currentUserEntry = getUserEntry((string) ($_SESSION['Username'] ?? ''));
$currentUser = is_array($currentUserEntry)
    && is_array($currentUserEntry['item'] ?? null)
    ? $currentUserEntry['item']
    : [];
$canManageUpdates = userHasPrivilege(
    $currentUser,
    'page-firewall-sinkhole-general',
) || userHasPrivilege($currentUser, 'page-all');

if ($updatesAvailable && ($_GET['update_status'] ?? '') === '1') {
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');

    try {
        $statusResponse = UpdateManager::readStatusState($paths->updateStatusFile)
            ?? ['state' => 'idle'];
    } catch (Throwable $throwable) {
        $statusResponse = [
            'state' => 'failed',
            'message' => $throwable->getMessage(),
        ];
    }

    echo json_encode(
        $statusResponse,
        JSON_INVALID_UTF8_SUBSTITUTE
            | JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE
            | JSON_THROW_ON_ERROR,
    );
    exit;
}

$updateActionError = null;

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'
    && $canManageUpdates === false
    && (isset($_POST['check_updates']) || isset($_POST['self_update']))
) {
    $updateActionError = pfsensePackageSinkholeTranslate(
        'package_update_privilege_required',
    );
} elseif ($updatesAvailable && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (isset($_POST['check_updates'])) {
        $actionOutputLines = [];

        exec(PackagePaths::UPDATE_CHECK_COMMAND . ' 2>&1', $actionOutputLines, $returnCode);
        $actionOutput = implode(PHP_EOL, $actionOutputLines);

        if (
            $returnCode !== 0
            || trim($actionOutput) === pfsensePackageSinkholeTranslate(
                'another_package_operation_running',
            )
        ) {
            $updateActionError = $actionOutput !== ''
                ? $actionOutput
                : pfsensePackageSinkholeTranslate('update_request_initialize_failed');
        }
    } elseif (isset($_POST['self_update'])) {
        try {
            $queuedState = UpdateManager::readUpdatesState($paths->updatesFile);
            $queuedVersion = $queuedState['latest_version'] ?? null;

            if (!is_string($queuedVersion) || $queuedVersion === '') {
                throw new RuntimeException(
                    pfsensePackageSinkholeTranslate('updates_not_checked'),
                );
            }

            $currentJob = UpdateManager::readStatusState($paths->updateStatusFile);

            if (is_array($currentJob) && ($currentJob['state'] ?? null) === 'running') {
                throw new RuntimeException((string) (
                    $currentJob['message']
                    ?? pfsensePackageSinkholeTranslate('update_starting')
                ));
            }

            UpdateManager::queueSelfUpdate($queuedVersion, $paths->updateStatusFile);

            try {
                mwexec_bg(PackagePaths::SELF_UPDATE_COMMAND);
            } catch (Throwable $throwable) {
                UpdateManager::failQueuedSelfUpdate(
                    $throwable->getMessage(),
                    $paths->updateStatusFile,
                );

                throw $throwable;
            }
        } catch (Throwable $throwable) {
            $updateActionError = $throwable->getMessage();
        }
    }
}

$updateState = null;
$updateStatus = null;

if ($updatesAvailable) {
    try {
        $updateState = UpdateManager::readUpdatesState($paths->updatesFile);
    } catch (Throwable $throwable) {
        $updateActionError ??= $throwable->getMessage();
    }

    try {
        $updateStatus = UpdateManager::readStatusState($paths->updateStatusFile);
    } catch (Throwable $throwable) {
        $updateActionError ??= $throwable->getMessage();
    }
}

$updateState ??= [
    'checked_at' => null,
    'latest_version' => null,
    'release_url' => null,
    'last_error' => null,
];
$settings = pfsensePackageSinkholeGetSettings();
$updateCheckFrequency = (string) ($settings['update_check_frequency'] ?? 'weekly');
$latestVersion = $updateState['latest_version'] ?? null;
$checkedAt = $updateState['checked_at'] ?? null;
$checkedAtDisplay = null;

if (is_string($checkedAt) && $checkedAt !== '') {
    $checkedTimestamp = strtotime($checkedAt);
    $checkedAtDisplay = $checkedTimestamp === false
        ? $checkedAt
        : date('Y-m-d H:i:s T', $checkedTimestamp);
}

$releaseUrl = $updateState['release_url'] ?? null;
$releaseUrl = is_string($releaseUrl) && UpdateManager::isAllowedReleaseUrl($releaseUrl)
    ? $releaseUrl
    : null;
$updateAvailable = is_string($installedPackageVersion)
    && is_string($latestVersion)
    && UpdateManager::isNewerVersion($installedPackageVersion, $latestVersion);
$updateError = $updateActionError ?? ($updateState['last_error'] ?? null);
$updateJobState = is_array($updateStatus) ? ($updateStatus['state'] ?? null) : null;
$updateJobMessage = is_array($updateStatus) ? ($updateStatus['message'] ?? null) : null;
$updateJobRunning = $updateJobState === 'running';
$updateBarTone = match (true) {
    $updateJobState === 'failed', is_string($updateError) && $updateError !== '' => 'is-error',
    $updateJobRunning => 'is-running',
    $updateJobState === 'succeeded', $updateAvailable => 'is-success',
    default => 'is-muted',
};
$packageLogoData = null;

if (is_readable($packageLogoPath)) {
    $packageLogo = file_get_contents($packageLogoPath);

    if (is_string($packageLogo)) {
        $packageLogoData = 'data:image/svg+xml;base64,' . base64_encode($packageLogo);
    }
}

$projectDescription = pfsensePackageSinkholeTranslate('project_description');
$projectDocumentation = 'https://mrjackyliang.github.io/pfsense-sinkhole/';
$projectRepository = 'https://github.com/mrjackyliang/pfsense-sinkhole';
$projectBugs = 'https://github.com/mrjackyliang/pfsense-sinkhole/issues';
$projectLicense = 'https://github.com/mrjackyliang/pfsense-sinkhole/blob/HEAD/LICENSE';
$projectReleaseNotes = $projectRepository . '/releases';
$fundSources = [
    'https://github.com/sponsors/mrjackyliang',
    'https://liang.nyc/paypal',
];

$productLabel = g_get('product_label');
$productVersion = g_get('product_version');
$currentEdition = is_string($productLabel) && stripos($productLabel, 'Plus') !== false
    ? 'Plus'
    : 'CE';
$currentVersion = is_string($productVersion) ? trim($productVersion) : '';
$normalizedVersion = preg_replace('/-RELEASE(?:-p[0-9]+)?$/i', '', $currentVersion);

if (is_string($normalizedVersion)) {
    $currentVersion = $normalizedVersion;
}

$normalizedVersion = preg_replace('/-p[0-9]+$/i', '', $currentVersion);

if (is_string($normalizedVersion)) {
    $currentVersion = $normalizedVersion;
}

if ($currentVersion === '') {
    $currentVersion = pfsensePackageSinkholeTranslate('unknown');
}

$freeBsdRelease = php_uname('r');
$currentFreeBsd = pfsensePackageSinkholeTranslate('unknown');

if (preg_match('/^([0-9]+\.[0-9]+)/', $freeBsdRelease, $freeBsdReleaseMatches) === 1) {
    $currentFreeBsd = $freeBsdReleaseMatches[1];
}

$testedReleases = TestedReleases::RELEASES;
$currentReleaseTested = false;

foreach ($testedReleases as $testedRelease) {
    if (
        $testedRelease['edition'] === $currentEdition
        && $testedRelease['version'] === $currentVersion
    ) {
        $currentReleaseTested = true;
        break;
    }
}

$supportLicenseLabel = pfsensePackageSinkholeTranslate('mit_license');
$supportLicenseLabelEscaped = $escape($supportLicenseLabel);
$supportLicenseLinkHtml = $supportLicenseLabelEscaped;

if ($projectLicense !== '') {
    $projectLicenseEscaped = $escape($projectLicense);
    $supportLicenseLinkHtml = sprintf(
        '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
        $projectLicenseEscaped,
        $supportLicenseLabelEscaped,
    );
}

$supportPackageToken = '__SINKHOLE_PACKAGE_NAME__';
$supportLicenseToken = '__SINKHOLE_LICENSE_LINK__';
$supportMessageTemplate = pfsensePackageSinkholeTranslate(
    'support_message',
    [$supportPackageToken, $supportLicenseToken],
);
$supportMessageTemplateEscaped = $escape($supportMessageTemplate);
$packageNameEscaped = $escape($packageName);
$supportMessage = str_replace(
    [$supportPackageToken, $supportLicenseToken],
    [$packageNameEscaped, $supportLicenseLinkHtml],
    $supportMessageTemplateEscaped,
);

$pgtitle = [
    gettext('Firewall'),
    $packageName,
    pfsensePackageSinkholeTranslate('about'),
];
$pglinks = [
    '',
    '/pkg_edit.php?xml=sinkhole.xml&id=0',
    '@self',
];

include('head.inc');
$selfUpdateButtonHtml = null;

if ($canManageUpdates && is_string($latestVersion)) {
    $selfUpdateButton = new Form_Button(
        'self_update',
        pfsensePackageSinkholeTranslate('update_to_version', [$latestVersion]),
        null,
        'fa-solid fa-download',
    );
    $selfUpdateButton->addClass('btn-success', 'btn-sm');
    $selfUpdateButtonHtml = (string) $selfUpdateButton;
}

$whatsNewButtonHtml = null;

if (is_string($releaseUrl)) {
    $whatsNewButton = new Form_Button(
        'whats_new',
        pfsensePackageSinkholeTranslate('whats_new'),
        $releaseUrl,
        'fa-solid fa-tag',
    );
    $whatsNewButton->removeClass('btn-default');
    $whatsNewButton->addClass('btn-info', 'btn-sm');
    $whatsNewButton->setAttribute('target', '_blank');
    $whatsNewButton->setAttribute('rel', 'noopener noreferrer');
    $whatsNewButtonHtml = (string) $whatsNewButton;
}

$checkUpdatesButtonHtml = null;

if ($canManageUpdates) {
    $checkUpdatesButton = new Form_Button(
        'check_updates',
        pfsensePackageSinkholeTranslate('check_now'),
        null,
        'fa-solid fa-arrows-rotate',
    );
    $checkUpdatesButton->removeClass('btn-default');
    $checkUpdatesButton->addClass('btn-info', 'btn-sm');
    $checkUpdatesButtonHtml = (string) $checkUpdatesButton;
}
?>
<link rel="stylesheet" href="/css/sinkhole.css">
<?php display_top_tabs(pfsensePackageSinkholeTabs('about')); ?>
<div class="pkg-about">
	<div class="panel panel-default">
		<div class="panel-body">
			<div class="form-group pkg-about-hero">
<?php if ($packageLogoData !== null): ?>
				<img class="pkg-about-logo" src="<?=$escape($packageLogoData)?>" width="96" height="96" alt="">
<?php endif; ?>
				<div class="pkg-about-hero-text">
					<h2 class="pkg-about-name"><?=$escape($packageName)?><span class="label label-primary"><?=$escape($packageVersion)?></span></h2>
					<p class="pkg-about-tagline"><?=$escape($projectDescription)?></p>
					<div class="pkg-about-actions">
						<a class="btn btn-sm btn-primary" href="<?=$escape($projectDocumentation)?>" target="_blank" rel="noopener noreferrer"><i class="fa-solid fa-book icon-embed-btn"></i><?=$escape(pfsensePackageSinkholeTranslate('documentation'))?></a>
						<a class="btn btn-sm btn-info" href="<?=$escape($projectRepository)?>" target="_blank" rel="noopener noreferrer"><i class="fa-brands fa-github icon-embed-btn"></i><?=$escape(pfsensePackageSinkholeTranslate('source_code'))?></a>
						<a class="btn btn-sm btn-info" href="<?=$escape($projectBugs)?>" target="_blank" rel="noopener noreferrer"><i class="fa-solid fa-bug icon-embed-btn"></i><?=$escape(pfsensePackageSinkholeTranslate('report_issue'))?></a>
						<a class="btn btn-sm btn-info" href="<?=$escape($projectReleaseNotes)?>" target="_blank" rel="noopener noreferrer"><i class="fa-solid fa-tag icon-embed-btn"></i><?=$escape(pfsensePackageSinkholeTranslate('release_notes'))?></a>
					</div>
<?php if ($updatesAvailable): ?>
					<div class="pkg-about-update <?=$escape($updateBarTone)?>">
						<span class="pkg-about-update-text" id="pkg-about-update-status">
<?php if (is_string($updateJobMessage) && $updateJobMessage !== ''): ?>
							<i class="fa-solid <?=$escape($updateJobRunning ? 'fa-spinner fa-spin' : ($updateJobState === 'succeeded' ? 'fa-circle-check' : 'fa-circle-exclamation'))?>"></i><strong><?=$escape($updateJobMessage)?></strong>
<?php elseif (is_string($updateError) && $updateError !== ''): ?>
							<i class="fa-solid fa-circle-exclamation"></i><span><?=$escape(pfsensePackageSinkholeTranslate('last_update_check_failed', [$updateError]))?></span>
<?php elseif ($updateAvailable && is_string($latestVersion)): ?>
							<i class="fa-solid fa-circle-up"></i><strong><?=$escape(pfsensePackageSinkholeTranslate('version_available', [$latestVersion]))?></strong><?php if (is_string($checkedAtDisplay)): ?><span class="pkg-about-update-detail"><?=$escape(pfsensePackageSinkholeTranslate('checked_at', [$checkedAtDisplay]))?></span><?php endif; ?>
<?php elseif (is_string($checkedAtDisplay) && !is_string($latestVersion)): ?>
							<i class="fa-solid fa-circle-info"></i><span><?=$escape(pfsensePackageSinkholeTranslate('no_public_release'))?></span><span class="pkg-about-update-detail"><?=$escape(pfsensePackageSinkholeTranslate('checked_at', [$checkedAtDisplay]))?></span>
<?php elseif ($updateCheckFrequency === 'never'): ?>
							<i class="fa-solid fa-circle-pause"></i><span><?=$escape(pfsensePackageSinkholeTranslate('update_checks_off'))?></span>
<?php elseif (is_string($checkedAtDisplay)): ?>
							<i class="fa-solid fa-circle-check"></i><span><?=$escape(pfsensePackageSinkholeTranslate('up_to_date_checked', [$checkedAtDisplay]))?></span>
<?php else: ?>
							<i class="fa-solid fa-circle-info"></i><span><?=$escape(pfsensePackageSinkholeTranslate('updates_not_checked'))?></span>
<?php endif; ?>
						</span>
						<div class="pkg-about-update-actions">
<?php if ($updateAvailable && is_string($latestVersion) && !$updateJobRunning && $updateJobState !== 'succeeded'): ?>
<?php if ($canManageUpdates): ?>
							<form method="post"><?=$selfUpdateButtonHtml?></form>
<?php endif; ?>
<?php if ($whatsNewButtonHtml !== null): ?>
							<?=$whatsNewButtonHtml?>
<?php endif; ?>
<?php elseif ($canManageUpdates && !$updateJobRunning): ?>
							<form method="post"><?=$checkUpdatesButtonHtml?></form>
<?php endif; ?>
						</div>
					</div>
<?php endif; ?>
				</div>
			</div>
		</div>
	</div>
	<div class="row">
<?php if ($testedReleases !== []): ?>
		<div class="col-md-7">
			<div class="panel panel-default">
				<div class="panel-heading"><h2 class="panel-title"><?=$escape(pfsensePackageSinkholeTranslate('tested_pfsense_releases'))?></h2></div>
				<div class="panel-body">
					<div class="table-responsive">
						<table class="table table-striped table-hover pkg-about-table">
							<thead><tr><th><?=$escape(pfsensePackageSinkholeTranslate('release'))?></th><th><?=$escape('FreeBSD')?></th></tr></thead>
							<tbody>
<?php foreach ($testedReleases as $testedRelease): ?>
								<tr><td><i class="fa-regular fa-circle-check text-success"></i><?=$escape(sprintf('pfSense %s %s', $testedRelease['edition'], $testedRelease['version']))?><?php if ($testedRelease['edition'] === $currentEdition && $testedRelease['version'] === $currentVersion): ?><span class="label label-info"><?=$escape(pfsensePackageSinkholeTranslate('this_firewall'))?></span><?php endif; ?></td><td><?=$escape($testedRelease['freebsd'])?></td></tr>
<?php endforeach; ?>
<?php if ($currentReleaseTested === false): ?>
								<tr class="pkg-about-untested"><td><i class="fa-regular fa-circle"></i><?=$escape(sprintf('pfSense %s %s', $currentEdition, $currentVersion))?><span class="label label-info"><?=$escape(pfsensePackageSinkholeTranslate('this_firewall'))?></span><span class="pkg-about-note"><?=$escape(pfsensePackageSinkholeTranslate('not_tested'))?></span></td><td><?=$escape($currentFreeBsd)?></td></tr>
<?php endif; ?>
								<tr><td colspan="2"><span class="pkg-about-footnote"><?=$escape(pfsensePackageSinkholeTranslate('tested_release_footnote'))?></span></td></tr>
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
<?php endif; ?>
		<div class="<?=$escape($testedReleases === [] ? 'col-md-12' : 'col-md-5')?>">
			<div class="panel panel-default">
				<div class="panel-heading"><h2 class="panel-title"><?=$escape(pfsensePackageSinkholeTranslate('support_project'))?></h2></div>
				<div class="panel-body pkg-about-pad">
					<div class="form-group pkg-about-support">
						<p><?=$supportMessage?></p>
<?php if ($fundSources !== []): ?>
						<div class="pkg-about-actions">
<?php foreach ($fundSources as $fundSourceIndex => $fundSource): ?>
<?php
    $fundSourceLabel = pfsensePackageSinkholeTranslate(
        'support_number',
        [$fundSourceIndex + 1],
    );
    $fundSourceIconClass = 'fa-solid fa-heart';
    $fundSourceButtonClass = 'btn-success';

    if (stripos($fundSource, 'github.com/sponsors/') !== false) {
        $fundSourceLabel = 'GitHub Sponsors';
    } elseif (stripos($fundSource, 'paypal') !== false) {
        $fundSourceLabel = 'PayPal';
        $fundSourceIconClass = 'fa-brands fa-paypal';
        $fundSourceButtonClass = 'btn-info';
    }
?>
							<a class="btn btn-sm <?=$escape($fundSourceButtonClass)?>" href="<?=$escape($fundSource)?>" target="_blank" rel="noopener noreferrer"><i class="<?=$escape($fundSourceIconClass)?> icon-embed-btn"></i><?=$escape($fundSourceLabel)?></a>
<?php endforeach; ?>
						</div>
<?php endif; ?>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>
<?php if ($updatesAvailable && $updateJobRunning): ?>
<script>
(function () {
	'use strict';

	var statusLine = document.getElementById('pkg-about-update-status');
	var messageNode = statusLine ? statusLine.querySelector('strong') : null;

	window.setInterval(function () {
		window.fetch('sinkhole-about.php?update_status=1', {
			credentials: 'same-origin',
			cache: 'no-store'
		}).then(function (response) {
			if (!response.ok) {
				throw new Error('status');
			}

			return response.json();
		}).then(function (status) {
			if (status.state !== 'running') {
				window.location.reload();

				return;
			}

			if (messageNode && typeof status.message === 'string') {
				messageNode.textContent = status.message;
			}
		}).catch(function () {
			// A later poll can recover from a transient WebGUI or network failure.
		});
	}, 3000);
}());
</script>
<?php endif; ?>
<?php

include('foot.inc');
