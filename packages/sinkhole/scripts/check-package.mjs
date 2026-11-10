import { access, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  releaseSigningKeyPattern,
  semanticVersionPattern,
} from './regex.mjs';

/**
 * Check Package - Workspace Directory.
 *
 * Resolves the generated pfSense package workspace from this script file.
 * Every structural check uses this stable absolute directory as its base.
 *
 * @since 0.0.0
 */
const workspaceDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Check Package - Required Files.
 *
 * Lists every source artifact needed to stage and publish the pfSense package.
 * A missing entry fails validation before a release archive is attempted.
 *
 * @since 0.0.0
 */
const requiredFiles = [
  'package.json',
  'port/Makefile.template',
  'port/pkg-descr',
  'port/pkg-plist',
  'port/files/pkg-deinstall.in',
  'port/files/pkg-install.in',
  'port/files/usr/local/pkg/sinkhole.inc',
  'port/files/usr/local/pkg/sinkhole.xml',
  'port/files/usr/local/pkg/priv/sinkhole.priv.inc',
  'port/files/usr/local/pkg/sinkhole/AlertConfiguration.php',
  'port/files/usr/local/pkg/sinkhole/AlertProcessor.php',
  'port/files/usr/local/pkg/sinkhole/AtomicFile.php',
  'port/files/usr/local/pkg/sinkhole/BypassConfiguration.php',
  'port/files/usr/local/pkg/sinkhole/BypassListStore.php',
  'port/files/usr/local/pkg/sinkhole/BypassParser.php',
  'port/files/usr/local/pkg/sinkhole/BypassRuleConfiguration.php',
  'port/files/usr/local/pkg/sinkhole/BypassUpdater.php',
  'port/files/usr/local/pkg/sinkhole/Catalog.php',
  'port/files/usr/local/pkg/sinkhole/CatalogCache.php',
  'port/files/usr/local/pkg/sinkhole/CatalogPresentation.php',
  'port/files/usr/local/pkg/sinkhole/ClientMap.php',
  'port/files/usr/local/pkg/sinkhole/ClientSource.php',
  'port/files/usr/local/pkg/sinkhole/Compiler.php',
  'port/files/usr/local/pkg/sinkhole/CurlDownloadClient.php',
  'port/files/usr/local/pkg/sinkhole/DomainParser.php',
  'port/files/usr/local/pkg/sinkhole/DownloadClient.php',
  'port/files/usr/local/pkg/sinkhole/FileLock.php',
  'port/files/usr/local/pkg/sinkhole/FileSystem.php',
  'port/files/usr/local/pkg/sinkhole/GeoLite2.php',
  'port/files/usr/local/pkg/sinkhole/IpConfiguration.php',
  'port/files/usr/local/pkg/sinkhole/IpListStore.php',
  'port/files/usr/local/pkg/sinkhole/IpNetwork.php',
  'port/files/usr/local/pkg/sinkhole/IpParser.php',
  'port/files/usr/local/pkg/sinkhole/IpRuleConfiguration.php',
  'port/files/usr/local/pkg/sinkhole/IpStatusStore.php',
  'port/files/usr/local/pkg/sinkhole/IpUpdater.php',
  'port/files/usr/local/pkg/sinkhole/ListConfiguration.php',
  'port/files/usr/local/pkg/sinkhole/PackagePaths.php',
  'port/files/usr/local/pkg/sinkhole/PfSenseAdapter.php',
  'port/files/usr/local/pkg/sinkhole/PlatformAdapter.php',
  'port/files/usr/local/pkg/sinkhole/RedirectConfiguration.php',
  'port/files/usr/local/pkg/sinkhole/SavedListStore.php',
  'port/files/usr/local/pkg/sinkhole/ScopeConfiguration.php',
  'port/files/usr/local/pkg/sinkhole/ServiceConfiguration.php',
  'port/files/usr/local/pkg/sinkhole/ServicePresentation.php',
  'port/files/usr/local/pkg/sinkhole/ServiceRegistry.php',
  'port/files/usr/local/pkg/sinkhole/ServiceRegistryCache.php',
  'port/files/usr/local/pkg/sinkhole/Settings.php',
  'port/files/usr/local/pkg/sinkhole/StateStore.php',
  'port/files/usr/local/pkg/sinkhole/TestedReleases.php',
  'port/files/usr/local/pkg/sinkhole/Translator.php',
  'port/files/usr/local/pkg/sinkhole/Translations.php',
  'port/files/usr/local/pkg/sinkhole/translations/bs.php',
  'port/files/usr/local/pkg/sinkhole/translations/zh_CN.php',
  'port/files/usr/local/pkg/sinkhole/translations/zh_Hans_CN.php',
  'port/files/usr/local/pkg/sinkhole/translations/zh_Hans_HK.php',
  'port/files/usr/local/pkg/sinkhole/translations/zh_Hant_TW.php',
  'port/files/usr/local/pkg/sinkhole/translations/nl_NL.php',
  'port/files/usr/local/pkg/sinkhole/translations/fr_FR.php',
  'port/files/usr/local/pkg/sinkhole/translations/de_DE.php',
  'port/files/usr/local/pkg/sinkhole/translations/it_IT.php',
  'port/files/usr/local/pkg/sinkhole/translations/ko_FR.php',
  'port/files/usr/local/pkg/sinkhole/translations/nb_NO.php',
  'port/files/usr/local/pkg/sinkhole/translations/pl_PL.php',
  'port/files/usr/local/pkg/sinkhole/translations/pt_PT.php',
  'port/files/usr/local/pkg/sinkhole/translations/pt_BR.php',
  'port/files/usr/local/pkg/sinkhole/translations/ru_RU.php',
  'port/files/usr/local/pkg/sinkhole/translations/es_ES.php',
  'port/files/usr/local/pkg/sinkhole/translations/es_AR.php',
  'port/files/usr/local/pkg/sinkhole/UnboundCustomOptions.php',
  'port/files/usr/local/pkg/sinkhole/UpdateManager.php',
  'port/files/usr/local/pkg/sinkhole/Updater.php',
  'port/files/usr/local/pkg/sinkhole/ValidationException.php',
  'port/files/usr/local/pkg/sinkhole/sinkhole_unbound.py',
  'port/files/usr/local/pkg/sinkhole/restore-runtime.sh',
  'port/files/usr/local/sbin/sinkhole',
  'port/files/usr/local/www/css/sinkhole.css',
  'port/files/usr/local/share/pfSense-pkg-Sinkhole/info.xml',
  'port/files/usr/local/share/pfSense-pkg-Sinkhole/logo.svg',
  'port/files/usr/local/share/pfSense-pkg-Sinkhole/release-signing.pub',
  'port/files/usr/local/www/sinkhole-about.php',
  'port/files/usr/local/www/sinkhole-alerts.php',
  'port/files/usr/local/www/sinkhole-alerts_edit.php',
  'port/files/usr/local/www/sinkhole-bypass.php',
  'port/files/usr/local/www/sinkhole-bypass_edit.php',
  'port/files/usr/local/www/sinkhole-lists.php',
  'port/files/usr/local/www/sinkhole-lists_edit.php',
  'port/files/usr/local/www/sinkhole-services.php',
  'port/files/usr/local/www/sinkhole-ip.php',
  'port/files/usr/local/www/sinkhole-ip_edit.php',
  'port/files/usr/local/www/sinkhole-scopes.php',
  'port/files/usr/local/www/sinkhole-scopes_edit.php',
  'port/files/usr/local/www/sinkhole-status.php',
  'tests/updates.php',
  'tests/bypass.php',
];

await Promise.all(requiredFiles.map(async (requiredFile) => {
  await access(join(workspaceDirectory, requiredFile));

  return;
}));

/**
 * Check Package - Release Signing Key File.
 *
 * Identifies the installed trust list used to authorize signed releases.
 * Diagnostics retain this relative path for actionable failures.
 *
 * @since 1.0.0
 */
const releaseSigningKeyFile = 'port/files/usr/local/share/pfSense-pkg-Sinkhole/release-signing.pub';

/**
 * Check Package - Release Signing Key Raw.
 *
 * Reads the trust list without discarding comments or blank lines.
 * The original text preserves exact source positions for validation.
 *
 * @since 1.0.0
 */
const releaseSigningKeyRaw = await readFile(
  join(workspaceDirectory, releaseSigningKeyFile),
  'utf-8',
);

/**
 * Check Package - Release Signing Key Lines.
 *
 * Splits the trust list while retaining every original entry.
 * Validation below normalizes one line at a time.
 *
 * @since 1.0.0
 */
const releaseSigningKeyLines = releaseSigningKeyRaw.split('\n');

for (
  let releaseSigningKeyIndex = 0;
  releaseSigningKeyIndex < releaseSigningKeyLines.length;
  releaseSigningKeyIndex += 1
) {
  const rawLine = releaseSigningKeyLines[releaseSigningKeyIndex];

  if (rawLine === undefined) {
    continue;
  }

  const line = rawLine.replaceAll('\r', '').trim();

  if (line === '' || line.startsWith('#') === true) {
    continue;
  }

  if (releaseSigningKeyPattern.test(line) === false) {
    throw new Error(
      `${releaseSigningKeyFile} has an invalid release signing key on line ${releaseSigningKeyIndex + 1}.`,
    );
  }
}

/**
 * Check Package - package.json Raw.
 *
 * Reads the workspace manifest before its release version is validated.
 * The raw value remains separate from the parsed object for clear diagnostics.
 *
 * @since 0.0.0
 */
const packageJsonRaw = await readFile(join(workspaceDirectory, 'package.json'), 'utf-8');

/**
 * Check Package - package.json.
 *
 * Parses the workspace manifest used to stage the FreeBSD port version.
 * Validation below rejects missing and malformed release values.
 *
 * @since 0.0.0
 */
const packageJson = JSON.parse(packageJsonRaw);

/**
 * Check Package - Version.
 *
 * Selects the manifest version embedded into the staged FreeBSD port.
 * Semantic-version validation keeps generated release metadata predictable.
 *
 * @since 0.0.0
 */
const version = packageJson['version'];

if (typeof version !== 'string' || semanticVersionPattern.test(version) === false) {
  throw new Error('package.json must contain a semantic version that can be staged as a FreeBSD port version.');
}

/**
 * Check Package - Makefile Template.
 *
 * Reads the port Makefile template so its Nova version token can be checked.
 * The staging command replaces this token with the validated package version.
 *
 * @since 0.0.0
 */
const makefileTemplate = await readFile(join(workspaceDirectory, 'port', 'Makefile.template'), 'utf-8');

if (makefileTemplate.includes('%%NOVA_PORTVERSION%%') === false) {
  throw new Error('port/Makefile.template must retain the %%NOVA_PORTVERSION%% build placeholder.');
}

/**
 * Check Package - Plist.
 *
 * Reads the installed-file manifest so the shared Sinkhole stylesheet and
 * custom About page can be checked against it.
 *
 * @since 1.0.0
 */
const plist = await readFile(join(workspaceDirectory, 'port', 'pkg-plist'), 'utf-8');

/**
 * Check Package - Sinkhole Stylesheet Install Marker.
 *
 * Builds the Makefile install line for the shared stylesheet in pieces so the
 * port variables are not read as template placeholders.
 *
 * @since 1.0.0
 */
const sinkholeStylesheetInstallMarker = [
  '$',
  '{FILESDIR}',
  '$',
  '{PREFIX}/www/css/sinkhole.css',
].join('');

if (
  plist.split('\n').includes('www/css/sinkhole.css') === false
  || makefileTemplate.includes(sinkholeStylesheetInstallMarker) === false
) {
  throw new Error('The port must stage and install the Sinkhole WebGUI stylesheet.');
}

if (plist.split('\n').includes('www/sinkhole-about.php') === false) {
  throw new Error('port/pkg-plist must install the Sinkhole About page.');
}

/**
 * Check Package - About Page Install Marker.
 *
 * Constructs the literal make-variable source path without template syntax.
 * The marker proves the port copies the About page into its staging tree.
 *
 * @since 1.0.0
 */
const aboutPageInstallMarker = [
  '$',
  '{FILESDIR}',
  '$',
  '{PREFIX}/www/sinkhole-about.php',
].join('');

if (makefileTemplate.includes(aboutPageInstallMarker) === false) {
  throw new Error('port/Makefile.template must stage the Sinkhole About page.');
}

/**
 * Check Package - Logo Install Marker.
 *
 * Confirms the byte-copied documentation logo reaches the port staging tree.
 * Both the recipe and plist must name the installed data file.
 *
 * @since 1.0.0
 */
const logoInstallMarker = [
  '$',
  '{FILESDIR}',
  '$',
  '{DATADIR}/logo.svg',
].join('');

if (
  makefileTemplate.includes(logoInstallMarker) === false
  || plist.split('\n').includes('%%DATADIR%%/logo.svg') === false
) {
  throw new Error('The port must stage and install the Sinkhole logo.');
}

/**
 * Check Package - Release Signing Install Marker.
 *
 * Builds the exact make-variable source path without template interpolation.
 * Both the recipe and plist must install the reviewed trust list.
 *
 * @since 1.0.0
 */
const releaseSigningInstallMarker = [
  '$',
  '{FILESDIR}',
  '$',
  '{DATADIR}/release-signing.pub',
].join('');

if (
  makefileTemplate.includes(`INSTALL_DATA} ${releaseSigningInstallMarker}`) === false
  || plist.split('\n').includes('%%DATADIR%%/release-signing.pub') === false
) {
  throw new Error('The port must stage and install release-signing.pub with INSTALL_DATA.');
}

/**
 * Check Package - Package Logo.
 *
 * The structural check runs with the full repository mounted, so it owns the
 * cross-workspace byte comparison that the isolated PHP suite cannot perform.
 *
 * @since 1.0.0
 */
const packageLogo = await readFile(join(
  workspaceDirectory,
  'port',
  'files',
  'usr',
  'local',
  'share',
  'pfSense-pkg-Sinkhole',
  'logo.svg',
));

/**
 * Check Package - Documentation Logo.
 *
 * Reads the documentation source logo for the cross-workspace byte comparison.
 * Keeping this check here lets the isolated PHP test mount only the package.
 *
 * @since 1.0.0
 */
const documentationLogo = await readFile(resolve(
  workspaceDirectory,
  '..',
  '..',
  'apps',
  'docs',
  'static',
  'images',
  'logo.svg',
));

if (packageLogo.equals(documentationLogo) === false) {
  throw new Error('The installed package logo must be a byte copy of the documentation logo.');
}

for (const catalogFile of [
  'ServiceConfiguration.php',
  'ServicePresentation.php',
  'ServiceRegistry.php',
  'ServiceRegistryCache.php',
  'TestedReleases.php',
  'Translator.php',
  'Translations.php',
  'translations/bs.php',
  'translations/zh_CN.php',
  'translations/zh_Hans_CN.php',
  'translations/zh_Hans_HK.php',
  'translations/zh_Hant_TW.php',
  'translations/nl_NL.php',
  'translations/fr_FR.php',
  'translations/de_DE.php',
  'translations/it_IT.php',
  'translations/ko_FR.php',
  'translations/nb_NO.php',
  'translations/pl_PL.php',
  'translations/pt_PT.php',
  'translations/pt_BR.php',
  'translations/ru_RU.php',
  'translations/es_ES.php',
  'translations/es_AR.php',
  'UnboundCustomOptions.php',
  'UpdateManager.php',
]) {
  const plistPath = `pkg/sinkhole/${catalogFile}`;
  const makefilePath = [
    '$',
    '{FILESDIR}',
    '$',
    `{PREFIX}/pkg/sinkhole/${catalogFile}`,
  ].join('');

  if (
    plist.split('\n').includes(plistPath) === false
    || makefileTemplate.includes(makefilePath) === false
  ) {
    throw new Error(`The port must stage and install ${catalogFile}.`);
  }
}

/**
 * Check Package - Services Page Install Marker.
 *
 * Keeps the page source, port install command, and plist entry together.
 * A missing marker fails before package staging can silently omit the page.
 *
 * @since 1.0.0
 */
const servicesPageInstallMarker = [
  '$',
  '{FILESDIR}',
  '$',
  '{PREFIX}/www/sinkhole-services.php',
].join('');

if (
  plist.split('\n').includes('www/sinkhole-services.php') === false
  || makefileTemplate.includes(servicesPageInstallMarker) === false
) {
  throw new Error('The port must stage and install the Sinkhole Services page.');
}

for (const editorPage of [
  'sinkhole-alerts_edit.php',
  'sinkhole-bypass_edit.php',
  'sinkhole-ip_edit.php',
  'sinkhole-lists_edit.php',
  'sinkhole-scopes_edit.php',
]) {
  const installMarker = [
    '$',
    '{FILESDIR}',
    '$',
    `{PREFIX}/www/${editorPage}`,
  ].join('');
  const source = await readFile(
    join(workspaceDirectory, 'port', 'files', 'usr', 'local', 'www', editorPage),
    'utf-8',
  );

  if (
    plist.split('\n').includes(`www/${editorPage}`) === false
    || makefileTemplate.includes(installMarker) === false
    || source.includes(`##|*MATCH=${editorPage}*`) === false
  ) {
    throw new Error(`The port must stage, install, and privilege ${editorPage}.`);
  }
}

/**
 * Check Package - About Page.
 *
 * Verifies the privilege, version fallbacks, safe links, and active package tab.
 * These markers keep the page aligned with the reviewed pfSense scaffold.
 *
 * @since 1.0.0
 */
const aboutPage = await readFile(
  join(workspaceDirectory, 'port', 'files', 'usr', 'local', 'www', 'sinkhole-about.php'),
  'utf-8',
);

for (const aboutPageMarker of [
  '##|*MATCH=sinkhole-about.php*',
  'UpdateManager::installedVersion()',
  'UpdateManager::readUpdatesState($paths->updatesFile)',
  'PackagePaths::UPDATE_CHECK_COMMAND',
  'PackagePaths::SELF_UPDATE_COMMAND',
  '\'self_update\',',
  'sinkhole-about.php?update_status=1',
  'pfsensePackageSinkholeTranslate(\'unknown\')',
  'pfsensePackageSinkholeTabs(\'about\')',
  'setAttribute(\'target\', \'_blank\')',
  'setAttribute(\'rel\', \'noopener noreferrer\')',
]) {
  if (aboutPage.includes(aboutPageMarker) === false) {
    throw new Error(`The About page is missing required content: ${aboutPageMarker}`);
  }
}

for (const protectedName of [
  'Sinkhole',
  'pfSense',
  'FreeBSD',
  'GitHub Sponsors',
  'PayPal',
]) {
  if (
    aboutPage.includes(`gettext('${protectedName}')`) === true
    || aboutPage.includes(`gettext("${protectedName}")`) === true
  ) {
    throw new Error(`The About page must not translate the protected name ${protectedName}.`);
  }
}

if (
  aboutPage.includes('? \'Plus\'') === false
  || aboutPage.includes(': \'CE\'') === false
  || aboutPage.includes('sprintf(\'pfSense %s %s\'') === false
) {
  throw new Error('The About page must compare raw edition IDs and keep its release label literal.');
}

/**
 * Check Package - Package Include.
 *
 * Reads the shared tab helper so About remains the final package tab.
 * Every custom page consumes this same ordered navigation definition.
 *
 * @since 1.0.0
 */
const packageInclude = await readFile(
  join(workspaceDirectory, 'port', 'files', 'usr', 'local', 'pkg', 'sinkhole.inc'),
  'utf-8',
);

/**
 * Check Package - Package XML.
 *
 * Reads the generic editor definition to verify its localization callback.
 * The hook rewrites Sinkhole-owned labels before pfSense renders the form.
 *
 * @since 1.0.0
 */
const packageXml = await readFile(
  join(workspaceDirectory, 'port', 'files', 'usr', 'local', 'pkg', 'sinkhole.xml'),
  'utf-8',
);

if (packageInclude.includes('\'about\' => \'/sinkhole-about.php\'') === false) {
  throw new Error('The Sinkhole tab helper must include About as its final tab.');
}

if (
  packageXml.includes('<custom_php_command_before_form>') === false
  || packageXml.includes('pfsensePackageSinkholeLocalizePackageGui($pkg);') === false
) {
  throw new Error('The package editor must localize the Sinkhole General page before rendering.');
}

process.stdout.write('pfSense package sources are structurally valid.\n');
