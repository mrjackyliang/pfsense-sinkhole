<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use JsonException;
use RuntimeException;
use Throwable;

require_once(__DIR__ . '/PackagePaths.php');
require_once(__DIR__ . '/Translator.php');

/**
 * Update Manager.
 *
 * Scheduled checks, notices, and the About tab share this boundary so release
 * parsing and every verification step remain independently testable.
 *
 * @since 1.0.0
 */
final class UpdateManager
{
    /** @var string @since 1.0.0 */
    public const RELEASES_API = 'https://api.github.com/repos/mrjackyliang/pfsense-sinkhole/releases/latest';

    /** @var string @since 1.0.0 */
    public const DOWNLOAD_PREFIX = 'https://github.com/mrjackyliang/pfsense-sinkhole/releases/download/';

    /** @var string @since 1.0.0 */
    public const NOTICE_ID = 'sinkhole-update-available';

    /** @var string @since 1.0.0 */
    public const PACKAGE_NAME = 'pfSense-pkg-Sinkhole';

    /** @var string @since 1.0.0 */
    public const PACKAGE_DATA_DIRECTORY = '/usr/local/share/pfSense-pkg-Sinkhole';

    /** @var string @since 1.0.0 */
    public const SIGNING_KEYS_FILE = self::PACKAGE_DATA_DIRECTORY . '/release-signing.pub';

    /** @var string @since 1.0.0 */
    public const SSH_KEYGEN_COMMAND = '/usr/bin/ssh-keygen';

    /** @var string @since 1.0.0 */
    public const ABOUT_PAGE = '/sinkhole-about.php';

    /** @var string @since 1.0.0 @private */
    private const USER_AGENT = 'pfSense-pkg-Sinkhole';

    /** @var int @since 1.0.0 @private */
    private const PACKAGE_DOWNLOAD_LIMIT = 64 * 1024 * 1024;

    /** @var int @since 1.0.0 @private */
    private const AUXILIARY_DOWNLOAD_LIMIT = 64 * 1024;

    /** @var string @since 1.0.0 @private */
    private const PKG_COMMAND = '/usr/local/sbin/pkg';

    /**
     * Update Manager - Constructor.
     *
     * Production uses fixed endpoints and trust paths. Tests can isolate release
     * state and command boundaries without exposing those overrides to the WebGUI.
     *
     * @param string $installedVersion - Installed package version.
     * @param string $releasesApi - Latest-release API endpoint.
     * @param string $downloadPrefix - Allowed release asset URL prefix.
     * @param string $updatesFile - Persistent update metadata path.
     * @param string $statusFile - Background update status path.
     * @param string $signingKeysFile - Test release signing key path.
     * @param string $sshKeygenCommand - Test OpenSSH executable path.
     *
     * @since 1.0.0
     */
    public function __construct(
        private readonly string $installedVersion,
        private readonly string $releasesApi = self::RELEASES_API,
        private readonly string $downloadPrefix = self::DOWNLOAD_PREFIX,
        private readonly string $updatesFile = PackagePaths::UPDATES_FILE,
        private readonly string $statusFile = PackagePaths::UPDATE_STATUS_FILE,
        private readonly string $signingKeysFile = self::SIGNING_KEYS_FILE,
        private readonly string $sshKeygenCommand = self::SSH_KEYGEN_COMMAND,
    ) {
    }

    /**
     * Update Manager - Is Available.
     *
     * A generated package without a GitHub release endpoint cannot check updates.
     * Sinkhole always supplies both reviewed repository constants.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function isAvailable(): bool
    {
        return self::RELEASES_API !== '' && self::DOWNLOAD_PREFIX !== '';
    }

    /**
     * Update Manager - Is No Public Release Status.
     *
     * GitHub uses HTTP 404 when a repository has no public release, which is a
     * successful empty update result rather than an update-check failure.
     *
     * @param int $statusCode - HTTP response status.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function isNoPublicReleaseStatus(int $statusCode): bool
    {
        return $statusCode === 404;
    }

    /**
     * Update Manager - Assert Environment.
     *
     * Fixed system includes provide configuration, proxy, notice, and logging
     * functions without loading package integration side effects.
     *
     * @return void
     *
     * @throws RuntimeException When the host lacks a required pfSense boundary.
     *
     * @since 1.0.0
     */
    public static function assertEnvironment(): void
    {
        if (self::isAvailable() === false) {
            throw new RuntimeException(self::translate('update_checks_unavailable_repository'));
        }

        if (PHP_OS_FAMILY !== 'BSD' || file_exists('/etc/version') === false) {
            throw new RuntimeException(self::translate('unsupported_pfsense_system'));
        }

        $requiredFiles = [
            '/etc/inc/config.inc',
            '/etc/inc/notices.inc',
            '/etc/inc/pfsense-utils.inc',
        ];

        foreach ($requiredFiles as $requiredFile) {
            if (is_readable($requiredFile) === false) {
                throw new RuntimeException(self::translate(
                    'required_pfsense_dependency_unavailable',
                    [$requiredFile],
                ));
            }

            require_once($requiredFile);
        }

        $requiredFunctions = [
            'close_notice',
            'config_get_path',
            'file_notice',
            'log_error',
            'set_curlproxy',
        ];

        foreach ($requiredFunctions as $requiredFunction) {
            if (function_exists($requiredFunction) === false) {
                throw new RuntimeException(self::translate(
                    'required_pfsense_dependency_unavailable',
                    [$requiredFunction],
                ));
            }
        }

        if (function_exists('curl_init') === false) {
            throw new RuntimeException(self::translate('curl_support_unavailable'));
        }
    }

    /**
     * Update Manager - Check.
     *
     * Fetches the latest release, preserves normalized state, and creates at most
     * one notice for each newly observed version.
     *
     * @param bool $remoteNotifications - Whether remote notice delivery is enabled.
     *
     * @return array
     *
     * @throws Throwable When release or state processing fails.
     *
     * @since 1.0.0
     */
    public function check(bool $remoteNotifications): array
    {
        $this->clearStatus();

        $state = self::readUpdatesState($this->updatesFile);
        $checkedAt = gmdate(DATE_ATOM);

        try {
            $release = $this->fetchLatestRelease();
            $state = [
                'checked_at' => $checkedAt,
                'latest_version' => $release['version'],
                'tag' => $release['tag'],
                'release_url' => $release['release_url'],
                'published_at' => $release['published_at'],
                'notified_version' => $state['notified_version'],
                'last_error' => null,
            ];
            $state = self::synchronizeNotice(
                $state,
                $this->installedVersion,
                $release['version'],
                $remoteNotifications,
            );

            self::writeJsonAtomically($this->updatesFile, $state);

            return $state;
        } catch (Throwable $throwable) {
            if (
                $throwable instanceof RuntimeException
                && self::isNoPublicReleaseStatus($throwable->getCode())
            ) {
                $state = [
                    'checked_at' => $checkedAt,
                    'latest_version' => null,
                    'tag' => null,
                    'release_url' => null,
                    'published_at' => null,
                    'notified_version' => $state['notified_version'],
                    'last_error' => null,
                ];

                self::writeJsonAtomically($this->updatesFile, $state);

                return $state;
            }

            $state['checked_at'] = $checkedAt;
            $state['last_error'] = $throwable->getMessage();

            self::writeJsonAtomically($this->updatesFile, $state);
            $this->logFailure($throwable);

            throw $throwable;
        }
    }

    /**
     * Update Manager - Cron Fields.
     *
     * Stable random components are shared across daily, weekly, and monthly
     * frequencies so changing the setting never redraws the schedule.
     *
     * @param string $frequency - Daily, weekly, monthly, or never.
     * @param array $schedule - Stable random schedule values.
     *
     * @return array{string, string, string, string, string}|null
     *
     * @since 1.0.0
     */
    public static function cronFields(string $frequency, array $schedule): ?array
    {
        $minute = (string) $schedule['minute'];
        $hour = (string) $schedule['hour'];

        return match ($frequency) {
            'daily' => [$minute, $hour, '*', '*', '*'],
            'weekly' => [$minute, $hour, '*', '*', (string) $schedule['weekday']],
            'monthly' => [$minute, $hour, (string) $schedule['monthday'], '*', '*'],
            'never' => null,
            default => [$minute, $hour, '*', '*', (string) $schedule['weekday']],
        };
    }

    /**
     * Update Manager - Installed Version.
     *
     * The installed-package record is authoritative, with shipped package metadata
     * serving as the lifecycle fallback used by the About page and CLI.
     *
     * @return string|null
     *
     * @since 1.0.0
     */
    public static function installedVersion(): ?string
    {
        if (function_exists('config_get_path')) {
            $installedPackages = config_get_path('installedpackages/package', []);

            if (is_array($installedPackages)) {
                foreach ($installedPackages as $installedPackage) {
                    if (
                        !is_array($installedPackage)
                        || ($installedPackage['name'] ?? null) !== 'Sinkhole'
                    ) {
                        continue;
                    }

                    $installedPackageVersion = $installedPackage['version'] ?? null;

                    if (is_string($installedPackageVersion) && $installedPackageVersion !== '') {
                        return $installedPackageVersion;
                    }
                }
            }
        }

        $packageInfoPath = self::PACKAGE_DATA_DIRECTORY . '/info.xml';

        if (is_readable($packageInfoPath) === false) {
            return null;
        }

        if (function_exists('parse_xml_config_pkg') === false) {
            $xmlParserPath = '/etc/inc/xmlparse.inc';

            if (is_readable($xmlParserPath) === false) {
                return null;
            }

            require_once($xmlParserPath);
        }

        $packageInfo = parse_xml_config_pkg($packageInfoPath, 'pfsensepkgs');
        $packageInfoPackage = is_array($packageInfo)
            ? ($packageInfo['package'] ?? null)
            : null;

        if (!is_array($packageInfoPackage)) {
            return null;
        }

        $packageInfoVersion = $packageInfoPackage['version'] ?? null;

        if (!is_string($packageInfoVersion)) {
            $packageInfoPackageFirst = $packageInfoPackage[0] ?? null;
            $packageInfoVersion = is_array($packageInfoPackageFirst)
                ? ($packageInfoPackageFirst['version'] ?? null)
                : null;
        }

        return is_string($packageInfoVersion) && $packageInfoVersion !== ''
            ? $packageInfoVersion
            : null;
    }

    /**
     * Update Manager - Is Allowed Asset URL.
     *
     * Production accepts only the Sinkhole GitHub release download path. The CLI
     * may supply one explicit test prefix for an isolated fake release server.
     *
     * @param string $url - Asset URL.
     * @param string $downloadPrefix - Allowed prefix.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function isAllowedAssetUrl(
        string $url,
        string $downloadPrefix = self::DOWNLOAD_PREFIX,
    ): bool {
        return $downloadPrefix !== '' && str_starts_with($url, $downloadPrefix);
    }

    /**
     * Update Manager - Is Allowed Release URL.
     *
     * Persistent release links must remain under this repository's HTTPS release
     * pages before the About tab renders them.
     *
     * @param string $url - Release page URL.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function isAllowedReleaseUrl(string $url): bool
    {
        if (!str_ends_with(self::DOWNLOAD_PREFIX, 'download/')) {
            return false;
        }

        $releasePagePrefix = substr(
            self::DOWNLOAD_PREFIX,
            0,
            -strlen('download/'),
        );

        return $releasePagePrefix !== '' && str_starts_with($url, $releasePagePrefix);
    }

    /**
     * Update Manager - Is Newer Version.
     *
     * Git tags may carry one leading letter while package metadata stores the
     * semantic version alone, so both values are normalized first.
     *
     * @param string $installedVersion - Installed version.
     * @param string $latestVersion - Latest release version.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function isNewerVersion(
        string $installedVersion,
        string $latestVersion,
    ): bool {
        $normalizedInstalledVersion = self::normalizeVersion($installedVersion);
        $normalizedLatestVersion = self::normalizeVersion($latestVersion);

        return version_compare(
            $normalizedLatestVersion,
            $normalizedInstalledVersion,
            '>',
        );
    }

    /**
     * Update Manager - Parse Release JSON.
     *
     * Malformed external data fails closed before any release field reaches
     * persistent package state or the About page.
     *
     * @param string $json - GitHub release JSON.
     *
     * @return array
     *
     * @throws RuntimeException When required release fields are invalid.
     *
     * @since 1.0.0
     */
    public static function parseReleaseJson(string $json): array
    {
        try {
            $releaseData = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw new RuntimeException(
                self::translate('release_metadata_invalid'),
                0,
                $jsonException,
            );
        }

        if (!is_array($releaseData)) {
            throw new RuntimeException(self::translate('release_metadata_invalid'));
        }

        $tag = $releaseData['tag_name'] ?? null;
        $releaseUrl = $releaseData['html_url'] ?? null;
        $publishedAt = $releaseData['published_at'] ?? null;
        $releaseAssets = $releaseData['assets'] ?? null;

        if (
            !is_string($tag)
            || $tag === ''
            || !is_string($releaseUrl)
            || self::isAllowedReleaseUrl($releaseUrl) === false
            || !is_string($publishedAt)
            || $publishedAt === ''
            || !is_array($releaseAssets)
        ) {
            throw new RuntimeException(self::translate('release_metadata_invalid'));
        }

        $version = self::normalizeVersion($tag);

        if (preg_match('/^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/', $version) !== 1) {
            throw new RuntimeException(self::translate('release_tag_invalid'));
        }

        $assets = [];

        foreach ($releaseAssets as $releaseAsset) {
            if (!is_array($releaseAsset)) {
                continue;
            }

            $releaseAssetName = $releaseAsset['name'] ?? null;
            $releaseAssetUrl = $releaseAsset['browser_download_url'] ?? null;
            $releaseAssetDigest = $releaseAsset['digest'] ?? null;

            if (!is_string($releaseAssetName) || !is_string($releaseAssetUrl)) {
                continue;
            }

            $assets[] = [
                'name' => $releaseAssetName,
                'url' => $releaseAssetUrl,
                'digest' => is_string($releaseAssetDigest)
                    ? $releaseAssetDigest
                    : null,
            ];
        }

        return [
            'tag' => $tag,
            'version' => $version,
            'release_url' => $releaseUrl,
            'published_at' => $publishedAt,
            'assets' => $assets,
        ];
    }

    /**
     * Update Manager - Queue Self Update.
     *
     * A queued state closes the detached-launch race so status polling begins
     * before the background CLI has loaded package classes.
     *
     * @param string|null $version - Expected version from the last check.
     * @param string $path - Status file path.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public static function queueSelfUpdate(
        ?string $version,
        string $path = PackagePaths::UPDATE_STATUS_FILE,
    ): void {
        $timestamp = gmdate(DATE_ATOM);

        self::writeJsonAtomically($path, [
            'state' => 'running',
            'message' => self::translate('update_starting'),
            'version' => $version,
            'started_at' => $timestamp,
            'updated_at' => $timestamp,
            'finished_at' => null,
        ]);
    }

    /**
     * Update Manager - Fail Queued Self Update.
     *
     * Environment and lock failures happen before selfUpdate() writes normal
     * progress, so the polling WebGUI receives a terminal failure state here.
     *
     * @param string $message - Complete localized failure.
     * @param string $path - Status file path.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public static function failQueuedSelfUpdate(
        string $message,
        string $path = PackagePaths::UPDATE_STATUS_FILE,
    ): void {
        $timestamp = gmdate(DATE_ATOM);
        $queuedState = null;

        try {
            $queuedState = self::readStatusState($path);
        } catch (Throwable) {
            // A fresh terminal state safely replaces malformed queued state.
        }

        self::writeJsonAtomically($path, [
            'state' => 'failed',
            'message' => $message,
            'version' => is_array($queuedState)
                ? ($queuedState['version'] ?? null)
                : null,
            'started_at' => is_array($queuedState)
                ? ($queuedState['started_at'] ?? $timestamp)
                : $timestamp,
            'updated_at' => $timestamp,
            'finished_at' => $timestamp,
        ]);
    }

    /**
     * Update Manager - Read Status State.
     *
     * The About page and its polling request share the same normalized read.
     * Missing state means no detached update has reported progress.
     *
     * @param string $path - Status file path.
     *
     * @return array|null
     *
     * @throws RuntimeException When saved status is malformed.
     *
     * @since 1.0.0
     */
    public static function readStatusState(
        string $path = PackagePaths::UPDATE_STATUS_FILE,
    ): ?array {
        if (is_readable($path) === false) {
            return null;
        }

        return self::readJsonObject(
            $path,
            self::translate('saved_self_update_status_unreadable'),
        );
    }

    /**
     * Update Manager - Read Updates State.
     *
     * Missing release state returns a complete null-filled shape. Stored values are
     * normalized before callers compare or render them.
     *
     * @param string $path - Updates file path.
     *
     * @return array
     *
     * @throws RuntimeException When saved release state is malformed.
     *
     * @since 1.0.0
     */
    public static function readUpdatesState(
        string $path = PackagePaths::UPDATES_FILE,
    ): array {
        $state = [
            'checked_at' => null,
            'latest_version' => null,
            'tag' => null,
            'release_url' => null,
            'published_at' => null,
            'notified_version' => null,
            'last_error' => null,
        ];

        if (is_readable($path) === false) {
            return $state;
        }

        $storedState = self::readJsonObject(
            $path,
            self::translate('saved_update_check_state_unreadable'),
        );

        foreach (array_keys($state) as $key) {
            $storedValue = $storedState[$key] ?? null;
            $state[$key] = is_string($storedValue) && $storedValue !== ''
                ? $storedValue
                : null;
        }

        return $state;
    }

    /**
     * Update Manager - Read Signing Keys.
     *
     * A missing or comment-only trust file permits unsigned releases. Any malformed
     * non-comment line fails closed before release assets are downloaded.
     *
     * @param string $path - Signing key file path.
     *
     * @return list<string>
     *
     * @throws RuntimeException When an existing key file is invalid.
     *
     * @since 1.0.0
     */
    public static function readSigningKeys(string $path): array
    {
        if (file_exists($path) === false) {
            return [];
        }

        if (is_readable($path) === false) {
            throw new RuntimeException(self::translate('signing_key_file_invalid'));
        }

        $contents = @file_get_contents($path);

        if (!is_string($contents)) {
            throw new RuntimeException(self::translate('signing_key_file_invalid'));
        }

        $keys = [];

        foreach (explode("\n", $contents) as $line) {
            $line = trim(str_replace("\r", '', $line));

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (
                preg_match(
                    '/^ssh-ed25519\s+(AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+\/]{43})(?:\s.*)?$/',
                    $line,
                    $matches,
                ) !== 1
            ) {
                throw new RuntimeException(self::translate('signing_key_file_invalid'));
            }

            $key = $matches[1];
            $decodedKey = base64_decode($key, true);

            if (!is_string($decodedKey) || strlen($decodedKey) !== 51) {
                throw new RuntimeException(self::translate('signing_key_file_invalid'));
            }

            $keys[] = $key;
        }

        return $keys;
    }

    /**
     * Update Manager - Allowed Signers Content.
     *
     * Each key is restricted to the package principal and signature namespace so a
     * signature created for another product or purpose cannot authorize an update.
     *
     * @param list<string> $keys - Trusted Ed25519 public key data.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function allowedSignersContent(array $keys): string
    {
        $content = '';

        foreach ($keys as $key) {
            $content .= self::PACKAGE_NAME
                . ' namespaces="'
                . self::PACKAGE_NAME
                . '" ssh-ed25519 '
                . $key
                . "\n";
        }

        return $content;
    }

    /**
     * Update Manager - Select Update Assets.
     *
     * The API digest wins over a checksum asset. Every selected URL must remain
     * under the exact configured release-download prefix.
     *
     * @param array $release - Parsed release.
     * @param string $downloadPrefix - Allowed asset URL prefix.
     *
     * @return array{package: array, digest: string|null, checksum: array|null, signature: array|null}
     *
     * @throws RuntimeException When required assets or URLs are invalid.
     *
     * @since 1.0.0
     */
    public static function selectUpdateAssets(
        array $release,
        string $downloadPrefix = self::DOWNLOAD_PREFIX,
    ): array {
        $version = (string) ($release['version'] ?? '');
        $packageAssetName = self::PACKAGE_NAME . '-' . $version . '.pkg';
        $checksumAssetName = $packageAssetName . '.sha256';
        $signatureAssetName = $packageAssetName . '.sig';
        $packageAsset = null;
        $checksumAsset = null;
        $signatureAsset = null;
        $releaseAssets = is_array($release['assets'] ?? null)
            ? $release['assets']
            : [];

        foreach ($releaseAssets as $asset) {
            if (!is_array($asset)) {
                continue;
            }

            $assetName = $asset['name'] ?? null;

            if ($assetName === $packageAssetName) {
                $packageAsset = $asset;
            } elseif ($assetName === $checksumAssetName) {
                $checksumAsset = $asset;
            } elseif ($assetName === $signatureAssetName) {
                $signatureAsset = $asset;
            }
        }

        if (!is_array($packageAsset)) {
            throw new RuntimeException(self::translate(
                'package_asset_missing',
                [$packageAssetName],
            ));
        }

        $packageAssetUrl = $packageAsset['url'] ?? null;

        if (
            !is_string($packageAssetUrl)
            || self::isAllowedAssetUrl($packageAssetUrl, $downloadPrefix) === false
        ) {
            throw new RuntimeException(self::translate('asset_url_untrusted'));
        }

        if (is_array($signatureAsset)) {
            $signatureAssetUrl = $signatureAsset['url'] ?? null;

            if (
                !is_string($signatureAssetUrl)
                || self::isAllowedAssetUrl($signatureAssetUrl, $downloadPrefix) === false
            ) {
                throw new RuntimeException(self::translate('asset_url_untrusted'));
            }
        }

        $packageDigest = $packageAsset['digest'] ?? null;

        if (
            is_string($packageDigest)
            && preg_match('/^sha256:[a-fA-F0-9]{64}$/', $packageDigest) === 1
        ) {
            return [
                'package' => $packageAsset,
                'digest' => $packageDigest,
                'checksum' => null,
                'signature' => $signatureAsset,
            ];
        }

        if (!is_array($checksumAsset)) {
            throw new RuntimeException(self::translate(
                'digest_or_checksum_missing',
                [$checksumAssetName],
            ));
        }

        $checksumAssetUrl = $checksumAsset['url'] ?? null;

        if (
            !is_string($checksumAssetUrl)
            || self::isAllowedAssetUrl($checksumAssetUrl, $downloadPrefix) === false
        ) {
            throw new RuntimeException(self::translate('asset_url_untrusted'));
        }

        return [
            'package' => $packageAsset,
            'digest' => null,
            'checksum' => $checksumAsset,
            'signature' => $signatureAsset,
        ];
    }

    /**
     * Update Manager - Assert Signature Requirements.
     *
     * A configured signing key makes the matching detached signature mandatory.
     * Comment-only trust files deliberately preserve unsigned installation.
     *
     * @param array $assets - Selected package release assets.
     * @param list<string> $keys - Trusted signing keys.
     *
     * @return void
     *
     * @throws RuntimeException When a keyed release omits its signature.
     *
     * @since 1.0.0
     */
    public static function assertSignatureRequirements(array $assets, array $keys): void
    {
        if (count($keys) === 0 || is_array($assets['signature'] ?? null)) {
            return;
        }

        $package = $assets['package'] ?? null;
        $packageName = is_array($package) ? ($package['name'] ?? '') : '';
        $signatureAssetName = (string) $packageName . '.sig';

        throw new RuntimeException(self::translate(
            'signature_asset_missing',
            [$signatureAssetName],
        ));
    }

    /**
     * Update Manager - Verify Release Signature.
     *
     * OpenSSH verifies the package bytes from standard input before pkg reads any
     * archive metadata or attempts installation.
     *
     * @param string $packagePath - Downloaded package path.
     * @param string $signaturePath - Detached signature path.
     * @param list<string> $keys - Trusted signing keys.
     * @param string $directory - Private allowed-signers directory.
     *
     * @return void
     *
     * @throws RuntimeException When verification cannot complete successfully.
     *
     * @since 1.0.0
     */
    public function verifyReleaseSignature(
        string $packagePath,
        string $signaturePath,
        array $keys,
        string $directory,
    ): void {
        if (
            is_file($this->sshKeygenCommand) === false
            || is_executable($this->sshKeygenCommand) === false
        ) {
            throw new RuntimeException(self::translate('ssh_keygen_unavailable'));
        }

        $allowedSignersPath = $directory . '/allowed_signers';
        $allowedSignersContent = self::allowedSignersContent($keys);
        $allowedSignersBytes = @file_put_contents(
            $allowedSignersPath,
            $allowedSignersContent,
            LOCK_EX,
        );

        if (
            $allowedSignersBytes !== strlen($allowedSignersContent)
            || @chmod($allowedSignersPath, 0600) === false
        ) {
            throw new RuntimeException(self::translate('package_command_start_failed'));
        }

        $verificationResult = $this->runCommand([
            $this->sshKeygenCommand,
            '-Y',
            'verify',
            '-f',
            $allowedSignersPath,
            '-I',
            self::PACKAGE_NAME,
            '-n',
            self::PACKAGE_NAME,
            '-s',
            $signaturePath,
        ], $packagePath);

        if ($verificationResult['exit_code'] !== 0) {
            throw new RuntimeException(self::translate('release_signature_invalid'));
        }
    }

    /**
     * Update Manager - Self Update.
     *
     * The caller owns the package FileLock. Installation begins only after URL,
     * size, digest, optional signature, and package metadata verification.
     *
     * @param bool $remoteNotifications - Whether later notices may reach remote channels.
     *
     * @return array
     *
     * @throws Throwable When any update step fails.
     *
     * @since 1.0.0
     */
    public function selfUpdate(bool $remoteNotifications): array
    {
        $temporaryDirectory = null;
        $startedAt = gmdate(DATE_ATOM);

        $this->writeStatus(
            'running',
            self::translate('checking_latest_release'),
            null,
            $startedAt,
            null,
        );

        try {
            $signingKeys = self::readSigningKeys($this->signingKeysFile);
            $release = $this->fetchLatestRelease();
            $version = $release['version'];

            if (self::isNewerVersion($this->installedVersion, $version) === false) {
                $state = $this->saveReleaseState(
                    $release,
                    $version,
                    $remoteNotifications,
                );

                $this->writeStatus(
                    'succeeded',
                    self::translate('version_already_installed', [$version]),
                    $version,
                    $startedAt,
                    gmdate(DATE_ATOM),
                );

                return $state;
            }

            $assets = self::selectUpdateAssets($release, $this->downloadPrefix);

            self::assertSignatureRequirements($assets, $signingKeys);

            $temporaryDirectory = $this->createTemporaryDirectory();
            $packagePath = $temporaryDirectory . '/' . $assets['package']['name'];

            $this->writeStatus(
                'running',
                self::translate('downloading_version_checksum', [$version]),
                $version,
                $startedAt,
                null,
            );

            $this->downloadFile(
                $assets['package']['url'],
                $packagePath,
                self::PACKAGE_DOWNLOAD_LIMIT,
            );

            $expectedDigest = $assets['digest'];

            if (is_array($assets['checksum'])) {
                $checksumPath = $temporaryDirectory . '/' . $assets['checksum']['name'];

                $this->downloadFile(
                    $assets['checksum']['url'],
                    $checksumPath,
                    self::AUXILIARY_DOWNLOAD_LIMIT,
                );

                $checksumContents = @file_get_contents($checksumPath);
                $expectedDigest = is_string($checksumContents)
                    ? self::checksumDigest($checksumContents)
                    : null;
            }

            $this->writeStatus(
                'running',
                self::translate('verifying_version', [$version]),
                $version,
                $startedAt,
                null,
            );

            if (
                !is_string($expectedDigest)
                || self::verifyDigest($packagePath, $expectedDigest) === false
            ) {
                throw new RuntimeException(self::translate('package_digest_mismatch'));
            }

            if (count($signingKeys) > 0 && is_array($assets['signature'])) {
                $signaturePath = $temporaryDirectory . '/' . $assets['signature']['name'];

                $this->downloadFile(
                    $assets['signature']['url'],
                    $signaturePath,
                    self::AUXILIARY_DOWNLOAD_LIMIT,
                );

                $this->verifyReleaseSignature(
                    $packagePath,
                    $signaturePath,
                    $signingKeys,
                    $temporaryDirectory,
                );
            }

            $this->verifyPackageMetadata($packagePath, $version);

            $this->writeStatus(
                'running',
                self::translate('installing_version', [$version]),
                $version,
                $startedAt,
                null,
            );

            $installResult = $this->runCommand([
                self::PKG_COMMAND,
                'add',
                '-f',
                $packagePath,
            ]);

            if ($installResult['exit_code'] !== 0) {
                throw new RuntimeException(self::translate(
                    'pkg_install_failed',
                    [$installResult['exit_code']],
                ));
            }

            $state = $this->saveReleaseState(
                $release,
                $version,
                $remoteNotifications,
            );

            $this->writeStatus(
                'succeeded',
                self::translate('version_installed', [$version]),
                $version,
                $startedAt,
                gmdate(DATE_ATOM),
            );

            return $state;
        } catch (Throwable $throwable) {
            $this->writeStatus(
                'failed',
                $throwable->getMessage(),
                isset($version) && is_string($version) ? $version : null,
                $startedAt,
                gmdate(DATE_ATOM),
            );
            $this->logFailure($throwable);

            throw $throwable;
        } finally {
            if (is_string($temporaryDirectory)) {
                $this->removeTemporaryDirectory($temporaryDirectory);
            }
        }
    }

    /**
     * Update Manager - Stable Cron Schedule.
     *
     * Existing valid values win without consulting the random source. Production
     * uses random_int() while tests can provide deterministic values.
     *
     * @param array $storedSchedule - Previously stored schedule.
     * @param callable|null $randomInteger - Optional integer generator.
     *
     * @return array{minute: int, hour: int, weekday: int, monthday: int}
     *
     * @since 1.0.0
     */
    public static function stableCronSchedule(
        array $storedSchedule,
        ?callable $randomInteger = null,
    ): array {
        $ranges = [
            'minute' => [0, 59],
            'hour' => [0, 23],
            'weekday' => [0, 6],
            'monthday' => [1, 28],
        ];
        $schedule = [];
        $randomInteger ??= static fn (int $minimum, int $maximum): int => random_int(
            $minimum,
            $maximum,
        );

        foreach ($ranges as $key => $range) {
            $storedValue = $storedSchedule[$key] ?? null;
            $minimum = $range[0];
            $maximum = $range[1];

            if (
                (
                    is_int($storedValue)
                    || (is_string($storedValue) && ctype_digit($storedValue))
                )
                && (int) $storedValue >= $minimum
                && (int) $storedValue <= $maximum
            ) {
                $schedule[$key] = (int) $storedValue;
                continue;
            }

            $schedule[$key] = $randomInteger($minimum, $maximum);
        }

        return $schedule;
    }

    /**
     * Update Manager - Synchronize Notice.
     *
     * Each remote version creates at most one bell notice. The explicit opt-in is
     * inverted for pfSense's local-only file_notice() argument.
     *
     * @param array $state - Update state.
     * @param string $installedVersion - Installed version.
     * @param string $latestVersion - Latest release version.
     * @param bool $remoteNotifications - Whether remote delivery is enabled.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public static function synchronizeNotice(
        array $state,
        string $installedVersion,
        string $latestVersion,
        bool $remoteNotifications,
    ): array {
        if (self::isNewerVersion($installedVersion, $latestVersion) === false) {
            if (function_exists('close_notice')) {
                \close_notice(self::NOTICE_ID);
            }

            return $state;
        }

        if (($state['notified_version'] ?? null) === $latestVersion) {
            return $state;
        }

        \file_notice(
            self::NOTICE_ID,
            self::translate('sinkhole_version_available', [$latestVersion]),
            'Sinkhole',
            self::ABOUT_PAGE,
            1,
            $remoteNotifications === false,
        );
        $state['notified_version'] = $latestVersion;

        return $state;
    }

    /**
     * Update Manager - Checksum Digest.
     *
     * The checksum asset contains one hexadecimal hash only. Filenames and other
     * checksum formats fail closed.
     *
     * @param string $checksum - Checksum file contents.
     *
     * @return string|null
     *
     * @since 1.0.0
     */
    public static function checksumDigest(string $checksum): ?string
    {
        $normalizedChecksum = trim($checksum);

        if (preg_match('/^[a-fA-F0-9]{64}$/', $normalizedChecksum) !== 1) {
            return null;
        }

        return 'sha256:' . strtolower($normalizedChecksum);
    }

    /**
     * Update Manager - Verify Digest.
     *
     * A constant-time comparison verifies the downloaded package against the
     * digest supplied by GitHub or its hash-only checksum asset.
     *
     * @param string $packagePath - Downloaded package path.
     * @param string $digest - Expected digest.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function verifyDigest(string $packagePath, string $digest): bool
    {
        if (preg_match('/^sha256:([a-fA-F0-9]{64})$/', $digest, $matches) !== 1) {
            return false;
        }

        $actualDigest = hash_file('sha256', $packagePath);

        return is_string($actualDigest)
            && hash_equals(
                strtolower($matches[1]),
                strtolower($actualDigest),
            );
    }

    /**
     * Update Manager - Clear Status.
     *
     * A standalone release check clears completed detached update progress so the
     * About bar presents the newly checked release state.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function clearStatus(): void
    {
        if (file_exists($this->statusFile)) {
            @unlink($this->statusFile);
        }
    }

    /**
     * Update Manager - Create Temporary Directory.
     *
     * Release artifacts and allowed signers remain inside one private random
     * directory that is removed after every success or failure.
     *
     * @return string
     *
     * @throws RuntimeException When the directory cannot be created.
     *
     * @since 1.0.0
     * @private
     */
    private function createTemporaryDirectory(): string
    {
        try {
            $suffix = bin2hex(random_bytes(16));
        } catch (Throwable $throwable) {
            throw new RuntimeException(
                self::translate('private_update_directory_failed'),
                0,
                $throwable,
            );
        }

        $temporaryDirectory = sys_get_temp_dir() . '/sinkhole-' . $suffix;

        if (mkdir($temporaryDirectory, 0700) === false) {
            throw new RuntimeException(self::translate('private_update_directory_failed'));
        }

        return $temporaryDirectory;
    }

    /**
     * Update Manager - Download File.
     *
     * pfSense proxy and TLS settings apply to a private destination with both cURL
     * and progress-callback size enforcement.
     *
     * @param string $url - Validated asset URL.
     * @param string $path - Private destination path.
     * @param int $byteLimit - Maximum accepted size.
     *
     * @return void
     *
     * @throws RuntimeException When transport or HTTP validation fails.
     *
     * @since 1.0.0
     * @private
     */
    private function downloadFile(string $url, string $path, int $byteLimit): void
    {
        $fileHandle = fopen($path, 'wb');

        if ($fileHandle === false || chmod($path, 0600) === false) {
            if (is_resource($fileHandle)) {
                fclose($fileHandle);
            }

            throw new RuntimeException(self::translate('release_asset_private_file_failed'));
        }

        $curlHandle = curl_init($url);

        if ($curlHandle === false) {
            fclose($fileHandle);

            throw new RuntimeException(self::translate('release_asset_private_file_failed'));
        }

        $downloadTooLarge = false;
        $progressCallback = static function (
            mixed $unusedHandle,
            float $downloadTotal,
            float $downloadedCount,
            float $uploadTotal,
            float $uploadedCount,
        ) use (&$downloadTooLarge, $byteLimit): int {
            if ($downloadedCount > $byteLimit) {
                $downloadTooLarge = true;

                return 1;
            }

            return 0;
        };

        $this->configureCurl($curlHandle, $url, [
            CURLOPT_FILE => $fileHandle,
            CURLOPT_HTTPHEADER => [
                'Accept: application/octet-stream',
            ],
            CURLOPT_MAXFILESIZE_LARGE => $byteLimit,
            CURLOPT_NOPROGRESS => false,
            CURLOPT_XFERINFOFUNCTION => $progressCallback,
        ]);

        $result = curl_exec($curlHandle);
        $statusCode = (int) curl_getinfo($curlHandle, CURLINFO_RESPONSE_CODE);
        $curlErrorCode = curl_errno($curlHandle);
        $curlError = curl_error($curlHandle);

        curl_close($curlHandle);
        fclose($fileHandle);

        if ($downloadTooLarge || $curlErrorCode === CURLE_FILESIZE_EXCEEDED) {
            @unlink($path);

            throw new RuntimeException(self::translate('release_asset_too_large'));
        }

        if ($result !== true || $statusCode < 200 || $statusCode >= 300) {
            @unlink($path);

            $detail = $curlError !== '' ? $curlError : (string) $statusCode;

            throw new RuntimeException(self::translate(
                'release_asset_download_failed',
                [$detail],
            ));
        }
    }

    /**
     * Update Manager - Fetch Latest Release.
     *
     * GitHub HTTP and rate-limit failures remain actionable without persisting any
     * unvalidated external response fields.
     *
     * @return array
     *
     * @throws RuntimeException When the request or response is invalid.
     *
     * @since 1.0.0
     * @private
     */
    private function fetchLatestRelease(): array
    {
        $responseHeaders = [];
        $curlHandle = curl_init($this->releasesApi);

        if ($curlHandle === false) {
            throw new RuntimeException(self::translate('update_request_initialize_failed'));
        }

        $headerCallback = static function (
            mixed $unusedHandle,
            string $headerLine,
        ) use (&$responseHeaders): int {
            $separatorPosition = strpos($headerLine, ':');

            if ($separatorPosition !== false) {
                $headerName = strtolower(trim(substr($headerLine, 0, $separatorPosition)));
                $headerValue = trim(substr($headerLine, $separatorPosition + 1));
                $responseHeaders[$headerName] = $headerValue;
            }

            return strlen($headerLine);
        };

        $this->configureCurl($curlHandle, $this->releasesApi, [
            CURLOPT_HEADERFUNCTION => $headerCallback,
            CURLOPT_HTTPHEADER => [
                'Accept: application/vnd.github+json',
                'X-GitHub-Api-Version: 2022-11-28',
            ],
            CURLOPT_RETURNTRANSFER => true,
        ]);

        $response = curl_exec($curlHandle);
        $statusCode = (int) curl_getinfo($curlHandle, CURLINFO_RESPONSE_CODE);
        $curlError = curl_error($curlHandle);

        curl_close($curlHandle);

        if ($response === false) {
            throw new RuntimeException(self::translate(
                'update_connection_failed',
                [$curlError],
            ));
        }

        if ($statusCode === 403 || $statusCode === 429) {
            throw new RuntimeException(
                self::translate('github_rate_limited'),
                $statusCode,
            );
        }

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new RuntimeException(self::translate(
                'github_http_status',
                [$statusCode],
            ), $statusCode);
        }

        if (!is_string($response)) {
            throw new RuntimeException(self::translate('release_metadata_invalid'));
        }

        return self::parseReleaseJson($response);
    }

    /**
     * Update Manager - Configure Curl.
     *
     * Every request uses bounded redirects, strict TLS, the pfSense proxy, and only
     * protocols allowed by its validated initial endpoint.
     *
     * @param mixed $curlHandle - cURL handle.
     * @param string $url - Initial URL.
     * @param array $options - Operation-specific options.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function configureCurl(mixed $curlHandle, string $url, array $options): void
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $allowedProtocols = $scheme === 'http'
            ? CURLPROTO_HTTP | CURLPROTO_HTTPS
            : CURLPROTO_HTTPS;
        $sharedOptions = [
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_PROTOCOLS => $allowedProtocols,
            CURLOPT_REDIR_PROTOCOLS => $allowedProtocols,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_USERAGENT => self::USER_AGENT,
        ];

        if (curl_setopt_array($curlHandle, $options + $sharedOptions) === false) {
            throw new RuntimeException(self::translate('update_request_initialize_failed'));
        }

        \set_curlproxy($curlHandle);
    }

    /**
     * Update Manager - Log Failure.
     *
     * Operator-visible failures reach pfSense's system log without recording release
     * payloads, signing keys, or package contents.
     *
     * @param Throwable $throwable - Failure to log.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function logFailure(Throwable $throwable): void
    {
        if (function_exists('log_error')) {
            \log_error('Sinkhole: ' . $throwable->getMessage());
        }
    }

    /**
     * Update Manager - Normalize Version.
     *
     * Removes one optional Git tag prefix before semantic version comparison.
     * Whitespace surrounding package metadata is ignored.
     *
     * @param string $version - Package version or release tag.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeVersion(string $version): string
    {
        return preg_replace('/^[vV]/', '', trim($version), 1) ?? trim($version);
    }

    /**
     * Update Manager - Read JSON Object.
     *
     * Update state must decode to an object-like associative array rather than a
     * list so malformed local state never changes update decisions.
     *
     * @param string $path - JSON path.
     * @param string $errorMessage - Localized malformed-file message.
     *
     * @return array
     *
     * @throws RuntimeException When the file is not a JSON object.
     *
     * @since 1.0.0
     * @private
     */
    private static function readJsonObject(string $path, string $errorMessage): array
    {
        $contents = @file_get_contents($path);

        if (!is_string($contents)) {
            throw new RuntimeException($errorMessage);
        }

        try {
            $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw new RuntimeException($errorMessage, 0, $jsonException);
        }

        if (!is_array($decoded) || array_is_list($decoded)) {
            throw new RuntimeException($errorMessage);
        }

        return $decoded;
    }

    /**
     * Update Manager - Remove Temporary Directory.
     *
     * Only fixed children of the exact random directory are unlinked before the
     * private update directory itself is removed.
     *
     * @param string $temporaryDirectory - Generated update directory.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function removeTemporaryDirectory(string $temporaryDirectory): void
    {
        $entries = @scandir($temporaryDirectory);

        foreach (is_array($entries) ? $entries : [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $entryPath = $temporaryDirectory . '/' . $entry;

            if (is_file($entryPath) || is_link($entryPath)) {
                @unlink($entryPath);
            }
        }

        @rmdir($temporaryDirectory);
    }

    /**
     * Update Manager - Run Command.
     *
     * Fixed executables receive separated arguments. Signature verification can
     * stream one reviewed package file through standard input.
     *
     * @param list<string> $command - Executable and arguments.
     * @param string|null $stdinPath - Optional standard-input file.
     *
     * @return array{exit_code: int, stdout: string, stderr: string}
     *
     * @throws RuntimeException When the process cannot start.
     *
     * @since 1.0.0
     * @private
     */
    private function runCommand(array $command, ?string $stdinPath = null): array
    {
        $descriptorSpecification = [
            0 => is_string($stdinPath)
                ? ['file', $stdinPath, 'r']
                : ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $pipes = [];
        $process = proc_open($command, $descriptorSpecification, $pipes);

        if (!is_resource($process)) {
            throw new RuntimeException(self::translate('package_command_start_failed'));
        }

        if ($stdinPath === null) {
            fclose($pipes[0]);
        }

        $standardOutput = stream_get_contents($pipes[1]);
        $standardError = stream_get_contents($pipes[2]);

        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        return [
            'exit_code' => $exitCode,
            'stdout' => is_string($standardOutput) ? $standardOutput : '',
            'stderr' => is_string($standardError) ? $standardError : '',
        ];
    }

    /**
     * Update Manager - Save Release State.
     *
     * A successful install or no-op refreshes release metadata and closes a notice
     * once the effective installed version is current.
     *
     * @param array $release - Parsed release.
     * @param string $effectiveVersion - Version treated as installed.
     * @param bool $remoteNotifications - Whether remote notices are enabled.
     *
     * @return array
     *
     * @since 1.0.0
     * @private
     */
    private function saveReleaseState(
        array $release,
        string $effectiveVersion,
        bool $remoteNotifications,
    ): array {
        $previousState = self::readUpdatesState($this->updatesFile);
        $state = [
            'checked_at' => gmdate(DATE_ATOM),
            'latest_version' => $release['version'],
            'tag' => $release['tag'],
            'release_url' => $release['release_url'],
            'published_at' => $release['published_at'],
            'notified_version' => $previousState['notified_version'],
            'last_error' => null,
        ];
        $state = self::synchronizeNotice(
            $state,
            $effectiveVersion,
            $release['version'],
            $remoteNotifications,
        );

        self::writeJsonAtomically($this->updatesFile, $state);

        return $state;
    }

    /**
     * Update Manager - Verify Package Metadata.
     *
     * pkg inspects the verified archive only after optional signature verification.
     * Both package name and version must match the selected release exactly.
     *
     * @param string $packagePath - Downloaded package path.
     * @param string $version - Expected version.
     *
     * @return void
     *
     * @throws RuntimeException When archive metadata does not match.
     *
     * @since 1.0.0
     * @private
     */
    private function verifyPackageMetadata(string $packagePath, string $version): void
    {
        $queryResult = $this->runCommand([
            self::PKG_COMMAND,
            'query',
            '-F',
            $packagePath,
            '%n %v',
        ]);
        $expectedMetadata = self::PACKAGE_NAME . ' ' . $version;
        $actualMetadata = trim($queryResult['stdout']);

        if (
            $queryResult['exit_code'] !== 0
            || $actualMetadata !== $expectedMetadata
        ) {
            throw new RuntimeException(self::translate('package_metadata_invalid'));
        }
    }

    /**
     * Update Manager - Write Status.
     *
     * The polling About tab consumes one complete atomic progress snapshot.
     * Finished timestamps distinguish terminal states from active work.
     *
     * @param string $state - Running, succeeded, or failed.
     * @param string $message - Localized status message.
     * @param string|null $version - Release version when known.
     * @param string $startedAt - Start timestamp.
     * @param string|null $finishedAt - Finish timestamp.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function writeStatus(
        string $state,
        string $message,
        ?string $version,
        string $startedAt,
        ?string $finishedAt,
    ): void {
        self::writeJsonAtomically($this->statusFile, [
            'state' => $state,
            'message' => $message,
            'version' => $version,
            'started_at' => $startedAt,
            'updated_at' => gmdate(DATE_ATOM),
            'finished_at' => $finishedAt,
        ]);
    }

    /**
     * Update Manager - Write JSON Atomically.
     *
     * Update state uses private permissions and a same-directory rename so readers
     * never observe a partial JSON document.
     *
     * @param string $path - Destination path.
     * @param array $data - JSON object.
     *
     * @return void
     *
     * @throws RuntimeException When state cannot be replaced atomically.
     *
     * @since 1.0.0
     * @private
     */
    private static function writeJsonAtomically(string $path, array $data): void
    {
        $directory = dirname($path);

        if (!is_dir($directory) && mkdir($directory, 0700, true) === false) {
            throw new RuntimeException(self::translate('update_state_save_failed'));
        }

        @chmod($directory, 0700);

        $temporaryPath = tempnam($directory, '.update-');

        if ($temporaryPath === false || chmod($temporaryPath, 0600) === false) {
            throw new RuntimeException(self::translate('update_state_save_failed'));
        }

        try {
            $encoded = json_encode(
                $data,
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $jsonException) {
            @unlink($temporaryPath);

            throw new RuntimeException(
                self::translate('update_state_save_failed'),
                0,
                $jsonException,
            );
        }

        if (file_put_contents($temporaryPath, $encoded . PHP_EOL, LOCK_EX) === false) {
            @unlink($temporaryPath);

            throw new RuntimeException(self::translate('update_state_save_failed'));
        }

        if (rename($temporaryPath, $path) === false) {
            @unlink($temporaryPath);

            throw new RuntimeException(self::translate('update_state_save_failed'));
        }

        @chmod($path, 0600);
    }

    /**
     * Update Manager - Translate.
     *
     * Every operator-visible update message comes from Sinkhole's English source
     * catalog and follows the configured pfSense locale fallback.
     *
     * @param string $key - Stable catalog key.
     * @param array<int, scalar|null> $arguments - Positional arguments.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function translate(string $key, array $arguments = []): string
    {
        return Translator::translate($key, $arguments);
    }
}
