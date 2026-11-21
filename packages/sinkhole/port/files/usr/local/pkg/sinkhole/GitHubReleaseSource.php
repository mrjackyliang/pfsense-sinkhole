<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use JsonException;
use RuntimeException;

require_once(__DIR__ . '/CurlDownloadClient.php');
require_once(__DIR__ . '/DownloadClient.php');
require_once(__DIR__ . '/ReleaseSource.php');
require_once(__DIR__ . '/Translator.php');

/**
 * GitHub Release Source.
 *
 * The only class that knows Sinkhole's GitHub URLs and release JSON. Requests go
 * through the download client, and each response becomes the project-owned
 * release array that update checks consume.
 *
 * @since 1.3.3
 */
final class GitHubReleaseSource implements ReleaseSource
{
    /** @var string @since 1.3.3 */
    public const RELEASES_API = 'https://api.github.com/repos/mrjackyliang/pfsense-sinkhole/releases/latest';

    /** @var string @since 1.3.3 */
    public const DOWNLOAD_PREFIX = 'https://github.com/mrjackyliang/pfsense-sinkhole/releases/download/';

    /** @var string @since 1.3.3 @private */
    private const USER_AGENT = 'pfSense-pkg-Sinkhole';

    /**
     * GitHub Release Source - Constructor.
     *
     * Production uses the fixed endpoints. Only the CLI passes the documented test
     * overrides, and tests pass a fake download client.
     *
     * @param string $releasesApi - Latest-release API endpoint.
     * @param string $downloadPrefix - Allowed release asset URL prefix.
     * @param DownloadClient $downloadClient - HTTP transport.
     *
     * @since 1.3.3
     */
    public function __construct(
        private readonly string $releasesApi = self::RELEASES_API,
        private readonly string $downloadPrefix = self::DOWNLOAD_PREFIX,
        private readonly DownloadClient $downloadClient = new CurlDownloadClient(),
    ) {
    }

    /**
     * GitHub Release Source - Is Available.
     *
     * A generated package without a GitHub release endpoint cannot check updates.
     * Sinkhole always supplies both reviewed repository constants.
     *
     * @return bool
     *
     * @since 1.3.3
     */
    public static function isAvailable(): bool
    {
        return self::RELEASES_API !== '' && self::DOWNLOAD_PREFIX !== '';
    }

    /**
     * GitHub Release Source - Asset URL.
     *
     * GitHub serves every release file under its "v"-prefixed tag directory.
     *
     * @param string $downloadPrefix - Release download prefix.
     * @param string $version - Normalized release version.
     * @param string $fileName - Attached file name.
     *
     * @return string
     *
     * @since 1.3.3
     */
    public static function assetUrl(string $downloadPrefix, string $version, string $fileName): string
    {
        return $downloadPrefix
            . 'v'
            . $version
            . '/'
            . $fileName;
    }

    /**
     * GitHub Release Source - Repository Download Prefix.
     *
     * Returns the release download prefix of one "owner/name" repository, the
     * same location the restore-heal script downloads from.
     *
     * @param string $repository - Repository as "owner/name".
     *
     * @return string
     *
     * @since 1.3.3
     */
    public static function repositoryDownloadPrefix(string $repository): string
    {
        return 'https://github.com/' . $repository . '/releases/download/';
    }

    /**
     * GitHub Release Source - Is Allowed Release URL.
     *
     * Persistent release links must remain under this repository's HTTPS release
     * pages before the About tab renders them.
     *
     * @param string $url - Release page URL.
     *
     * @return bool
     *
     * @since 1.3.3
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
     * GitHub Release Source - Parse Release JSON.
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
     * @since 1.3.3
     */
    public static function parseReleaseJson(string $json): array
    {
        try {
            $releaseData = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw new RuntimeException(
                Translator::translate('release_metadata_invalid'),
                0,
                $jsonException,
            );
        }

        if (!is_array($releaseData)) {
            throw new RuntimeException(Translator::translate('release_metadata_invalid'));
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
            throw new RuntimeException(Translator::translate('release_metadata_invalid'));
        }

        $version = preg_replace('/^[vV]/', '', trim($tag), 1) ?? trim($tag);

        if (preg_match('/^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/', $version) !== 1) {
            throw new RuntimeException(Translator::translate('release_tag_invalid'));
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
     * GitHub Release Source - Asset URL Prefix.
     *
     * @return string
     *
     * @since 1.3.3
     */
    public function assetUrlPrefix(): string
    {
        return $this->downloadPrefix;
    }

    /**
     * GitHub Release Source - Release Asset URL.
     *
     * @param string $version - Normalized release version.
     * @param string $fileName - Attached file name.
     *
     * @return string
     *
     * @since 1.3.3
     */
    public function releaseAssetUrl(string $version, string $fileName): string
    {
        return self::assetUrl($this->downloadPrefix, $version, $fileName);
    }

    /**
     * GitHub Release Source - Fetch Latest Release.
     *
     * GitHub HTTP and rate-limit failures remain actionable without persisting any
     * unvalidated external response fields.
     *
     * @return array
     *
     * @throws RuntimeException When the request or response is invalid.
     *
     * @since 1.3.3
     */
    public function fetchLatestRelease(): array
    {
        $response = $this->downloadClient->request(
            $this->releasesApi,
            [
                'Accept: application/vnd.github+json',
                'X-GitHub-Api-Version: 2022-11-28',
            ],
            self::USER_AGENT,
        );

        if ($response['started'] === false) {
            throw new RuntimeException(Translator::translate('update_request_initialize_failed'));
        }

        if ($response['completed'] === false) {
            throw new RuntimeException(Translator::translate(
                'update_connection_failed',
                [$response['error']],
            ));
        }

        $statusCode = $response['status'];

        if ($statusCode === 403 || $statusCode === 429) {
            throw new RuntimeException(
                Translator::translate('github_rate_limited'),
                $statusCode,
            );
        }

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new RuntimeException(Translator::translate(
                'github_http_status',
                [$statusCode],
            ), $statusCode);
        }

        if (!is_string($response['body'])) {
            throw new RuntimeException(Translator::translate('release_metadata_invalid'));
        }

        return self::parseReleaseJson($response['body']);
    }

    /**
     * GitHub Release Source - Download Asset.
     *
     * The download client applies pfSense proxy and TLS settings to a private
     * destination with both cURL and progress-callback size enforcement.
     *
     * @param string $url - Validated asset URL.
     * @param string $path - Private destination path.
     * @param int $byteLimit - Maximum accepted size.
     *
     * @return void
     *
     * @throws RuntimeException When transport or HTTP validation fails.
     *
     * @since 1.3.3
     */
    public function downloadAsset(string $url, string $path, int $byteLimit): void
    {
        $response = $this->downloadClient->request(
            $url,
            [
                'Accept: application/octet-stream',
            ],
            self::USER_AGENT,
            $path,
            $byteLimit,
        );

        if ($response['started'] === false && $response['failure'] === 'configure') {
            throw new RuntimeException(Translator::translate('update_request_initialize_failed'));
        }

        if ($response['started'] === false) {
            throw new RuntimeException(Translator::translate('release_asset_private_file_failed'));
        }

        if ($response['too_large']) {
            @unlink($path);

            throw new RuntimeException(Translator::translate('release_asset_too_large'));
        }

        $statusCode = $response['status'];

        if ($response['completed'] === false || $statusCode < 200 || $statusCode >= 300) {
            @unlink($path);

            $detail = $response['error'] !== '' ? $response['error'] : (string) $statusCode;
            $exceptionCode = $response['completed'] ? $statusCode : 0;

            throw new RuntimeException(Translator::translate(
                'release_asset_download_failed',
                [$detail],
            ), $exceptionCode);
        }
    }
}
