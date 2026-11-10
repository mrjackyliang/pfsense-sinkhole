<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use PfSense\Sinkhole\Domain\IpNetwork;
use PfSense\Sinkhole\Domain\IpParser;
use PfSense\Sinkhole\Domain\IpRuleConfiguration;
use RuntimeException;
use Throwable;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/DownloadClient.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/GeoLite2.php');
require_once(__DIR__ . '/IpListStore.php');
require_once(__DIR__ . '/IpNetwork.php');
require_once(__DIR__ . '/IpParser.php');
require_once(__DIR__ . '/IpRuleConfiguration.php');
require_once(__DIR__ . '/IpStatusStore.php');
require_once(__DIR__ . '/PackagePaths.php');
require_once(__DIR__ . '/PfSenseAdapter.php');

/**
 * IP Updater.
 *
 * Downloads IP feeds and at-most-weekly GeoLite2 data, preserves last-good
 * inputs, atomically replaces per-family files, and refreshes the live pf anchor.
 *
 * @since 1.0.0
 */
final class IpUpdater
{
    /** @var string @since 1.0.0 */
    public const GEOLITE2_ARCHIVE_URL =
        'https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip';

    /** @var string @since 1.0.0 */
    public const GEOLITE2_CHECKSUM_URL =
        'https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip.sha256';

    /** @var int @since 1.0.0 */
    public const GEOLITE2_REFRESH_SECONDS = 604800;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_DOWNLOAD_BYTES = 67108864;

    /** @since 1.0.0 */
    public function __construct(
        private readonly PfSenseAdapter $adapter,
        private readonly DownloadClient $downloadClient,
        private readonly IpParser $parser,
        private readonly IpListStore $store,
        private readonly PackagePaths $paths,
        private readonly GeoLite2 $geoLite2,
        private readonly IpStatusStore $statusStore,
    ) {
    }

    /**
     * IP Updater - Run.
     *
     * @param bool $apply - Whether this is a configuration apply handoff.
     *
     * @return array{status: string, attempted: int, updated: int, failed: int, ipv4: int, ipv6: int, skipped: int}
     *
     * @since 1.0.0
     */
    public function run(bool $apply = false): array
    {
        $configuration = [];

        try {
            $configuration = $this->adapter->getIpConfiguration();

            return $this->runConfigured($configuration, $apply);
        } catch (Throwable $throwable) {
            $licenseKey = is_string($configuration['license_key'] ?? null)
                ? $configuration['license_key']
                : '';
            $safeError = $this->safeError($throwable->getMessage(), $licenseKey);
            $this->adapter->log('IP blocking update failed: ' . $safeError);

            try {
                $previous = $this->statusStore->read();
                $this->statusStore->write(array_replace($previous, [
                    'state' => 'failed',
                    'last_attempt' => gmdate('c'),
                    'last_error' => $safeError,
                ]));
            } catch (Throwable) {
                $this->adapter->log('Unable to record the IP blocking update failure.');
            }

            throw new RuntimeException($safeError, 0, $throwable);
        }
    }

    /**
     * IP Updater - Run Configured.
     *
     * @param array $configuration - Validated IP settings partition.
     * @param bool $apply - Whether this is a configuration apply handoff.
     *
     * @return array{status: string, attempted: int, updated: int, failed: int, ipv4: int, ipv6: int, skipped: int}
     *
     * @since 1.0.0
     * @private
     */
    private function runConfigured(array $configuration, bool $apply): array
    {
        if ($this->adapter->updateShouldStop()) {
            return $this->stoppedResult();
        }

        if ($configuration['enabled'] === false) {
            $this->adapter->applyIpAnchor();
            $this->statusStore->write(['state' => 'disabled']);

            return [
                'status' => 'disabled',
                'attempted' => 0,
                'updated' => 0,
                'failed' => 0,
                'ipv4' => 0,
                'ipv6' => 0,
                'skipped' => 0,
            ];
        }

        if ($configuration['invalid_values'] !== []) {
            throw new RuntimeException('IP blocking settings contain values that need repair.');
        }

        $attempted = 0;
        $updated = 0;
        $failed = 0;
        $skipped = 0;
        $errors = [];
        $this->store->sweepTemporaryFiles();

        foreach ($configuration['lists'] as $identifier => $list) {
            if ($this->adapter->updateShouldStop()) {
                return $this->stoppedResult($attempted, $updated, $failed, $skipped);
            }

            if ($list['enabled'] === false) {
                continue;
            }

            if (
                $apply
                && $this->requiresDownload($identifier, $list['url'], $list['family']) === false
            ) {
                continue;
            }

            $attempted++;
            $attemptedAt = gmdate('c');
            $downloadPath = $this->store->createTemporaryFile('.download-');
            $normalizedPath = $this->store->createTemporaryFile('.normalized-');

            try {
                $download = $this->downloadClient->download(
                    $list['url'],
                    $downloadPath,
                    self::MAXIMUM_DOWNLOAD_BYTES,
                );

                if ($download['success'] === false) {
                    throw new RuntimeException($download['error'] ?? 'The IP list download failed.');
                }

                $downloadSize = filesize($downloadPath);

                if (
                    !is_int($download['bytes'] ?? null)
                    || $download['bytes'] <= 0
                    || $download['bytes'] > self::MAXIMUM_DOWNLOAD_BYTES
                    || !FileSystem::isRegularFile($downloadPath)
                    || !is_int($downloadSize)
                    || $downloadSize <= 0
                    || $downloadSize > self::MAXIMUM_DOWNLOAD_BYTES
                    || $downloadSize !== $download['bytes']
                ) {
                    throw new RuntimeException(
                        'The IP list download is empty or exceeds the 64 MiB size limit.',
                    );
                }

                $family = ($list['family'] === 'both') ? null : $list['family'];
                $parsed = $this->parser->parseFile($downloadPath, $normalizedPath, $family);

                if ($parsed['accepted'] === 0) {
                    throw new RuntimeException('The download contains no valid IP networks.');
                }

                $sha256 = hash_file('sha256', $normalizedPath);

                if (!is_string($sha256)) {
                    throw new RuntimeException('Unable to hash the normalized IP list.');
                }

                $this->store->commitSuccessfulDownload($identifier, $normalizedPath, [
                    'url' => $list['url'],
                    'family' => $list['family'],
                    'fetched_at' => gmdate('c'),
                    'entries' => $parsed['accepted'],
                    'skipped' => $parsed['skipped'],
                    'sha256' => $sha256,
                    'last_attempt' => $attemptedAt,
                    'last_error' => null,
                ]);
                $updated++;
            } catch (Throwable $throwable) {
                $failed++;
                $safeError = $this->safeError($throwable->getMessage(), $configuration['license_key']);
                $errors[] = $safeError;

                try {
                    $this->store->recordFailure(
                        $identifier,
                        $list['url'],
                        $attemptedAt,
                        $safeError,
                    );
                } catch (Throwable $metadataThrowable) {
                    $this->adapter->log('Unable to record an IP list update failure.');
                }

                $this->adapter->log('IP list update failed for ID ' . $identifier . ': ' . $safeError);
            } finally {
                foreach ([$downloadPath, $normalizedPath] as $temporaryPath) {
                    if (file_exists($temporaryPath) || is_link($temporaryPath)) {
                        unlink($temporaryPath);
                    }
                }
            }
        }

        if ($this->adapter->updateShouldStop()) {
            return $this->stoppedResult($attempted, $updated, $failed, $skipped);
        }

        $this->store->removeUnconfigured(array_keys($configuration['lists']));
        $networks = [];

        foreach ($configuration['lists'] as $identifier => $list) {
            if ($list['enabled']) {
                $savedNetworks = $this->store->readNetworks($identifier);
                $savedFamily = null;
                $savedMetadata = [];

                try {
                    $savedMetadata = $this->store->metadata($identifier);
                    $savedFamily = $savedMetadata['family'] ?? null;
                } catch (Throwable) {
                    $savedFamily = null;
                }

                if (
                    is_int($savedMetadata['skipped'] ?? null)
                    && $savedMetadata['skipped'] >= 0
                ) {
                    $skipped += $savedMetadata['skipped'];
                }

                if ($list['family'] !== 'both' && $savedFamily !== $list['family']) {
                    $savedNetworks = array_values(array_filter(
                        $savedNetworks,
                        static fn(string $network): bool => IpNetwork::family($network)
                            === $list['family'],
                    ));
                }

                $networks = array_merge($networks, $savedNetworks);

                if (count($networks) > IpNetwork::MAXIMUM_NETWORKS) {
                    throw new RuntimeException('The merged IP network count limit was exceeded.');
                }
            }
        }

        if ($this->adapter->updateShouldStop()) {
            return $this->stoppedResult($attempted, $updated, $failed, $skipped);
        }

        if ($configuration['countries'] !== []) {
            try {
                $geoResult = $this->countryNetworks($configuration);
                $networks = array_merge($networks, $geoResult['ipv4'], $geoResult['ipv6']);

                if (count($networks) > IpNetwork::MAXIMUM_NETWORKS) {
                    throw new RuntimeException('The merged IP network count limit was exceeded.');
                }
                $skipped += $geoResult['skipped'];
            } catch (Throwable $throwable) {
                $failed++;
                $safeError = $this->safeError($throwable->getMessage(), $configuration['license_key']);
                $errors[] = $safeError;
                $this->adapter->log('GeoLite2 update failed: ' . $safeError);

                if (FileSystem::isRegularFile($this->paths->geoLite2ArchiveFile)) {
                    try {
                        $geoResult = $this->geoLite2->importArchive(
                            $this->paths->geoLite2ArchiveFile,
                            $configuration['countries'],
                        );
                        $networks = array_merge(
                            $networks,
                            $geoResult['ipv4'],
                            $geoResult['ipv6'],
                        );

                        if (count($networks) > IpNetwork::MAXIMUM_NETWORKS) {
                            throw new RuntimeException('The merged IP network count limit was exceeded.');
                        }
                        $skipped += $geoResult['skipped'];
                    } catch (Throwable) {
                        $this->adapter->log('The last-good GeoLite2 archive could not be imported.');
                    }
                }
            }
        }

        if ($this->adapter->updateShouldStop()) {
            return $this->stoppedResult($attempted, $updated, $failed, $skipped);
        }

        $blocked = IpNetwork::merge($networks);
        $allowed = $this->adapter->ipAllowlistNetworks($configuration['allowlist']);
        $allowed = array_merge(
            $allowed,
            $this->adapter->ipProtectedAddresses($configuration['interfaces']),
        );
        $blocked = IpNetwork::subtract($blocked, $allowed);
        $ipv4 = array_values(array_filter(
            $blocked,
            static fn(string $network): bool => IpNetwork::family($network) === 'ipv4',
        ));
        $ipv6 = array_values(array_filter(
            $blocked,
            static fn(string $network): bool => IpNetwork::family($network) === 'ipv6',
        ));

        if ($this->adapter->updateShouldStop()) {
            return $this->stoppedResult($attempted, $updated, $failed, $skipped);
        }

        AtomicFile::write(
            $this->paths->ipTableIpv4File,
            ($ipv4 === []) ? '' : implode(PHP_EOL, $ipv4) . PHP_EOL,
            0600,
        );
        AtomicFile::write(
            $this->paths->ipTableIpv6File,
            ($ipv6 === []) ? '' : implode(PHP_EOL, $ipv6) . PHP_EOL,
            0600,
        );
        $this->adapter->applyIpAnchor();
        $this->adapter->replaceIpTable(
            IpRuleConfiguration::TABLE_IPV4,
            $this->paths->ipTableIpv4File,
        );
        $this->adapter->replaceIpTable(
            IpRuleConfiguration::TABLE_IPV6,
            $this->paths->ipTableIpv6File,
        );

        $now = gmdate('c');
        $previous = $this->statusStore->read();
        $status = ($failed > 0) ? 'warning' : 'completed';
        $this->statusStore->write([
            'state' => $status,
            'last_attempt' => $now,
            'last_success' => ($failed === 0) ? $now : ($previous['last_success'] ?? null),
            'ipv4_entries' => count($ipv4),
            'ipv6_entries' => count($ipv6),
            'skipped_lines' => $skipped,
            'lists_attempted' => $attempted,
            'lists_failed' => $failed,
            'geolite_updated_at' => $this->geoMetadata()['fetched_at'] ?? null,
            'geolite_extractor' => $this->geoMetadata()['extractor'] ?? null,
            'last_error' => ($errors === []) ? null : implode(' ', $errors),
        ]);

        return [
            'status' => $status,
            'attempted' => $attempted,
            'updated' => $updated,
            'failed' => $failed,
            'ipv4' => count($ipv4),
            'ipv6' => count($ipv6),
            'skipped' => $skipped,
        ];
    }

    /** @since 1.0.0 */
    private function stoppedResult(
        int $attempted = 0,
        int $updated = 0,
        int $failed = 0,
        int $skipped = 0,
    ): array {
        return [
            'status' => 'stopped',
            'attempted' => $attempted,
            'updated' => $updated,
            'failed' => $failed,
            'ipv4' => 0,
            'ipv6' => 0,
            'skipped' => $skipped,
        ];
    }

    /** @since 1.0.0 */
    private function requiresDownload(string $identifier, string $url, string $family): bool
    {
        if ($this->store->hasSavedCopy($identifier) === false) {
            return true;
        }

        try {
            $metadata = $this->store->metadata($identifier);
        } catch (Throwable) {
            $this->adapter->log(
                'Saved IP-list metadata requires refresh for ID ' . $identifier . '.',
            );

            return true;
        }

        return ($metadata['url'] ?? null) !== $url
            || ($metadata['family'] ?? null) !== $family;
    }

    /** @since 1.0.0 */
    private function countryNetworks(array $configuration): array
    {
        $metadata = $this->geoMetadata();
        $fetchedAt = is_int($metadata['fetched_at'] ?? null) ? $metadata['fetched_at'] : 0;
        $needsUpdate = !FileSystem::isRegularFile($this->paths->geoLite2ArchiveFile)
            || time() - $fetchedAt >= self::GEOLITE2_REFRESH_SECONDS;

        if ($needsUpdate) {
            $directory = dirname($this->paths->geoLite2ArchiveFile);
            FileSystem::ensureDirectory($directory, 0700);
            $archivePath = FileSystem::createTemporaryFile($directory, '.geolite2-', 0600);
            $checksumPath = FileSystem::createTemporaryFile($directory, '.geolite2-sha-', 0600);

            try {
                foreach ([
                    [self::GEOLITE2_ARCHIVE_URL, $archivePath, GeoLite2::MAXIMUM_ARCHIVE_BYTES],
                    [self::GEOLITE2_CHECKSUM_URL, $checksumPath, 4096],
                ] as [$url, $path, $limit]) {
                    $download = $this->downloadClient->download(
                        $url,
                        $path,
                        $limit,
                        $configuration['account_id'],
                        $configuration['license_key'],
                    );

                    if ($download['success'] === false) {
                        throw new RuntimeException($download['error'] ?? 'The GeoLite2 download failed.');
                    }

                    $actualBytes = filesize($path);

                    if (
                        !is_int($download['bytes'] ?? null)
                        || $download['bytes'] <= 0
                        || $download['bytes'] > $limit
                        || !FileSystem::isRegularFile($path)
                        || !is_int($actualBytes)
                        || $actualBytes <= 0
                        || $actualBytes > $limit
                        || $actualBytes !== $download['bytes']
                    ) {
                        throw new RuntimeException(
                            'A GeoLite2 download is empty or exceeds its size limit.',
                        );
                    }
                }

                $checksum = file_get_contents($checksumPath);

                if (!is_string($checksum)) {
                    throw new RuntimeException('Unable to read the GeoLite2 checksum.');
                }

                $sha256 = GeoLite2::verifyArchive($archivePath, $checksum);
                $result = $this->geoLite2->importArchive($archivePath, $configuration['countries']);

                if (rename($archivePath, $this->paths->geoLite2ArchiveFile) === false) {
                    throw new RuntimeException('Unable to replace the verified GeoLite2 archive.');
                }

                $metadata = [
                    'fetched_at' => time(),
                    'sha256' => $sha256,
                    'extractor' => $result['extractor'],
                ];
                $this->writeGeoMetadata($metadata);

                return $result;
            } finally {
                foreach ([$archivePath, $checksumPath] as $temporaryPath) {
                    if (file_exists($temporaryPath) || is_link($temporaryPath)) {
                        unlink($temporaryPath);
                    }
                }
            }
        }

        return $this->geoLite2->importArchive(
            $this->paths->geoLite2ArchiveFile,
            $configuration['countries'],
        );
    }

    /** @since 1.0.0 */
    private function geoMetadata(): array
    {
        if (!FileSystem::isRegularFile($this->paths->geoLite2MetadataFile)) {
            return [];
        }

        $contents = file_get_contents($this->paths->geoLite2MetadataFile);
        $metadata = is_string($contents) ? json_decode($contents, true, 8) : null;

        return is_array($metadata) ? $metadata : [];
    }

    /** @since 1.0.0 */
    private function writeGeoMetadata(array $metadata): void
    {
        $contents = json_encode($metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (!is_string($contents)) {
            throw new RuntimeException('Unable to encode GeoLite2 metadata.');
        }

        AtomicFile::write($this->paths->geoLite2MetadataFile, $contents . PHP_EOL, 0600);
    }

    /** @since 1.0.0 */
    private function safeError(string $message, string $licenseKey): string
    {
        if ($licenseKey !== '') {
            $message = str_replace($licenseKey, '[redacted]', $message);
            $message = str_replace(rawurlencode($licenseKey), '[redacted]', $message);
        }

        return substr(str_replace(["\r", "\n"], ' ', $message), 0, 500);
    }
}
