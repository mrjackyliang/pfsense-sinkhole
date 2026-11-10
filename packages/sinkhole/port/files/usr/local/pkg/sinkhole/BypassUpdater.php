<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\BypassParser;
use RuntimeException;
use Throwable;

require_once(__DIR__ . '/BypassConfiguration.php');
require_once(__DIR__ . '/BypassListStore.php');
require_once(__DIR__ . '/BypassParser.php');
require_once(__DIR__ . '/Compiler.php');
require_once(__DIR__ . '/DownloadClient.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/PackagePaths.php');
require_once(__DIR__ . '/PfSenseAdapter.php');

/**
 * Bypass Updater.
 *
 * Fetches mixed Bypass Lists through the existing bounded download boundary, keeps
 * every last good copy, compiles domain changes, and atomically refreshes address
 * tables in the independent bypass anchor.
 *
 * @since 1.0.0
 */
final class BypassUpdater
{
    /** @var int @since 1.0.0 */
    public const MAXIMUM_DOWNLOAD_BYTES = 67_108_864;

    /** @since 1.0.0 */
    public function __construct(
        private readonly PfSenseAdapter $adapter,
        private readonly DownloadClient $downloadClient,
        private readonly BypassParser $parser,
        private readonly BypassListStore $store,
        private readonly PackagePaths $paths,
        private readonly Compiler $compiler,
    ) {
    }

    /**
     * Bypass Updater - Run.
     *
     * @param bool $apply - Whether this is a selective configuration apply.
     *
     * @return array{status: string, attempted: int, updated: int, failed: int, dns_active: bool, firewall_active: bool, changed: bool}
     *
     * @since 1.0.0
     */
    public function run(bool $apply = false): array
    {
        $configuration = $this->adapter->getBypassConfiguration();

        if ($configuration['invalid_values'] !== []) {
            throw new RuntimeException('Bypass protection settings contain values that need repair.');
        }

        if ($this->adapter->updateShouldStop()) {
            return $this->result('stopped', 0, 0, 0, $configuration, false);
        }

        $this->store->sweepTemporaryFiles();
        $attempted = 0;
        $updated = 0;
        $failed = 0;
        $changed = false;

        foreach ($configuration['lists'] as $identifier => $list) {
            if ($this->adapter->updateShouldStop()) {
                return $this->result(
                    'stopped',
                    $attempted,
                    $updated,
                    $failed,
                    $configuration,
                    $changed,
                );
            }

            if (
                $list['enabled'] === false
                || !BypassConfiguration::kindEnabled($configuration, $list['kind'])
            ) {
                continue;
            }

            if ($apply && $this->requiresDownload($identifier, $list) === false) {
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

                if (($download['success'] ?? false) !== true) {
                    throw new RuntimeException(
                        is_string($download['error'] ?? null)
                            ? $download['error']
                            : 'The Bypass List download failed.',
                    );
                }

                $downloadSize = filesize($downloadPath);
                $reportedBytes = $download['bytes'] ?? null;

                if (
                    !is_int($reportedBytes)
                    || $reportedBytes <= 0
                    || $reportedBytes > self::MAXIMUM_DOWNLOAD_BYTES
                    || !FileSystem::isRegularFile($downloadPath)
                    || !is_int($downloadSize)
                    || $downloadSize <= 0
                    || $downloadSize > self::MAXIMUM_DOWNLOAD_BYTES
                    || $downloadSize !== $reportedBytes
                ) {
                    throw new RuntimeException(
                        'The Bypass List download is empty or exceeds the 64 MiB size limit.',
                    );
                }

                $parsed = $this->parser->parseFile($downloadPath, $normalizedPath);

                if ($parsed['accepted'] === 0) {
                    throw new RuntimeException('The download contains no valid Bypass List entries.');
                }

                $sha256 = hash_file('sha256', $normalizedPath);

                if (!is_string($sha256)) {
                    throw new RuntimeException('Unable to hash the normalized Bypass List.');
                }

                $previous = $this->store->metadata($identifier);
                $changed = !$this->store->hasSavedCopy($identifier)
                    || ($previous['sha256'] ?? null) !== $sha256
                    || ($previous['kind'] ?? null) !== $list['kind']
                    || $changed;
                $this->store->commitSuccessfulDownload($identifier, $normalizedPath, [
                    'url' => $list['url'],
                    'kind' => $list['kind'],
                    'fetched_at' => gmdate('c'),
                    'entries' => $parsed['accepted'],
                    'domains' => $parsed['domains'],
                    'networks' => $parsed['networks'],
                    'ipv4' => $parsed['ipv4'],
                    'ipv6' => $parsed['ipv6'],
                    'skipped' => $parsed['skipped'],
                    'sha256' => $sha256,
                    'last_attempt' => $attemptedAt,
                    'last_attempt_url' => $list['url'],
                    'last_error' => null,
                ]);
                $updated++;
            } catch (Throwable $throwable) {
                $failed++;
                $safeError = substr(str_replace(["\r", "\n"], ' ', $throwable->getMessage()), 0, 500);

                try {
                    $this->store->recordFailure(
                        $identifier,
                        $list['url'],
                        $attemptedAt,
                        $safeError,
                    );
                } catch (Throwable) {
                    $this->adapter->log('Unable to record a Bypass List update failure.');
                }

                $this->adapter->log(
                    'Bypass List update failed for ID ' . $identifier . ': ' . $safeError,
                );
            } finally {
                foreach ([$downloadPath, $normalizedPath] as $temporaryPath) {
                    if (file_exists($temporaryPath) || is_link($temporaryPath)) {
                        unlink($temporaryPath);
                    }
                }
            }
        }

        if ($this->adapter->updateShouldStop()) {
            return $this->result(
                'stopped',
                $attempted,
                $updated,
                $failed,
                $configuration,
                $changed,
            );
        }

        $changed = $this->store->removeUnconfigured(array_keys($configuration['lists'])) || $changed;

        if ($changed) {
            $this->compiler->markNeeded();
        }

        $this->adapter->refreshBypassTables($configuration, $this->store);

        return $this->result(
            ($failed > 0) ? 'warning' : 'completed',
            $attempted,
            $updated,
            $failed,
            $configuration,
            $changed,
        );
    }

    /** @since 1.0.0 */
    private function requiresDownload(string $identifier, array $list): bool
    {
        if (!$this->store->hasSavedCopy($identifier)) {
            return true;
        }

        try {
            $metadata = $this->store->metadata($identifier);
        } catch (Throwable) {
            return true;
        }

        return ($metadata['url'] ?? null) !== $list['url']
            || ($metadata['kind'] ?? null) !== $list['kind'];
    }

    /** @since 1.0.0 */
    private function result(
        string $status,
        int $attempted,
        int $updated,
        int $failed,
        array $configuration,
        bool $changed,
    ): array {
        return [
            'status' => $status,
            'attempted' => $attempted,
            'updated' => $updated,
            'failed' => $failed,
            'dns_active' => ($configuration['dns_enabled'] ?? false) === true,
            'firewall_active' => ($configuration['firewall_enabled'] ?? false) === true,
            'changed' => $changed,
        ];
    }
}
