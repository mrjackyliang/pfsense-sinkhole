<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use JsonException;
use RuntimeException;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/PackagePaths.php');

/**
 * IP List Store.
 *
 * Keeps normalized last-good IP list copies separate from DNS list data.
 *
 * @since 1.0.0
 */
final class IpListStore
{
    /** @since 1.0.0 */
    public function __construct(private readonly PackagePaths $paths)
    {
    }

    /**
     * IP List Store - Create Temporary File.
     *
     * @param string $prefix - Fixed filename prefix.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function createTemporaryFile(string $prefix): string
    {
        FileSystem::ensureDirectory($this->paths->persistentDirectory, 0700);
        FileSystem::ensureDirectory($this->paths->ipListDirectory, 0700);

        return FileSystem::createTemporaryFile($this->paths->ipListDirectory, $prefix, 0600);
    }

    /** @since 1.0.0 */
    public function hasSavedCopy(string $identifier): bool
    {
        return FileSystem::isRegularFile($this->paths->ipListFile($identifier));
    }

    /**
     * IP List Store - Read Networks.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return list<string>
     *
     * @since 1.0.0
     */
    public function readNetworks(string $identifier): array
    {
        $path = $this->paths->ipListFile($identifier);

        if (!FileSystem::isRegularFile($path)) {
            return [];
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if (!is_array($lines)) {
            throw new RuntimeException('Unable to read the saved IP list.');
        }

        return array_values(array_filter($lines, 'is_string'));
    }

    /**
     * IP List Store - Metadata.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function metadata(string $identifier): array
    {
        $path = $this->paths->ipMetadataFile($identifier);

        if (!FileSystem::isRegularFile($path)) {
            return [];
        }

        $contents = file_get_contents($path);

        try {
            $metadata = is_string($contents)
                ? json_decode($contents, true, 16, JSON_THROW_ON_ERROR)
                : null;
        } catch (JsonException $exception) {
            throw new RuntimeException('IP list metadata is invalid.', 0, $exception);
        }

        if (!is_array($metadata)) {
            throw new RuntimeException('IP list metadata is invalid.');
        }

        return $metadata;
    }

    /**
     * IP List Store - Commit Successful Download.
     *
     * @param string $identifier - Stable list identifier.
     * @param string $normalizedPath - Complete normalized temporary file.
     * @param array $metadata - Secret-free metadata.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function commitSuccessfulDownload(
        string $identifier,
        string $normalizedPath,
        array $metadata,
    ): void {
        $size = filesize($normalizedPath);

        if (!FileSystem::isRegularFile($normalizedPath) || !is_int($size) || $size <= 0) {
            throw new RuntimeException('The normalized IP list is empty.');
        }

        if (rename($normalizedPath, $this->paths->ipListFile($identifier)) === false) {
            throw new RuntimeException('Unable to replace the saved IP list.');
        }

        $this->writeMetadata($identifier, $metadata);
    }

    /** @since 1.0.0 */
    public function recordFailure(
        string $identifier,
        string $url,
        string $attemptedAt,
        string $error,
    ): void {
        $metadata = array_replace([
            'url' => $url,
            'fetched_at' => null,
            'entries' => 0,
            'skipped' => 0,
            'sha256' => null,
            'last_attempt' => $attemptedAt,
            'last_error' => null,
        ], $this->metadata($identifier));
        $metadata['last_attempt_url'] = $url;
        $metadata['last_attempt'] = $attemptedAt;
        $metadata['last_error'] = substr(str_replace(["\r", "\n"], ' ', $error), 0, 500);
        $this->writeMetadata($identifier, $metadata);
    }

    /**
     * IP List Store - Remove Unconfigured.
     *
     * @param list<string> $configuredIdentifiers - Current stable identifiers.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function removeUnconfigured(array $configuredIdentifiers): void
    {
        if (!is_dir($this->paths->ipListDirectory) || is_link($this->paths->ipListDirectory)) {
            return;
        }

        $configured = array_fill_keys($configuredIdentifiers, true);
        $entries = scandir($this->paths->ipListDirectory);

        if (!is_array($entries)) {
            throw new RuntimeException('Unable to inspect saved IP lists.');
        }

        foreach ($entries as $entry) {
            if (preg_match('/^([a-f0-9]{32})\.(?:networks|json)$/D', $entry, $matches) !== 1) {
                continue;
            }

            if (isset($configured[$matches[1]])) {
                continue;
            }

            foreach ([
                $this->paths->ipListFile($matches[1]),
                $this->paths->ipMetadataFile($matches[1]),
            ] as $path) {
                FileSystem::removeFixedFile($path);
            }
        }
    }

    /** @since 1.0.0 */
    public function sweepTemporaryFiles(): void
    {
        FileSystem::sweepStaleEntries(
            $this->paths->ipListDirectory,
            ['.download-', '.normalized-', '.sinkhole-atomic-'],
        );
    }

    /** @since 1.0.0 */
    private function writeMetadata(string $identifier, array $metadata): void
    {
        $allowed = array_intersect_key($metadata, array_fill_keys([
            'url',
            'family',
            'fetched_at',
            'entries',
            'skipped',
            'sha256',
            'last_attempt',
            'last_attempt_url',
            'last_error',
        ], true));
        $contents = json_encode($allowed, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (!is_string($contents)) {
            throw new RuntimeException('Unable to encode IP list metadata.');
        }

        AtomicFile::write($this->paths->ipMetadataFile($identifier), $contents . PHP_EOL, 0600);
    }
}
