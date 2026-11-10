<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use JsonException;
use RuntimeException;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/PackagePaths.php');

/**
 * Saved List Store.
 *
 * Owns normalized list and metadata files while preserving the last successful copy
 * across failed, empty, and oversized downloads.
 *
 * @since 1.0.0
 */
final class SavedListStore
{
    /**
     * Saved List Store - Constructor.
     *
     * A path object keeps all file resolution inside the package-owned directory.
     *
     * @param PackagePaths $paths - Package paths.
     *
     * @since 1.0.0
     */
    public function __construct(private readonly PackagePaths $paths)
    {
    }

    /**
     * Saved List Store - Create Temporary File.
     *
     * Temporary downloads and normalized output stay on the same filesystem as the
     * saved copy so the final rename is atomic.
     *
     * @param string $prefix - Fixed caller prefix.
     *
     * @return string
     *
     * @throws RuntimeException When a temporary file cannot be created.
     *
     * @since 1.0.0
     */
    public function createTemporaryFile(string $prefix): string
    {
        FileSystem::ensureDirectory($this->paths->persistentDirectory, 0700);
        FileSystem::ensureDirectory($this->paths->listDirectory, 0700);

        return FileSystem::createTemporaryFile($this->paths->listDirectory, $prefix, 0600);
    }

    /**
     * Saved List Store - Has Saved Copy.
     *
     * The compiler includes only enabled lists with a readable last-good normalized
     * file.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function hasSavedCopy(string $identifier): bool
    {
        return is_readable($this->paths->listFile($identifier));
    }

    /**
     * Saved List Store - Saved Copy Path.
     *
     * Returns the validated package-owned normalized filename for streaming reads.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function savedCopyPath(string $identifier): string
    {
        return $this->paths->listFile($identifier);
    }

    /**
     * Saved List Store - Metadata.
     *
     * Missing metadata becomes an empty record; malformed metadata is reported rather
     * than silently replacing it.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return array
     *
     * @throws RuntimeException When stored metadata is unreadable or invalid.
     *
     * @since 1.0.0
     */
    public function metadata(string $identifier): array
    {
        $path = $this->paths->metadataFile($identifier);

        if (file_exists($path) === false) {
            return [];
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            throw new RuntimeException('Unable to read block list metadata.');
        }

        try {
            $metadata = json_decode($contents, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('Block list metadata is invalid.', 0, $exception);
        }

        if (!is_array($metadata)) {
            throw new RuntimeException('Block list metadata is invalid.');
        }

        return $metadata;
    }

    /**
     * Saved List Store - Commit Successful Download.
     *
     * Renames a complete non-empty normalized file over the prior copy, then records
     * metadata through its own atomic replacement.
     *
     * @param string $identifier     - Stable list identifier.
     * @param string $normalizedPath - Complete normalized temporary file.
     * @param array  $metadata       - Successful-download metadata.
     *
     * @return void
     *
     * @throws RuntimeException When the copy or metadata cannot be committed.
     *
     * @since 1.0.0
     */
    public function commitSuccessfulDownload(
        string $identifier,
        string $normalizedPath,
        array $metadata,
    ): void {
        $destination = $this->paths->listFile($identifier);
        $normalizedSize = filesize($normalizedPath);

        if (
            FileSystem::isRegularFile($normalizedPath) === false
            || !is_int($normalizedSize)
            || $normalizedSize <= 0
        ) {
            throw new RuntimeException('The normalized block list is empty.');
        }

        if (rename($normalizedPath, $destination) === false) {
            throw new RuntimeException('Unable to replace the saved block list.');
        }

        $this->writeMetadata($identifier, $metadata);
    }

    /**
     * Saved List Store - Record Failure.
     *
     * Updates attempt and error fields while retaining fetched time, count, and hash
     * from the previous successful copy.
     *
     * @param string $identifier  - Stable list identifier.
     * @param string $url         - Validated source URL.
     * @param string $attemptedAt - UTC attempt time.
     * @param string $error       - Safe error summary.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function recordFailure(
        string $identifier,
        string $url,
        string $attemptedAt,
        string $error,
    ): void {
        $metadata = array_replace(
            [
                'url' => $url,
                'fetched_at' => null,
                'entries' => 0,
                'sha256' => null,
                'last_attempt' => $attemptedAt,
                'last_error' => null,
            ],
            $this->metadata($identifier),
        );
        $metadata['url'] = $url;
        $metadata['last_attempt'] = $attemptedAt;
        $metadata['last_error'] = substr(str_replace(["\r", "\n"], ' ', $error), 0, 500);

        $this->writeMetadata($identifier, $metadata);
    }

    /**
     * Saved List Store - Remove.
     *
     * Deleting a configured row also removes its no-longer-referenced normalized copy
     * and metadata.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return void
     *
     * @throws RuntimeException When a package-owned file cannot be removed.
     *
     * @since 1.0.0
     */
    public function remove(string $identifier): void
    {
        $paths = [
            $this->paths->listFile($identifier),
            $this->paths->metadataFile($identifier),
        ];

        foreach ($paths as $path) {
            if ((file_exists($path) || is_link($path)) && unlink($path) === false) {
                throw new RuntimeException('Unable to remove saved block list data.');
            }
        }
    }

    /**
     * Saved List Store - Remove Unconfigured.
     *
     * Apply jobs discard normalized copies and metadata whose stable identifiers no
     * longer appear in the saved configuration.
     *
     * @param list<string> $configuredIdentifiers - Configured identifiers.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function removeUnconfigured(array $configuredIdentifiers): void
    {
        if (is_dir($this->paths->listDirectory) === false || is_link($this->paths->listDirectory)) {
            return;
        }

        $configured = array_fill_keys($configuredIdentifiers, true);
        $entries = scandir($this->paths->listDirectory);

        if ($entries === false) {
            throw new RuntimeException('Unable to inspect saved block lists.');
        }

        foreach ($entries as $entry) {
            if (preg_match('/^([a-f0-9]{32})\.(?:domains|json)$/D', $entry, $matches) !== 1) {
                continue;
            }

            if (isset($configured[$matches[1]]) === false) {
                $this->remove($matches[1]);
            }
        }
    }

    /**
     * Saved List Store - Sweep Temporary Files.
     *
     * A new update-lock owner removes only fixed temporary names left by interrupted
     * downloads, normalization, and atomic metadata replacement.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function sweepTemporaryFiles(): void
    {
        FileSystem::sweepStaleEntries(
            $this->paths->listDirectory,
            [
                '.download-',
                '.normalized-',
                '.sinkhole-atomic-',
            ],
        );
    }

    /**
     * Saved List Store - Write Metadata.
     *
     * JSON encoding remains centralized so every status file uses the same formatting
     * and restrictive permissions.
     *
     * @param string $identifier - Stable list identifier.
     * @param array  $metadata   - Metadata record.
     *
     * @return void
     *
     * @throws RuntimeException When metadata cannot be encoded.
     *
     * @since 1.0.0
     * @private
     */
    private function writeMetadata(string $identifier, array $metadata): void
    {
        try {
            $contents = json_encode(
                $metadata,
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $exception) {
            throw new RuntimeException('Unable to encode block list metadata.', 0, $exception);
        }

        AtomicFile::write($this->paths->metadataFile($identifier), $contents . PHP_EOL);
    }
}
