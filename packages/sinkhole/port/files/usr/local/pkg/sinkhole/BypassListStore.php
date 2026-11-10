<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use JsonException;
use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\IpNetwork;
use RuntimeException;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/DomainParser.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/IpNetwork.php');
require_once(__DIR__ . '/PackagePaths.php');

/**
 * Bypass List Store.
 *
 * Owns one atomic mixed normalized file and its bounded status metadata for every
 * configured Bypass List, preserving the last good file after failed downloads.
 *
 * @since 1.0.0
 */
final class BypassListStore
{
    /** @since 1.0.0 */
    public function __construct(private readonly PackagePaths $paths)
    {
    }

    /** @since 1.0.0 */
    public function createTemporaryFile(string $prefix): string
    {
        FileSystem::ensureDirectory($this->paths->persistentDirectory, 0700);
        FileSystem::ensureDirectory($this->paths->bypassListDirectory, 0700);

        return FileSystem::createTemporaryFile($this->paths->bypassListDirectory, $prefix, 0600);
    }

    /** @since 1.0.0 */
    public function hasSavedCopy(string $identifier): bool
    {
        return FileSystem::isRegularFile($this->paths->bypassListFile($identifier));
    }

    /** @since 1.0.0 */
    public function savedCopyPath(string $identifier): string
    {
        return $this->paths->bypassListFile($identifier);
    }

    /**
     * Bypass List Store - Read Networks.
     *
     * @param string $identifier - Stable list identifier.
     *
     * @return list<string>
     *
     * @since 1.0.0
     */
    public function readNetworks(string $identifier): array
    {
        $path = $this->paths->bypassListFile($identifier);

        if (!FileSystem::isRegularFile($path)) {
            return [];
        }

        $handle = fopen($path, 'rb');

        if ($handle === false) {
            throw new RuntimeException('Unable to read the saved Bypass List.');
        }

        $networks = [];

        try {
            while (($line = fgets($handle)) !== false) {
                $entry = self::parseNormalizedLine($line);

                if ($entry === null) {
                    throw new RuntimeException('A saved Bypass List is invalid.');
                }

                if ($entry['type'] !== 'network') {
                    continue;
                }

                $networks[] = $entry['network'];

                if (count($networks) > IpNetwork::MAXIMUM_NETWORKS) {
                    throw new RuntimeException('The Bypass List network limit was exceeded.');
                }
            }

            if (!feof($handle)) {
                throw new RuntimeException('Unable to finish reading the saved Bypass List.');
            }
        } finally {
            fclose($handle);
        }

        return $networks;
    }

    /**
     * Bypass List Store - Parse Normalized Line.
     *
     * @param string $line - One package-owned normalized row.
     *
     * @return array|null
     *
     * @since 1.0.0
     */
    public static function parseNormalizedLine(string $line): ?array
    {
        $fields = explode("\t", rtrim($line, "\r\n"));

        if (count($fields) === 3 && $fields[0] === 'D') {
            if (!in_array($fields[1], [DomainParser::EXACT, DomainParser::SUBTREE], true)) {
                return null;
            }

            $domain = DomainParser::normalizeDomain($fields[2]);

            if ($domain === null || $domain !== $fields[2]) {
                return null;
            }

            return [
                'type' => 'domain',
                'semantic' => $fields[1],
                'domain' => $domain,
            ];
        }

        if (count($fields) === 2 && $fields[0] === 'I') {
            try {
                $network = IpNetwork::normalize($fields[1]);
            } catch (\InvalidArgumentException) {
                return null;
            }

            if ($network !== $fields[1]) {
                return null;
            }

            return ['type' => 'network', 'network' => $network];
        }

        return null;
    }

    /** @since 1.0.0 */
    public function metadata(string $identifier): array
    {
        $path = $this->paths->bypassMetadataFile($identifier);

        if (!FileSystem::isRegularFile($path)) {
            return [];
        }

        $contents = file_get_contents($path);

        try {
            $metadata = is_string($contents)
                ? json_decode($contents, true, 16, JSON_THROW_ON_ERROR)
                : null;
        } catch (JsonException $exception) {
            throw new RuntimeException('Bypass List metadata is invalid.', 0, $exception);
        }

        if (!is_array($metadata)) {
            throw new RuntimeException('Bypass List metadata is invalid.');
        }

        return $metadata;
    }

    /** @since 1.0.0 */
    public function commitSuccessfulDownload(
        string $identifier,
        string $normalizedPath,
        array $metadata,
    ): void {
        $size = filesize($normalizedPath);

        if (!FileSystem::isRegularFile($normalizedPath) || !is_int($size) || $size <= 0) {
            throw new RuntimeException('The normalized Bypass List is empty.');
        }

        if (rename($normalizedPath, $this->paths->bypassListFile($identifier)) === false) {
            throw new RuntimeException('Unable to replace the saved Bypass List.');
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
            'kind' => null,
            'fetched_at' => null,
            'entries' => 0,
            'domains' => 0,
            'networks' => 0,
            'ipv4' => 0,
            'ipv6' => 0,
            'skipped' => 0,
            'sha256' => null,
            'last_attempt' => $attemptedAt,
            'last_attempt_url' => $url,
            'last_error' => null,
        ], $this->metadata($identifier));
        $metadata['last_attempt'] = $attemptedAt;
        $metadata['last_attempt_url'] = $url;
        $metadata['last_error'] = substr(str_replace(["\r", "\n"], ' ', $error), 0, 500);
        $this->writeMetadata($identifier, $metadata);
    }

    /** @since 1.0.0 */
    public function remove(string $identifier): void
    {
        FileSystem::removeFixedFile($this->paths->bypassListFile($identifier));
        FileSystem::removeFixedFile($this->paths->bypassMetadataFile($identifier));
    }

    /** @since 1.0.0 */
    public function removeUnconfigured(array $configuredIdentifiers): bool
    {
        if (!is_dir($this->paths->bypassListDirectory) || is_link($this->paths->bypassListDirectory)) {
            return false;
        }

        $configured = array_fill_keys($configuredIdentifiers, true);
        $entries = scandir($this->paths->bypassListDirectory);

        if (!is_array($entries)) {
            throw new RuntimeException('Unable to inspect saved Bypass Lists.');
        }

        $removed = false;

        foreach ($entries as $entry) {
            if (preg_match('/^([a-f0-9]{32})\.(?:entries|json)$/D', $entry, $matches) !== 1) {
                continue;
            }

            if (isset($configured[$matches[1]])) {
                continue;
            }

            $this->remove($matches[1]);
            $removed = true;
        }

        return $removed;
    }

    /** @since 1.0.0 */
    public function sweepTemporaryFiles(): void
    {
        FileSystem::sweepStaleEntries(
            $this->paths->bypassListDirectory,
            ['.download-', '.normalized-', '.sinkhole-atomic-'],
        );
    }

    /** @since 1.0.0 */
    private function writeMetadata(string $identifier, array $metadata): void
    {
        $allowed = array_intersect_key($metadata, array_fill_keys([
            'url',
            'kind',
            'fetched_at',
            'entries',
            'domains',
            'networks',
            'ipv4',
            'ipv6',
            'skipped',
            'sha256',
            'last_attempt',
            'last_attempt_url',
            'last_error',
        ], true));
        $contents = json_encode($allowed, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (!is_string($contents)) {
            throw new RuntimeException('Unable to encode Bypass List metadata.');
        }

        AtomicFile::write($this->paths->bypassMetadataFile($identifier), $contents . PHP_EOL, 0600);
    }
}
