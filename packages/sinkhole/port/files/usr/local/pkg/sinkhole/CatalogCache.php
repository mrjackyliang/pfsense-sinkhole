<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use PfSense\Sinkhole\Domain\Catalog;
use RuntimeException;
use stdClass;
use Throwable;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/Catalog.php');
require_once(__DIR__ . '/DownloadClient.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/PackagePaths.php');

/**
 * Catalog Cache.
 *
 * Fetches the two fixed popular-list catalogs on demand, validates each complete
 * document before committing it, and retains the last good copy after failures.
 *
 * @since 1.0.0
 */
final class CatalogCache
{
    /** @var int @since 1.0.0 */
    public const MAXIMUM_CATALOG_BYTES = 4194304;

    /** @var int @since 1.0.0 */
    public const CACHE_LIFETIME_SECONDS = 86400;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_CACHE_BYTES = 12582912;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_ERROR_BYTES = 1024;

    /** @var int @since 1.0.0 */
    private const CACHE_SCHEMA_VERSION = 1;

    /** @var string @since 1.0.0 */
    private const CATALOG_LISTS = 'lists';

    /** @var string @since 1.0.0 */
    private const CATALOG_IP = 'ip';

    /** @var string @since 1.0.0 */
    private const CATALOG_BYPASS = 'bypass';

    /**
     * Catalog Cache - Source URLs.
     *
     * These fixed endpoints are never derived from request or downloaded data.
     *
     * @var array<string, string>
     *
     * @since 1.0.0
     */
    private const SOURCE_URLS = [
        Catalog::SOURCE_ADGUARD_HOME =>
            'https://adguardteam.github.io/HostlistsRegistry/assets/filters.json',
        Catalog::SOURCE_PFBLOCKERNG =>
            'https://raw.githubusercontent.com/pfsense/FreeBSD-ports/devel/'
            . 'net/pfSense-pkg-pfBlockerNG-devel/files/usr/local/www/pfblockerng/'
            . 'pfblockerng_feeds.json',
    ];

    /**
     * Catalog Cache - Constructor.
     *
     * @param PackagePaths   $paths          - Package-owned paths.
     * @param DownloadClient $downloadClient - Existing bounded HTTP transport.
     *
     * @since 1.0.0
     */
    public function __construct(
        private readonly PackagePaths $paths,
        private readonly DownloadClient $downloadClient,
    ) {
    }

    /**
     * Catalog Cache - Load.
     *
     * Fresh copies are reused for one day. A forced load always attempts both
     * fixed sources while preserving each independently on failure.
     *
     * @param bool     $force - Whether to bypass the one-day cache lifetime.
     * @param int|null $now   - Testable Unix time.
     *
     * @return array{
     *     entries: list<array>,
     *     statuses: array<string, array{
     *         source: string,
     *         fetched_at: int|null,
     *         last_error: string
     *     }>
     * }
     *
     * @since 1.0.0
     */
    public function load(bool $force = false, ?int $now = null): array
    {
        $now ??= time();
        $entries = [];
        $statuses = [];

        foreach (array_keys(self::SOURCE_URLS) as $source) {
            $result = $this->loadSource(
                $source,
                $force,
                $now,
                self::CATALOG_LISTS,
            );
            $entries = array_merge($entries, $result['entries']);
            $statuses[$source] = $result['status'];
        }

        return [
            'entries' => $entries,
            'statuses' => $statuses,
        ];
    }

    /**
     * Catalog Cache - Load IP.
     *
     * Reuses the same full pfBlockerNG cache document as DNS search but parses only
     * its IPv4 and IPv6 feed sections.
     *
     * @param bool $force - Whether to bypass the one-day cache lifetime.
     * @param int|null $now - Testable Unix time.
     *
     * @return array{entries: list<array>, statuses: array<string, array>}
     *
     * @since 1.0.0
     */
    public function loadIp(bool $force = false, ?int $now = null): array
    {
        $now ??= time();
        $result = $this->loadSource(
            Catalog::SOURCE_PFBLOCKERNG,
            $force,
            $now,
            self::CATALOG_IP,
        );

        return [
            'entries' => $result['entries'],
            'statuses' => [Catalog::SOURCE_PFBLOCKERNG => $result['status']],
        ];
    }

    /**
     * Catalog Cache - Load Bypass.
     *
     * Reuses both complete source documents while exposing only the stable DNS,
     * IPv4, IPv6, and filter keys owned by the Bypass catalog.
     *
     * @param bool $force - Whether to bypass the one-day cache lifetime.
     * @param int|null $now - Testable Unix time.
     *
     * @return array{entries: list<array>, statuses: array<string, array>}
     *
     * @since 1.0.0
     */
    public function loadBypass(bool $force = false, ?int $now = null): array
    {
        $now ??= time();
        $entries = [];
        $statuses = [];

        foreach (array_keys(self::SOURCE_URLS) as $source) {
            $result = $this->loadSource(
                $source,
                $force,
                $now,
                self::CATALOG_BYPASS,
            );
            $entries = array_merge($entries, $result['entries']);
            $statuses[$source] = $result['status'];
        }

        return [
            'entries' => $entries,
            'statuses' => $statuses,
        ];
    }

    /**
     * Catalog Cache - Status.
     *
     * Reads fetch metadata without downloading or parsing the remote documents.
     *
     * @return array<string, array{
     *     source: string,
     *     fetched_at: int|null,
     *     last_error: string
     * }>
     *
     * @since 1.0.0
     */
    public function status(): array
    {
        $statuses = [];

        foreach (array_keys(self::SOURCE_URLS) as $source) {
            try {
                $record = $this->readRecord($source);
                $statuses[$source] = $this->recordStatus($source, $record);
            } catch (Throwable $throwable) {
                $statuses[$source] = $this->recordStatus(
                    $source,
                    $this->emptyRecord($this->errorMessage($throwable)),
                );
            }
        }

        return $statuses;
    }

    /**
     * Catalog Cache - Remove Cache Files.
     *
     * Both fixed files are attempted even if one cannot be removed.
     *
     * @param PackagePaths $paths - Package-owned paths.
     *
     * @return void
     *
     * @throws RuntimeException When a cache file remains.
     *
     * @since 1.0.0
     */
    public static function removeCacheFiles(PackagePaths $paths): void
    {
        $failed = [];

        foreach (self::cacheFiles($paths) as $path) {
            if (@lstat($path) === false) {
                continue;
            }

            if (@unlink($path) === false) {
                $failed[] = $path;
            }
        }

        if (count($failed) > 0) {
            throw new RuntimeException('Unable to remove the popular-list catalog cache.');
        }
    }

    /**
     * Catalog Cache - Load Source.
     *
     * @param string $source - Stable catalog source key.
     * @param bool   $force  - Whether to fetch regardless of age.
     * @param int    $now    - Current Unix time.
     * @param string $catalog - Lists, IP, or Bypass parser selection.
     *
     * @return array{
     *     entries: list<array>,
     *     status: array{source: string, fetched_at: int|null, last_error: string}
     * }
     *
     * @since 1.0.0
     * @private
     */
    private function loadSource(
        string $source,
        bool $force,
        int $now,
        string $catalog,
    ): array
    {
        $record = $this->emptyRecord('');
        $cachedEntries = [];

        try {
            $savedRecord = $this->readRecord($source);

            if (is_array($savedRecord)) {
                $record = $savedRecord;
            }

            if (is_string($record['contents'])) {
                $cachedEntries = $this->parseEntries(
                    $source,
                    $record['contents'],
                    $catalog,
                );
            }
        } catch (Throwable $throwable) {
            $record = $this->emptyRecord($this->errorMessage($throwable));
            $cachedEntries = [];
        }

        if ($force === false && $this->isFresh($record['fetched_at'], $now)) {
            return [
                'entries' => $cachedEntries,
                'status' => $this->recordStatus($source, $record),
            ];
        }

        try {
            $contents = $this->download($source);
            $downloadedEntries = $this->parseEntries($source, $contents, $catalog);

            $this->validateDownloadedEntries(
                $source,
                $contents,
                $catalog,
                $downloadedEntries,
            );

            $record = [
                'fetched_at' => $now,
                'contents' => $contents,
                'last_error' => '',
            ];
            $this->writeRecord($source, $record);

            return [
                'entries' => $downloadedEntries,
                'status' => $this->recordStatus($source, $record),
            ];
        } catch (Throwable $throwable) {
            $record['last_error'] = $this->errorMessage($throwable);

            try {
                $this->writeRecord($source, $record);
            } catch (Throwable $cacheThrowable) {
                $record['last_error'] = $this->limitError(
                    $record['last_error'] . ' ' . $cacheThrowable->getMessage(),
                );
            }

            return [
                'entries' => $cachedEntries,
                'status' => $this->recordStatus($source, $record),
            ];
        }
    }

    /**
     * Catalog Cache - Parse Entries.
     *
     * One parser selection reads the same saved complete document without making
     * a page-specific cache or another network request.
     *
     * @param string $source   - Stable source key.
     * @param string $contents - Complete saved source document.
     * @param string $catalog  - Lists, IP, or Bypass parser selection.
     *
     * @return list<array>
     *
     * @since 1.0.0
     * @private
     */
    private function parseEntries(
        string $source,
        string $contents,
        string $catalog,
    ): array {
        return match ($catalog) {
            self::CATALOG_LISTS => Catalog::parse($source, $contents),
            self::CATALOG_IP => Catalog::parseIp($contents),
            self::CATALOG_BYPASS => Catalog::parseBypass($source, $contents),
            default => throw new RuntimeException('The catalog parser is invalid.'),
        };
    }

    /**
     * Catalog Cache - Validate Downloaded Entries.
     *
     * A Bypass refresh validates the ordinary Lists and IP views before replacing
     * their shared source document, even when Bypass itself has valid entries.
     *
     * @param string $source - Stable source key.
     * @param string $contents - Complete downloaded JSON document.
     * @param string $catalog - Lists, IP, or Bypass parser selection.
     * @param list<array> $downloadedEntries - Entries selected for the caller.
     *
     * @return void
     *
     * @throws RuntimeException When the shared document has no ordinary entries.
     *
     * @since 1.0.0
     * @private
     */
    private function validateDownloadedEntries(
        string $source,
        string $contents,
        string $catalog,
        array $downloadedEntries,
    ): void {
        $validationEntries = $downloadedEntries;

        if ($catalog === self::CATALOG_BYPASS) {
            $validationEntries = Catalog::parse($source, $contents);

            if ($source === Catalog::SOURCE_PFBLOCKERNG) {
                $ipEntries = Catalog::parseIp($contents);
                $validationEntries = array_merge($validationEntries, $ipEntries);
            }
        }

        if (count($validationEntries) === 0) {
            throw new RuntimeException('The catalog contains no valid entries.');
        }
    }

    /**
     * Catalog Cache - Download.
     *
     * @param string $source - Stable source key.
     *
     * @return string
     *
     * @throws RuntimeException When transport or file validation fails.
     *
     * @since 1.0.0
     * @private
     */
    private function download(string $source): string
    {
        FileSystem::ensureDirectory($this->paths->catalogCacheDirectory, 0700);
        $temporaryPath = FileSystem::createTemporaryFile(
            $this->paths->catalogCacheDirectory,
            '.sinkhole-catalog-download-',
            0600,
        );

        try {
            $result = $this->downloadClient->download(
                self::SOURCE_URLS[$source],
                $temporaryPath,
                self::MAXIMUM_CATALOG_BYTES,
            );

            if (($result['success'] ?? false) !== true) {
                $error = is_string($result['error'] ?? null)
                    ? $result['error']
                    : 'The catalog download failed.';

                throw new RuntimeException($error);
            }

            $reportedBytes = $result['bytes'] ?? null;
            $actualBytes = @filesize($temporaryPath);

            if (
                !is_int($reportedBytes)
                || $reportedBytes <= 0
                || $reportedBytes > self::MAXIMUM_CATALOG_BYTES
                || FileSystem::isRegularFile($temporaryPath) === false
                || !is_int($actualBytes)
                || $actualBytes <= 0
                || $actualBytes > self::MAXIMUM_CATALOG_BYTES
                || $actualBytes !== $reportedBytes
            ) {
                throw new RuntimeException(
                    'The catalog download is empty or exceeds the 4 MiB size limit.',
                );
            }

            $contents = @file_get_contents($temporaryPath);

            if (!is_string($contents) || strlen($contents) !== $actualBytes) {
                throw new RuntimeException('Unable to read the catalog download.');
            }

            return $contents;
        } finally {
            if (@lstat($temporaryPath) !== false) {
                @unlink($temporaryPath);
            }
        }
    }

    /**
     * Catalog Cache - Read Record.
     *
     * @param string $source - Stable source key.
     *
     * @return array{fetched_at: int|null, contents: string|null, last_error: string}|null
     *
     * @throws RuntimeException When a present cache is malformed.
     *
     * @since 1.0.0
     * @private
     */
    private function readRecord(string $source): ?array
    {
        $path = self::cacheFile($this->paths, $source);
        $before = @lstat($path);

        if ($before === false) {
            return null;
        }

        if (
            ($before['mode'] & 0170000) !== 0100000
            || $before['size'] <= 0
            || $before['size'] > self::MAXIMUM_CACHE_BYTES
        ) {
            throw new RuntimeException('The saved catalog cache is invalid.');
        }

        $serialized = @file_get_contents($path);
        $after = @lstat($path);

        if (
            !is_string($serialized)
            || !is_array($after)
            || $before['dev'] !== $after['dev']
            || $before['ino'] !== $after['ino']
            || $before['size'] !== $after['size']
            || strlen($serialized) !== $before['size']
        ) {
            throw new RuntimeException('Unable to read the saved catalog cache.');
        }

        $document = json_decode($serialized, false, 8, JSON_THROW_ON_ERROR);

        if (
            !$document instanceof stdClass
            || ($document->schema_version ?? null) !== self::CACHE_SCHEMA_VERSION
            || ($document->source ?? null) !== $source
            || !property_exists($document, 'fetched_at')
            || !property_exists($document, 'contents')
            || !property_exists($document, 'last_error')
            || ($document->fetched_at !== null && !is_int($document->fetched_at))
            || ($document->contents !== null && !is_string($document->contents))
            || ($document->last_error !== null && !is_string($document->last_error))
            || (is_string($document->contents)
                && strlen($document->contents) > self::MAXIMUM_CATALOG_BYTES)
        ) {
            throw new RuntimeException('The saved catalog cache is invalid.');
        }

        return [
            'fetched_at' => $document->fetched_at,
            'contents' => $document->contents,
            'last_error' => $this->limitError((string) ($document->last_error ?? '')),
        ];
    }

    /**
     * Catalog Cache - Write Record.
     *
     * @param string $source - Stable source key.
     * @param array{fetched_at: int|null, contents: string|null, last_error: string} $record - Record.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function writeRecord(string $source, array $record): void
    {
        FileSystem::ensureDirectory($this->paths->catalogCacheDirectory, 0700);
        $serialized = json_encode(
            [
                'schema_version' => self::CACHE_SCHEMA_VERSION,
                'source' => $source,
                'fetched_at' => $record['fetched_at'],
                'contents' => $record['contents'],
                'last_error' => $this->limitError($record['last_error']),
            ],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        );

        AtomicFile::write(
            self::cacheFile($this->paths, $source),
            $serialized . "\n",
            0600,
            $this->paths->catalogCacheDirectory,
        );
    }

    /**
     * Catalog Cache - Is Fresh.
     *
     * @param int|null $fetchedAt - Last successful fetch time.
     * @param int      $now       - Current Unix time.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function isFresh(?int $fetchedAt, int $now): bool
    {
        return $fetchedAt !== null
            && $fetchedAt >= 0
            && $fetchedAt <= $now
            && ($now - $fetchedAt) < self::CACHE_LIFETIME_SECONDS;
    }

    /**
     * Catalog Cache - Record Status.
     *
     * @param string $source - Stable source key.
     * @param array{fetched_at: int|null, contents: string|null, last_error: string}|null $record - Record.
     *
     * @return array{source: string, fetched_at: int|null, last_error: string}
     *
     * @since 1.0.0
     * @private
     */
    private function recordStatus(string $source, ?array $record): array
    {
        $record ??= $this->emptyRecord('');

        return [
            'source' => Catalog::sourceLabels()[$source],
            'fetched_at' => $record['fetched_at'],
            'last_error' => $record['last_error'],
        ];
    }

    /**
     * Catalog Cache - Empty Record.
     *
     * @param string $lastError - Current error text.
     *
     * @return array{fetched_at: null, contents: null, last_error: string}
     *
     * @since 1.0.0
     * @private
     */
    private function emptyRecord(string $lastError): array
    {
        return [
            'fetched_at' => null,
            'contents' => null,
            'last_error' => $this->limitError($lastError),
        ];
    }

    /**
     * Catalog Cache - Error Message.
     *
     * @param Throwable $throwable - Failed cache or fetch operation.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private function errorMessage(Throwable $throwable): string
    {
        $message = trim($throwable->getMessage());

        return $this->limitError(
            ($message === '') ? 'The catalog operation failed.' : $message,
        );
    }

    /**
     * Catalog Cache - Limit Error.
     *
     * @param string $message - Potentially transport-supplied diagnostic text.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private function limitError(string $message): string
    {
        if (preg_match('//u', $message) !== 1) {
            $message = 'The catalog operation failed.';
        }

        $message = trim((string) preg_replace('/[\x00-\x1f\x7f]+/', ' ', $message));

        if (strlen($message) <= self::MAXIMUM_ERROR_BYTES) {
            return $message;
        }

        if (function_exists('mb_strcut')) {
            return mb_strcut($message, 0, self::MAXIMUM_ERROR_BYTES, 'UTF-8');
        }

        $message = substr($message, 0, self::MAXIMUM_ERROR_BYTES);

        while ($message !== '' && preg_match('//u', $message) !== 1) {
            $message = substr($message, 0, -1);
        }

        return $message;
    }

    /**
     * Catalog Cache - Cache File.
     *
     * @param PackagePaths $paths  - Package-owned paths.
     * @param string       $source - Stable source key.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function cacheFile(PackagePaths $paths, string $source): string
    {
        return match ($source) {
            Catalog::SOURCE_ADGUARD_HOME => $paths->adGuardHomeCatalogCacheFile,
            Catalog::SOURCE_PFBLOCKERNG => $paths->pfBlockerNgCatalogCacheFile,
            default => throw new RuntimeException('The catalog source is invalid.'),
        };
    }

    /**
     * Catalog Cache - Cache Files.
     *
     * @param PackagePaths $paths - Package-owned paths.
     *
     * @return list<string>
     *
     * @since 1.0.0
     * @private
     */
    private static function cacheFiles(PackagePaths $paths): array
    {
        return [
            $paths->adGuardHomeCatalogCacheFile,
            $paths->pfBlockerNgCatalogCacheFile,
        ];
    }
}
