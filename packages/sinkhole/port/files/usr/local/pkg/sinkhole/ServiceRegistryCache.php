<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use PfSense\Sinkhole\Domain\ServiceRegistry;
use RuntimeException;
use stdClass;
use Throwable;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/DownloadClient.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/PackagePaths.php');
require_once(__DIR__ . '/ServiceRegistry.php');

/**
 * Blocked Service Registry Cache.
 *
 * Fetches the fixed registry only on demand and atomically retains its last good
 * document for compilation without network access.
 *
 * @since 1.0.0
 */
final class ServiceRegistryCache
{
    /** @var string @since 1.0.0 */
    public const REGISTRY_URL =
        'https://adguardteam.github.io/HostlistsRegistry/assets/services.json';

    /** @var int @since 1.0.0 */
    public const MAXIMUM_REGISTRY_BYTES = 16777216;

    /** @var int @since 1.0.0 */
    public const CACHE_LIFETIME_SECONDS = 86400;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_CACHE_BYTES = 50331648;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_ERROR_BYTES = 1024;

    /** @var int @since 1.0.0 */
    private const CACHE_SCHEMA_VERSION = 1;

    /** @since 1.0.0 */
    public function __construct(
        private readonly PackagePaths $paths,
        private readonly DownloadClient $downloadClient,
    ) {
    }

    /**
     * Blocked Service Registry Cache - Load.
     *
     * @param bool $force - Whether to bypass the one-day cache lifetime.
     * @param int|null $now - Testable Unix time.
     *
     * @return array{registry: array, status: array{fetched_at: int|null, last_error: string}, changed: bool}
     *
     * @since 1.0.0
     */
    public function load(bool $force = false, ?int $now = null): array
    {
        $now ??= time();
        $record = self::emptyRecord('');
        $registry = ServiceRegistry::emptyRegistry();

        try {
            $savedRecord = self::readRecord($this->paths->serviceRegistryCacheFile);

            if ($savedRecord !== null) {
                $record = $savedRecord;
            }

            if (is_string($record['contents'])) {
                $registry = ServiceRegistry::parse($record['contents']);
            }
        } catch (Throwable $throwable) {
            $record = self::emptyRecord(self::errorMessage($throwable));
        }

        if ($force === false && self::isFresh($record['fetched_at'], $now)) {
            return [
                'registry' => $registry,
                'status' => self::statusFromRecord($record),
                'changed' => false,
            ];
        }

        try {
            $contents = $this->download();
            $downloadedRegistry = ServiceRegistry::parse($contents);

            if ($downloadedRegistry['services'] === []) {
                throw new RuntimeException('The blocked-services registry contains no services.');
            }

            $changed = !is_string($record['contents']) || $record['contents'] !== $contents;
            $record = [
                'fetched_at' => $now,
                'contents' => $contents,
                'last_error' => '',
            ];
            $this->writeRecord($record);

            return [
                'registry' => $downloadedRegistry,
                'status' => self::statusFromRecord($record),
                'changed' => $changed,
            ];
        } catch (Throwable $throwable) {
            $record['last_error'] = self::errorMessage($throwable);

            try {
                $this->writeRecord($record);
            } catch (Throwable $cacheThrowable) {
                $record['last_error'] = self::limitError(
                    $record['last_error'] . ' ' . $cacheThrowable->getMessage(),
                );
            }

            return [
                'registry' => $registry,
                'status' => self::statusFromRecord($record),
                'changed' => false,
            ];
        }
    }

    /**
     * Blocked Service Registry Cache - Cached Registry.
     *
     * Compilation uses this read-only boundary and therefore never triggers a
     * network request.
     *
     * @param PackagePaths $paths - Package-owned paths.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public static function cachedRegistry(PackagePaths $paths): array
    {
        try {
            $record = self::readRecord($paths->serviceRegistryCacheFile);

            return is_array($record) && is_string($record['contents'])
                ? ServiceRegistry::parse($record['contents'])
                : ServiceRegistry::emptyRegistry();
        } catch (Throwable) {
            return ServiceRegistry::emptyRegistry();
        }
    }

    /**
     * Blocked Service Registry Cache - Status.
     *
     * @return array{fetched_at: int|null, last_error: string}
     *
     * @since 1.0.0
     */
    public function status(): array
    {
        try {
            return self::statusFromRecord(
                self::readRecord($this->paths->serviceRegistryCacheFile)
                ?? self::emptyRecord(''),
            );
        } catch (Throwable $throwable) {
            return self::statusFromRecord(self::emptyRecord(self::errorMessage($throwable)));
        }
    }

    /**
     * Blocked Service Registry Cache - Remove.
     *
     * @since 1.0.0
     */
    public static function removeCacheFile(PackagePaths $paths): void
    {
        if (
            @lstat($paths->serviceRegistryCacheFile) !== false
            && @unlink($paths->serviceRegistryCacheFile) === false
        ) {
            throw new RuntimeException('Unable to remove the blocked-services registry cache.');
        }
    }

    /** @return string @since 1.0.0 @private */
    private function download(): string
    {
        FileSystem::ensureDirectory($this->paths->catalogCacheDirectory, 0700);
        $temporaryPath = FileSystem::createTemporaryFile(
            $this->paths->catalogCacheDirectory,
            '.sinkhole-services-download-',
            0600,
        );

        try {
            $result = $this->downloadClient->download(
                self::REGISTRY_URL,
                $temporaryPath,
                self::MAXIMUM_REGISTRY_BYTES,
            );
            $reportedBytes = $result['bytes'] ?? null;
            $actualBytes = @filesize($temporaryPath);

            if (($result['success'] ?? false) !== true) {
                throw new RuntimeException(is_string($result['error'] ?? null)
                    ? $result['error']
                    : 'The blocked-services registry download failed.');
            }

            if (
                !is_int($reportedBytes)
                || $reportedBytes <= 0
                || $reportedBytes > self::MAXIMUM_REGISTRY_BYTES
                || !is_int($actualBytes)
                || $actualBytes !== $reportedBytes
                || $actualBytes > self::MAXIMUM_REGISTRY_BYTES
                || FileSystem::isRegularFile($temporaryPath) === false
            ) {
                throw new RuntimeException(
                    'The blocked-services registry is empty or exceeds the 16 MiB size limit.',
                );
            }

            $contents = @file_get_contents($temporaryPath);

            if (!is_string($contents) || strlen($contents) !== $actualBytes) {
                throw new RuntimeException('Unable to read the blocked-services registry.');
            }

            return $contents;
        } finally {
            if (@lstat($temporaryPath) !== false) {
                @unlink($temporaryPath);
            }
        }
    }

    /** @return array|null @since 1.0.0 @private */
    private static function readRecord(string $path): ?array
    {
        $before = @lstat($path);

        if ($before === false) {
            return null;
        }

        if (
            ($before['mode'] & 0170000) !== 0100000
            || $before['size'] <= 0
            || $before['size'] > self::MAXIMUM_CACHE_BYTES
        ) {
            throw new RuntimeException('The saved blocked-services cache is invalid.');
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
            throw new RuntimeException('Unable to read the saved blocked-services cache.');
        }

        $document = json_decode($serialized, false, 8, JSON_THROW_ON_ERROR);

        if (
            !$document instanceof stdClass
            || ($document->schema_version ?? null) !== self::CACHE_SCHEMA_VERSION
            || !property_exists($document, 'fetched_at')
            || !property_exists($document, 'contents')
            || !property_exists($document, 'last_error')
            || ($document->fetched_at !== null && !is_int($document->fetched_at))
            || ($document->contents !== null && !is_string($document->contents))
            || !is_string($document->last_error)
            || (is_string($document->contents)
                && strlen($document->contents) > self::MAXIMUM_REGISTRY_BYTES)
        ) {
            throw new RuntimeException('The saved blocked-services cache is invalid.');
        }

        return [
            'fetched_at' => $document->fetched_at,
            'contents' => $document->contents,
            'last_error' => self::limitError($document->last_error),
        ];
    }

    /** @since 1.0.0 @private */
    private function writeRecord(array $record): void
    {
        FileSystem::ensureDirectory($this->paths->catalogCacheDirectory, 0700);
        $serialized = json_encode([
            'schema_version' => self::CACHE_SCHEMA_VERSION,
            'fetched_at' => $record['fetched_at'],
            'contents' => $record['contents'],
            'last_error' => self::limitError($record['last_error']),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        AtomicFile::write(
            $this->paths->serviceRegistryCacheFile,
            $serialized . "\n",
            0600,
            $this->paths->catalogCacheDirectory,
        );
    }

    /** @since 1.0.0 @private */
    private static function isFresh(?int $fetchedAt, int $now): bool
    {
        return $fetchedAt !== null
            && $fetchedAt >= 0
            && $fetchedAt <= $now
            && ($now - $fetchedAt) < self::CACHE_LIFETIME_SECONDS;
    }

    /** @return array{fetched_at: int|null, contents: string|null, last_error: string} @since 1.0.0 @private */
    private static function emptyRecord(string $error): array
    {
        return ['fetched_at' => null, 'contents' => null, 'last_error' => self::limitError($error)];
    }

    /** @return array{fetched_at: int|null, last_error: string} @since 1.0.0 @private */
    private static function statusFromRecord(array $record): array
    {
        return [
            'fetched_at' => $record['fetched_at'],
            'last_error' => $record['last_error'],
        ];
    }

    /** @since 1.0.0 @private */
    private static function errorMessage(Throwable $throwable): string
    {
        $message = trim($throwable->getMessage());

        return self::limitError($message === ''
            ? 'The blocked-services registry operation failed.'
            : $message);
    }

    /** @since 1.0.0 @private */
    private static function limitError(string $message): string
    {
        if (preg_match('//u', $message) !== 1) {
            $message = 'The blocked-services registry operation failed.';
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
}
