<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use RuntimeException;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/FileSystem.php');

/**
 * IP Status Store.
 *
 * Stores only bounded operational fields; MaxMind credentials are not accepted by
 * this boundary and therefore cannot enter status output.
 *
 * @since 1.0.0
 */
final class IpStatusStore
{
    /** @since 1.0.0 */
    public function __construct(private readonly string $path)
    {
    }

    /**
     * IP Status Store - Read.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function read(): array
    {
        $status = @lstat($this->path);

        if (!is_array($status)) {
            return [];
        }

        if (($status['mode'] & 0170000) !== 0100000 || $status['size'] > 65536) {
            return [];
        }

        $contents = file_get_contents($this->path);
        $decoded = is_string($contents) ? json_decode($contents, true, 16) : null;

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * IP Status Store - Write.
     *
     * @param array $status - Secret-free operational status.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function write(array $status): void
    {
        $allowed = array_intersect_key($status, array_fill_keys([
            'state',
            'last_attempt',
            'last_success',
            'ipv4_entries',
            'ipv6_entries',
            'skipped_lines',
            'lists_attempted',
            'lists_failed',
            'geolite_updated_at',
            'geolite_extractor',
            'last_error',
        ], true));

        if (isset($allowed['last_error']) && is_string($allowed['last_error'])) {
            $allowed['last_error'] = substr(
                str_replace(["\r", "\n"], ' ', $allowed['last_error']),
                0,
                1024,
            );
        }

        $contents = json_encode($allowed, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (!is_string($contents)) {
            throw new RuntimeException('Unable to encode IP blocking status.');
        }

        AtomicFile::write($this->path, $contents . PHP_EOL, 0600);
    }

    /** @since 1.0.0 */
    public function clear(): void
    {
        FileSystem::removeFixedFile($this->path);
    }
}
