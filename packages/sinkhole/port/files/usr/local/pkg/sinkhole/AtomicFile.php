<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use RuntimeException;

/**
 * Atomic File.
 *
 * Writes package data through a sibling temporary file so interrupted operations
 * never replace a working file with partial contents.
 *
 * @since 1.0.0
 */
final class AtomicFile
{
    /**
     * Atomic File - Write.
     *
     * The temporary file is created under the final mode, flushed, and renamed over
     * the destination on the same filesystem.
     *
     * @param string $path     - Destination path.
     * @param string $contents - Complete file contents.
     * @param int    $mode     - File mode.
     * @param string|null $temporaryDirectory - Root-owned temporary directory.
     *
     * @return void
     *
     * @throws RuntimeException When the write cannot complete atomically.
     *
     * @since 1.0.0
     */
    public static function write(
        string $path,
        string $contents,
        int $mode = 0600,
        ?string $temporaryDirectory = null,
    ): void {
        $directory = dirname($path);
        if (is_link($directory)) {
            throw new RuntimeException('The destination directory is invalid.');
        }

        if (is_dir($directory) === false) {
            $previousMask = umask(0077);

            try {
                if (mkdir($directory, 0700, true) === false) {
                    throw new RuntimeException('Unable to create the destination directory.');
                }
            } finally {
                umask($previousMask);
            }
        }

        $temporaryParent = $temporaryDirectory ?? $directory;

        if (is_link($temporaryParent) || is_dir($temporaryParent) === false) {
            throw new RuntimeException('The temporary directory is invalid.');
        }

        $temporaryPath = '';
        $handle = false;

        $previousMask = umask((~$mode) & 0777);

        try {
            for ($attempt = 0; $attempt < 10; $attempt++) {
                $candidatePath = $temporaryParent
                    . '/.sinkhole-atomic-'
                    . bin2hex(random_bytes(16));
                $candidateHandle = @fopen($candidatePath, 'x+b');

                if ($candidateHandle !== false) {
                    $temporaryPath = $candidatePath;
                    $handle = $candidateHandle;

                    break;
                }
            }
        } finally {
            umask($previousMask);
        }

        if ($handle === false) {
            throw new RuntimeException('Unable to create a temporary file.');
        }

        try {
            try {
                self::writeAll($handle, $contents);

                if (fflush($handle) === false) {
                    throw new RuntimeException('Unable to flush the temporary file.');
                }

                if (function_exists('fsync') && fsync($handle) === false) {
                    throw new RuntimeException('Unable to synchronize the temporary file.');
                }
            } finally {
                fclose($handle);
                $handle = false;
            }

            if (rename($temporaryPath, $path) === false) {
                throw new RuntimeException('Unable to replace the destination file.');
            }

            $temporaryPath = '';
        } finally {
            if (is_resource($handle)) {
                fclose($handle);
            }

            if ($temporaryPath !== '' && (file_exists($temporaryPath) || is_link($temporaryPath))) {
                unlink($temporaryPath);
            }
        }
    }

    /**
     * Atomic File - Write All.
     *
     * Handles short writes until the complete in-memory value reaches the temporary
     * file or a filesystem error interrupts the operation.
     *
     * @param mixed  $handle   - Open file resource.
     * @param string $contents - Complete file contents.
     *
     * @return void
     *
     * @throws RuntimeException When a write fails.
     *
     * @since 1.0.0
     * @private
     */
    private static function writeAll(mixed $handle, string $contents): void
    {
        $offset = 0;
        $length = strlen($contents);

        while ($offset < $length) {
            $bytesWritten = fwrite($handle, substr($contents, $offset));

            if ($bytesWritten === false || $bytesWritten === 0) {
                throw new RuntimeException('Unable to write the temporary file.');
            }

            $offset += $bytesWritten;
        }
    }
}
