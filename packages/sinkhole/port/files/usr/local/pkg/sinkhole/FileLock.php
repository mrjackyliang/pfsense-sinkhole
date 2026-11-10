<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use RuntimeException;

/**
 * File Lock.
 *
 * Coordinates package operations with reusable timed filesystem locks.
 *
 * @since 1.0.0
 */
final class FileLock
{
    /**
     * File Lock - Process Locks.
     *
     * Nested package operations in one PHP process share the same descriptor while
     * other processes still observe one exclusive filesystem lock.
     *
     * @var array<string, array{handle: mixed, references: int}>
     *
     * @since 1.0.0
     * @private
     */
    private static array $processLocks = [];

    /**
     * File Lock - Acquired.
     *
     * Tracks this instance's reference so release and destruction are idempotent.
     *
     * @var bool
     *
     * @since 1.0.0
     * @private
     */
    private bool $acquired = false;

    /**
     * File Lock - Constructor.
     *
     * Production uses "/var/run" while tests can provide a disposable path.
     *
     * @param string $path - Lock file path.
     *
     * @since 1.0.0
     */
    public function __construct(private readonly string $path)
    {
    }

    /**
     * File Lock - Destructor.
     *
     * Explicit release remains preferred, while destruction protects exceptional
     * paths from leaking the descriptor.
     *
     * @since 1.0.0
     */
    public function __destruct()
    {
        $this->release();
    }

    /**
     * File Lock - Acquire.
     *
     * Waits up to the requested timeout when another valid process owns the lock.
     * A zero timeout preserves the non-blocking updater behavior.
     *
     * @param int $timeoutSeconds - Maximum wait in seconds.
     *
     * @return bool
     *
     * @throws RuntimeException When coordination cannot be established.
     *
     * @since 1.0.0
     */
    public function acquire(int $timeoutSeconds = 0): bool
    {
        if ($timeoutSeconds < 0) {
            throw new RuntimeException('The Sinkhole lock timeout is invalid.');
        }

        if ($this->acquired) {
            return true;
        }

        if (isset(self::$processLocks[$this->path])) {
            self::$processLocks[$this->path]['references']++;
            $this->acquired = true;

            return true;
        }

        $handle = $this->openHandle();
        $deadline = microtime(true) + $timeoutSeconds;

        while (flock($handle, LOCK_EX | LOCK_NB) === false) {
            if ($timeoutSeconds === 0 || microtime(true) >= $deadline) {
                fclose($handle);

                return false;
            }

            usleep(100000);
        }

        if (
            ftruncate($handle, 0) === false
            || rewind($handle) === false
            || fwrite($handle, (string) getmypid() . PHP_EOL) === false
            || fflush($handle) === false
        ) {
            flock($handle, LOCK_UN);
            fclose($handle);

            throw new RuntimeException('Unable to update the Sinkhole lock.');
        }

        self::$processLocks[$this->path] = [
            'handle' => $handle,
            'references' => 1,
        ];
        $this->acquired = true;

        return true;
    }

    /**
     * File Lock - Is Locked.
     *
     * Diagnostic callers can probe the real advisory lock instead of treating the
     * reusable lock file's presence as evidence that a job is still running.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function isLocked(): bool
    {
        if (isset(self::$processLocks[$this->path])) {
            return true;
        }

        $handle = $this->openHandle();

        if (flock($handle, LOCK_EX | LOCK_NB) === false) {
            fclose($handle);

            return true;
        }

        flock($handle, LOCK_UN);
        fclose($handle);

        return false;
    }

    /**
     * File Lock - Release.
     *
     * The reusable lock file remains in place to avoid an unlink race with a newly
     * starting process, while its PID is truncated before the final unlock.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function release(): void
    {
        if ($this->acquired === false || isset(self::$processLocks[$this->path]) === false) {
            return;
        }

        self::$processLocks[$this->path]['references']--;
        $this->acquired = false;

        if (self::$processLocks[$this->path]['references'] > 0) {
            return;
        }

        $handle = self::$processLocks[$this->path]['handle'];

        if (ftruncate($handle, 0)) {
            fflush($handle);
        }

        flock($handle, LOCK_UN);
        fclose($handle);

        unset(self::$processLocks[$this->path]);
    }

    /**
     * File Lock - Open Handle.
     *
     * Creates a missing lock exclusively under a restrictive umask and never changes
     * the mode of a path that another process created first.
     *
     * @return mixed
     *
     * @throws RuntimeException When the lock path is not a regular file.
     *
     * @since 1.0.0
     * @private
     */
    private function openHandle(): mixed
    {
        $status = @lstat($this->path);

        if (is_array($status)) {
            if (($status['mode'] & 0170000) !== 0100000) {
                throw new RuntimeException('The Sinkhole lock path is invalid.');
            }

            $handle = @fopen($this->path, 'c+b');

            if ($handle === false) {
                throw new RuntimeException('Unable to open the Sinkhole lock.');
            }

            return $handle;
        }

        $previousMask = umask(0077);

        try {
            $handle = @fopen($this->path, 'x+b');
        } finally {
            umask($previousMask);
        }

        if ($handle !== false) {
            return $handle;
        }

        $status = @lstat($this->path);

        if (!is_array($status) || ($status['mode'] & 0170000) !== 0100000) {
            throw new RuntimeException('The Sinkhole lock path is invalid.');
        }

        $handle = @fopen($this->path, 'c+b');

        if ($handle === false) {
            throw new RuntimeException('Unable to open the Sinkhole lock.');
        }

        return $handle;
    }
}
