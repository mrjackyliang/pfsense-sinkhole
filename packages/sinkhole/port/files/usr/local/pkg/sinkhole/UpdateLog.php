<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use Closure;
use Throwable;

require_once(__DIR__ . '/AtomicFile.php');

/**
 * Update Log.
 *
 * Writes one bounded, secret-free progress log per update run so the Status page
 * can follow downloads, compilation and deployment while the run is still going.
 *
 * @since 1.2.0
 */
final class UpdateLog
{
    /**
     * Update Log - Maximum Bytes.
     *
     * The hard size cap for one run's log, including the truncation notice and the
     * closing line, so a run with thousands of lists never fills `/var/run`.
     *
     * @since 1.2.0
     */
    public const MAXIMUM_BYTES = 262144;

    /**
     * Update Log - Progress Bytes.
     *
     * Progress lines stop here, leaving room under the hard cap for the one
     * truncation notice and the lines that close the run.
     *
     * @since 1.2.0
     */
    public const PROGRESS_BYTES = 258048;

    /**
     * Update Log - Maximum Line Bytes.
     *
     * One message, after its timestamp, never exceeds this size, so a long error
     * from a download library cannot crowd out the rest of the run.
     *
     * @since 1.2.0
     */
    public const MAXIMUM_LINE_BYTES = 1024;

    /**
     * Update Log - Maximum Read Bytes.
     *
     * The Status page's polling endpoint returns at most this much new text per
     * request; the next poll continues from the returned offset.
     *
     * @since 1.2.0
     */
    public const MAXIMUM_READ_BYTES = 65536;

    /**
     * Update Log - Run Pattern.
     *
     * Run identifiers are short hexadecimal digests, so the endpoint can reject
     * any other value before it touches the file.
     *
     * @since 1.2.0
     */
    public const RUN_PATTERN = '/^[a-f0-9]{16}$/';

    /**
     * Update Log - Truncated Message.
     *
     * Written once when a run reaches the progress cap; later progress lines are
     * dropped while the closing line still fits.
     *
     * @since 1.2.0
     */
    public const TRUNCATED_MESSAGE = 'Log truncated; later progress lines are omitted.';

    /**
     * Update Log - Handle.
     *
     * The append handle opened on the file this run created, or null when the log
     * is unavailable and every write is skipped.
     *
     * @var resource|null
     *
     * @since 1.2.0
     * @private
     */
    private mixed $handle = null;

    /**
     * Update Log - Bytes.
     *
     * Counts what this run has written so the size cap holds without asking the
     * filesystem after every line.
     *
     * @var int
     *
     * @since 1.2.0
     * @private
     */
    private int $bytes = 0;

    /**
     * Update Log - Truncated.
     *
     * Records that the truncation notice is already written, so it appears only
     * once per run.
     *
     * @var bool
     *
     * @since 1.2.0
     * @private
     */
    private bool $truncated = false;

    /**
     * Update Log - Started At.
     *
     * The clock reading taken when the run began, used for the duration on the
     * closing line.
     *
     * @var float
     *
     * @since 1.2.0
     * @private
     */
    private float $startedAt = 0.0;

    /**
     * Update Log - Secrets.
     *
     * Values such as the MaxMind license key that are replaced before any line is
     * written, in addition to the URL reduction every line receives.
     *
     * @var list<string>
     *
     * @since 1.2.0
     * @private
     */
    private array $secrets = [];

    /**
     * Update Log - Clock.
     *
     * Returns the current Unix time with fractions; tests replace it to produce
     * fixed timestamps and durations.
     *
     * @var Closure(): float
     *
     * @since 1.2.0
     * @private
     */
    private readonly Closure $clock;

    /**
     * Update Log - Constructor.
     *
     * Production passes the fixed runtime path; tests pass a temporary path and a
     * fixed clock.
     *
     * @param string       $path  - Log file path.
     * @param Closure|null $clock - Optional clock returning Unix time with fractions.
     *
     * @since 1.2.0
     */
    public function __construct(
        private readonly string $path,
        ?Closure $clock = null,
    ) {
        $this->clock = $clock ?? static fn(): float => microtime(true);
    }

    /**
     * Update Log - Destructor.
     *
     * Closes the append handle when the command finishes without an explicit
     * close.
     *
     * @since 1.2.0
     */
    public function __destruct()
    {
        $this->close();
    }

    /**
     * Update Log - Path.
     *
     * The Status page and the endpoint read the same fixed file the updater
     * writes.
     *
     * @return string
     *
     * @since 1.2.0
     */
    public function path(): string
    {
        return $this->path;
    }

    /**
     * Update Log - Begin.
     *
     * Replaces the previous run's file atomically with a new one holding only the
     * start line. The caller already holds the update lock.
     *
     * @param string $trigger - What started the run: scheduled, manual or apply.
     *
     * @return void
     *
     * @since 1.2.0
     */
    public function begin(string $trigger): void
    {
        $this->close();
        $this->bytes = 0;
        $this->truncated = false;
        $this->secrets = [];
        $this->startedAt = ($this->clock)();

        $triggerLabel = match ($trigger) {
            'manual' => 'manual',
            'apply' => 'settings change',
            default => 'scheduled',
        };
        $line = $this->formatLine('Update started (' . $triggerLabel . ').');

        try {
            AtomicFile::write($this->path, $line, 0600);

            $handle = @fopen($this->path, 'ab');

            if ($handle === false) {
                return;
            }

            $openedStatus = fstat($handle);
            $pathStatus = @lstat($this->path);

            if (
                !is_array($openedStatus)
                || !is_array($pathStatus)
                || ($pathStatus['mode'] & 0170000) !== 0100000
                || $openedStatus['ino'] !== $pathStatus['ino']
                || $openedStatus['dev'] !== $pathStatus['dev']
            ) {
                fclose($handle);

                return;
            }

            $this->handle = $handle;
            $this->bytes = strlen($line);
        } catch (Throwable) {
            $this->handle = null;
        }
    }

    /**
     * Update Log - Add Secret.
     *
     * Registers a value that must never appear in the log, such as a license key
     * read from the settings for this run.
     *
     * @param string $secret - Secret value.
     *
     * @return void
     *
     * @since 1.2.0
     */
    public function addSecret(string $secret): void
    {
        if ($secret === '' || in_array($secret, $this->secrets, true)) {
            return;
        }

        $this->secrets[] = $secret;
    }

    /**
     * Update Log - Line.
     *
     * Appends one progress line. Lines past the progress cap are dropped after a
     * single truncation notice; a write failure never interrupts the update.
     *
     * @param string $message - English operational message.
     *
     * @return void
     *
     * @since 1.2.0
     */
    public function line(string $message): void
    {
        $this->write($message, false);
    }

    /**
     * Update Log - Finish.
     *
     * Closes the run with its duration and totals; the closing line may use the
     * room reserved under the hard cap.
     *
     * @param array $result - Updater result.
     *
     * @return void
     *
     * @since 1.2.0
     */
    public function finish(array $result): void
    {
        $duration = $this->duration();

        if (($result['status'] ?? '') === 'stopped') {
            $this->write('Update stopped for package removal after ' . $duration . '.', true);

            return;
        }

        $this->write(sprintf(
            'Update finished in %s: %d attempted, %d successful, %d failed.',
            $duration,
            (int) ($result['attempted'] ?? 0),
            (int) ($result['updated'] ?? 0),
            (int) ($result['failed'] ?? 0),
        ), true);
    }

    /**
     * Update Log - Fail.
     *
     * Closes the run with the reason it failed; the reason passes through the same
     * URL and secret reduction as every other line.
     *
     * @param string $reason - Failure reason.
     *
     * @return void
     *
     * @since 1.2.0
     */
    public function fail(string $reason): void
    {
        $this->write('Update failed after ' . $this->duration() . ': ' . $reason, true);
    }

    /**
     * Update Log - Close.
     *
     * Releases the append handle; later writes are skipped until the next run
     * begins.
     *
     * @return void
     *
     * @since 1.2.0
     */
    public function close(): void
    {
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }

        $this->handle = null;
    }

    /**
     * Update Log - Host.
     *
     * Reduces a list URL to its host, so log lines never carry credentials, paths
     * with tokens or query strings.
     *
     * @param string $url - List URL.
     *
     * @return string
     *
     * @since 1.2.0
     */
    public static function host(string $url): string
    {
        $host = parse_url($url, PHP_URL_HOST);

        if (!is_string($host) || $host === '') {
            return 'an unknown host';
        }

        return strtolower($host);
    }

    /**
     * Update Log - Count.
     *
     * Pairs a count with the singular or plural noun, so log lines read "1 entry" and
     * "2 entries".
     *
     * @param int    $count    - Counted items.
     * @param string $singular - Noun for exactly one item.
     * @param string $plural   - Noun for every other count.
     *
     * @return string
     *
     * @since 1.2.0
     */
    public static function count(int $count, string $singular, string $plural): string
    {
        return $count . ' ' . (($count === 1) ? $singular : $plural);
    }

    /**
     * Update Log - Read.
     *
     * Returns complete lines from an offset, plus a run identifier that changes
     * whenever a new run replaces the file, so a poller knows to start over.
     *
     * @param string      $path         - Log file path.
     * @param int         $offset       - Byte offset the reader already has.
     * @param string|null $run          - Run identifier the reader already has.
     * @param int         $maximumBytes - Maximum bytes to return.
     *
     * @return array{run: string, size: int, offset: int, text: string, reset: bool}
     *
     * @since 1.2.0
     */
    public static function read(
        string $path,
        int $offset,
        ?string $run = null,
        int $maximumBytes = self::MAXIMUM_READ_BYTES,
    ): array {
        $knownRun = $run ?? '';
        $missing = [
            'run' => '',
            'size' => 0,
            'offset' => 0,
            'text' => '',
            'reset' => $offset > 0 || $knownRun !== '',
        ];
        $pathStatus = @lstat($path);

        if (!is_array($pathStatus) || ($pathStatus['mode'] & 0170000) !== 0100000) {
            return $missing;
        }

        $handle = @fopen($path, 'rb');

        if ($handle === false) {
            return $missing;
        }

        try {
            $openedStatus = fstat($handle);

            if (
                !is_array($openedStatus)
                || $openedStatus['ino'] !== $pathStatus['ino']
                || $openedStatus['dev'] !== $pathStatus['dev']
            ) {
                return $missing;
            }

            $size = $openedStatus['size'];
            $firstLine = fgets($handle, 512);
            $runIdentity = $openedStatus['dev']
                . ':'
                . $openedStatus['ino']
                . ':'
                . (is_string($firstLine) ? $firstLine : '');
            $runIdentifier = substr(hash('sha256', $runIdentity), 0, 16);
            $reset = $offset > $size
                || ($knownRun !== '' && $knownRun !== $runIdentifier);
            $start = ($reset) ? 0 : $offset;
            $length = min(max(0, $maximumBytes), $size - $start);
            $text = '';

            if ($length > 0 && fseek($handle, $start) === 0) {
                $contents = stream_get_contents($handle, $length);
                $text = is_string($contents) ? $contents : '';
            }

            $lastNewline = strrpos($text, "\n");
            $text = ($lastNewline === false) ? '' : substr($text, 0, $lastNewline + 1);

            return [
                'run' => $runIdentifier,
                'size' => $size,
                'offset' => $start + strlen($text),
                'text' => $text,
                'reset' => $reset,
            ];
        } finally {
            fclose($handle);
        }
    }

    /**
     * Update Log - Write.
     *
     * Applies the progress cap to ordinary lines and the hard cap to closing
     * lines, writing the truncation notice the first time a line is dropped.
     *
     * @param string $message - Message.
     * @param bool   $final   - Whether the line closes the run.
     *
     * @return void
     *
     * @since 1.2.0
     * @private
     */
    private function write(string $message, bool $final): void
    {
        if (!is_resource($this->handle)) {
            return;
        }

        $line = $this->formatLine($message);
        $limit = ($final) ? self::MAXIMUM_BYTES : self::PROGRESS_BYTES;

        if ($this->bytes + strlen($line) <= $limit) {
            $this->append($line);

            return;
        }

        if ($final || $this->truncated) {
            return;
        }

        $this->truncated = true;
        $this->append($this->formatLine(self::TRUNCATED_MESSAGE));
    }

    /**
     * Update Log - Append.
     *
     * Writes one complete line and flushes it so a poller sees it at once; any
     * failure disables the log for the rest of the run.
     *
     * @param string $line - Formatted line.
     *
     * @return void
     *
     * @since 1.2.0
     * @private
     */
    private function append(string $line): void
    {
        $offset = 0;
        $length = strlen($line);

        while ($offset < $length) {
            $bytesWritten = @fwrite($this->handle, substr($line, $offset));

            if ($bytesWritten === false || $bytesWritten === 0) {
                $this->close();

                return;
            }

            $offset += $bytesWritten;
        }

        fflush($this->handle);
        $this->bytes += $length;
    }

    /**
     * Update Log - Format Line.
     *
     * Prefixes the firewall's local time, as the system log does, and reduces the
     * message to one bounded, secret-free line.
     *
     * @param string $message - Message.
     *
     * @return string
     *
     * @since 1.2.0
     * @private
     */
    private function formatLine(string $message): string
    {
        $timestamp = date('Y-m-d H:i:s', (int) floor(($this->clock)()));

        return $timestamp . ' ' . $this->sanitize($message) . "\n";
    }

    /**
     * Update Log - Sanitize.
     *
     * Replaces registered secrets, reduces every URL to its host and removes
     * control characters before the length cap applies.
     *
     * @param string $message - Message.
     *
     * @return string
     *
     * @since 1.2.0
     * @private
     */
    private function sanitize(string $message): string
    {
        foreach ($this->secrets as $secret) {
            $encodedSecret = rawurlencode($secret);
            $message = str_replace([$secret, $encodedSecret], '[redacted]', $message);
        }

        $reducedMessage = preg_replace_callback(
            '~\b[a-z][a-z0-9+.\-]*://[^\s<>"\']+~i',
            static fn(array $matches): string => self::host($matches[0]),
            $message,
        );
        $message = is_string($reducedMessage) ? $reducedMessage : '';
        $printableMessage = preg_replace('/[\x00-\x1F\x7F]+/', ' ', $message);
        $message = trim(is_string($printableMessage) ? $printableMessage : '');

        if (strlen($message) <= self::MAXIMUM_LINE_BYTES) {
            return $message;
        }

        $shortenedMessage = function_exists('mb_strcut')
            ? mb_strcut($message, 0, self::MAXIMUM_LINE_BYTES - 3, 'UTF-8')
            : substr($message, 0, self::MAXIMUM_LINE_BYTES - 3);

        return $shortenedMessage . '...';
    }

    /**
     * Update Log - Duration.
     *
     * Formats the time since the run began in seconds with one decimal, or in
     * minutes and seconds for longer runs.
     *
     * @return string
     *
     * @since 1.2.0
     * @private
     */
    private function duration(): string
    {
        $elapsedSeconds = max(0.0, ($this->clock)() - $this->startedAt);

        if ($elapsedSeconds < 60.0) {
            return sprintf('%.1f s', $elapsedSeconds);
        }

        $wholeSeconds = (int) round($elapsedSeconds);

        return sprintf('%d min %02d s', intdiv($wholeSeconds, 60), $wholeSeconds % 60);
    }
}
