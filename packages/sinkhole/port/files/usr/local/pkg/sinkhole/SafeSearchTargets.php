<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use RuntimeException;
use Throwable;

require_once(__DIR__ . '/AtomicFile.php');

/**
 * SafeSearch Targets.
 *
 * Looks up each engine's safe host and keeps the last good addresses, so a failed
 * lookup never changes what clients receive. The Unbound module only reads the
 * compiled copy and never performs network I/O itself.
 *
 * @since 1.1.0
 */
final class SafeSearchTargets
{
    /** @var int @since 1.1.0 */
    public const MAXIMUM_ADDRESSES = 16;

    /** @var int @since 1.1.0 */
    private const MAXIMUM_FILE_BYTES = 65536;

    /** @var callable(string, string): list<string> */
    private $resolver;

    /**
     * SafeSearch Targets - Constructor.
     *
     * @param string $path - Targets state file.
     * @param null|callable(string, string): list<string> $resolver - ``(host, 'A'|'AAAA')`` lookup.
     *
     * @since 1.1.0
     */
    public function __construct(private readonly string $path, ?callable $resolver = null)
    {
        $this->resolver = $resolver ?? self::systemResolver(...);
    }

    /**
     * SafeSearch Targets - Read.
     *
     * @return array<string, array{ipv4: list<string>, ipv6: list<string>, checked_at: int|null, last_error: string}>
     *
     * @since 1.1.0
     */
    public function read(): array
    {
        $status = @lstat($this->path);

        if (
            !is_array($status)
            || ($status['mode'] & 0170000) !== 0100000
            || $status['size'] > self::MAXIMUM_FILE_BYTES
        ) {
            return [];
        }

        $contents = @file_get_contents($this->path);
        $decoded = is_string($contents) ? json_decode($contents, true, 8) : null;
        $targets = [];

        foreach (is_array($decoded) ? $decoded : [] as $host => $record) {
            if (!is_string($host) || self::isHost($host) === false || !is_array($record)) {
                continue;
            }

            $targets[$host] = [
                'ipv4' => self::addresses($record['ipv4'] ?? [], FILTER_FLAG_IPV4),
                'ipv6' => self::addresses($record['ipv6'] ?? [], FILTER_FLAG_IPV6),
                'checked_at' => is_int($record['checked_at'] ?? null) ? $record['checked_at'] : null,
                'last_error' => is_string($record['last_error'] ?? null)
                    ? substr($record['last_error'], 0, 512)
                    : '',
            ];
        }

        return $targets;
    }

    /**
     * SafeSearch Targets - Refresh.
     *
     * Looks up every requested host. A host with no answer keeps its previous
     * addresses and records the error. Hosts no longer requested are dropped.
     *
     * @param list<string> $hosts - Safe hosts currently in use.
     * @param int|null $now - Clock override for tests.
     *
     * @return bool Whether any address set changed.
     *
     * @since 1.1.0
     */
    public function refresh(array $hosts, ?int $now = null): bool
    {
        $now ??= time();
        $previous = $this->read();
        $next = [];
        $changed = false;

        foreach (array_values(array_unique($hosts)) as $host) {
            if (!is_string($host) || self::isHost($host) === false) {
                continue;
            }

            $record = $previous[$host] ?? [
                'ipv4' => [],
                'ipv6' => [],
                'checked_at' => null,
                'last_error' => '',
            ];

            try {
                $ipv4 = self::addresses(($this->resolver)($host, 'A'), FILTER_FLAG_IPV4);
                $ipv6 = self::addresses(($this->resolver)($host, 'AAAA'), FILTER_FLAG_IPV6);

                if ($ipv4 === [] && $ipv6 === []) {
                    throw new RuntimeException('The safe host returned no addresses.');
                }

                $changed = $changed || $ipv4 !== $record['ipv4'] || $ipv6 !== $record['ipv6'];
                $record = [
                    'ipv4' => $ipv4,
                    'ipv6' => $ipv6,
                    'checked_at' => $now,
                    'last_error' => '',
                ];
            } catch (Throwable $throwable) {
                $record['checked_at'] = $now;
                $record['last_error'] = substr(
                    str_replace(["\r", "\n"], ' ', $throwable->getMessage()),
                    0,
                    512,
                );
            }

            $next[$host] = $record;
        }

        $contents = json_encode($next, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (!is_string($contents)) {
            throw new RuntimeException('Unable to encode the SafeSearch targets.');
        }

        AtomicFile::write($this->path, $contents . PHP_EOL, 0644);

        return $changed;
    }

    /**
     * SafeSearch Targets - System Resolver.
     *
     * @param string $host - Safe host.
     * @param string $type - ``A`` or ``AAAA``.
     *
     * @return list<string>
     *
     * @since 1.1.0
     * @private
     */
    private static function systemResolver(string $host, string $type): array
    {
        $records = @dns_get_record($host, ($type === 'AAAA') ? DNS_AAAA : DNS_A);

        if (!is_array($records)) {
            throw new RuntimeException('The safe host lookup failed.');
        }

        $addresses = [];

        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;

            if (is_string($address)) {
                $addresses[] = $address;
            }
        }

        return $addresses;
    }

    /**
     * SafeSearch Targets - Addresses.
     *
     * @param mixed $value - Untrusted addresses.
     * @param int $family - ``FILTER_FLAG_IPV4`` or ``FILTER_FLAG_IPV6``.
     *
     * @return list<string> Sorted, unique, canonical addresses.
     *
     * @since 1.1.0
     * @private
     */
    private static function addresses(mixed $value, int $family): array
    {
        $addresses = [];

        foreach (is_array($value) ? $value : [] as $address) {
            if (!is_string($address) || filter_var($address, FILTER_VALIDATE_IP, $family) === false) {
                continue;
            }

            $packed = inet_pton($address);

            if ($packed === false) {
                continue;
            }

            $addresses[inet_ntop($packed)] = true;
        }

        $addresses = array_keys($addresses);
        sort($addresses, SORT_STRING);

        return array_slice($addresses, 0, self::MAXIMUM_ADDRESSES);
    }

    /** @since 1.1.0 @private */
    private static function isHost(string $value): bool
    {
        return preg_match(
            '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D',
            $value,
        ) === 1;
    }
}
