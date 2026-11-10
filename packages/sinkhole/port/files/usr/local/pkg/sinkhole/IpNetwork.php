<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use InvalidArgumentException;
use RuntimeException;

/**
 * IP Network.
 *
 * Canonicalizes, merges, and subtracts IPv4 and IPv6 CIDRs without shelling
 * out or relying on integer widths that differ between pfSense platforms.
 *
 * @since 1.0.0
 */
final class IpNetwork
{
    /** @var int @since 1.0.0 */
    public const MINIMUM_IPV4_BLOCK_PREFIX = 8;

    /** @var int @since 1.0.0 */
    public const MINIMUM_IPV6_BLOCK_PREFIX = 16;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_NETWORKS = 2000000;

    /**
     * IP Network - Normalize.
     *
     * Addresses become host CIDRs and networks are masked to their canonical
     * boundary before they reach saved copies, tables, or comparisons.
     *
     * @param string $value - Address or CIDR value.
     *
     * @return string
     *
     * @throws InvalidArgumentException When the value is not an IP network.
     *
     * @since 1.0.0
     */
    public static function normalize(string $value): string
    {
        $value = trim($value);
        $parts = explode('/', $value);

        if (count($parts) > 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException('The IP network is invalid.');
        }

        $packed = inet_pton($parts[0]);

        if (!is_string($packed)) {
            throw new InvalidArgumentException('The IP network is invalid.');
        }

        $maximumPrefix = strlen($packed) * 8;
        $prefix = $maximumPrefix;

        if (count($parts) === 2) {
            if ($parts[1] === '' || ctype_digit($parts[1]) === false) {
                throw new InvalidArgumentException('The IP network prefix is invalid.');
            }

            $prefix = (int) $parts[1];
        }

        if ($prefix < 0 || $prefix > $maximumPrefix) {
            throw new InvalidArgumentException('The IP network prefix is invalid.');
        }

        $network = self::mask($packed, $prefix);
        $address = inet_ntop($network);

        if (!is_string($address)) {
            throw new InvalidArgumentException('The IP network is invalid.');
        }

        return strtolower($address) . '/' . $prefix;
    }

    /**
     * IP Network - Family.
     *
     * The normalized address bytes decide the table family independently from
     * text formatting such as compressed IPv6 notation.
     *
     * @param string $network - Address or CIDR value.
     *
     * @return string
     *
     * @throws InvalidArgumentException When the value is not an IP network.
     *
     * @since 1.0.0
     */
    public static function family(string $network): string
    {
        $entry = self::entry($network);

        return ($entry['bytes'] === 4) ? 'ipv4' : 'ipv6';
    }

    /**
     * IP Network - Meets Blocking Prefix Minimum.
     *
     * Firewall block sources use one shared safety floor so an untrusted list
     * cannot select nearly an entire address family by mistake.
     *
     * @param string $network - Address or CIDR value.
     *
     * @return bool
     *
     * @throws InvalidArgumentException When the value is not an IP network.
     *
     * @since 1.0.0
     */
    public static function meetsBlockingPrefixMinimum(string $network): bool
    {
        $entry = self::entry($network);
        $minimumPrefix = ($entry['bytes'] === 4)
            ? self::MINIMUM_IPV4_BLOCK_PREFIX
            : self::MINIMUM_IPV6_BLOCK_PREFIX;

        return $entry['prefix'] >= $minimumPrefix;
    }

    /**
     * IP Network - Merge.
     *
     * Removes duplicates and contained networks, then repeatedly joins adjacent
     * sibling CIDRs into the smallest deterministic per-family representation.
     *
     * @param list<string> $networks - Address and CIDR values.
     * @param int $maximumNetworks - Maximum retained networks.
     *
     * @return list<string>
     *
     * @throws RuntimeException When the configured cap is exceeded.
     *
     * @since 1.0.0
     */
    public static function merge(
        array $networks,
        int $maximumNetworks = self::MAXIMUM_NETWORKS,
    ): array {
        if ($maximumNetworks <= 0) {
            throw new RuntimeException('The IP network count limit is invalid.');
        }

        $uniqueEntries = [];

        foreach ($networks as $network) {
            if (!is_string($network)) {
                throw new InvalidArgumentException('The IP network is invalid.');
            }

            $entry = self::entry($network);
            $key = $entry['bytes'] . ':' . bin2hex($entry['packed']) . '/' . $entry['prefix'];
            $uniqueEntries[$key] = $entry;

            if (count($uniqueEntries) > $maximumNetworks) {
                throw new RuntimeException('The IP network count limit was exceeded.');
            }
        }

        $entries = array_values($uniqueEntries);
        usort(
            $entries,
            static function (array $firstEntry, array $secondEntry): int {
                $familyComparison = $firstEntry['bytes'] <=> $secondEntry['bytes'];

                if ($familyComparison !== 0) {
                    return $familyComparison;
                }

                $addressComparison = strcmp($firstEntry['packed'], $secondEntry['packed']);

                if ($addressComparison !== 0) {
                    return $addressComparison;
                }

                return $firstEntry['prefix'] <=> $secondEntry['prefix'];
            },
        );

        $mergedEntries = [];

        foreach ($entries as $entry) {
            $previousIndex = count($mergedEntries) - 1;

            if (
                $previousIndex >= 0
                && self::containsEntry($mergedEntries[$previousIndex], $entry)
            ) {
                continue;
            }

            $mergedEntries[] = $entry;

            while (count($mergedEntries) >= 2) {
                $secondIndex = count($mergedEntries) - 1;
                $firstIndex = $secondIndex - 1;
                $firstEntry = $mergedEntries[$firstIndex];
                $secondEntry = $mergedEntries[$secondIndex];

                if (self::areSiblings($firstEntry, $secondEntry) === false) {
                    break;
                }

                array_pop($mergedEntries);
                array_pop($mergedEntries);

                $parentPrefix = $firstEntry['prefix'] - 1;
                $mergedEntries[] = [
                    'packed' => self::mask($firstEntry['packed'], $parentPrefix),
                    'prefix' => $parentPrefix,
                    'bytes' => $firstEntry['bytes'],
                ];
            }
        }

        return array_map(
            static fn(array $mergedEntry): string => self::format($mergedEntry),
            $mergedEntries,
        );
    }

    /**
     * IP Network - Subtract.
     *
     * Walks a compact allowlist prefix tree so a broad blocked network can be
     * split around allowed hosts or subnets without scanning every allow entry.
     *
     * @param list<string> $blockedNetworks - Blocked networks.
     * @param list<string> $allowedNetworks - Allowed networks.
     * @param int $maximumNetworks - Maximum resulting networks.
     *
     * @return list<string>
     *
     * @throws RuntimeException When subtraction exceeds the configured cap.
     *
     * @since 1.0.0
     */
    public static function subtract(
        array $blockedNetworks,
        array $allowedNetworks,
        int $maximumNetworks = self::MAXIMUM_NETWORKS,
    ): array {
        $blocked = self::merge($blockedNetworks, $maximumNetworks);
        $allowed = self::merge($allowedNetworks, $maximumNetworks);

        if (count($allowed) === 0) {
            return $blocked;
        }

        $tries = [
            4 => self::buildTrie(array_values(array_filter(
                $allowed,
                static fn(string $allowedNetwork): bool => self::family($allowedNetwork) === 'ipv4',
            ))),
            16 => self::buildTrie(array_values(array_filter(
                $allowed,
                static fn(string $allowedNetwork): bool => self::family($allowedNetwork) === 'ipv6',
            ))),
        ];
        $resultEntries = [];

        foreach ($blocked as $blockedNetwork) {
            $blockedEntry = self::entry($blockedNetwork);
            $nodes = $tries[$blockedEntry['bytes']];
            $nodeIndex = 0;
            $covered = false;

            for ($bitIndex = 0; $bitIndex < $blockedEntry['prefix']; $bitIndex++) {
                if ($nodes[$nodeIndex]['terminal']) {
                    $covered = true;

                    break;
                }

                $branch = self::bit($blockedEntry['packed'], $bitIndex);
                $nextIndex = $nodes[$nodeIndex][$branch];

                if (!is_int($nextIndex)) {
                    $nodeIndex = -1;

                    break;
                }

                $nodeIndex = $nextIndex;
            }

            if ($covered) {
                continue;
            }

            if ($nodeIndex < 0) {
                $resultEntries[] = $blockedEntry;
            } else {
                self::subtractEntry(
                    $blockedEntry,
                    $nodes,
                    $nodeIndex,
                    $resultEntries,
                    $maximumNetworks,
                );
            }

            if (count($resultEntries) > $maximumNetworks) {
                throw new RuntimeException('The IP network count limit was exceeded.');
            }
        }

        $result = array_map(
            static fn(array $resultEntry): string => self::format($resultEntry),
            $resultEntries,
        );

        return self::merge($result, $maximumNetworks);
    }

    /**
     * IP Network - Contains.
     *
     * Tests and callers use the same binary containment rule as merge and
     * allowlist subtraction.
     *
     * @param string $container - Candidate containing network.
     * @param string $contained - Candidate contained network.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function contains(string $container, string $contained): bool
    {
        return self::containsEntry(self::entry($container), self::entry($contained));
    }

    /**
     * IP Network - Entry.
     *
     * @param string $network - Address or CIDR value.
     *
     * @return array{packed: string, prefix: int, bytes: int}
     *
     * @since 1.0.0
     * @private
     */
    private static function entry(string $network): array
    {
        $normalized = self::normalize($network);
        $parts = explode('/', $normalized, 2);
        $packed = inet_pton($parts[0]);

        if (!is_string($packed)) {
            throw new InvalidArgumentException('The IP network is invalid.');
        }

        return [
            'packed' => $packed,
            'prefix' => (int) $parts[1],
            'bytes' => strlen($packed),
        ];
    }

    /**
     * IP Network - Format.
     *
     * @param array{packed: string, prefix: int, bytes: int} $entry - Binary network entry.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function format(array $entry): string
    {
        $address = inet_ntop($entry['packed']);

        if (!is_string($address)) {
            throw new RuntimeException('Unable to format an IP network.');
        }

        return strtolower($address) . '/' . $entry['prefix'];
    }

    /**
     * IP Network - Mask.
     *
     * @param string $packed - Packed IP address.
     * @param int $prefix - Prefix length.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function mask(string $packed, int $prefix): string
    {
        $masked = '';

        foreach (str_split($packed) as $index => $byte) {
            $remaining = $prefix - ($index * 8);
            $mask = ($remaining >= 8)
                ? 255
                : (($remaining <= 0) ? 0 : (255 << (8 - $remaining)) & 255);
            $masked .= chr(ord($byte) & $mask);
        }

        return $masked;
    }

    /**
     * IP Network - Contains Entry.
     *
     * @param array{packed: string, prefix: int, bytes: int} $container - Container.
     * @param array{packed: string, prefix: int, bytes: int} $contained - Contained entry.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function containsEntry(array $container, array $contained): bool
    {
        return $container['bytes'] === $contained['bytes']
            && $container['prefix'] <= $contained['prefix']
            && hash_equals(
                $container['packed'],
                self::mask($contained['packed'], $container['prefix']),
            );
    }

    /**
     * IP Network - Are Siblings.
     *
     * @param array{packed: string, prefix: int, bytes: int} $firstEntry - First entry.
     * @param array{packed: string, prefix: int, bytes: int} $secondEntry - Second entry.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function areSiblings(array $firstEntry, array $secondEntry): bool
    {
        if (
            $firstEntry['bytes'] !== $secondEntry['bytes']
            || $firstEntry['prefix'] !== $secondEntry['prefix']
            || $firstEntry['prefix'] <= 0
            || hash_equals($firstEntry['packed'], $secondEntry['packed'])
        ) {
            return false;
        }

        $parentPrefix = $firstEntry['prefix'] - 1;

        return hash_equals(
            self::mask($firstEntry['packed'], $parentPrefix),
            self::mask($secondEntry['packed'], $parentPrefix),
        );
    }

    /**
     * IP Network - Build Trie.
     *
     * @param list<string> $networks - Normalized same-family networks.
     *
     * @return list<array{terminal: bool, 0: int|null, 1: int|null}>
     *
     * @since 1.0.0
     * @private
     */
    private static function buildTrie(array $networks): array
    {
        $nodes = [[
            'terminal' => false,
            0 => null,
            1 => null,
        ]];

        foreach ($networks as $network) {
            $entry = self::entry($network);
            $nodeIndex = 0;

            for ($bitIndex = 0; $bitIndex < $entry['prefix']; $bitIndex++) {
                if ($nodes[$nodeIndex]['terminal']) {
                    break;
                }

                $branch = self::bit($entry['packed'], $bitIndex);
                $nextIndex = $nodes[$nodeIndex][$branch];

                if (!is_int($nextIndex)) {
                    $nextIndex = count($nodes);
                    $nodes[] = [
                        'terminal' => false,
                        0 => null,
                        1 => null,
                    ];
                    $nodes[$nodeIndex][$branch] = $nextIndex;
                }

                $nodeIndex = $nextIndex;
            }

            $nodes[$nodeIndex]['terminal'] = true;
            $nodes[$nodeIndex][0] = null;
            $nodes[$nodeIndex][1] = null;
        }

        return $nodes;
    }

    /**
     * IP Network - Subtract Entry.
     *
     * @param array{packed: string, prefix: int, bytes: int} $entry - Blocked entry.
     * @param list<array{terminal: bool, 0: int|null, 1: int|null}> $nodes - Allow trie.
     * @param int $nodeIndex - Current trie node.
     * @param list<array{packed: string, prefix: int, bytes: int}> $results - Results.
     * @param int $maximumNetworks - Maximum resulting networks.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private static function subtractEntry(
        array $entry,
        array $nodes,
        int $nodeIndex,
        array &$results,
        int $maximumNetworks,
    ): void {
        if ($nodes[$nodeIndex]['terminal']) {
            return;
        }

        if ($nodes[$nodeIndex][0] === null && $nodes[$nodeIndex][1] === null) {
            $results[] = $entry;

            return;
        }

        $maximumPrefix = $entry['bytes'] * 8;

        if ($entry['prefix'] >= $maximumPrefix) {
            $results[] = $entry;

            return;
        }

        $childPrefix = $entry['prefix'] + 1;

        foreach ([0, 1] as $branch) {
            $childEntry = [
                'packed' => self::withBit($entry['packed'], $entry['prefix'], $branch),
                'prefix' => $childPrefix,
                'bytes' => $entry['bytes'],
            ];
            $childNodeIndex = $nodes[$nodeIndex][$branch];

            if (is_int($childNodeIndex)) {
                self::subtractEntry(
                    $childEntry,
                    $nodes,
                    $childNodeIndex,
                    $results,
                    $maximumNetworks,
                );
            } else {
                $results[] = $childEntry;
            }

            if (count($results) > $maximumNetworks) {
                throw new RuntimeException('The IP network count limit was exceeded.');
            }
        }
    }

    /**
     * IP Network - Bit.
     *
     * @param string $packed - Packed address.
     * @param int $bitIndex - Zero-based bit index.
     *
     * @return int
     *
     * @since 1.0.0
     * @private
     */
    private static function bit(string $packed, int $bitIndex): int
    {
        $byteIndex = intdiv($bitIndex, 8);
        $shift = 7 - ($bitIndex % 8);

        return (ord($packed[$byteIndex]) >> $shift) & 1;
    }

    /**
     * IP Network - With Bit.
     *
     * @param string $packed - Packed network boundary.
     * @param int $bitIndex - Zero-based bit index.
     * @param int $bit - Bit value.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function withBit(string $packed, int $bitIndex, int $bit): string
    {
        $byteIndex = intdiv($bitIndex, 8);
        $shift = 7 - ($bitIndex % 8);
        $byte = ord($packed[$byteIndex]);
        $mask = 1 << $shift;
        $byte = ($bit === 1) ? ($byte | $mask) : ($byte & (~$mask & 255));
        $packed[$byteIndex] = chr($byte);

        return $packed;
    }
}
