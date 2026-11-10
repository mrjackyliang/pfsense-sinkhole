<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use RuntimeException;

require_once(__DIR__ . '/DomainParser.php');
require_once(__DIR__ . '/IpNetwork.php');
require_once(__DIR__ . '/IpParser.php');

/**
 * Bypass Parser.
 *
 * Streams one-entry-per-line mixed domain and IP data into a bounded typed file.
 * Downloaded contents remain untrusted and no input token becomes pf syntax.
 *
 * @since 1.0.0
 */
final class BypassParser
{
    /** @var list<string> @since 1.0.0 */
    private const SPECIAL_USE_NETWORKS = [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '224.0.0.0/4',
        '240.0.0.0/4',
        '255.255.255.255/32',
        '::/128',
        '::1/128',
        '::ffff:0:0/96',
        'fc00::/7',
        'fe80::/10',
        'ff00::/8',
    ];

    /** @var int @since 1.0.0 */
    public const MAXIMUM_ENTRIES = 2_000_000;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_LINE_LENGTH = 8192;

    /** @since 1.0.0 */
    public function __construct(private readonly IpParser $ipParser = new IpParser())
    {
    }

    /**
     * Bypass Parser - Parse File.
     *
     * @param string $inputPath - Downloaded input path.
     * @param string $outputPath - Normalized typed output path.
     * @param int $maximumEntries - Accepted-entry limit.
     *
     * @return array{accepted: int, domains: int, networks: int, skipped: int, ipv4: int, ipv6: int}
     *
     * @since 1.0.0
     */
    public function parseFile(
        string $inputPath,
        string $outputPath,
        int $maximumEntries = self::MAXIMUM_ENTRIES,
    ): array {
        if ($maximumEntries < 1 || $maximumEntries > self::MAXIMUM_ENTRIES) {
            throw new RuntimeException('The Bypass List entry limit is invalid.');
        }

        $input = fopen($inputPath, 'rb');

        if ($input === false) {
            throw new RuntimeException('Unable to read the downloaded Bypass List.');
        }

        $output = fopen($outputPath, 'wb');

        if ($output === false) {
            fclose($input);

            throw new RuntimeException('Unable to create the normalized Bypass List.');
        }

        $result = [
            'accepted' => 0,
            'domains' => 0,
            'networks' => 0,
            'skipped' => 0,
            'ipv4' => 0,
            'ipv6' => 0,
        ];

        try {
            while (($line = fgets($input, self::MAXIMUM_LINE_LENGTH)) !== false) {
                if (!str_ends_with($line, "\n") && !feof($input)) {
                    while (($remainder = fgets($input, self::MAXIMUM_LINE_LENGTH)) !== false) {
                        if (str_ends_with($remainder, "\n") || feof($input)) {
                            break;
                        }
                    }

                    $result['skipped']++;

                    continue;
                }

                $record = $this->parseLine($line);

                if ($record === null) {
                    $result['skipped']++;

                    continue;
                }

                if ($result['accepted'] >= $maximumEntries) {
                    throw new RuntimeException('The Bypass List entry limit was exceeded.');
                }

                $text = implode("\t", $record) . PHP_EOL;

                if (fwrite($output, $text) !== strlen($text)) {
                    throw new RuntimeException('Unable to write the normalized Bypass List.');
                }

                $result['accepted']++;

                if ($record[0] === 'D') {
                    $result['domains']++;
                } else {
                    $result['networks']++;
                    $result[str_contains($record[1], ':') ? 'ipv6' : 'ipv4']++;
                }
            }

            if (!feof($input) || fflush($output) === false) {
                throw new RuntimeException('Unable to finish normalizing the Bypass List.');
            }
        } finally {
            fclose($input);
            fclose($output);
        }

        return $result;
    }

    /**
     * Bypass Parser - Parse Line.
     *
     * @param string $line - Untrusted input line.
     *
     * @return array{string, string, string}|array{string, string}|null
     *
     * @since 1.0.0
     */
    public function parseLine(string $line): ?array
    {
        $comment = strpos($line, '#');

        if ($comment !== false) {
            $line = substr($line, 0, $comment);
        }

        $candidate = trim($line);

        if ($candidate === '' || preg_match('/\s/', $candidate) === 1) {
            return null;
        }

        $network = $this->ipParser->parseLine($candidate);

        if ($network !== null && self::networkIsSafe($network)) {
            return ['I', $network];
        }

        if ($network !== null) {
            return null;
        }

        $domain = DomainParser::normalizeDomain($candidate);

        if ($domain === null) {
            return null;
        }

        return ['D', DomainParser::SUBTREE, $domain];
    }

    /**
     * Bypass Parser - Network Is Safe.
     *
     * Bypass address lists are intentionally narrower than IP block lists. Broad
     * or special-use entries could otherwise disconnect clients from local and
     * firewall-hosted services.
     *
     * @param string $network - Canonical candidate network.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function networkIsSafe(string $network): bool
    {
        $family = IpNetwork::family($network);

        if (IpNetwork::meetsBlockingPrefixMinimum($network) === false) {
            return false;
        }

        foreach (self::SPECIAL_USE_NETWORKS as $specialUseNetwork) {
            if (IpNetwork::family($specialUseNetwork) !== $family) {
                continue;
            }

            if (
                IpNetwork::contains($network, $specialUseNetwork)
                || IpNetwork::contains($specialUseNetwork, $network)
            ) {
                return false;
            }
        }

        return true;
    }
}
