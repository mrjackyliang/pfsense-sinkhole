<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use RuntimeException;

require_once(__DIR__ . '/IpNetwork.php');

/**
 * IP Parser.
 *
 * Streams untrusted address lists into canonical CIDRs while retaining bounded
 * accepted and skipped-line counts for update status.
 *
 * @since 1.0.0
 */
final class IpParser
{
    /** @var int @since 1.0.0 */
    private const MAXIMUM_LINE_LENGTH = 8192;

    /**
     * IP Parser - Parse File.
     *
     * @param string $inputPath - Downloaded input path.
     * @param string $outputPath - Normalized output path.
     * @param string|null $family - Optional ``ipv4`` or ``ipv6`` restriction.
     * @param int $maximumEntries - Maximum accepted entries.
     *
     * @return array{accepted: int, skipped: int, ipv4: int, ipv6: int}
     *
     * @since 1.0.0
     */
    public function parseFile(
        string $inputPath,
        string $outputPath,
        ?string $family = null,
        int $maximumEntries = IpNetwork::MAXIMUM_NETWORKS,
    ): array {
        if (!in_array($family, [null, 'ipv4', 'ipv6'], true) || $maximumEntries <= 0) {
            throw new RuntimeException('The IP list parser limit or family is invalid.');
        }

        $input = fopen($inputPath, 'rb');

        if ($input === false) {
            throw new RuntimeException('Unable to read the downloaded IP list.');
        }

        $output = fopen($outputPath, 'wb');

        if ($output === false) {
            fclose($input);

            throw new RuntimeException('Unable to create the normalized IP list.');
        }

        $accepted = 0;
        $skipped = 0;
        $families = ['ipv4' => 0, 'ipv6' => 0];

        try {
            while (($line = fgets($input, self::MAXIMUM_LINE_LENGTH)) !== false) {
                if (!str_ends_with($line, "\n") && !feof($input)) {
                    while (($remainder = fgets($input, self::MAXIMUM_LINE_LENGTH)) !== false) {
                        if (str_ends_with($remainder, "\n") || feof($input)) {
                            break;
                        }
                    }
                    $skipped++;

                    continue;
                }

                if (self::lineIsIgnorable($line)) {
                    continue;
                }

                $network = $this->parseLine($line);

                if ($network === null || ($family !== null && IpNetwork::family($network) !== $family)) {
                    $skipped++;

                    continue;
                }

                if ($accepted >= $maximumEntries) {
                    throw new RuntimeException('The IP list entry limit was exceeded.');
                }

                $record = $network . PHP_EOL;

                if (fwrite($output, $record) !== strlen($record)) {
                    throw new RuntimeException('Unable to write the normalized IP list.');
                }

                $accepted++;
                $families[IpNetwork::family($network)]++;
            }

            if (!feof($input) || fflush($output) === false) {
                throw new RuntimeException('Unable to finish normalizing the IP list.');
            }
        } finally {
            fclose($input);
            fclose($output);
        }

        return [
            'accepted' => $accepted,
            'skipped' => $skipped,
            'ipv4' => $families['ipv4'],
            'ipv6' => $families['ipv6'],
        ];
    }

    /**
     * IP Parser - Parse Line.
     *
     * Returns null for both ignorable input and rejected candidate entries; file
     * parsing separates those cases before updating its skipped-line count.
     *
     * @param string $line - Untrusted list line.
     *
     * @return string|null
     *
     * @since 1.0.0
     */
    public function parseLine(string $line): ?string
    {
        if (self::lineIsIgnorable($line)) {
            return null;
        }

        $line = trim($line);
        $fields = preg_split('/\s+/', $line, 2);
        $candidate = is_array($fields) ? $fields[0] : $line;

        try {
            $network = IpNetwork::normalize($candidate);

            return IpNetwork::meetsBlockingPrefixMinimum($network)
                ? $network
                : null;
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * IP Parser - Line Is Ignorable.
     *
     * Blank and comment-only input stays outside accepted and skipped counts so
     * status reflects only candidate entries that the parser could not use.
     *
     * @param string $line - Untrusted list line.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function lineIsIgnorable(string $line): bool
    {
        $line = trim($line);

        return $line === '' || str_starts_with($line, '#') || str_starts_with($line, ';');
    }
}
