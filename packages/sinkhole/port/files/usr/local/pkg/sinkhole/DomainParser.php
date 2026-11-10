<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use RuntimeException;

/**
 * Domain Parser.
 *
 * Converts untrusted hosts, plain-domain, and supported adblock lines into a compact
 * normalized stream without loading an entire downloaded list into memory.
 *
 * @since 1.0.0
 */
final class DomainParser
{
    /**
     * Domain Parser - Exact Semantic.
     *
     * Exact rows match only the normalized queried name.
     *
     * @since 1.0.0
     */
    public const EXACT = 'E';

    /**
     * Domain Parser - Subtree Semantic.
     *
     * Subtree rows match the normalized name and every descendant.
     *
     * @since 1.0.0
     */
    public const SUBTREE = 'S';

    /**
     * Domain Parser - Maximum Line Length.
     *
     * Valid DNS rows are far shorter; the cap prevents one hostile line from forcing
     * a large allocation even when the overall download remains within its limit.
     *
     * @since 1.0.0
     * @private
     */
    private const MAXIMUM_LINE_LENGTH = 8192;

    /**
     * Domain Parser - Cosmetic Separators.
     *
     * Element-hiding and scriptlet rules affect page rendering rather than DNS, so
     * treating their left side as a domain would incorrectly block the whole site.
     *
     * @since 1.0.0
     * @private
     */
    private const COSMETIC_SEPARATORS = [
        '##',
        '#@#',
        '#?#',
        '#@?#',
        '#$#',
        '#@$#',
        '#%#',
        '#@%#',
    ];

    /**
     * Domain Parser - Domain Pattern.
     *
     * One anchored expression enforces total, label, underscore, hyphen, and dotted-
     * name rules identically to the embedded Python loader.
     *
     * @since 1.0.0
     * @private
     */
    private const DOMAIN_PATTERN = '/^(?=.{1,253}$)'
        . '(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+'
        . '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/D';

    /**
     * Domain Parser - Parse File.
     *
     * Writes one "semantic-tab-domain" record per accepted name and reports accepted
     * name and ignored-line counts.
     *
     * @param string $inputPath  - Downloaded input path.
     * @param string $outputPath - Normalized output path.
     *
     * @return array{accepted: int, ignored: int}
     *
     * @throws RuntimeException When either file cannot be processed.
     *
     * @since 1.0.0
     */
    public function parseFile(string $inputPath, string $outputPath): array
    {
        $inputHandle = fopen($inputPath, 'rb');

        if ($inputHandle === false) {
            throw new RuntimeException('Unable to read the downloaded block list.');
        }

        $outputHandle = fopen($outputPath, 'wb');

        if ($outputHandle === false) {
            fclose($inputHandle);

            throw new RuntimeException('Unable to create the normalized block list.');
        }

        $accepted = 0;
        $ignored = 0;

        try {
            while (($line = fgets($inputHandle, self::MAXIMUM_LINE_LENGTH)) !== false) {
                if (!str_ends_with($line, "\n") && !feof($inputHandle)) {
                    $this->discardLineRemainder($inputHandle);
                    $ignored++;

                    continue;
                }

                $entries = $this->parseLineEntries($line);

                if (count($entries) === 0) {
                    $ignored++;

                    continue;
                }

                foreach ($entries as $entry) {
                    $record = $entry['semantic'] . "\t" . $entry['domain'] . PHP_EOL;

                    if (fwrite($outputHandle, $record) !== strlen($record)) {
                        throw new RuntimeException('Unable to write the normalized block list.');
                    }

                    $accepted++;
                }
            }

            if (!feof($inputHandle)) {
                throw new RuntimeException('Unable to finish reading the downloaded block list.');
            }

            if (fflush($outputHandle) === false) {
                throw new RuntimeException('Unable to flush the normalized block list.');
            }
        } finally {
            fclose($inputHandle);
            fclose($outputHandle);
        }

        return [
            'accepted' => $accepted,
            'ignored' => $ignored,
        ];
    }

    /**
     * Domain Parser - Parse Line.
     *
     * Auto-detects the three supported formats and rejects comments, unsupported
     * adblock syntax, addresses, placeholders, and invalid DNS names.
     *
     * @param string $line - Untrusted input line.
     *
     * @return array{domain: string, semantic: string}|null
     *
     * @since 1.0.0
     */
    public function parseLine(string $line): ?array
    {
        $entries = $this->parseLineEntries($line);

        return $entries[0] ?? null;
    }

    /**
     * Domain Parser - Parse Line Entries.
     *
     * Hosts rows may contain several names after one address. Plain rows drop a
     * trailing hash comment before the same strict dotted-name validation.
     *
     * @param string $line - Untrusted input line.
     *
     * @return list<array{domain: string, semantic: string}>
     *
     * @since 1.0.0
     */
    public function parseLineEntries(string $line): array
    {
        $line = trim($line);

        if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, '!')) {
            return [];
        }

        if (preg_match('/\s+#/', $line, $commentMatches, PREG_OFFSET_CAPTURE) === 1) {
            $commentPosition = $commentMatches[0][1];
            $line = trim(substr($line, 0, $commentPosition));
        }

        if ($line === '') {
            return [];
        }

        foreach (self::COSMETIC_SEPARATORS as $cosmeticSeparator) {
            if (str_contains($line, $cosmeticSeparator)) {
                return [];
            }
        }

        if (preg_match('/^\|\|([^\^$]+)\^(?:\$important)?$/iD', $line, $matches) === 1) {
            $domain = self::normalizeDomain($matches[1]);

            return ($domain === null) ? [] : [[
                    'domain' => $domain,
                    'semantic' => self::SUBTREE,
                ]];
        }

        $fields = preg_split('/\s+/', $line);

        if (is_array($fields) && count($fields) >= 2 && filter_var($fields[0], FILTER_VALIDATE_IP) !== false) {
            $entries = [];

            foreach (array_slice($fields, 1) as $field) {
                $domain = self::normalizeDomain($field);

                if ($domain !== null) {
                    $entries[] = [
                        'domain' => $domain,
                        'semantic' => self::EXACT,
                    ];
                }
            }

            return $entries;
        }

        if (preg_match('/\s/', $line) === 1 || strpbrk($line, '|^$*/@') !== false) {
            return [];
        }

        $domain = self::normalizeDomain($line);

        return ($domain === null) ? [] : [[
                'domain' => $domain,
                'semantic' => self::EXACT,
            ]];
    }

    /**
     * Domain Parser - Normalize Domain.
     *
     * Lowercases, removes one trailing dot, converts IDNs when available, and enforces
     * DNS label and total-name limits.
     *
     * @param string $value - Candidate domain.
     *
     * @return string|null
     *
     * @since 1.0.0
     */
    public static function normalizeDomain(string $value): ?string
    {
        $domain = strtolower(trim($value));
        $domain = rtrim($domain, '.');

        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP) !== false) {
            return null;
        }

        if (preg_match('/[^\x20-\x7e]/', $domain) === 1) {
            if (!function_exists('idn_to_ascii')) {
                return null;
            }

            $flags = defined('IDNA_DEFAULT') ? IDNA_DEFAULT : 0;

            if (defined('INTL_IDNA_VARIANT_UTS46')) {
                $converted = idn_to_ascii($domain, $flags, INTL_IDNA_VARIANT_UTS46);
            } else {
                $converted = idn_to_ascii($domain, $flags);
            }

            if (!is_string($converted)) {
                return null;
            }

            $domain = strtolower($converted);
        }

        $placeholders = [
            '0.0.0.0',
            '255.255.255.255',
            'broadcasthost',
            'ip6-allnodes',
            'ip6-allhosts',
            'ip6-allrouters',
            'ip6-localhost',
            'ip6-localnet',
            'ip6-loopback',
            'ip6-mcastprefix',
            'local',
            'localdomain',
            'localhost',
            'localhost4',
            'localhost4.localdomain4',
            'localhost6',
            'localhost6.localdomain6',
            'localhost.localdomain',
        ];

        if (in_array($domain, $placeholders, true) || preg_match('/^[0-9.]+$/D', $domain) === 1) {
            return null;
        }

        return (preg_match(self::DOMAIN_PATTERN, $domain) === 1) ? $domain : null;
    }

    /**
     * Domain Parser - Normalize Allowed Domains.
     *
     * Returns unique normalized entries and the one-based line numbers that require
     * correction before the WebGUI can save them.
     *
     * @param string $value - Textarea contents.
     *
     * @return array{domains: list<string>, invalid_lines: list<int>}
     *
     * @since 1.0.0
     */
    public static function normalizeAllowedDomains(string $value): array
    {
        $domains = [];
        $invalidLines = [];
        $lines = preg_split('/\R/', $value);

        foreach ((is_array($lines) ? $lines : []) as $index => $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            $domain = self::normalizeDomain($line);

            if ($domain === null) {
                $invalidLines[] = $index + 1;

                continue;
            }

            $domains[$domain] = true;
        }

        $normalizedDomains = array_keys($domains);

        sort($normalizedDomains, SORT_STRING);

        return [
            'domains' => $normalizedDomains,
            'invalid_lines' => $invalidLines,
        ];
    }

    /**
     * Domain Parser - Normalize Allowed Domain Values.
     *
     * Revalidates pfSense's repeated configuration elements without relying on XML
     * text-node whitespace or joining separate domains together.
     *
     * @param mixed $value - Persisted domain elements.
     *
     * @return array{domains: list<string>, invalid_positions: list<int>}
     *
     * @since 1.0.0
     */
    public static function normalizeAllowedDomainValues(mixed $value): array
    {
        if ($value === null || $value === '') {
            return [
                'domains' => [],
                'invalid_positions' => [],
            ];
        }

        if (!is_array($value)) {
            return [
                'domains' => [],
                'invalid_positions' => [1],
            ];
        }

        $domains = [];
        $invalidPositions = [];

        foreach (array_values($value) as $index => $rawDomain) {
            if (!is_string($rawDomain)) {
                $invalidPositions[] = $index + 1;

                continue;
            }

            $domain = self::normalizeDomain($rawDomain);

            if ($domain === null) {
                $invalidPositions[] = $index + 1;

                continue;
            }

            $domains[$domain] = true;
        }

        $normalizedDomains = array_keys($domains);

        sort($normalizedDomains, SORT_STRING);

        return [
            'domains' => $normalizedDomains,
            'invalid_positions' => $invalidPositions,
        ];
    }

    /**
     * Domain Parser - Parse Normalized Line.
     *
     * The compiler revalidates saved files so local corruption cannot reach the
     * Unbound module.
     *
     * @param string $line - Saved normalized line.
     *
     * @return array{domain: string, semantic: string}|null
     *
     * @since 1.0.0
     */
    public static function parseNormalizedLine(string $line): ?array
    {
        $fields = explode("\t", rtrim($line, "\r\n"));

        if (count($fields) !== 2 || !in_array($fields[0], [self::EXACT, self::SUBTREE], true)) {
            return null;
        }

        $domain = self::normalizeDomain($fields[1]);

        if ($domain === null || $domain !== $fields[1]) {
            return null;
        }

        return [
            'domain' => $domain,
            'semantic' => $fields[0],
        ];
    }

    /**
     * Domain Parser - Discard Line Remainder.
     *
     * Consumes an overlong hostile line in bounded chunks before normal parsing
     * resumes at the next line.
     *
     * @param mixed $inputHandle - Open input resource.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function discardLineRemainder(mixed $inputHandle): void
    {
        while (($chunk = fgets($inputHandle, self::MAXIMUM_LINE_LENGTH)) !== false) {
            if (str_ends_with($chunk, "\n") || feof($inputHandle)) {
                return;
            }
        }
    }
}
