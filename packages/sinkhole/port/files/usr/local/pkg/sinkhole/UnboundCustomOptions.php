<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

/**
 * Unbound Custom Options.
 *
 * Reconciles Sinkhole's managed Resolver directives without interpreting or
 * normalizing any administrator-owned custom-option bytes.
 *
 * @since 1.0.0
 */
final class UnboundCustomOptions
{
    /** @var string @since 1.0.0 */
    public const BEGIN_MARKER = '# Sinkhole: begin (managed by the Sinkhole package)';

    /** @var string @since 1.0.0 */
    public const SERVER_LINE = 'server:';

    /** @var string @since 1.0.0 */
    public const DISCOVERY_ZONE_LINE = 'local-zone: "_dns.resolver.arpa." transparent';

    /** @var string @since 1.0.0 */
    public const END_MARKER = '# Sinkhole: end';

    /**
     * Unbound Custom Options - Reconcile Discovery Zone.
     *
     * Removes every complete or repairable managed block, then appends one
     * canonical block only when Discovery needs the transparent local zone.
     *
     * @param string $customOptions - Decoded DNS Resolver custom options.
     * @param bool $wanted - Whether the managed Discovery zone is wanted.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function reconcileDiscoveryZone(
        string $customOptions,
        bool $wanted,
    ): string {
        $customOptions = self::removeManagedBlocks($customOptions);

        if ($wanted === false) {
            return $customOptions;
        }

        $lineEnding = self::lineEnding($customOptions);
        $block = implode($lineEnding, [
            self::BEGIN_MARKER,
            self::SERVER_LINE,
            self::DISCOVERY_ZONE_LINE,
            self::END_MARKER,
        ]);

        if ($customOptions === '') {
            return $block;
        }

        return $customOptions . $lineEnding . $block;
    }

    /**
     * Unbound Custom Options - Has Discovery Zone.
     *
     * Reports the exact directive independently of the surrounding markers so a
     * damaged or manually edited block remains visible on the Status page.
     *
     * @param string $customOptions - Decoded DNS Resolver custom options.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function hasDiscoveryZone(string $customOptions): bool
    {
        foreach (self::lines($customOptions) as $line) {
            if ($line['content'] === self::DISCOVERY_ZONE_LINE) {
                return true;
            }
        }

        return false;
    }

    /**
     * Unbound Custom Options - Remove Managed Blocks.
     *
     * A missing end marker removes only the begin marker and contiguous known
     * Sinkhole lines. Unknown following lines always remain administrator-owned.
     *
     * @param string $customOptions - Decoded DNS Resolver custom options.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function removeManagedBlocks(string $customOptions): string
    {
        while (true) {
            $lines = self::lines($customOptions);
            $beginIndex = null;

            foreach ($lines as $index => $line) {
                if ($line['content'] === self::BEGIN_MARKER) {
                    $beginIndex = $index;
                    break;
                }
            }

            if ($beginIndex === null) {
                return $customOptions;
            }

            $lastIndex = $beginIndex;
            $endIndex = null;

            for ($index = $beginIndex + 1; $index < count($lines); $index++) {
                if ($lines[$index]['content'] === self::END_MARKER) {
                    $endIndex = $index;
                    break;
                }
            }

            if ($endIndex !== null) {
                $lastIndex = $endIndex;
            } else {
                for ($index = $beginIndex + 1; $index < count($lines); $index++) {
                    if (
                        $lines[$index]['content'] !== self::SERVER_LINE
                        && $lines[$index]['content'] !== self::DISCOVERY_ZONE_LINE
                    ) {
                        break;
                    }

                    $lastIndex = $index;
                }
            }

            $start = $lines[$beginIndex]['start'];

            if ($start >= 2 && substr($customOptions, $start - 2, 2) === "\r\n") {
                $start -= 2;
            } elseif (
                $start >= 1
                && in_array($customOptions[$start - 1], ["\r", "\n"], true)
            ) {
                $start--;
            }

            $lastLine = $lines[$lastIndex];
            $end = $lastLine['content_end'];
            $hasPrefix = $start > 0;
            $hasSuffix = $lastLine['end'] < strlen($customOptions);

            if ($hasPrefix === false || $hasSuffix === false) {
                $end = $lastLine['end'];
            }

            $customOptions = substr($customOptions, 0, $start)
                . substr($customOptions, $end);
        }
    }

    /**
     * Unbound Custom Options - Lines.
     *
     * @param string $value - Arbitrary byte-preserved text.
     *
     * @return list<array{content: string, start: int, content_end: int, end: int}>
     *
     * @since 1.0.0
     * @private
     */
    private static function lines(string $value): array
    {
        $lines = [];
        $length = strlen($value);
        $offset = 0;

        while ($offset < $length) {
            $matched = preg_match(
                '/\r\n|\r|\n/',
                $value,
                $matches,
                PREG_OFFSET_CAPTURE,
                $offset,
            );

            if ($matched !== 1) {
                $lines[] = [
                    'content' => substr($value, $offset),
                    'start' => $offset,
                    'content_end' => $length,
                    'end' => $length,
                ];
                break;
            }

            $lineEnding = $matches[0][0];
            $contentEnd = $matches[0][1];
            $end = $contentEnd + strlen($lineEnding);
            $lines[] = [
                'content' => substr($value, $offset, $contentEnd - $offset),
                'start' => $offset,
                'content_end' => $contentEnd,
                'end' => $end,
            ];
            $offset = $end;
        }

        return $lines;
    }

    /**
     * Unbound Custom Options - Line Ending.
     *
     * @param string $value - Existing administrator-owned text.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function lineEnding(string $value): string
    {
        if (preg_match('/\r\n|\r|\n/', $value, $matches) === 1) {
            return $matches[0];
        }

        return "\n";
    }
}
