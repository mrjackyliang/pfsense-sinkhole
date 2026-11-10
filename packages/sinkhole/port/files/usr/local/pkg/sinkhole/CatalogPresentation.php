<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Web;

use PfSense\Sinkhole\Domain\Catalog;

require_once(__DIR__ . '/Catalog.php');

/**
 * Catalog Presentation.
 *
 * Escapes every downloaded value at the final HTML boundary while preserving the
 * normalized entry for domain and persistence work.
 *
 * @since 1.0.0
 */
final class CatalogPresentation
{
    /**
     * Catalog Presentation - Entry.
     *
     * @param array $entry - Normalized catalog search result.
     *
     * @return array{
     *     name: string,
     *     description: string,
     *     homepage: string,
     *     url: string,
     *     source: string,
     *     contents: string,
     *     family: string,
     *     kind: string,
     *     category: string,
     *     maintainer: string,
     *     identifier: string,
     *     added: bool
     * }
     *
     * @since 1.0.0
     */
    public static function entry(array $entry): array
    {
        return [
            'name' => self::escape(self::stringValue($entry, 'name')),
            'description' => self::escape(self::stringValue($entry, 'description')),
            'homepage' => self::escape(self::stringValue($entry, 'homepage')),
            'url' => self::escape(self::stringValue($entry, 'url')),
            'source' => self::escape(self::stringValue($entry, 'source')),
            'contents' => self::escape(self::stringValue($entry, 'contents')),
            'family' => self::escape(self::stringValue($entry, 'family')),
            'kind' => self::escape(self::stringValue($entry, 'kind')),
            'category' => self::escape(self::stringValue($entry, 'category')),
            'maintainer' => self::escape(self::stringValue($entry, 'maintainer')),
            'identifier' => self::escape(Catalog::entryIdentifier($entry)),
            'added' => ($entry['added'] ?? false) === true,
        ];
    }

    /**
     * Catalog Presentation - Escape.
     *
     * @param string $value - Untrusted display text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function escape(string $value): string
    {
        return htmlspecialchars(
            $value,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8',
        );
    }

    /**
     * Catalog Presentation - String Value.
     *
     * @param array  $entry - Catalog entry.
     * @param string $key   - Expected string key.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function stringValue(array $entry, string $key): string
    {
        return is_string($entry[$key] ?? null) ? $entry[$key] : '';
    }
}
