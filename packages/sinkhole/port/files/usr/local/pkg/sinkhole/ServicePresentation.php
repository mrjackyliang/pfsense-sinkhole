<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Web;

use PfSense\Sinkhole\Runtime\Translator;

require_once(__DIR__ . '/Translator.php');

/**
 * Blocked Service Presentation.
 *
 * Keeps downloaded SVG bytes out of the DOM by exposing them only as a base64 data
 * URI suitable for an image source.
 *
 * @since 1.0.0
 */
final class ServicePresentation
{
    /** @var string @since 1.0.0 */
    private const GENERIC_ICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        . '<rect width="64" height="64" rx="12" fill="#%s"/>'
        . '<path d="M32 12l17 7v12c0 11-7 18-17 22C22 49 15 42 15 31V19l17-7z" fill="#fff"/>'
        . '</svg>';

    /**
     * Blocked Service Presentation - Service.
     *
     * @param array $service - Parsed service or synthesized unknown record.
     *
     * @return array{id: string, name: string, group: string, group_name: string, icon: string, unknown: bool}
     *
     * @since 1.0.0
     */
    public static function service(array $service): array
    {
        $group = self::stringValue($service, 'group');
        $icon = is_string($service['icon_svg'] ?? null) && $service['icon_svg'] !== ''
            ? $service['icon_svg']
            : sprintf(
                self::GENERIC_ICON,
                substr(hash('sha256', $group), 0, 6),
            );

        return [
            'id' => self::escape(self::stringValue($service, 'id')),
            'name' => self::escape(self::stringValue($service, 'name')),
            'group' => self::escape($group),
            'group_name' => self::escape(self::groupName($group)),
            'icon' => self::escape('data:image/svg+xml;base64,' . base64_encode($icon)),
            'unknown' => ($service['unknown'] ?? false) === true,
        ];
    }

    /**
     * Blocked Service Presentation - Group Name.
     *
     * Pages use this boundary so registry-provided labels never become display
     * text and unknown upstream identifiers still remain readable.
     *
     * @param string $identifier - Registry group identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function groupName(string $identifier): string
    {
        return Translator::serviceGroupName($identifier);
    }

    /** @since 1.0.0 */
    public static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /** @since 1.0.0 @private */
    private static function stringValue(array $value, string $key): string
    {
        return is_string($value[$key] ?? null) ? $value[$key] : '';
    }
}
