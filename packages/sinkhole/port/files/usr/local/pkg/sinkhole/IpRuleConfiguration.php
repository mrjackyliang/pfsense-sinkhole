<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use InvalidArgumentException;

require_once(__DIR__ . '/IpConfiguration.php');

/**
 * IP Rule Configuration.
 *
 * Renders the fixed pf anchor reference, tables, and selected directional block
 * rules from validated platform values.
 *
 * @since 1.0.0
 */
final class IpRuleConfiguration
{
    /** @var string @since 1.0.0 */
    public const ANCHOR = 'sinkhole/ip';

    /** @var string @since 1.0.0 */
    public const TABLE_IPV4 = 'sinkhole_block_v4';

    /** @var string @since 1.0.0 */
    public const TABLE_IPV6 = 'sinkhole_block_v6';

    /** @var string @since 1.0.0 */
    public const COMMENT = '# Sinkhole IP blocking';

    /**
     * IP Rule Configuration - Reference Text.
     *
     * The package hook inserts only this anchor reference into pfSense's early
     * rules so Sinkhole can manage the anchor contents independently.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function referenceText(): string
    {
        return sprintf('anchor "%s"', self::ANCHOR) . PHP_EOL;
    }

    /**
     * IP Rule Configuration - Anchor Text.
     *
     * @param list<array{interface: string, real_interface: string, ipv4: bool, ipv6: bool}> $interfaces - Selected resolved interfaces.
     * @param list<string> $directions - ``inbound`` and/or ``outbound``.
     * @param string $ipv4File - Fixed IPv4 table file.
     * @param string $ipv6File - Fixed IPv6 table file.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function anchorText(
        array $interfaces,
        array $directions,
        string $ipv4File,
        string $ipv6File,
    ): string {
        $directions = array_values(array_unique($directions));

        foreach ($directions as $direction) {
            if (!in_array($direction, IpConfiguration::DIRECTIONS, true)) {
                throw new InvalidArgumentException('The IP block direction is invalid.');
            }
        }

        foreach ([$ipv4File, $ipv6File] as $path) {
            if (preg_match('/^\/[A-Za-z0-9._\/-]+$/D', $path) !== 1) {
                throw new InvalidArgumentException('The IP table path is invalid.');
            }
        }

        $rules = [
            self::COMMENT,
            sprintf('table <%s> persist file "%s"', self::TABLE_IPV4, $ipv4File),
            sprintf('table <%s> persist file "%s"', self::TABLE_IPV6, $ipv6File),
        ];

        foreach ($interfaces as $interface) {
            $realInterface = is_string($interface['real_interface'] ?? null)
                ? $interface['real_interface']
                : '';

            if (preg_match('/^[A-Za-z0-9_.:-]+$/D', $realInterface) !== 1) {
                throw new InvalidArgumentException('The real interface name is invalid.');
            }

            foreach ([
                'inet' => ($interface['ipv4'] ?? false) === true,
                'inet6' => ($interface['ipv6'] ?? false) === true,
            ] as $family => $available) {
                if (!$available) {
                    continue;
                }

                $table = ($family === 'inet') ? self::TABLE_IPV4 : self::TABLE_IPV6;

                if (in_array('inbound', $directions, true)) {
                    $rules[] = sprintf(
                        'block drop in quick on %s %s from <%s> to any',
                        $realInterface,
                        $family,
                        $table,
                    );
                }

                if (in_array('outbound', $directions, true)) {
                    $rules[] = sprintf(
                        'block drop in quick on %s %s from any to <%s>',
                        $realInterface,
                        $family,
                        $table,
                    );
                }
            }
        }

        return implode(PHP_EOL, $rules) . PHP_EOL;
    }
}
