<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

/**
 * Bypass Rule Configuration.
 *
 * Renders the independent pf anchor that contains only interface-scoped bypass
 * protections. Port rules exclude this firewall directly; table inputs have its
 * protected addresses subtracted before this rule text is loaded.
 *
 * @since 1.0.0
 */
final class BypassRuleConfiguration
{
    /** @var string @since 1.0.0 */
    public const ANCHOR = 'sinkhole/bypass';

    /** @var string @since 1.0.0 */
    public const TABLE_IPV4 = 'sinkhole_bypass_v4';

    /** @var string @since 1.0.0 */
    public const TABLE_IPV6 = 'sinkhole_bypass_v6';

    /** @var string @since 1.0.0 */
    public const COMMENT = '# Sinkhole bypass protection';

    /**
     * Bypass Rule Configuration - Reference Text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function referenceText(): string
    {
        return 'anchor "' . self::ANCHOR . '"' . PHP_EOL;
    }

    /**
     * Bypass Rule Configuration - Anchor Text.
     *
     * @param list<array{interface: string, real_interface: string, ipv4: bool, ipv6: bool}> $interfaces - Selected interface details.
     * @param array $configuration - Valid partitioned bypass configuration.
     * @param string $ipv4File - Fixed IPv4 table file.
     * @param string $ipv6File - Fixed IPv6 table file.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function anchorText(
        array $interfaces,
        array $configuration,
        string $ipv4File,
        string $ipv6File,
    ): string {
        $usesProviderTables = ($configuration['block_encrypted_dns'] ?? false) === true
            || ($configuration['block_tor'] ?? false) === true
            || ($configuration['block_vpn'] ?? false) === true;
        $lines = [self::COMMENT];

        if ($usesProviderTables) {
            $lines[] = sprintf('table <%s> persist file "%s"', self::TABLE_IPV4, $ipv4File);
            $lines[] = sprintf('table <%s> persist file "%s"', self::TABLE_IPV6, $ipv6File);
        }

        foreach ($interfaces as $interface) {
            if (!is_array($interface)) {
                continue;
            }

            $realInterface = (string) ($interface['real_interface'] ?? '');

            if ($realInterface === '') {
                continue;
            }

            foreach ([
                ['family' => 'inet', 'available' => ($interface['ipv4'] ?? false) === true],
                ['family' => 'inet6', 'available' => ($interface['ipv6'] ?? false) === true],
            ] as $family) {
                if ($family['available'] === false) {
                    continue;
                }

                $prefix = sprintf(
                    'block drop in quick on %s %s',
                    $realInterface,
                    $family['family'],
                );

                if (($configuration['block_tls_quic'] ?? false) === true) {
                    $lines[] = $prefix
                        . ' proto { tcp udp } from any to ! (self) port 853';
                }

                if ($usesProviderTables) {
                    $table = ($family['family'] === 'inet')
                        ? self::TABLE_IPV4
                        : self::TABLE_IPV6;
                    $lines[] = $prefix
                        . ' from any to <'
                        . $table
                        . '>';
                }

                if (($configuration['block_vpn_ports'] ?? false) === true) {
                    $lines[] = $prefix
                        . ' proto { tcp udp } from any to ! (self) port 1194';
                    $lines[] = $prefix
                        . ' proto udp from any to ! (self) port { 500 4500 51820 }';
                    $lines[] = $prefix
                        . ' proto esp from any to ! (self)';
                }
            }
        }

        $ruleCount = count(array_filter(
            $lines,
            static fn (string $line): bool => str_starts_with($line, 'block '),
        ));

        return ($ruleCount === 0) ? '' : implode(PHP_EOL, $lines) . PHP_EOL;
    }
}
