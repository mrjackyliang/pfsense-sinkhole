<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use InvalidArgumentException;

require_once(__DIR__ . '/BypassConfiguration.php');
require_once(__DIR__ . '/IpNetwork.php');

/**
 * Bypass Rule Configuration.
 *
 * Renders the independent pf anchor that contains only interface-scoped bypass
 * protections. Port rules exclude this firewall directly; table inputs have its
 * protected addresses and literal exempt destinations subtracted before this
 * rule text is loaded.
 *
 * Block exemptions never pass traffic. The blocks move into nested inline
 * anchors whose negated conditions must all match, so exempt traffic matches
 * no Sinkhole rule and continues to the administrator's own rules.
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

    /** @var string @since 1.2.0 */
    public const TABLE_EXEMPT_SOURCES = 'sinkhole_bypass_exempt_src';

    /** @var string @since 1.2.0 */
    public const TABLE_EXEMPT_DESTINATIONS = 'sinkhole_bypass_exempt_dst';

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
     * Without exemptions the text is the flat rule list. With exemptions, port
     * blocks sit in one nested chain and provider-table blocks in one chain per
     * family. pf resolves a table only in the anchor that references it or in
     * the main ruleset, so every Sinkhole table is referenced by a first-level
     * anchor rule here, while deeper levels reference only pfSense alias tables.
     * The anchors are not `quick`, because FreeBSD stops evaluating after any
     * matching `quick` anchor even when no rule inside it matched.
     *
     * @param list<array{interface: string, real_interface: string, ipv4: bool, ipv6: bool}> $interfaces - Selected interface details.
     * @param array $configuration - Valid partitioned bypass configuration.
     * @param string $ipv4File - Fixed IPv4 table file.
     * @param string $ipv6File - Fixed IPv6 table file.
     *
     * @return string
     *
     * @since 1.0.0
     * @since 1.2.0
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
        $flatRules = [];
        $portRules = [];
        $providerPrefixes = [
            'inet' => [],
            'inet6' => [],
        ];

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
                    $tlsRule = $prefix
                        . ' proto { tcp udp } from any to ! (self) port 853';
                    $flatRules[] = $tlsRule;
                    $portRules[] = $tlsRule;
                }

                if ($usesProviderTables) {
                    $table = ($family['family'] === 'inet')
                        ? self::TABLE_IPV4
                        : self::TABLE_IPV6;
                    $flatRules[] = $prefix
                        . ' from any to <'
                        . $table
                        . '>';
                    $providerPrefixes[$family['family']][] = $prefix;
                }

                if (($configuration['block_vpn_ports'] ?? false) === true) {
                    $vpnRules = [
                        $prefix . ' proto { tcp udp } from any to ! (self) port 1194',
                        $prefix . ' proto udp from any to ! (self) port { 500 4500 51820 }',
                        $prefix . ' proto esp from any to ! (self)',
                    ];
                    $flatRules = array_merge($flatRules, $vpnRules);
                    $portRules = array_merge($portRules, $vpnRules);
                }
            }
        }

        if (count($flatRules) === 0) {
            return '';
        }

        $exemptions = BypassConfiguration::effectiveExemptions($configuration);
        $sources = self::splitExemptions($exemptions['sources']);
        $destinations = self::splitExemptions($exemptions['destinations']);
        $aliasCriteria = self::aliasCriteria($sources['aliases'], $destinations['aliases']);

        if (
            $sources['literals'] === []
            && $destinations['literals'] === []
            && $aliasCriteria === []
        ) {
            return implode(PHP_EOL, array_merge($lines, $flatRules)) . PHP_EOL;
        }

        $sourceTableCriteria = '';
        $destinationTableCriteria = '';

        if ($sources['literals'] !== []) {
            $lines[] = sprintf(
                'table <%s> { %s }',
                self::TABLE_EXEMPT_SOURCES,
                implode(' ', $sources['literals']),
            );
            $sourceTableCriteria = 'from ! <' . self::TABLE_EXEMPT_SOURCES . '>';
        }

        if ($destinations['literals'] !== []) {
            $lines[] = sprintf(
                'table <%s> { %s }',
                self::TABLE_EXEMPT_DESTINATIONS,
                implode(' ', $destinations['literals']),
            );
            $destinationTableCriteria = 'to ! <' . self::TABLE_EXEMPT_DESTINATIONS . '>';
        }

        if ($portRules !== []) {
            $portCriteria = $aliasCriteria;
            $portTableCriteria = trim($sourceTableCriteria . ' ' . $destinationTableCriteria);

            if ($portTableCriteria !== '') {
                array_unshift($portCriteria, 'in ' . $portTableCriteria);
            }

            $lines = array_merge(
                $lines,
                self::nestedRules('ports', $portCriteria, $portRules),
            );
        }

        foreach ([
            'inet' => self::TABLE_IPV4,
            'inet6' => self::TABLE_IPV6,
        ] as $family => $table) {
            if ($providerPrefixes[$family] === []) {
                continue;
            }

            if ($sourceTableCriteria === '' && $aliasCriteria === []) {
                foreach ($providerPrefixes[$family] as $providerPrefix) {
                    $lines[] = $providerPrefix . ' from any to <' . $table . '>';
                }

                continue;
            }

            $providerRules = array_map(
                static fn (string $providerPrefix): string => $providerPrefix . ' all',
                $providerPrefixes[$family],
            );
            $providerSourceCriteria = ($sourceTableCriteria === '')
                ? 'from any'
                : $sourceTableCriteria;
            $providerCriteria = $aliasCriteria;
            array_unshift(
                $providerCriteria,
                'in ' . $family . ' ' . $providerSourceCriteria . ' to <' . $table . '>',
            );
            $lines = array_merge(
                $lines,
                self::nestedRules('providers_' . $family, $providerCriteria, $providerRules),
            );
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    /**
     * Bypass Rule Configuration - Split Exemptions.
     *
     * Separates validated literal addresses and networks from alias names and
     * drops any token that is neither, so a malformed value can only remove an
     * exemption, never reach pf text. Networks are masked to their boundary
     * because pf rejects table entries with host bits set.
     *
     * @param list<string> $exemptions - Normalized exemption values.
     *
     * @return array{literals: list<string>, aliases: list<string>}
     *
     * @since 1.2.0
     */
    public static function splitExemptions(array $exemptions): array
    {
        $literals = [];
        $aliases = [];

        foreach ($exemptions as $exemption) {
            if (!is_string($exemption)) {
                continue;
            }

            if (self::isNetwork($exemption)) {
                $literal = (str_contains($exemption, '/'))
                    ? IpNetwork::normalize($exemption)
                    : $exemption;
                $literals[$literal] = true;

                continue;
            }

            if (
                preg_match('/^[A-Za-z0-9_]{1,31}$/D', $exemption) === 1
                && preg_match('/^(?:[0-9]+|_+)$/D', $exemption) !== 1
            ) {
                $aliases[$exemption] = true;
            }
        }

        return [
            'literals' => array_keys($literals),
            'aliases' => array_keys($aliases),
        ];
    }

    /**
     * Bypass Rule Configuration - Alias Criteria.
     *
     * One nesting level holds at most one source alias and one destination
     * alias, because a negated pf table matches only when the address is absent
     * from that one table.
     *
     * @param list<string> $sourceAliases - Exempt source alias names.
     * @param list<string> $destinationAliases - Exempt destination alias names.
     *
     * @return list<string>
     *
     * @since 1.2.0
     * @private
     */
    private static function aliasCriteria(array $sourceAliases, array $destinationAliases): array
    {
        $criteria = [];
        $levelCount = max(count($sourceAliases), count($destinationAliases));

        for ($level = 0; $level < $levelCount; $level++) {
            $parts = ['in'];

            if (isset($sourceAliases[$level])) {
                $parts[] = 'from ! <' . $sourceAliases[$level] . '>';
            }

            if (isset($destinationAliases[$level])) {
                $parts[] = 'to ! <' . $destinationAliases[$level] . '>';
            }

            $criteria[] = implode(' ', $parts);
        }

        return $criteria;
    }

    /**
     * Bypass Rule Configuration - Nested Rules.
     *
     * pfctl requires a newline after each opening brace and after each closing
     * brace, so every anchor line and rule stays on its own line.
     *
     * @param string $name - First-level inline anchor name.
     * @param list<string> $criteria - Match criteria for each nesting level.
     * @param list<string> $rules - Block rules for the innermost level.
     *
     * @return list<string>
     *
     * @since 1.2.0
     * @private
     */
    private static function nestedRules(string $name, array $criteria, array $rules): array
    {
        $lines = [];

        foreach (array_values($criteria) as $level => $levelCriteria) {
            $anchorName = ($level === 0) ? $name : 'aliases_' . $level;
            $lines[] = str_repeat('    ', $level)
                . 'anchor "'
                . $anchorName
                . '" '
                . $levelCriteria
                . ' {';
        }

        $ruleIndent = str_repeat('    ', count($criteria));

        foreach ($rules as $rule) {
            $lines[] = $ruleIndent . $rule;
        }

        for ($level = count($criteria) - 1; $level >= 0; $level--) {
            $lines[] = str_repeat('    ', $level) . '}';
        }

        return $lines;
    }

    /**
     * Bypass Rule Configuration - Is Network.
     *
     * @param string $value - Exemption value.
     *
     * @return bool
     *
     * @since 1.2.0
     * @private
     */
    private static function isNetwork(string $value): bool
    {
        try {
            IpNetwork::normalize($value);
        } catch (InvalidArgumentException) {
            return false;
        }

        return true;
    }
}
