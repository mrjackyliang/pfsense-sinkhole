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

                // Reject, like pfSense's Reject action: TCP gets a reset and UDP an ICMP
                // unreachable, so a blocked client falls back at once instead of timing out.
                $prefix = sprintf(
                    'block return in quick on %s %s',
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
     * Bypass Rule Configuration - Context Anchor Text.
     *
     * Every block rule selects a context client table. Broader client tables carry
     * negated entries supplied by the adapter, so pf's longest-prefix table match
     * enforces device, network, then Global precedence without pass rules.
     *
     * @param array<string, array{configuration: array, clients: array{ipv4: list<string>, ipv6: list<string>}, destinations: array{ipv4: list<string>, ipv6: list<string>}}> $contexts - Effective context rules and table entries.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function contextAnchorText(array $contexts): string
    {
        ksort($contexts, SORT_STRING);
        $lines = [self::COMMENT];
        $rules = [];

        foreach ($contexts as $context => $record) {
            if (!is_string($context) || !is_array($record)) {
                continue;
            }

            $configuration = is_array($record['configuration'] ?? null)
                ? $record['configuration']
                : [];
            $exemptions = BypassConfiguration::effectiveExemptions($configuration);
            $sources = self::splitExemptions($exemptions['sources']);
            $destinationExemptions = self::splitExemptions($exemptions['destinations']);
            $aliasCriteria = self::aliasCriteria(
                $sources['aliases'],
                $destinationExemptions['aliases'],
            );
            $usesPortRules = ($configuration['block_tls_quic'] ?? false) === true
                || ($configuration['block_vpn_ports'] ?? false) === true;
            $destinationExemptionTable = null;
            $contextLines = [];
            $contextRules = [];

            if ($usesPortRules && $destinationExemptions['literals'] !== []) {
                $destinationExemptionTable = self::contextTableName(
                    $context,
                    'both',
                    'exempt_destinations',
                );
                $contextLines[] = sprintf(
                    'table <%s> { %s }',
                    $destinationExemptionTable,
                    implode(' ', $destinationExemptions['literals']),
                );
            }

            foreach (['ipv4' => 'inet', 'ipv6' => 'inet6'] as $family => $pfFamily) {
                $rawClients = is_array($record['clients'][$family] ?? null)
                    ? $record['clients'][$family]
                    : [];

                if ($sources['literals'] !== []) {
                    $positiveClients = array_values(array_filter(
                        $rawClients,
                        static fn (mixed $entry): bool => is_string($entry)
                            && !str_starts_with($entry, '!'),
                    ));
                    $negativeClients = array_values(array_filter(
                        $rawClients,
                        static fn (mixed $entry): bool => is_string($entry)
                            && str_starts_with($entry, '!'),
                    ));
                    $rawClients = array_merge(
                        IpNetwork::subtract($positiveClients, $sources['literals']),
                        $negativeClients,
                    );
                }

                $clients = self::normalizedTableEntries(
                    $rawClients,
                    $family,
                    true,
                );
                $hasPositiveClient = count(array_filter(
                    $clients,
                    static fn (string $entry): bool => !str_starts_with($entry, '!'),
                )) > 0;

                if (!$hasPositiveClient) {
                    continue;
                }

                $clientTable = self::contextTableName($context, $family, 'clients');
                $contextLines[] = sprintf(
                    'table <%s> { %s }',
                    $clientTable,
                    implode(' ', $clients),
                );
                $prefix = sprintf(
                    'block return in quick %s',
                    $pfFamily,
                );
                $source = ' from <' . $clientTable . '>';
                $portRules = [];

                if (($configuration['block_tls_quic'] ?? false) === true) {
                    $portRules[] = $prefix
                        . ' proto { tcp udp }'
                        . $source
                        . ' to ! (self) port 853';
                }

                $usesProviders = ($configuration['block_encrypted_dns'] ?? false) === true
                    || ($configuration['block_tor'] ?? false) === true
                    || ($configuration['block_vpn'] ?? false) === true;
                $providerDestinations = self::normalizedTableEntries(
                    is_array($record['destinations'][$family] ?? null)
                        ? $record['destinations'][$family]
                        : [],
                    $family,
                    false,
                );

                if ($usesProviders && $providerDestinations !== []) {
                    $destinationTable = self::contextTableName(
                        $context,
                        $family,
                        'destinations',
                    );
                    $contextLines[] = sprintf(
                        'table <%s> { %s }',
                        $destinationTable,
                        implode(' ', $providerDestinations),
                    );
                    $providerRule = $prefix
                        . $source
                        . ' to <'
                        . $destinationTable
                        . '>';

                    if ($aliasCriteria === []) {
                        $contextRules[] = $providerRule;
                    } else {
                        $contextRules = array_merge(
                            $contextRules,
                            self::nestedRules(
                                'ctx_' . substr(hash('sha256', $context), 0, 12)
                                    . '_' . $family . '_providers',
                                array_merge(
                                    [
                                        'in '
                                            . $pfFamily
                                            . ' from <'
                                            . $clientTable
                                            . '> to <'
                                            . $destinationTable
                                            . '>',
                                    ],
                                    $aliasCriteria,
                                ),
                                ['block return in quick all'],
                            ),
                        );
                    }
                }

                if (($configuration['block_vpn_ports'] ?? false) === true) {
                    $portRules[] = $prefix
                        . ' proto { tcp udp }'
                        . $source
                        . ' to ! (self) port 1194';
                    $portRules[] = $prefix
                        . ' proto udp'
                        . $source
                        . ' to ! (self) port { 500 4500 51820 }';
                    $portRules[] = $prefix . ' proto esp' . $source . ' to ! (self)';
                }

                if ($portRules !== []) {
                    if ($aliasCriteria === [] && $destinationExemptionTable === null) {
                        $contextRules = array_merge($contextRules, $portRules);
                    } else {
                        $criteria = [
                            'in ' . $pfFamily . ' from <' . $clientTable . '>'
                                . (($destinationExemptionTable === null)
                                    ? ''
                                    : ' to ! <' . $destinationExemptionTable . '>'),
                        ];
                        $criteria = array_merge($criteria, $aliasCriteria);
                        $innerRules = array_map(
                            static function (string $rule) use ($source): string {
                                return str_replace($source, ' from any', $rule);
                            },
                            $portRules,
                        );
                        $contextRules = array_merge(
                            $contextRules,
                            self::nestedRules(
                                'ctx_' . substr(hash('sha256', $context), 0, 12)
                                    . '_' . $family . '_ports',
                                $criteria,
                                $innerRules,
                            ),
                        );
                    }
                }
            }

            if ($contextRules === []) {
                continue;
            }

            $lines = array_merge($lines, $contextLines);
            $rules = array_merge($rules, $contextRules);
        }

        return ($rules === [])
            ? ''
            : implode(PHP_EOL, array_merge($lines, $rules)) . PHP_EOL;
    }

    /**
     * Bypass Rule Configuration - Context Table Name.
     *
     * @param string $context - Context key.
     * @param string $family - ipv4, ipv6, or both.
     * @param string $purpose - Table purpose.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function contextTableName(
        string $context,
        string $family,
        string $purpose = 'clients',
    ): string {
        $purposeCodes = [
            'clients' => 'c',
            'destinations' => 'd',
            'exempt_sources' => 's',
            'exempt_destinations' => 'e',
        ];
        $familyCodes = ['ipv4' => '4', 'ipv6' => '6', 'both' => 'x'];

        if (
            ($context !== 'global'
                && preg_match('/^(?:network|device):[a-f0-9]{32}$/D', $context) !== 1)
            || !isset($purposeCodes[$purpose])
            || !isset($familyCodes[$family])
        ) {
            throw new InvalidArgumentException('The Bypass context table is invalid.');
        }

        return 'sh_b' . $purposeCodes[$purpose]
            . '_'
            . substr(hash('sha256', $context), 0, 12)
            . '_'
            . $familyCodes[$family];
    }

    /**
     * Bypass Rule Configuration - Normalized Table Entries.
     *
     * @param list<string> $entries - Literal table entries.
     * @param string $family - ipv4 or ipv6.
     * @param bool $allowNegated - Whether negated entries are accepted.
     *
     * @return list<string>
     *
     * @since 1.3.0
     * @private
     */
    private static function normalizedTableEntries(
        array $entries,
        string $family,
        bool $allowNegated,
    ): array {
        $normalized = [];

        foreach ($entries as $entry) {
            if (!is_string($entry)) {
                continue;
            }

            $negated = str_starts_with($entry, '!');
            $value = $negated ? substr($entry, 1) : $entry;

            if ($negated && !$allowNegated) {
                continue;
            }

            try {
                $network = IpNetwork::normalize($value);
            } catch (InvalidArgumentException) {
                continue;
            }

            if (IpNetwork::family($network) !== $family) {
                continue;
            }

            if (!str_contains($value, '/')) {
                $network = explode('/', $network, 2)[0];
            }

            $normalized[($negated ? '!' : '') . $network] = true;
        }

        $values = array_keys($normalized);
        usort(
            $values,
            static function (string $first, string $second): int {
                $negation = (int) str_starts_with($first, '!')
                    <=> (int) str_starts_with($second, '!');

                return ($negation !== 0) ? $negation : strcmp($first, $second);
            },
        );

        return $values;
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
