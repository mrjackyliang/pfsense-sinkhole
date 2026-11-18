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

    /** @var list<string> @since 1.3.0 */
    public const TABLE_ROLES = ['client', 'block'];

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
     * New callers pass context table descriptors. The optional legacy arguments
     * retain the pre-1.3 renderer for callers that have not moved to contexts yet.
     *
     * @param array $contexts - Context descriptors or legacy interface details.
     * @param list<string> $directions - Legacy ``inbound`` and/or ``outbound``.
     * @param string $ipv4File - Legacy fixed IPv4 table file.
     * @param string $ipv6File - Legacy fixed IPv6 table file.
     *
     * @return string
     *
     * @since 1.0.0
     * @since 1.3.0
     */
    public static function anchorText(
        array $contexts,
        array $directions = [],
        string $ipv4File = '',
        string $ipv6File = '',
    ): string {
        if ($ipv4File !== '' || $ipv6File !== '' || $directions !== []) {
            return self::legacyAnchorText(
                $contexts,
                $directions,
                $ipv4File,
                $ipv6File,
            );
        }

        $rules = [self::COMMENT];
        $seenTables = [];

        foreach ($contexts as $descriptor) {
            if (!is_array($descriptor)) {
                throw new InvalidArgumentException('The IP context descriptor is invalid.');
            }

            $context = is_string($descriptor['context'] ?? null)
                ? $descriptor['context']
                : '';
            self::contextToken($context);
            $contextDirections = array_values(array_unique(
                is_array($descriptor['directions'] ?? null)
                    ? $descriptor['directions']
                    : [],
            ));

            foreach ($contextDirections as $direction) {
                if (!in_array($direction, IpConfiguration::DIRECTIONS, true)) {
                    throw new InvalidArgumentException('The IP block direction is invalid.');
                }
            }

            $clientDigest = is_string($descriptor['client_digest'] ?? null)
                ? $descriptor['client_digest']
                : '';

            if (preg_match('/^[a-f0-9]{64}$/D', $clientDigest) !== 1) {
                throw new InvalidArgumentException('The IP context client digest is invalid.');
            }

            $tables = is_array($descriptor['tables'] ?? null)
                ? $descriptor['tables']
                : [];
            $rules[] = sprintf('# Context %s clients %s', $context, $clientDigest);

            foreach (['ipv4', 'ipv6'] as $family) {
                $familyTables = is_array($tables[$family] ?? null)
                    ? $tables[$family]
                    : [];

                foreach (self::TABLE_ROLES as $role) {
                    $name = is_string($familyTables[$role . '_table'] ?? null)
                        ? $familyTables[$role . '_table']
                        : '';
                    $file = is_string($familyTables[$role . '_file'] ?? null)
                        ? $familyTables[$role . '_file']
                        : '';
                    self::assertTableName($name);
                    self::assertTablePath($file);

                    if (isset($seenTables[$name])) {
                        throw new InvalidArgumentException('The IP context table name is duplicated.');
                    }

                    $seenTables[$name] = true;
                    $rules[] = sprintf('table <%s> persist file "%s"', $name, $file);
                }

                $pfFamily = ($family === 'ipv4') ? 'inet' : 'inet6';
                $clientTable = $familyTables['client_table'];
                $blockTable = $familyTables['block_table'];

                foreach ($contextDirections as $direction) {
                    if ($direction === 'outbound') {
                        $rules[] = sprintf(
                            'block drop in quick %s from <%s> to <%s>',
                            $pfFamily,
                            $clientTable,
                            $blockTable,
                        );
                    } else {
                        $rules[] = sprintf(
                            'block drop in quick %s from <%s> to <%s>',
                            $pfFamily,
                            $blockTable,
                            $clientTable,
                        );
                    }
                }
            }
        }

        return implode(PHP_EOL, $rules) . PHP_EOL;
    }

    /**
     * IP Rule Configuration - Context Tables.
     *
     * Derives four short stable table names and fixed sibling files from the
     * context key. Global keeps the historical block files for upgrade safety.
     *
     * @param string $context - Global, network, or device context key.
     * @param string $ipv4File - Historical IPv4 block file.
     * @param string $ipv6File - Historical IPv6 block file.
     *
     * @return array{
     *     ipv4: array{client_table: string, client_file: string, block_table: string, block_file: string},
     *     ipv6: array{client_table: string, client_file: string, block_table: string, block_file: string}
     * }
     *
     * @since 1.3.0
     */
    public static function contextTables(
        string $context,
        string $ipv4File,
        string $ipv6File,
    ): array {
        self::assertTablePath($ipv4File);
        self::assertTablePath($ipv6File);
        $token = self::contextToken($context);
        $files = [
            'ipv4' => $ipv4File,
            'ipv6' => $ipv6File,
        ];
        $suffixes = [
            'ipv4' => '4',
            'ipv6' => '6',
        ];
        $result = [];

        foreach ($files as $family => $baseFile) {
            $suffix = $suffixes[$family];
            $directory = dirname($baseFile);
            $contextPrefix = $directory . '/sinkhole-ip-' . $token;
            $result[$family] = [
                'client_table' => 'sinkhole_ip_' . $token . '_c' . $suffix,
                'client_file' => $contextPrefix . '-clients-v' . $suffix . '.txt',
                'block_table' => 'sinkhole_ip_' . $token . '_b' . $suffix,
                'block_file' => ($context === 'global')
                    ? $baseFile
                    : $contextPrefix . '-block-v' . $suffix . '.txt',
            ];
        }

        return $result;
    }

    /**
     * IP Rule Configuration - Context Token.
     *
     * Uses the first twelve SHA-256 hexadecimal characters so every derived pf
     * table remains stable and comfortably below the platform's name limit.
     *
     * @param string $context - Global, network, or device context key.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function contextToken(string $context): string
    {
        if (
            $context !== 'global'
            && preg_match('/^(?:network|device):[a-f0-9]{32}$/D', $context) !== 1
        ) {
            throw new InvalidArgumentException('The IP context key is invalid.');
        }

        return substr(hash('sha256', $context), 0, 12);
    }

    /**
     * IP Rule Configuration - Legacy Anchor Text.
     *
     * Keeps the established renderer callable during a rolling package upgrade;
     * all 1.3 runtime paths use context descriptors instead.
     *
     * @param array $interfaces - Selected resolved interfaces.
     * @param list<string> $directions - Inbound and/or outbound.
     * @param string $ipv4File - Fixed IPv4 table file.
     * @param string $ipv6File - Fixed IPv6 table file.
     *
     * @return string
     *
     * @since 1.3.0
     * @private
     */
    private static function legacyAnchorText(
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
            self::assertTablePath($path);
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

    /**
     * IP Rule Configuration - Assert Table Name.
     *
     * Accepts only names generated by the context hash contract before they are
     * interpolated into independently loaded pf rules.
     *
     * @param string $name - Candidate table name.
     *
     * @return void
     *
     * @since 1.3.0
     * @private
     */
    private static function assertTableName(string $name): void
    {
        if (preg_match('/^sinkhole_ip_[a-f0-9]{12}_[bc][46]$/D', $name) !== 1) {
            throw new InvalidArgumentException('The IP context table name is invalid.');
        }
    }

    /**
     * IP Rule Configuration - Assert Table Path.
     *
     * Restricts pf table files to absolute paths made from fixed safe characters.
     *
     * @param string $path - Candidate table path.
     *
     * @return void
     *
     * @since 1.3.0
     * @private
     */
    private static function assertTablePath(string $path): void
    {
        if (preg_match('/^\/[A-Za-z0-9._\/-]+$/D', $path) !== 1) {
            throw new InvalidArgumentException('The IP table path is invalid.');
        }
    }
}
