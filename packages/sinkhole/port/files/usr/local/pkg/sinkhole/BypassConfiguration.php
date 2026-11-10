<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

require_once(__DIR__ . '/ListConfiguration.php');
require_once(__DIR__ . '/ValidationException.php');

/**
 * Bypass Configuration.
 *
 * Keeps every bypass protection independently opt-in and partitions malformed saved
 * rows so upgrades never turn a protection on while repair data remains visible.
 *
 * @since 1.0.0
 */
final class BypassConfiguration
{
    /** @var string @since 1.0.0 */
    public const KIND_ENCRYPTED_DNS = 'encrypted_dns';

    /** @var string @since 1.0.0 */
    public const KIND_TOR = 'tor';

    /** @var string @since 1.0.0 */
    public const KIND_VPN = 'vpn';

    /** @var list<string> @since 1.0.0 */
    public const KINDS = [self::KIND_ENCRYPTED_DNS, self::KIND_TOR, self::KIND_VPN];

    /** @var string @since 1.0.0 */
    public const DISCOVERY_OFF = 'off';

    /** @var string @since 1.0.0 */
    public const DISCOVERY_ADVERTISE = 'advertise';

    /** @var string @since 1.0.0 */
    public const DISCOVERY_NODATA = 'nodata';

    /** @var list<string> @since 1.0.0 */
    public const DISCOVERY_MODES = [
        self::DISCOVERY_OFF,
        self::DISCOVERY_ADVERTISE,
        self::DISCOVERY_NODATA,
    ];

    /** @var list<string> @since 1.0.0 */
    public const BOOLEAN_FIELDS = [
        'block_tls_quic',
        'block_encrypted_dns',
        'disable_firefox_doh',
        'disable_private_relay',
        'block_tor',
        'block_vpn',
        'block_vpn_ports',
    ];

    /**
     * Bypass Configuration - Partition.
     *
     * @param mixed $value - Persisted bypass settings.
     * @param list<string> $interfaces - Valid shared redirect interfaces.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public static function partition(mixed $value, array $interfaces = []): array
    {
        $result = [
            'block_tls_quic' => false,
            'block_encrypted_dns' => false,
            'disable_firefox_doh' => false,
            'disable_private_relay' => false,
            'discovery' => self::DISCOVERY_OFF,
            'block_tor' => false,
            'block_vpn' => false,
            'block_vpn_ports' => false,
            'lists' => [],
            'invalid_values' => [],
            'invalid_lists' => [],
            'interfaces' => array_values($interfaces),
            'enabled' => false,
            'dns_enabled' => false,
            'firewall_enabled' => false,
        ];

        if ($value === null || $value === '' || $value === []) {
            return $result;
        }

        if (!is_array($value)) {
            $result['invalid_values'][] = self::invalidValue(
                'bypass_settings',
                $value,
                new ValidationException('saved_bypass_settings_invalid'),
            );

            return $result;
        }

        foreach (self::BOOLEAN_FIELDS as $field) {
            $stored = $value[$field] ?? '';

            if ($stored === 'on' || $stored === true) {
                $result[$field] = true;
            } elseif (!in_array($stored, ['', false, null], true)) {
                $result['invalid_values'][] = self::invalidValue(
                    $field,
                    $stored,
                    new ValidationException('bypass_boolean_value_invalid'),
                );
            }
        }

        $discovery = $value['discovery'] ?? self::DISCOVERY_OFF;

        if (is_string($discovery) && in_array($discovery, self::DISCOVERY_MODES, true)) {
            $result['discovery'] = $discovery;
        } else {
            $result['invalid_values'][] = self::invalidValue(
                'discovery',
                $discovery,
                new ValidationException('bypass_discovery_value_invalid'),
            );
        }

        $listValue = $value['lists'] ?? [];

        if (is_array($listValue) && count($listValue) === 1 && array_key_exists('item', $listValue)) {
            $listValue = $listValue['item'];
        }

        $listPartition = self::partitionLists($listValue);
        $result['lists'] = $listPartition['lists'];
        $result['invalid_lists'] = $listPartition['invalid_rows'];
        $result['dns_enabled'] = self::dnsEnabled($result);
        $result['firewall_enabled'] = self::firewallEnabled($result);
        $result['enabled'] = $result['dns_enabled'] || $result['firewall_enabled'];

        if ($result['enabled'] && $interfaces === []) {
            $result['invalid_values'][] = self::invalidValue(
                'interfaces',
                '',
                new ValidationException('bypass_interface_required'),
            );
        }

        return $result;
    }

    /**
     * Bypass Configuration - Partition Lists.
     *
     * @param mixed $value - Persisted Bypass List rows.
     *
     * @return array{lists: array<string, array>, invalid_rows: list<array>}
     *
     * @since 1.0.0
     */
    public static function partitionLists(mixed $value): array
    {
        if ($value === null || $value === '' || $value === []) {
            return ['lists' => [], 'invalid_rows' => []];
        }

        if (!is_array($value)) {
            return [
                'lists' => [],
                'invalid_rows' => [self::invalidList(0, $value, 'saved_bypass_lists_invalid')],
            ];
        }

        $lists = [];
        $invalidRows = [];
        $position = 0;

        foreach ($value as $storageKey => $row) {
            try {
                if (!is_array($row)) {
                    throw new ValidationException('saved_bypass_list_invalid');
                }

                $identifier = is_string($row['id'] ?? null) ? $row['id'] : '';
                $kind = is_string($row['kind'] ?? null) ? $row['kind'] : '';

                if (is_string($storageKey) && $storageKey !== $identifier) {
                    throw new ValidationException('saved_bypass_list_identifier_changed');
                }

                if (isset($lists[$identifier])) {
                    throw new ValidationException('saved_bypass_list_identifier_duplicated');
                }

                $list = self::normalizeListRow(
                    $identifier,
                    is_string($row['descr'] ?? null) ? $row['descr'] : '',
                    is_string($row['url'] ?? null) ? $row['url'] : '',
                    ($row['enabled'] ?? '') === 'on' || ($row['enabled'] ?? null) === true,
                    $kind,
                );
                $lists[$identifier] = $list;
            } catch (ValidationException $exception) {
                $invalidRows[] = self::invalidList(
                    $position,
                    $row,
                    $exception->messageKey(),
                    $exception->messageArguments(),
                );
            }

            $position++;
        }

        return ['lists' => $lists, 'invalid_rows' => $invalidRows];
    }

    /**
     * Bypass Configuration - Normalize List Row.
     *
     * Manual and catalog additions share one validation boundary so a catalog
     * result cannot bypass the editor's URL, name, identifier, or kind rules.
     *
     * @param string $identifier - Stable list identifier.
     * @param string $name       - Local display name.
     * @param string $url        - HTTP or HTTPS source URL.
     * @param bool   $enabled    - Whether scheduled updates include the row.
     * @param string $kind       - Fixed Bypass List kind.
     *
     * @return array{id: string, name: string, url: string, enabled: bool, kind: string}
     *
     * @throws ValidationException When any list field is invalid.
     *
     * @since 1.0.0
     */
    public static function normalizeListRow(
        string $identifier,
        string $name,
        string $url,
        bool $enabled,
        string $kind,
    ): array {
        if (!in_array($kind, self::KINDS, true)) {
            throw new ValidationException('bypass_list_kind_invalid');
        }

        $list = ListConfiguration::normalizeRow(
            $identifier,
            $name,
            $url,
            $enabled,
        );
        unset($list['global']);
        $list['kind'] = $kind;

        return $list;
    }

    /**
     * Bypass Configuration - DNS Enabled.
     *
     * @param array $configuration - Partitioned configuration.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function dnsEnabled(array $configuration): bool
    {
        return ($configuration['block_encrypted_dns'] ?? false) === true
            || ($configuration['disable_firefox_doh'] ?? false) === true
            || ($configuration['disable_private_relay'] ?? false) === true
            || ($configuration['discovery'] ?? self::DISCOVERY_OFF) !== self::DISCOVERY_OFF
            || ($configuration['block_tor'] ?? false) === true
            || ($configuration['block_vpn'] ?? false) === true;
    }

    /**
     * Bypass Configuration - Firewall Enabled.
     *
     * @param array $configuration - Partitioned configuration.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function firewallEnabled(array $configuration): bool
    {
        return ($configuration['block_tls_quic'] ?? false) === true
            || ($configuration['block_encrypted_dns'] ?? false) === true
            || ($configuration['block_tor'] ?? false) === true
            || ($configuration['block_vpn'] ?? false) === true
            || ($configuration['block_vpn_ports'] ?? false) === true;
    }

    /**
     * Bypass Configuration - Kind Enabled.
     *
     * @param array $configuration - Partitioned configuration.
     * @param string $kind - Bypass List kind.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function kindEnabled(array $configuration, string $kind): bool
    {
        return match ($kind) {
            self::KIND_ENCRYPTED_DNS => ($configuration['block_encrypted_dns'] ?? false) === true,
            self::KIND_TOR => ($configuration['block_tor'] ?? false) === true,
            self::KIND_VPN => ($configuration['block_vpn'] ?? false) === true,
            default => false,
        };
    }

    /** @since 1.0.0 */
    private static function invalidValue(
        string $field,
        mixed $value,
        ValidationException $exception,
    ): array {
        $fieldKeys = [
            'bypass_settings' => 'bypass_protection',
            'block_tls_quic' => 'tls_and_quic',
            'block_encrypted_dns' => 'providers',
            'disable_firefox_doh' => 'firefox',
            'disable_private_relay' => 'private_relay',
            'discovery' => 'discovery',
            'block_tor' => 'tor',
            'block_vpn' => 'vpn',
            'block_vpn_ports' => 'vpn',
            'interfaces' => 'interfaces',
        ];

        return [
            'field' => $field,
            'field_key' => $fieldKeys[$field] ?? 'bypass_protection',
            'value' => is_scalar($value) ? substr((string) $value, 0, 4096) : '',
            'reason' => $exception->getMessage(),
            'reason_key' => $exception->messageKey(),
            'reason_arguments' => $exception->messageArguments(),
        ];
    }

    /** @since 1.0.0 */
    private static function invalidList(
        int $position,
        mixed $row,
        string $reasonKey,
        array $reasonArguments = [],
    ): array {
        return [
            'position' => $position,
            'id' => is_array($row) && is_string($row['id'] ?? null) ? $row['id'] : '',
            'name' => is_array($row) && is_string($row['descr'] ?? null) ? $row['descr'] : '',
            'url' => is_array($row) && is_string($row['url'] ?? null) ? $row['url'] : '',
            'kind' => is_array($row) && is_string($row['kind'] ?? null) ? $row['kind'] : '',
            'enabled' => is_array($row)
                && (($row['enabled'] ?? '') === 'on' || ($row['enabled'] ?? null) === true),
            'reason' => $reasonKey,
            'reason_key' => $reasonKey,
            'reason_arguments' => $reasonArguments,
            'row' => $row,
        ];
    }
}
