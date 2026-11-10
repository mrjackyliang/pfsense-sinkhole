<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

require_once(__DIR__ . '/IpNetwork.php');
require_once(__DIR__ . '/ListConfiguration.php');
require_once(__DIR__ . '/ValidationException.php');

/**
 * IP Configuration.
 *
 * Separates IP blocking from DNS settings and partitions malformed saved values
 * into repair rows without ever returning the stored MaxMind license key for UI
 * display.
 *
 * @since 1.0.0
 */
final class IpConfiguration
{
    /** @var list<string> @since 1.0.0 */
    public const DIRECTIONS = ['inbound', 'outbound'];

    /** @var list<string> @since 1.0.0 */
    public const FAMILIES = ['ipv4', 'ipv6', 'both'];

    /**
     * IP Configuration - Partition.
     *
     * @param mixed $value - Persisted IP settings.
     * @param array<string, string> $interfaces - Configured interfaces.
     * @param array<string, string> $aliases - Host and network aliases.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public static function partition(mixed $value, array $interfaces, array $aliases): array
    {
        $result = [
            'enabled' => false,
            'interfaces' => [],
            'directions' => [],
            'lists' => [],
            'countries' => [],
            'account_id' => '',
            'license_key' => '',
            'license_key_set' => false,
            'allowlist' => [],
            'stored_interfaces' => [],
            'stored_directions' => [],
            'stored_countries' => [],
            'stored_allowlist' => [],
            'invalid_values' => [],
            'invalid_lists' => [],
        ];

        if ($value === null || $value === '' || $value === []) {
            return $result;
        }

        if (!is_array($value)) {
            $result['invalid_values'][] = self::invalidValue(
                'ip_settings',
                '',
                new ValidationException('saved_ip_settings_invalid'),
            );

            return $result;
        }

        $enabled = $value['enabled'] ?? '';

        if ($enabled === 'on' || $enabled === true) {
            $result['enabled'] = true;
        } elseif (!in_array($enabled, ['', false, null], true)) {
            $result['invalid_values'][] = self::invalidValue(
                'enable',
                $enabled,
                new ValidationException('ip_enable_value_invalid'),
            );
        }

        self::partitionSelection(
            $value['interfaces'] ?? [],
            array_keys($interfaces),
            'interface',
            'ip_interface_not_configured',
            $result['interfaces'],
            $result['stored_interfaces'],
            $result['invalid_values'],
        );
        self::partitionSelection(
            $value['directions'] ?? [],
            self::DIRECTIONS,
            'direction',
            'ip_direction_invalid',
            $result['directions'],
            $result['stored_directions'],
            $result['invalid_values'],
        );

        $listPartition = self::partitionLists(self::unwrapItems($value['lists'] ?? []));
        $result['lists'] = $listPartition['lists'];
        $result['invalid_lists'] = $listPartition['invalid_rows'];

        $countries = self::unwrapItems($value['countries'] ?? []);

        foreach (is_array($countries) ? array_values($countries) : [$countries] as $country) {
            $display = self::displayValue($country);
            $result['stored_countries'][] = $display;

            if (!is_string($country) || preg_match('/^[A-Za-z]{2}$/D', $country) !== 1) {
                $result['invalid_values'][] = self::invalidValue(
                    'country',
                    $country,
                    new ValidationException('ip_country_invalid'),
                );

                continue;
            }

            $result['countries'][strtoupper($country)] = true;
        }
        $result['countries'] = array_keys($result['countries']);
        sort($result['countries'], SORT_STRING);

        $accountValue = $value['account_id'] ?? '';
        $accountId = is_string($accountValue) ? trim($accountValue) : '';
        $result['account_id'] = $accountId;

        if (
            !is_string($accountValue)
            || ($accountId !== '' && preg_match('/^[0-9]{1,32}$/D', $accountId) !== 1)
        ) {
            $result['invalid_values'][] = self::invalidValue(
                'account_id',
                $accountValue,
                new ValidationException('maxmind_account_id_invalid'),
            );
        }

        $licenseValue = $value['license_key'] ?? '';
        $licenseKey = is_string($licenseValue) ? $licenseValue : '';
        $result['license_key'] = $licenseKey;
        $result['license_key_set'] = $licenseKey !== '';

        if (
            !is_string($licenseValue)
            || (
                $licenseKey !== ''
                && (
                    strlen($licenseKey) > 128
                    || preg_match('/^[\x21-\x7e]+$/D', $licenseKey) !== 1
                )
            )
        ) {
            $result['invalid_values'][] = self::invalidValue(
                'license_key',
                '',
                new ValidationException('maxmind_license_key_invalid'),
            );
        }

        $allowlist = self::unwrapItems($value['allowlist'] ?? []);

        foreach (is_array($allowlist) ? array_values($allowlist) : [$allowlist] as $allowedValue) {
            $display = self::displayValue($allowedValue);
            $result['stored_allowlist'][] = $display;

            if (is_string($allowedValue) && array_key_exists($allowedValue, $aliases)) {
                $result['allowlist'][$allowedValue] = true;

                continue;
            }

            try {
                if (!is_string($allowedValue)) {
                    throw new \InvalidArgumentException();
                }

                $normalized = IpNetwork::normalize($allowedValue);
                $result['allowlist'][$normalized] = true;
            } catch (\InvalidArgumentException) {
                $result['invalid_values'][] = self::invalidValue(
                    'allowlist',
                    $allowedValue,
                    new ValidationException('ip_allowlist_value_invalid'),
                );
            }
        }
        $result['allowlist'] = array_keys($result['allowlist']);

        if ($result['enabled'] && count($result['interfaces']) === 0) {
            $result['invalid_values'][] = self::invalidValue(
                'interfaces',
                '',
                new ValidationException('ip_interface_required'),
            );
        }

        if ($result['enabled'] && count($result['directions']) === 0) {
            $result['invalid_values'][] = self::invalidValue(
                'directions',
                '',
                new ValidationException('ip_direction_required'),
            );
        }

        if (
            count($result['countries']) > 0
            && ($result['account_id'] === '' || $result['license_key_set'] === false)
        ) {
            $result['invalid_values'][] = self::invalidValue(
                'countries',
                '',
                new ValidationException('maxmind_credentials_required'),
            );
        }

        return $result;
    }

    /**
     * IP Configuration - Partition Lists.
     *
     * @param mixed $value - Persisted list rows.
     *
     * @return array{lists: array<string, array>, invalid_rows: list<array>}
     *
     * @since 1.0.0
     */
    public static function partitionLists(mixed $value): array
    {
        if ($value === null || $value === '') {
            return ['lists' => [], 'invalid_rows' => []];
        }

        if (!is_array($value)) {
            return ['lists' => [], 'invalid_rows' => [self::invalidList(0, $value, 'saved_ip_lists_invalid')]];
        }

        $lists = [];
        $invalidRows = [];
        $position = 0;

        foreach ($value as $storageKey => $row) {
            try {
                if (!is_array($row)) {
                    throw new ValidationException('saved_ip_list_invalid');
                }

                $identifier = is_string($row['id'] ?? null) ? $row['id'] : '';
                $family = is_string($row['family'] ?? null) ? $row['family'] : '';

                if (is_string($storageKey) && $storageKey !== $identifier) {
                    throw new ValidationException('saved_ip_list_identifier_changed');
                }

                if (isset($lists[$identifier])) {
                    throw new ValidationException('saved_ip_list_identifier_duplicated');
                }

                if (!in_array($family, self::FAMILIES, true)) {
                    throw new ValidationException('ip_list_family_invalid');
                }

                $list = ListConfiguration::normalizeRow(
                    $identifier,
                    is_string($row['descr'] ?? null) ? $row['descr'] : '',
                    is_string($row['url'] ?? null) ? $row['url'] : '',
                    ($row['enabled'] ?? '') === 'on' || ($row['enabled'] ?? null) === true,
                );
                unset($list['global']);
                $list['family'] = $family;
                $lists[$identifier] = $list;
            } catch (ValidationException $exception) {
                $invalidRows[] = self::invalidList($position, $row, $exception->messageKey());
            }

            $position++;
        }

        return ['lists' => $lists, 'invalid_rows' => $invalidRows];
    }

    /** @since 1.0.0 */
    private static function partitionSelection(
        mixed $value,
        array $allowed,
        string $field,
        string $reasonKey,
        array &$valid,
        array &$stored,
        array &$invalid,
    ): void {
        $values = self::unwrapItems($value);

        foreach (is_array($values) ? array_values($values) : [$values] as $candidate) {
            $stored[] = self::displayValue($candidate);

            if (!is_string($candidate) || !in_array($candidate, $allowed, true)) {
                $invalid[] = self::invalidValue(
                    $field,
                    $candidate,
                    new ValidationException($reasonKey),
                );

                continue;
            }

            $valid[$candidate] = true;
        }

        $valid = array_keys($valid);
    }

    /** @since 1.0.0 */
    private static function unwrapItems(mixed $value): mixed
    {
        if (is_array($value) && count($value) === 1 && array_key_exists('item', $value)) {
            $value = $value['item'];
        }

        return ($value === null || $value === '' || $value === []) ? [] : $value;
    }

    /** @since 1.0.0 */
    private static function displayValue(mixed $value): string
    {
        return is_scalar($value) ? substr((string) $value, 0, 4096) : '';
    }

    /** @since 1.0.0 */
    private static function invalidValue(
        string $field,
        mixed $value,
        ValidationException $exception,
    ): array {
        $fieldKeys = [
            'ip_settings' => 'ip_country_blocking',
            'enable' => 'enable',
            'interface' => 'interfaces',
            'interfaces' => 'interfaces',
            'direction' => 'directions',
            'directions' => 'directions',
            'country' => 'countries',
            'countries' => 'countries',
            'account_id' => 'maxmind_account_id',
            'license_key' => 'maxmind_license_key',
            'allowlist' => 'ip_allowlist',
        ];

        return [
            'field' => $field,
            'field_key' => $fieldKeys[$field] ?? 'ip_country_blocking',
            'value' => ($field === 'license_key') ? '' : self::displayValue($value),
            'reason' => $exception->getMessage(),
            'reason_key' => $exception->messageKey(),
            'reason_arguments' => $exception->messageArguments(),
        ];
    }

    /** @since 1.0.0 */
    private static function invalidList(int $position, mixed $row, string $reasonKey): array
    {
        return [
            'position' => $position,
            'id' => is_array($row) && is_string($row['id'] ?? null) ? $row['id'] : '',
            'name' => is_array($row) && is_string($row['descr'] ?? null) ? $row['descr'] : '',
            'url' => is_array($row) && is_string($row['url'] ?? null) ? $row['url'] : '',
            'family' => is_array($row) && is_string($row['family'] ?? null) ? $row['family'] : '',
            'enabled' => is_array($row)
                && (($row['enabled'] ?? '') === 'on' || ($row['enabled'] ?? null) === true),
            'reason' => $reasonKey,
            'reason_key' => $reasonKey,
            'reason_arguments' => [],
            'row' => $row,
        ];
    }
}
