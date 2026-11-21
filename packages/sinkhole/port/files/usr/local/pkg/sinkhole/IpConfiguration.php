<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use PfSense\Sinkhole\Runtime\Platform;

require_once(__DIR__ . '/IpNetwork.php');
require_once(__DIR__ . '/ListConfiguration.php');
require_once(__DIR__ . '/Platform.php');
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

    /** @var string @since 1.3.0 */
    public const CONTEXT_MIGRATION_VERSION = '1.3.0';

    /** @var string @since 1.3.0 */
    public const CONTEXT_MIGRATION_FIELD = 'context_migration_version';

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
     * @since 1.3.0
     */
    public static function partition(mixed $value, array $interfaces, array $aliases): array
    {
        $result = [
            'enabled' => false,
            'interfaces' => [],
            'directions' => [],
            'lists' => [],
            'list_ids' => [],
            'countries' => [],
            'account_id' => '',
            'license_key' => '',
            'license_key_set' => false,
            'allowlist' => [],
            'stored_interfaces' => [],
            'stored_directions' => [],
            'stored_list_ids' => [],
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

        if (array_key_exists('list_ids', $value)) {
            self::partitionSelection(
                $value['list_ids'],
                array_keys($result['lists']),
                'list_id',
                'ip_list_missing',
                $result['list_ids'],
                $result['stored_list_ids'],
                $result['invalid_values'],
            );
        } else {
            foreach ($result['lists'] as $identifier => $list) {
                if (($list['enabled'] ?? false) === true) {
                    $result['list_ids'][] = $identifier;
                    $result['stored_list_ids'][] = $identifier;
                }
            }
        }

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
     * @since 1.3.0
     */
    public static function partitionLists(mixed $value): array
    {
        if ($value === null || $value === '') {
            return ['lists' => [], 'invalid_rows' => []];
        }

        if (!is_array($value)) {
            return ['lists' => [], 'invalid_rows' => [self::invalidList(0, $value, 'saved_ip_lists_invalid')]];
        }

        if (array_key_exists('id', $value)) {
            $value = [$value];
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

    /**
     * IP Configuration - For Context.
     *
     * Reads one exact context without applying inherited settings. Optional live
     * validation inputs let the platform adapter reject deleted aliases and interfaces.
     *
     * @param array $section - Package-wide IP section.
     * @param array $contextRows - Stored context rows or their ``item`` wrapper.
     * @param string $context - Global, network, or device context key.
     * @param array<string, string>|null $interfaces - Optional configured interfaces.
     * @param array<string, string>|null $aliases - Optional host and network aliases.
     *
     * @return array|null
     *
     * @since 1.3.0
     */
    public static function forContext(
        array $section,
        array $contextRows,
        string $context,
        ?array $interfaces = null,
        ?array $aliases = null,
    ): ?array {
        if ($context === 'global') {
            $interfaces ??= self::permissiveInterfaces($section['interfaces'] ?? []);
            $aliases ??= self::permissiveAliases($section['allowlist'] ?? []);

            return self::partition(
                self::packageSectionStorage($section),
                $interfaces,
                $aliases,
            );
        }

        if (self::contextKeyIsValid($context) === false) {
            return null;
        }

        foreach (self::contextRows($contextRows) as $row) {
            if (!is_array($row) || ($row['context'] ?? null) !== $context) {
                continue;
            }

            $aliases ??= self::permissiveAliases($row['allowlist'] ?? []);

            return self::partitionContextRow($section, $row, $aliases);
        }

        return null;
    }

    /**
     * IP Configuration - Submit Context.
     *
     * Normalizes the existing IP form field names and reports validation errors
     * without mutating pfSense configuration or exposing a stored license key.
     *
     * @param string $context - Global, network, or device context key.
     * @param array $post - Submitted form values.
     * @param array<string, string> $interfaces - Configured interfaces.
     * @param array<string, string> $aliases - Host and network aliases.
     * @param array $currentSettings - Current exact-context settings.
     * @param array $globalSettings - Current package-wide settings for child contexts.
     *
     * @return array{settings: array, errors: list<string>}
     *
     * @since 1.3.0
     */
    public static function submitContext(
        string $context,
        array $post,
        array $interfaces = [],
        array $aliases = [],
        array $currentSettings = [],
        array $globalSettings = [],
    ): array {
        $errors = [];

        if ($context !== 'global' && self::contextKeyIsValid($context) === false) {
            return [
                'settings' => [],
                'errors' => ['The IP context is invalid.'],
            ];
        }

        $packageSettings = ($context === 'global') ? $currentSettings : $globalSettings;

        if ($packageSettings === [] && Platform::adapter()->canReadConfiguration()) {
            $storedSection = Platform::adapter()->readConfigurationPath('installedpackages/sinkhole/ip', []);
            $packageSettings = is_array($storedSection) ? $storedSection : [];
        }

        $packageStorage = self::packageSectionStorage($packageSettings);

        try {
            $countries = self::submissionLines(
                $post['ip_countries'] ?? '',
                'ip_countries_invalid',
            );
        } catch (ValidationException $exception) {
            $countries = [];
            $errors[] = $exception->getMessage();
        }

        try {
            $allowlist = self::submissionLines(
                $post['ip_allowlist'] ?? '',
                'ip_allowlist_invalid',
            );
        } catch (ValidationException $exception) {
            $allowlist = [];
            $errors[] = $exception->getMessage();
        }

        $directions = self::submittedSelection($post['ip_directions'] ?? []);
        $listIds = self::submittedSelection(
            $post['ip_list_ids'] ?? $post['ip_lists'] ?? [],
        );
        $submitted = [
            'enabled' => isset($post['ip_enabled']) ? 'on' : '',
            'directions' => ['item' => $directions],
            'list_ids' => ['item' => $listIds],
            'countries' => ['item' => $countries],
            'allowlist' => ['item' => $allowlist],
        ];

        if ($context === 'global') {
            $currentLicenseKey = is_string($packageStorage['license_key'] ?? null)
                ? $packageStorage['license_key']
                : '';
            $submittedLicenseKey = is_string($post['maxmind_license_key'] ?? null)
                ? $post['maxmind_license_key']
                : '';

            if (isset($post['clear_maxmind_license_key'])) {
                $submittedLicenseKey = '';
            } elseif ($submittedLicenseKey === '') {
                $submittedLicenseKey = $currentLicenseKey;
            }

            $submitted['interfaces'] = [
                'item' => self::submittedSelection($post['ip_interfaces'] ?? []),
            ];
            $submitted['lists'] = $packageStorage['lists'] ?? ['item' => []];
            $submitted['account_id'] = is_string($post['maxmind_account_id'] ?? null)
                ? $post['maxmind_account_id']
                : '';
            $submitted['license_key'] = $submittedLicenseKey;
            $settings = self::partition($submitted, $interfaces, $aliases);
        } else {
            $submitted['context'] = $context;
            $settings = self::partitionContextRow($packageStorage, $submitted, $aliases);
        }

        foreach ($settings['invalid_values'] ?? [] as $invalidValue) {
            $reason = is_string($invalidValue['reason'] ?? null)
                ? $invalidValue['reason']
                : '';

            if ($reason !== '') {
                $errors[] = $reason;
            }
        }

        return [
            'settings' => $settings,
            'errors' => array_values(array_unique($errors)),
        ];
    }

    /**
     * IP Configuration - Store Context.
     *
     * Writes one exact context in pfSense's repeated-item XML shape through the
     * platform adapter. The caller owns the single configuration save and any
     * runtime apply handoff.
     *
     * @param string $context - Global, network, or device context key.
     * @param array $settings - Normalized exact-context settings.
     *
     * @return void
     *
     * @since 1.3.0
     */
    public static function storeContext(string $context, array $settings): void
    {
        if (Platform::adapter()->canWriteConfiguration() === false) {
            throw new \RuntimeException('The pfSense configuration writer is unavailable.');
        }

        if ($context === 'global') {
            $storedSection = Platform::adapter()->readConfigurationPath('installedpackages/sinkhole/ip', []);
            $section = is_array($storedSection) ? $storedSection : [];
            $section['enabled'] = (($settings['enabled'] ?? false) === true) ? 'on' : '';
            $section['interfaces'] = [
                'item' => self::settingsValues($settings, 'interfaces', 'stored_interfaces'),
            ];
            $section['directions'] = [
                'item' => self::settingsValues($settings, 'directions', 'stored_directions'),
            ];
            $section['list_ids'] = [
                'item' => self::settingsValues($settings, 'list_ids', 'stored_list_ids'),
            ];
            $section['countries'] = [
                'item' => self::settingsValues($settings, 'countries', 'stored_countries'),
            ];
            $section['account_id'] = is_string($settings['account_id'] ?? null)
                ? $settings['account_id']
                : '';
            $section['license_key'] = is_string($settings['license_key'] ?? null)
                ? $settings['license_key']
                : '';
            $section['allowlist'] = [
                'item' => self::settingsValues($settings, 'allowlist', 'stored_allowlist'),
            ];

            Platform::adapter()->writeConfigurationPath('installedpackages/sinkhole/ip', $section);

            return;
        }

        if (self::contextKeyIsValid($context) === false) {
            throw new \InvalidArgumentException('The IP context is invalid.');
        }

        $storedRows = Platform::adapter()->readConfigurationPath('installedpackages/sinkhole/ip_contexts/item', []);
        $rows = self::contextRows(is_array($storedRows) ? $storedRows : []);
        $replacement = self::contextStorage($context, $settings);
        $replaced = false;
        $result = [];

        foreach ($rows as $row) {
            if (is_array($row) && ($row['context'] ?? null) === $context) {
                if ($replaced === false) {
                    $result[] = $replacement;
                    $replaced = true;
                }

                continue;
            }

            $result[] = $row;
        }

        if ($replaced === false) {
            $result[] = $replacement;
        }

        Platform::adapter()->writeConfigurationPath('installedpackages/sinkhole/ip_contexts/item', $result);
    }

    /**
     * IP Configuration - Remove Context.
     *
     * Deletes only matching network or device rows and leaves configuration
     * persistence to the Clients-page caller that removes the owning client.
     *
     * @param string $context - Network or device context key.
     *
     * @return void
     *
     * @since 1.3.0
     */
    public static function removeContext(string $context): void
    {
        if (self::contextKeyIsValid($context) === false) {
            return;
        }

        $storedRows = Platform::adapter()->readConfigurationPath('installedpackages/sinkhole/ip_contexts/item', []);
        $rows = self::contextRows(is_array($storedRows) ? $storedRows : []);
        $remainingRows = array_values(array_filter(
            $rows,
            static fn(mixed $row): bool => !is_array($row)
                || ($row['context'] ?? null) !== $context,
        ));

        Platform::adapter()->writeConfigurationPath('installedpackages/sinkhole/ip_contexts/item', $remainingRows);
    }

    /**
     * IP Configuration - Context Keys.
     *
     * Lists each valid stored network or device row once, in stable storage order,
     * for the read-only All overview and runtime context enumeration.
     *
     * @return list<string>
     *
     * @since 1.3.0
     */
    public static function contextKeys(): array
    {
        $storedRows = Platform::adapter()->readConfigurationPath('installedpackages/sinkhole/ip_contexts/item', []);
        $keys = [];

        foreach (self::contextRows(is_array($storedRows) ? $storedRows : []) as $row) {
            $context = is_array($row) && is_string($row['context'] ?? null)
                ? $row['context']
                : '';

            if (self::contextKeyIsValid($context)) {
                $keys[$context] = true;
            }
        }

        return array_keys($keys);
    }

    /**
     * IP Configuration - Fields For Context.
     *
     * Global exposes package-wide interfaces and MaxMind credentials; child
     * contexts expose only their exact blocking policy fields.
     *
     * @param string $context - Global, network, or device context key.
     *
     * @return list<string>
     *
     * @since 1.3.0
     */
    public static function fieldsForContext(string $context): array
    {
        $contextFields = [
            'ip_enabled',
            'ip_directions',
            'ip_list_ids',
            'ip_countries',
            'ip_allowlist',
        ];

        if ($context === 'global') {
            return [
                'ip_enabled',
                'ip_interfaces',
                'ip_directions',
                'ip_list_ids',
                'ip_countries',
                'maxmind_account_id',
                'maxmind_license_key',
                'clear_maxmind_license_key',
                'ip_allowlist',
            ];
        }

        return self::contextKeyIsValid($context) ? $contextFields : [];
    }

    /**
     * IP Configuration - Partition Context Row.
     *
     * Reuses the global validation boundary with inert package-wide values, then
     * removes fields a network or device is not allowed to own.
     *
     * @param array $section - Package-wide section holding source definitions.
     * @param array $row - Stored child-context row.
     * @param array<string, string> $aliases - Host and network aliases.
     *
     * @return array
     *
     * @since 1.3.0
     * @private
     */
    private static function partitionContextRow(
        array $section,
        array $row,
        array $aliases,
    ): array {
        $value = $row;
        $value['interfaces'] = ['item' => ['context']];
        $value['lists'] = ['item' => self::sourceStorageRows($section['lists'] ?? [])];
        $value['account_id'] = '1';
        $value['license_key'] = 'context';
        $configuration = self::partition(
            $value,
            ['context' => 'Context'],
            $aliases,
        );

        if (($configuration['countries'] ?? []) !== []) {
            $credentialCheck = self::partition(
                [
                    'countries' => ['item' => ['ZZ']],
                    'account_id' => $section['account_id'] ?? '',
                    'license_key' => $section['license_key'] ?? '',
                ],
                [],
                [],
            );

            foreach ($credentialCheck['invalid_values'] as $invalidValue) {
                if (in_array(
                    $invalidValue['field'] ?? '',
                    ['countries', 'account_id', 'license_key'],
                    true,
                )) {
                    $configuration['invalid_values'][] = $invalidValue;
                }
            }
        }

        foreach ([
            'interfaces',
            'stored_interfaces',
            'lists',
            'account_id',
            'license_key',
            'license_key_set',
            'invalid_lists',
        ] as $packageField) {
            unset($configuration[$packageField]);
        }

        return $configuration;
    }

    /**
     * IP Configuration - Package Section Storage.
     *
     * Accepts raw storage or an already partitioned result and returns the XML-safe
     * shape required when validating a context submission.
     *
     * @param array $settings - Raw or partitioned package settings.
     *
     * @return array
     *
     * @since 1.3.0
     * @private
     */
    private static function packageSectionStorage(array $settings): array
    {
        $storage = $settings;

        if (($settings['enabled'] ?? null) === true) {
            $storage['enabled'] = 'on';
        } elseif (($settings['enabled'] ?? null) === false) {
            $storage['enabled'] = '';
        }

        foreach ([
            'interfaces' => 'stored_interfaces',
            'directions' => 'stored_directions',
            'list_ids' => 'stored_list_ids',
            'countries' => 'stored_countries',
            'allowlist' => 'stored_allowlist',
        ] as $field => $storedField) {
            if (array_key_exists($storedField, $settings)) {
                $storage[$field] = ['item' => self::settingsValues(
                    $settings,
                    $field,
                    $storedField,
                )];
            }
        }

        if (array_key_exists('lists', $settings)) {
            $storage['lists'] = ['item' => self::sourceStorageRows($settings['lists'])];
        }

        return $storage;
    }

    /**
     * IP Configuration - Source Storage Rows.
     *
     * Converts normalized source maps back to their persisted row names while
     * retaining valid raw source rows unchanged.
     *
     * @param mixed $value - Raw or normalized source rows.
     *
     * @return list<array>
     *
     * @since 1.3.0
     * @private
     */
    private static function sourceStorageRows(mixed $value): array
    {
        $value = self::unwrapItems($value);

        if (is_array($value) && array_key_exists('id', $value)) {
            $value = [$value];
        }

        $rows = [];

        foreach (is_array($value) ? $value : [] as $row) {
            if (!is_array($row)) {
                continue;
            }

            if (is_string($row['name'] ?? null) && !array_key_exists('descr', $row)) {
                $row = [
                    'id' => is_string($row['id'] ?? null) ? $row['id'] : '',
                    'descr' => $row['name'],
                    'url' => is_string($row['url'] ?? null) ? $row['url'] : '',
                    'family' => is_string($row['family'] ?? null) ? $row['family'] : '',
                    'enabled' => (($row['enabled'] ?? false) === true) ? 'on' : '',
                ];
            }

            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * IP Configuration - Context Storage.
     *
     * Serializes only fields owned by a network or device, preventing package-wide
     * source definitions, credentials, or interfaces from leaking into a row.
     *
     * @param string $context - Network or device context key.
     * @param array $settings - Normalized exact-context settings.
     *
     * @return array
     *
     * @since 1.3.0
     * @private
     */
    private static function contextStorage(string $context, array $settings): array
    {
        return [
            'context' => $context,
            'enabled' => (($settings['enabled'] ?? false) === true) ? 'on' : '',
            'directions' => [
                'item' => self::settingsValues($settings, 'directions', 'stored_directions'),
            ],
            'list_ids' => [
                'item' => self::settingsValues($settings, 'list_ids', 'stored_list_ids'),
            ],
            'countries' => [
                'item' => self::settingsValues($settings, 'countries', 'stored_countries'),
            ],
            'allowlist' => [
                'item' => self::settingsValues($settings, 'allowlist', 'stored_allowlist'),
            ],
        ];
    }

    /**
     * IP Configuration - Settings Values.
     *
     * Selects the repair-preserving stored values when available and otherwise
     * filters a normalized list to scalar strings for XML storage.
     *
     * @param array $settings - Normalized settings.
     * @param string $field - Normalized field name.
     * @param string $storedField - Repair-preserving field name.
     *
     * @return list<string>
     *
     * @since 1.3.0
     * @private
     */
    private static function settingsValues(
        array $settings,
        string $field,
        string $storedField,
    ): array {
        $values = $settings[$storedField] ?? $settings[$field] ?? [];
        $values = self::unwrapItems($values);

        if (is_string($values)) {
            return [$values];
        }

        return array_values(array_filter(
            is_array($values) ? $values : [],
            static fn(mixed $value): bool => is_string($value),
        ));
    }

    /**
     * IP Configuration - Context Rows.
     *
     * Unwraps pfSense's repeated ``item`` container and tolerates a single raw row
     * so migration and page writes share one boundary.
     *
     * @param array $value - Stored context container or rows.
     *
     * @return list<mixed>
     *
     * @since 1.3.0
     * @private
     */
    private static function contextRows(array $value): array
    {
        $value = self::unwrapItems($value);

        if (is_array($value) && array_key_exists('context', $value)) {
            return [$value];
        }

        return is_array($value) ? array_values($value) : [];
    }

    /**
     * IP Configuration - Context Key Is Valid.
     *
     * Storage accepts only stable network and device identifiers; Global remains
     * in its historical section and All is deliberately never persisted.
     *
     * @param string $context - Candidate context key.
     *
     * @return bool
     *
     * @since 1.3.0
     * @private
     */
    private static function contextKeyIsValid(string $context): bool
    {
        return preg_match('/^(?:network|device):[a-f0-9]{32}$/D', $context) === 1;
    }

    /**
     * IP Configuration - Submission Lines.
     *
     * Normalizes the existing textarea contract while accepting list fixtures in
     * unit tests and rejecting non-string values before storage.
     *
     * @param mixed $value - Submitted textarea or line list.
     * @param string $errorKey - Existing validation message key.
     *
     * @return list<string>
     *
     * @throws ValidationException When the submitted value is malformed.
     *
     * @since 1.3.0
     * @private
     */
    private static function submissionLines(mixed $value, string $errorKey): array
    {
        if (is_array($value)) {
            $lines = $value;
        } elseif (is_string($value)) {
            $lines = preg_split('/\r\n|\r|\n/', $value);

            if (!is_array($lines)) {
                throw new ValidationException($errorKey);
            }
        } else {
            throw new ValidationException($errorKey);
        }

        $result = [];

        foreach ($lines as $line) {
            if (!is_string($line)) {
                throw new ValidationException($errorKey);
            }

            $line = trim($line);

            if ($line !== '') {
                $result[] = $line;
            }
        }

        return $result;
    }

    /**
     * IP Configuration - Submitted Selection.
     *
     * Keeps only scalar string choices from a multi-select submission; the normal
     * partition validator reports unknown values against the configured choices.
     *
     * @param mixed $value - Submitted multi-select value.
     *
     * @return list<string>
     *
     * @since 1.3.0
     * @private
     */
    private static function submittedSelection(mixed $value): array
    {
        return array_values(array_filter(
            is_array($value) ? $value : [],
            static fn(mixed $candidate): bool => is_string($candidate),
        ));
    }

    /**
     * IP Configuration - Permissive Interfaces.
     *
     * Exact-context reads without platform inputs treat stored names as the known
     * set; the adapter supplies the real configured set for runtime validation.
     *
     * @param mixed $value - Stored interface selection.
     *
     * @return array<string, string>
     *
     * @since 1.3.0
     * @private
     */
    private static function permissiveInterfaces(mixed $value): array
    {
        $interfaces = [];

        foreach (self::settingsValues(['interfaces' => $value], 'interfaces', '') as $interface) {
            $interfaces[$interface] = $interface;
        }

        return $interfaces;
    }

    /**
     * IP Configuration - Permissive Aliases.
     *
     * Exact-context reads retain syntactically non-IP allowlist values until the
     * platform adapter can validate them against pfSense's current alias set.
     *
     * @param mixed $value - Stored allowlist.
     *
     * @return array<string, string>
     *
     * @since 1.3.0
     * @private
     */
    private static function permissiveAliases(mixed $value): array
    {
        $aliases = [];

        foreach (self::settingsValues(['allowlist' => $value], 'allowlist', '') as $candidate) {
            if (filter_var(explode('/', $candidate, 2)[0], FILTER_VALIDATE_IP) === false) {
                $aliases[$candidate] = $candidate;
            }
        }

        return $aliases;
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
            'list_id' => 'ip_lists',
            'list_ids' => 'ip_lists',
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
