<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

require_once(__DIR__ . '/ListConfiguration.php');
require_once(__DIR__ . '/RedirectConfiguration.php');
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
    /** @var string @since 1.3.0 */
    public const SECTION_PATH = 'installedpackages/sinkhole/bypass';

    /** @var string @since 1.3.0 */
    public const CONTEXTS_PATH = 'installedpackages/sinkhole/bypass_contexts/item';

    /** @var string @since 1.3.0 */
    public const CONTEXT_MIGRATION_FLAG = 'contexts_migrated_1_3_0';

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
     * Each alias adds one nested pf anchor, so the limit keeps the rendered rules
     * far below pf's anchor stack depth.
     *
     * @var int
     *
     * @since 1.2.0
     */
    public const MAXIMUM_EXEMPTION_ALIASES = 16;

    /**
     * Bypass Configuration - Partition.
     *
     * Invalid block exemptions stay out of `invalid_values` so a renamed alias
     * never turns the blocks off. They are reported in `invalid_exemptions`, and
     * the rule renderer then applies no exemption at all.
     *
     * @param mixed $value - Persisted bypass settings.
     * @param list<string> $interfaces - Valid shared redirect interfaces.
     * @param array<string, string> $aliases - Existing host and network aliases.
     *
     * @return array
     *
     * @since 1.0.0
     * @since 1.2.0
     * @since 1.3.0
     */
    public static function partition(mixed $value, array $interfaces = [], array $aliases = []): array
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
            'selected_lists' => [],
            'exempt_sources' => [],
            'exempt_destinations' => [],
            'stored_exempt_sources' => [],
            'stored_exempt_destinations' => [],
            'invalid_values' => [],
            'invalid_exemptions' => [],
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
        $result['selected_lists'] = array_keys($listPartition['lists']);
        $result['invalid_lists'] = $listPartition['invalid_rows'];

        $sourcePartition = self::partitionExemptions(
            $value['exempt_sources'] ?? [],
            $aliases,
            'source',
        );
        $result['exempt_sources'] = $sourcePartition['values'];
        $result['stored_exempt_sources'] = $sourcePartition['stored'];

        $destinationPartition = self::partitionExemptions(
            $value['exempt_destinations'] ?? [],
            $aliases,
            'destination',
        );
        $result['exempt_destinations'] = $destinationPartition['values'];
        $result['stored_exempt_destinations'] = $destinationPartition['stored'];
        $result['invalid_exemptions'] = array_merge(
            $sourcePartition['invalid'],
            $destinationPartition['invalid'],
        );

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
     * Bypass Configuration - For Context.
     *
     * Returns only settings owned by the requested context. A missing network or
     * device row returns null so the caller can show that broader settings apply.
     *
     * @param array $section - Global Bypass section or partitioned configuration.
     * @param array $contextRows - Persisted context rows.
     * @param string $context - Context key.
     *
     * @return array|null
     *
     * @since 1.3.0
     */
    public static function forContext(
        array $section,
        array $contextRows,
        string $context,
    ): ?array {
        if ($context === 'global') {
            if (array_key_exists('dns_enabled', $section)) {
                $global = $section;

                if (array_key_exists('global_enabled', $section)) {
                    $global['enabled'] = ($section['global_enabled'] ?? false) === true;
                    $global['dns_enabled'] = ($section['global_dns_enabled'] ?? false) === true;
                    $global['firewall_enabled'] =
                        ($section['global_firewall_enabled'] ?? false) === true;
                    unset(
                        $global['global_enabled'],
                        $global['global_dns_enabled'],
                        $global['global_firewall_enabled'],
                        $global['contexts']
                    );
                }

                return $global;
            }

            return self::partition(
                $section,
                self::globalInterfaces($section),
                self::configuredAliases($section),
            );
        }

        if (self::validOwnedContext($context) === false) {
            return null;
        }

        if (
            array_key_exists('dns_enabled', $section)
            && is_array($section['contexts'] ?? null)
        ) {
            $contextConfiguration = $section['contexts'][$context] ?? null;

            return is_array($contextConfiguration) ? $contextConfiguration : null;
        }

        $rows = self::unwrapRows($contextRows);

        foreach ($rows as $row) {
            if (!is_array($row) || ($row['context'] ?? null) !== $context) {
                continue;
            }

            $global = array_key_exists('dns_enabled', $section)
                ? $section
                : self::partition($section, self::globalInterfaces($section));

            return self::partitionContextRow(
                $row,
                is_array($global['lists'] ?? null) ? $global['lists'] : [],
                self::configuredAliases($row),
            );
        }

        return null;
    }

    /**
     * Bypass Configuration - Submit Context.
     *
     * @param string $context - Context key.
     * @param array $post - Submitted form fields.
     * @param array<string, string> $interfaces - Configured interfaces.
     * @param array<string, string> $aliases - Existing host and network aliases.
     * @param array<string, array> $listSources - Package-wide Bypass sources.
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
        array $listSources = [],
    ): array {
        if ($context !== 'global' && self::validOwnedContext($context) === false) {
            return [
                'settings' => [],
                'errors' => [(new ValidationException('scope_identifier_invalid'))->getMessage()],
            ];
        }

        if ($listSources === []) {
            $global = self::partition(
                function_exists('config_get_path')
                    ? config_get_path(self::SECTION_PATH, [])
                    : [],
            );
            $listSources = $global['lists'];
        }

        $stored = [];

        foreach (self::BOOLEAN_FIELDS as $field) {
            $stored[$field] = self::submitted($post[$field] ?? null) ? 'on' : '';
        }

        $stored['discovery'] = $post['discovery'] ?? self::DISCOVERY_OFF;
        $sourceText = $post['block_exempt_sources'] ?? $post['exempt_sources'] ?? '';
        $destinationText = $post['block_exempt_destinations']
            ?? $post['exempt_destinations']
            ?? '';
        $errors = [];

        if (!is_string($sourceText)) {
            $errors[] = (new ValidationException('exempt_sources_invalid'))->getMessage();
        }

        if (!is_string($destinationText)) {
            $errors[] = (new ValidationException('exempt_destinations_invalid'))->getMessage();
        }

        if (!is_string($sourceText) || !is_string($destinationText)) {
            $stored['exempt_sources'] = ['item' => []];
            $stored['exempt_destinations'] = ['item' => []];
        } else {
            try {
                $exemptions = self::normalizeExemptionSubmission(
                    $sourceText,
                    $destinationText,
                    $aliases,
                );
                $stored['exempt_sources'] = ['item' => $exemptions['exempt_sources']];
                $stored['exempt_destinations'] = ['item' => $exemptions['exempt_destinations']];
            } catch (ValidationException $exception) {
                $errors[] = $exception->getMessage();
                $stored['exempt_sources'] = ['item' => []];
                $stored['exempt_destinations'] = ['item' => []];
            }
        }

        if ($context === 'global') {
            $postedInterfaces = $post['bypass_interfaces'] ?? $post['interfaces'] ?? [];

            if (!is_array($postedInterfaces)) {
                $errors[] = (new ValidationException(
                    'redirect_interface_selection_invalid',
                ))->getMessage();
                $postedInterfaces = [];
            }

            $selectedInterfaces = [];

            foreach ($postedInterfaces as $interface) {
                if (!is_string($interface) || !array_key_exists($interface, $interfaces)) {
                    $errors[] = (new ValidationException(
                        'redirect_interface_not_configured',
                    ))->getMessage();

                    continue;
                }

                $selectedInterfaces[$interface] = true;
            }

            $storageLists = [];

            foreach ($listSources as $identifier => $list) {
                if (!is_string($identifier) || !is_array($list)) {
                    continue;
                }

                $storageLists[] = self::listStorageRow($identifier, $list);
            }

            $stored['lists'] = ['item' => $storageLists];
            $settings = self::partition(
                $stored,
                array_keys($selectedInterfaces),
                $aliases,
            );

            foreach (array_merge($settings['invalid_values'], $settings['invalid_exemptions']) as $invalid) {
                if (is_array($invalid) && is_string($invalid['reason'] ?? null)) {
                    $errors[] = $invalid['reason'];
                }
            }

            return [
                'settings' => $settings,
                'errors' => array_values(array_unique($errors)),
            ];
        }

        $selection = $post['bypass_lists'] ?? $post['selected_lists'] ?? $post['lists'] ?? [];
        $stored['context'] = $context;
        $stored['enabled'] = self::submitted(
            $post['enabled'] ?? $post['bypass_enabled'] ?? null,
        ) ? 'on' : '';
        $stored['lists'] = ['item' => is_array($selection) ? $selection : []];

        if (!is_array($selection)) {
            $errors[] = (new ValidationException(
                'selected_block_lists_invalid',
            ))->getMessage();
        }

        $settings = self::partitionContextRow($stored, $listSources, $aliases);

        foreach (array_merge($settings['invalid_values'], $settings['invalid_exemptions']) as $invalid) {
            if (is_array($invalid) && is_string($invalid['reason'] ?? null)) {
                $errors[] = $invalid['reason'];
            }
        }

        return [
            'settings' => $settings,
            'errors' => array_values(array_unique($errors)),
        ];
    }

    /**
     * Bypass Configuration - Store Context.
     *
     * Persists without creating a configuration revision; the page owns the one
     * write shared with its other changes.
     *
     * @param string $context - Context key.
     * @param array $settings - Normalized context settings.
     *
     * @return void
     *
     * @since 1.3.0
     */
    public static function storeContext(string $context, array $settings): void
    {
        if (!function_exists('config_get_path') || !function_exists('config_set_path')) {
            return;
        }

        if ($context === 'global') {
            $section = config_get_path(self::SECTION_PATH, []);
            $section = is_array($section) ? $section : [];

            foreach (self::BOOLEAN_FIELDS as $field) {
                $section[$field] = ($settings[$field] ?? false) === true ? 'on' : '';
            }

            $section['discovery'] = is_string($settings['discovery'] ?? null)
                ? $settings['discovery']
                : self::DISCOVERY_OFF;

            foreach (['exempt_sources', 'exempt_destinations'] as $field) {
                $values = is_array($settings[$field] ?? null) ? $settings[$field] : [];
                $section[$field] = ['item' => array_values(array_filter($values, 'is_string'))];
            }

            config_set_path(self::SECTION_PATH, $section);

            if (is_array($settings['interfaces'] ?? null)) {
                config_set_path(
                    'installedpackages/sinkhole/redirect/interfaces',
                    ['item' => array_values(array_filter($settings['interfaces'], 'is_string'))],
                );
            }

            return;
        }

        if (self::validOwnedContext($context) === false) {
            return;
        }

        $rows = self::unwrapRows(config_get_path(self::CONTEXTS_PATH, []));
        $storage = self::contextStorage($context, $settings);
        $replaced = false;

        foreach ($rows as $position => $row) {
            if (is_array($row) && ($row['context'] ?? null) === $context) {
                $rows[$position] = $storage;
                $replaced = true;

                break;
            }
        }

        if ($replaced === false) {
            $rows[] = $storage;
        }

        config_set_path(self::CONTEXTS_PATH, array_values($rows));
    }

    /**
     * Bypass Configuration - Remove Context.
     *
     * @param string $context - Network or device context key.
     *
     * @return void
     *
     * @since 1.3.0
     */
    public static function removeContext(string $context): void
    {
        if (
            self::validOwnedContext($context) === false
            || !function_exists('config_get_path')
            || !function_exists('config_set_path')
        ) {
            return;
        }

        $rows = self::unwrapRows(config_get_path(self::CONTEXTS_PATH, []));
        $rows = array_values(array_filter(
            $rows,
            static fn (mixed $row): bool => !is_array($row)
                || ($row['context'] ?? null) !== $context,
        ));
        config_set_path(self::CONTEXTS_PATH, $rows);
    }

    /**
     * Bypass Configuration - Context Keys.
     *
     * @return list<string>
     *
     * @since 1.3.0
     */
    public static function contextKeys(): array
    {
        $keys = ['global' => true];
        $rows = function_exists('config_get_path')
            ? self::unwrapRows(config_get_path(self::CONTEXTS_PATH, []))
            : [];

        foreach ($rows as $row) {
            $context = is_array($row) && is_string($row['context'] ?? null)
                ? $row['context']
                : '';

            if (self::validOwnedContext($context)) {
                $keys[$context] = true;
            }
        }

        return array_keys($keys);
    }

    /**
     * Bypass Configuration - Fields For Context.
     *
     * @param string $context - Context key.
     *
     * @return list<string>
     *
     * @since 1.3.0
     */
    public static function fieldsForContext(string $context): array
    {
        $fields = array_merge(
            self::BOOLEAN_FIELDS,
            ['discovery', 'block_exempt_sources', 'block_exempt_destinations'],
        );

        if ($context === 'global') {
            return array_merge(['bypass_interfaces'], $fields);
        }

        return self::validOwnedContext($context)
            ? array_merge(['enabled', 'bypass_lists'], $fields)
            : [];
    }

    /**
     * Bypass Configuration - Attach Context Rows.
     *
     * @param array $configuration - Partitioned Global settings.
     * @param array $contextRows - Persisted context rows.
     * @param array<string, string> $aliases - Existing host and network aliases.
     *
     * @return array
     *
     * @since 1.3.0
     */
    public static function withContexts(
        array $configuration,
        array $contextRows,
        array $aliases = [],
    ): array {
        $globalValid = ($configuration['invalid_values'] ?? []) === [];
        $configuration['global_enabled'] = $globalValid
            && ($configuration['enabled'] ?? false) === true;
        $configuration['global_dns_enabled'] = $globalValid
            && ($configuration['dns_enabled'] ?? false) === true;
        $configuration['global_firewall_enabled'] = $globalValid
            && ($configuration['firewall_enabled'] ?? false) === true;
        $configuration['enabled'] = $configuration['global_enabled'];
        $configuration['dns_enabled'] = $configuration['global_dns_enabled'];
        $configuration['firewall_enabled'] = $configuration['global_firewall_enabled'];
        $configuration['contexts'] = [];

        foreach (self::unwrapRows($contextRows) as $row) {
            if (!is_array($row) || !is_string($row['context'] ?? null)) {
                continue;
            }

            $context = $row['context'];

            if (self::validOwnedContext($context) === false || isset($configuration['contexts'][$context])) {
                continue;
            }

            $configuration['contexts'][$context] = self::partitionContextRow(
                $row,
                is_array($configuration['lists'] ?? null) ? $configuration['lists'] : [],
                $aliases,
            );
        }

        ksort($configuration['contexts'], SORT_STRING);

        foreach ($configuration['contexts'] as $contextConfiguration) {
            if (($contextConfiguration['invalid_values'] ?? []) !== []) {
                continue;
            }

            $configuration['enabled'] = ($configuration['enabled'] ?? false)
                || ($contextConfiguration['enabled'] ?? false);
            $configuration['dns_enabled'] = ($configuration['dns_enabled'] ?? false)
                || ($contextConfiguration['dns_enabled'] ?? false);
            $configuration['firewall_enabled'] = ($configuration['firewall_enabled'] ?? false)
                || ($contextConfiguration['firewall_enabled'] ?? false);
        }

        return $configuration;
    }

    /**
     * Bypass Configuration - Kind Enabled Anywhere.
     *
     * @param array $configuration - Global configuration with context rows.
     * @param string $kind - Bypass source kind.
     *
     * @return bool
     *
     * @since 1.3.0
     */
    public static function kindEnabledAnywhere(array $configuration, string $kind): bool
    {
        if (
            ($configuration['global_enabled'] ?? $configuration['enabled'] ?? false) === true
            && self::kindEnabled($configuration, $kind)
        ) {
            return true;
        }

        foreach (is_array($configuration['contexts'] ?? null) ? $configuration['contexts'] : [] as $context) {
            if (
                is_array($context)
                && ($context['enabled'] ?? false) === true
                && ($context['invalid_values'] ?? []) === []
                && self::kindEnabled($context, $kind)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Bypass Configuration - Source Used Anywhere.
     *
     * @param array $configuration - Global configuration with context rows.
     * @param string $identifier - Source identifier.
     * @param string $kind - Source kind.
     *
     * @return bool
     *
     * @since 1.3.0
     */
    public static function sourceUsedAnywhere(
        array $configuration,
        string $identifier,
        string $kind,
    ): bool {
        if (
            ($configuration['global_enabled'] ?? $configuration['enabled'] ?? false) === true
            && self::kindEnabled($configuration, $kind)
        ) {
            return true;
        }

        foreach (is_array($configuration['contexts'] ?? null) ? $configuration['contexts'] : [] as $context) {
            if (
                !is_array($context)
                || ($context['enabled'] ?? false) !== true
                || ($context['invalid_values'] ?? []) !== []
                || !self::kindEnabled($context, $kind)
            ) {
                continue;
            }

            if (in_array($identifier, $context['selected_lists'] ?? [], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Bypass Configuration - Partition Context Row.
     *
     * @param array $row - Persisted row.
     * @param array<string, array> $listSources - Package-wide Bypass sources.
     * @param array<string, string> $aliases - Existing aliases.
     *
     * @return array
     *
     * @since 1.3.0
     */
    public static function partitionContextRow(
        array $row,
        array $listSources,
        array $aliases = [],
    ): array {
        $context = is_string($row['context'] ?? null) ? $row['context'] : '';
        $settingsRow = $row;
        unset($settingsRow['context'], $settingsRow['enabled'], $settingsRow['lists']);
        $result = self::partition($settingsRow, ['context'], $aliases);
        unset($result['interfaces'], $result['lists'], $result['invalid_lists']);

        $storedEnabled = $row['enabled'] ?? '';
        $explicitlyEnabled = $storedEnabled === 'on' || $storedEnabled === true;

        if (!in_array($storedEnabled, ['', false, null, 'on', true], true)) {
            $result['invalid_values'][] = self::invalidValue(
                'enabled',
                $storedEnabled,
                new ValidationException('bypass_boolean_value_invalid'),
            );
        }

        $selection = $row['lists'] ?? [];

        if (is_array($selection) && count($selection) === 1 && array_key_exists('item', $selection)) {
            $selection = $selection['item'];
        }

        if ($selection === null || $selection === '') {
            $selection = [];
        }

        $selected = [];

        if (!is_array($selection)) {
            $result['invalid_values'][] = self::invalidValue(
                'lists',
                $selection,
                new ValidationException('selected_block_lists_invalid'),
            );
        } else {
            foreach ($selection as $identifier) {
                if (!is_string($identifier) || !isset($listSources[$identifier])) {
                    $result['invalid_values'][] = self::invalidValue(
                        'lists',
                        $identifier,
                        new ValidationException('bypass_list_missing'),
                    );

                    continue;
                }

                $selected[$identifier] = true;
            }
        }

        $dnsEnabled = ($result['dns_enabled'] ?? false) === true;
        $firewallEnabled = ($result['firewall_enabled'] ?? false) === true;
        $result['context'] = $context;
        $result['selected_lists'] = array_keys($selected);
        $result['enabled'] = $explicitlyEnabled;
        $result['dns_enabled'] = $result['enabled'] && $dnsEnabled;
        $result['firewall_enabled'] = $result['enabled'] && $firewallEnabled;

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

    /**
     * Bypass Configuration - Normalize Exemption Submission.
     *
     * Applies the saved-exemption contract to one WebGUI submission and rejects
     * the write when any line needs repair.
     *
     * @param string $exemptSourcesText - Submitted exempt-source lines.
     * @param string $exemptDestinationsText - Submitted exempt-destination lines.
     * @param array<string, string> $aliases - Existing host and network aliases.
     *
     * @return array{exempt_sources: list<string>, exempt_destinations: list<string>}
     *
     * @throws ValidationException When a submitted exemption is invalid.
     *
     * @since 1.2.0
     */
    public static function normalizeExemptionSubmission(
        string $exemptSourcesText,
        string $exemptDestinationsText,
        array $aliases,
    ): array {
        $sourceValues = RedirectConfiguration::nonEmptyLines(
            $exemptSourcesText,
            'exempt_sources_invalid',
        );
        $destinationValues = RedirectConfiguration::nonEmptyLines(
            $exemptDestinationsText,
            'exempt_destinations_invalid',
        );

        $partition = self::partition([
            'exempt_sources' => [
                'item' => $sourceValues,
            ],
            'exempt_destinations' => [
                'item' => $destinationValues,
            ],
        ], [], $aliases);

        if ($partition['invalid_exemptions'] !== []) {
            $invalidExemption = $partition['invalid_exemptions'][0];

            throw new ValidationException(
                $invalidExemption['reason_key'],
                $invalidExemption['reason_arguments'],
            );
        }

        return [
            'exempt_sources' => $partition['exempt_sources'],
            'exempt_destinations' => $partition['exempt_destinations'],
        ];
    }

    /**
     * Bypass Configuration - Effective Exemptions.
     *
     * Any invalid saved exemption drops every exemption, so the blocks keep
     * applying to all traffic until the saved values are repaired.
     *
     * @param array $configuration - Partitioned configuration.
     *
     * @return array{sources: list<string>, destinations: list<string>}
     *
     * @since 1.2.0
     */
    public static function effectiveExemptions(array $configuration): array
    {
        if (($configuration['invalid_exemptions'] ?? []) !== []) {
            return [
                'sources' => [],
                'destinations' => [],
            ];
        }

        $sources = is_array($configuration['exempt_sources'] ?? null)
            ? $configuration['exempt_sources']
            : [];
        $destinations = is_array($configuration['exempt_destinations'] ?? null)
            ? $configuration['exempt_destinations']
            : [];

        return [
            'sources' => array_values(array_filter($sources, 'is_string')),
            'destinations' => array_values(array_filter($destinations, 'is_string')),
        ];
    }

    /**
     * Bypass Configuration - Partition Exemptions.
     *
     * Reuses the redirect exemption rules and adds the alias limit that the
     * nested block anchors need.
     *
     * @param mixed $value - Persisted exemption list.
     * @param array<string, string> $aliases - Existing host and network aliases.
     * @param string $kind - Exemption kind, either source or destination.
     *
     * @return array{values: list<string>, stored: list<string>, invalid: list<array>}
     *
     * @since 1.2.0
     * @private
     */
    private static function partitionExemptions(
        mixed $value,
        array $aliases,
        string $kind,
    ): array {
        $partition = RedirectConfiguration::partitionExemptions(
            $value,
            $aliases,
            'block_exemptions',
            'block_exemptions',
            $kind,
        );
        $aliasValues = array_values(array_filter(
            $partition['values'],
            static fn (string $exemption): bool => isset($aliases[$exemption]),
        ));

        if (count($aliasValues) > self::MAXIMUM_EXEMPTION_ALIASES) {
            $partition['invalid'][] = self::invalidValue(
                'block_exemptions',
                implode(' ', $aliasValues),
                new ValidationException(
                    'bypass_exemption_aliases_limit',
                    [self::MAXIMUM_EXEMPTION_ALIASES],
                ),
            );
        }

        return $partition;
    }

    /** @since 1.3.0 */
    private static function contextStorage(string $context, array $settings): array
    {
        $storage = [
            'context' => $context,
            'enabled' => ($settings['enabled'] ?? false) === true ? 'on' : '',
        ];

        foreach (self::BOOLEAN_FIELDS as $field) {
            $storage[$field] = ($settings[$field] ?? false) === true ? 'on' : '';
        }

        $storage['discovery'] = is_string($settings['discovery'] ?? null)
            ? $settings['discovery']
            : self::DISCOVERY_OFF;
        $storage['lists'] = [
            'item' => array_values(array_filter(
                is_array($settings['selected_lists'] ?? null)
                    ? $settings['selected_lists']
                    : [],
                'is_string',
            )),
        ];

        foreach (['exempt_sources', 'exempt_destinations'] as $field) {
            $storage[$field] = [
                'item' => array_values(array_filter(
                    is_array($settings[$field] ?? null) ? $settings[$field] : [],
                    'is_string',
                )),
            ];
        }

        return $storage;
    }

    /** @since 1.3.0 */
    private static function listStorageRow(string $identifier, array $list): array
    {
        return [
            'id' => $identifier,
            'descr' => is_string($list['name'] ?? null) ? $list['name'] : '',
            'kind' => is_string($list['kind'] ?? null) ? $list['kind'] : '',
            'url' => is_string($list['url'] ?? null) ? $list['url'] : '',
            'enabled' => ($list['enabled'] ?? false) === true ? 'on' : '',
        ];
    }

    /** @since 1.3.0 */
    private static function unwrapRows(mixed $value): array
    {
        if (is_array($value) && count($value) === 1 && array_key_exists('item', $value)) {
            $value = $value['item'];
        }

        if (!is_array($value) || $value === []) {
            return [];
        }

        return array_key_exists('context', $value) ? [$value] : array_values($value);
    }

    /** @since 1.3.0 */
    private static function validOwnedContext(string $context): bool
    {
        return preg_match('/^(?:network|device):[a-f0-9]{32}$/D', $context) === 1;
    }

    /** @since 1.3.0 */
    private static function submitted(mixed $value): bool
    {
        // pfSense's Form_Checkbox posts "yes" by default.
        return in_array($value, ['yes', 'on', '1', 1, true], true);
    }

    /** @since 1.3.0 */
    private static function globalInterfaces(array $section): array
    {
        $value = $section['interfaces'] ?? [];

        if ($value === [] && function_exists('config_get_path')) {
            $value = config_get_path(
                'installedpackages/sinkhole/redirect/interfaces',
                [],
            );
        }

        if (is_array($value) && count($value) === 1 && array_key_exists('item', $value)) {
            $value = $value['item'];
        }

        return is_array($value)
            ? array_values(array_unique(array_filter($value, 'is_string')))
            : [];
    }

    /** @since 1.3.0 */
    private static function storedAliases(array $section): array
    {
        $aliases = [];

        foreach (['exempt_sources', 'exempt_destinations'] as $field) {
            $value = $section[$field] ?? [];

            if (is_array($value) && count($value) === 1 && array_key_exists('item', $value)) {
                $value = $value['item'];
            }

            foreach (is_array($value) ? $value : [] as $candidate) {
                if (
                    is_string($candidate)
                    && preg_match('/^[A-Za-z0-9_]{1,31}$/D', $candidate) === 1
                    && filter_var($candidate, FILTER_VALIDATE_IP) === false
                ) {
                    $aliases[$candidate] = 'network';
                }
            }
        }

        return $aliases;
    }

    /** @since 1.3.0 */
    private static function configuredAliases(array $fallbackSection): array
    {
        if (!function_exists('config_get_path')) {
            return self::storedAliases($fallbackSection);
        }

        $rows = config_get_path('aliases/alias', []);

        if (is_array($rows) && array_key_exists('name', $rows)) {
            $rows = [$rows];
        }

        $aliases = [];

        foreach (is_array($rows) ? $rows : [] as $row) {
            if (
                !is_array($row)
                || !is_string($row['name'] ?? null)
                || !is_string($row['type'] ?? null)
                || !in_array($row['type'], ['host', 'network'], true)
            ) {
                continue;
            }

            $aliases[$row['name']] = $row['type'];
        }

        return $aliases;
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
            'enabled' => 'bypass_protection',
            'lists' => 'bypass_lists',
            'interfaces' => 'interfaces',
            'block_exemptions' => 'block_exemptions',
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
