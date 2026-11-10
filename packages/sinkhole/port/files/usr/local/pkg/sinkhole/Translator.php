<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use RuntimeException;

/**
 * Translator.
 *
 * Translates package-owned text independently of pfSense's core gettext domain.
 * The catalog uses the exact language identifiers stored in system/language.
 *
 * @since 1.0.0
 */
final class Translator
{
    /** @since 1.0.0 */
    public const DEFAULT_LOCALE = 'en_US';

    /**
     * Closed mappings from runtime values to declared catalog keys.
     *
     * @var array<string, array<string, string>>
     * @since 1.0.0
     */
    private const TRANSLATION_KEY_MAPS = [
        'alert_form' => [
            'add' => 'add_alert_rule',
            'edit' => 'edit_alert_rule',
        ],
        'boolean' => [
            'false' => 'no',
            'true' => 'yes',
        ],
        'bypass_kind' => [
            'encrypted_dns' => 'encrypted_dns',
            'tor' => 'tor',
            'vpn' => 'vpn',
        ],
        'bypass_list_form' => [
            'add' => 'add_bypass_list',
            'edit' => 'edit_bypass_list',
        ],
        'catalog_category' => [
            'ads_trackers' => 'catalog_category_ads_trackers',
            'security' => 'catalog_category_security',
            'services_bypass' => 'catalog_category_services_bypass',
            'regional' => 'catalog_category_regional',
            'other' => 'catalog_category_other',
        ],
        'catalog_contents' => [
            'domains' => 'domains',
            'ipv4_addresses' => 'ipv4_addresses',
            'ipv6_addresses' => 'ipv6_addresses',
        ],
        'catalog_group' => [
            'category' => 'category',
            'maintainer' => 'maintainer',
        ],
        'client_status' => [
            'error' => 'status_error',
            'skipped' => 'status_skipped',
            'stopped' => 'status_stopped',
            'unchanged' => 'status_unchanged',
            'unknown' => 'status_unknown',
            'updated' => 'status_updated',
        ],
        'cli_failure' => [
            'redirect_check' => 'cli_redirect_check_failed',
            'update' => 'cli_update_failed',
        ],
        'device_form' => [
            'add' => 'add_device',
            'edit' => 'edit_device',
        ],
        'direction' => [
            'inbound' => 'inbound',
            'outbound' => 'outbound',
        ],
        'edition' => [
            'CE' => 'edition_ce',
            'Plus' => 'edition_plus',
        ],
        'field' => [
            'countries' => 'countries',
            'directions' => 'directions',
            'discovery' => 'discovery',
            'enable' => 'enable',
            'exempt_destination' => 'exempt_destination',
            'exempt_destinations' => 'exempt_destinations',
            'exempt_source' => 'exempt_source',
            'exempt_sources' => 'exempt_sources',
            'interface' => 'interface',
            'interfaces' => 'interfaces',
            'bypass_protection' => 'bypass_protection',
            'firefox' => 'firefox',
            'ip_allowlist' => 'ip_allowlist',
            'ip_country_blocking' => 'ip_country_blocking',
            'maxmind_account_id' => 'maxmind_account_id',
            'maxmind_license_key' => 'maxmind_license_key',
            'redirect_settings' => 'redirect_settings',
            'private_relay' => 'private_relay',
            'providers' => 'providers',
            'tls_and_quic' => 'tls_and_quic',
            'tor' => 'tor',
            'vpn' => 'vpn',
        ],
        'form_action' => [
            'add' => 'add',
            'edit' => 'save',
        ],
        'ip_family' => [
            'both' => 'both_families',
            'ipv4' => 'ipv4',
            'ipv6' => 'ipv6',
        ],
        'ip_list_form' => [
            'add' => 'add_ip_list',
            'edit' => 'edit_ip_list',
        ],
        'list_form' => [
            'add' => 'add_block_list',
            'edit' => 'edit_block_list',
        ],
        'network_form' => [
            'add' => 'add_network',
            'edit' => 'edit_network',
        ],
        'package_gui' => [
            'About' => 'about',
            'Alerts' => 'alerts',
            'Also send each new-version notice through configured pfSense remote notification services.' => 'update_remote_notifications_setting_help',
            'Check GitHub for new Sinkhole releases on a stable randomized schedule.' => 'update_check_help',
            'Choose how often enabled block lists update.' => 'update_frequency_help',
            'Daily' => 'daily',
            'Enable' => 'enable',
            'Enable scheduled list updates and DNS Resolver integration.' => 'enable_package_help',
            'Every 6 hours' => 'every_six_hours',
            'General' => 'general',
            'Hourly' => 'hourly',
            'IP' => 'ip',
            'Bypass' => 'bypass',
            'Keep Settings' => 'keep_settings',
            'Keep lists and settings when the package is removed.' => 'keep_settings_help',
            'Lists' => 'lists',
            'Monthly' => 'monthly',
            'Never' => 'never',
            'Package Updates' => 'package_updates',
            'Remote Notifications' => 'update_remote_notifications_setting',
            'Scopes' => 'scopes',
            'Services' => 'services',
            'Status' => 'status',
            'Update Checks' => 'update_checks',
            'Update Frequency' => 'update_frequency',
            'Weekly' => 'weekly',
        ],
        'redirect_check_status' => [
            'completed' => 'redirect_check_completed',
            'locked' => 'redirect_check_locked',
            'matching' => 'redirect_check_matching',
            'mismatch' => 'redirect_check_mismatch',
            'package-locked' => 'redirect_check_package_locked',
            'rejected' => 'redirect_check_rejected',
            'reloaded' => 'redirect_check_reloaded',
        ],
        'redirect_state' => [
            'off' => 'off',
            'on' => 'on',
            'paused' => 'paused',
        ],
        'resolver_reason' => [
            'dns_resolver_disabled' => 'dns_resolver_disabled',
            'dns_resolver_python_disabled' => 'dns_resolver_python_disabled',
            'dns_resolver_python_slot_owned' => 'dns_resolver_python_slot_owned',
            'sinkhole_disabled' => 'sinkhole_disabled',
            'sinkhole_not_resolver_owner' => 'sinkhole_not_resolver_owner',
            'sinkhole_resolver_position_invalid' => 'sinkhole_resolver_position_invalid',
            'sinkhole_runtime_unavailable' => 'sinkhole_runtime_unavailable',
        ],
        'resolver_state' => [
            'active' => 'active',
            'inactive' => 'inactive',
        ],
        'rule_state' => [
            'loaded' => 'yes',
            'missing' => 'no',
            'out_of_date' => 'out_of_date',
        ],
        'scope_kind' => [
            'device' => 'device',
            'network' => 'network',
            'unknown' => 'unknown',
        ],
        'secret_state' => [
            'set' => 'secret_is_set',
            'unset' => 'secret_is_not_set',
        ],
        'service_group' => [
            'ai' => 'service_group_ai',
            'cdn' => 'service_group_cdn',
            'dating' => 'service_group_dating',
            'gambling' => 'service_group_gambling',
            'gaming' => 'service_group_gaming',
            'hosting' => 'service_group_hosting',
            'messenger' => 'service_group_messenger',
            'privacy' => 'service_group_privacy',
            'shopping' => 'service_group_shopping',
            'social_network' => 'service_group_social_network',
            'software' => 'service_group_software',
            'streaming' => 'service_group_streaming',
        ],
        'tab' => [
            'about' => 'about',
            'alerts' => 'alerts',
            'bypass' => 'bypass',
            'general' => 'general',
            'ip' => 'ip',
            'lists' => 'lists',
            'services' => 'services',
            'scopes' => 'scopes',
            'status' => 'status',
        ],
        'toggle_action' => [
            'disabled' => 'enable',
            'enabled' => 'disable',
        ],
        'update_status' => [
            'completed' => 'status_completed',
            'disabled' => 'status_disabled',
            'stopped' => 'status_stopped',
            'unknown' => 'status_unknown',
            'warning' => 'status_warning',
        ],
        'validation' => [
            'alert_client_selection_required' => 'alert_client_selection_required',
            'alert_list_selection_required' => 'alert_list_selection_required',
            'alert_repeat_minutes_invalid' => 'alert_repeat_minutes_invalid',
            'alert_rule_description_invalid' => 'alert_rule_description_invalid',
            'alert_rule_identifier_invalid' => 'alert_rule_identifier_invalid',
            'alert_rule_missing' => 'alert_rule_missing',
            'allowed_domains_invalid_lines' => 'allowed_domains_invalid_lines',
            'block_list_identifier_invalid' => 'block_list_identifier_invalid',
            'block_list_missing' => 'block_list_missing',
            'block_list_name_invalid' => 'block_list_name_invalid',
            'block_list_url_invalid' => 'block_list_url_invalid',
            'block_list_url_scheme_invalid' => 'block_list_url_scheme_invalid',
            'bypass_boolean_value_invalid' => 'bypass_boolean_value_invalid',
            'bypass_discovery_tls_required' => 'bypass_discovery_tls_required',
            'bypass_discovery_value_invalid' => 'bypass_discovery_value_invalid',
            'bypass_interface_required' => 'bypass_interface_required',
            'bypass_list_kind_invalid' => 'bypass_list_kind_invalid',
            'bypass_list_missing' => 'bypass_list_missing',
            'catalog_entry_already_added' => 'catalog_entry_already_added',
            'catalog_entry_missing' => 'catalog_entry_missing',
            'device_identification_method_invalid' => 'device_identification_method_invalid',
            'device_identifier_duplicated' => 'device_identifier_duplicated',
            'device_identifier_invalid' => 'device_identifier_invalid',
            'device_ip_address_invalid' => 'device_ip_address_invalid',
            'device_mac_address_invalid' => 'device_mac_address_invalid',
            'device_missing' => 'device_missing',
            'device_name_invalid' => 'device_name_invalid',
            'dhcp_static_mapping_missing' => 'dhcp_static_mapping_missing',
            'exempt_destination_address_invalid' => 'exempt_destination_address_invalid',
            'exempt_destination_ascii_required' => 'exempt_destination_ascii_required',
            'exempt_destination_invalid' => 'exempt_destination_invalid',
            'exempt_destination_value_invalid' => 'exempt_destination_value_invalid',
            'exempt_destinations_invalid' => 'exempt_destinations_invalid',
            'exempt_source_address_invalid' => 'exempt_source_address_invalid',
            'exempt_source_ascii_required' => 'exempt_source_ascii_required',
            'exempt_source_invalid' => 'exempt_source_invalid',
            'exempt_source_value_invalid' => 'exempt_source_value_invalid',
            'exempt_sources_invalid' => 'exempt_sources_invalid',
            'invalid_alert_rule_missing' => 'invalid_alert_rule_missing',
            'invalid_block_list_row_missing' => 'invalid_block_list_row_missing',
            'invalid_bypass_list_row_missing' => 'invalid_bypass_list_row_missing',
            'invalid_device_row_missing' => 'invalid_device_row_missing',
            'invalid_ip_list_row_missing' => 'invalid_ip_list_row_missing',
            'invalid_network_row_missing' => 'invalid_network_row_missing',
            'invalid_scope_type_unknown' => 'invalid_scope_type_unknown',
            'ip_allowlist_invalid' => 'ip_allowlist_invalid',
            'ip_allowlist_value_invalid' => 'ip_allowlist_value_invalid',
            'ip_countries_invalid' => 'ip_countries_invalid',
            'ip_country_invalid' => 'ip_country_invalid',
            'ip_direction_invalid' => 'ip_direction_invalid',
            'ip_direction_required' => 'ip_direction_required',
            'ip_enable_value_invalid' => 'ip_enable_value_invalid',
            'ip_interface_not_configured' => 'ip_interface_not_configured',
            'ip_interface_required' => 'ip_interface_required',
            'ip_list_family_invalid' => 'ip_list_family_invalid',
            'ip_list_missing' => 'ip_list_missing',
            'maxmind_account_id_invalid' => 'maxmind_account_id_invalid',
            'maxmind_credentials_required' => 'maxmind_credentials_required',
            'maxmind_license_key_invalid' => 'maxmind_license_key_invalid',
            'network_identifier_invalid' => 'network_identifier_invalid',
            'network_interface_duplicated' => 'network_interface_duplicated',
            'network_interface_not_configured' => 'network_interface_not_configured',
            'network_missing' => 'network_missing',
            'redirect_enable_value_invalid' => 'redirect_enable_value_invalid',
            'redirect_interface_not_configured' => 'redirect_interface_not_configured',
            'redirect_interface_required' => 'redirect_interface_required',
            'redirect_interface_selection_invalid' => 'redirect_interface_selection_invalid',
            'saved_alert_rule_identifier_duplicated' => 'saved_alert_rule_identifier_duplicated',
            'saved_alert_rule_invalid' => 'saved_alert_rule_invalid',
            'saved_alert_rules_invalid' => 'saved_alert_rules_invalid',
            'saved_alert_selection_invalid' => 'saved_alert_selection_invalid',
            'saved_allowed_domain_invalid' => 'saved_allowed_domain_invalid',
            'saved_block_list_identifier_changed' => 'saved_block_list_identifier_changed',
            'saved_block_list_identifier_duplicated' => 'saved_block_list_identifier_duplicated',
            'saved_block_list_invalid' => 'saved_block_list_invalid',
            'saved_block_lists_invalid' => 'saved_block_lists_invalid',
            'saved_bypass_list_identifier_changed' => 'saved_bypass_list_identifier_changed',
            'saved_bypass_list_identifier_duplicated' => 'saved_bypass_list_identifier_duplicated',
            'saved_bypass_list_invalid' => 'saved_bypass_list_invalid',
            'saved_bypass_lists_invalid' => 'saved_bypass_lists_invalid',
            'saved_bypass_settings_invalid' => 'saved_bypass_settings_invalid',
            'saved_device_identifier_duplicated' => 'saved_device_identifier_duplicated',
            'saved_device_invalid' => 'saved_device_invalid',
            'saved_devices_invalid' => 'saved_devices_invalid',
            'saved_exempt_destinations_invalid' => 'saved_exempt_destinations_invalid',
            'saved_exempt_sources_invalid' => 'saved_exempt_sources_invalid',
            'saved_ip_list_identifier_changed' => 'saved_ip_list_identifier_changed',
            'saved_ip_list_identifier_duplicated' => 'saved_ip_list_identifier_duplicated',
            'saved_ip_list_invalid' => 'saved_ip_list_invalid',
            'saved_ip_lists_invalid' => 'saved_ip_lists_invalid',
            'saved_ip_settings_invalid' => 'saved_ip_settings_invalid',
            'saved_network_identifier_duplicated' => 'saved_network_identifier_duplicated',
            'saved_network_invalid' => 'saved_network_invalid',
            'saved_networks_invalid' => 'saved_networks_invalid',
            'saved_redirect_interfaces_invalid' => 'saved_redirect_interfaces_invalid',
            'saved_redirect_settings_invalid' => 'saved_redirect_settings_invalid',
            'scope_identifier_invalid' => 'scope_identifier_invalid',
            'select_dhcp_static_mapping' => 'select_dhcp_static_mapping',
            'selected_block_list_missing' => 'selected_block_list_missing',
            'selected_block_lists_invalid' => 'selected_block_lists_invalid',
            'selected_device_missing' => 'selected_device_missing',
            'selected_network_missing' => 'selected_network_missing',
            'update_frequency_invalid' => 'update_frequency_invalid',
        ],
    ];

    /** @var array<string, array<string, string>>|null @since 1.0.0 */
    private static ?array $catalogs = null;

    /**
     * Returns every pfSense language identifier supported by the package.
     *
     * @return list<string>
     *
     * @since 1.0.0
     */
    public static function supportedLocales(): array
    {
        return array_keys(self::catalogs());
    }

    /**
     * Returns the configured pfSense language or the English fallback.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function currentLocale(): string
    {
        $locale = self::DEFAULT_LOCALE;

        if (function_exists('config_get_path')) {
            $configuredLocale = config_get_path('system/language', self::DEFAULT_LOCALE);

            if (is_string($configuredLocale) && $configuredLocale !== '') {
                $locale = $configuredLocale;
            }
        }

        return array_key_exists($locale, self::catalogs()) ? $locale : self::DEFAULT_LOCALE;
    }

    /**
     * Translates one message for the configured pfSense language.
     *
     * @param string $key - Stable catalog key.
     * @param array<int, scalar|null> $arguments - Positional sprintf arguments.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function translate(string $key, array $arguments = []): string
    {
        return self::translateForLocale(self::currentLocale(), $key, $arguments);
    }

    /**
     * Translates a runtime value through one closed catalog-key mapping.
     *
     * @param string $map - Translation mapping name.
     * @param string $value - Runtime value to map.
     * @param array<int, scalar|null> $arguments - Positional sprintf arguments.
     * @param string|null $fallbackValue - Fixed mapped value used for unknown runtime values.
     *
     * @return string
     *
     * @throws RuntimeException When the mapping or mapped value is unknown.
     *
     * @since 1.0.0
     */
    public static function translateMapped(
        string $map,
        string $value,
        array $arguments = [],
        ?string $fallbackValue = null,
    ): string {
        if (!array_key_exists($map, self::TRANSLATION_KEY_MAPS)) {
            throw new RuntimeException(sprintf(
                'Unknown Sinkhole translation map "%s".',
                $map,
            ));
        }

        $mapping = self::TRANSLATION_KEY_MAPS[$map];
        $mappedValue = array_key_exists($value, $mapping) ? $value : $fallbackValue;

        if ($mappedValue === null || !array_key_exists($mappedValue, $mapping)) {
            throw new RuntimeException(sprintf(
                'Unknown value "%s" for Sinkhole translation map "%s".',
                $value,
                $map,
            ));
        }

        return self::translate($mapping[$mappedValue], $arguments);
    }

    /**
     * Translator - Service Group Name.
     *
     * Known registry identifiers use the closed catalog map, while identifiers
     * added upstream remain readable without trusting registry display text.
     *
     * @param string $identifier - Registry group identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function serviceGroupName(string $identifier): string
    {
        $mapping = self::TRANSLATION_KEY_MAPS['service_group'];

        if (array_key_exists($identifier, $mapping)) {
            return self::translate($mapping[$identifier]);
        }

        return ucfirst(str_replace('_', ' ', $identifier));
    }

    /**
     * Translates one message for an explicit pfSense language identifier.
     *
     * @param string $locale - pfSense language identifier.
     * @param string $key - Stable catalog key.
     * @param array<int, scalar|null> $arguments - Positional sprintf arguments.
     *
     * @return string
     *
     * @throws RuntimeException When the English source key is missing.
     *
     * @since 1.0.0
     */
    public static function translateForLocale(
        string $locale,
        string $key,
        array $arguments = [],
    ): string {
        $catalogs = self::catalogs();
        $selectedLocale = array_key_exists($locale, $catalogs)
            ? $locale
            : self::DEFAULT_LOCALE;

        if (!array_key_exists($key, $catalogs[self::DEFAULT_LOCALE])) {
            throw new RuntimeException(sprintf(
                'Unknown Sinkhole translation key "%s".',
                $key,
            ));
        }

        $template = $catalogs[$selectedLocale][$key]
            ?? $catalogs[self::DEFAULT_LOCALE][$key];
        $placeholderCount = self::placeholderCount($template);

        if (count($arguments) !== $placeholderCount) {
            throw new RuntimeException(sprintf(
                'Sinkhole translation key "%s" expects %d argument(s); received %d.',
                $key,
                $placeholderCount,
                count($arguments),
            ));
        }

        return ($arguments === []) ? $template : vsprintf($template, $arguments);
    }

    /**
     * Returns one explicit catalog, with each missing translation filled from English.
     *
     * @param string $locale - pfSense language identifier.
     *
     * @return array<string, string>
     *
     * @since 1.0.0
     */
    public static function catalogForLocale(string $locale): array
    {
        $catalogs = self::catalogs();
        $selectedCatalog = $catalogs[$locale] ?? [];

        return array_replace($catalogs[self::DEFAULT_LOCALE], $selectedCatalog);
    }

    /**
     * Loads the immutable package catalogs once.
     *
     * @return array<string, array<string, string>>
     *
     * @throws RuntimeException When the catalog source is malformed.
     *
     * @since 1.0.0
     * @private
     */
    private static function catalogs(): array
    {
        if (is_array(self::$catalogs)) {
            return self::$catalogs;
        }

        $catalogs = require(__DIR__ . '/Translations.php');

        if (!is_array($catalogs) || !isset($catalogs[self::DEFAULT_LOCALE])) {
            throw new RuntimeException('Sinkhole translation catalogs are invalid.');
        }

        self::$catalogs = $catalogs;

        return self::$catalogs;
    }

    /**
     * Returns the highest positional placeholder in one trusted catalog value.
     *
     * @param string $template - Catalog message template.
     *
     * @return int
     *
     * @since 1.0.0
     * @private
     */
    private static function placeholderCount(string $template): int
    {
        $matchCount = preg_match_all(
            '/%(?:(?<position>[1-9][0-9]*)\$)?[-+ 0\'#]*[0-9]*(?:\.[0-9]+)?[bcdeEfFgGosuxX]/',
            $template,
            $matches,
        );

        if ($matchCount === false || $matchCount === 0) {
            return 0;
        }

        $nextPosition = 1;
        $maximumPosition = 0;

        foreach ($matches['position'] as $position) {
            $resolvedPosition = ($position === '') ? $nextPosition : (int) $position;
            $maximumPosition = max($maximumPosition, $resolvedPosition);
            $nextPosition = $resolvedPosition + 1;
        }

        return $maximumPosition;
    }
}
