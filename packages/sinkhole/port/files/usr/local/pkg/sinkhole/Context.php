<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

require_once(__DIR__ . '/Platform.php');
require_once(__DIR__ . '/Translator.php');

/**
 * Context.
 *
 * Names the place a settings page edits (Global, one network, one device, or the
 * read-only All overview) and renders the second tab row that switches between
 * them. The selection follows the user across tabs through the WebGUI session.
 *
 * @since 1.3.0
 */
final class Context
{
    /**
     * Context - Global Key.
     *
     * @since 1.3.0
     */
    public const GLOBAL = 'global';

    /**
     * Context - All Key.
     *
     * The read-only overview. Nothing is ever saved under it.
     *
     * @since 1.3.0
     */
    public const ALL = 'all';

    /**
     * Context - Session Key.
     *
     * @since 1.3.0
     */
    public const SESSION_KEY = 'sinkhole_context';

    /**
     * Context - Request Key.
     *
     * @since 1.3.0
     */
    public const REQUEST_KEY = 'context';

    /**
     * Context - Interface Descriptions.
     *
     * Cached pfSense interface descriptions used when a network row carries no
     * display name of its own.
     *
     * @var array<string, string>|null
     *
     * @since 1.3.0
     * @private
     */
    private static ?array $interfaceDescriptions = null;

    /**
     * Context - Parse.
     *
     * @param string $key - Context key.
     *
     * @return array{type: string, id: string}|null
     *
     * @since 1.3.0
     */
    public static function parse(string $key): ?array
    {
        if ($key === self::GLOBAL || $key === self::ALL) {
            return ['type' => $key, 'id' => ''];
        }

        if (preg_match('/^(network|device):([a-f0-9]{32})$/D', $key, $matches) !== 1) {
            return null;
        }

        return ['type' => $matches[1], 'id' => $matches[2]];
    }

    /**
     * Context - Current.
     *
     * Uses the submitted or linked context when it is valid and still exists,
     * otherwise the one remembered in the session, otherwise Global.
     *
     * @param array<string, array> $networks - Networks by ID.
     * @param array<string, array> $devices - Devices by ID.
     * @param bool $allowAll - Whether the page has an All overview.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function current(array $networks, array $devices, bool $allowAll): string
    {
        $candidates = [
            $_POST[self::REQUEST_KEY] ?? null,
            $_GET[self::REQUEST_KEY] ?? null,
            $_SESSION[self::SESSION_KEY] ?? null,
        ];

        foreach ($candidates as $candidate) {
            if (is_string($candidate) && self::exists($candidate, $networks, $devices, $allowAll)) {
                return $candidate;
            }
        }

        return self::GLOBAL;
    }

    /**
     * Context - Remember.
     *
     * pfSense closes the PHP session after authentication, so the write reopens
     * it briefly when its session helpers are available.
     *
     * @param string $key - Context key.
     *
     * @return void
     *
     * @since 1.3.0
     */
    public static function remember(string $key): void
    {
        if (self::parse($key) === null) {
            return;
        }

        if (isset($_SESSION) && ($_SESSION[self::SESSION_KEY] ?? null) === $key) {
            return;
        }

        $reopened = false;

        if (
            session_status() !== PHP_SESSION_ACTIVE
            && function_exists('phpsession_begin')
            && function_exists('phpsession_end')
        ) {
            phpsession_begin();
            $reopened = true;
        }

        $_SESSION[self::SESSION_KEY] = $key;

        if ($reopened) {
            phpsession_end(true);
        }
    }

    /**
     * Context - Label.
     *
     * @param string $key - Context key.
     * @param array<string, array> $networks - Networks by ID.
     * @param array<string, array> $devices - Devices by ID.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function label(string $key, array $networks, array $devices): string
    {
        $parsed = self::parse($key);

        if ($parsed === null) {
            return Translator::translate('unknown');
        }

        return match ($parsed['type']) {
            self::GLOBAL => Translator::translate('global'),
            self::ALL => Translator::translate('all'),
            'network' => isset($networks[$parsed['id']])
                ? Translator::translate('service_network_scope', [self::networkName($networks[$parsed['id']])])
                : Translator::translate('unavailable_network'),
            'device' => isset($devices[$parsed['id']])
                ? Translator::translate('service_device_scope', [self::deviceName($devices[$parsed['id']])])
                : Translator::translate('unavailable_device'),
            default => Translator::translate('unknown'),
        };
    }

    /**
     * Context - Network Name.
     *
     * A network is named after its pfSense interface description.
     *
     * @param array $network - Network row.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function networkName(array $network): string
    {
        if (is_string($network['name'] ?? null) && $network['name'] !== '') {
            return $network['name'];
        }

        $interface = is_string($network['interface'] ?? null) ? $network['interface'] : '';
        $descriptions = self::interfaceDescriptions();

        return ($descriptions[$interface] ?? '') !== ''
            ? $descriptions[$interface]
            : strtoupper($interface);
    }

    /**
     * Context - Device Name.
     *
     * @param array $device - Device row.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function deviceName(array $device): string
    {
        foreach (['name', 'descr'] as $field) {
            if (is_string($device[$field] ?? null) && $device[$field] !== '') {
                return $device[$field];
            }
        }

        return Translator::translate('unknown');
    }

    /**
     * Context - Link.
     *
     * @param string $page - Page path, such as ``sinkhole-blocking.php``.
     * @param string $key - Context key.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function link(string $page, string $key): string
    {
        return $page . '?' . self::REQUEST_KEY . '=' . rawurlencode($key);
    }

    /**
     * Context - Banner Text.
     *
     * @param string $current - Current context key.
     * @param array<string, array> $networks - Networks by ID.
     * @param array<string, array> $devices - Devices by ID.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function bannerText(string $current, array $networks, array $devices): string
    {
        $parsed = self::parse($current) ?? ['type' => self::GLOBAL, 'id' => ''];

        return match ($parsed['type']) {
            self::ALL => Translator::translate('context_banner_all'),
            'network' => Translator::translate('context_banner_network', [
                self::networkName($networks[$parsed['id']] ?? []),
            ]),
            'device' => Translator::translate('context_banner_device', [
                self::deviceName($devices[$parsed['id']] ?? []),
            ]),
            default => Translator::translate('context_banner_global'),
        };
    }

    /**
     * Context - Render Row.
     *
     * Builds the second tab row from pfSense's own nav-pills markup, the chips
     * for the selected kind, and the banner naming what the page edits.
     *
     * @param string $page - Page path the links point to.
     * @param string $current - Current context key.
     * @param array<string, array> $networks - Networks by ID.
     * @param array<string, array> $devices - Devices by ID.
     * @param bool $allowAll - Whether to offer the All overview.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function renderRow(
        string $page,
        string $current,
        array $networks,
        array $devices,
        bool $allowAll,
    ): string {
        $parsed = self::parse($current) ?? ['type' => self::GLOBAL, 'id' => ''];
        $kinds = [];

        if ($allowAll) {
            $kinds[] = [Translator::translate('all'), $parsed['type'] === self::ALL, self::link($page, self::ALL)];
        }

        $kinds[] = [
            Translator::translate('global'),
            $parsed['type'] === self::GLOBAL,
            self::link($page, self::GLOBAL),
        ];

        if ($networks !== []) {
            $kinds[] = [
                sprintf('%s (%d)', Translator::translate('networks'), count($networks)),
                $parsed['type'] === 'network',
                self::link($page, 'network:' . (string) array_key_first($networks)),
            ];
        }

        if ($devices !== []) {
            $kinds[] = [
                sprintf('%s (%d)', Translator::translate('devices'), count($devices)),
                $parsed['type'] === 'device',
                self::link($page, 'device:' . (string) array_key_first($devices)),
            ];
        }

        $html = '<div class="sinkhole-context">'
            . self::pills($kinds, 'sinkhole-context-kinds', '');

        if ($parsed['type'] === 'network') {
            $chips = [];

            foreach ($networks as $identifier => $network) {
                $chips[] = [
                    self::chipLabel(self::networkName($network), $network),
                    $identifier === $parsed['id'],
                    self::link($page, 'network:' . $identifier),
                ];
            }

            $html .= self::pills($chips, 'sinkhole-context-chips', '');
        } elseif ($parsed['type'] === 'device') {
            $chips = [];

            foreach ($devices as $identifier => $device) {
                $chips[] = [
                    self::chipLabel(self::deviceName($device), $device),
                    $identifier === $parsed['id'],
                    self::link($page, 'device:' . $identifier),
                ];
            }

            $html .= '<div class="sinkhole-context-search">'
                . '<input type="search" class="form-control input-sm" id="sinkhole-context-search"'
                . ' placeholder="' . self::escape(Translator::translate('context_search_devices')) . '"'
                . ' aria-label="' . self::escape(Translator::translate('context_search_devices')) . '">'
                . '</div>'
                . self::pills($chips, 'sinkhole-context-chips', 'sinkhole-context-devices')
                . '<script type="text/javascript">'
                . '//<![CDATA[' . "\n"
                . 'events.push(function() {'
                . '$(\'#sinkhole-context-search\').on(\'input\', function() {'
                . 'var query = $(this).val().toLowerCase();'
                . '$(\'#sinkhole-context-devices > li\').each(function() {'
                . 'var name = String($(this).attr(\'data-sinkhole-context-name\') || \'\');'
                . '$(this).toggle($(this).hasClass(\'active\') || name.indexOf(query) !== -1);'
                . '});'
                . '});'
                . '});' . "\n"
                . '//]]>'
                . '</script>';
        }

        $html .= '</div>';
        $html .= '<div class="alert alert-info sinkhole-context-banner" role="status">'
            . self::escape(self::bannerText($current, $networks, $devices))
            . '</div>';

        $row = null;

        if ($parsed['type'] === 'network') {
            $row = $networks[$parsed['id']] ?? null;
        } elseif ($parsed['type'] === 'device') {
            $row = $devices[$parsed['id']] ?? null;
        }

        if (is_array($row) && !self::enabled($row)) {
            $disabledText = ($parsed['type'] === 'network')
                ? Translator::translate('context_network_disabled')
                : Translator::translate('context_device_disabled');
            $html .= '<div class="alert alert-warning sinkhole-context-banner" role="status">'
                . self::escape($disabledText)
                . '</div>';
        }

        return $html;
    }

    /**
     * Context - Exists.
     *
     * @param string $key - Context key.
     * @param array<string, array> $networks - Networks by ID.
     * @param array<string, array> $devices - Devices by ID.
     * @param bool $allowAll - Whether All is accepted.
     *
     * @return bool
     *
     * @since 1.3.0
     * @private
     */
    private static function exists(string $key, array $networks, array $devices, bool $allowAll): bool
    {
        $parsed = self::parse($key);

        if ($parsed === null) {
            return false;
        }

        return match ($parsed['type']) {
            self::GLOBAL => true,
            self::ALL => $allowAll,
            'network' => isset($networks[$parsed['id']]),
            'device' => isset($devices[$parsed['id']]),
            default => false,
        };
    }

    /**
     * Context - Pills.
     *
     * Mirrors the markup pfSense's ``display_top_tabs()`` prints for a
     * second-level tab row.
     *
     * @param list<array{0: string, 1: bool, 2: string}> $items - Label, active flag, and link.
     * @param string $class - Package class for the row.
     * @param string $id - Optional element ID.
     *
     * @return string
     *
     * @since 1.3.0
     * @private
     */
    private static function pills(array $items, string $class, string $id): string
    {
        $html = '<ul class="nav nav-pills ' . self::escape($class) . '"'
            . (($id === '') ? '' : ' id="' . self::escape($id) . '"')
            . ' role="tablist">';

        foreach ($items as [$label, $active, $url]) {
            $html .= '<li role="presentation"'
                . ($active ? ' class="active"' : '')
                . ' data-sinkhole-context-name="' . self::escape(strtolower($label)) . '">'
                . '<a href="' . self::escape($url) . '">' . self::escape($label) . '</a>'
                . '</li>';
        }

        return $html . '</ul>';
    }

    /**
     * Context - Chip Label.
     *
     * @param string $name - Display name.
     * @param array $row - Network or device row.
     *
     * @return string
     *
     * @since 1.3.0
     * @private
     */
    private static function chipLabel(string $name, array $row): string
    {
        return self::enabled($row)
            ? $name
            : Translator::translate('context_disabled_suffix', [$name]);
    }

    /**
     * Context - Enabled.
     *
     * @param array $row - Network or device row.
     *
     * @return bool
     *
     * @since 1.3.0
     * @private
     */
    private static function enabled(array $row): bool
    {
        $enabled = $row['enabled'] ?? true;

        return $enabled === true || $enabled === 'on';
    }

    /**
     * Context - Interface Descriptions.
     *
     * @return array<string, string>
     *
     * @since 1.3.0
     * @private
     */
    private static function interfaceDescriptions(): array
    {
        if (is_array(self::$interfaceDescriptions)) {
            return self::$interfaceDescriptions;
        }

        $descriptions = [];

        foreach (Platform::adapter()->configuredInterfaceDescriptions() as $interface => $description) {
            if (is_string($interface) && is_string($description)) {
                $descriptions[$interface] = $description;
            }
        }

        self::$interfaceDescriptions = $descriptions;

        return $descriptions;
    }

    /**
     * Context - Escape.
     *
     * @param string $value - Text.
     *
     * @return string
     *
     * @since 1.3.0
     * @private
     */
    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
