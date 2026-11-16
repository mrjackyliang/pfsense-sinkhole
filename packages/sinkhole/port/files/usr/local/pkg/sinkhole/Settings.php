<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

require_once(__DIR__ . '/DomainParser.php');
require_once(__DIR__ . '/ValidationException.php');

/**
 * Settings.
 *
 * Normalizes the small general-settings contract at both WebGUI and run time.
 *
 * @since 1.0.0
 */
final class Settings
{
    /**
     * Settings - Frequencies.
     *
     * Only these fixed values can reach cron synchronization.
     *
     * @since 1.0.0
     */
    public const FREQUENCIES = [
        'hourly',
        'every_six_hours',
        'daily',
        'weekly',
    ];

    /**
     * Settings - From Storage.
     *
     * Persisted settings remain untrusted and unknown schedules are rejected before
     * the updater or lifecycle integration performs work.
     *
     * @param array $settings - Persisted settings.
     *
     * @return array{enabled: bool, update_frequency: string, keep_settings: bool}
     *
     * @throws InvalidArgumentException When the frequency is unsupported.
     *
     * @since 1.0.0
     */
    public static function fromStorage(array $settings): array
    {
        $frequency = $settings['update_frequency'] ?? 'daily';

        if (is_array($frequency)) {
            $frequency = $frequency[0] ?? 'daily';
        }

        $frequency = (string) $frequency;

        if (!in_array($frequency, self::FREQUENCIES, true)) {
            throw new ValidationException('update_frequency_invalid');
        }

        return [
            'enabled' => ($settings['enabled'] ?? '') === 'on',
            'update_frequency' => $frequency,
            'keep_settings' => count($settings) === 0
                || ($settings['keep_settings'] ?? '') === 'on',
        ];
    }

    /** @var int @since 1.1.0 */
    public const MAXIMUM_REBIND_EXCEPTIONS = 100;

    /** @var int @since 1.1.0 */
    public const MAXIMUM_SERVE_EXPIRED_TTL = 31536000;

    /** @var int @since 1.1.0 */
    public const MAXIMUM_SERVE_EXPIRED_CLIENT_TIMEOUT = 60000;

    /**
     * Settings - Resolver From Storage.
     *
     * Validates the General page's Resolver section. An empty number keeps the
     * Resolver's own default and writes nothing.
     *
     * @param array $settings - Persisted or posted settings.
     *
     * @return array{rebind_exceptions: list<string>, serve_expired_ttl: int|null, serve_expired_client_timeout: int|null}
     *
     * @throws ValidationException When a value is invalid.
     *
     * @since 1.1.0
     */
    public static function resolverFromStorage(array $settings): array
    {
        $rebindText = $settings['rebind_exceptions'] ?? '';
        $rebindText = is_string($rebindText) ? $rebindText : '';
        $rebind = DomainParser::normalizeAllowedDomains($rebindText);

        if ($rebind['invalid_lines'] !== []) {
            throw new ValidationException(
                'rebind_exceptions_invalid',
                [implode(', ', $rebind['invalid_lines'])],
            );
        }

        if (count($rebind['domains']) > self::MAXIMUM_REBIND_EXCEPTIONS) {
            throw new ValidationException(
                'rebind_exceptions_too_many',
                [self::MAXIMUM_REBIND_EXCEPTIONS],
            );
        }

        return [
            'rebind_exceptions' => $rebind['domains'],
            'serve_expired_ttl' => self::optionalInteger(
                $settings['serve_expired_ttl'] ?? '',
                self::MAXIMUM_SERVE_EXPIRED_TTL,
                'serve_expired_ttl_invalid',
            ),
            'serve_expired_client_timeout' => self::optionalInteger(
                $settings['serve_expired_client_timeout'] ?? '',
                self::MAXIMUM_SERVE_EXPIRED_CLIENT_TIMEOUT,
                'serve_expired_client_timeout_invalid',
            ),
        ];
    }

    /**
     * Settings - Resolver Directives.
     *
     * @param array{rebind_exceptions: list<string>, serve_expired_ttl: int|null, serve_expired_client_timeout: int|null} $resolver
     *     - Validated Resolver settings.
     *
     * @return list<string> Unbound ``server:`` directives in a fixed order.
     *
     * @since 1.1.0
     */
    public static function resolverDirectives(array $resolver): array
    {
        $directives = [];

        foreach ($resolver['rebind_exceptions'] as $domain) {
            $directives[] = 'private-domain: "' . $domain . '"';
        }

        if ($resolver['serve_expired_ttl'] !== null) {
            $directives[] = 'serve-expired-ttl: ' . $resolver['serve_expired_ttl'];
        }

        if ($resolver['serve_expired_client_timeout'] !== null) {
            $directives[] = 'serve-expired-client-timeout: '
                . $resolver['serve_expired_client_timeout'];
        }

        return $directives;
    }

    /**
     * Settings - Optional Integer.
     *
     * @param mixed $value - Untrusted value.
     * @param int $maximum - Inclusive upper bound.
     * @param string $errorKey - Catalog key for an invalid value.
     *
     * @return int|null
     *
     * @since 1.1.0
     * @private
     */
    private static function optionalInteger(mixed $value, int $maximum, string $errorKey): ?int
    {
        if (is_array($value)) {
            $value = $value[0] ?? '';
        }

        $value = trim((string) $value);

        if ($value === '') {
            return null;
        }

        if (preg_match('/^[0-9]{1,9}$/D', $value) !== 1 || (int) $value > $maximum) {
            throw new ValidationException($errorKey, [$maximum]);
        }

        return (int) $value;
    }
}
