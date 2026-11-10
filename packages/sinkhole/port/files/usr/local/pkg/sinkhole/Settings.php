<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

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
}
