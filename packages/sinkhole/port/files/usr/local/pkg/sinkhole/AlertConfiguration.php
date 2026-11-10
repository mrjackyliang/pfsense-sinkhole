<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

require_once(__DIR__ . '/ScopeConfiguration.php');
require_once(__DIR__ . '/ValidationException.php');

/**
 * Alert Configuration.
 *
 * Validates alert rules while retaining malformed saved rows for repair in the
 * WebGUI.
 *
 * @since 1.0.0
 */
final class AlertConfiguration
{
    /**
     * Alert Configuration - Generate Identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function generateIdentifier(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Alert Configuration - Partition Alerts.
     *
     * @param mixed $value - Persisted alert rows.
     * @param array<string, array> $lists - Valid block lists.
     * @param array<string, array> $networks - Valid network scopes.
     * @param array<string, array> $devices - Valid device scopes.
     *
     * @return array{alerts: array<string, array>, invalid_rows: list<array>}
     *
     * @since 1.0.0
     */
    public static function partitionAlerts(
        mixed $value,
        array $lists,
        array $networks,
        array $devices,
    ): array {
        if ($value === null || $value === '') {
            return ['alerts' => [], 'invalid_rows' => []];
        }

        if (!is_array($value)) {
            return [
                'alerts' => [],
                'invalid_rows' => [self::invalidRow(
                    0,
                    $value,
                    new ValidationException('saved_alert_rules_invalid'),
                )],
            ];
        }

        $alerts = [];
        $invalidRows = [];

        foreach (array_values($value) as $position => $row) {
            try {
                if (!is_array($row)) {
                    throw new ValidationException('saved_alert_rule_invalid');
                }

                $alert = self::normalizeRow($row, $lists, $networks, $devices);

                if (isset($alerts[$alert['id']])) {
                    throw new ValidationException('saved_alert_rule_identifier_duplicated');
                }

                $alerts[$alert['id']] = $alert;
            } catch (ValidationException $exception) {
                $invalidRows[] = self::invalidRow($position, $row, $exception);
            }
        }

        return ['alerts' => $alerts, 'invalid_rows' => $invalidRows];
    }

    /**
     * Alert Configuration - Normalize Row.
     *
     * @param array $row - Alert row.
     * @param array<string, array> $lists - Valid block lists.
     * @param array<string, array> $networks - Valid network scopes.
     * @param array<string, array> $devices - Valid device scopes.
     *
     * @return array{
     *     id: string,
     *     description: string,
     *     any_list: bool,
     *     lists: list<string>,
     *     everyone: bool,
     *     networks: list<string>,
     *     devices: list<string>,
     *     repeat_minutes: int,
     *     notice: bool,
     *     remote: bool,
     *     enabled: bool
     * }
     *
     * @since 1.0.0
     */
    public static function normalizeRow(
        array $row,
        array $lists,
        array $networks,
        array $devices,
    ): array {
        $identifier = is_string($row['id'] ?? null) ? $row['id'] : '';

        if (preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1) {
            throw new ValidationException('alert_rule_identifier_invalid');
        }

        $description = is_string($row['descr'] ?? null) ? trim($row['descr']) : '';

        if (
            $description === ''
            || strlen($description) > 128
            || preg_match('//u', $description) !== 1
            || preg_match('/[\x00-\x1f\x7f]/', $description) === 1
        ) {
            throw new ValidationException('alert_rule_description_invalid');
        }

        $anyList = self::checked($row['lists_any'] ?? null);
        $selectedLists = $anyList
            ? []
            : self::selection(
                $row['lists'] ?? [],
                $lists,
                'selected_block_list_missing',
            );

        if ($anyList === false && count($selectedLists) === 0) {
            throw new ValidationException('alert_list_selection_required');
        }

        $everyone = self::checked($row['clients_everyone'] ?? null);
        $selectedNetworks = $everyone
            ? []
            : self::selection(
                $row['networks'] ?? [],
                $networks,
                'selected_network_missing',
            );
        $selectedDevices = $everyone
            ? []
            : self::selection(
                $row['devices'] ?? [],
                $devices,
                'selected_device_missing',
            );

        if ($everyone === false && count($selectedNetworks) === 0 && count($selectedDevices) === 0) {
            throw new ValidationException('alert_client_selection_required');
        }

        $repeatValue = $row['repeat_minutes'] ?? 60;
        $repeatMinutes = filter_var(
            $repeatValue,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1, 'max_range' => 1440]],
        );

        if ($repeatMinutes === false) {
            throw new ValidationException('alert_repeat_minutes_invalid');
        }

        return [
            'id' => $identifier,
            'description' => $description,
            'any_list' => $anyList,
            'lists' => $anyList ? [] : $selectedLists,
            'everyone' => $everyone,
            'networks' => $everyone ? [] : $selectedNetworks,
            'devices' => $everyone ? [] : $selectedDevices,
            'repeat_minutes' => $repeatMinutes,
            'notice' => !array_key_exists('notice', $row) || self::checked($row['notice']),
            'remote' => !array_key_exists('remote', $row) || self::checked($row['remote']),
            'enabled' => self::checked($row['enabled'] ?? null),
        ];
    }

    /**
     * Alert Configuration - Selection.
     *
     * @param mixed $value - Repeated stored values or direct form values.
     * @param array<string, array> $available - Available rows by ID.
     * @param string $missingMessageKey - Missing-reference catalog key.
     *
     * @return list<string>
     *
     * @since 1.0.0
     * @private
     */
    private static function selection(
        mixed $value,
        array $available,
        string $missingMessageKey,
    ): array
    {
        $value = ScopeConfiguration::unwrapRepeatedItems($value);

        if ($value === []) {
            return [];
        }

        if (!is_array($value)) {
            throw new ValidationException('saved_alert_selection_invalid');
        }

        $selected = [];

        foreach ($value as $identifier) {
            if (!is_string($identifier) || !isset($available[$identifier])) {
                throw new ValidationException($missingMessageKey);
            }

            $selected[$identifier] = true;
        }

        return array_keys($selected);
    }

    /**
     * Alert Configuration - Checked.
     *
     * @param mixed $value - Checkbox value.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function checked(mixed $value): bool
    {
        return $value === true || $value === 'on';
    }

    /**
     * Alert Configuration - Invalid Row.
     *
     * @param int $position - Persisted row position.
     * @param mixed $row - Original row.
     * @param ValidationException $exception - Validation failure.
     *
     * @return array
     *
     * @since 1.0.0
     * @private
     */
    private static function invalidRow(
        int $position,
        mixed $row,
        ValidationException $exception,
    ): array
    {
        return [
            'position' => $position,
            'id' => is_array($row) && is_string($row['id'] ?? null) ? $row['id'] : '',
            'description' => is_array($row) && is_string($row['descr'] ?? null)
                ? $row['descr']
                : '',
            'enabled' => is_array($row) && self::checked($row['enabled'] ?? null),
            'reason' => $exception->getMessage(),
            'reason_key' => $exception->messageKey(),
            'reason_arguments' => $exception->messageArguments(),
            'row' => $row,
        ];
    }
}
