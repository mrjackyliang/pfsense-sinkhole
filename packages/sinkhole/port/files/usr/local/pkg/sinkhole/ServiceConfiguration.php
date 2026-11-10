<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

require_once(__DIR__ . '/ServiceRegistry.php');

/**
 * Blocked Service Configuration.
 *
 * Owns the list-valued XML shape and deliberately retains syntactically valid
 * service IDs that are absent from the current registry for administrator repair.
 *
 * @since 1.0.0
 */
final class ServiceConfiguration
{
    /** @var int @since 1.0.0 */
    public const MAXIMUM_SELECTIONS_PER_SCOPE = ServiceRegistry::MAXIMUM_SERVICES;

    /**
     * Blocked Service Configuration - Partition.
     *
     * @param mixed $value - Untrusted saved configuration.
     *
     * @return array{global: list<string>, networks: array<string, list<string>>, devices: array<string, list<string>>}
     *
     * @since 1.0.0
     */
    public static function partition(mixed $value): array
    {
        $configuration = [
            'global' => [],
            'networks' => [],
            'devices' => [],
        ];

        if (!is_array($value)) {
            return $configuration;
        }

        $configuration['global'] = self::selection($value['global'] ?? []);

        foreach (['networks', 'devices'] as $kind) {
            $rows = self::unwrapItems($value[$kind] ?? []);

            foreach (is_array($rows) ? $rows : [] as $rowKey => $row) {
                if (
                    is_string($rowKey)
                    && preg_match('/^[a-f0-9]{32}$/D', $rowKey) === 1
                    && is_array($row)
                    && !array_key_exists('id', $row)
                ) {
                    $configuration[$kind][$rowKey] = self::selection($row);
                    continue;
                }

                $identifier = is_array($row) && is_string($row['id'] ?? null)
                    ? $row['id']
                    : '';

                if ($identifier === '' || preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1) {
                    continue;
                }

                $configuration[$kind][$identifier] = self::selection($row['services'] ?? []);
            }
        }

        return $configuration;
    }

    /**
     * Blocked Service Configuration - Storage.
     *
     * @param array $configuration - Canonical configuration.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public static function storage(array $configuration): array
    {
        $configuration = self::partition($configuration);
        $storage = [
            'global' => ['item' => $configuration['global']],
            'networks' => ['item' => []],
            'devices' => ['item' => []],
        ];

        foreach (['networks', 'devices'] as $kind) {
            foreach ($configuration[$kind] as $identifier => $services) {
                $storage[$kind]['item'][] = [
                    'id' => $identifier,
                    'services' => ['item' => $services],
                ];
            }
        }

        return $storage;
    }

    /**
     * Blocked Service Configuration - Scope Selection.
     *
     * @param array $configuration - Canonical configuration.
     * @param string $scope - ``global``, ``network:<id>`` or ``device:<id>``.
     *
     * @return list<string>
     *
     * @since 1.0.0
     */
    public static function scopeSelection(array $configuration, string $scope): array
    {
        $configuration = self::partition($configuration);

        if ($scope === 'global') {
            return $configuration['global'];
        }

        [$kind, $identifier] = self::scopeParts($scope);

        return $configuration[$kind][$identifier] ?? [];
    }

    /**
     * Blocked Service Configuration - Replace Scope Selection.
     *
     * @param array $configuration - Canonical configuration.
     * @param string $scope - Stable scope value.
     * @param mixed $services - Posted service identifiers.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public static function replaceScopeSelection(
        array $configuration,
        string $scope,
        mixed $services,
    ): array {
        $configuration = self::partition($configuration);
        $selection = self::selection($services);

        if ($scope === 'global') {
            $configuration['global'] = $selection;

            return $configuration;
        }

        [$kind, $identifier] = self::scopeParts($scope);
        $configuration[$kind][$identifier] = $selection;

        return $configuration;
    }

    /**
     * Blocked Service Configuration - Counts.
     *
     * @param array $configuration - Canonical configuration.
     *
     * @return array{global: int, networks: array<string, int>, devices: array<string, int>}
     *
     * @since 1.0.0
     */
    public static function counts(array $configuration): array
    {
        $configuration = self::partition($configuration);
        $counts = [
            'global' => count($configuration['global']),
            'networks' => [],
            'devices' => [],
        ];

        foreach (['networks', 'devices'] as $kind) {
            foreach ($configuration[$kind] as $identifier => $services) {
                $counts[$kind][$identifier] = count($services);
            }
        }

        return $counts;
    }

    /** @return list<string> @since 1.0.0 @private */
    private static function selection(mixed $value): array
    {
        $value = self::unwrapItems($value);
        $selected = [];

        foreach (is_array($value) ? $value : [] as $identifier) {
            if (
                ServiceRegistry::isIdentifier($identifier)
                && !in_array(
                    $identifier,
                    ServiceRegistry::HIDDEN_SERVICE_IDENTIFIERS,
                    true,
                )
            ) {
                $selected[$identifier] = true;
            }

            if (count($selected) >= self::MAXIMUM_SELECTIONS_PER_SCOPE) {
                break;
            }
        }

        $identifiers = array_keys($selected);
        sort($identifiers, SORT_STRING);

        return $identifiers;
    }

    /** @return mixed @since 1.0.0 @private */
    private static function unwrapItems(mixed $value): mixed
    {
        if (is_array($value) && count($value) === 1 && array_key_exists('item', $value)) {
            return $value['item'];
        }

        return ($value === null || $value === '') ? [] : $value;
    }

    /** @return array{string, string} @since 1.0.0 @private */
    private static function scopeParts(string $scope): array
    {
        if (preg_match('/^(network|device):([a-f0-9]{32})$/D', $scope, $matches) !== 1) {
            throw new \InvalidArgumentException('The blocked-service scope is invalid.');
        }

        return [$matches[1] . 's', $matches[2]];
    }
}
