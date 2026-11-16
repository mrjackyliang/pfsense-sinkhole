<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

require_once(__DIR__ . '/SafeSearchEngines.php');

/**
 * SafeSearch Configuration.
 *
 * Owns the list-valued XML shape of per-scope SafeSearch choices. A client
 * receives every choice from Global, its network and its device combined.
 *
 * @since 1.1.0
 */
final class SafeSearchConfiguration
{
    /**
     * SafeSearch Configuration - Partition.
     *
     * @param mixed $value - Untrusted saved configuration.
     *
     * @return array{global: list<string>, networks: array<string, list<string>>, devices: array<string, list<string>>}
     *
     * @since 1.1.0
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

        $configuration['global'] = SafeSearchEngines::normalizeSelection($value['global'] ?? []);

        foreach (['networks', 'devices'] as $kind) {
            $rows = self::unwrapItems($value[$kind] ?? []);

            foreach (is_array($rows) ? $rows : [] as $rowKey => $row) {
                if (
                    is_string($rowKey)
                    && preg_match('/^[a-f0-9]{32}$/D', $rowKey) === 1
                    && is_array($row)
                    && !array_key_exists('id', $row)
                ) {
                    $selection = SafeSearchEngines::normalizeSelection($row);
                } else {
                    $rowKey = is_array($row) && is_string($row['id'] ?? null) ? $row['id'] : '';
                    $selection = SafeSearchEngines::normalizeSelection(
                        is_array($row) ? ($row['engines'] ?? []) : [],
                    );
                }

                if (preg_match('/^[a-f0-9]{32}$/D', (string) $rowKey) !== 1 || $selection === []) {
                    continue;
                }

                $configuration[$kind][$rowKey] = $selection;
            }
        }

        return $configuration;
    }

    /**
     * SafeSearch Configuration - Storage.
     *
     * @param array $configuration - Canonical configuration.
     *
     * @return array
     *
     * @since 1.1.0
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
            foreach ($configuration[$kind] as $identifier => $engines) {
                $storage[$kind]['item'][] = [
                    'id' => $identifier,
                    'engines' => ['item' => $engines],
                ];
            }
        }

        return $storage;
    }

    /**
     * SafeSearch Configuration - Scope Selection.
     *
     * @param array $configuration - Canonical configuration.
     * @param string $scope - ``global``, ``network:<id>`` or ``device:<id>``.
     *
     * @return list<string>
     *
     * @since 1.1.0
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
     * SafeSearch Configuration - Replace Scope Selection.
     *
     * @param array $configuration - Canonical configuration.
     * @param string $scope - Stable scope value.
     * @param mixed $engines - Posted choice identifiers.
     *
     * @return array
     *
     * @since 1.1.0
     */
    public static function replaceScopeSelection(
        array $configuration,
        string $scope,
        mixed $engines,
    ): array {
        $configuration = self::partition($configuration);
        $selection = SafeSearchEngines::normalizeSelection($engines);

        if ($scope === 'global') {
            $configuration['global'] = $selection;

            return $configuration;
        }

        [$kind, $identifier] = self::scopeParts($scope);

        if ($selection === []) {
            unset($configuration[$kind][$identifier]);
        } else {
            $configuration[$kind][$identifier] = $selection;
        }

        return $configuration;
    }

    /**
     * SafeSearch Configuration - Choices In Use.
     *
     * @param array $configuration - Canonical configuration.
     * @param list<string> $networks - Enabled network scope identifiers.
     * @param list<string> $devices - Enabled device scope identifiers.
     *
     * @return list<string> Choices selected by Global or any listed scope.
     *
     * @since 1.1.0
     */
    public static function choicesInUse(array $configuration, array $networks, array $devices): array
    {
        $configuration = self::partition($configuration);
        $selected = $configuration['global'];

        foreach ($networks as $identifier) {
            $selected = array_merge($selected, $configuration['networks'][$identifier] ?? []);
        }

        foreach ($devices as $identifier) {
            $selected = array_merge($selected, $configuration['devices'][$identifier] ?? []);
        }

        $selected = array_flip($selected);

        return array_values(array_filter(
            SafeSearchEngines::identifiers(),
            static fn(string $identifier): bool => isset($selected[$identifier]),
        ));
    }

    /**
     * SafeSearch Configuration - Counts.
     *
     * @param array $configuration - Canonical configuration.
     *
     * @return array{global: int, networks: array<string, int>, devices: array<string, int>}
     *
     * @since 1.1.0
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
            foreach ($configuration[$kind] as $identifier => $engines) {
                $counts[$kind][$identifier] = count($engines);
            }
        }

        return $counts;
    }

    /** @return mixed @since 1.1.0 @private */
    private static function unwrapItems(mixed $value): mixed
    {
        if (is_array($value) && count($value) === 1 && array_key_exists('item', $value)) {
            return $value['item'];
        }

        return ($value === null || $value === '') ? [] : $value;
    }

    /** @return array{string, string} @since 1.1.0 @private */
    private static function scopeParts(string $scope): array
    {
        if (preg_match('/^(network|device):([a-f0-9]{32})$/D', $scope, $matches) !== 1) {
            throw new \InvalidArgumentException('The SafeSearch scope is invalid.');
        }

        return [$matches[1] . 's', $matches[2]];
    }
}
