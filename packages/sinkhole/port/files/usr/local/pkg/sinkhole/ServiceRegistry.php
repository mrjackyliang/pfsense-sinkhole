<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use RuntimeException;
use stdClass;

require_once(__DIR__ . '/DomainParser.php');

/**
 * Blocked Service Registry.
 *
 * Validates and bounds AdGuard Home's service registry while converting accepted
 * rules to the same normalized domain semantics used by downloaded lists.
 *
 * @since 1.0.0
 */
final class ServiceRegistry
{
    /**
     * Blocked Service Registry - Hidden Service Identifiers.
     *
     * Stable registry IDs covered by a dedicated Bypass protection never enter
     * Services presentation, selection counts, search, or compilation.
     *
     * @var list<string>
     *
     * @since 1.0.0
     */
    public const HIDDEN_SERVICE_IDENTIFIERS = ['icloud_private_relay'];

    /** @var int @since 1.0.0 */
    public const MAXIMUM_SERVICES = 512;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_GROUPS = 64;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_RULES_PER_SERVICE = 1024;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_TOTAL_RULES = 65536;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_ICON_BYTES = 32768;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_SEARCH_BYTES = 256;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_IDENTIFIER_BYTES = 128;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_NAME_BYTES = 256;

    /** @var int @since 1.0.0 */
    private const MAXIMUM_RULE_BYTES = 8192;

    /**
     * Blocked Service Registry - Parse.
     *
     * @param string $contents - Complete untrusted registry document.
     *
     * @return array{groups: array<string, true>, services: array<string, array{id: string, name: string, group: string, rules: list<array{domain: string, semantic: string}>, skipped_rules: int, icon_svg: string, icon_oversized: bool}>}
     *
     * @throws RuntimeException When the registry shape or a size bound is invalid.
     *
     * @since 1.0.0
     */
    public static function parse(string $contents): array
    {
        $document = json_decode($contents, false, 32, JSON_THROW_ON_ERROR);

        if (
            !$document instanceof stdClass
            || !is_array($document->blocked_services ?? null)
            || !is_array($document->groups ?? null)
        ) {
            throw new RuntimeException('The blocked-services registry is invalid.');
        }

        if (count($document->groups) > self::MAXIMUM_GROUPS) {
            throw new RuntimeException('The blocked-services registry has too many groups.');
        }

        if (count($document->blocked_services) > self::MAXIMUM_SERVICES) {
            throw new RuntimeException('The blocked-services registry has too many services.');
        }

        $groups = [];

        foreach ($document->groups as $group) {
            if (
                !$group instanceof stdClass
                || !is_string($group->id ?? null)
                || (
                    property_exists($group, 'name')
                    && !is_string($group->name)
                )
            ) {
                throw new RuntimeException('A blocked-services group is invalid.');
            }

            $identifier = self::normalizeIdentifier($group->id);

            if ($identifier === null || isset($groups[$identifier])) {
                throw new RuntimeException('A blocked-services group is invalid.');
            }

            $groups[$identifier] = true;
        }

        $parser = new DomainParser();
        $services = [];
        $serviceIdentifiers = [];
        $totalRuleCount = 0;

        foreach ($document->blocked_services as $service) {
            if (
                !$service instanceof stdClass
                || !is_string($service->id ?? null)
                || !is_string($service->name ?? null)
                || !is_string($service->group ?? null)
                || !is_array($service->rules ?? null)
                || !is_string($service->icon_svg ?? null)
            ) {
                throw new RuntimeException('A blocked service is invalid.');
            }

            if (count($service->rules) > self::MAXIMUM_RULES_PER_SERVICE) {
                throw new RuntimeException('A blocked service has too many rules.');
            }

            $totalRuleCount += count($service->rules);

            if ($totalRuleCount > self::MAXIMUM_TOTAL_RULES) {
                throw new RuntimeException('The blocked-services registry has too many rules.');
            }

            $identifier = self::normalizeIdentifier($service->id);
            $name = self::normalizeText($service->name, self::MAXIMUM_NAME_BYTES);
            $groupIdentifier = self::normalizeIdentifier($service->group);

            if (
                $identifier === null
                || $name === null
                || $name === ''
                || $groupIdentifier === null
                || !isset($groups[$groupIdentifier])
                || isset($serviceIdentifiers[$identifier])
            ) {
                throw new RuntimeException('A blocked service is invalid.');
            }

            $serviceIdentifiers[$identifier] = true;

            $rules = [];
            $skippedRules = 0;

            foreach ($service->rules as $rule) {
                if (!is_string($rule) || strlen($rule) > self::MAXIMUM_RULE_BYTES) {
                    throw new RuntimeException('A blocked-service rule is invalid or oversized.');
                }

                $entries = $parser->parseLineEntries($rule);

                if ($entries === []) {
                    $skippedRules++;
                    continue;
                }

                foreach ($entries as $entry) {
                    $rules[$entry['semantic'] . "\0" . $entry['domain']] = $entry;
                }
            }

            $iconOversized = strlen($service->icon_svg) > self::MAXIMUM_ICON_BYTES;
            $icon = $iconOversized ? '' : $service->icon_svg;

            if ($icon !== '' && preg_match('//u', $icon) !== 1) {
                throw new RuntimeException('A blocked-service icon is invalid.');
            }

            if (in_array($identifier, self::HIDDEN_SERVICE_IDENTIFIERS, true)) {
                continue;
            }

            $services[$identifier] = [
                'id' => $identifier,
                'name' => $name,
                'group' => $groupIdentifier,
                'rules' => array_values($rules),
                'skipped_rules' => $skippedRules,
                'icon_svg' => $icon,
                'icon_oversized' => $iconOversized,
            ];
        }

        uasort($services, static fn(array $first, array $second): int =>
            strcasecmp($first['name'], $second['name']) ?: strcmp($first['id'], $second['id']));

        return [
            'groups' => $groups,
            'services' => $services,
        ];
    }

    /**
     * Blocked Service Registry - Empty Registry.
     *
     * @return array{groups: array, services: array}
     *
     * @since 1.0.0
     */
    public static function emptyRegistry(): array
    {
        return ['groups' => [], 'services' => []];
    }

    /**
     * Blocked Service Registry - Identifier.
     *
     * @param mixed $value - Candidate service or group identifier.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function isIdentifier(mixed $value): bool
    {
        return is_string($value) && self::normalizeIdentifier($value) !== null;
    }

    /**
     * Blocked Service Registry - Normalize Search Query.
     *
     * @param string $query - Untrusted search text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function normalizeSearchQuery(string $query): string
    {
        return self::normalizeText($query, self::MAXIMUM_SEARCH_BYTES) ?? '';
    }

    /**
     * Blocked Service Registry - Synthetic List Identifier.
     *
     * @param string $serviceIdentifier - Valid service identifier.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function syntheticListIdentifier(string $serviceIdentifier): string
    {
        if (!self::isIdentifier($serviceIdentifier)) {
            throw new RuntimeException('The blocked-service identifier is invalid.');
        }

        return substr(hash('sha256', "blocked-service\0" . $serviceIdentifier), 0, 32);
    }

    /**
     * Blocked Service Registry - Faceted View.
     *
     * @param array $registry - Parsed registry.
     * @param string $query - Search text.
     * @param string $group - Selected registry group.
     *
     * @return array{services: list<array>, groups: list<array{id: string, count: int}>, group_counts: array<string, int>}
     *
     * @since 1.0.0
     */
    public static function facetedView(array $registry, string $query, string $group): array
    {
        $query = self::normalizeSearchQuery($query);
        $groups = is_array($registry['groups'] ?? null) ? $registry['groups'] : [];
        $services = is_array($registry['services'] ?? null) ? $registry['services'] : [];
        $group = isset($groups[$group]) ? $group : '';
        $matchingSearch = [];

        foreach ($services as $service) {
            if (!is_array($service) || !is_string($service['name'] ?? null)) {
                continue;
            }

            if ($query !== '' && self::contains($service['name'], $query) === false) {
                continue;
            }

            $matchingSearch[] = $service;
        }

        $counts = ['' => count($matchingSearch)];

        foreach (array_keys($groups) as $identifier) {
            $counts[$identifier] = 0;
        }

        foreach ($matchingSearch as $service) {
            if (isset($counts[$service['group']])) {
                $counts[$service['group']]++;
            }
        }

        $filtered = array_values(array_filter(
            $matchingSearch,
            static fn(array $service): bool => $group === '' || $service['group'] === $group,
        ));
        $groupRows = [];

        foreach (array_keys($groups) as $identifier) {
            if (($counts[$identifier] ?? 0) > 0) {
                $groupRows[] = [
                    'id' => $identifier,
                    'count' => $counts[$identifier],
                ];
            }
        }

        return [
            'services' => $filtered,
            'groups' => $groupRows,
            'group_counts' => $counts,
        ];
    }

    /** @return string|null @since 1.0.0 @private */
    private static function normalizeIdentifier(string $value): ?string
    {
        $value = trim($value);

        if (
            strlen($value) > self::MAXIMUM_IDENTIFIER_BYTES
            || preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]*$/D', $value) !== 1
        ) {
            return null;
        }

        return $value;
    }

    /** @return string|null @since 1.0.0 @private */
    private static function normalizeText(string $value, int $maximumBytes): ?string
    {
        $value = trim($value);

        if (
            preg_match('//u', $value) !== 1
            || preg_match('/[\x00-\x1f\x7f]/', $value) === 1
        ) {
            return null;
        }

        if (strlen($value) <= $maximumBytes) {
            return $value;
        }

        if (function_exists('mb_strcut')) {
            return mb_strcut($value, 0, $maximumBytes, 'UTF-8');
        }

        $value = substr($value, 0, $maximumBytes);

        while ($value !== '' && preg_match('//u', $value) !== 1) {
            $value = substr($value, 0, -1);
        }

        return $value;
    }

    /** @since 1.0.0 @private */
    private static function contains(string $haystack, string $needle): bool
    {
        if (function_exists('mb_stripos')) {
            return mb_stripos($haystack, $needle, 0, 'UTF-8') !== false;
        }

        return stripos($haystack, $needle) !== false;
    }
}
