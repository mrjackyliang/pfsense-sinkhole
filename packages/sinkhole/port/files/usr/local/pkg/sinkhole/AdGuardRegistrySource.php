<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use PfSense\Sinkhole\Domain\Catalog;
use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\ServiceRegistry;
use RuntimeException;
use stdClass;

require_once(__DIR__ . '/Catalog.php');
require_once(__DIR__ . '/DomainParser.php');
require_once(__DIR__ . '/ServiceRegistry.php');

/**
 * AdGuard Registry Source.
 *
 * Owns AdGuard's HostlistsRegistry: the filter and blocked-service document URLs
 * and their JSON layout. Callers receive only normalized catalog entries and the
 * project's service registry, so an upstream format change touches this file alone.
 *
 * @since 1.3.3
 */
final class AdGuardRegistrySource
{
    /**
     * AdGuard Registry Source - Filters URL.
     *
     * This fixed endpoint is never derived from request or downloaded data.
     *
     * @var string
     *
     * @since 1.3.3
     */
    public const FILTERS_URL = 'https://adguardteam.github.io/HostlistsRegistry/assets/filters.json';

    /**
     * AdGuard Registry Source - Services URL.
     *
     * This fixed endpoint is never derived from request or downloaded data.
     *
     * @var string
     *
     * @since 1.3.3
     */
    public const SERVICES_URL = 'https://adguardteam.github.io/HostlistsRegistry/assets/services.json';

    /**
     * AdGuard Registry Source - Parse Filters.
     *
     * Uses only active filters and their download URL while keeping tag identifiers
     * bounded for the common entry shape.
     *
     * @param string $contents - Complete JSON document.
     *
     * @return list<array>
     *
     * @throws RuntimeException When the document has no filter list.
     *
     * @since 1.3.3
     */
    public static function parseFilters(string $contents): array
    {
        $document = Catalog::decodeDocument($contents);

        if (!isset($document->filters) || !is_array($document->filters)) {
            throw new RuntimeException('The AdGuard Home catalog is invalid.');
        }

        $groups = [];

        if (isset($document->groups) && !is_array($document->groups)) {
            throw new RuntimeException('The AdGuard Home catalog groups are invalid.');
        }

        foreach (array_slice($document->groups ?? [], 0, Catalog::MAXIMUM_GROUPS) as $groupValue) {
            $groupIdentifier = $groupValue instanceof stdClass
                ? ($groupValue->groupId ?? $groupValue->id ?? null)
                : null;
            $groupNameValue = $groupValue instanceof stdClass
                ? ($groupValue->groupName ?? $groupValue->name ?? null)
                : null;

            if (
                !$groupValue instanceof stdClass
                || (!is_int($groupIdentifier) && !is_string($groupIdentifier))
                || !is_string($groupNameValue)
            ) {
                continue;
            }

            $groupName = Catalog::normalizeText($groupNameValue, Catalog::MAXIMUM_GROUP_BYTES);

            if ($groupName !== null && $groupName !== '') {
                $groups[(string) $groupIdentifier] = $groupName;
            }
        }

        $entries = [];
        $filterCount = 0;

        foreach ($document->filters as $filter) {
            if ($filterCount >= Catalog::MAXIMUM_ENTRIES) {
                break;
            }

            $filterCount++;

            if (!$filter instanceof stdClass) {
                continue;
            }

            $deprecated = $filter->deprecated ?? false;

            if (!is_bool($deprecated) || $deprecated) {
                continue;
            }

            if (
                !is_string($filter->name ?? null)
                || !is_string($filter->downloadUrl ?? null)
            ) {
                continue;
            }

            $descriptionValue = $filter->description ?? '';
            $homepageValue = $filter->homepage ?? '';
            $tagsValue = $filter->tags ?? [];
            $groupIdValue = $filter->groupId ?? null;
            $filterKeyValue = $filter->filterKey ?? '';

            if (
                !is_string($descriptionValue)
                || !is_string($homepageValue)
                || !is_array($tagsValue)
                || ($groupIdValue !== null && !is_int($groupIdValue) && !is_string($groupIdValue))
                || (!is_int($filterKeyValue) && !is_string($filterKeyValue))
            ) {
                continue;
            }

            $name = Catalog::normalizeText($filter->name, Catalog::MAXIMUM_NAME_BYTES);
            $description = Catalog::normalizeText(
                $descriptionValue,
                Catalog::MAXIMUM_DESCRIPTION_BYTES,
            );
            $url = Catalog::normalizeListUrl($filter->downloadUrl);

            if ($name === null || $name === '' || $description === null || $url === null) {
                continue;
            }

            $tags = [];
            $tagCount = 0;

            foreach ($tagsValue as $tagValue) {
                if ($tagCount >= Catalog::MAXIMUM_TAGS) {
                    break;
                }

                $tagCount++;

                if (!is_int($tagValue) && !is_string($tagValue)) {
                    continue;
                }

                $tag = Catalog::normalizeText((string) $tagValue, Catalog::MAXIMUM_TAG_BYTES);

                if ($tag !== null && $tag !== '') {
                    $tags[] = $tag;
                }
            }

            $homepage = Catalog::normalizeHomepage($homepageValue);
            $group = ($groupIdValue === null) ? null : ($groups[(string) $groupIdValue] ?? null);
            $catalogKey = Catalog::normalizeText(
                (string) $filterKeyValue,
                Catalog::MAXIMUM_GROUP_BYTES,
            ) ?? '';
            $entries[] = [
                'name' => $name,
                'description' => $description,
                'homepage' => $homepage,
                'url' => $url,
                'source' => Catalog::sourceLabels()[Catalog::SOURCE_ADGUARD_HOME],
                'contents' => Catalog::contentsForSourceSection(
                    Catalog::SOURCE_ADGUARD_HOME,
                    'filters',
                ),
                'group' => $group,
                'tags' => $tags,
                'category' => Catalog::categoryForGroup(Catalog::SOURCE_ADGUARD_HOME, $group),
                'maintainer' => Catalog::maintainer($homepage),
                'source_key' => Catalog::SOURCE_ADGUARD_HOME,
                'catalog_section' => 'filters',
                'catalog_key' => $catalogKey,
            ];
        }

        return $entries;
    }

    /**
     * AdGuard Registry Source - Parse Services.
     *
     * Validates the blocked-services document against the registry's size bounds
     * and returns the project's registry shape.
     *
     * @param string $contents - Complete untrusted registry document.
     *
     * @return array{groups: array<string, true>, services: array<string, array{id: string, name: string, group: string, rules: list<array{domain: string, semantic: string}>, skipped_rules: int, icon_svg: string, icon_oversized: bool}>}
     *
     * @throws RuntimeException When the registry shape or a size bound is invalid.
     *
     * @since 1.3.3
     */
    public static function parseServices(string $contents): array
    {
        $document = json_decode($contents, false, 32, JSON_THROW_ON_ERROR);

        if (
            !$document instanceof stdClass
            || !is_array($document->blocked_services ?? null)
            || !is_array($document->groups ?? null)
        ) {
            throw new RuntimeException('The blocked-services registry is invalid.');
        }

        if (count($document->groups) > ServiceRegistry::MAXIMUM_GROUPS) {
            throw new RuntimeException('The blocked-services registry has too many groups.');
        }

        if (count($document->blocked_services) > ServiceRegistry::MAXIMUM_SERVICES) {
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

            $identifier = ServiceRegistry::normalizeIdentifier($group->id);

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

            if (count($service->rules) > ServiceRegistry::MAXIMUM_RULES_PER_SERVICE) {
                throw new RuntimeException('A blocked service has too many rules.');
            }

            $totalRuleCount += count($service->rules);

            if ($totalRuleCount > ServiceRegistry::MAXIMUM_TOTAL_RULES) {
                throw new RuntimeException('The blocked-services registry has too many rules.');
            }

            $identifier = ServiceRegistry::normalizeIdentifier($service->id);
            $name = ServiceRegistry::normalizeText($service->name, ServiceRegistry::MAXIMUM_NAME_BYTES);
            $groupIdentifier = ServiceRegistry::normalizeIdentifier($service->group);

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
                if (!is_string($rule) || strlen($rule) > ServiceRegistry::MAXIMUM_RULE_BYTES) {
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

            $iconOversized = strlen($service->icon_svg) > ServiceRegistry::MAXIMUM_ICON_BYTES;
            $icon = $iconOversized ? '' : $service->icon_svg;

            if ($icon !== '' && preg_match('//u', $icon) !== 1) {
                throw new RuntimeException('A blocked-service icon is invalid.');
            }

            if (in_array($identifier, ServiceRegistry::HIDDEN_SERVICE_IDENTIFIERS, true)) {
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
}
