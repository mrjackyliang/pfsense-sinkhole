<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use RuntimeException;
use stdClass;

require_once(__DIR__ . '/BypassConfiguration.php');
require_once(__DIR__ . '/ListConfiguration.php');
require_once(__DIR__ . '/ValidationException.php');

/**
 * Catalog.
 *
 * Converts both supported catalog formats into bounded, validated entries and
 * owns search, duplicate, ordinary-list, IP-list, and Bypass List creation policy.
 *
 * @since 1.0.0
 */
final class Catalog
{
    /** @var string @since 1.0.0 */
    public const CATEGORY_ADS_TRACKERS = 'ads_trackers';

    /** @var string @since 1.0.0 */
    public const CATEGORY_SECURITY = 'security';

    /** @var string @since 1.0.0 */
    public const CATEGORY_SERVICES_BYPASS = 'services_bypass';

    /** @var string @since 1.0.0 */
    public const CATEGORY_REGIONAL = 'regional';

    /** @var string @since 1.0.0 */
    public const CATEGORY_OTHER = 'other';

    /** @var string @since 1.0.0 */
    public const GROUP_BY_CATEGORY = 'category';

    /** @var string @since 1.0.0 */
    public const GROUP_BY_MAINTAINER = 'maintainer';

    /**
     * Catalog - AdGuard Home Source.
     *
     * The stable key selects the matching parser and cache without trusting a
     * request value as a display label.
     *
     * @since 1.0.0
     */
    public const SOURCE_ADGUARD_HOME = 'adguard_home';

    /**
     * Catalog - pfBlockerNG Source.
     *
     * The stable key selects the pfBlockerNG document; DNS and IP callers choose
     * their own non-overlapping sections.
     *
     * @since 1.0.0
     */
    public const SOURCE_PFBLOCKERNG = 'pfblockerng';

    /**
     * Catalog - Domain Contents.
     *
     * The stable value identifies catalog entries whose downloaded rows contain
     * domain names rather than address-family values.
     *
     * @since 1.0.0
     */
    public const CONTENTS_DOMAINS = 'domains';

    /**
     * Catalog - IPv4 Contents.
     *
     * The stable value identifies catalog entries whose downloaded rows contain
     * IPv4 addresses or networks.
     *
     * @since 1.0.0
     */
    public const CONTENTS_IPV4_ADDRESSES = 'ipv4_addresses';

    /**
     * Catalog - IPv6 Contents.
     *
     * The stable value identifies catalog entries whose downloaded rows contain
     * IPv6 addresses or networks.
     *
     * @since 1.0.0
     */
    public const CONTENTS_IPV6_ADDRESSES = 'ipv6_addresses';

    /**
     * Catalog - Maximum Entries.
     *
     * A source cannot make search retain an unbounded number of candidates.
     *
     * @since 1.0.0
     */
    public const MAXIMUM_ENTRIES = 1000;

    /**
     * Catalog - Maximum Groups.
     *
     * Group traversal stops before an unexpected source can expand work without
     * bound.
     *
     * @since 1.0.0
     */
    public const MAXIMUM_GROUPS = 256;

    /**
     * Catalog - Maximum Tags.
     *
     * Registry tag identifiers are retained only up to this per-entry bound.
     *
     * @since 1.0.0
     */
    public const MAXIMUM_TAGS = 32;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_NAME_BYTES = 128;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_DESCRIPTION_BYTES = 1024;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_GROUP_BYTES = 128;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_TAG_BYTES = 64;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_SEARCH_BYTES = 256;

    /** @var int @since 1.0.0 */
    public const MAXIMUM_SEARCH_RESULTS = 500;

    /** @var string @since 1.0.0 */
    private const VALIDATION_IDENTIFIER = '00000000000000000000000000000000';

    /** @var string @since 1.0.0 */
    private const VALIDATION_NAME = 'Catalog entry';

    /** @var array<string, string> @since 1.0.0 */
    private const ADGUARD_CATEGORIES = [
        'General' => self::CATEGORY_ADS_TRACKERS,
        'Security' => self::CATEGORY_SECURITY,
        'Regional' => self::CATEGORY_REGIONAL,
        'Other' => self::CATEGORY_OTHER,
    ];

    /** @var array<string, string> @since 1.0.0 */
    private const PFBLOCKERNG_CATEGORIES = [
        'EasyList' => self::CATEGORY_ADS_TRACKERS,
        'ADs' => self::CATEGORY_ADS_TRACKERS,
        'ADs_Basic' => self::CATEGORY_ADS_TRACKERS,
        'Firebog_Advertising' => self::CATEGORY_ADS_TRACKERS,
        'Firebog_Trackers' => self::CATEGORY_ADS_TRACKERS,
        'Compilation' => self::CATEGORY_ADS_TRACKERS,
        'Malicious' => self::CATEGORY_SECURITY,
        'Malicious2' => self::CATEGORY_SECURITY,
        'Phishing' => self::CATEGORY_SECURITY,
        'Cryptojackers' => self::CATEGORY_SECURITY,
        'Firebog_Malicious' => self::CATEGORY_SECURITY,
        'Firebog_Suspicious' => self::CATEGORY_SECURITY,
        'BBcan177' => self::CATEGORY_SECURITY,
        'BBC' => self::CATEGORY_SECURITY,
        'STUN' => self::CATEGORY_SERVICES_BYPASS,
        'Skype_Resolvers' => self::CATEGORY_SERVICES_BYPASS,
        'Torrent' => self::CATEGORY_SERVICES_BYPASS,
        'URL_Shorteners' => self::CATEGORY_SERVICES_BYPASS,
        'Email' => self::CATEGORY_SERVICES_BYPASS,
        'Firebog_Other' => self::CATEGORY_OTHER,
    ];

    /**
     * Catalog - Bypass Kind Mappings.
     *
     * Stable source sections and group or filter keys own the classification;
     * downloaded URLs never decide which Bypass protection uses an entry.
     *
     * @var array<string, array<string, string>>
     *
     * @since 1.0.0
     */
    private const BYPASS_KIND_MAPPINGS = [
        self::SOURCE_ADGUARD_HOME => [
            'filters:*bypass*' => BypassConfiguration::KIND_ENCRYPTED_DNS,
        ],
        self::SOURCE_PFBLOCKERNG => [
            'dnsbl:DoH' => BypassConfiguration::KIND_ENCRYPTED_DNS,
            'ipv4:DoH_IP' => BypassConfiguration::KIND_ENCRYPTED_DNS,
            'ipv6:DoH_6' => BypassConfiguration::KIND_ENCRYPTED_DNS,
            'ipv4:TOR' => BypassConfiguration::KIND_TOR,
            'ipv4:VPN_4' => BypassConfiguration::KIND_VPN,
            'ipv6:VPN_6' => BypassConfiguration::KIND_VPN,
        ],
    ];

    /**
     * Catalog - Parse.
     *
     * Dispatches a downloaded document only to the parser assigned to its fixed
     * source key.
     *
     * @param string $source   - Stable source key.
     * @param string $contents - Complete downloaded JSON document.
     *
     * @return list<array{
     *     name: string,
     *     description: string,
     *     homepage: string,
     *     url: string,
     *     source: string,
     *     contents: string,
     *     group: string|null,
     *     tags: list<string>,
     *     category: string,
     *     maintainer: string,
     *     source_key: string,
     *     catalog_section: string,
     *     catalog_key: string
     * }>
     *
     * @throws RuntimeException When the source key or document structure is invalid.
     *
     * @since 1.0.0
     */
    public static function parse(string $source, string $contents): array
    {
        $entries = match ($source) {
            self::SOURCE_ADGUARD_HOME => self::parseAdGuardHome($contents),
            self::SOURCE_PFBLOCKERNG => self::parsePfBlockerNg($contents),
            default => throw new RuntimeException('The catalog source is invalid.'),
        };

        return self::withoutBypassEntries($entries);
    }

    /**
     * Catalog - Parse IP.
     *
     * DNS catalog callers remain restricted to ``dnsbl`` while the IP page reads
     * only pfBlockerNG's ``ipv4`` and ``ipv6`` sections.
     *
     * @param string $contents - Complete pfBlockerNG JSON document.
     *
     * @return list<array>
     *
     * @since 1.0.0
     */
    public static function parseIp(string $contents): array
    {
        $entries = self::parseIpEntries($contents);

        return self::withoutBypassEntries($entries);
    }

    /**
     * Catalog - Parse Bypass.
     *
     * Selects only the stable catalog keys owned by Bypass and attaches the kind
     * that controls which independently opt-in checkbox can use each result.
     *
     * @param string $source   - Stable source key.
     * @param string $contents - Complete downloaded JSON document.
     *
     * @return list<array>
     *
     * @throws RuntimeException When the source key or document structure is invalid.
     *
     * @since 1.0.0
     */
    public static function parseBypass(string $source, string $contents): array
    {
        if ($source === self::SOURCE_ADGUARD_HOME) {
            $entries = self::parseAdGuardHome($contents);
        } elseif ($source === self::SOURCE_PFBLOCKERNG) {
            $dnsEntries = self::parsePfBlockerNg($contents);
            $ipEntries = self::parseIpEntries($contents);
            $entries = array_merge($dnsEntries, $ipEntries);
        } else {
            throw new RuntimeException('The catalog source is invalid.');
        }

        $bypassEntries = [];

        foreach ($entries as $entry) {
            $kind = self::bypassKindForEntry($entry);

            if ($kind === null) {
                continue;
            }

            $entry['kind'] = $kind;
            $bypassEntries[] = $entry;

            if (count($bypassEntries) >= self::MAXIMUM_ENTRIES) {
                break;
            }
        }

        return $bypassEntries;
    }

    /**
     * Catalog - Bypass Kind For Catalog Key.
     *
     * The public pure mapping lets callers and fixtures verify classification
     * without depending on a URL or on the downloaded entry's display text.
     *
     * @param string $source     - Stable source key.
     * @param string $section    - Stable source section.
     * @param string $catalogKey - Stable group or filter key.
     *
     * @return string|null
     *
     * @since 1.0.0
     */
    public static function bypassKindForCatalogKey(
        string $source,
        string $section,
        string $catalogKey,
    ): ?string {
        $sourceMappings = self::BYPASS_KIND_MAPPINGS[$source] ?? [];
        $mappingKey = $section . ':' . $catalogKey;

        if (isset($sourceMappings[$mappingKey])) {
            return $sourceMappings[$mappingKey];
        }

        if (
            $source === self::SOURCE_ADGUARD_HOME
            && $section === 'filters'
            && str_contains(strtolower($catalogKey), 'bypass')
        ) {
            return $sourceMappings['filters:*bypass*'] ?? null;
        }

        return null;
    }

    /**
     * Catalog - Source Labels.
     *
     * The WebGUI and cache share these fixed product labels rather than accepting
     * source text from downloaded documents.
     *
     * @return array<string, string>
     *
     * @since 1.0.0
     */
    public static function sourceLabels(): array
    {
        return [
            self::SOURCE_ADGUARD_HOME => 'AdGuard Home',
            self::SOURCE_PFBLOCKERNG => 'pfBlockerNG',
        ];
    }

    /**
     * Catalog - Contents For Source Section.
     *
     * Maps only the fixed source and section metadata to a stable contents value
     * so a downloaded URL can never determine a feed's contents.
     *
     * @param string $source  - Stable source key.
     * @param string $section - Stable source section.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function contentsForSourceSection(string $source, string $section): string
    {
        return match ($source . ':' . $section) {
            self::SOURCE_ADGUARD_HOME . ':filters',
            self::SOURCE_PFBLOCKERNG . ':dnsbl' => self::CONTENTS_DOMAINS,
            self::SOURCE_PFBLOCKERNG . ':ipv4' => self::CONTENTS_IPV4_ADDRESSES,
            self::SOURCE_PFBLOCKERNG . ':ipv6' => self::CONTENTS_IPV6_ADDRESSES,
            default => '',
        };
    }

    /**
     * Catalog - Category Keys.
     *
     * The fixed order is shared by filter chips and category grouping.
     *
     * @return list<string>
     *
     * @since 1.0.0
     */
    public static function categoryKeys(): array
    {
        return [
            self::CATEGORY_ADS_TRACKERS,
            self::CATEGORY_SECURITY,
            self::CATEGORY_SERVICES_BYPASS,
            self::CATEGORY_REGIONAL,
            self::CATEGORY_OTHER,
        ];
    }

    /**
     * Catalog - Normalize Category Filter.
     *
     * @param string $category - Untrusted category key.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function normalizeCategoryFilter(string $category): string
    {
        return in_array($category, self::categoryKeys(), true) ? $category : '';
    }

    /**
     * Catalog - Normalize Bypass Kind Filter.
     *
     * The Bypass catalog accepts only the kinds owned by its configuration so a
     * request value cannot create an unrecognized filter or result group.
     *
     * @param string $kind - Untrusted Bypass kind.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function normalizeBypassKindFilter(string $kind): string
    {
        return in_array($kind, BypassConfiguration::KINDS, true) ? $kind : '';
    }

    /**
     * Catalog - Normalize Maintainer Filter.
     *
     * @param string $maintainer - Untrusted maintainer text.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function normalizeMaintainerFilter(string $maintainer): string
    {
        return self::normalizeText($maintainer, self::MAXIMUM_SEARCH_BYTES) ?? '';
    }

    /**
     * Catalog - Normalize Grouping.
     *
     * @param string $groupBy - Untrusted grouping key.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function normalizeGroupBy(string $groupBy): string
    {
        return ($groupBy === self::GROUP_BY_MAINTAINER)
            ? self::GROUP_BY_MAINTAINER
            : self::GROUP_BY_CATEGORY;
    }

    /**
     * Catalog - Category For Group.
     *
     * @param string      $sourceKey - Stable source key.
     * @param string|null $group     - Catalog-owned group name.
     * @param bool        $ipCatalog - Whether the entry belongs to IP search.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function categoryForGroup(
        string $sourceKey,
        ?string $group,
        bool $ipCatalog = false,
    ): string {
        if ($ipCatalog) {
            return self::CATEGORY_OTHER;
        }

        return match ($sourceKey) {
            self::SOURCE_ADGUARD_HOME => self::ADGUARD_CATEGORIES[$group ?? '']
                ?? self::CATEGORY_OTHER,
            self::SOURCE_PFBLOCKERNG => self::PFBLOCKERNG_CATEGORIES[$group ?? '']
                ?? self::CATEGORY_OTHER,
            default => self::CATEGORY_OTHER,
        };
    }

    /**
     * Catalog - Maintainer.
     *
     * @param string $homepage - Validated homepage URL.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function maintainer(string $homepage): string
    {
        $parts = parse_url($homepage);
        $host = is_array($parts) && is_string($parts['host'] ?? null)
            ? strtolower($parts['host'])
            : '';

        if (str_starts_with($host, 'www.')) {
            $host = substr($host, 4);
        }

        if ($host === '') {
            return '';
        }

        if (in_array($host, ['github.com', 'gitlab.com'], true)) {
            $path = is_array($parts) && is_string($parts['path'] ?? null)
                ? trim($parts['path'], '/')
                : '';
            $owner = explode('/', $path, 2)[0] ?? '';
            $owner = self::normalizeText(strtolower($owner), self::MAXIMUM_NAME_BYTES) ?? '';

            if ($owner !== '') {
                return $host . '/' . $owner;
            }
        }

        return $host;
    }

    /**
     * Catalog - Faceted View.
     *
     * Category counts deliberately omit the selected category while following the
     * search, source, and maintainer filters. Maintainer counts omit only the
     * selected maintainer so both controls remain useful together.
     *
     * @param list<array> $entries - Valid normalized entries.
     * @param string $query - Search text.
     * @param string $source - Source label.
     * @param string $maintainer - Maintainer filter.
     * @param string $category - Category filter.
     * @param string $groupBy - Grouping key.
     *
     * @return array{entries: list<array>, groups: list<array{key: string, count: int, entries: list<array>}>, category_counts: array<string, int>, maintainers: list<array{name: string, count: int}>}
     *
     * @since 1.0.0
     */
    public static function facetedView(
        array $entries,
        string $query,
        string $source,
        string $maintainer,
        string $category,
        string $groupBy,
    ): array {
        $query = self::normalizeSearchQuery($query);
        $source = self::normalizeSourceFilter($source);
        $maintainer = self::normalizeMaintainerFilter($maintainer);
        $category = self::normalizeCategoryFilter($category);
        $groupBy = self::normalizeGroupBy($groupBy);
        $normalizedEntries = [];

        foreach ($entries as $entry) {
            if (!self::isEntry($entry)) {
                continue;
            }

            $normalizedEntries[] = self::withMetadata($entry);
        }

        $baseEntries = self::filterEntries($normalizedEntries, $query, $source, '', '');
        $categoryEntries = self::filterEntries(
            $baseEntries,
            '',
            '',
            $maintainer,
            '',
        );
        $categoryCounts = array_fill_keys(self::categoryKeys(), 0);
        $categoryCounts[''] = count($categoryEntries);

        foreach ($categoryEntries as $entry) {
            $categoryCounts[$entry['category']]++;
        }

        $maintainerEntries = self::filterEntries($baseEntries, '', '', '', $category);
        $maintainerCounts = [];

        foreach ($maintainerEntries as $entry) {
            $maintainerCounts[$entry['maintainer']] = ($maintainerCounts[$entry['maintainer']] ?? 0) + 1;
        }

        $maintainers = [];

        foreach ($maintainerCounts as $name => $count) {
            $maintainers[] = ['name' => $name, 'count' => $count];
        }

        usort($maintainers, static function (array $first, array $second): int {
            return ($second['count'] <=> $first['count'])
                ?: strcasecmp($first['name'], $second['name']);
        });

        $matches = self::filterEntries(
            $baseEntries,
            '',
            '',
            $maintainer,
            $category,
        );
        $matches = array_slice($matches, 0, self::MAXIMUM_SEARCH_RESULTS);
        $groupedEntries = [];

        foreach ($matches as $entry) {
            $key = ($groupBy === self::GROUP_BY_MAINTAINER)
                ? $entry['maintainer']
                : $entry['category'];
            $groupedEntries[$key][] = $entry;
        }

        $groupKeys = array_keys($groupedEntries);

        if ($groupBy === self::GROUP_BY_CATEGORY) {
            $groupKeys = array_values(array_filter(
                self::categoryKeys(),
                static fn(string $key): bool => isset($groupedEntries[$key]),
            ));
        } else {
            usort($groupKeys, static function (string $first, string $second) use ($groupedEntries): int {
                return (count($groupedEntries[$second]) <=> count($groupedEntries[$first]))
                    ?: strcasecmp($first, $second);
            });
        }

        $groups = [];

        foreach ($groupKeys as $key) {
            $groups[] = [
                'key' => $key,
                'count' => count($groupedEntries[$key]),
                'entries' => $groupedEntries[$key],
            ];
        }

        return [
            'entries' => $matches,
            'groups' => $groups,
            'category_counts' => $categoryCounts,
            'maintainers' => $maintainers,
        ];
    }

    /**
     * Catalog - Bypass Faceted View.
     *
     * Kind counts follow search, source, and maintainer filters while the
     * maintainer menu follows the selected kind. Results always group by kind.
     *
     * @param list<array> $entries - Valid normalized Bypass entries.
     * @param string $query - Search text.
     * @param string $source - Source label.
     * @param string $maintainer - Maintainer filter.
     * @param string $kind - Bypass kind filter.
     *
     * @return array{entries: list<array>, groups: list<array{key: string, count: int, entries: list<array>}>, kind_counts: array<string, int>, maintainers: list<array{name: string, count: int}>}
     *
     * @since 1.0.0
     */
    public static function bypassFacetedView(
        array $entries,
        string $query,
        string $source,
        string $maintainer,
        string $kind,
    ): array {
        $query = self::normalizeSearchQuery($query);
        $source = self::normalizeSourceFilter($source);
        $maintainer = self::normalizeMaintainerFilter($maintainer);
        $kind = self::normalizeBypassKindFilter($kind);
        $normalizedEntries = [];

        foreach ($entries as $entry) {
            if (!self::isEntry($entry)) {
                continue;
            }

            $entryKind = is_string($entry['kind'] ?? null)
                ? self::normalizeBypassKindFilter($entry['kind'])
                : '';

            if ($entryKind === '') {
                continue;
            }

            $entry = self::withMetadata($entry);
            $entry['kind'] = $entryKind;
            $normalizedEntries[] = $entry;
        }

        $baseEntries = self::filterEntries($normalizedEntries, $query, $source, '', '');
        $kindEntries = self::filterEntries($baseEntries, '', '', $maintainer, '');
        $kindCounts = array_fill_keys(BypassConfiguration::KINDS, 0);
        $kindCounts[''] = count($kindEntries);

        foreach ($kindEntries as $entry) {
            $kindCounts[$entry['kind']]++;
        }

        $maintainerEntries = self::filterEntries(
            $baseEntries,
            '',
            '',
            '',
            '',
            $kind,
        );
        $maintainerCounts = [];

        foreach ($maintainerEntries as $entry) {
            $maintainerCounts[$entry['maintainer']] =
                ($maintainerCounts[$entry['maintainer']] ?? 0) + 1;
        }

        $maintainers = [];

        foreach ($maintainerCounts as $name => $count) {
            $maintainers[] = ['name' => $name, 'count' => $count];
        }

        usort($maintainers, static function (array $first, array $second): int {
            return ($second['count'] <=> $first['count'])
                ?: strcasecmp($first['name'], $second['name']);
        });

        $matches = self::filterEntries(
            $baseEntries,
            '',
            '',
            $maintainer,
            '',
            $kind,
        );
        $matches = array_slice($matches, 0, self::MAXIMUM_SEARCH_RESULTS);
        $groupedEntries = [];

        foreach ($matches as $entry) {
            $groupedEntries[$entry['kind']][] = $entry;
        }

        $groupKeys = array_values(array_filter(
            BypassConfiguration::KINDS,
            static fn(string $groupKind): bool => isset($groupedEntries[$groupKind]),
        ));
        $groups = [];

        foreach ($groupKeys as $groupKind) {
            $groups[] = [
                'key' => $groupKind,
                'count' => count($groupedEntries[$groupKind]),
                'entries' => $groupedEntries[$groupKind],
            ];
        }

        return [
            'entries' => $matches,
            'groups' => $groups,
            'kind_counts' => $kindCounts,
            'maintainers' => $maintainers,
        ];
    }

    /**
     * Catalog - Normalize Search Query.
     *
     * Search input is bounded and must be valid control-free UTF-8 before it is
     * compared or returned to a form value.
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
     * Catalog - Normalize Source Filter.
     *
     * Unknown filter values become the all-source selection instead of influencing
     * entry matching.
     *
     * @param string $source - Untrusted source label.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function normalizeSourceFilter(string $source): string
    {
        return in_array($source, self::sourceLabels(), true) ? $source : '';
    }

    /**
     * Catalog - Search.
     *
     * Matches only names and descriptions, applies the fixed source filter, and
     * returns a deterministic bounded result set.
     *
     * @param list<array> $entries - Valid normalized catalog entries.
     * @param string      $query   - Name and description search text.
     * @param string      $source  - Selected source label or an empty string.
     *
     * @return list<array>
     *
     * @since 1.0.0
     */
    public static function search(array $entries, string $query, string $source): array
    {
        return array_slice(
            self::filterEntries(
                $entries,
                self::normalizeSearchQuery($query),
                self::normalizeSourceFilter($source),
                '',
                '',
            ),
            0,
            self::MAXIMUM_SEARCH_RESULTS,
        );
    }

    /**
     * Catalog - Mark Added.
     *
     * URL equality is the complete duplicate rule for catalog results and manually
     * configured lists.
     *
     * @param list<array> $entries - Search results.
     * @param array<string, array> $lists - Current ordinary lists.
     *
     * @return list<array>
     *
     * @since 1.0.0
     */
    public static function markAdded(array $entries, array $lists): array
    {
        $configuredUrls = [];

        foreach ($lists as $list) {
            if (is_array($list) && is_string($list['url'] ?? null)) {
                $configuredUrls[$list['url']] = true;
            }
        }

        $results = [];

        foreach ($entries as $entry) {
            if (!self::isEntry($entry)) {
                continue;
            }

            $entry['added'] = isset($configuredUrls[$entry['url']]);
            $results[] = $entry;
        }

        return $results;
    }

    /**
     * Catalog - Entry Identifier.
     *
     * A fixed digest lets an Add action identify a server-side cached entry without
     * posting downloaded names or URLs back as trusted values.
     *
     * @param array $entry - Valid normalized catalog entry.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function entryIdentifier(array $entry): string
    {
        if (!self::isEntry($entry)) {
            return '';
        }

        return hash('sha256', $entry['source'] . "\0" . $entry['url']);
    }

    /**
     * Catalog - Add List.
     *
     * Resolves the posted digest against current cached results and delegates the
     * new row to the same validator used by manual list saves.
     *
     * @param list<array> $entries - Current normalized catalog entries.
     * @param array<string, array> $lists - Current ordinary lists.
     * @param string $entryIdentifier - Posted catalog entry digest.
     *
     * @return array<string, array>
     *
     * @throws ValidationException When the result is absent or already configured.
     *
     * @since 1.0.0
     */
    public static function addList(
        array $entries,
        array $lists,
        string $entryIdentifier,
    ): array {
        if (preg_match('/^[a-f0-9]{64}$/D', $entryIdentifier) !== 1) {
            throw new ValidationException('catalog_entry_missing');
        }

        $matchingEntry = null;

        foreach ($entries as $entry) {
            if (
                self::isEntry($entry)
                && hash_equals(self::entryIdentifier($entry), $entryIdentifier)
            ) {
                $matchingEntry = $entry;

                break;
            }
        }

        if (!is_array($matchingEntry)) {
            throw new ValidationException('catalog_entry_missing');
        }

        foreach ($lists as $list) {
            if (
                is_array($list)
                && is_string($list['url'] ?? null)
                && $list['url'] === $matchingEntry['url']
            ) {
                throw new ValidationException('catalog_entry_already_added');
            }
        }

        $identifier = ListConfiguration::generateIdentifier();
        $lists[$identifier] = ListConfiguration::normalizeRow(
            $identifier,
            self::addedListName($matchingEntry),
            $matchingEntry['url'],
            true,
            true,
        );

        return $lists;
    }

    /**
     * Catalog - Add IP List.
     *
     * Resolves a current IP result and creates the same validated family-specific
     * row used by the IP editor while retaining the catalog-derived name suffix.
     *
     * @param list<array> $entries - Current normalized IP catalog entries.
     * @param array<string, array> $lists - Current IP lists.
     * @param string $entryIdentifier - Posted catalog entry digest.
     *
     * @return array<string, array>
     *
     * @throws ValidationException When the result is absent or already configured.
     *
     * @since 1.0.0
     */
    public static function addIpList(
        array $entries,
        array $lists,
        string $entryIdentifier,
    ): array {
        if (preg_match('/^[a-f0-9]{64}$/D', $entryIdentifier) !== 1) {
            throw new ValidationException('catalog_entry_missing');
        }

        $matchingEntry = null;

        foreach ($entries as $entry) {
            if (
                self::isEntry($entry)
                && hash_equals(self::entryIdentifier($entry), $entryIdentifier)
            ) {
                $matchingEntry = $entry;

                break;
            }
        }

        if (
            !is_array($matchingEntry)
            || !is_string($matchingEntry['family'] ?? null)
            || !in_array($matchingEntry['family'], ['ipv4', 'ipv6'], true)
        ) {
            throw new ValidationException('catalog_entry_missing');
        }

        foreach ($lists as $list) {
            if (
                is_array($list)
                && is_string($list['url'] ?? null)
                && $list['url'] === $matchingEntry['url']
            ) {
                throw new ValidationException('catalog_entry_already_added');
            }
        }

        $identifier = ListConfiguration::generateIdentifier();
        $row = ListConfiguration::normalizeRow(
            $identifier,
            self::addedListName($matchingEntry),
            $matchingEntry['url'],
            true,
        );
        unset($row['global']);
        $row['family'] = $matchingEntry['family'];
        $lists[$identifier] = $row;

        return $lists;
    }

    /**
     * Catalog - Add Bypass List.
     *
     * Resolves only a currently classified Bypass result and creates an enabled
     * row through the same validator used by the manual Bypass List editor.
     *
     * @param list<array> $entries - Current normalized Bypass catalog entries.
     * @param array<string, array> $lists - Current Bypass Lists.
     * @param string $entryIdentifier - Posted catalog entry digest.
     *
     * @return array<string, array>
     *
     * @throws ValidationException When the result is absent or already configured.
     *
     * @since 1.0.0
     */
    public static function addBypassList(
        array $entries,
        array $lists,
        string $entryIdentifier,
    ): array {
        if (preg_match('/^[a-f0-9]{64}$/D', $entryIdentifier) !== 1) {
            throw new ValidationException('catalog_entry_missing');
        }

        $matchingEntry = null;

        foreach ($entries as $entry) {
            if (
                self::isEntry($entry)
                && self::bypassKindForEntry($entry) !== null
                && hash_equals(self::entryIdentifier($entry), $entryIdentifier)
            ) {
                $matchingEntry = $entry;

                break;
            }
        }

        if (!is_array($matchingEntry)) {
            throw new ValidationException('catalog_entry_missing');
        }

        foreach ($lists as $list) {
            if (
                is_array($list)
                && is_string($list['url'] ?? null)
                && $list['url'] === $matchingEntry['url']
            ) {
                throw new ValidationException('catalog_entry_already_added');
            }
        }

        $kind = self::bypassKindForEntry($matchingEntry);

        if ($kind === null) {
            throw new ValidationException('catalog_entry_missing');
        }

        $identifier = ListConfiguration::generateIdentifier();
        $lists[$identifier] = BypassConfiguration::normalizeListRow(
            $identifier,
            self::addedListName($matchingEntry),
            $matchingEntry['url'],
            true,
            $kind,
        );

        return $lists;
    }

    /**
     * Catalog - Parse IP Entries.
     *
     * Keeps the full source-section parse separate so Bypass can select its fixed
     * IP groups before the ordinary IP catalog removes them.
     *
     * @param string $contents - Complete pfBlockerNG JSON document.
     *
     * @return list<array>
     *
     * @since 1.0.0
     * @private
     */
    private static function parseIpEntries(string $contents): array
    {
        $document = self::decodeDocument($contents);
        $entries = [];
        $groupCount = 0;
        $feedCount = 0;

        foreach (['ipv4', 'ipv6'] as $family) {
            $section = $document->{$family} ?? null;

            if (!$section instanceof stdClass) {
                continue;
            }

            foreach (get_object_vars($section) as $groupNameValue => $groupValue) {
                if ($groupCount >= self::MAXIMUM_GROUPS || $feedCount >= self::MAXIMUM_ENTRIES) {
                    break 2;
                }

                $groupCount++;

                if (
                    !$groupValue instanceof stdClass
                    || !is_string($groupValue->description ?? null)
                    || !is_array($groupValue->feeds ?? null)
                ) {
                    continue;
                }

                $group = self::normalizeText($groupNameValue, self::MAXIMUM_GROUP_BYTES);
                $description = self::normalizeText(
                    $groupValue->description,
                    self::MAXIMUM_DESCRIPTION_BYTES,
                );

                if ($group === null || $group === '' || $description === null) {
                    continue;
                }

                foreach ($groupValue->feeds as $feed) {
                    if ($feedCount >= self::MAXIMUM_ENTRIES) {
                        break;
                    }

                    $feedCount++;

                    if (
                        !$feed instanceof stdClass
                        || !is_string($feed->feed ?? null)
                        || !is_string($feed->url ?? null)
                    ) {
                        continue;
                    }

                    $website = $feed->website ?? '';
                    $name = self::normalizeText($feed->feed, self::MAXIMUM_NAME_BYTES);
                    $url = self::normalizeListUrl($feed->url);

                    if (!is_string($website) || $name === null || $name === '' || $url === null) {
                        continue;
                    }

                    $homepage = self::normalizeHomepage($website);
                    $entries[] = [
                        'name' => $name,
                        'description' => $description,
                        'homepage' => $homepage,
                        'url' => $url,
                        'source' => self::sourceLabels()[self::SOURCE_PFBLOCKERNG],
                        'contents' => self::contentsForSourceSection(
                            self::SOURCE_PFBLOCKERNG,
                            $family,
                        ),
                        'group' => $group,
                        'tags' => [],
                        'family' => $family,
                        'category' => self::CATEGORY_OTHER,
                        'maintainer' => self::maintainer($homepage),
                        'source_key' => self::SOURCE_PFBLOCKERNG,
                        'catalog_section' => $family,
                        'catalog_key' => $group,
                    ];
                }
            }
        }

        if ($entries === [] && !isset($document->ipv4) && !isset($document->ipv6)) {
            throw new RuntimeException('The pfBlockerNG IP catalog is invalid.');
        }

        return $entries;
    }

    /**
     * Catalog - Parse AdGuard Home.
     *
     * Uses only active filters and their download URL while keeping tag identifiers
     * bounded for the common entry shape.
     *
     * @param string $contents - Complete JSON document.
     *
     * @return list<array>
     *
     * @since 1.0.0
     * @private
     */
    private static function parseAdGuardHome(string $contents): array
    {
        $document = self::decodeDocument($contents);

        if (!isset($document->filters) || !is_array($document->filters)) {
            throw new RuntimeException('The AdGuard Home catalog is invalid.');
        }

        $groups = [];

        if (isset($document->groups) && !is_array($document->groups)) {
            throw new RuntimeException('The AdGuard Home catalog groups are invalid.');
        }

        foreach (array_slice($document->groups ?? [], 0, self::MAXIMUM_GROUPS) as $groupValue) {
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

            $groupName = self::normalizeText($groupNameValue, self::MAXIMUM_GROUP_BYTES);

            if ($groupName !== null && $groupName !== '') {
                $groups[(string) $groupIdentifier] = $groupName;
            }
        }

        $entries = [];
        $filterCount = 0;

        foreach ($document->filters as $filter) {
            if ($filterCount >= self::MAXIMUM_ENTRIES) {
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

            $name = self::normalizeText($filter->name, self::MAXIMUM_NAME_BYTES);
            $description = self::normalizeText(
                $descriptionValue,
                self::MAXIMUM_DESCRIPTION_BYTES,
            );
            $url = self::normalizeListUrl($filter->downloadUrl);

            if ($name === null || $name === '' || $description === null || $url === null) {
                continue;
            }

            $tags = [];
            $tagCount = 0;

            foreach ($tagsValue as $tagValue) {
                if ($tagCount >= self::MAXIMUM_TAGS) {
                    break;
                }

                $tagCount++;

                if (!is_int($tagValue) && !is_string($tagValue)) {
                    continue;
                }

                $tag = self::normalizeText((string) $tagValue, self::MAXIMUM_TAG_BYTES);

                if ($tag !== null && $tag !== '') {
                    $tags[] = $tag;
                }
            }

            $homepage = self::normalizeHomepage($homepageValue);
            $group = ($groupIdValue === null) ? null : ($groups[(string) $groupIdValue] ?? null);
            $catalogKey = self::normalizeText(
                (string) $filterKeyValue,
                self::MAXIMUM_GROUP_BYTES,
            ) ?? '';
            $entries[] = [
                'name' => $name,
                'description' => $description,
                'homepage' => $homepage,
                'url' => $url,
                'source' => self::sourceLabels()[self::SOURCE_ADGUARD_HOME],
                'contents' => self::contentsForSourceSection(
                    self::SOURCE_ADGUARD_HOME,
                    'filters',
                ),
                'group' => $group,
                'tags' => $tags,
                'category' => self::categoryForGroup(self::SOURCE_ADGUARD_HOME, $group),
                'maintainer' => self::maintainer($homepage),
                'source_key' => self::SOURCE_ADGUARD_HOME,
                'catalog_section' => 'filters',
                'catalog_key' => $catalogKey,
            ];
        }

        return $entries;
    }

    /**
     * Catalog - Parse pfBlockerNG.
     *
     * Traverses only DNS groups, using each group description for its feeds and
     * ignoring IP sections and alternate URLs reserved for later milestones.
     *
     * @param string $contents - Complete JSON document.
     *
     * @return list<array>
     *
     * @since 1.0.0
     * @private
     */
    private static function parsePfBlockerNg(string $contents): array
    {
        $document = self::decodeDocument($contents);

        if (!isset($document->dnsbl) || !$document->dnsbl instanceof stdClass) {
            throw new RuntimeException('The pfBlockerNG catalog is invalid.');
        }

        $entries = [];
        $groupCount = 0;
        $feedCount = 0;

        foreach (get_object_vars($document->dnsbl) as $groupNameValue => $groupValue) {
            if (
                $groupCount >= self::MAXIMUM_GROUPS
                || $feedCount >= self::MAXIMUM_ENTRIES
            ) {
                break;
            }

            $groupCount++;

            if (!$groupValue instanceof stdClass) {
                continue;
            }

            if (
                !is_string($groupValue->description ?? null)
                || !is_array($groupValue->feeds ?? null)
            ) {
                continue;
            }

            $group = self::normalizeText($groupNameValue, self::MAXIMUM_GROUP_BYTES);
            $description = self::normalizeText(
                $groupValue->description,
                self::MAXIMUM_DESCRIPTION_BYTES,
            );

            if ($group === null || $group === '' || $description === null) {
                continue;
            }

            foreach ($groupValue->feeds as $feed) {
                if ($feedCount >= self::MAXIMUM_ENTRIES) {
                    break;
                }

                $feedCount++;

                if (
                    !$feed instanceof stdClass
                    || !is_string($feed->feed ?? null)
                    || !is_string($feed->url ?? null)
                ) {
                    continue;
                }

                $homepageValue = $feed->website ?? '';

                if (!is_string($homepageValue)) {
                    continue;
                }

                $name = self::normalizeText($feed->feed, self::MAXIMUM_NAME_BYTES);
                $url = self::normalizeListUrl($feed->url);

                if ($name === null || $name === '' || $url === null) {
                    continue;
                }

                $homepage = self::normalizeHomepage($homepageValue);
                $entries[] = [
                    'name' => $name,
                    'description' => $description,
                    'homepage' => $homepage,
                    'url' => $url,
                    'source' => self::sourceLabels()[self::SOURCE_PFBLOCKERNG],
                    'contents' => self::contentsForSourceSection(
                        self::SOURCE_PFBLOCKERNG,
                        'dnsbl',
                    ),
                    'group' => $group,
                    'tags' => [],
                    'category' => self::categoryForGroup(self::SOURCE_PFBLOCKERNG, $group),
                    'maintainer' => self::maintainer($homepage),
                    'source_key' => self::SOURCE_PFBLOCKERNG,
                    'catalog_section' => 'dnsbl',
                    'catalog_key' => $group,
                ];
            }
        }

        return $entries;
    }

    /**
     * Catalog - Decode Document.
     *
     * Object decoding preserves the distinction between required JSON objects and
     * arrays before any source-specific traversal begins.
     *
     * @param string $contents - Complete JSON document.
     *
     * @return stdClass
     *
     * @throws RuntimeException When the top-level value is not an object.
     *
     * @since 1.0.0
     * @private
     */
    private static function decodeDocument(string $contents): stdClass
    {
        $document = json_decode($contents, false, 32, JSON_THROW_ON_ERROR);

        if (!$document instanceof stdClass) {
            throw new RuntimeException('The catalog document is invalid.');
        }

        return $document;
    }

    /**
     * Catalog - Normalize Text.
     *
     * Catalog display fields retain ordinary hostile-looking text for escaping at
     * presentation time, but reject controls and truncate on a UTF-8 boundary.
     *
     * @param string $value        - Untrusted catalog text.
     * @param int    $maximumBytes - Maximum retained bytes.
     *
     * @return string|null
     *
     * @since 1.0.0
     * @private
     */
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

        $limitedValue = substr($value, 0, $maximumBytes);

        while ($limitedValue !== '' && preg_match('//u', $limitedValue) !== 1) {
            $limitedValue = substr($limitedValue, 0, -1);
        }

        return $limitedValue;
    }

    /**
     * Catalog - Normalize List URL.
     *
     * A neutral valid name and identifier route each candidate through the exact
     * URL validation contract used by an ordinary manual list.
     *
     * @param string $url - Untrusted list URL.
     *
     * @return string|null
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeListUrl(string $url): ?string
    {
        try {
            $row = ListConfiguration::normalizeRow(
                self::VALIDATION_IDENTIFIER,
                self::VALIDATION_NAME,
                $url,
                true,
            );

            return $row['url'];
        } catch (ValidationException) {
            return null;
        }
    }

    /**
     * Catalog - Normalize Homepage.
     *
     * Optional homepage links use the same safe URL rules but do not remove an
     * otherwise valid list when the source supplies an unusable website value.
     *
     * @param string $homepage - Untrusted homepage URL.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeHomepage(string $homepage): string
    {
        if (trim($homepage) === '') {
            return '';
        }

        return self::normalizeListUrl($homepage) ?? '';
    }

    /**
     * Catalog - Is Entry.
     *
     * Search and Add defensively verify the normalized shape again because cached
     * arrays remain an untrusted file boundary.
     *
     * @param mixed $entry - Candidate normalized entry.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function isEntry(mixed $entry): bool
    {
        return is_array($entry)
            && is_string($entry['name'] ?? null)
            && is_string($entry['description'] ?? null)
            && is_string($entry['homepage'] ?? null)
            && is_string($entry['url'] ?? null)
            && is_string($entry['source'] ?? null)
            && (
                ($entry['group'] ?? null) === null
                || is_string($entry['group'] ?? null)
            )
            && is_array($entry['tags'] ?? null);
    }

    /**
     * Catalog - With Metadata.
     *
     * Older cached arrays and test fixtures are upgraded at the pure boundary so a
     * cache schema bump is unnecessary.
     *
     * @param array $entry - Valid catalog entry.
     *
     * @return array
     *
     * @since 1.0.0
     * @private
     */
    private static function withMetadata(array $entry): array
    {
        $sourceKey = ($entry['source'] === self::sourceLabels()[self::SOURCE_ADGUARD_HOME])
            ? self::SOURCE_ADGUARD_HOME
            : self::SOURCE_PFBLOCKERNG;
        $category = is_string($entry['category'] ?? null)
            ? self::normalizeCategoryFilter($entry['category'])
            : '';

        $entry['category'] = ($category === '')
            ? self::categoryForGroup(
                $sourceKey,
                is_string($entry['group'] ?? null) ? $entry['group'] : null,
                isset($entry['family']),
            )
            : $category;
        $entry['maintainer'] = is_string($entry['maintainer'] ?? null)
            ? self::normalizeMaintainerFilter($entry['maintainer'])
            : self::maintainer($entry['homepage']);
        $entry['contents'] = self::contentsForSourceSection(
            $sourceKey,
            is_string($entry['catalog_section'] ?? null)
                ? $entry['catalog_section']
                : '',
        );

        return $entry;
    }

    /**
     * Catalog - Added List Name.
     *
     * Keeps domain names unchanged and reserves bytes for an address-family
     * suffix without splitting a UTF-8 base name or duplicating that suffix.
     *
     * @param array $entry - Valid normalized catalog entry.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function addedListName(array $entry): string
    {
        $name = is_string($entry['name'] ?? null) ? $entry['name'] : '';

        if (($entry['source_key'] ?? null) !== self::SOURCE_PFBLOCKERNG) {
            return $name;
        }

        $suffix = match ($entry['catalog_section'] ?? null) {
            'ipv4' => ' (IPv4)',
            'ipv6' => ' (IPv6)',
            default => '',
        };

        if ($suffix === '') {
            return $name;
        }

        $baseName = str_ends_with($name, $suffix)
            ? substr($name, 0, strlen($name) - strlen($suffix))
            : $name;
        $maximumBaseBytes = self::MAXIMUM_NAME_BYTES - strlen($suffix);
        $limitedBaseName = self::normalizeText($baseName, $maximumBaseBytes);

        if ($limitedBaseName === null || $limitedBaseName === '') {
            return $name;
        }

        return $limitedBaseName . $suffix;
    }

    /**
     * Catalog - Without Bypass Entries.
     *
     * Ordinary DNS and IP catalogs drop every key owned by Bypass before search,
     * facets, counts, grouping, or Add can observe it.
     *
     * @param list<array> $entries - Parsed source entries.
     *
     * @return list<array>
     *
     * @since 1.0.0
     * @private
     */
    private static function withoutBypassEntries(array $entries): array
    {
        return array_values(array_filter(
            $entries,
            static fn(array $entry): bool => self::bypassKindForEntry($entry) === null,
        ));
    }

    /**
     * Catalog - Bypass Kind For Entry.
     *
     * Parsed source metadata is rechecked at every catalog boundary so a cached
     * array cannot supply its own kind or classify itself by URL.
     *
     * @param array $entry - Parsed catalog entry.
     *
     * @return string|null
     *
     * @since 1.0.0
     * @private
     */
    private static function bypassKindForEntry(array $entry): ?string
    {
        if (
            !is_string($entry['source_key'] ?? null)
            || !is_string($entry['catalog_section'] ?? null)
            || !is_string($entry['catalog_key'] ?? null)
        ) {
            return null;
        }

        return self::bypassKindForCatalogKey(
            $entry['source_key'],
            $entry['catalog_section'],
            $entry['catalog_key'],
        );
    }

    /**
     * Catalog - Filter Entries.
     *
     * @param list<array> $entries - Candidate entries.
     * @param string $query - Search text.
     * @param string $source - Source label.
     * @param string $maintainer - Exact maintainer.
     * @param string $category - Exact category.
     * @param string $kind - Exact Bypass kind.
     *
     * @return list<array>
     *
     * @since 1.0.0
     * @private
     */
    private static function filterEntries(
        array $entries,
        string $query,
        string $source,
        string $maintainer,
        string $category,
        string $kind = '',
    ): array {
        $matches = [];

        foreach ($entries as $entry) {
            if (!self::isEntry($entry)) {
                continue;
            }

            $entry = self::withMetadata($entry);

            if ($source !== '' && $entry['source'] !== $source) {
                continue;
            }

            if ($maintainer !== '' && $entry['maintainer'] !== $maintainer) {
                continue;
            }

            if ($category !== '' && $entry['category'] !== $category) {
                continue;
            }

            if ($kind !== '' && ($entry['kind'] ?? null) !== $kind) {
                continue;
            }

            if (
                $query !== ''
                && self::contains($entry['name'], $query) === false
                && self::contains($entry['description'], $query) === false
            ) {
                continue;
            }

            $matches[] = $entry;
        }

        usort($matches, static function (array $firstEntry, array $secondEntry): int {
            return strcasecmp($firstEntry['name'], $secondEntry['name'])
                ?: strcmp($firstEntry['source'], $secondEntry['source'])
                ?: strcmp($firstEntry['url'], $secondEntry['url']);
        });

        return $matches;
    }

    /**
     * Catalog - Contains.
     *
     * Unicode-aware comparison is used when the runtime provides mbstring, with a
     * deterministic byte-safe fallback on smaller PHP installations.
     *
     * @param string $haystack - Catalog name or description.
     * @param string $needle   - Normalized search text.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private static function contains(string $haystack, string $needle): bool
    {
        if (function_exists('mb_stripos')) {
            return mb_stripos($haystack, $needle, 0, 'UTF-8') !== false;
        }

        return stripos($haystack, $needle) !== false;
    }
}
