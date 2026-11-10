<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\Catalog;
use PfSense\Sinkhole\Domain\ValidationException;
use PfSense\Sinkhole\Runtime\CatalogCache;
use PfSense\Sinkhole\Runtime\DownloadClient;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Web\CatalogPresentation;

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Catalog.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/CatalogCache.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/CatalogPresentation.php');

/**
 * Sinkhole Catalog Test - Download Client.
 *
 * Supplies ordered invented documents without network access and records the cap
 * passed by the cache service.
 *
 * @since 1.0.0
 */
final class SinkholeCatalogTestDownloadClient implements DownloadClient
{
    /** @var list<array{url: string, maximum_bytes: int}> @since 1.0.0 */
    public array $calls = [];

    /**
     * Sinkhole Catalog Test - Download Client Constructor.
     *
     * @param list<array{contents?: string, error?: string}> $responses - Ordered responses.
     *
     * @since 1.0.0
     */
    public function __construct(private array $responses)
    {
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function download(
        string $url,
        string $destinationPath,
        int $maximumBytes,
        ?string $username = null,
        ?string $password = null,
    ): array {
        $this->calls[] = [
            'url' => $url,
            'maximum_bytes' => $maximumBytes,
        ];
        $response = array_shift($this->responses);

        if (!is_array($response) || !is_string($response['contents'] ?? null)) {
            return [
                'success' => false,
                'bytes' => 0,
                'error' => is_array($response) && is_string($response['error'] ?? null)
                    ? $response['error']
                    : 'Invented catalog fetch failure.',
            ];
        }

        $bytes = file_put_contents($destinationPath, $response['contents']);

        if (!is_int($bytes)) {
            return [
                'success' => false,
                'bytes' => 0,
                'error' => 'Unable to write the invented response.',
            ];
        }

        return [
            'success' => true,
            'bytes' => $bytes,
            'error' => null,
        ];
    }
}

/**
 * Sinkhole Catalog Test - Registry Document.
 *
 * @param list<array> $filters - Invented filter rows.
 * @param list<array> $groups - Invented group rows.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeCatalogTestRegistryDocument(array $filters, array $groups = []): string
{
    return json_encode([
        'filters' => $filters,
        'tags' => [],
        'groups' => $groups,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
}

/**
 * Sinkhole Catalog Test - Feed Document.
 *
 * @param array<string, array> $groups - Invented DNS groups.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeCatalogTestFeedDocument(array $groups): string
{
    return json_encode([
        'description' => 'Invented fixture',
        'copyright' => 'Example',
        'ipv4' => [
            'Ignored Example' => [
                'description' => 'Must not be used',
                'feeds' => [[
                    'feed' => 'Ignored Address Example',
                    'website' => 'https://example.net/ignored',
                    'url' => 'https://example.com/ignored.txt',
                    'header' => 'Ignored',
                ]],
            ],
        ],
        'ipv6' => [],
        'dnsbl' => $groups,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
}

/**
 * Sinkhole Catalog Test - Complete Feed Document.
 *
 * Keeps every invented source section explicit so shared-cache fixtures can
 * isolate ordinary entries from Bypass-owned entries.
 *
 * @param array<string, array> $dnsGroups - Invented DNS groups.
 * @param array<string, array> $ipv4Groups - Invented IPv4 groups.
 * @param array<string, array> $ipv6Groups - Invented IPv6 groups.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeCatalogTestCompleteFeedDocument(
    array $dnsGroups,
    array $ipv4Groups,
    array $ipv6Groups,
): string {
    return json_encode([
        'description' => 'Invented complete fixture',
        'copyright' => 'Example',
        'ipv4' => $ipv4Groups,
        'ipv6' => $ipv6Groups,
        'dnsbl' => $dnsGroups,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
}

/**
 * Sinkhole Catalog Test - Registry Row.
 *
 * @param string $name       - Invented entry name.
 * @param string $url        - Invented list URL.
 * @param string $description - Invented description.
 *
 * @return array
 *
 * @since 1.0.0
 */
function sinkholeCatalogTestRegistryRow(
    string $name,
    string $url,
    string $description = 'Invented registry description',
): array {
    return [
        'filterKey' => 1,
        'filterId' => 1,
        'groupId' => 1,
        'name' => $name,
        'description' => $description,
        'homepage' => 'https://example.net/home',
        'downloadUrl' => $url,
        'tags' => [1, 2],
        'languages' => ['en'],
        'deprecated' => false,
        'version' => '1',
        'timeUpdated' => '2026-01-01T00:00:00Z',
    ];
}

/**
 * Sinkhole Catalog Test - DNS Group.
 *
 * @param string      $description - Invented group description.
 * @param list<array> $feeds       - Invented feed rows.
 *
 * @return array
 *
 * @since 1.0.0
 */
function sinkholeCatalogTestDnsGroup(string $description, array $feeds): array
{
    return [
        'description' => $description,
        'info' => 'Invented information',
        'action' => 'Unbound',
        'cron' => '01hour',
        'feeds' => $feeds,
    ];
}

/**
 * Sinkhole Catalog Test - Feed Row.
 *
 * @param string $name - Invented feed name.
 * @param string $url  - Invented list URL.
 *
 * @return array
 *
 * @since 1.0.0
 */
function sinkholeCatalogTestFeedRow(string $name, string $url): array
{
    return [
        'feed' => $name,
        'website' => 'https://example.net/feed-home',
        'url' => $url,
        'header' => 'Invented header',
        'alternate' => 'https://example.com/unused-alternate.txt',
    ];
}

/**
 * Sinkhole Catalog Test - Assert Parse Fails.
 *
 * @param string $source   - Stable source key.
 * @param string $contents - Malformed fixture.
 * @param string $message  - Failure context.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeCatalogTestAssertParseFails(
    string $source,
    string $contents,
    string $message,
): void {
    $threw = false;

    try {
        Catalog::parse($source, $contents);
    } catch (Throwable) {
        $threw = true;
    }

    sinkholeTestAssertTrue($threw, $message);
}

sinkholeTestRun([
    'popular catalog formats normalize to one entry shape' => static function (): void {
        $registryEntries = Catalog::parse(
            Catalog::SOURCE_ADGUARD_HOME,
            sinkholeCatalogTestRegistryDocument([
                sinkholeCatalogTestRegistryRow(
                    'Registry Alpha Example',
                    'https://example.com/registry-alpha.txt',
                ),
            ]),
        );
        $feedEntries = Catalog::parse(
            Catalog::SOURCE_PFBLOCKERNG,
            sinkholeCatalogTestFeedDocument([
                'Invented Group' => sinkholeCatalogTestDnsGroup(
                    'Invented group description',
                    [sinkholeCatalogTestFeedRow(
                        'Feed Beta Example',
                        'http://example.com/feed-beta.txt',
                    )],
                ),
            ]),
        );

        sinkholeTestAssertSame(1, count($registryEntries), 'One registry row must normalize.');
        sinkholeTestAssertSame(
            [
                'name',
                'description',
                'homepage',
                'url',
                'source',
                'contents',
                'group',
                'tags',
                'category',
                'maintainer',
                'source_key',
                'catalog_section',
                'catalog_key',
            ],
            array_keys($registryEntries[0]),
            'Both parsers must return the documented common shape.',
        );
        sinkholeTestAssertSame(
            Catalog::sourceLabels()[Catalog::SOURCE_ADGUARD_HOME],
            $registryEntries[0]['source'],
            'The registry must use its fixed source label.',
        );
        sinkholeTestAssertSame(['1', '2'], $registryEntries[0]['tags'], 'Tag IDs must normalize.');
        sinkholeTestAssertSame(1, count($feedEntries), 'One DNS feed must normalize.');
        sinkholeTestAssertSame(
            'Invented group description',
            $feedEntries[0]['description'],
            'A DNS feed must use its group description.',
        );
        sinkholeTestAssertSame(
            'Invented Group',
            $feedEntries[0]['group'],
            'A DNS feed must retain its bounded group label.',
        );
        sinkholeTestAssertSame(
            'http://example.com/feed-beta.txt',
            $feedEntries[0]['url'],
            'The primary feed URL must be used instead of an alternate.',
        );
    },
    'catalog contents derive from fixed source sections' => static function (): void {
        $expectations = [
            [
                Catalog::SOURCE_ADGUARD_HOME,
                'filters',
                Catalog::CONTENTS_DOMAINS,
            ],
            [
                Catalog::SOURCE_PFBLOCKERNG,
                'dnsbl',
                Catalog::CONTENTS_DOMAINS,
            ],
            [
                Catalog::SOURCE_PFBLOCKERNG,
                'ipv4',
                Catalog::CONTENTS_IPV4_ADDRESSES,
            ],
            [
                Catalog::SOURCE_PFBLOCKERNG,
                'ipv6',
                Catalog::CONTENTS_IPV6_ADDRESSES,
            ],
        ];

        foreach ($expectations as [$source, $section, $expectedContents]) {
            sinkholeTestAssertSame(
                $expectedContents,
                Catalog::contentsForSourceSection($source, $section),
                'Each fixed source section must identify what its feeds contain.',
            );
        }

        sinkholeTestAssertSame(
            '',
            Catalog::contentsForSourceSection(
                Catalog::SOURCE_ADGUARD_HOME,
                'https://example.test/invented-list.txt',
            ),
            'A URL-looking section must not classify catalog contents.',
        );
        sinkholeTestAssertSame(
            '',
            Catalog::contentsForSourceSection('invented_source', 'ipv4'),
            'An unknown source must not inherit a known section classification.',
        );
    },
    'every catalog group maps to its category with an Other fallback' => static function (): void {
        $expectedGroups = [
            Catalog::SOURCE_ADGUARD_HOME => [
                Catalog::CATEGORY_ADS_TRACKERS => ['General'],
                Catalog::CATEGORY_SECURITY => ['Security'],
                Catalog::CATEGORY_REGIONAL => ['Regional'],
                Catalog::CATEGORY_OTHER => ['Other'],
            ],
            Catalog::SOURCE_PFBLOCKERNG => [
                Catalog::CATEGORY_ADS_TRACKERS => [
                    'EasyList',
                    'ADs',
                    'ADs_Basic',
                    'Firebog_Advertising',
                    'Firebog_Trackers',
                    'Compilation',
                ],
                Catalog::CATEGORY_SECURITY => [
                    'Malicious',
                    'Malicious2',
                    'Phishing',
                    'Cryptojackers',
                    'Firebog_Malicious',
                    'Firebog_Suspicious',
                    'BBcan177',
                    'BBC',
                ],
                Catalog::CATEGORY_SERVICES_BYPASS => [
                    'STUN',
                    'Skype_Resolvers',
                    'Torrent',
                    'URL_Shorteners',
                    'Email',
                ],
                Catalog::CATEGORY_OTHER => ['Firebog_Other'],
            ],
        ];

        foreach ($expectedGroups as $source => $categories) {
            foreach ($categories as $category => $groups) {
                foreach ($groups as $group) {
                    sinkholeTestAssertSame(
                        $category,
                        Catalog::categoryForGroup($source, $group),
                        'The listed group must map to its documented category: ' . $group,
                    );
                }
            }
        }

        sinkholeTestAssertSame(
            Catalog::CATEGORY_OTHER,
            Catalog::categoryForGroup(Catalog::SOURCE_ADGUARD_HOME, 'Invented New Group'),
            'An unmapped AdGuard group must fall back to Other.',
        );
        sinkholeTestAssertSame(
            Catalog::CATEGORY_OTHER,
            Catalog::categoryForGroup(Catalog::SOURCE_PFBLOCKERNG, 'Invented New Group'),
            'An unmapped pfBlockerNG group must fall back to Other.',
        );
        sinkholeTestAssertSame(
            Catalog::CATEGORY_OTHER,
            Catalog::categoryForGroup(Catalog::SOURCE_PFBLOCKERNG, 'DoH'),
            'The Lists category mapping must no longer classify DoH as another service.',
        );
        sinkholeTestAssertSame(
            Catalog::CATEGORY_OTHER,
            Catalog::categoryForGroup(Catalog::SOURCE_PFBLOCKERNG, 'EasyList', true),
            'IP catalog entries must use the simple Other category.',
        );
    },
    'bypass catalog owns every mapped feed and leaves unrelated groups in place' => static function (): void {
        $ordinaryRegistry = sinkholeCatalogTestRegistryRow(
            'Invented Ordinary Registry Feed',
            'https://example.test/bypass-looking-ordinary-registry.txt',
        );
        $ordinaryRegistry['filterKey'] = 'invented_ordinary_filter';
        $bypassRegistry = sinkholeCatalogTestRegistryRow(
            'Invented Encrypted Registry Feed',
            'https://example.test/encrypted-registry.txt',
        );
        $bypassRegistry['filterKey'] = 'invented_encrypted_proxy_bypass';
        $registryDocument = sinkholeCatalogTestRegistryDocument([
            $ordinaryRegistry,
            $bypassRegistry,
        ]);
        $feedDocument = json_encode([
            'description' => 'Invented complete catalog fixture',
            'copyright' => 'Invented fixture',
            'dnsbl' => [
                'DoH' => sinkholeCatalogTestDnsGroup(
                    'Invented encrypted DNS description',
                    [sinkholeCatalogTestFeedRow(
                        'Invented DNS Bypass Feed',
                        'https://example.test/dns-bypass.txt',
                    )],
                ),
                'STUN' => sinkholeCatalogTestDnsGroup(
                    'Invented other services description',
                    [sinkholeCatalogTestFeedRow(
                        'Invented Other Service Feed',
                        'https://example.test/other-service.txt',
                    )],
                ),
            ],
            'ipv4' => [
                'DoH_IP' => sinkholeCatalogTestDnsGroup(
                    'Invented encrypted address description',
                    [sinkholeCatalogTestFeedRow(
                        'Invented IPv4 Encrypted Feed',
                        'https://example.test/ipv4-encrypted.txt',
                    )],
                ),
                'TOR' => sinkholeCatalogTestDnsGroup(
                    'Invented relay description',
                    [sinkholeCatalogTestFeedRow(
                        'Invented Tor Feed',
                        'https://example.test/tor.txt',
                    )],
                ),
                'VPN_4' => sinkholeCatalogTestDnsGroup(
                    'Invented tunnel description',
                    [sinkholeCatalogTestFeedRow(
                        'Invented IPv4 VPN Feed',
                        'https://example.test/ipv4-vpn.txt',
                    )],
                ),
                'Invented_Address_Group' => sinkholeCatalogTestDnsGroup(
                    'Invented ordinary IPv4 description',
                    [sinkholeCatalogTestFeedRow(
                        'Invented Ordinary IPv4 Feed',
                        'https://example.test/doh-vpn-looking-ordinary-ipv4.txt',
                    )],
                ),
            ],
            'ipv6' => [
                'DoH_6' => sinkholeCatalogTestDnsGroup(
                    'Invented encrypted IPv6 description',
                    [sinkholeCatalogTestFeedRow(
                        'Invented IPv6 Encrypted Feed',
                        'https://example.test/ipv6-encrypted.txt',
                    )],
                ),
                'VPN_6' => sinkholeCatalogTestDnsGroup(
                    'Invented IPv6 tunnel description',
                    [sinkholeCatalogTestFeedRow(
                        'Invented IPv6 VPN Feed',
                        'https://example.test/ipv6-vpn.txt',
                    )],
                ),
                'Invented_Address_Group_6' => sinkholeCatalogTestDnsGroup(
                    'Invented ordinary IPv6 description',
                    [sinkholeCatalogTestFeedRow(
                        'Invented Ordinary IPv6 Feed',
                        'https://example.test/ordinary-ipv6.txt',
                    )],
                ),
            ],
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $listEntries = array_merge(
            Catalog::parse(Catalog::SOURCE_ADGUARD_HOME, $registryDocument),
            Catalog::parse(Catalog::SOURCE_PFBLOCKERNG, $feedDocument),
        );
        $ipEntries = Catalog::parseIp($feedDocument);
        $bypassEntries = array_merge(
            Catalog::parseBypass(Catalog::SOURCE_ADGUARD_HOME, $registryDocument),
            Catalog::parseBypass(Catalog::SOURCE_PFBLOCKERNG, $feedDocument),
        );

        $expectedMappings = [
            [Catalog::SOURCE_PFBLOCKERNG, 'dnsbl', 'DoH', BypassConfiguration::KIND_ENCRYPTED_DNS],
            [Catalog::SOURCE_PFBLOCKERNG, 'ipv4', 'DoH_IP', BypassConfiguration::KIND_ENCRYPTED_DNS],
            [Catalog::SOURCE_PFBLOCKERNG, 'ipv6', 'DoH_6', BypassConfiguration::KIND_ENCRYPTED_DNS],
            [Catalog::SOURCE_PFBLOCKERNG, 'ipv4', 'TOR', BypassConfiguration::KIND_TOR],
            [Catalog::SOURCE_PFBLOCKERNG, 'ipv4', 'VPN_4', BypassConfiguration::KIND_VPN],
            [Catalog::SOURCE_PFBLOCKERNG, 'ipv6', 'VPN_6', BypassConfiguration::KIND_VPN],
            [Catalog::SOURCE_ADGUARD_HOME, 'filters', 'invented_encrypted_proxy_bypass', BypassConfiguration::KIND_ENCRYPTED_DNS],
        ];

        foreach ($expectedMappings as [$source, $section, $catalogKey, $kind]) {
            sinkholeTestAssertSame(
                $kind,
                Catalog::bypassKindForCatalogKey($source, $section, $catalogKey),
                'Each stable source key must map to its fixed Bypass kind: ' . $catalogKey,
            );
        }

        sinkholeTestAssertSame(
            null,
            Catalog::bypassKindForCatalogKey(
                Catalog::SOURCE_PFBLOCKERNG,
                'ipv4',
                'Invented_Address_Group',
            ),
            'An unrelated group must not become a Bypass feed.',
        );
        $listNames = array_column($listEntries, 'name');
        sort($listNames, SORT_STRING);
        $ipNames = array_column($ipEntries, 'name');
        sort($ipNames, SORT_STRING);
        $bypassNames = array_column($bypassEntries, 'name');
        sort($bypassNames, SORT_STRING);

        sinkholeTestAssertSame(
            ['Invented Ordinary Registry Feed', 'Invented Other Service Feed'],
            $listNames,
            'Lists must retain unrelated DNS entries and remove every Bypass feed.',
        );
        sinkholeTestAssertSame(
            ['Invented Ordinary IPv4 Feed', 'Invented Ordinary IPv6 Feed'],
            $ipNames,
            'IP must retain unrelated address entries and remove every Bypass feed.',
        );
        sinkholeTestAssertSame(
            [
                'Invented DNS Bypass Feed',
                'Invented Encrypted Registry Feed',
                'Invented IPv4 Encrypted Feed',
                'Invented IPv4 VPN Feed',
                'Invented IPv6 Encrypted Feed',
                'Invented IPv6 VPN Feed',
                'Invented Tor Feed',
            ],
            $bypassNames,
            'Bypass must contain only every mapped source entry.',
        );

        $kindsByName = array_column($bypassEntries, 'kind', 'name');
        sinkholeTestAssertSame(
            BypassConfiguration::KIND_TOR,
            $kindsByName['Invented Tor Feed'],
            'The catalog must fix the Tor kind.',
        );
        sinkholeTestAssertSame(
            BypassConfiguration::KIND_VPN,
            $kindsByName['Invented IPv6 VPN Feed'],
            'The catalog must fix the VPN kind.',
        );
    },
    'bypass catalog add validates kind duplicates and identifiers' => static function (): void {
        $row = sinkholeCatalogTestRegistryRow(
            'Invented Catalog Bypass Row',
            'https://example.test/catalog-bypass-row.txt',
        );
        $row['filterKey'] = 'invented_catalog_bypass';
        $entries = Catalog::parseBypass(
            Catalog::SOURCE_ADGUARD_HOME,
            sinkholeCatalogTestRegistryDocument([$row]),
        );
        $entries[0]['kind'] = BypassConfiguration::KIND_TOR;
        $lists = Catalog::addBypassList(
            $entries,
            [],
            Catalog::entryIdentifier($entries[0]),
        );
        $list = array_values($lists)[0];

        sinkholeTestAssertSame(
            BypassConfiguration::KIND_ENCRYPTED_DNS,
            $list['kind'],
            'Add must rederive the kind fixed by the catalog mapping.',
        );
        sinkholeTestAssertSame(true, $list['enabled'], 'A catalog Bypass List must start enabled.');
        sinkholeTestAssertSame(
            false,
            array_key_exists('global', $list),
            'A Bypass List must use the manual Bypass row shape.',
        );

        foreach ([
            [Catalog::entryIdentifier($entries[0]), 'catalog_entry_already_added'],
            [str_repeat('f', 64), 'catalog_entry_missing'],
            ['invented-invalid-identifier', 'catalog_entry_missing'],
        ] as [$identifier, $expectedKey]) {
            $actualKey = '';

            try {
                Catalog::addBypassList($entries, $lists, $identifier);
            } catch (ValidationException $exception) {
                $actualKey = $exception->messageKey();
            }

            sinkholeTestAssertSame(
                $expectedKey,
                $actualKey,
                'Bypass catalog Add must reject duplicate and unknown identifiers.',
            );
        }
    },
    'catalog maintainers derive from hosts and forge owners' => static function (): void {
        sinkholeTestAssertSame(
            'example.test',
            Catalog::maintainer('https://www.example.test/list/home'),
            'Ordinary maintainers must use the host without www.',
        );
        sinkholeTestAssertSame(
            'github.com/invented-owner',
            Catalog::maintainer('https://github.com/Invented-Owner/project'),
            'GitHub maintainers must include the first path owner.',
        );
        sinkholeTestAssertSame(
            'gitlab.com/invented-group',
            Catalog::maintainer('https://www.gitlab.com/Invented-Group/project'),
            'GitLab maintainers must include the first path owner.',
        );
        sinkholeTestAssertSame('', Catalog::maintainer(''), 'A missing homepage has no maintainer.');
    },
    'catalog grouping counts and combined filters remain consistent' => static function (): void {
        $first = sinkholeCatalogTestRegistryRow(
            'Invented Ads One',
            'https://example.test/ads-one.txt',
        );
        $first['groupId'] = 1;
        $first['homepage'] = 'https://github.com/Invented-Owner/one';
        $second = sinkholeCatalogTestRegistryRow(
            'Invented Security Two',
            'https://example.test/security-two.txt',
        );
        $second['groupId'] = 2;
        $second['homepage'] = 'https://github.com/Invented-Owner/two';
        $third = sinkholeCatalogTestRegistryRow(
            'Different Ads Three',
            'https://example.test/ads-three.txt',
        );
        $third['groupId'] = 1;
        $third['homepage'] = 'https://www.other-maintainer.test/home';
        $entries = Catalog::parse(
            Catalog::SOURCE_ADGUARD_HOME,
            sinkholeCatalogTestRegistryDocument(
                [$first, $second, $third],
                [
                    ['groupId' => 1, 'groupName' => 'General'],
                    ['groupId' => 2, 'groupName' => 'Security'],
                ],
            ),
        );
        $view = Catalog::facetedView(
            $entries,
            'Invented',
            Catalog::sourceLabels()[Catalog::SOURCE_ADGUARD_HOME],
            'github.com/invented-owner',
            '',
            Catalog::GROUP_BY_CATEGORY,
        );

        sinkholeTestAssertSame(2, $view['category_counts'][''], 'All must follow combined filters.');
        sinkholeTestAssertSame(
            1,
            $view['category_counts'][Catalog::CATEGORY_ADS_TRACKERS],
            'Ads count must follow search, source and maintainer filters.',
        );
        sinkholeTestAssertSame(
            1,
            $view['category_counts'][Catalog::CATEGORY_SECURITY],
            'Security count must follow search, source and maintainer filters.',
        );
        sinkholeTestAssertSame(2, count($view['groups']), 'Category grouping must retain both groups.');

        $maintainerView = Catalog::facetedView(
            $entries,
            '',
            '',
            '',
            '',
            Catalog::GROUP_BY_MAINTAINER,
        );
        sinkholeTestAssertSame(
            2,
            count($maintainerView['groups']),
            'Maintainer grouping must split the filtered catalog.',
        );
        sinkholeTestAssertSame(
            2,
            $maintainerView['maintainers'][0]['count'],
            'The maintainer menu must be ordered by list count.',
        );
        sinkholeTestAssertSame(
            'github.com/invented-owner',
            $maintainerView['maintainers'][0]['name'],
            'The most prolific maintainer must be listed first.',
        );
    },
    'bypass kind facets normalize count and group in fixed order' => static function (): void {
        foreach (BypassConfiguration::KINDS as $kind) {
            sinkholeTestAssertSame(
                $kind,
                Catalog::normalizeBypassKindFilter($kind),
                'Each configured Bypass kind must remain selectable.',
            );
        }

        sinkholeTestAssertSame(
            '',
            Catalog::normalizeBypassKindFilter(''),
            'An empty Bypass kind must select All.',
        );
        sinkholeTestAssertSame(
            '',
            Catalog::normalizeBypassKindFilter('invented_kind'),
            'An unknown Bypass kind must normalize to All.',
        );

        $entry = static function (
            string $name,
            string $path,
            string $source,
            string $maintainer,
            string $kind,
        ): array {
            return [
                'name' => $name,
                'description' => 'Fixture Bypass catalog description.',
                'homepage' => 'https://' . $maintainer . '/home',
                'url' => 'https://example.test/' . $path . '.txt',
                'source' => $source,
                'group' => null,
                'tags' => [],
                'maintainer' => $maintainer,
                'kind' => $kind,
            ];
        };

        $pfBlockerNg = Catalog::sourceLabels()[Catalog::SOURCE_PFBLOCKERNG];
        $adGuardHome = Catalog::sourceLabels()[Catalog::SOURCE_ADGUARD_HOME];
        $entries = [
            $entry(
                'Invented Encrypted One',
                'encrypted-one',
                $pfBlockerNg,
                'example.test',
                BypassConfiguration::KIND_ENCRYPTED_DNS,
            ),
            $entry(
                'Invented Encrypted Two',
                'encrypted-two',
                $pfBlockerNg,
                'example.test',
                BypassConfiguration::KIND_ENCRYPTED_DNS,
            ),
            $entry(
                'Invented Encrypted Three',
                'encrypted-three',
                $pfBlockerNg,
                'example.test',
                BypassConfiguration::KIND_ENCRYPTED_DNS,
            ),
            $entry(
                'Invented Tor One',
                'tor-one',
                $pfBlockerNg,
                'example.test',
                BypassConfiguration::KIND_TOR,
            ),
            $entry(
                'Invented VPN One',
                'vpn-one',
                $pfBlockerNg,
                'example.test',
                BypassConfiguration::KIND_VPN,
            ),
            $entry(
                'Invented VPN Two',
                'vpn-two',
                $pfBlockerNg,
                'example.test',
                BypassConfiguration::KIND_VPN,
            ),
            $entry(
                'Different Encrypted',
                'different',
                $pfBlockerNg,
                'example.test',
                BypassConfiguration::KIND_ENCRYPTED_DNS,
            ),
            $entry(
                'Invented Tor Other',
                'tor-other',
                $pfBlockerNg,
                'other.test',
                BypassConfiguration::KIND_TOR,
            ),
            $entry(
                'Invented VPN Other Source',
                'vpn-source',
                $adGuardHome,
                'example.test',
                BypassConfiguration::KIND_VPN,
            ),
            $entry(
                'Invented Invalid Kind',
                'invalid-kind',
                $pfBlockerNg,
                'example.test',
                'invented_kind',
            ),
        ];
        $view = Catalog::bypassFacetedView(
            $entries,
            'Invented',
            $pfBlockerNg,
            'example.test',
            '',
        );

        sinkholeTestAssertSame(
            6,
            $view['kind_counts'][''],
            'All must follow the Bypass search, source, and maintainer filters.',
        );
        sinkholeTestAssertSame(
            3,
            $view['kind_counts'][BypassConfiguration::KIND_ENCRYPTED_DNS],
            'Encrypted DNS counts must follow every non-kind filter.',
        );
        sinkholeTestAssertSame(
            1,
            $view['kind_counts'][BypassConfiguration::KIND_TOR],
            'Tor counts must follow every non-kind filter.',
        );
        sinkholeTestAssertSame(
            2,
            $view['kind_counts'][BypassConfiguration::KIND_VPN],
            'VPN counts must follow every non-kind filter.',
        );
        sinkholeTestAssertSame(
            BypassConfiguration::KINDS,
            array_column($view['groups'], 'key'),
            'Bypass groups must follow the configured kind order.',
        );
        sinkholeTestAssertSame(
            [3, 1, 2],
            array_column($view['groups'], 'count'),
            'Each Bypass group must report its filtered result count.',
        );

        $torView = Catalog::bypassFacetedView(
            $entries,
            'Invented',
            $pfBlockerNg,
            'example.test',
            BypassConfiguration::KIND_TOR,
        );
        sinkholeTestAssertSame(
            [BypassConfiguration::KIND_TOR],
            array_column($torView['groups'], 'key'),
            'A selected kind must retain only its result panel.',
        );
        sinkholeTestAssertSame(
            $view['kind_counts'],
            $torView['kind_counts'],
            'Kind chips must omit the selected kind while counting.',
        );

        $withoutTor = array_values(array_filter(
            $entries,
            static fn(array $catalogEntry): bool =>
                ($catalogEntry['kind'] ?? '') !== BypassConfiguration::KIND_TOR,
        ));
        $withoutTorView = Catalog::bypassFacetedView(
            $withoutTor,
            'Invented',
            $pfBlockerNg,
            'example.test',
            '',
        );
        sinkholeTestAssertSame(
            [
                BypassConfiguration::KIND_ENCRYPTED_DNS,
                BypassConfiguration::KIND_VPN,
            ],
            array_column($withoutTorView['groups'], 'key'),
            'Kinds without filtered results must not render empty panels.',
        );
    },
    'malformed catalog documents are rejected' => static function (): void {
        sinkholeCatalogTestAssertParseFails(
            Catalog::SOURCE_ADGUARD_HOME,
            '{not json',
            'Invalid JSON must be rejected.',
        );
        sinkholeCatalogTestAssertParseFails(
            Catalog::SOURCE_ADGUARD_HOME,
            '{"filters":{}}',
            'The registry filters value must be an array.',
        );
        sinkholeCatalogTestAssertParseFails(
            Catalog::SOURCE_PFBLOCKERNG,
            '{"dnsbl":[]}',
            'The DNS catalog value must be an object.',
        );
        sinkholeCatalogTestAssertParseFails(
            'invented_source',
            '{}',
            'An unknown source key must be rejected.',
        );
    },
    'deprecated malformed and unsafe catalog rows are dropped' => static function (): void {
        $deprecated = sinkholeCatalogTestRegistryRow(
            'Deprecated Example',
            'https://example.com/deprecated.txt',
        );
        $deprecated['deprecated'] = true;
        $badScheme = sinkholeCatalogTestRegistryRow(
            'Bad Scheme Example',
            'ftp://example.com/bad-scheme.txt',
        );
        $credentials = sinkholeCatalogTestRegistryRow(
            'Credential Example',
            'https://user:secret@example.com/private.txt',
        );
        $badHomepage = sinkholeCatalogTestRegistryRow(
            'Valid URL Example',
            'https://example.com/valid.txt',
        );
        $badHomepage['homepage'] = 'ftp://example.net/bad-home';
        $malformed = sinkholeCatalogTestRegistryRow(
            'Malformed Example',
            'https://example.com/malformed.txt',
        );
        $malformed['description'] = [];
        $registryEntries = Catalog::parse(
            Catalog::SOURCE_ADGUARD_HOME,
            sinkholeCatalogTestRegistryDocument([
                $deprecated,
                $badScheme,
                $credentials,
                $badHomepage,
                $malformed,
            ]),
        );
        $feedEntries = Catalog::parse(
            Catalog::SOURCE_PFBLOCKERNG,
            sinkholeCatalogTestFeedDocument([
                'Invented Group' => sinkholeCatalogTestDnsGroup(
                    'Invented group description',
                    [
                        sinkholeCatalogTestFeedRow(
                            'Unsafe Feed Example',
                            'ftp://example.com/feed.txt',
                        ),
                        ['Feed' => 'Wrong key', 'url' => 'https://example.com/wrong.txt'],
                        sinkholeCatalogTestFeedRow(
                            'Safe Feed Example',
                            'https://example.net/safe.txt',
                        ),
                    ],
                ),
            ]),
        );

        sinkholeTestAssertSame(1, count($registryEntries), 'Only the safe active registry row remains.');
        sinkholeTestAssertSame('', $registryEntries[0]['homepage'], 'An unsafe homepage must be dropped.');
        sinkholeTestAssertSame(1, count($feedEntries), 'Only the safe well-formed DNS feed remains.');
        sinkholeTestAssertSame(
            'https://example.net/safe.txt',
            $feedEntries[0]['url'],
            'The safe DNS feed URL must remain.',
        );
    },
    'catalog field and collection caps are enforced' => static function (): void {
        $filters = [];

        for ($position = 0; $position < Catalog::MAXIMUM_ENTRIES + 5; $position++) {
            $filters[] = sinkholeCatalogTestRegistryRow(
                'Registry Example ' . (string) $position,
                'https://example.com/registry-' . (string) $position . '.txt',
            );
        }

        $filters[0]['name'] = str_repeat('N', Catalog::MAXIMUM_NAME_BYTES + 20);
        $filters[0]['description'] = str_repeat(
            'D',
            Catalog::MAXIMUM_DESCRIPTION_BYTES + 20,
        );
        $filters[0]['tags'] = array_merge(
            [str_repeat('T', Catalog::MAXIMUM_TAG_BYTES + 20)],
            range(1, Catalog::MAXIMUM_TAGS + 10),
        );
        $registryEntries = Catalog::parse(
            Catalog::SOURCE_ADGUARD_HOME,
            sinkholeCatalogTestRegistryDocument($filters),
        );

        sinkholeTestAssertSame(
            Catalog::MAXIMUM_ENTRIES,
            count($registryEntries),
            'Registry results must stop at the entry cap.',
        );
        sinkholeTestAssertSame(
            Catalog::MAXIMUM_NAME_BYTES,
            strlen($registryEntries[0]['name']),
            'Names must be byte-capped.',
        );
        sinkholeTestAssertSame(
            Catalog::MAXIMUM_DESCRIPTION_BYTES,
            strlen($registryEntries[0]['description']),
            'Descriptions must be byte-capped.',
        );
        sinkholeTestAssertSame(
            Catalog::MAXIMUM_TAGS,
            count($registryEntries[0]['tags']),
            'Tags must stop at the per-entry cap.',
        );
        sinkholeTestAssertSame(
            Catalog::MAXIMUM_TAG_BYTES,
            strlen($registryEntries[0]['tags'][0]),
            'Each tag must be byte-capped.',
        );

        $groups = [];

        for ($position = 0; $position < Catalog::MAXIMUM_GROUPS + 5; $position++) {
            $groupName = ($position === 0)
                ? str_repeat('G', Catalog::MAXIMUM_GROUP_BYTES + 20)
                : 'Invented Group ' . (string) $position;
            $groups[$groupName] = sinkholeCatalogTestDnsGroup(
                str_repeat('E', Catalog::MAXIMUM_DESCRIPTION_BYTES + 20),
                [sinkholeCatalogTestFeedRow(
                    'Feed Example ' . (string) $position,
                    'https://example.net/feed-' . (string) $position . '.txt',
                )],
            );
        }

        $feedEntries = Catalog::parse(
            Catalog::SOURCE_PFBLOCKERNG,
            sinkholeCatalogTestFeedDocument($groups),
        );
        sinkholeTestAssertSame(
            Catalog::MAXIMUM_GROUPS,
            count($feedEntries),
            'DNS group traversal must stop at the group cap.',
        );
        sinkholeTestAssertSame(
            Catalog::MAXIMUM_GROUP_BYTES,
            strlen((string) $feedEntries[0]['group']),
            'Group labels must be byte-capped.',
        );
    },
    'catalog search add and duplicate state use ordinary lists' => static function (): void {
        $entries = array_merge(
            Catalog::parse(
                Catalog::SOURCE_ADGUARD_HOME,
                sinkholeCatalogTestRegistryDocument([
                    sinkholeCatalogTestRegistryRow(
                        'Registry Alpha Example',
                        'https://example.com/registry-alpha.txt',
                        'A searchable family description',
                    ),
                ]),
            ),
            Catalog::parse(
                Catalog::SOURCE_PFBLOCKERNG,
                sinkholeCatalogTestFeedDocument([
                    'Invented Group' => sinkholeCatalogTestDnsGroup(
                        'A different description',
                        [sinkholeCatalogTestFeedRow(
                            'Feed Beta Example',
                            'https://example.net/feed-beta.txt',
                        )],
                    ),
                ]),
            ),
        );
        $matches = Catalog::search($entries, 'family', '');

        sinkholeTestAssertSame(1, count($matches), 'Search must match an entry description.');
        sinkholeTestAssertSame(
            [],
            Catalog::search($entries, 'family', Catalog::sourceLabels()[Catalog::SOURCE_PFBLOCKERNG]),
            'The source filter must narrow search results.',
        );

        $lists = Catalog::addList($entries, [], Catalog::entryIdentifier($matches[0]));
        $list = array_values($lists)[0];
        sinkholeTestAssertSame(
            'Registry Alpha Example',
            $list['name'],
            'Add must retain the catalog entry name.',
        );
        sinkholeTestAssertSame(
            'https://example.com/registry-alpha.txt',
            $list['url'],
            'Add must retain the validated catalog URL.',
        );
        sinkholeTestAssertSame(true, $list['enabled'], 'A catalog list must use the manual enabled default.');
        sinkholeTestAssertSame(true, $list['global'], 'A catalog list must use the manual global default.');

        $marked = Catalog::markAdded($entries, $lists);
        sinkholeTestAssertSame(true, $marked[0]['added'], 'The same URL must be marked as added.');
        sinkholeTestAssertSame(false, $marked[1]['added'], 'A different URL must remain addable.');

        $duplicateKey = '';

        try {
            Catalog::addList($entries, $lists, Catalog::entryIdentifier($matches[0]));
        } catch (ValidationException $exception) {
            $duplicateKey = $exception->messageKey();
        }

        sinkholeTestAssertSame(
            'catalog_entry_already_added',
            $duplicateKey,
            'A duplicate Add must be rejected through a translated validation key.',
        );
    },
    'catalog adds keep same-name domain and address feeds distinct' => static function (): void {
        $longName = str_repeat('N', Catalog::MAXIMUM_NAME_BYTES);
        $feedDocument = sinkholeCatalogTestCompleteFeedDocument(
            [
                'Invented DNS Group' => sinkholeCatalogTestDnsGroup(
                    'Invented domain description',
                    [sinkholeCatalogTestFeedRow(
                        'Dibdot DoH list',
                        'https://example.test/dibdot-domains.txt',
                    )],
                ),
                'DoH' => sinkholeCatalogTestDnsGroup(
                    'Invented Bypass domain description',
                    [sinkholeCatalogTestFeedRow(
                        'Dibdot DoH list',
                        'https://example.test/dibdot-bypass-domains.txt',
                    )],
                ),
            ],
            [
                'Invented IPv4 Group' => sinkholeCatalogTestDnsGroup(
                    'Invented IPv4 description',
                    [
                        sinkholeCatalogTestFeedRow(
                            'Dibdot DoH list',
                            'https://example.test/dibdot-ipv4.txt',
                        ),
                        sinkholeCatalogTestFeedRow(
                            'Already marked (IPv4)',
                            'https://example.test/already-marked-ipv4.txt',
                        ),
                        sinkholeCatalogTestFeedRow(
                            $longName,
                            'https://example.test/long-ipv4.txt',
                        ),
                    ],
                ),
                'VPN_4' => sinkholeCatalogTestDnsGroup(
                    'Invented IPv4 Bypass description',
                    [
                        sinkholeCatalogTestFeedRow(
                            'Ejrv VPN',
                            'https://example.test/ejrv-vpn-ipv4.txt',
                        ),
                        sinkholeCatalogTestFeedRow(
                            'Already marked Bypass (IPv4)',
                            'https://example.test/already-marked-bypass-ipv4.txt',
                        ),
                    ],
                ),
            ],
            [
                'Invented IPv6 Group' => sinkholeCatalogTestDnsGroup(
                    'Invented IPv6 description',
                    [
                        sinkholeCatalogTestFeedRow(
                            'Dibdot DoH list',
                            'https://example.test/dibdot-ipv6.txt',
                        ),
                        sinkholeCatalogTestFeedRow(
                            'Already marked (IPv6)',
                            'https://example.test/already-marked-ipv6.txt',
                        ),
                    ],
                ),
                'VPN_6' => sinkholeCatalogTestDnsGroup(
                    'Invented IPv6 Bypass description',
                    [
                        sinkholeCatalogTestFeedRow(
                            'Ejrv VPN',
                            'https://example.test/ejrv-vpn-ipv6.txt',
                        ),
                        sinkholeCatalogTestFeedRow(
                            'Already marked Bypass (IPv6)',
                            'https://example.test/already-marked-bypass-ipv6.txt',
                        ),
                    ],
                ),
            ],
        );
        $domainEntries = Catalog::parse(Catalog::SOURCE_PFBLOCKERNG, $feedDocument);
        $domainLists = Catalog::addList(
            $domainEntries,
            [],
            Catalog::entryIdentifier($domainEntries[0]),
        );
        $domainList = array_values($domainLists)[0];

        sinkholeTestAssertSame(
            'Dibdot DoH list',
            $domainList['name'],
            'A pfBlockerNG domain entry must keep its plain catalog name.',
        );

        $ipEntries = Catalog::parseIp($feedDocument);
        $ipLists = [];

        foreach ($ipEntries as $ipEntry) {
            $ipLists = Catalog::addIpList(
                $ipEntries,
                $ipLists,
                Catalog::entryIdentifier($ipEntry),
            );
        }

        $ipNames = array_column(array_values($ipLists), 'name');
        sinkholeTestAssertSame(
            [
                'Dibdot DoH list (IPv4)',
                'Already marked (IPv4)',
                str_repeat('N', 121) . ' (IPv4)',
                'Dibdot DoH list (IPv6)',
                'Already marked (IPv6)',
            ],
            $ipNames,
            'IP Add must append one family suffix while retaining the complete suffix.',
        );
        sinkholeTestAssertSame(
            Catalog::MAXIMUM_NAME_BYTES,
            strlen($ipNames[2]),
            'A long IP catalog name must trim only its base to the saved-name limit.',
        );

        $bypassEntries = Catalog::parseBypass(Catalog::SOURCE_PFBLOCKERNG, $feedDocument);
        $bypassLists = [];

        foreach ($bypassEntries as $bypassEntry) {
            $bypassLists = Catalog::addBypassList(
                $bypassEntries,
                $bypassLists,
                Catalog::entryIdentifier($bypassEntry),
            );
        }

        sinkholeTestAssertSame(
            [
                'Dibdot DoH list',
                'Ejrv VPN (IPv4)',
                'Already marked Bypass (IPv4)',
                'Ejrv VPN (IPv6)',
                'Already marked Bypass (IPv6)',
            ],
            array_column(array_values($bypassLists), 'name'),
            'Bypass Add must keep domain names plain and suffix both address families once.',
        );
    },
    'hostile catalog text is escaped only at presentation' => static function (): void {
        $hostile = sinkholeCatalogTestRegistryRow(
            '<script>alert("x")</script>',
            'https://example.com/hostile.txt?first=1&second=2',
            '"><img src=x onerror=alert(1)> & description',
        );
        $entries = Catalog::parse(
            Catalog::SOURCE_ADGUARD_HOME,
            sinkholeCatalogTestRegistryDocument([$hostile]),
        );
        $entries[0]['contents'] = '<Domains & addresses>';
        $presented = CatalogPresentation::entry(Catalog::markAdded($entries, [])[0]);

        sinkholeTestAssertSame(
            '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;',
            $presented['name'],
            'Hostile names must be HTML-escaped.',
        );
        sinkholeTestAssertContains(
            '&lt;img',
            $presented['description'],
            'Hostile descriptions must be HTML-escaped.',
        );
        sinkholeTestAssertContains(
            '&amp;',
            $presented['url'],
            'Safe URL query separators must be escaped in HTML.',
        );
        sinkholeTestAssertSame(
            '&lt;Domains &amp; addresses&gt;',
            $presented['contents'],
            'Catalog contents must be HTML-escaped by the presentation boundary.',
        );
        sinkholeTestAssertSame(
            false,
            str_contains($presented['name'], '<script>'),
            'No executable-looking name markup may reach the page.',
        );
    },
    'catalog cache reuses refreshes and falls back through the download client' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $initialRegistry = sinkholeCatalogTestRegistryDocument([
                sinkholeCatalogTestRegistryRow(
                    'Initial Registry Example',
                    'https://example.com/initial-registry.txt',
                ),
            ]);
            $initialFeeds = sinkholeCatalogTestFeedDocument([
                'Initial Group' => sinkholeCatalogTestDnsGroup(
                    'Initial group description',
                    [sinkholeCatalogTestFeedRow(
                        'Initial Feed Example',
                        'https://example.net/initial-feed.txt',
                    )],
                ),
            ]);
            $refreshedRegistry = sinkholeCatalogTestRegistryDocument([
                sinkholeCatalogTestRegistryRow(
                    'Refreshed Registry Example',
                    'https://example.com/refreshed-registry.txt',
                ),
            ]);
            $refreshedFeeds = sinkholeCatalogTestFeedDocument([
                'Refreshed Group' => sinkholeCatalogTestDnsGroup(
                    'Refreshed group description',
                    [sinkholeCatalogTestFeedRow(
                        'Refreshed Feed Example',
                        'https://example.net/refreshed-feed.txt',
                    )],
                ),
            ]);
            $client = new SinkholeCatalogTestDownloadClient([
                ['contents' => $initialRegistry],
                ['contents' => $initialFeeds],
                ['contents' => $refreshedRegistry],
                ['contents' => $refreshedFeeds],
                ['error' => 'Invented first-source failure.'],
                ['error' => 'Invented second-source failure.'],
            ]);
            $paths = new PackagePaths([
                'catalog_cache_directory' => $directory . '/cache',
            ]);
            $cache = new CatalogCache($paths, $client);
            $initial = $cache->load(false, 100000);

            sinkholeTestAssertSame(2, count($client->calls), 'An empty cache must fetch both sources.');
            sinkholeTestAssertSame(2, count($initial['entries']), 'Both initial documents must load.');
            sinkholeTestAssertSame(
                CatalogCache::MAXIMUM_CATALOG_BYTES,
                $client->calls[0]['maximum_bytes'],
                'Catalog downloads must use the dedicated few-MiB cap.',
            );

            $reused = $cache->load(false, 100100);
            sinkholeTestAssertSame(2, count($client->calls), 'A one-day cache hit must not fetch.');
            sinkholeTestAssertSame(
                'Initial Registry Example',
                $reused['entries'][0]['name'],
                'A cache hit must reuse the saved good document.',
            );

            $refreshed = $cache->load(true, 100200);
            sinkholeTestAssertSame(4, count($client->calls), 'Refresh must force both source fetches.');
            sinkholeTestAssertSame(
                'Refreshed Registry Example',
                $refreshed['entries'][0]['name'],
                'Refresh must replace a good cache atomically.',
            );

            $fallback = $cache->load(true, 100300);
            sinkholeTestAssertSame(6, count($client->calls), 'A second refresh must attempt both sources.');
            sinkholeTestAssertSame(
                'Refreshed Registry Example',
                $fallback['entries'][0]['name'],
                'A failed refresh must retain the last good registry copy.',
            );
            sinkholeTestAssertSame(
                'Refreshed Feed Example',
                $fallback['entries'][1]['name'],
                'A failed refresh must retain the last good DNS feed copy.',
            );

            foreach ($fallback['statuses'] as $status) {
                sinkholeTestAssertTrue(
                    $status['last_error'] !== '',
                    'Each failed fetch must expose its last error.',
                );
                sinkholeTestAssertSame(
                    100200,
                    $status['fetched_at'],
                    'A failed fetch must retain the last successful fetch time.',
                );
            }

            $statusOnly = $cache->status();
            sinkholeTestAssertSame(6, count($client->calls), 'Status reads must never fetch.');
            sinkholeTestAssertSame(
                $fallback['statuses'],
                $statusOnly,
                'Status reads must report the saved fetch time and error.',
            );
            CatalogCache::removeCacheFiles($paths);
            sinkholeTestAssertSame(
                false,
                file_exists($paths->adGuardHomeCatalogCacheFile),
                'Removal must delete the registry cache file.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->pfBlockerNgCatalogCacheFile),
                'Removal must delete the DNS feed cache file.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'bypass refresh rejects documents that would empty shared ordinary catalogs' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $ordinaryRegistry = sinkholeCatalogTestRegistryRow(
                'Initial Ordinary Registry',
                'https://example.test/initial-ordinary-registry.txt',
            );
            $ordinaryRegistry['filterKey'] = 'initial_ordinary_registry';
            $bypassRegistry = sinkholeCatalogTestRegistryRow(
                'Initial Registry Bypass',
                'https://example.test/initial-registry-bypass.txt',
            );
            $bypassRegistry['filterKey'] = 'initial_registry_bypass';
            $initialRegistry = sinkholeCatalogTestRegistryDocument([
                $ordinaryRegistry,
                $bypassRegistry,
            ]);
            $initialFeeds = sinkholeCatalogTestCompleteFeedDocument(
                [
                    'Invented Ordinary DNS' => sinkholeCatalogTestDnsGroup(
                        'Initial ordinary DNS description',
                        [sinkholeCatalogTestFeedRow(
                            'Initial Ordinary DNS Feed',
                            'https://example.test/initial-ordinary-dns.txt',
                        )],
                    ),
                    'DoH' => sinkholeCatalogTestDnsGroup(
                        'Initial encrypted DNS description',
                        [sinkholeCatalogTestFeedRow(
                            'Initial DNS Bypass Feed',
                            'https://example.test/initial-dns-bypass.txt',
                        )],
                    ),
                ],
                [
                    'Invented Ordinary IP' => sinkholeCatalogTestDnsGroup(
                        'Initial ordinary IP description',
                        [sinkholeCatalogTestFeedRow(
                            'Initial Ordinary IP Feed',
                            'https://example.test/initial-ordinary-ip.txt',
                        )],
                    ),
                    'TOR' => sinkholeCatalogTestDnsGroup(
                        'Initial Tor description',
                        [sinkholeCatalogTestFeedRow(
                            'Initial Tor Bypass Feed',
                            'https://example.test/initial-tor-bypass.txt',
                        )],
                    ),
                ],
                [],
            );
            $replacementRegistryRow = sinkholeCatalogTestRegistryRow(
                'Replacement Registry Bypass',
                'https://example.test/replacement-registry-bypass.txt',
            );
            $replacementRegistryRow['filterKey'] = 'replacement_registry_bypass';
            $replacementRegistry = sinkholeCatalogTestRegistryDocument([
                $replacementRegistryRow,
            ]);
            $replacementFeeds = sinkholeCatalogTestCompleteFeedDocument(
                [
                    'DoH' => sinkholeCatalogTestDnsGroup(
                        'Replacement encrypted DNS description',
                        [sinkholeCatalogTestFeedRow(
                            'Replacement DNS Bypass Feed',
                            'https://example.test/replacement-dns-bypass.txt',
                        )],
                    ),
                ],
                [
                    'TOR' => sinkholeCatalogTestDnsGroup(
                        'Replacement Tor description',
                        [sinkholeCatalogTestFeedRow(
                            'Replacement Tor Bypass Feed',
                            'https://example.test/replacement-tor-bypass.txt',
                        )],
                    ),
                ],
                [
                    'VPN_6' => sinkholeCatalogTestDnsGroup(
                        'Replacement VPN description',
                        [sinkholeCatalogTestFeedRow(
                            'Replacement VPN Bypass Feed',
                            'https://example.test/replacement-vpn-bypass.txt',
                        )],
                    ),
                ],
            );
            $client = new SinkholeCatalogTestDownloadClient([
                ['contents' => $initialRegistry],
                ['contents' => $initialFeeds],
                ['contents' => $replacementRegistry],
                ['contents' => $replacementFeeds],
            ]);
            $paths = new PackagePaths([
                'catalog_cache_directory' => $directory . '/cache',
            ]);
            $cache = new CatalogCache($paths, $client);
            $initialBypass = $cache->loadBypass(false, 200000);
            $initialBypassNames = array_column($initialBypass['entries'], 'name');
            sort($initialBypassNames, SORT_STRING);

            sinkholeTestAssertSame(
                [
                    'Initial DNS Bypass Feed',
                    'Initial Registry Bypass',
                    'Initial Tor Bypass Feed',
                ],
                $initialBypassNames,
                'The initial shared documents must expose their Bypass entries.',
            );

            $fallbackBypass = $cache->loadBypass(true, 200100);
            $fallbackBypassNames = array_column($fallbackBypass['entries'], 'name');
            sort($fallbackBypassNames, SORT_STRING);
            sinkholeTestAssertSame(
                $initialBypassNames,
                $fallbackBypassNames,
                'A Bypass-only replacement must retain both last-good shared documents.',
            );

            foreach ($fallbackBypass['statuses'] as $status) {
                sinkholeTestAssertContains(
                    'no valid entries',
                    $status['last_error'],
                    'Each rejected shared document must report ordinary validation failure.',
                );
                sinkholeTestAssertSame(
                    200000,
                    $status['fetched_at'],
                    'A rejected Bypass refresh must retain the prior shared fetch time.',
                );
            }

            $ordinaryLists = $cache->load(false, 200200);
            $ordinaryListNames = array_column($ordinaryLists['entries'], 'name');
            sort($ordinaryListNames, SORT_STRING);
            sinkholeTestAssertSame(
                ['Initial Ordinary DNS Feed', 'Initial Ordinary Registry'],
                $ordinaryListNames,
                'Lists must still read the last shared documents they accepted.',
            );
            $ordinaryIp = $cache->loadIp(false, 200200);
            sinkholeTestAssertSame(
                ['Initial Ordinary IP Feed'],
                array_column($ordinaryIp['entries'], 'name'),
                'IP must still read the last shared document it accepted.',
            );
            sinkholeTestAssertSame(
                4,
                count($client->calls),
                'Reading the retained fresh shared cache must not download again.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'every milestone five key exists in the English catalog' => static function (): void {
        $catalogs = require(
            __DIR__ . '/../port/files/usr/local/pkg/sinkhole/Translations.php'
        );
        $english = $catalogs['en_US'] ?? [];
        $keys = [
            'add_from_catalog',
            'added',
            'all_sources',
            'all_maintainers',
            'catalog_category_ads_trackers',
            'catalog_category_other',
            'catalog_category_regional',
            'catalog_category_security',
            'catalog_category_services_bypass',
            'catalog_entry_already_added',
            'catalog_entry_missing',
            'catalog_refresh_finished',
            'catalog_search_help',
            'contents',
            'homepage',
            'group_by',
            'ipv4_addresses',
            'ipv6_addresses',
            'last_fetch',
            'no_catalog_results',
            'no_homepage',
            'open_catalog',
            'popular_list_catalogs',
            'refresh',
            'search',
            'source',
            'maintainer',
        ];

        foreach ($keys as $key) {
            sinkholeTestAssertTrue(
                is_string($english[$key] ?? null) && $english[$key] !== '',
                'The English catalog must define milestone-five key: ' . $key,
            );
        }

        sinkholeTestAssertSame(
            'Other services',
            $english['catalog_category_services_bypass'],
            'The retained category key must use its narrowed label.',
        );
    },
]);
