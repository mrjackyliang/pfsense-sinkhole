<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\ServiceConfiguration;
use PfSense\Sinkhole\Domain\ServiceRegistry;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\DownloadClient;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\SavedListStore;
use PfSense\Sinkhole\Runtime\ServiceRegistryCache;
use PfSense\Sinkhole\Web\ServicePresentation;

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Compiler.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/DownloadClient.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/PackagePaths.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/SavedListStore.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ServiceConfiguration.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ServicePresentation.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ServiceRegistry.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ServiceRegistryCache.php');

/** @since 1.0.0 */
final class SinkholeServicesTestDownloadClient implements DownloadClient
{
    /** @var list<array{url: string, maximum_bytes: int}> @since 1.0.0 */
    public array $calls = [];

    /** @param list<array{contents?: string, error?: string}> $responses @since 1.0.0 */
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
        $this->calls[] = ['url' => $url, 'maximum_bytes' => $maximumBytes];
        $response = array_shift($this->responses);

        if (!is_array($response) || !is_string($response['contents'] ?? null)) {
            return [
                'success' => false,
                'bytes' => 0,
                'error' => is_array($response) && is_string($response['error'] ?? null)
                    ? $response['error']
                    : 'Invented registry failure.',
            ];
        }

        $bytes = file_put_contents($destinationPath, $response['contents']);

        return [
            'success' => is_int($bytes),
            'bytes' => is_int($bytes) ? $bytes : 0,
            'error' => is_int($bytes) ? null : 'Invented write failure.',
        ];
    }
}

/** @since 1.0.0 */
function sinkholeServicesTestDocument(
    string $name = 'Invented Video',
    array $rules = ['||blocked.service.test^'],
    string $icon = '<svg xmlns="http://www.w3.org/2000/svg"><path/></svg>',
    ?string $groupName = null,
    string $serviceGroup = 'invented_media',
    string $serviceIdentifier = 'invented-video',
): string {
    $group = ['id' => 'invented_media'];

    if ($groupName !== null) {
        $group['name'] = $groupName;
    }

    return json_encode([
        'blocked_services' => [[
            'id' => $serviceIdentifier,
            'name' => $name,
            'group' => $serviceGroup,
            'rules' => $rules,
            'icon_svg' => $icon,
        ]],
        'groups' => [$group],
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
}

/** @since 1.0.0 */
function sinkholeServicesTestPaths(string $root): PackagePaths
{
    return new PackagePaths([
        'persistent_directory' => $root . '/persistent',
        'runtime_root_directory' => $root . '/runtime',
        'runtime_lock_file' => $root . '/runtime.lock',
        'catalog_cache_directory' => $root . '/cache',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/** @return array @since 1.0.0 */
function sinkholeServicesTestManifest(PackagePaths $paths): array
{
    return json_decode(
        (string) file_get_contents($paths->runtimeDataDirectory . '/manifest.json'),
        true,
        32,
        JSON_THROW_ON_ERROR,
    );
}

/** @return array<string, array{exact: list<int>, subtree: list<int>}> @since 1.0.0 */
function sinkholeServicesTestRows(PackagePaths $paths): array
{
    $rows = [];
    $lines = file($paths->runtimeDataDirectory . '/domains.tsv', FILE_IGNORE_NEW_LINES);

    foreach (is_array($lines) ? $lines : [] as $line) {
        [$domain, $exact, $subtree] = explode("\t", $line);
        $rows[$domain] = [
            'exact' => ($exact === '') ? [] : array_map('intval', explode(',', $exact)),
            'subtree' => ($subtree === '') ? [] : array_map('intval', explode(',', $subtree)),
        ];
    }

    return $rows;
}

sinkholeTestRun([
    'blocked-services registry validates and normalizes invented rules' => static function (): void {
        $registry = ServiceRegistry::parse(sinkholeServicesTestDocument(
            rules: [
                '||blocked.service.test^',
                'unsupported*$rule',
                '0.0.0.0 exact.service.test',
            ],
        ));
        $service = $registry['services']['invented-video'];

        sinkholeTestAssertSame(
            ['invented_media' => true],
            $registry['groups'],
            'Group membership must use the registry identifier only.',
        );
        sinkholeTestAssertSame(
            'invented_media',
            $service['group'],
            'Services must retain their validated group identifier.',
        );
        sinkholeTestAssertSame(2, count($service['rules']), 'Accepted rule entries must normalize.');
        sinkholeTestAssertSame(1, $service['skipped_rules'], 'Unsupported rules must be counted.');
        sinkholeTestAssertSame(
            'blocked.service.test',
            $service['rules'][0]['domain'],
            'Adblock service rules must use the ordinary domain parser.',
        );
    },
    'known service group identifiers use catalog names' => static function (): void {
        sinkholeTestAssertSame(
            'AI',
            ServicePresentation::groupName('ai'),
            'Known service groups must render from the English catalog.',
        );
    },
    'unknown service group identifiers use readable fallback names' => static function (): void {
        sinkholeTestAssertSame(
            'Invented media',
            ServicePresentation::groupName('invented_media'),
            'Unknown service groups must replace underscores and capitalize the first letter.',
        );
    },
    'optional registry group names are accepted but never displayed' => static function (): void {
        $registry = ServiceRegistry::parse(sinkholeServicesTestDocument(
            groupName: 'Untrusted Invented Label',
        ));
        $presented = ServicePresentation::service($registry['services']['invented-video']);

        sinkholeTestAssertSame(
            ['invented_media' => true],
            $registry['groups'],
            'Optional registry group names must not enter parsed display data.',
        );
        sinkholeTestAssertSame(
            'Invented media',
            $presented['group_name'],
            'Optional registry group names must not override the identifier fallback.',
        );
    },
    'services whose group is absent from groups are rejected' => static function (): void {
        $threw = false;

        try {
            ServiceRegistry::parse(sinkholeServicesTestDocument(
                serviceGroup: 'missing_invented_group',
            ));
        } catch (RuntimeException) {
            $threw = true;
        }

        sinkholeTestAssertTrue(
            $threw,
            'A service must still reference a declared registry group.',
        );
    },
    'malformed and oversized blocked-services registries are rejected' => static function (): void {
        foreach ([
            '{}',
            '{"blocked_services":{},"groups":[]}',
            json_encode([
                'blocked_services' => array_fill(
                    0,
                    ServiceRegistry::MAXIMUM_SERVICES + 1,
                    new stdClass(),
                ),
                'groups' => [],
            ], JSON_THROW_ON_ERROR),
            sinkholeServicesTestDocument(
                rules: array_fill(
                    0,
                    ServiceRegistry::MAXIMUM_RULES_PER_SERVICE + 1,
                    '||oversized.service.test^',
                ),
            ),
        ] as $document) {
            $threw = false;

            try {
                ServiceRegistry::parse($document);
            } catch (Throwable) {
                $threw = true;
            }

            sinkholeTestAssertTrue($threw, 'Malformed or oversized registries must fail closed.');
        }
    },
    'untrusted service icons are exposed only through a data-uri image source' => static function (): void {
        $hostileIcon = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>';
        $registry = ServiceRegistry::parse(sinkholeServicesTestDocument(icon: $hostileIcon));
        $presented = ServicePresentation::service($registry['services']['invented-video']);
        $image = '<img src="' . $presented['icon'] . '" alt="">';

        sinkholeTestAssertContains(
            'data:image/svg+xml;base64,',
            $image,
            'The icon must be a data URI.',
        );
        sinkholeTestAssertSame(false, str_contains($image, '<svg'), 'SVG markup must not be inline.');
        sinkholeTestAssertSame(false, str_contains($image, '<script'), 'Hostile SVG markup must not be inline.');

        $oversized = ServiceRegistry::parse(sinkholeServicesTestDocument(
            icon: str_repeat('x', ServiceRegistry::MAXIMUM_ICON_BYTES + 1),
        ));
        sinkholeTestAssertSame(
            true,
            $oversized['services']['invented-video']['icon_oversized'],
            'Oversized icons must be replaced by the generic image.',
        );
    },
    'per-scope service storage keeps unknown ids for repair' => static function (): void {
        $networkIdentifier = '11111111111111111111111111111111';
        $configuration = [
            'global' => ['invented-video', 'retired-invented-service'],
            'networks' => [$networkIdentifier => ['invented-video']],
            'devices' => [],
        ];
        $storage = ServiceConfiguration::storage($configuration);
        $roundTrip = ServiceConfiguration::partition($storage);

        sinkholeTestAssertSame(
            ['invented-video', 'retired-invented-service'],
            $roundTrip['global'],
            'Unknown syntactically valid IDs must survive storage for repair.',
        );
        sinkholeTestAssertSame(
            ['invented-video'],
            $roundTrip['networks'][$networkIdentifier],
            'Network selections must round-trip below item elements.',
        );
        sinkholeTestAssertTrue(
            array_key_exists('item', $storage['global']),
            'Global service values must use the repeated item key.',
        );
        sinkholeTestAssertTrue(
            array_key_exists('item', $storage['networks']['item'][0]['services']),
            'Scoped service values must use the repeated item key.',
        );
    },
    'bypass-owned service ids are hidden dropped and never compiled' => static function (): void {
        $hiddenIdentifier = ServiceRegistry::HIDDEN_SERVICE_IDENTIFIERS[0];
        $registry = ServiceRegistry::parse(sinkholeServicesTestDocument(
            name: 'Invented Relay Signal',
            rules: ['||invented-relay.service.test^'],
            serviceIdentifier: $hiddenIdentifier,
        ));
        $view = ServiceRegistry::facetedView($registry, 'Invented', 'invented_media');

        sinkholeTestAssertSame(
            [],
            $registry['services'],
            'A Bypass-owned registry ID must not enter presentation data.',
        );
        sinkholeTestAssertSame([], $view['services'], 'Search must not return a hidden service.');
        sinkholeTestAssertSame([], $view['groups'], 'Group buttons must omit hidden-only groups.');
        sinkholeTestAssertSame(
            0,
            $view['group_counts'][''],
            'The all-services count must omit hidden services.',
        );

        $networkIdentifier = '12121212121212121212121212121212';
        $saved = [
            'global' => [$hiddenIdentifier, 'retired-invented-service'],
            'networks' => [$networkIdentifier => [$hiddenIdentifier, 'invented-video']],
            'devices' => [],
        ];
        $partitioned = ServiceConfiguration::partition($saved);
        $storage = ServiceConfiguration::storage($saved);

        sinkholeTestAssertSame(
            ['retired-invented-service'],
            $partitioned['global'],
            'Loading must drop the hidden ID while preserving unrelated unknown IDs.',
        );
        sinkholeTestAssertSame(
            ['invented-video'],
            $partitioned['networks'][$networkIdentifier],
            'Scoped loading must drop the hidden ID.',
        );
        sinkholeTestAssertSame(
            false,
            str_contains(json_encode($storage, JSON_THROW_ON_ERROR), $hiddenIdentifier),
            'Saving must not write the hidden ID back to configuration.',
        );
        $counts = ServiceConfiguration::counts($saved);
        sinkholeTestAssertSame(1, $counts['global'], 'Counts must omit the hidden global selection.');
        sinkholeTestAssertSame(
            1,
            $counts['networks'][$networkIdentifier],
            'Counts must omit the hidden network selection.',
        );

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeServicesTestPaths($directory);
            $untrustedRegistry = [
                'groups' => ['invented_media' => true],
                'services' => [
                    $hiddenIdentifier => [
                        'id' => $hiddenIdentifier,
                        'name' => 'Invented Relay Signal',
                        'group' => 'invented_media',
                        'rules' => [[
                            'domain' => 'invented-relay.service.test',
                            'semantic' => 'subtree',
                        ]],
                    ],
                ],
            ];
            (new Compiler($paths, new SavedListStore($paths)))->compile(
                configuredLists: [],
                allowedDomains: [],
                configuredServices: ['global' => [$hiddenIdentifier]],
                serviceRegistry: $untrustedRegistry,
            );
            $manifest = sinkholeServicesTestManifest($paths);

            sinkholeTestAssertSame(
                [],
                $manifest['lists'],
                'Compilation must ignore an old hidden selection even at a defensive registry boundary.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'blocked-service rules compile only into their scope and allow files keep priority' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeServicesTestPaths($directory);
            $networkIdentifier = '22222222222222222222222222222222';
            $registry = ServiceRegistry::parse(sinkholeServicesTestDocument(rules: [
                '||blocked.service.test^',
                '||allowed.service.test^',
            ]));
            (new Compiler($paths, new SavedListStore($paths)))->compile(
                configuredLists: [],
                allowedDomains: [],
                configuredNetworks: [[
                    'id' => $networkIdentifier,
                    'interface' => 'lan',
                    'lists' => [],
                    'allowed_domains' => ['allowed.service.test'],
                    'enabled' => true,
                ]],
                configuredServices: [
                    'global' => [],
                    'networks' => [$networkIdentifier => ['invented-video']],
                    'devices' => [],
                ],
                serviceRegistry: $registry,
            );
            $manifest = sinkholeServicesTestManifest($paths);
            $rows = sinkholeServicesTestRows($paths);
            $syntheticIdentifier = ServiceRegistry::syntheticListIdentifier('invented-video');
            $serviceBit = $manifest['lists'][$syntheticIdentifier]['bit'];

            sinkholeTestAssertSame(
                [],
                $manifest['scopes']['global']['lists'],
                'A network service must not be assigned globally.',
            );
            sinkholeTestAssertSame(
                [$syntheticIdentifier],
                $manifest['scopes']['networks'][$networkIdentifier]['lists'],
                'The selected service must be assigned only to its network scope.',
            );
            sinkholeTestAssertTrue(
                in_array($serviceBit, $rows['blocked.service.test']['subtree'], true),
                'The selected service domain must carry the service list bit.',
            );
            sinkholeTestAssertSame(
                "allowed.service.test\n",
                file_get_contents(
                    $paths->runtimeDataDirectory
                    . '/allow-network-'
                    . $networkIdentifier
                    . '.txt',
                ),
                'The same-level allow file must retain priority over service rules.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'service registry cache reuses refreshes falls back and removes its file' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $initial = sinkholeServicesTestDocument('Invented Initial');
            $refreshed = sinkholeServicesTestDocument('Invented Refreshed');
            $client = new SinkholeServicesTestDownloadClient([
                ['contents' => $initial],
                ['contents' => $refreshed],
                ['error' => 'Invented registry outage.'],
            ]);
            $paths = sinkholeServicesTestPaths($directory);
            $cache = new ServiceRegistryCache($paths, $client);
            $first = $cache->load(false, 1000);
            $reused = $cache->load(false, 1100);

            sinkholeTestAssertSame(1, count($client->calls), 'A fresh registry must be reused.');
            sinkholeTestAssertSame(
                'Invented Initial',
                $reused['registry']['services']['invented-video']['name'],
                'A cache hit must keep the initial document.',
            );
            $second = $cache->load(true, 1200);
            $fallback = $cache->load(true, 1300);
            sinkholeTestAssertSame(
                'Invented Refreshed',
                $second['registry']['services']['invented-video']['name'],
                'A forced refresh must replace the cache.',
            );
            sinkholeTestAssertSame(3, count($client->calls), 'Each forced refresh must fetch.');
            sinkholeTestAssertSame(
                'Invented Refreshed',
                $fallback['registry']['services']['invented-video']['name'],
                'A failed refresh must use the last good copy.',
            );
            sinkholeTestAssertTrue(
                $fallback['status']['last_error'] !== '',
                'A failed refresh must expose its error.',
            );
            sinkholeTestAssertSame(
                $second['registry'],
                ServiceRegistryCache::cachedRegistry($paths),
                'Compilation reads must reuse the cache without a network client.',
            );
            ServiceRegistryCache::removeCacheFile($paths);
            sinkholeTestAssertSame(
                false,
                file_exists($paths->serviceRegistryCacheFile),
                'Removal must delete the service registry cache.',
            );
            sinkholeTestAssertSame(
                'Invented Initial',
                $first['registry']['services']['invented-video']['name'],
                'The initial fetch must be returned.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'blocked-services English catalog keys are complete' => static function (): void {
        $catalogs = require(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Translations.php');
        $english = $catalogs['en_US'] ?? [];

        foreach ([
            'blocked_services',
            'blocked_services_help',
            'needs_repair',
            'no_services_found',
            'revision_saved_services',
            'service_registry_refresh_finished',
            'service_registry_status',
            'service_group_ai',
            'service_group_cdn',
            'service_group_dating',
            'service_group_gambling',
            'service_group_gaming',
            'service_group_hosting',
            'service_group_messenger',
            'service_group_privacy',
            'service_group_shopping',
            'service_group_social_network',
            'service_group_software',
            'service_group_streaming',
            'services',
            'unknown_service_help',
        ] as $key) {
            sinkholeTestAssertTrue(
                is_string($english[$key] ?? null) && $english[$key] !== '',
                'The English catalog must define blocked-services key: ' . $key,
            );
        }
    },
]);
