<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\ClientMap;
use PfSense\Sinkhole\Runtime\ClientSource;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\SavedListStore;
use PfSense\Sinkhole\Runtime\StateStore;

require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Compiler.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ClientSource.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ClientMap.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ScopeConfiguration.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/StateStore.php');

/**
 * End-to-End Client Source.
 *
 * Supplies fixed interface and device fixtures to the real client-map builder.
 *
 * @since 1.0.0
 */
final class SinkholeE2eClientSource implements ClientSource
{
    /** @inheritDoc @since 1.0.0 */
    public function getNetworks(): array
    {
        return [
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' => [
                'id' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'interface' => 'lan',
                'enabled' => true,
            ],
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' => [
                'id' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                'interface' => 'opt1',
                'enabled' => true,
            ],
        ];
    }

    /** @inheritDoc @since 1.0.0 */
    public function getDevices(): array
    {
        return ['dddddddddddddddddddddddddddddddd' => [
            'id' => 'dddddddddddddddddddddddddddddddd',
            'identifier_type' => 'ip',
            'identifier' => '192.0.2.10',
            'interface' => '',
            'enabled' => true,
        ]];
    }

    /** @inheritDoc @since 1.0.0 */
    public function getInterfaceSubnets(): array
    {
        return [
            'lan' => ['192.0.2.0/24'],
            'opt1' => ['198.51.100.0/24'],
        ];
    }

    /** @inheritDoc @since 1.0.0 */
    public function getInterfaceAddresses(): array
    {
        return [];
    }

    /** @inheritDoc @since 1.0.0 */
    public function getBypassInterfaces(): array
    {
        return [];
    }

    /** @inheritDoc @since 1.0.0 */
    public function getStaticMappings(): array
    {
        return [];
    }

    /** @inheritDoc @since 1.0.0 */
    public function getArpEntries(): array
    {
        return [];
    }

    /** @inheritDoc @since 1.0.0 */
    public function getNdpOutput(): string
    {
        return '';
    }

    /** @inheritDoc @since 1.0.0 */
    public function getDhcpLeases(): array
    {
        return [];
    }

    /** @inheritDoc @since 1.0.0 */
    public function getDhcpLeaseContext(): array
    {
        return [
            'times_local' => false,
            'active' => 'active',
            'expired' => 'expired',
            'reserved' => 'reserved',
            'never' => 'Never',
        ];
    }

    /** @inheritDoc @since 1.0.0 */
    public function usesMemoryFileSystem(): bool
    {
        return false;
    }

    /** @inheritDoc @since 1.0.0 */
    public function log(string $message): void
    {
        unset($message);
    }
}

if (count($argv) !== 3 || !in_array($argv[2], ['initial', 'reload', 'zero'], true)) {
    fwrite(STDERR, 'Usage: e2e-compile.php ROOT initial|reload|zero' . PHP_EOL);

    exit(64);
}

$root = $argv[1];
$scenario = $argv[2];

if (is_dir($root) === false && mkdir($root, 0700, true) === false) {
    throw new RuntimeException('Unable to create the end-to-end root.');
}

$paths = new PackagePaths([
    'persistent_directory' => $root . '/persistent',
    'runtime_root_directory' => $root . '/runtime',
    'update_lock_file' => $root . '/sinkhole-update.lock',
    'runtime_lock_file' => $root . '/sinkhole-runtime.lock',
    'client_lock_file' => $root . '/sinkhole-clients.lock',
    'runtime_user' => '',
    'runtime_group' => '',
    'storage_user' => '',
    'storage_group' => '',
]);
$store = new SavedListStore($paths);
$compiler = new Compiler($paths, $store);
$identifier = '77777777777777777777777777777777';
$networkListIdentifier = '88888888888888888888888888888888';
$deviceListIdentifier = '99999999999999999999999999999999';
$lists = [];
$allowedDomains = [];
$networks = [];
$devices = [];
$alerts = [];

if ($scenario !== 'zero') {
    $rawContents = ($scenario === 'initial')
        ? implode(PHP_EOL, [
            '0.0.0.0 hosts.example.com second.example.net # hosts comment',
            '0.0.0.0 ads.example.com ## note',
            'plain.example.org # plain comment',
            '_service.example.com',
            '||adblock.example.net^',
            '||tree.example.net^',
            '||ignored.example.com^$third-party',
            'cosmetic.example.com##.ad-slot',
            'cosmetic.example.org#@#.promoted',
            'cosmetic.example.net#?#div:has(a)',
            'style.example.com#$#body',
            'example.com##.ad-slot',
            'example.com,example.org#@#.x',
            'localhost',
            'com',
            'lan',
            '# ignored fixture comment',
            '',
        ])
        : "0.0.0.0 reloaded.example.org\n";
    $rawPath = $root . '/fixture-' . $scenario . '.txt';
    $normalizedPath = $store->createTemporaryFile('.e2e-normalized-');

    file_put_contents($rawPath, $rawContents);
    $parseResult = (new DomainParser())->parseFile($rawPath, $normalizedPath);

    if ($parseResult['accepted'] === 0) {
        throw new RuntimeException('The end-to-end fixture produced no domains.');
    }

    $sha256 = hash_file('sha256', $normalizedPath);

    if (!is_string($sha256)) {
        throw new RuntimeException('Unable to hash the end-to-end fixture.');
    }

    $store->commitSuccessfulDownload(
        $identifier,
        $normalizedPath,
        [
            'url' => 'https://lists.example.invalid/e2e.test',
            'fetched_at' => '2026-01-01T00:00:00+00:00',
            'entries' => $parseResult['accepted'],
            'ignored' => $parseResult['ignored'],
            'sha256' => $sha256,
            'last_attempt' => '2026-01-01T00:00:00+00:00',
            'last_error' => null,
        ],
    );
    $lists = [
        $identifier => [
            'id' => $identifier,
            'descr' => 'End-to-End Example',
            'url' => 'https://lists.example.invalid/e2e.test',
            'enabled' => 'on',
            'global' => 'on',
        ],
    ];
    $allowedDomains = ($scenario === 'initial') ? ['allowed.tree.example.net'] : [];

    if ($scenario === 'initial') {
        foreach (
            [
                $networkListIdentifier => [
                    'name' => 'Network Example',
                    'url' => 'https://lists.example.invalid/network-e2e.test',
                    'contents' => "network-a.example.test\n",
                ],
                $deviceListIdentifier => [
                    'name' => 'Device Example',
                    'url' => 'https://lists.example.invalid/device-e2e.test',
                    'contents' => "device-a.example.test\n",
                ],
            ] as $scopeListIdentifier => $fixture
        ) {
            $scopeRawPath = $root . '/fixture-' . $scopeListIdentifier . '.txt';
            $scopeNormalizedPath = $store->createTemporaryFile('.e2e-normalized-');
            file_put_contents($scopeRawPath, $fixture['contents']);
            $scopeParseResult = (new DomainParser())->parseFile(
                $scopeRawPath,
                $scopeNormalizedPath,
            );
            $scopeSha256 = hash_file('sha256', $scopeNormalizedPath);

            if (!is_string($scopeSha256) || $scopeParseResult['accepted'] === 0) {
                throw new RuntimeException('A scoped end-to-end fixture is invalid.');
            }

            $store->commitSuccessfulDownload(
                $scopeListIdentifier,
                $scopeNormalizedPath,
                [
                    'url' => $fixture['url'],
                    'fetched_at' => '2026-01-01T00:00:00+00:00',
                    'entries' => $scopeParseResult['accepted'],
                    'ignored' => $scopeParseResult['ignored'],
                    'sha256' => $scopeSha256,
                    'last_attempt' => '2026-01-01T00:00:00+00:00',
                    'last_error' => null,
                ],
            );
            $lists[$scopeListIdentifier] = [
                'id' => $scopeListIdentifier,
                'descr' => $fixture['name'],
                'url' => $fixture['url'],
                'enabled' => 'on',
                'global' => '',
            ];
        }

        $networks = [
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' => [
                'id' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'interface' => 'lan',
                'lists' => [$networkListIdentifier],
                'allowed_domains' => [],
                'enabled' => true,
            ],
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' => [
                'id' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                'interface' => 'opt1',
                'lists' => [],
                'allowed_domains' => [],
                'enabled' => true,
            ],
        ];
        $devices = ['dddddddddddddddddddddddddddddddd' => [
            'id' => 'dddddddddddddddddddddddddddddddd',
            'lists' => [$deviceListIdentifier],
            'allowed_domains' => [],
            'enabled' => true,
        ]];
        $alerts = ['44444444444444444444444444444444' => [
            'id' => '44444444444444444444444444444444',
            'description' => 'Device alert',
            'any_list' => false,
            'lists' => [$deviceListIdentifier],
            'everyone' => false,
            'networks' => [],
            'devices' => ['dddddddddddddddddddddddddddddddd'],
            'repeat_minutes' => 60,
            'notice' => true,
            'remote' => true,
            'enabled' => true,
        ]];
    }
}

$result = $compiler->compile(
    $lists,
    $allowedDomains,
    false,
    true,
    null,
    false,
    null,
    $networks,
    $devices,
    $alerts,
);

if ($scenario === 'initial') {
    $clientResult = (new ClientMap(
        $paths,
        new SinkholeE2eClientSource(),
        new StateStore($paths->stateFile),
    ))->refresh();

    if ($clientResult['status'] === 'error') {
        throw new RuntimeException((string) $clientResult['error']);
    }
}

fwrite(
    STDOUT,
    json_encode($result, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL,
);
