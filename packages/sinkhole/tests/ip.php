<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\Catalog;
use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\IpConfiguration;
use PfSense\Sinkhole\Domain\IpNetwork;
use PfSense\Sinkhole\Domain\IpParser;
use PfSense\Sinkhole\Domain\IpRuleConfiguration;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\DownloadClient;
use PfSense\Sinkhole\Runtime\GeoLite2;
use PfSense\Sinkhole\Runtime\IpListStore;
use PfSense\Sinkhole\Runtime\IpStatusStore;
use PfSense\Sinkhole\Runtime\IpUpdater;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\PfSenseAdapter;
use PfSense\Sinkhole\Runtime\SavedListStore;
use PfSense\Sinkhole\Runtime\StateStore;
use PfSense\Sinkhole\Runtime\Updater;

set_include_path(__DIR__ . '/stubs' . PATH_SEPARATOR . get_include_path());

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/stubs/config.inc');
require_once(__DIR__ . '/stubs/services.inc');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole.inc');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Catalog.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/DownloadClient.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/GeoLite2.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpConfiguration.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpListStore.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpNetwork.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpParser.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpRuleConfiguration.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpStatusStore.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpUpdater.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/PackagePaths.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/PfSenseAdapter.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/StateStore.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Updater.php');

/** @since 1.0.0 */
final class SinkholeIpTestDownloadClient implements DownloadClient
{
    /** @var list<array> @since 1.0.0 */
    public array $calls = [];

    /** @since 1.0.0 */
    public function __construct(private readonly string $error = '')
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
        $this->calls[] = compact('url', 'destinationPath', 'maximumBytes', 'username', 'password');

        return ['success' => false, 'bytes' => 0, 'error' => $this->error];
    }
}

/** @since 1.0.0 */
final class SinkholeIpFixtureDownloadClient implements DownloadClient
{
    /** @since 1.0.0 */
    public function __construct(private readonly array $responses)
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
        unset($username, $password);
        $contents = $this->responses[$url] ?? null;

        if (!is_string($contents) || strlen($contents) > $maximumBytes) {
            return ['success' => false, 'bytes' => 0, 'error' => 'Invented fixture missing.'];
        }

        $bytes = file_put_contents($destinationPath, $contents);

        return is_int($bytes)
            ? ['success' => true, 'bytes' => $bytes, 'error' => null]
            : ['success' => false, 'bytes' => 0, 'error' => 'Invented fixture write failed.'];
    }
}

/** @since 1.0.0 */
function sinkholeIpTestPaths(string $root): PackagePaths
{
    return new PackagePaths([
        'persistent_directory' => $root . '/persistent',
        'runtime_root_directory' => $root . '/runtime',
        'module_source_file' => $root . '/sinkhole_unbound.py',
        'update_lock_file' => $root . '/update.lock',
        'runtime_lock_file' => $root . '/runtime.lock',
        'client_lock_file' => $root . '/client.lock',
        'alert_lock_file' => $root . '/alert.lock',
        'redirect_check_lock_file' => $root . '/check.lock',
        'redirect_check_state_file' => $root . '/check.json',
        'redirect_rule_error_file' => $root . '/rules.packages.sinkhole',
        'status_file' => $root . '/status.json',
        'ip_table_ipv4_file' => $root . '/sinkhole-block-v4.txt',
        'ip_table_ipv6_file' => $root . '/sinkhole-block-v6.txt',
        'ip_anchor_file' => $root . '/sinkhole-ip-anchor.conf',
        'ip_anchor_digest_file' => $root . '/sinkhole-ip-anchor.sha256',
        'geolite2_archive_file' => $root . '/geolite.zip',
        'geolite2_metadata_file' => $root . '/geolite.json',
        'ip_status_file' => $root . '/ip-status.json',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/**
 * Sinkhole IP Test - Missing Protected Address Helpers.
 *
 * An isolated include path proves that absent optional pfSense helpers retain the
 * static protected set and emit only one warning per helper on one adapter.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeIpTestMissingProtectedAddressHelpers(): void
{
    global $sinkholeStubLogs;

    $root = sinkholeTestTemporaryDirectory();
    $previousIncludePath = get_include_path();

    try {
        sinkholeStubReset([
            'system' => ['dnsserver' => ['198.51.100.2']],
            'gateways' => ['gateway_item' => [['gateway' => '198.51.100.3']]],
        ]);
        set_include_path($root);
        $paths = sinkholeIpTestPaths($root);
        $adapter = new PfSenseAdapter(
            $paths,
            new StateStore($paths->stateFile, $paths->statusFile),
        );

        sinkholeTestAssertSame(
            ['198.51.100.2', '198.51.100.3'],
            $adapter->ipProtectedAddresses(),
            'Missing runtime helpers must retain configured DNS and gateway protection.',
        );
        sinkholeTestAssertSame(
            ['198.51.100.2', '198.51.100.3'],
            $adapter->ipProtectedAddresses(),
            'Repeated discovery must continue without optional runtime helpers.',
        );
        sinkholeTestAssertSame(
            2,
            count($sinkholeStubLogs),
            'Each missing protected-address helper must be logged only once per adapter.',
        );
        sinkholeTestAssertContains(
            'get_dynamic_nameservers',
            implode("\n", $sinkholeStubLogs),
            'The missing dynamic DNS helper must be identified in the adapter log.',
        );
        sinkholeTestAssertContains(
            'return_gateways_array',
            implode("\n", $sinkholeStubLogs),
            'The missing runtime gateway helper must be identified in the adapter log.',
        );
    } finally {
        set_include_path($previousIncludePath);
        sinkholeTestRemoveTemporaryDirectory($root);
    }
}

if (($argv[1] ?? '') === '--missing-protected-address-helpers') {
    sinkholeIpTestMissingProtectedAddressHelpers();

    exit(0);
}

sinkholeTestRun([
    'IP parser canonicalizes rows separates ignorable input and enforces families' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $input = $root . '/input.txt';
            $output = $root . '/output.txt';
            $ipv4Output = $root . '/ipv4-output.txt';
            file_put_contents(
                $input,
                "# comment\n; comment\n\n \t \n"
                    . "192.0.2.7\n192.0.2.99/24 # note\ninvalid\n2001:db8::1/64\n"
                    . "0.0.0.0/0\n1.0.0.0/7\n8.0.0.0/8\n"
                    . "::/0\n2000::/15\n2001::/16\n",
            );
            $result = (new IpParser())->parseFile($input, $output);

            sinkholeTestAssertSame(5, $result['accepted'], 'Valid rows at both safety bounds must parse.');
            sinkholeTestAssertSame(
                5,
                $result['skipped'],
                'Only invalid and too-broad rows must be counted; comments and blanks must not.',
            );
            sinkholeTestAssertSame(
                "192.0.2.7/32\n192.0.2.0/24\n2001:db8::/64\n"
                    . "8.0.0.0/8\n2001::/16\n",
                file_get_contents($output),
                'IP rows must be stored canonically.',
            );

            $ipv4Result = (new IpParser())->parseFile($input, $ipv4Output, 'ipv4');

            sinkholeTestAssertSame(
                3,
                $ipv4Result['accepted'],
                'An IPv4 list must retain only valid IPv4 rows.',
            );
            sinkholeTestAssertSame(
                7,
                $ipv4Result['skipped'],
                'Valid wrong-family rows must join invalid and too-broad rows in the skipped count.',
            );
            sinkholeTestAssertSame(
                "192.0.2.7/32\n192.0.2.0/24\n8.0.0.0/8\n",
                file_get_contents($ipv4Output),
                'A family restriction must not write valid rows from the other family.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'IP networks merge contained siblings and subtract allowlists' => static function (): void {
        sinkholeTestAssertSame(
            ['192.0.2.0/24', '2001:db8::/64'],
            IpNetwork::merge([
                '192.0.2.0/25',
                '192.0.2.128/25',
                '192.0.2.1/32',
                '2001:db8::/65',
                '2001:db8:0:0:8000::/65',
            ]),
            'Sibling and contained CIDRs must collapse per family.',
        );
        sinkholeTestAssertSame(
            ['192.0.2.0/26', '192.0.2.128/25'],
            IpNetwork::subtract(['192.0.2.0/24'], ['192.0.2.64/26']),
            'The allowlist must split a broader blocked network around its CIDR.',
        );
        sinkholeTestAssertSame(
            ['192.0.2.0/32', '192.0.2.2/31'],
            IpNetwork::subtract(['192.0.2.0/30'], ['192.0.2.1']),
            'An excluded IPv4 host must split the containing blocked CIDR.',
        );
        sinkholeTestAssertSame(
            ['2001:db8::/128', '2001:db8::2/127'],
            IpNetwork::subtract(['2001:db8::/126'], ['2001:db8::1']),
            'An excluded IPv6 host must split the containing blocked CIDR.',
        );
        $limitThrew = false;

        try {
            IpNetwork::merge(['192.0.2.1', '198.51.100.1'], 1);
        } catch (RuntimeException) {
            $limitThrew = true;
        }

        sinkholeTestAssertTrue($limitThrew, 'The configurable merge count cap must be enforced.');
    },
    'pfBlockerNG IP catalog parses both address sections and leaves DNS separate' => static function (): void {
        $document = json_encode([
            'ipv4' => ['PRI1' => [
                'description' => 'Invented IPv4 group',
                'info' => 'fixture',
                'action' => 'Disabled',
                'cron' => 'Never',
                'feeds' => [[
                    'feed' => 'Invented v4 feed',
                    'website' => 'https://example.test/v4',
                    'url' => 'https://example.test/v4.txt',
                    'header' => 'v4',
                ]],
            ]],
            'ipv6' => ['PRI1' => [
                'description' => 'Invented IPv6 group',
                'info' => 'fixture',
                'action' => 'Disabled',
                'cron' => 'Never',
                'feeds' => [[
                    'feed' => 'Invented v6 feed',
                    'website' => 'https://example.test/v6',
                    'url' => 'https://example.test/v6.txt',
                    'header' => 'v6',
                ]],
            ]],
            'dnsbl' => ['DNS' => [
                'description' => 'Invented DNS group',
                'feeds' => [[
                    'feed' => 'Invented DNS feed',
                    'website' => '',
                    'url' => 'https://example.test/dns.txt',
                    'header' => 'dns',
                ]],
            ]],
        ], JSON_THROW_ON_ERROR);
        $ipEntries = Catalog::parseIp($document);
        $dnsEntries = Catalog::parse(Catalog::SOURCE_PFBLOCKERNG, $document);

        sinkholeTestAssertSame(['ipv4', 'ipv6'], array_column($ipEntries, 'family'), 'Both IP sections must parse.');
        sinkholeTestAssertSame(['Invented DNS feed'], array_column($dnsEntries, 'name'), 'DNS search must still use only dnsbl.');
    },
    'GeoLite2 fixtures use geoname fallback and verified checksums' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $locations = $root . '/locations.csv';
            $ipv4 = $root . '/ipv4.csv';
            $ipv6 = $root . '/ipv6.csv';
            $archive = $root . '/archive.zip';
            file_put_contents($locations, "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name\n1,en,NA,North America,AA,Alpha\n2,en,EU,Europe,BB,Beta\n");
            file_put_contents($ipv4, "network,geoname_id,registered_country_geoname_id\n192.0.2.0/24,1,2\n198.51.100.0/24,,1\n203.0.113.0/24,2,1\n");
            file_put_contents($ipv6, "network,geoname_id,registered_country_geoname_id\n2001:db8::/32,1,2\n");
            file_put_contents($archive, 'invented archive bytes');
            $sha256 = hash_file('sha256', $archive);
            $result = (new GeoLite2())->importFiles($locations, $ipv4, $ipv6, ['AA']);

            sinkholeTestAssertSame(
                ['192.0.2.0/24', '198.51.100.0/24'],
                $result['ipv4'],
                'Primary geoname IDs and registered-country fallbacks must both work.',
            );
            sinkholeTestAssertSame(['2001:db8::/32'], $result['ipv6'], 'IPv6 country networks must import.');
            sinkholeTestAssertSame($sha256, GeoLite2::verifyArchive($archive, $sha256 . "  fixture.zip\n"), 'The matching SHA-256 must verify.');
            $mismatchThrew = false;

            try {
                GeoLite2::verifyArchive($archive, str_repeat('0', 64) . "  fixture.zip\n");
            } catch (RuntimeException) {
                $mismatchThrew = true;
            }

            sinkholeTestAssertTrue($mismatchThrew, 'A mismatched GeoLite2 checksum must be rejected.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'anchor text is exact for every direction and family and contains no pass' => static function (): void {
        $interfaces = [[
            'interface' => 'lan',
            'real_interface' => 'igc0',
            'ipv4' => true,
            'ipv6' => true,
        ]];
        $rules = IpRuleConfiguration::anchorText(
            $interfaces,
            ['inbound', 'outbound'],
            '/var/db/sinkhole-block-v4.txt',
            '/var/db/sinkhole-block-v6.txt',
        );
        $expected = <<<'RULES'
# Sinkhole IP blocking
table <sinkhole_block_v4> persist file "/var/db/sinkhole-block-v4.txt"
table <sinkhole_block_v6> persist file "/var/db/sinkhole-block-v6.txt"
block drop in quick on igc0 inet from <sinkhole_block_v4> to any
block drop in quick on igc0 inet from any to <sinkhole_block_v4>
block drop in quick on igc0 inet6 from <sinkhole_block_v6> to any
block drop in quick on igc0 inet6 from any to <sinkhole_block_v6>
RULES;
        sinkholeTestAssertSame($expected . PHP_EOL, $rules, 'The exact dual-family rule text must remain stable.');
        sinkholeTestAssertSame(
            "# Sinkhole IP blocking\n"
                . "table <sinkhole_block_v4> persist file \"/var/db/sinkhole-block-v4.txt\"\n"
                . "table <sinkhole_block_v6> persist file \"/var/db/sinkhole-block-v6.txt\"\n"
                . "block drop in quick on igc0 inet from <sinkhole_block_v4> to any\n",
            IpRuleConfiguration::anchorText(
                [[
                    'interface' => 'lan',
                    'real_interface' => 'igc0',
                    'ipv4' => true,
                    'ipv6' => false,
                ]],
                ['inbound'],
                '/var/db/sinkhole-block-v4.txt',
                '/var/db/sinkhole-block-v6.txt',
            ),
            'The exact IPv4 inbound rule text must remain stable.',
        );
        sinkholeTestAssertSame(
            "# Sinkhole IP blocking\n"
                . "table <sinkhole_block_v4> persist file \"/var/db/sinkhole-block-v4.txt\"\n"
                . "table <sinkhole_block_v6> persist file \"/var/db/sinkhole-block-v6.txt\"\n"
                . "block drop in quick on em2 inet from any to <sinkhole_block_v4>\n",
            IpRuleConfiguration::anchorText(
                [[
                    'interface' => 'lan',
                    'real_interface' => 'em2',
                    'ipv4' => true,
                    'ipv6' => false,
                ]],
                ['outbound'],
                '/var/db/sinkhole-block-v4.txt',
                '/var/db/sinkhole-block-v6.txt',
            ),
            'The exact IPv4 outbound rule text must remain stable.',
        );
        sinkholeTestAssertSame(
            "# Sinkhole IP blocking\n"
                . "table <sinkhole_block_v4> persist file \"/var/db/sinkhole-block-v4.txt\"\n"
                . "table <sinkhole_block_v6> persist file \"/var/db/sinkhole-block-v6.txt\"\n"
                . "block drop in quick on igc0 inet6 from <sinkhole_block_v6> to any\n",
            IpRuleConfiguration::anchorText(
                [[
                    'interface' => 'lan',
                    'real_interface' => 'igc0',
                    'ipv4' => false,
                    'ipv6' => true,
                ]],
                ['inbound'],
                '/var/db/sinkhole-block-v4.txt',
                '/var/db/sinkhole-block-v6.txt',
            ),
            'The exact IPv6 inbound rule text must remain stable.',
        );
        sinkholeTestAssertSame(
            "# Sinkhole IP blocking\n"
                . "table <sinkhole_block_v4> persist file \"/var/db/sinkhole-block-v4.txt\"\n"
                . "table <sinkhole_block_v6> persist file \"/var/db/sinkhole-block-v6.txt\"\n"
                . "block drop in quick on em2 inet6 from any to <sinkhole_block_v6>\n",
            IpRuleConfiguration::anchorText(
                [[
                    'interface' => 'lan',
                    'real_interface' => 'em2',
                    'ipv4' => false,
                    'ipv6' => true,
                ]],
                ['outbound'],
                '/var/db/sinkhole-block-v4.txt',
                '/var/db/sinkhole-block-v6.txt',
            ),
            'The exact IPv6 outbound rule text must remain stable.',
        );
        sinkholeTestAssertSame(false, str_contains($rules, 'pass '), 'The anchor must contain no pass rule.');
    },
    'empty IP list fields survive every pfSense XML writer shape' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $shapes = [
            'empty string' => '',
            'empty array' => [],
            'empty item array' => ['item' => []],
            'empty item string' => ['item' => ''],
            'missing key' => null,
        ];
        $fields = [
            'interfaces' => ['interfaces', 'stored_interfaces'],
            'directions' => ['directions', 'stored_directions'],
            'lists' => ['lists'],
            'countries' => ['countries', 'stored_countries'],
            'allowlist' => ['allowlist', 'stored_allowlist'],
        ];

        try {
            $paths = sinkholeIpTestPaths($root);

            foreach ($fields as $field => $resultKeys) {
                foreach ($shapes as $shapeName => $shape) {
                    $stored = [];

                    if ($shapeName !== 'missing key') {
                        $stored[$field] = $shape;
                    }

                    sinkholeStubReset([
                        'installedpackages' => ['sinkhole' => ['ip' => $stored]],
                    ]);
                    write_config('Round-trip an invented empty IP list field.');
                    $configuration = (new PfSenseAdapter(
                        $paths,
                        new StateStore($paths->stateFile, $paths->statusFile),
                    ))->getIpConfiguration();
                    $context = $field . ' using ' . $shapeName;

                    foreach ($resultKeys as $resultKey) {
                        sinkholeTestAssertSame(
                            [],
                            $configuration[$resultKey],
                            'The empty field must remain empty after XML round-trip: ' . $context,
                        );
                    }

                    sinkholeTestAssertSame(
                        [],
                        $configuration['invalid_values'],
                        'The empty field must not produce an invalid value: ' . $context,
                    );
                    sinkholeTestAssertSame(
                        [],
                        $configuration['invalid_lists'],
                        'The empty field must not produce an invalid list row: ' . $context,
                    );
                }
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'IP anchor flush distinguishes absent empty loaded and failed states' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubCommandStatuses;
        global $sinkholeStubExecOutputs;
        global $sinkholeStubExecStatuses;
        global $sinkholeStubIpAnchorLoaded;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeIpTestPaths($root);
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $rulesCommand = "/sbin/pfctl -a 'sinkhole/ip' -sr 2>/dev/null";
            $tablesCommand = "/sbin/pfctl -a 'sinkhole/ip' -sT 2>/dev/null";
            $parentAnchorsCommand = "/sbin/pfctl -a 'sinkhole' -sA 2>/dev/null";
            $rootAnchorsCommand = '/sbin/pfctl -sA 2>/dev/null';
            $flushCommand = "/sbin/pfctl -a 'sinkhole/ip' -F all";

            sinkholeStubReset([]);
            file_put_contents($paths->ipAnchorFile, 'stale absent anchor');
            file_put_contents($paths->ipAnchorDigestFile, 'stale absent digest');
            $sinkholeStubExecStatuses[$rulesCommand] = 1;
            $sinkholeStubExecStatuses[$tablesCommand] = 1;

            $adapter->flushIpAnchor();

            sinkholeTestAssertSame(
                [$rulesCommand, $tablesCommand],
                $sinkholeStubCommands,
                'An absent anchor must be inspected without running a flush command.',
            );
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorFile), 'An absent anchor must remove stale anchor text.');
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorDigestFile), 'An absent anchor must remove its stale digest.');

            sinkholeStubReset([]);
            file_put_contents($paths->ipAnchorFile, 'stale empty anchor');
            file_put_contents($paths->ipAnchorDigestFile, 'stale empty digest');
            $sinkholeStubExecStatuses[$rulesCommand] = 0;
            $sinkholeStubExecStatuses[$tablesCommand] = 0;

            $adapter->flushIpAnchor();

            sinkholeTestAssertSame(
                [$rulesCommand, $tablesCommand],
                $sinkholeStubCommands,
                'An empty anchor must be inspected without running a flush command.',
            );
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorFile), 'An empty anchor must remove stale anchor text.');
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorDigestFile), 'An empty anchor must remove its stale digest.');

            sinkholeStubReset([]);
            file_put_contents($paths->ipAnchorFile, 'loaded anchor');
            file_put_contents($paths->ipAnchorDigestFile, 'loaded digest');
            $sinkholeStubIpAnchorLoaded = true;

            $adapter->flushIpAnchor();

            sinkholeTestAssertSame(
                [$rulesCommand, $tablesCommand, $flushCommand],
                $sinkholeStubCommands,
                'A loaded anchor must be inspected and flushed.',
            );
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorFile), 'A successful flush must remove the anchor text.');
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorDigestFile), 'A successful flush must remove the anchor digest.');

            sinkholeStubReset([]);
            file_put_contents($paths->ipAnchorFile, 'loaded failed anchor');
            $sinkholeStubIpAnchorLoaded = true;
            $sinkholeStubCommandStatuses[$flushCommand] = 1;
            $flushThrew = false;

            try {
                $adapter->flushIpAnchor();
            } catch (RuntimeException $runtimeException) {
                $flushThrew = $runtimeException->getMessage()
                    === 'Unable to flush the Sinkhole IP anchor.';
            }

            sinkholeTestAssertSame(true, $flushThrew, 'A failed loaded-anchor flush must throw the existing error.');
            sinkholeTestAssertSame(
                [$rulesCommand, $tablesCommand, $flushCommand],
                $sinkholeStubCommands,
                'A failed loaded-anchor flush must retain the complete command sequence.',
            );
            sinkholeTestAssertSame(true, file_exists($paths->ipAnchorFile), 'A failed flush must retain the anchor text for retry.');

            sinkholeStubReset([]);
            $sinkholeStubExecStatuses[$rulesCommand] = 0;
            $sinkholeStubExecStatuses[$tablesCommand] = 1;
            $sinkholeStubCommandStatuses[$flushCommand] = 1;
            file_put_contents($paths->ipAnchorFile, 'stale mixed-status anchor');
            file_put_contents($paths->ipAnchorDigestFile, 'stale mixed-status digest');

            $adapter->flushIpAnchor();

            sinkholeTestAssertSame(
                [$rulesCommand, $tablesCommand],
                $sinkholeStubCommands,
                'The FreeBSD 16 mixed absent-anchor statuses must not run a flush command.',
            );
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorFile), 'The mixed absent state must remove stale anchor text.');
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorDigestFile), 'The mixed absent state must remove its stale digest.');

            sinkholeStubReset([]);
            file_put_contents($paths->ipAnchorFile, 'stale parent-missing anchor');
            $sinkholeStubExecOutputs[$rulesCommand] = ['pfctl: Anchor does not exist.'];
            $sinkholeStubExecOutputs[$tablesCommand] = ['pfctl: Anchor does not exist.'];
            $sinkholeStubExecStatuses[$rulesCommand] = 1;
            $sinkholeStubExecStatuses[$tablesCommand] = 1;
            $sinkholeStubExecStatuses[$parentAnchorsCommand] = 0;

            $adapter->flushIpAnchor();

            sinkholeTestAssertSame(
                [$rulesCommand, $tablesCommand, $parentAnchorsCommand],
                $sinkholeStubCommands,
                'A missing child in the parent anchor list must count as absent.',
            );

            sinkholeStubReset([]);
            file_put_contents($paths->ipAnchorFile, 'stale root-missing anchor');
            $sinkholeStubExecOutputs[$rulesCommand] = ['pfctl: Anchor does not exist.'];
            $sinkholeStubExecOutputs[$tablesCommand] = ['pfctl: Anchor does not exist.'];
            $sinkholeStubExecStatuses[$rulesCommand] = 1;
            $sinkholeStubExecStatuses[$tablesCommand] = 1;
            $sinkholeStubExecStatuses[$parentAnchorsCommand] = 1;
            $sinkholeStubExecStatuses[$rootAnchorsCommand] = 0;

            $adapter->flushIpAnchor();

            sinkholeTestAssertSame(
                [
                    $rulesCommand,
                    $tablesCommand,
                    $parentAnchorsCommand,
                    $rootAnchorsCommand,
                ],
                $sinkholeStubCommands,
                'A missing child in the root anchor list must count as absent.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'adapter discovers every protected address and loads flushes and replaces through stubs' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubDynamicNameserverArguments;
        global $sinkholeStubDynamicNameservers;
        global $sinkholeStubGatewayArguments;
        global $sinkholeStubGatewayRows;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeIpTestPaths($root);
            sinkholeStubReset([
                'installedpackages' => ['sinkhole' => ['ip' => [
                    'enabled' => 'on',
                    'interfaces' => ['item' => ['lan']],
                    'directions' => ['item' => ['inbound']],
                    'lists' => ['item' => []],
                    'countries' => ['item' => []],
                    'account_id' => '',
                    'license_key' => '',
                    'allowlist' => ['item' => []],
                ]]],
                'system' => [
                    'webgui' => ['protocol' => 'https', 'port' => '8443'],
                    'dnsserver' => ['9.9.9.9'],
                    'enablesshd' => true,
                    'ssh' => ['port' => '2222'],
                ],
                'gateways' => ['gateway_item' => [['gateway' => '192.0.2.1']]],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.2', 'ipv6' => '2001:db8::2']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $sinkholeStubDynamicNameservers = [
                '203.0.113.3',
                '',
                'dynamic',
            ];
            $sinkholeStubGatewayRows = [
                'WAN_DHCP' => ['gateway' => '203.0.113.2', 'dynamic' => true],
                'WAN_DHCP6' => ['gateway' => 'fe80::2%igc0', 'dynamic' => true],
                'FAILOVER_DISABLED' => ['gateway' => '198.51.100.9', 'disabled' => true],
                'FAILOVER_INACTIVE' => ['gateway' => '198.51.100.10', 'inactive' => true],
                'PLACEHOLDER' => ['gateway' => 'dynamic'],
                'EMPTY' => ['gateway' => ''],
            ];
            file_put_contents($paths->ipTableIpv4File, '');
            file_put_contents($paths->ipTableIpv6File, '');
            $adapter = new PfSenseAdapter($paths, new StateStore($paths->stateFile, $paths->statusFile));
            $rules = $adapter->ipAnchorText();

            sinkholeTestAssertSame(
                [
                    '192.0.2.2',
                    '2001:db8::2',
                    '9.9.9.9',
                    '203.0.113.3',
                    '192.0.2.1',
                    '203.0.113.2',
                    'fe80::2',
                    '198.51.100.9',
                    '198.51.100.10',
                ],
                $adapter->ipProtectedAddresses(),
                'Static and runtime interface, DNS, and gateway addresses must be protected.',
            );
            sinkholeTestAssertSame(
                [''],
                $sinkholeStubDynamicNameserverArguments,
                'Dynamic DNS discovery must request addresses from every interface.',
            );
            sinkholeTestAssertSame(
                [[
                    'disabled' => true,
                    'localhost' => false,
                    'inactive' => true,
                ]],
                $sinkholeStubGatewayArguments,
                'Runtime gateway discovery must include disabled and inactive gateways.',
            );
            sinkholeTestAssertSame(
                ['0.0.0.0/0', '::/0'],
                $adapter->ipAllowlistNetworks(['0.0.0.0/0', '::/0']),
                'The IP Allowlist must retain broad entries because they only reduce blocking.',
            );
            sinkholeTestAssertSame(false, str_contains($rules, 'pass '), 'Protected traffic must not create anchor passes.');
            sinkholeTestAssertSame('loaded', $adapter->applyIpAnchor(), 'Enabled IP blocking must load the anchor.');
            sinkholeTestAssertSame([
                "/sbin/pfctl -a 'sinkhole/ip' -f '" . $paths->ipAnchorFile . "'",
            ], $sinkholeStubCommands, 'The complete anchor must load from its fixed file.');

            $sinkholeStubCommands = [];
            sinkholeTestAssertSame(true, $adapter->replaceIpTable(IpRuleConfiguration::TABLE_IPV4, $paths->ipTableIpv4File), 'An existing table must be replaced.');
            sinkholeTestAssertSame([
                "/sbin/pfctl -a 'sinkhole/ip' -t 'sinkhole_block_v4' -T replace -f '"
                    . $paths->ipTableIpv4File . "'",
            ], $sinkholeStubCommands, 'pfctl must atomically replace from the fixed file.');

            $sinkholeStubCommands = [];
            sinkholeTestAssertSame(true, $adapter->replaceIpTable(IpRuleConfiguration::TABLE_IPV6, $paths->ipTableIpv6File), 'A missing table must be created by replacement.');
            sinkholeTestAssertSame([
                "/sbin/pfctl -a 'sinkhole/ip' -t 'sinkhole_block_v6' -T replace -f '"
                    . $paths->ipTableIpv6File . "'",
            ], $sinkholeStubCommands, 'A missing table must receive the creating replacement directly.');

            $sinkholeStubCommands = [];
            $adapter->flushIpAnchor();
            sinkholeTestAssertSame([
                "/sbin/pfctl -a 'sinkhole/ip' -sr 2>/dev/null",
                "/sbin/pfctl -a 'sinkhole/ip' -sT 2>/dev/null",
                "/sbin/pfctl -a 'sinkhole/ip' -F all",
            ], $sinkholeStubCommands, 'Turning IP blocking off or removing it must flush the whole anchor.');
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorFile), 'A flush must remove the stored anchor text.');
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorDigestFile), 'A flush must remove the loaded digest.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'missing runtime address helpers fail open and log once' => static function (): void {
        $process = proc_open(
            [PHP_BINARY, __FILE__, '--missing-protected-address-helpers'],
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
        );

        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start the missing-helper fixture.');
        }

        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $status = proc_close($process);

        sinkholeTestAssertSame(
            0,
            $status,
            'The missing-helper fixture must finish without stopping an update boundary. '
                . $output
                . $error,
        );
    },
    'package hook returns exact early anchor filter and NAT text' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeIpTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => ['ip' => [
                'enabled' => 'on',
                'interfaces' => ['item' => ['lan']],
                'directions' => ['item' => ['inbound']],
                'lists' => ['item' => []],
                'countries' => ['item' => []],
                'account_id' => '',
                'license_key' => '',
                'allowlist' => ['item' => []],
            ]]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '10.0.0.1']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $adapter = new PfSenseAdapter($paths, new StateStore($paths->stateFile, $paths->statusFile));
            pfsensePackageSinkholeAdapter($adapter);
            file_put_contents($paths->redirectRuleErrorFile, "leftover\n");

            sinkholeTestAssertSame(
                "anchor \"sinkhole/ip\"\n",
                pfsensePackageSinkholeFilterRules('pfearly'),
                'The pfearly call must return only the exact IP anchor reference.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->redirectRuleErrorFile),
                'The active pfearly call must clear a leftover package-rule error.',
            );
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('filter'),
                'The filter call must return no package text.',
            );
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('nat'),
                'The NAT call must remain empty when DNS redirect is disabled.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'package Sync loads the wanted IP anchor' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeIpTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => ['ip' => [
                'enabled' => 'on',
                'interfaces' => ['item' => ['lan']],
                'directions' => ['item' => ['outbound']],
                'lists' => ['item' => []],
                'countries' => ['item' => []],
                'account_id' => '',
                'license_key' => '',
                'allowlist' => ['item' => []],
            ]]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $adapter = new PfSenseAdapter($paths, new StateStore($paths->stateFile, $paths->statusFile));
            pfsensePackageSinkholeAdapter($adapter);

            pfsensePackageSinkholeSync(0);

            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/ip' -f '" . $paths->ipAnchorFile . "'",
                implode("\n", $sinkholeStubCommands),
                'Sync must load the current anchor text directly.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'sinkhole update completes on a fresh firewall with IP blocking off' => static function (): void {
        global $sinkholeStubCommands;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeIpTestPaths($root);

            sinkholeStubReset([]);

            $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);
            $savedListStore = new SavedListStore($paths);
            $downloadClient = new SinkholeIpTestDownloadClient();
            $ipUpdater = new IpUpdater(
                $adapter,
                $downloadClient,
                new IpParser(),
                new IpListStore($paths),
                $paths,
                new GeoLite2(),
                new IpStatusStore($paths->ipStatusFile),
            );
            $updater = new Updater(
                $adapter,
                $downloadClient,
                new DomainParser(),
                $savedListStore,
                new Compiler($paths, $savedListStore, $stateStore),
                $stateStore,
                null,
                $ipUpdater,
            );

            $result = $updater->run();

            sinkholeTestAssertSame('disabled', $result['status'], 'A fresh disabled update must complete normally.');
            sinkholeTestAssertSame(0, $result['failed'], 'A missing fresh anchor must not become an update failure.');
            sinkholeTestAssertSame([
                "/sbin/pfctl -a 'sinkhole/ip' -sr 2>/dev/null",
                "/sbin/pfctl -a 'sinkhole/ip' -sT 2>/dev/null",
            ], $sinkholeStubCommands, 'A fresh update must inspect the absent anchor without flushing it.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'IP updater keeps last-good lists and replaces both live tables through stubs' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();
        $identifier = str_repeat('c', 32);

        try {
            $paths = sinkholeIpTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => ['ip' => [
                'enabled' => 'on',
                'interfaces' => ['item' => ['lan']],
                'directions' => ['item' => ['inbound']],
                'lists' => ['item' => [[
                    'id' => $identifier,
                    'descr' => 'Invented last-good feed',
                    'url' => 'https://example.test/last-good.txt',
                    'family' => 'ipv4',
                    'enabled' => 'on',
                ]]],
                'countries' => ['item' => []],
                'account_id' => '',
                'license_key' => '',
                'allowlist' => ['item' => []],
            ]]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.2']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            mkdir($paths->ipListDirectory, 0700, true);
            file_put_contents($paths->ipListFile($identifier), "192.0.2.0/24\n");
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $result = (new IpUpdater(
                $adapter,
                new SinkholeIpTestDownloadClient('invented transport failure'),
                new IpParser(),
                new IpListStore($paths),
                $paths,
                new GeoLite2(),
                new IpStatusStore($paths->ipStatusFile),
            ))->run();

            sinkholeTestAssertSame('warning', $result['status'], 'A failed refresh with saved data must warn.');
            sinkholeTestAssertSame("192.0.2.0/24\n", file_get_contents($paths->ipListFile($identifier)), 'The failed refresh must retain the last-good copy.');
            sinkholeTestAssertSame(
                "192.0.2.0/31\n"
                    . "192.0.2.3/32\n"
                    . "192.0.2.4/30\n"
                    . "192.0.2.8/29\n"
                    . "192.0.2.16/28\n"
                    . "192.0.2.32/27\n"
                    . "192.0.2.64/26\n"
                    . "192.0.2.128/25\n",
                file_get_contents($paths->ipTableIpv4File),
                'The retained IPv4 copy must populate the atomic table file.',
            );
            sinkholeTestAssertSame('', file_get_contents($paths->ipTableIpv6File), 'The other family must still receive an empty atomic table file.');
            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/ip' -f '" . $paths->ipAnchorFile . "'",
                implode("\n", $sinkholeStubCommands),
                'The update job must load the complete anchor from its fixed file.',
            );
            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/ip' -t 'sinkhole_block_v4' -T replace -f '"
                    . $paths->ipTableIpv4File . "'",
                implode("\n", $sinkholeStubCommands),
                'The updater must replace the existing IPv4 table through the stub.',
            );
            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/ip' -t 'sinkhole_block_v6' -T replace -f '"
                    . $paths->ipTableIpv6File . "'",
                implode("\n", $sinkholeStubCommands),
                'The updater must replace the existing IPv6 table through the stub.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'IP updater saves normalized copies counts skipped rows and merges table families' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();
        $firstIdentifier = str_repeat('d', 32);
        $secondIdentifier = str_repeat('e', 32);
        $firstUrl = 'https://example.test/invented-v4.txt';
        $secondUrl = 'https://example.test/invented-both.txt';

        try {
            $paths = sinkholeIpTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => ['ip' => [
                'enabled' => 'on',
                'interfaces' => ['item' => ['lan']],
                'directions' => ['item' => ['inbound', 'outbound']],
                'lists' => ['item' => [[
                    'id' => $firstIdentifier,
                    'descr' => 'Invented IPv4 fixture',
                    'url' => $firstUrl,
                    'family' => 'ipv4',
                    'enabled' => 'on',
                ], [
                    'id' => $secondIdentifier,
                    'descr' => 'Invented dual-family fixture',
                    'url' => $secondUrl,
                    'family' => 'both',
                    'enabled' => 'on',
                ]]],
                'countries' => ['item' => []],
                'account_id' => '',
                'license_key' => '',
                'allowlist' => ['item' => []],
            ]]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => [
                'ipv4' => '10.0.0.1',
                'ipv6' => '2001:db8:ffff::1',
            ]];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $result = (new IpUpdater(
                $adapter,
                new SinkholeIpFixtureDownloadClient([
                    $firstUrl => "192.0.2.1\nnot-an-address\n",
                    $secondUrl => "192.0.2.0/25\n192.0.2.128/25\n2001:db8::1/64\nskip-me\n",
                ]),
                new IpParser(),
                new IpListStore($paths),
                $paths,
                new GeoLite2(),
                new IpStatusStore($paths->ipStatusFile),
            ))->run();

            sinkholeTestAssertSame('completed', $result['status'], 'Both invented feeds must update successfully.');
            sinkholeTestAssertSame(2, $result['skipped'], 'Skipped rows must aggregate across feeds.');
            sinkholeTestAssertSame("192.0.2.1/32\n", file_get_contents($paths->ipListFile($firstIdentifier)), 'The first saved copy must be canonical.');
            sinkholeTestAssertSame("192.0.2.0/25\n192.0.2.128/25\n2001:db8::/64\n", file_get_contents($paths->ipListFile($secondIdentifier)), 'The second saved copy must retain canonical per-feed rows.');
            sinkholeTestAssertSame("192.0.2.0/24\n", file_get_contents($paths->ipTableIpv4File), 'Sibling and contained IPv4 rows must merge in the table file.');
            sinkholeTestAssertSame("2001:db8::/64\n", file_get_contents($paths->ipTableIpv6File), 'IPv6 rows must reach only the IPv6 table file.');
            sinkholeTestAssertSame(1, (new IpListStore($paths))->metadata($firstIdentifier)['skipped'], 'Per-list metadata must retain its skipped-row count.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'IP updater subtracts selected subnets and static or DHCP gateway and DNS hosts' => static function (): void {
        global $sinkholeStubDynamicNameservers;
        global $sinkholeStubGatewayRows;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();
        $identifier = str_repeat('f', 32);
        $url = 'https://example.test/protected-hosts.txt';

        try {
            $paths = sinkholeIpTestPaths($root);
            sinkholeStubReset([
                'installedpackages' => ['sinkhole' => ['ip' => [
                    'enabled' => 'on',
                    'interfaces' => ['item' => ['lan']],
                    'directions' => ['item' => ['inbound']],
                    'lists' => ['item' => [[
                        'id' => $identifier,
                        'descr' => 'Invented protected-host fixture',
                        'url' => $url,
                        'family' => 'both',
                        'enabled' => 'on',
                    ]]],
                    'countries' => ['item' => []],
                    'account_id' => '',
                    'license_key' => '',
                    'allowlist' => ['item' => []],
                ]]],
                'system' => ['dnsserver' => ['198.51.100.2', '2001:db8:2::2']],
                'gateways' => ['gateway_item' => [
                    ['gateway' => '198.51.100.3'],
                    ['gateway' => '2001:db8:2::3'],
                ]],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => [
                'ipv4' => '192.0.2.1',
                'ipv4_prefix' => 24,
                'ipv6' => '2001:db8:1::1',
                'ipv6_prefix' => 64,
            ]];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $sinkholeStubDynamicNameservers = [
                '203.0.113.3',
                '',
                'dynamic',
            ];
            $sinkholeStubGatewayRows = [
                'WAN_DHCP' => ['gateway' => '203.0.113.2', 'dynamic' => true],
                'WAN_DHCP6' => ['gateway' => 'fe80::2%igc0', 'dynamic' => true],
                'FAILOVER_DISABLED' => ['gateway' => '203.0.113.4', 'disabled' => true],
                'FAILOVER_INACTIVE' => ['gateway' => '203.0.113.5', 'inactive' => true],
                'PLACEHOLDER' => ['gateway' => 'dynamic'],
                'EMPTY' => ['gateway' => ''],
            ];
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $result = (new IpUpdater(
                $adapter,
                new SinkholeIpFixtureDownloadClient([
                    $url => "192.0.2.0/24\n198.51.100.0/30\n"
                        . "203.0.113.0/29\n2001:db8:1::/64\n"
                        . "2001:db8:2::/126\nfe80::/126\n",
                ]),
                new IpParser(),
                new IpListStore($paths),
                $paths,
                new GeoLite2(),
                new IpStatusStore($paths->ipStatusFile),
            ))->run();

            sinkholeTestAssertSame('completed', $result['status'], 'The invented protected-host feed must update.');
            sinkholeTestAssertSame(
                "198.51.100.0/31\n"
                    . "203.0.113.0/31\n"
                    . "203.0.113.6/31\n",
                file_get_contents($paths->ipTableIpv4File),
                'Static and DHCP IPv4 DNS and gateway hosts must be removed.',
            );
            sinkholeTestAssertSame(
                "2001:db8:2::/127\n"
                    . "fe80::/127\n"
                    . "fe80::3/128\n",
                file_get_contents($paths->ipTableIpv6File),
                'Static and scoped DHCP IPv6 gateways must be removed.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'minute reconciliation reloads empty or different anchors and leaves a match alone' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubCommandStatuses;
        global $sinkholeStubFilterConfigureCount;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeIpTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => ['ip' => [
                'enabled' => 'on',
                'interfaces' => ['item' => ['lan']],
                'directions' => ['item' => ['outbound']],
                'lists' => ['item' => []],
                'countries' => ['item' => []],
                'account_id' => '',
                'license_key' => '',
                'allowlist' => ['item' => []],
            ]]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.2']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            file_put_contents($paths->ipTableIpv4File, "198.51.100.1/32\n203.0.113.1/32\n");
            file_put_contents($paths->ipTableIpv6File, "2001:db8::1/128\n");
            $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);
            $statusCommand = "/sbin/pfctl -a 'sinkhole/ip' -sr 2>/dev/null | /usr/bin/grep -q '.'";
            $loadCommand = "/sbin/pfctl -a 'sinkhole/ip' -f '" . $paths->ipAnchorFile . "'";
            $adapter->applyIpAnchor();
            $sinkholeStubCommands = [];
            $sinkholeStubCommandStatuses[$statusCommand] = 1;

            sinkholeTestAssertSame('reloaded', $adapter->reconcileIpAnchor(), 'An empty live anchor must reload immediately.');
            sinkholeTestAssertSame([
                $statusCommand,
                $loadCommand,
            ], $sinkholeStubCommands, 'An empty anchor check must run only the status and reload commands.');

            $sinkholeStubCommands = [];
            $sinkholeStubCommandStatuses[$statusCommand] = 0;
            sinkholeTestAssertSame('matching', $adapter->reconcileIpAnchor(), 'A matching loaded digest and nonempty anchor need no mutation.');
            sinkholeTestAssertSame([
                $statusCommand,
            ], $sinkholeStubCommands, 'A matching minute check must not load, flush, or replace anything.');

            config_set_path(
                'installedpackages/sinkhole/ip/directions/item',
                ['inbound'],
            );
            $sinkholeStubCommands = [];
            sinkholeTestAssertSame('reloaded', $adapter->reconcileIpAnchor(), 'Changed wanted anchor text must reload immediately.');
            sinkholeTestAssertSame([
                $statusCommand,
                $loadCommand,
            ], $sinkholeStubCommands, 'A digest mismatch must run only the status and reload commands.');

            $sinkholeStubCommands = [];
            $anchorStatus = $adapter->ipAnchorStatus();
            sinkholeTestAssertSame(true, $anchorStatus['loaded'], 'Status must report the current anchor as loaded.');
            sinkholeTestAssertSame(1, $anchorStatus['rule_count'], 'Status must report the loaded block-rule count.');
            sinkholeTestAssertSame(2, $anchorStatus['ipv4_entries'], 'Status must report the IPv4 table-file size.');
            sinkholeTestAssertSame(1, $anchorStatus['ipv6_entries'], 'Status must report the IPv6 table-file size.');

            config_set_path('installedpackages/sinkhole/ip/enabled', '');
            unlink($paths->ipAnchorFile);
            unlink($paths->ipAnchorDigestFile);
            $sinkholeStubCommands = [];
            sinkholeTestAssertSame(
                'reloaded',
                $adapter->reconcileIpAnchor(),
                'A live orphaned anchor must be flushed when IP blocking is off.',
            );
            sinkholeTestAssertSame([
                $statusCommand,
                "/sbin/pfctl -a 'sinkhole/ip' -sr 2>/dev/null",
                "/sbin/pfctl -a 'sinkhole/ip' -sT 2>/dev/null",
                "/sbin/pfctl -a 'sinkhole/ip' -F all",
            ], $sinkholeStubCommands, 'The disabled minute check must detect and flush a live anchor.');

            $sinkholeStubCommands = [];
            pfsensePackageSinkholeAdapter($adapter);
            pfsensePackageSinkholeMarkRemoving();
            sinkholeTestAssertSame('', $adapter->ipRuleText(), 'Removal intent must suppress the early anchor reference.');
            sinkholeTestAssertSame([
                "/sbin/pfctl -a 'sinkhole/ip' -sr 2>/dev/null",
                "/sbin/pfctl -a 'sinkhole/ip' -sT 2>/dev/null",
                "/sbin/pfctl -a 'sinkhole/bypass' -sr 2>/dev/null",
                "/sbin/pfctl -a 'sinkhole/bypass' -sT 2>/dev/null",
            ], $sinkholeStubCommands, 'Removal intent must not flush an anchor that is already absent.');
            sinkholeTestAssertSame(1, $sinkholeStubFilterConfigureCount, 'Removal intent must reload the filter once to remove the anchor reference.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'license key is absent from repair values logs status page output and cache metadata' => static function (): void {
        global $sinkholeStubLogs;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();
        $secret = 'INVENTED-LICENSE-SECRET';

        try {
            $paths = sinkholeIpTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => ['ip' => [
                'enabled' => 'on',
                'interfaces' => ['item' => ['lan']],
                'directions' => ['item' => ['inbound']],
                'lists' => ['item' => [[
                    'id' => str_repeat('a', 32),
                    'descr' => 'Invented feed',
                    'url' => 'https://example.test/ip.txt',
                    'family' => 'ipv4',
                    'enabled' => 'on',
                ]]],
                'countries' => ['item' => []],
                'account_id' => '12345',
                'license_key' => $secret,
                'allowlist' => ['item' => []],
            ]]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.2']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $adapter = new PfSenseAdapter($paths, new StateStore($paths->stateFile, $paths->statusFile));
            $client = new SinkholeIpTestDownloadClient('invented failure ' . $secret);
            $updater = new IpUpdater(
                $adapter,
                $client,
                new IpParser(),
                new IpListStore($paths),
                $paths,
                new GeoLite2(),
                new IpStatusStore($paths->ipStatusFile),
            );
            $updater->run();
            $status = file_get_contents($paths->ipStatusFile);
            $metadata = file_get_contents($paths->ipMetadataFile(str_repeat('a', 32)));
            $page = file_get_contents(__DIR__ . '/../port/files/usr/local/www/sinkhole-ip.php');

            sinkholeTestAssertTrue(!str_contains(implode("\n", $sinkholeStubLogs), $secret), 'Logs must redact the license key.');
            sinkholeTestAssertTrue(is_string($status) && !str_contains($status, $secret), 'Status must redact the license key.');
            sinkholeTestAssertTrue(is_string($metadata) && !str_contains($metadata, $secret), 'Saved IP-list metadata must redact the license key.');
            sinkholeTestAssertTrue(is_string($page) && str_contains($page, "'password',\n    '',"), 'The saved key must never become the password input value.');
            sinkholeTestAssertTrue(!file_exists($paths->geoLite2MetadataFile), 'No credential may be cached when countries are not configured.');

            $invalid = IpConfiguration::partition(['license_key' => "bad\n"], [], []);
            sinkholeTestAssertSame('', $invalid['invalid_values'][0]['value'], 'A malformed saved key must be redacted from repair output.');
            sinkholeTestAssertSame("bad\n", $invalid['license_key'], 'A malformed saved key must survive unrelated repair actions without being displayed.');
            sinkholeTestAssertSame(true, $invalid['license_key_set'], 'A malformed non-empty saved key must be reported only as set.');
            $invalidAccount = IpConfiguration::partition(['account_id' => 'not-digits'], [], []);
            sinkholeTestAssertSame('not-digits', $invalidAccount['account_id'], 'A malformed account ID must remain available for repair.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'removal flushes the anchor and clears IP runtime files while preserving saved copies' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubIpAnchorLoaded;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeIpTestPaths($root);
            sinkholeStubReset([]);
            mkdir($paths->ipListDirectory, 0700, true);
            file_put_contents($paths->ipListFile(str_repeat('b', 32)), "192.0.2.0/24\n");

            foreach ([
                $paths->ipTableIpv4File,
                $paths->ipTableIpv6File,
                $paths->ipAnchorFile,
                $paths->ipAnchorDigestFile,
                $paths->geoLite2ArchiveFile,
                $paths->geoLite2MetadataFile,
                $paths->ipStatusFile,
            ] as $path) {
                file_put_contents($path, 'invented');
            }

            $adapter = new PfSenseAdapter($paths, new StateStore($paths->stateFile, $paths->statusFile));
            $sinkholeStubIpAnchorLoaded = true;
            $adapter->clearIpRuntimeData();

            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/ip' -F all",
                implode("\n", $sinkholeStubCommands),
                'Removal must flush the complete IP anchor.',
            );
            sinkholeTestAssertSame(true, file_exists($paths->ipListFile(str_repeat('b', 32))), 'Keep Settings must retain saved IP list copies.');
            sinkholeTestAssertSame(false, file_exists($paths->ipTableIpv4File), 'Runtime table files must be removed.');
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorFile), 'Removal must delete the anchor file.');
            sinkholeTestAssertSame(false, file_exists($paths->ipAnchorDigestFile), 'Removal must delete the anchor digest.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'milestone six UI and catalog keys are packaged' => static function (): void {
        $workspace = dirname(__DIR__);
        $catalogs = require($workspace . '/port/files/usr/local/pkg/sinkhole/Translations.php');
        $english = $catalogs['en_US'];

        foreach ([
            'ip_country_blocking',
            'maxmind_license_key_status',
            'skipped_lines',
            'geolite2_last_update',
            'revision_saved_ip_blocking',
            'ip_anchor',
            'anchor_rule_count',
        ] as $key) {
            sinkholeTestAssertTrue(isset($english[$key]), 'The milestone catalog key must exist: ' . $key);
        }

        sinkholeTestAssertContains('www/sinkhole-ip.php', (string) file_get_contents($workspace . '/port/pkg-plist'), 'The IP page must be installed.');
        sinkholeTestAssertContains('page-firewall-sinkhole-ip', (string) file_get_contents($workspace . '/port/files/usr/local/pkg/priv/sinkhole.priv.inc'), 'The IP page must have a privilege.');
    },
]);
