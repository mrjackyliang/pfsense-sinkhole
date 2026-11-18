<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\BypassConfiguration;
use PfSense\Sinkhole\Domain\BypassParser;
use PfSense\Sinkhole\Domain\BypassRuleConfiguration;
use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\IpParser;
use PfSense\Sinkhole\Domain\UnboundCustomOptions;
use PfSense\Sinkhole\Domain\ValidationException;
use PfSense\Sinkhole\Runtime\BypassListStore;
use PfSense\Sinkhole\Runtime\BypassUpdater;
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
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/BypassParser.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/BypassUpdater.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/DomainParser.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/GeoLite2.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpListStore.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpParser.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpStatusStore.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/IpUpdater.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Updater.php');

$sinkholeBypassTestCertificateLookupFailure = false;

if (!function_exists('lookup_cert')) {
    /**
     * Sinkhole Bypass Test - Look Up Certificate.
     *
     * Mirrors pfSense's wrapped certificate return shape.
     *
     * @param string $reference - Certificate reference.
     *
     * @return array{idx: int|null, item: array|null}
     *
     * @since 1.0.0
     */
    function lookup_cert(string $reference): array
    {
        global $sinkholeBypassTestCertificateLookupFailure;

        if ($sinkholeBypassTestCertificateLookupFailure) {
            throw new RuntimeException('Invented Bypass certificate lookup failure.');
        }

        $certificates = config_get_path('cert', []);

        foreach (is_array($certificates) ? $certificates : [] as $index => $certificate) {
            if (is_array($certificate) && ($certificate['refid'] ?? null) === $reference) {
                return ['idx' => $index, 'item' => $certificate];
            }
        }

        return ['idx' => null, 'item' => null];
    }
}

/**
 * Sinkhole Bypass Test - DNS Resolver Certificate.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeBypassTestCertificate(): string
{
    return <<<'CERTIFICATE'
-----BEGIN CERTIFICATE-----
MIIDIjCCAgqgAwIBAgIUXChg2yf55fqc43hQd/5L6IwBSMcwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVcmVzb2x2ZXIuZXhhbXBsZS50ZXN0MB4XDTI2MTEwOTAw
MjgxM1oXDTM2MTEwNjAwMjgxM1owIDEeMBwGA1UEAwwVcmVzb2x2ZXIuZXhhbXBs
ZS50ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtWLrXJCx8m5X
bmHwroiy9rbouMRR5b235SFnrdgN1StuDvDV22FzA+ju7PQTFJjdqHAdtU2lX2db
t3URNs8XV/dj2ly5Poehe9V+8tXUOzGfK+4vXI8OZAnT+JmtElfVtvBdo7KvdWPk
KnH31gc5IY+L9u7tDC2IAyMAHn1qHyMUlLMT1lqXeF4HTH4gsUBsoOBgwTHLsyww
zzj5A1FF4kRT4UWKSbz3etzetvkfr7YpfBmife9AbacSv/GAuY7/HPbotbWQHz4f
RqiO+r6KsZg3nbVZozkEfz0F+nf0sMiXXm6UfBESRAtyIUl/XSoBTfJXSQjkJqFy
TBayLl6rIQIDAQABo1QwUjAdBgNVHQ4EFgQU2wvcwlxrEP3VmiTr1pA+KC47/0sw
DwYDVR0TAQH/BAUwAwEB/zAgBgNVHREEGTAXghVyZXNvbHZlci5leGFtcGxlLnRl
c3QwDQYJKoZIhvcNAQELBQADggEBAAI5PRUtcyIAyUVBfn+EcKQxJUA+l2orz1U0
4d07wnlr64wuJJ9l+G05XYmjrxgaSQPgdvjG3ptPqdiU1L9TzJPqrQk7ojkArxh+
KOajtHUMyTkTVhZU+2fmEvWBImDYXXv/X9wRzQ3lOR/qPtfozpOIepHRuxyu+Fb3
iRdjWOnADqYtT9s1DdWs8L8efxnHHaZ6TjvXcb6+t7OZlDks/LBE7gYRfa/wSM+J
JO6JvHsDIT+XhzX6dN8C4z4SHAzDPy+VnB6D5gPjMfGiuPPk10GjJwHl38gv7RoC
EnQWnJBHixuMAekomqeeMR38OLKqhSAflmiEs5LWmpviW2W06DU=
-----END CERTIFICATE-----
CERTIFICATE;
}

/** @since 1.0.0 */
final class SinkholeBypassFixtureDownloadClient implements DownloadClient
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
            return [
                'success' => false,
                'bytes' => 0,
                'error' => 'Invented Bypass List transport failure.',
            ];
        }

        $bytes = file_put_contents($destinationPath, $contents);

        return is_int($bytes)
            ? ['success' => true, 'bytes' => $bytes, 'error' => null]
            : ['success' => false, 'bytes' => 0, 'error' => 'Invented fixture write failed.'];
    }
}

/** @since 1.0.0 */
function sinkholeBypassTestPaths(string $root): PackagePaths
{
    file_put_contents($root . '/sinkhole_unbound.py', "# invented module fixture\n");

    return new PackagePaths([
        'persistent_directory' => $root . '/persistent',
        'runtime_root_directory' => $root . '/runtime',
        'module_source_file' => $root . '/sinkhole_unbound.py',
        'update_lock_file' => $root . '/update.lock',
        'runtime_lock_file' => $root . '/runtime.lock',
        'client_lock_file' => $root . '/client.lock',
        'alert_lock_file' => $root . '/alert.lock',
        'redirect_check_lock_file' => $root . '/redirect-check.lock',
        'redirect_check_state_file' => $root . '/redirect-check.json',
        'redirect_rule_error_file' => $root . '/rules.packages.sinkhole',
        'bypass_table_ipv4_file' => $root . '/sinkhole-bypass-v4.txt',
        'bypass_table_ipv6_file' => $root . '/sinkhole-bypass-v6.txt',
        'bypass_anchor_file' => $root . '/sinkhole-bypass-anchor.conf',
        'bypass_anchor_digest_file' => $root . '/sinkhole-bypass-anchor.sha256',
        'ip_table_ipv4_file' => $root . '/sinkhole-ip-v4.txt',
        'ip_table_ipv6_file' => $root . '/sinkhole-ip-v6.txt',
        'ip_anchor_file' => $root . '/sinkhole-ip-anchor.conf',
        'ip_anchor_digest_file' => $root . '/sinkhole-ip-anchor.sha256',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/** @since 1.0.0 */
function sinkholeBypassTestStorage(
    array $lists = [],
    array $overrides = [],
): array {
    $storage = [
        'block_tls_quic' => '',
        'block_encrypted_dns' => '',
        'disable_firefox_doh' => '',
        'disable_private_relay' => '',
        'discovery' => BypassConfiguration::DISCOVERY_OFF,
        'block_tor' => '',
        'block_vpn' => '',
        'block_vpn_ports' => '',
        'lists' => ['item' => $lists],
    ];

    return array_replace($storage, $overrides);
}

/**
 * Sinkhole Bypass Test - Save DNS List.
 *
 * @param SavedListStore $store - Saved-list store.
 * @param string $identifier - Stable fixture identifier.
 * @param string $url - Configured fixture URL.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeBypassTestSaveDnsList(
    SavedListStore $store,
    string $identifier,
    string $url,
): void {
    $contents = "S\tordinary.example.test\n";
    $temporaryPath = $store->createTemporaryFile('.dns-fixture-');
    file_put_contents($temporaryPath, $contents);
    $store->commitSuccessfulDownload($identifier, $temporaryPath, [
        'url' => $url,
        'fetched_at' => '2026-01-01T00:00:00+00:00',
        'entries' => 1,
        'sha256' => hash('sha256', $contents),
        'last_attempt' => '2026-01-01T00:00:00+00:00',
        'last_error' => null,
    ]);
}

sinkholeTestRun([
    'Bypass protection is off by default for fresh and upgraded configurations' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $fresh = BypassConfiguration::partition([], []);
            $upgraded = BypassConfiguration::partition([], ['lan']);

            foreach ([$fresh, $upgraded] as $configuration) {
                sinkholeTestAssertSame(false, $configuration['enabled'], 'No protection may enable implicitly.');
                sinkholeTestAssertSame(false, $configuration['dns_enabled'], 'No DNS answer may enable implicitly.');
                sinkholeTestAssertSame(false, $configuration['firewall_enabled'], 'No firewall rule may enable implicitly.');
                sinkholeTestAssertSame('off', $configuration['discovery'], 'DDR must default to Off.');
                sinkholeTestAssertSame([], $configuration['lists'], 'No Bypass List may be invented.');
            }

            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => [
                'redirect' => ['interfaces' => ['item' => ['lan']]],
            ]]]);
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            sinkholeTestAssertSame('', $adapter->bypassRuleText(), 'An upgrade must add no early anchor reference.');
            sinkholeTestAssertSame('', $adapter->bypassAnchorText(), 'An upgrade must add no Bypass rules.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Discovery custom options preserve admin bytes and repair managed blocks' => static function (): void {
        $block = '# Sinkhole: begin (managed by the Sinkhole package)' . "\n"
            . 'server:' . "\n"
            . 'local-zone: "_dns.resolver.arpa." transparent' . "\n"
            . '# Sinkhole: end';
        sinkholeTestAssertSame(
            $block,
            UnboundCustomOptions::reconcileDiscoveryZone('', true),
            'An empty custom-options value must receive only the managed block.',
        );
        $withoutTrailingLineEnding = 'server:' . "\n" . 'verbosity: 1';
        $added = UnboundCustomOptions::reconcileDiscoveryZone(
            $withoutTrailingLineEnding,
            true,
        );
        sinkholeTestAssertSame(
            $withoutTrailingLineEnding . "\n" . $block,
            $added,
            'The block must follow existing text that has no trailing line ending.',
        );
        sinkholeTestAssertSame(
            $added,
            UnboundCustomOptions::reconcileDiscoveryZone($added, true),
            'Adding an already-present block must be idempotent.',
        );
        sinkholeTestAssertSame(
            $withoutTrailingLineEnding,
            UnboundCustomOptions::reconcileDiscoveryZone($added, false),
            'Removing the block must restore every administrator-owned byte.',
        );
        sinkholeTestAssertSame(
            $withoutTrailingLineEnding,
            UnboundCustomOptions::reconcileDiscoveryZone(
                $withoutTrailingLineEnding,
                false,
            ),
            'Removing an absent block must leave custom options unchanged.',
        );
        sinkholeTestAssertSame(
            $added,
            UnboundCustomOptions::reconcileDiscoveryZone(
                $withoutTrailingLineEnding . "\n" . $block . "\n" . $block,
                true,
            ),
            'Duplicate managed blocks must collapse to one canonical block.',
        );
        $adminAfterHalfBlock = 'forward-zone:' . "\n" . 'name: "."';
        sinkholeTestAssertSame(
            $withoutTrailingLineEnding . "\n" . $adminAfterHalfBlock,
            UnboundCustomOptions::reconcileDiscoveryZone(
                $withoutTrailingLineEnding . "\n"
                    . UnboundCustomOptions::BEGIN_MARKER . "\n"
                    . UnboundCustomOptions::SERVER_LINE . "\n"
                    . UnboundCustomOptions::DISCOVERY_ZONE_LINE . "\n"
                    . $adminAfterHalfBlock,
                false,
            ),
            'A block without an end marker must remove only known Sinkhole lines.',
        );
        $crlfAdmin = "server:\r\nverbosity: 2\r\n";
        $crlfBlock = str_replace("\n", "\r\n", $block);
        $crlfAdded = UnboundCustomOptions::reconcileDiscoveryZone($crlfAdmin, true);
        sinkholeTestAssertSame(
            $crlfAdmin . "\r\n" . $crlfBlock,
            $crlfAdded,
            'CRLF custom options must keep CRLF in the managed block.',
        );
        sinkholeTestAssertSame(
            $crlfAdmin,
            UnboundCustomOptions::reconcileDiscoveryZone($crlfAdded, false),
            'Removing a CRLF block must restore the exact admin text.',
        );
        sinkholeTestAssertSame(
            true,
            UnboundCustomOptions::hasDiscoveryZone($crlfAdded),
            'Status detection must recognize the exact Discovery zone line.',
        );
    },
    'mixed Bypass Lists normalize domains addresses CIDRs junk and limits' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $input = $root . '/mixed.txt';
            $output = $root . '/normalized.txt';
            file_put_contents(
                $input,
                "# invented fixture\nalpha.example.test\n192.0.2.7\n"
                    . "198.51.100.0/24 # note\n2001:db8::1\n2001:db8:1::/48\n"
                    . "junk value\nbad@\n",
            );
            $parser = new BypassParser();
            $result = $parser->parseFile($input, $output);

            sinkholeTestAssertSame(5, $result['accepted'], 'Every valid mixed entry must be accepted.');
            sinkholeTestAssertSame(1, $result['domains'], 'The invented domain must be typed separately.');
            sinkholeTestAssertSame(4, $result['networks'], 'Addresses and CIDRs must be canonical networks.');
            sinkholeTestAssertSame(3, $result['skipped'], 'Comments and junk must be skipped safely.');
            sinkholeTestAssertSame(
                "D\tS\talpha.example.test\n"
                    . "I\t192.0.2.7/32\n"
                    . "I\t198.51.100.0/24\n"
                    . "I\t2001:db8::1/128\n"
                    . "I\t2001:db8:1::/48\n",
                file_get_contents($output),
                'The saved mixed copy must contain only canonical typed records.',
            );
            $limitThrew = false;

            try {
                $parser->parseFile($input, $root . '/limited.txt', 1);
            } catch (RuntimeException $exception) {
                $limitThrew = $exception->getMessage()
                    === 'The Bypass List entry limit was exceeded.';
            }

            sinkholeTestAssertSame(true, $limitThrew, 'The streaming entry limit must stop oversized input.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Bypass Lists reject broad and special-use networks' => static function (): void {
        $parser = new BypassParser();
        $rejected = [
            '1.0.0.0/7',
            '0.0.0.0/0',
            '0.0.0.0/8',
            '10.0.0.0/8',
            '100.64.0.0/10',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '192.0.0.0/8',
            '224.0.0.0/4',
            '240.0.0.0/4',
            '255.255.255.255',
            '2000::/15',
            '::/0',
            '::',
            '::1',
            '::ffff:0:0/96',
            'fc00::/7',
            'fe80::/10',
            'ff00::/8',
        ];

        foreach ($rejected as $network) {
            sinkholeTestAssertSame(
                null,
                $parser->parseLine($network),
                'The Bypass parser must reject ' . $network . '.',
            );
        }

        sinkholeTestAssertSame(
            ['I', '192.0.2.0/24'],
            $parser->parseLine('192.0.2.0/24'),
            'A normal invented public /24 must remain eligible.',
        );
        sinkholeTestAssertSame(
            ['I', '8.0.0.0/8'],
            $parser->parseLine('8.0.0.0/8'),
            'The shared IPv4 /8 safety boundary must remain eligible.',
        );
        sinkholeTestAssertSame(
            ['I', '2001::/16'],
            $parser->parseLine('2001::/16'),
            'The shared IPv6 /16 safety boundary must remain eligible.',
        );
    },
    'Bypass firewall text is exact for both families and every protection' => static function (): void {
        $configuration = [
            'block_tls_quic' => true,
            'block_encrypted_dns' => true,
            'block_tor' => true,
            'block_vpn' => true,
            'block_vpn_ports' => true,
        ];
        $rules = BypassRuleConfiguration::anchorText(
            [[
                'interface' => 'lan',
                'real_interface' => 'igc0',
                'ipv4' => true,
                'ipv6' => true,
            ]],
            $configuration,
            '/var/db/sinkhole-bypass-v4.txt',
            '/var/db/sinkhole-bypass-v6.txt',
        );
        $expected = <<<'RULES'
# Sinkhole bypass protection
table <sinkhole_bypass_v4> persist file "/var/db/sinkhole-bypass-v4.txt"
table <sinkhole_bypass_v6> persist file "/var/db/sinkhole-bypass-v6.txt"
block return in quick on igc0 inet proto { tcp udp } from any to ! (self) port 853
block return in quick on igc0 inet from any to <sinkhole_bypass_v4>
block return in quick on igc0 inet proto { tcp udp } from any to ! (self) port 1194
block return in quick on igc0 inet proto udp from any to ! (self) port { 500 4500 51820 }
block return in quick on igc0 inet proto esp from any to ! (self)
block return in quick on igc0 inet6 proto { tcp udp } from any to ! (self) port 853
block return in quick on igc0 inet6 from any to <sinkhole_bypass_v6>
block return in quick on igc0 inet6 proto { tcp udp } from any to ! (self) port 1194
block return in quick on igc0 inet6 proto udp from any to ! (self) port { 500 4500 51820 }
block return in quick on igc0 inet6 proto esp from any to ! (self)
RULES;

        sinkholeTestAssertSame($expected . PHP_EOL, $rules, 'The exact Bypass rules must remain stable.');
        sinkholeTestAssertSame(
            0,
            preg_match('/^\s*pass\b/m', $rules),
            'No Bypass rule may pass firewall traffic.',
        );
        $ruleLines = preg_split('/\r\n|\r|\n/', trim($rules)) ?: [];

        foreach ($ruleLines as $ruleLine) {
            if (
                $ruleLine === ''
                || str_starts_with($ruleLine, '#')
                || str_starts_with($ruleLine, 'table ')
            ) {
                continue;
            }

            sinkholeTestAssertTrue(
                str_starts_with($ruleLine, 'block return in quick on '),
                'Every Bypass firewall rule must be an inbound quick block.',
            );
        }

        sinkholeTestAssertSame(
            '',
            BypassRuleConfiguration::anchorText([], $configuration, '/v4', '/v6'),
            'No selected interface must produce no rules.',
        );
    },
    'Bypass tables protect selected interface subnets and virtual IPs' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset([
                'virtualip' => ['vip' => [
                    ['mode' => 'carp', 'subnet' => '198.51.100.7'],
                    ['mode' => 'ipalias', 'subnet' => '2001:db8:2::7'],
                    ['mode' => 'proxyarp', 'subnet' => '203.0.113.9'],
                ]],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => [
                'ipv4' => '192.0.2.1',
                'ipv4_prefix' => 24,
                'ipv6' => '2001:db8:1::1',
                'ipv6_prefix' => 64,
            ]];
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $protected = $adapter->ipProtectedAddresses(['lan']);

            foreach (
                [
                    '192.0.2.0/24',
                    '2001:db8:1::/64',
                    '198.51.100.7',
                    '2001:db8:2::7',
                ] as $expected
            ) {
                sinkholeTestAssertSame(
                    true,
                    in_array($expected, $protected, true),
                    $expected . ' must be protected from Bypass tables.',
                );
            }

            sinkholeTestAssertSame(
                false,
                in_array('203.0.113.9', $protected, true),
                'A non-CARP and non-IP-alias virtual address must not be invented as protected.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'compiler emits effective Bypass names beside ordinary allowed domains' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $identifier = str_repeat('a', 32);

        try {
            $paths = sinkholeBypassTestPaths($root);
            $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
            $bypassStore = new BypassListStore($paths);
            mkdir($paths->bypassListDirectory, 0700, true);
            file_put_contents(
                $paths->bypassListFile($identifier),
                "D\tS\tprovider.example.test\nI\t192.0.2.0/24\n",
            );
            file_put_contents(
                $paths->bypassMetadataFile($identifier),
                '{"url": "https://example.test/provider.txt"}' . PHP_EOL,
            );
            $configuration = BypassConfiguration::partition(
                sinkholeBypassTestStorage([[
                    'id' => $identifier,
                    'descr' => 'Invented provider fixture',
                    'url' => 'https://example.test/provider.txt',
                    'kind' => BypassConfiguration::KIND_ENCRYPTED_DNS,
                    'enabled' => 'on',
                ]], ['block_encrypted_dns' => 'on']),
                ['lan'],
            );
            $compiler = new Compiler(
                $paths,
                new SavedListStore($paths),
                $stateStore,
                null,
                $bypassStore,
            );
            $compiler->compile(
                [],
                ['allowed.provider.example.test'],
                configuredBypass: $configuration,
            );
            $manifest = json_decode(
                (string) file_get_contents($paths->runtimeDataDirectory . '/manifest.json'),
                true,
                16,
                JSON_THROW_ON_ERROR,
            );

            sinkholeTestAssertSame(4, $manifest['schema_version'], 'Bypass name indexes require manifest schema 4.');
            sinkholeTestAssertSame(1, $manifest['bypass_domain_count'], 'One effective Bypass name must compile.');
            sinkholeTestAssertSame(
                substr(hash('sha256', 'provider.example.test', true), 0, 16) . "\x00\x00",
                file_get_contents($paths->runtimeDataDirectory . '/bypass.index'),
                'The Bypass index must hold the hashed name and its kind-mask position.',
            );
            sinkholeTestAssertSame(
                [['', 'encrypted_dns']],
                $manifest['bypass_index']['masks'],
                'The Bypass index mask table must keep the kind columns.',
            );
            sinkholeTestAssertSame(
                "provider.example.test\t\tencrypted_dns\n",
                file_get_contents($paths->runtimeDataDirectory . '/bypass.tsv'),
                'The compiler must emit kind membership separately from ordinary list bits.',
            );
            sinkholeTestAssertSame(
                "allowed.provider.example.test\n",
                file_get_contents($paths->runtimeDataDirectory . '/allow.txt'),
                'Allowed domains must remain available to outrank Bypass List names.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'compiler refuses a Bypass List copy saved from another URL' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $identifier = str_repeat('b', 32);

        try {
            $paths = sinkholeBypassTestPaths($root);
            $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
            $bypassStore = new BypassListStore($paths);
            mkdir($paths->bypassListDirectory, 0700, true);
            file_put_contents(
                $paths->bypassListFile($identifier),
                "D\tS\tprevious-provider.example.test\n",
            );
            file_put_contents(
                $paths->bypassMetadataFile($identifier),
                '{"url": "https://example.test/previous-provider.txt"}' . PHP_EOL,
            );
            $configuration = BypassConfiguration::partition(
                sinkholeBypassTestStorage([[
                    'id' => $identifier,
                    'descr' => 'Invented edited provider fixture',
                    'url' => 'https://example.test/edited-provider.txt',
                    'kind' => BypassConfiguration::KIND_ENCRYPTED_DNS,
                    'enabled' => 'on',
                ]], ['block_encrypted_dns' => 'on']),
                ['lan'],
            );
            (new Compiler(
                $paths,
                new SavedListStore($paths),
                $stateStore,
                null,
                $bypassStore,
            ))->compile([], [], configuredBypass: $configuration);
            $manifest = json_decode(
                (string) file_get_contents($paths->runtimeDataDirectory . '/manifest.json'),
                true,
                16,
                JSON_THROW_ON_ERROR,
            );

            sinkholeTestAssertSame(0, $manifest['bypass_domain_count'], 'The previous-URL copy must not compile.');
            sinkholeTestAssertSame(
                true,
                $bypassStore->discardMismatchedCopy($identifier, 'https://example.test/edited-provider.txt'),
                'An update must discard the previous-URL copy.',
            );
            sinkholeTestAssertSame(false, $bypassStore->hasSavedCopy($identifier), 'The copy must be gone.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Bypass failures leave ordinary DNS compilation and IP updates running' => static function (): void {
        global $sinkholeStubCommandStatuses;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $cases = [
            'unassigned interface' => [
                'redirect_interfaces' => [],
                'bypass' => sinkholeBypassTestStorage([], ['block_tls_quic' => 'on']),
                'fail_anchor' => false,
                'configuration_warning' => true,
                'update_warning' => true,
            ],
            'invalid Discovery runtime' => [
                'redirect_interfaces' => ['lan'],
                'bypass' => sinkholeBypassTestStorage([], ['discovery' => 'advertise']),
                'fail_anchor' => false,
                'configuration_warning' => true,
                'update_warning' => false,
            ],
            'anchor load failure' => [
                'redirect_interfaces' => ['lan'],
                'bypass' => sinkholeBypassTestStorage([], ['block_tls_quic' => 'on']),
                'fail_anchor' => true,
                'configuration_warning' => false,
                'update_warning' => true,
            ],
        ];

        foreach ($cases as $caseName => $case) {
            $root = sinkholeTestTemporaryDirectory();

            try {
                $paths = sinkholeBypassTestPaths($root);
                $dnsIdentifier = str_repeat(substr(hash('sha256', $caseName), 0, 1), 32);
                $dnsUrl = 'https://example.test/' . rawurlencode($caseName) . '-dns.txt';
                sinkholeStubReset([
                    'unbound' => [
                        'enable' => 'on',
                        'python' => 'on',
                        'python_script' => 'sinkhole',
                        'enablessl' => '',
                    ],
                    'installedpackages' => ['sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                            'keep_settings' => 'on',
                        ]],
                        'lists' => ['item' => [[
                            'id' => $dnsIdentifier,
                            'descr' => 'Invented ordinary DNS List',
                            'url' => $dnsUrl,
                            'enabled' => 'on',
                            'global' => 'on',
                        ]]],
                        'redirect' => [
                            'interfaces' => ['item' => $case['redirect_interfaces']],
                        ],
                        'bypass' => $case['bypass'],
                        'ip' => [
                            'enabled' => 'on',
                            'interfaces' => ['item' => ['lan']],
                            'directions' => ['item' => ['outbound']],
                            'lists' => ['item' => []],
                            'countries' => ['item' => []],
                            'account_id' => '',
                            'license_key' => '',
                            'allowlist' => ['item' => []],
                        ],
                    ]],
                ]);
                $sinkholeStubInterfaces = ['lan' => 'LAN'];
                $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
                $sinkholeStubRealInterfaces = ['lan' => 'igc0'];

                if ($case['fail_anchor']) {
                    $sinkholeStubCommandStatuses[
                        "/sbin/pfctl -a 'sinkhole/bypass' -f '"
                        . $paths->bypassAnchorFile
                        . "'"
                    ] = 1;
                }

                $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
                $adapter = new PfSenseAdapter($paths, $stateStore, 0);
                $savedStore = new SavedListStore($paths);
                sinkholeBypassTestSaveDnsList($savedStore, $dnsIdentifier, $dnsUrl);
                $bypassStore = new BypassListStore($paths);
                $compiler = new Compiler(
                    $paths,
                    $savedStore,
                    $stateStore,
                    null,
                    $bypassStore,
                );
                $downloadClient = new SinkholeBypassFixtureDownloadClient([]);
                $updater = new Updater(
                    $adapter,
                    $downloadClient,
                    new DomainParser(),
                    $savedStore,
                    $compiler,
                    $stateStore,
                    null,
                    new IpUpdater(
                        $adapter,
                        $downloadClient,
                        new IpParser(),
                        new IpListStore($paths),
                        $paths,
                        new GeoLite2(),
                        new IpStatusStore($paths->ipStatusFile),
                    ),
                    new BypassUpdater(
                        $adapter,
                        $downloadClient,
                        new BypassParser(),
                        $bypassStore,
                        $paths,
                        $compiler,
                    ),
                );
                $result = $updater->run(false, true);
                $bypassStatus = $stateStore->bypassStatus();
                $ipStatus = (new IpStatusStore($paths->ipStatusFile))->read();

                sinkholeTestAssertSame(
                    true,
                    $result['compiled'],
                    $caseName . ' must not stop ordinary DNS compilation.',
                );
                sinkholeTestAssertContains(
                    'ordinary.example.test',
                    (string) file_get_contents($paths->runtimeDataDirectory . '/domains.tsv'),
                    $caseName . ' must retain the ordinary DNS List in the generation.',
                );
                sinkholeTestAssertSame(
                    'completed',
                    $ipStatus['state'] ?? null,
                    $caseName . ' must not stop the independent IP updater.',
                );
                sinkholeTestAssertSame(
                    $case['configuration_warning'],
                    is_string($bypassStatus['configuration_warning']),
                    $caseName . ' must record the expected compiler warning state.',
                );
                sinkholeTestAssertSame(
                    $case['update_warning'],
                    is_string($bypassStatus['update_warning']),
                    $caseName . ' must record the expected updater warning state.',
                );
                sinkholeTestAssertSame(
                    false,
                    file_exists($paths->statusFile),
                    $caseName . ' warnings must not use runtime status storage.',
                );
            } finally {
                sinkholeTestRemoveTemporaryDirectory($root);
            }
        }
    },
    'Bypass updater parses mixed lists keeps last good data and replaces both tables' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubDynamicNameservers;
        global $sinkholeStubGatewayRows;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();
        $identifier = str_repeat('b', 32);
        $unusedIdentifier = str_repeat('d', 32);
        $url = 'https://example.test/mixed-bypass.txt';

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => [
                'redirect' => ['interfaces' => ['item' => ['lan']]],
                'bypass' => sinkholeBypassTestStorage([[
                    'id' => $identifier,
                    'descr' => 'Invented mixed Bypass List',
                    'url' => $url,
                    'kind' => BypassConfiguration::KIND_ENCRYPTED_DNS,
                    'enabled' => 'on',
                ], [
                    'id' => $unusedIdentifier,
                    'descr' => 'Invented unused Tor List',
                    'url' => 'https://example.test/unused-tor.txt',
                    'kind' => BypassConfiguration::KIND_TOR,
                    'enabled' => 'on',
                ]], ['block_encrypted_dns' => 'on']),
            ]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => [
                'ipv4' => '203.0.113.1',
                'ipv6' => '2001:db8:ffff::1',
            ]];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $sinkholeStubDynamicNameservers = [
                '192.0.2.10',
                '',
                'dynamic',
            ];
            $sinkholeStubGatewayRows = [
                'WAN_DHCP' => ['gateway' => '192.0.2.9', 'disabled' => true],
                'WAN_DHCP6' => ['gateway' => 'fe80::2%igc0', 'dynamic' => true],
                'FAILOVER_INACTIVE' => ['gateway' => '192.0.2.11', 'inactive' => true],
                'PLACEHOLDER' => ['gateway' => 'dynamic'],
                'EMPTY' => ['gateway' => ''],
            ];
            $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
            $store = new BypassListStore($paths);
            $adapter = new PfSenseAdapter($paths, $stateStore);
            $compiler = new Compiler(
                $paths,
                new SavedListStore($paths),
                $stateStore,
                null,
                $store,
            );
            $updater = new BypassUpdater(
                $adapter,
                new SinkholeBypassFixtureDownloadClient([
                    $url => "provider.example.test\n192.0.2.7\n192.0.2.9\n"
                        . "192.0.2.10\n192.0.2.11\n"
                        . "198.51.100.0/24\n203.0.113.1\n2001:db8::/64\n"
                        . "2001:db8:ffff::1\njunk value\n",
                ]),
                new BypassParser(),
                $store,
                $paths,
                $compiler,
            );
            $result = $updater->run();

            sinkholeTestAssertSame('completed', $result['status'], 'The invented mixed list must update.');
            sinkholeTestAssertSame(1, $result['attempted'], 'A list whose protection kind is off must not download.');
            sinkholeTestAssertSame(1, $result['updated'], 'One Bypass List must report success.');
            sinkholeTestAssertSame(
                false,
                file_exists($paths->bypassListFile($unusedIdentifier)),
                'An enabled list whose Tor protection is off must remain unused.',
            );
            sinkholeTestAssertSame(
                "D\tS\tprovider.example.test\n"
                    . "I\t192.0.2.7/32\n"
                    . "I\t192.0.2.9/32\n"
                    . "I\t192.0.2.10/32\n"
                    . "I\t192.0.2.11/32\n"
                    . "I\t198.51.100.0/24\n"
                    . "I\t203.0.113.1/32\n"
                    . "I\t2001:db8::/64\n"
                    . "I\t2001:db8:ffff::1/128\n",
                file_get_contents($paths->bypassListFile($identifier)),
                'The last-good copy must retain canonical mixed entries.',
            );
            sinkholeTestAssertSame(
                "192.0.2.7/32\n198.51.100.0/24\n",
                file_get_contents($paths->bypassTableIpv4File),
                'DHCP gateway and dynamic DNS hosts must stay out of the IPv4 table.',
            );
            sinkholeTestAssertSame(
                "2001:db8::/64\n",
                file_get_contents($paths->bypassTableIpv6File),
                'Only unprotected invented IPv6 networks must reach the IPv6 table.',
            );
            sinkholeTestAssertSame(
                false,
                str_contains(
                    (string) file_get_contents($paths->bypassTableIpv4File),
                    '203.0.113.1',
                ),
                'A Bypass table must exclude the firewall IPv4 address.',
            );
            sinkholeTestAssertSame(
                false,
                str_contains(
                    (string) file_get_contents($paths->bypassTableIpv6File),
                    '2001:db8:ffff::1',
                ),
                'A Bypass table must exclude the firewall IPv6 address.',
            );
            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/bypass' -f '" . $paths->bypassAnchorFile . "'",
                implode("\n", $sinkholeStubCommands),
                'The independent Bypass anchor must load from its fixed file.',
            );
            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/bypass' -t 'sinkhole_bypass_v4' -T replace -f '",
                implode("\n", $sinkholeStubCommands),
                'The IPv4 Bypass table must be replaced atomically.',
            );
            $savedCopy = file_get_contents($paths->bypassListFile($identifier));
            $failed = (new BypassUpdater(
                $adapter,
                new SinkholeBypassFixtureDownloadClient([]),
                new BypassParser(),
                $store,
                $paths,
                $compiler,
            ))->run();

            sinkholeTestAssertSame('warning', $failed['status'], 'A failed refresh with saved data must warn.');
            sinkholeTestAssertSame($savedCopy, file_get_contents($paths->bypassListFile($identifier)), 'A failed refresh must keep the last good copy.');
            sinkholeTestAssertContains(
                'Invented Bypass List transport failure.',
                (string) $store->metadata($identifier)['last_error'],
                'Per-list status must retain the latest failure.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Bypass saves rebuild or remove table files before loading the anchor' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();
        $identifier = str_repeat('e', 32);
        $list = [
            'id' => $identifier,
            'descr' => 'Invented saved provider list',
            'url' => 'https://example.test/saved-provider.txt',
            'kind' => BypassConfiguration::KIND_ENCRYPTED_DNS,
            'enabled' => 'on',
        ];
        $redirect = [
            'enabled' => false,
            'interfaces' => ['lan'],
            'exempt_sources' => [],
            'exempt_destinations' => [],
        ];

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset([]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            mkdir($paths->bypassListDirectory, 0700, true);
            file_put_contents(
                $paths->bypassListFile($identifier),
                "I\t198.51.100.0/24\n",
            );
            file_put_contents(
                $paths->bypassMetadataFile($identifier),
                json_encode(['url' => $list['url']]) . PHP_EOL,
            );
            file_put_contents($paths->bypassTableIpv4File, "203.0.113.0/24\n");
            file_put_contents($paths->bypassTableIpv6File, "2001:db8:ffff::/48\n");
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );

            $adapter->saveBypassConfiguration(
                sinkholeBypassTestStorage([$list], ['block_encrypted_dns' => 'on']),
                $redirect,
            );
            sinkholeTestAssertSame(
                "198.51.100.0/24\n",
                file_get_contents($paths->bypassTableIpv4File),
                'Saving must replace stale IPv4 table contents from effective lists.',
            );
            sinkholeTestAssertSame(
                '',
                file_get_contents($paths->bypassTableIpv6File),
                'Saving must replace stale IPv6 table contents even when none remain.',
            );

            $adapter->saveBypassConfiguration(
                sinkholeBypassTestStorage([$list]),
                $redirect,
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->bypassTableIpv4File)
                    || file_exists($paths->bypassTableIpv6File),
                'Turning every list-backed kind off must delete both table files.',
            );

            $list['enabled'] = '';
            $adapter->saveBypassConfiguration(
                sinkholeBypassTestStorage([$list], ['block_encrypted_dns' => 'on']),
                $redirect,
            );
            sinkholeTestAssertSame(
                '',
                file_get_contents($paths->bypassTableIpv4File),
                'Disabling the last effective list must load an empty IPv4 table.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Discovery saves reconcile custom options and restart only for zone changes' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;
        global $sinkholeStubUnboundConfigureCount;

        $root = sinkholeTestTemporaryDirectory();
        $adminOptions = 'server:' . "\n" . 'verbosity: 1';
        $redirect = [
            'enabled' => false,
            'interfaces' => ['lan'],
            'exempt_sources' => [],
            'exempt_destinations' => [],
        ];

        try {
            sinkholeStubReset([
                'unbound' => [
                    'enable' => 'on',
                    'python' => 'on',
                    'python_order' => 'pre_validator',
                    'python_script' => 'sinkhole',
                    'custom_options' => base64_encode($adminOptions),
                    'enablessl' => 'on',
                    'tlsport' => '853',
                    'sslcertref' => 'invented-resolver-certificate',
                ],
                'cert' => [[
                    'refid' => 'invented-resolver-certificate',
                    'crt' => base64_encode(sinkholeBypassTestCertificate()),
                ]],
                'installedpackages' => ['sinkhole' => [
                    'config' => [[
                        'enabled' => 'on',
                        'update_frequency' => 'daily',
                    ]],
                    'redirect' => ['interfaces' => ['item' => ['lan']]],
                    'bypass' => sinkholeBypassTestStorage(),
                ]],
                'system' => [],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $paths = sinkholeBypassTestPaths($root);
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $expectedOptions = UnboundCustomOptions::reconcileDiscoveryZone(
                $adminOptions,
                true,
            );

            $adapter->saveBypassConfiguration(
                sinkholeBypassTestStorage([], ['discovery' => 'nodata']),
                $redirect,
            );
            sinkholeTestAssertSame(
                $expectedOptions,
                base64_decode((string) config_get_path('unbound/custom_options'), true),
                'Turning Discovery on must append the managed custom-options block.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubUnboundConfigureCount,
                'Turning Discovery on must restart Unbound exactly once.',
            );
            sinkholeTestAssertSame(
                true,
                $adapter->getBypassConfiguration()['discovery_zone_present'],
                'Bypass status must report the exact zone line as present.',
            );

            $adapter->saveBypassConfiguration(
                sinkholeBypassTestStorage([], ['discovery' => 'advertise']),
                $redirect,
            );
            sinkholeTestAssertSame(
                $expectedOptions,
                base64_decode((string) config_get_path('unbound/custom_options'), true),
                'Changing active Discovery modes must leave the block unchanged.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubUnboundConfigureCount,
                'Changing active Discovery modes must not restart Unbound.',
            );

            $adapter->saveBypassConfiguration(
                sinkholeBypassTestStorage(),
                $redirect,
            );
            sinkholeTestAssertSame(
                $adminOptions,
                base64_decode((string) config_get_path('unbound/custom_options'), true),
                'Turning Discovery off must restore the administrator options exactly.',
            );
            sinkholeTestAssertSame(
                2,
                $sinkholeStubUnboundConfigureCount,
                'Turning Discovery off must restart Unbound exactly once.',
            );

            $adapter->saveBypassConfiguration(
                sinkholeBypassTestStorage(),
                $redirect,
            );
            sinkholeTestAssertSame(
                2,
                $sinkholeStubUnboundConfigureCount,
                'Saving an unchanged Discovery state must not restart Unbound.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Discovery zone is removed when selected Bypass interfaces disappear' => static function (): void {
        global $sinkholeStubInterfaces;
        global $sinkholeStubUnboundConfigureCount;
        global $sinkholeStubWrites;

        $root = sinkholeTestTemporaryDirectory();
        $adminOptions = 'verbosity: 2';

        try {
            sinkholeStubReset([
                'unbound' => [
                    'enable' => 'on',
                    'python' => 'on',
                    'python_order' => 'pre_validator',
                    'python_script' => 'sinkhole',
                    'custom_options' => base64_encode(
                        UnboundCustomOptions::reconcileDiscoveryZone(
                            $adminOptions,
                            true,
                        ),
                    ),
                ],
                'installedpackages' => ['sinkhole' => [
                    'config' => [[
                        'enabled' => 'on',
                        'update_frequency' => 'daily',
                    ]],
                    'redirect' => ['interfaces' => ['item' => ['lan']]],
                    'bypass' => sinkholeBypassTestStorage(
                        [],
                        ['discovery' => 'nodata'],
                    ),
                ]],
                'system' => [],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $paths = sinkholeBypassTestPaths($root);
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $adapter->enableDnsResolverIntegration();
            $sinkholeStubUnboundConfigureCount = 0;
            $sinkholeStubWrites = [];

            config_set_path('installedpackages/sinkhole/redirect/interfaces/item', []);
            $adapter->enableDnsResolverIntegration();

            sinkholeTestAssertSame(
                $adminOptions,
                base64_decode((string) config_get_path('unbound/custom_options'), true),
                'Losing every selected interface must remove only the managed block.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubUnboundConfigureCount,
                'Removing the zone for an empty interface selection must restart once.',
            );
            sinkholeTestAssertSame(
                1,
                count($sinkholeStubWrites),
                'Removing the zone for an empty interface selection must write once.',
            );

            config_set_path(
                'installedpackages/sinkhole/redirect/interfaces/item',
                ['lan'],
            );
            $adapter->enableDnsResolverIntegration();
            config_set_path('installedpackages/sinkhole/config/0/enabled', '');
            $adapter->enableDnsResolverIntegration();
            sinkholeTestAssertSame(
                $adminOptions,
                base64_decode((string) config_get_path('unbound/custom_options'), true),
                'Disabling the package must remove the managed block.',
            );
            sinkholeTestAssertSame(
                3,
                $sinkholeStubUnboundConfigureCount,
                'Re-adding for an interface and removing for package disablement must each restart once.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'The update cron ignores enabled Bypass Lists whose kind is off' => static function (): void {
        global $sinkholeStubCronOperations;
        global $sinkholeStubInterfaces;

        $root = sinkholeTestTemporaryDirectory();
        $identifier = str_repeat('f', 32);

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => [
                'redirect' => ['interfaces' => ['item' => ['lan']]],
                'bypass' => sinkholeBypassTestStorage([[
                    'id' => $identifier,
                    'descr' => 'Invented dormant Tor List',
                    'url' => 'https://example.test/dormant-tor.txt',
                    'kind' => BypassConfiguration::KIND_TOR,
                    'enabled' => 'on',
                ]]),
            ]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            pfsensePackageSinkholeAdapter(new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            ));

            pfsensePackageSinkholeInstallCron();
            sinkholeTestAssertSame(
                false,
                $sinkholeStubCronOperations[0][1],
                'A dormant list alone must not keep the update cron enabled.',
            );

            config_set_path('installedpackages/sinkhole/bypass/block_tor', 'on');
            $sinkholeStubCronOperations = [];
            pfsensePackageSinkholeInstallCron();
            sinkholeTestAssertSame(
                true,
                $sinkholeStubCronOperations[0][1],
                'Turning on the list kind must enable the shared update cron.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Discovery advertise validation rejects a disabled Resolver TLS service' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => []]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $threw = false;

            try {
                $adapter->saveBypassConfiguration(
                    sinkholeBypassTestStorage([], ['discovery' => 'advertise']),
                    [
                        'enabled' => false,
                        'interfaces' => ['lan'],
                        'exempt_sources' => [],
                        'exempt_destinations' => [],
                    ],
                );
            } catch (ValidationException $exception) {
                $threw = $exception->messageKey() === 'bypass_discovery_tls_required'
                    && str_contains($exception->messageArguments()[0], 'SSL/TLS service is off');
            }

            sinkholeTestAssertSame(true, $threw, 'Advertise must fail with a clear TLS-service reason.');
            sinkholeTestAssertSame(
                [],
                config_get_path('installedpackages/sinkhole/bypass', []),
                'Failed validation must not persist the Bypass setting.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Discovery advertise accepts pfSense wrapped Resolver certificates' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset([
                'unbound' => [
                    'enable' => 'on',
                    'enablessl' => 'on',
                    'tlsport' => '853',
                    'sslcertref' => 'invented-resolver-certificate',
                ],
                'cert' => [[
                    'refid' => 'invented-resolver-certificate',
                    'crt' => base64_encode(sinkholeBypassTestCertificate()),
                ]],
                'installedpackages' => ['sinkhole' => []],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $tls = $adapter->dnsResolverTlsStatus();

            sinkholeTestAssertSame(true, $tls['service_enabled'], 'The Resolver TLS switch must be detected.');
            sinkholeTestAssertSame(true, $tls['enabled'], 'The wrapped certificate must be usable for DDR.');
            sinkholeTestAssertSame('resolver.example.test', $tls['hostname'], 'DDR must use the certificate DNS SAN.');
            sinkholeTestAssertSame(853, $tls['port'], 'DDR must advertise the standard DNS-over-TLS port.');

            $adapter->saveBypassConfiguration(
                sinkholeBypassTestStorage([], ['discovery' => 'advertise']),
                [
                    'enabled' => false,
                    'interfaces' => ['lan'],
                    'exempt_sources' => [],
                    'exempt_destinations' => [],
                ],
            );

            sinkholeTestAssertSame(
                'advertise',
                config_get_path('installedpackages/sinkhole/bypass/discovery'),
                'A usable wrapped certificate must pass DDR save validation.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Bypass anchor listing suppresses stderr and accepts an absent child' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubExecOutputs;
        global $sinkholeStubExecStatuses;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeBypassTestPaths($root);
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $rulesCommand = "/sbin/pfctl -a 'sinkhole/bypass' -sr 2>/dev/null";
            $tablesCommand = "/sbin/pfctl -a 'sinkhole/bypass' -sT 2>/dev/null";
            $parentAnchorsCommand = "/sbin/pfctl -a 'sinkhole' -sA 2>/dev/null";

            sinkholeStubReset([]);
            file_put_contents($paths->bypassAnchorFile, 'invented stale anchor');
            file_put_contents($paths->bypassAnchorDigestFile, 'invented stale digest');
            $sinkholeStubExecOutputs[$rulesCommand] = ['pfctl: Anchor does not exist.'];
            $sinkholeStubExecOutputs[$tablesCommand] = ['pfctl: Anchor does not exist.'];
            $sinkholeStubExecStatuses[$rulesCommand] = 1;
            $sinkholeStubExecStatuses[$tablesCommand] = 1;
            $sinkholeStubExecStatuses[$parentAnchorsCommand] = 0;

            $adapter->flushBypassAnchor();

            sinkholeTestAssertSame(
                [$rulesCommand, $tablesCommand, $parentAnchorsCommand],
                $sinkholeStubCommands,
                'An absent Bypass child must be inspected without issuing a flush.',
            );
            sinkholeTestAssertSame(false, file_exists($paths->bypassAnchorFile), 'An absent anchor must remove stale text.');
            sinkholeTestAssertSame(false, file_exists($paths->bypassAnchorDigestFile), 'An absent anchor must remove its digest.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'A ruleless Bypass anchor stays absent and current without repeated loads' => static function (): void {
        global $sinkholeStubBypassAnchorLoaded;
        global $sinkholeStubCommands;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => [
                'redirect' => ['interfaces' => ['item' => ['lan']]],
                'bypass' => sinkholeBypassTestStorage(
                    [],
                    ['block_encrypted_dns' => 'on'],
                ),
            ]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => []];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );

            sinkholeTestAssertSame(
                'flushed',
                $adapter->applyBypassAnchor(),
                'An interface without an address must leave no Bypass anchor.',
            );
            sinkholeTestAssertSame(
                false,
                $sinkholeStubBypassAnchorLoaded,
                'No Bypass rules must be loaded.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->bypassAnchorFile),
                'A ruleless Bypass configuration must write no anchor.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->bypassAnchorDigestFile),
                'A ruleless Bypass configuration must retain no anchor digest.',
            );
            $status = $adapter->bypassAnchorStatus();
            sinkholeTestAssertSame(
                false,
                $status['loaded'],
                'An absent Bypass anchor must not report as loaded.',
            );
            sinkholeTestAssertSame(
                false,
                $status['anchor_loaded'],
                'The ruleless Bypass anchor must stay absent.',
            );
            sinkholeTestAssertSame(
                false,
                $status['out_of_date'],
                'An intentionally absent Bypass anchor must be current.',
            );
            sinkholeTestAssertSame(
                0,
                $status['rule_count'],
                'An absent Bypass anchor must report zero block rules.',
            );

            $sinkholeStubCommands = [];
            sinkholeTestAssertSame(
                'matching',
                $adapter->reconcileBypassAnchor(),
                'The first minute reconciliation must keep the absent anchor current.',
            );
            sinkholeTestAssertSame(
                'matching',
                $adapter->reconcileBypassAnchor(),
                'Repeated minute reconciliation must keep the absent anchor current.',
            );
            sinkholeTestAssertSame(
                false,
                str_contains(implode("\n", $sinkholeStubCommands), " -f '"),
                'Repeated reconciliation must issue no Bypass anchor load.',
            );
            sinkholeTestAssertSame(
                false,
                str_contains(implode("\n", $sinkholeStubCommands), ' -F all'),
                'Repeated reconciliation must issue no Bypass anchor flush.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'IP and Bypass anchors coexist and disabling Bypass leaves IP loaded' => static function (): void {
        global $sinkholeStubBypassAnchorLoaded;
        global $sinkholeStubCommands;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubIpAnchorLoaded;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => [
                'redirect' => ['interfaces' => ['item' => ['lan']]],
                'bypass' => sinkholeBypassTestStorage([], ['block_tls_quic' => 'on']),
                'ip' => [
                    'enabled' => 'on',
                    'interfaces' => ['item' => ['lan']],
                    'directions' => ['item' => ['outbound']],
                    'lists' => ['item' => []],
                    'countries' => ['item' => []],
                    'account_id' => '',
                    'license_key' => '',
                    'allowlist' => ['item' => []],
                ],
            ]]]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $adapter->applyIpAnchor();
            $adapter->applyBypassAnchor();
            pfsensePackageSinkholeAdapter($adapter);

            sinkholeTestAssertSame(true, $sinkholeStubIpAnchorLoaded, 'The IP anchor must be loaded.');
            sinkholeTestAssertSame(true, $sinkholeStubBypassAnchorLoaded, 'The Bypass anchor must be loaded.');
            sinkholeTestAssertSame(
                "anchor \"sinkhole/ip\"\nanchor \"sinkhole/bypass\"\n",
                pfsensePackageSinkholeFilterRules('pfearly'),
                'A filter reload must register both independent early anchors.',
            );
            $sinkholeStubIpAnchorLoaded = false;
            $sinkholeStubBypassAnchorLoaded = false;
            $sinkholeStubCommands = [];

            sinkholeTestAssertSame(
                'reloaded',
                $adapter->reconcileIpAnchor(),
                'The IP anchor must reload after a filter reload removes its rules.',
            );
            sinkholeTestAssertSame(
                'reloaded',
                $adapter->reconcileBypassAnchor(),
                'The Bypass anchor must reload after a filter reload removes its rules.',
            );
            sinkholeTestAssertSame(true, $sinkholeStubIpAnchorLoaded, 'The IP anchor must be restored.');
            sinkholeTestAssertSame(true, $sinkholeStubBypassAnchorLoaded, 'The Bypass anchor must be restored.');
            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/ip' -f '",
                implode("\n", $sinkholeStubCommands),
                'Filter-reload recovery must load the IP anchor from its fixed file.',
            );
            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/bypass' -f '",
                implode("\n", $sinkholeStubCommands),
                'Filter-reload recovery must load the Bypass anchor from its fixed file.',
            );
            config_set_path('installedpackages/sinkhole/bypass/block_tls_quic', '');
            $sinkholeStubCommands = [];
            $adapter->applyBypassAnchor();

            sinkholeTestAssertSame(true, $sinkholeStubIpAnchorLoaded, 'Disabling Bypass must not disturb IP blocking.');
            sinkholeTestAssertSame(false, $sinkholeStubBypassAnchorLoaded, 'Disabling Bypass must flush its own anchor.');
            sinkholeTestAssertSame(
                false,
                str_contains(implode("\n", $sinkholeStubCommands), "sinkhole/ip' -F all"),
                'The Bypass flush must issue no IP-anchor command.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'A Bypass reference exception leaves the IP anchor reference intact' => static function (): void {
        global $sinkholeBypassTestCertificateLookupFailure;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubLogs;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset([
                'unbound' => [
                    'enable' => 'on',
                    'enablessl' => 'on',
                    'tlsport' => '853',
                    'sslcertref' => 'invented-certificate',
                ],
                'installedpackages' => ['sinkhole' => [
                    'redirect' => ['interfaces' => ['item' => ['lan']]],
                    'bypass' => sinkholeBypassTestStorage([], ['block_tls_quic' => 'on']),
                    'ip' => [
                        'enabled' => 'on',
                        'interfaces' => ['item' => ['lan']],
                        'directions' => ['item' => ['outbound']],
                        'lists' => ['item' => []],
                        'countries' => ['item' => []],
                        'account_id' => '',
                        'license_key' => '',
                        'allowlist' => ['item' => []],
                    ],
                ]],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            pfsensePackageSinkholeAdapter($adapter);
            $sinkholeBypassTestCertificateLookupFailure = true;

            sinkholeTestAssertSame(
                "anchor \"sinkhole/ip\"\n",
                pfsensePackageSinkholeFilterRules('pfearly'),
                'A Bypass exception must not remove the independent IP reference.',
            );
            sinkholeTestAssertContains(
                'Bypass blocking rules were omitted: Invented Bypass certificate lookup failure.',
                implode("\n", $sinkholeStubLogs),
                'The isolated Bypass reference failure must be logged.',
            );
        } finally {
            $sinkholeBypassTestCertificateLookupFailure = false;
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'removal flushes Bypass runtime and cache while Keep Settings controls configuration' => static function (): void {
        global $sinkholeStubBypassAnchorLoaded;
        global $sinkholeStubCommands;

        $root = sinkholeTestTemporaryDirectory();
        $identifier = str_repeat('c', 32);

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => [
                'keep_settings' => 'on',
                'bypass' => sinkholeBypassTestStorage(),
            ]]]);
            mkdir($paths->bypassListDirectory, 0700, true);
            file_put_contents($paths->bypassListFile($identifier), "D\tS\tcache.example.test\n");

            foreach ([
                $paths->bypassTableIpv4File,
                $paths->bypassTableIpv6File,
                $paths->bypassAnchorFile,
                $paths->bypassAnchorDigestFile,
            ] as $path) {
                file_put_contents($path, 'invented');
            }

            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            $sinkholeStubBypassAnchorLoaded = true;
            $adapter->clearBypassRuntimeData();

            sinkholeTestAssertContains(
                "/sbin/pfctl -a 'sinkhole/bypass' -F all",
                implode("\n", $sinkholeStubCommands),
                'Removal must flush the complete Bypass anchor.',
            );
            sinkholeTestAssertSame(false, is_dir($paths->bypassListDirectory), 'Removal must delete cached Bypass Lists.');
            sinkholeTestAssertSame(false, file_exists($paths->bypassAnchorFile), 'Removal must delete anchor text.');
            sinkholeTestAssertTrue(
                is_array(config_get_path('installedpackages/sinkhole/bypass', null)),
                'Keep Settings must retain the saved Bypass configuration.',
            );
            $adapter->removePersistentData();
            sinkholeTestAssertSame(
                null,
                config_get_path('installedpackages/sinkhole', null),
                'Keep Settings off must remove the package configuration.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'An IP cleanup failure does not skip Bypass removal cleanup' => static function (): void {
        global $sinkholeStubLogs;

        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset(['installedpackages' => ['sinkhole' => [
                'keep_settings' => 'on',
            ]]]);
            mkdir($paths->ipTableIpv4File, 0700, true);
            file_put_contents($paths->bypassTableIpv4File, "198.51.100.0/24\n");
            file_put_contents($paths->bypassAnchorFile, "# invented Bypass anchor\n");
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );
            pfsensePackageSinkholeAdapter($adapter);

            pfsensePackageSinkholeRemove(0);

            sinkholeTestAssertSame(
                false,
                file_exists($paths->bypassTableIpv4File)
                    || file_exists($paths->bypassAnchorFile),
                'Bypass cleanup must run after an independent IP cleanup failure.',
            );
            sinkholeTestAssertContains(
                'IP removal cleanup failed:',
                implode("\n", $sinkholeStubLogs),
                'The independent IP cleanup failure must still be logged.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Bypass block exemptions nest the blocks without passes for aliases and literals' => static function (): void {
        $interfaces = [[
            'interface' => 'lan',
            'real_interface' => 'igc0',
            'ipv4' => true,
            'ipv6' => true,
        ]];
        $configuration = [
            'block_tls_quic' => true,
            'block_encrypted_dns' => true,
            'exempt_sources' => ['IP4_CENTRALSTATION', '10.0.0.5'],
            'exempt_destinations' => ['9.9.9.9'],
            'invalid_exemptions' => [],
        ];
        $rules = BypassRuleConfiguration::anchorText(
            $interfaces,
            $configuration,
            '/var/db/sinkhole-bypass-v4.txt',
            '/var/db/sinkhole-bypass-v6.txt',
        );
        $expected = <<<'RULES'
# Sinkhole bypass protection
table <sinkhole_bypass_v4> persist file "/var/db/sinkhole-bypass-v4.txt"
table <sinkhole_bypass_v6> persist file "/var/db/sinkhole-bypass-v6.txt"
table <sinkhole_bypass_exempt_src> { 10.0.0.5 }
table <sinkhole_bypass_exempt_dst> { 9.9.9.9 }
anchor "ports" in from ! <sinkhole_bypass_exempt_src> to ! <sinkhole_bypass_exempt_dst> {
    anchor "aliases_1" in from ! <IP4_CENTRALSTATION> {
        block return in quick on igc0 inet proto { tcp udp } from any to ! (self) port 853
        block return in quick on igc0 inet6 proto { tcp udp } from any to ! (self) port 853
    }
}
anchor "providers_inet" in inet from ! <sinkhole_bypass_exempt_src> to <sinkhole_bypass_v4> {
    anchor "aliases_1" in from ! <IP4_CENTRALSTATION> {
        block return in quick on igc0 inet all
    }
}
anchor "providers_inet6" in inet6 from ! <sinkhole_bypass_exempt_src> to <sinkhole_bypass_v6> {
    anchor "aliases_1" in from ! <IP4_CENTRALSTATION> {
        block return in quick on igc0 inet6 all
    }
}
RULES;

        sinkholeTestAssertSame($expected . PHP_EOL, $rules, 'Mixed exemptions must nest every block exactly.');
        sinkholeTestAssertSame(
            0,
            preg_match('/^\s*pass\b/m', $rules),
            'Block exemptions must never pass firewall traffic.',
        );
        sinkholeTestAssertSame(
            0,
            preg_match('/^\s*anchor .*\bquick\b/m', $rules),
            'Exemption anchors must not be quick, which would end evaluation for unmatched traffic.',
        );

        $aliasRules = BypassRuleConfiguration::anchorText(
            $interfaces,
            [
                'block_tls_quic' => true,
                'block_tor' => true,
                'exempt_sources' => ['NAS_HOSTS', 'CAMERAS'],
                'exempt_destinations' => ['DNS_SERVERS'],
                'invalid_exemptions' => [],
            ],
            '/v4',
            '/v6',
        );
        $expectedAliasRules = <<<'RULES'
# Sinkhole bypass protection
table <sinkhole_bypass_v4> persist file "/v4"
table <sinkhole_bypass_v6> persist file "/v6"
anchor "ports" in from ! <NAS_HOSTS> to ! <DNS_SERVERS> {
    anchor "aliases_1" in from ! <CAMERAS> {
        block return in quick on igc0 inet proto { tcp udp } from any to ! (self) port 853
        block return in quick on igc0 inet6 proto { tcp udp } from any to ! (self) port 853
    }
}
anchor "providers_inet" in inet from any to <sinkhole_bypass_v4> {
    anchor "aliases_1" in from ! <NAS_HOSTS> to ! <DNS_SERVERS> {
        anchor "aliases_2" in from ! <CAMERAS> {
            block return in quick on igc0 inet all
        }
    }
}
anchor "providers_inet6" in inet6 from any to <sinkhole_bypass_v6> {
    anchor "aliases_1" in from ! <NAS_HOSTS> to ! <DNS_SERVERS> {
        anchor "aliases_2" in from ! <CAMERAS> {
            block return in quick on igc0 inet6 all
        }
    }
}
RULES;

        sinkholeTestAssertSame(
            $expectedAliasRules . PHP_EOL,
            $aliasRules,
            'Alias-only exemptions must reference pfSense alias tables one pair per level.',
        );
        sinkholeTestAssertSame(
            false,
            str_contains($aliasRules, 'sinkhole_bypass_exempt_'),
            'Alias-only exemptions must not declare literal tables.',
        );

        $literalRules = BypassRuleConfiguration::anchorText(
            [[
                'interface' => 'lan',
                'real_interface' => 'igc0',
                'ipv4' => true,
                'ipv6' => true,
            ]],
            [
                'block_vpn_ports' => true,
                'block_vpn' => true,
                'exempt_sources' => ['192.0.2.10', '2001:db8:5::/64', '198.51.100.9/24'],
                'exempt_destinations' => ['2606:4700:4700::1111'],
                'invalid_exemptions' => [],
            ],
            '/v4',
            '/v6',
        );
        $expectedLiteralRules = <<<'RULES'
# Sinkhole bypass protection
table <sinkhole_bypass_v4> persist file "/v4"
table <sinkhole_bypass_v6> persist file "/v6"
table <sinkhole_bypass_exempt_src> { 192.0.2.10 2001:db8:5::/64 198.51.100.0/24 }
table <sinkhole_bypass_exempt_dst> { 2606:4700:4700::1111 }
anchor "ports" in from ! <sinkhole_bypass_exempt_src> to ! <sinkhole_bypass_exempt_dst> {
    block return in quick on igc0 inet proto { tcp udp } from any to ! (self) port 1194
    block return in quick on igc0 inet proto udp from any to ! (self) port { 500 4500 51820 }
    block return in quick on igc0 inet proto esp from any to ! (self)
    block return in quick on igc0 inet6 proto { tcp udp } from any to ! (self) port 1194
    block return in quick on igc0 inet6 proto udp from any to ! (self) port { 500 4500 51820 }
    block return in quick on igc0 inet6 proto esp from any to ! (self)
}
anchor "providers_inet" in inet from ! <sinkhole_bypass_exempt_src> to <sinkhole_bypass_v4> {
    block return in quick on igc0 inet all
}
anchor "providers_inet6" in inet6 from ! <sinkhole_bypass_exempt_src> to <sinkhole_bypass_v6> {
    block return in quick on igc0 inet6 all
}
RULES;

        sinkholeTestAssertSame(
            $expectedLiteralRules . PHP_EOL,
            $literalRules,
            'Literal exemptions of both families must share one masked table per direction.',
        );

        $destinationRules = BypassRuleConfiguration::anchorText(
            [[
                'interface' => 'lan',
                'real_interface' => 'igc0',
                'ipv4' => true,
                'ipv6' => false,
            ]],
            [
                'block_tls_quic' => true,
                'block_encrypted_dns' => true,
                'exempt_sources' => [],
                'exempt_destinations' => ['1.1.1.1'],
                'invalid_exemptions' => [],
            ],
            '/v4',
            '/v6',
        );
        $expectedDestinationRules = <<<'RULES'
# Sinkhole bypass protection
table <sinkhole_bypass_v4> persist file "/v4"
table <sinkhole_bypass_v6> persist file "/v6"
table <sinkhole_bypass_exempt_dst> { 1.1.1.1 }
anchor "ports" in to ! <sinkhole_bypass_exempt_dst> {
    block return in quick on igc0 inet proto { tcp udp } from any to ! (self) port 853
}
block return in quick on igc0 inet from any to <sinkhole_bypass_v4>
RULES;

        sinkholeTestAssertSame(
            $expectedDestinationRules . PHP_EOL,
            $destinationRules,
            'Literal destinations alone must leave provider rules flat because the tables subtract them.',
        );

        $flatConfiguration = [
            'block_tls_quic' => true,
            'block_encrypted_dns' => true,
        ];
        $flatRules = BypassRuleConfiguration::anchorText($interfaces, $flatConfiguration, '/v4', '/v6');

        sinkholeTestAssertSame(
            $flatRules,
            BypassRuleConfiguration::anchorText(
                $interfaces,
                array_replace($flatConfiguration, [
                    'exempt_sources' => [],
                    'exempt_destinations' => [],
                    'invalid_exemptions' => [],
                ]),
                '/v4',
                '/v6',
            ),
            'Empty exemptions must render the unchanged flat rules.',
        );
        sinkholeTestAssertSame(
            $flatRules,
            BypassRuleConfiguration::anchorText(
                $interfaces,
                array_replace($configuration, [
                    'invalid_exemptions' => [[
                        'field' => 'block_exemptions',
                        'field_key' => 'block_exemptions',
                        'value' => 'GONE',
                        'reason' => 'invented',
                        'reason_key' => 'exempt_source_value_invalid',
                        'reason_arguments' => [],
                    ]],
                ]),
                '/v4',
                '/v6',
            ),
            'Any invalid saved exemption must keep every block without exemptions.',
        );
        sinkholeTestAssertSame(
            ['literals' => ['10.0.0.5'], 'aliases' => ['IP4_CENTRALSTATION']],
            BypassRuleConfiguration::splitExemptions([
                'IP4_CENTRALSTATION',
                '10.0.0.5',
                'bad name',
                '123',
                '{ any }',
            ]),
            'Only literal networks and pf-safe alias names may reach rule text.',
        );
    },
    'Bypass block exemptions partition invalid values without disabling the blocks' => static function (): void {
        $aliases = [
            'IP4_CENTRALSTATION' => 'host',
            'Office_Net' => 'network',
        ];
        $storage = sinkholeBypassTestStorage([], [
            'block_tls_quic' => 'on',
            'exempt_sources' => ['item' => ['IP4_CENTRALSTATION', ' 10.0.0.5 ', '10.0.0.5']],
            'exempt_destinations' => ['item' => ['2606:4700:4700:0:0:0:0:1111']],
        ]);
        $valid = BypassConfiguration::partition($storage, ['lan'], $aliases);

        sinkholeTestAssertSame(
            ['IP4_CENTRALSTATION', '10.0.0.5'],
            $valid['exempt_sources'],
            'Exempt sources must be normalized and deduplicated with the redirect rules.',
        );
        sinkholeTestAssertSame(
            ['2606:4700:4700::1111'],
            $valid['exempt_destinations'],
            'A single saved exempt destination must be accepted and canonicalized.',
        );
        sinkholeTestAssertSame(
            ['IP4_CENTRALSTATION', ' 10.0.0.5 ', '10.0.0.5'],
            $valid['stored_exempt_sources'],
            'The stored exempt sources must keep their original text for repair.',
        );
        sinkholeTestAssertSame([], $valid['invalid_exemptions'], 'Valid exemptions must report no repair.');

        $invalid = BypassConfiguration::partition(
            array_replace($storage, [
                'exempt_destinations' => ['item' => ['Renamed_Alias', 'ports_alias!']],
            ]),
            ['lan'],
            $aliases,
        );

        sinkholeTestAssertSame([], $invalid['invalid_values'], 'Invalid exemptions must not pause the blocks.');
        sinkholeTestAssertSame(true, $invalid['firewall_enabled'], 'Invalid exemptions must keep the firewall blocks on.');
        sinkholeTestAssertSame(2, count($invalid['invalid_exemptions']), 'Every invalid exemption must be listed for repair.');
        sinkholeTestAssertSame(
            'block_exemptions',
            $invalid['invalid_exemptions'][0]['field_key'],
            'Invalid block exemptions must name their own field.',
        );
        sinkholeTestAssertSame(
            'exempt_destination_value_invalid',
            $invalid['invalid_exemptions'][0]['reason_key'],
            'A missing alias must reuse the redirect validation reason.',
        );
        sinkholeTestAssertSame(
            ['sources' => [], 'destinations' => []],
            BypassConfiguration::effectiveExemptions($invalid),
            'Any invalid exemption must drop every exemption.',
        );

        $aliasLimit = BypassConfiguration::MAXIMUM_EXEMPTION_ALIASES + 1;
        $manyAliases = [];

        for ($aliasIndex = 0; $aliasIndex < $aliasLimit; $aliasIndex++) {
            $manyAliases['Alias_' . $aliasIndex] = 'host';
        }

        $limited = BypassConfiguration::partition(
            array_replace($storage, [
                'exempt_sources' => ['item' => array_keys($manyAliases)],
            ]),
            ['lan'],
            $manyAliases,
        );

        sinkholeTestAssertSame(
            'bypass_exemption_aliases_limit',
            $limited['invalid_exemptions'][0]['reason_key'] ?? '',
            'Too many aliases must be refused before the anchors nest too deep.',
        );

        $rejected = '';

        try {
            BypassConfiguration::normalizeExemptionSubmission(
                "10.0.0.5\n\nIP4_CENTRALSTATION",
                'not-an-address',
                $aliases,
            );
        } catch (ValidationException $exception) {
            $rejected = $exception->messageKey();
        }

        sinkholeTestAssertSame(
            'exempt_destination_value_invalid',
            $rejected,
            'A submitted invalid exempt destination must be refused.',
        );
        sinkholeTestAssertSame(
            [
                'exempt_sources' => ['10.0.0.5', 'IP4_CENTRALSTATION'],
                'exempt_destinations' => ['9.9.9.9'],
            ],
            BypassConfiguration::normalizeExemptionSubmission(
                "10.0.0.5\r\n\r\nIP4_CENTRALSTATION",
                '9.9.9.9',
                $aliases,
            ),
            'A valid submission must skip blank lines and keep order.',
        );
    },
    'Bypass block exemptions save round trip subtract tables and fail closed' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubLogs;
        global $sinkholeStubRealInterfaces;

        $root = sinkholeTestTemporaryDirectory();
        $identifier = str_repeat('f', 32);
        $list = [
            'id' => $identifier,
            'descr' => 'Invented exemption provider list',
            'url' => 'https://example.test/exemption-provider.txt',
            'kind' => BypassConfiguration::KIND_ENCRYPTED_DNS,
            'enabled' => 'on',
        ];
        $redirect = [
            'enabled' => false,
            'interfaces' => ['lan'],
            'exempt_sources' => [],
            'exempt_destinations' => [],
        ];

        try {
            $paths = sinkholeBypassTestPaths($root);
            sinkholeStubReset([
                'aliases' => [
                    'alias' => [
                        [
                            'name' => 'IP4_CENTRALSTATION',
                            'type' => 'host',
                            'address' => '192.0.2.40',
                        ],
                    ],
                ],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
            $sinkholeStubRealInterfaces = ['lan' => 'igc0'];
            mkdir($paths->bypassListDirectory, 0700, true);
            file_put_contents(
                $paths->bypassListFile($identifier),
                "I\t198.51.100.0/24\n",
            );
            file_put_contents(
                $paths->bypassMetadataFile($identifier),
                json_encode(['url' => $list['url']]) . PHP_EOL,
            );
            $adapter = new PfSenseAdapter(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
            );

            $storage = pfsensePackageSinkholeBypassStorage(
                BypassConfiguration::partition([], ['lan']),
                [$identifier => BypassConfiguration::normalizeListRow(
                    $identifier,
                    $list['descr'],
                    $list['url'],
                    true,
                    BypassConfiguration::KIND_ENCRYPTED_DNS,
                )],
                [],
                [
                    'block_tls_quic' => true,
                    'block_encrypted_dns' => true,
                    'exempt_sources' => ['IP4_CENTRALSTATION', '10.0.0.5'],
                    'exempt_destinations' => ['198.51.100.7'],
                ],
            );
            $adapter->saveBypassConfiguration($storage, $redirect);

            $stored = $adapter->getBypassConfiguration();
            sinkholeTestAssertSame(
                ['IP4_CENTRALSTATION', '10.0.0.5'],
                $stored['exempt_sources'],
                'Exempt sources must survive the XML round trip.',
            );
            sinkholeTestAssertSame(
                ['198.51.100.7'],
                $stored['exempt_destinations'],
                'A single exempt destination must survive the XML round trip.',
            );

            $ipv4Table = (string) file_get_contents($paths->bypassTableIpv4File);
            sinkholeTestAssertSame(
                false,
                str_contains($ipv4Table, '198.51.100.0/24') || str_contains($ipv4Table, '198.51.100.7/32'),
                'A literal exempt destination must be subtracted from the provider table.',
            );
            sinkholeTestAssertContains('198.51.100.6/32', $ipv4Table, 'The rest of the provider network must stay blocked.');
            sinkholeTestAssertContains('198.51.100.128/25', $ipv4Table, 'The rest of the provider network must stay blocked.');

            $anchorText = (string) file_get_contents($paths->bypassAnchorFile);
            sinkholeTestAssertContains(
                'anchor "providers_inet" in inet from ! <sinkhole_bypass_exempt_src> to <sinkhole_bypass_v4> {',
                $anchorText,
                'The loaded anchor must apply the saved exemptions.',
            );
            sinkholeTestAssertSame(
                2,
                $adapter->bypassAnchorStatus()['rule_count'],
                'Status must count nested block rules.',
            );

            $refused = '';

            try {
                $adapter->saveBypassConfiguration(
                    array_replace($storage, [
                        'exempt_sources' => ['item' => ['Missing_Alias']],
                    ]),
                    $redirect,
                );
            } catch (ValidationException $exception) {
                $refused = $exception->messageKey();
            }

            sinkholeTestAssertSame(
                'exempt_source_value_invalid',
                $refused,
                'Saving an unknown alias must be refused.',
            );

            config_set_path('aliases', []);
            $paused = $adapter->getBypassConfiguration();
            sinkholeTestAssertSame([], $paused['invalid_values'], 'A removed alias must not pause the blocks.');
            sinkholeTestAssertSame(1, count($paused['invalid_exemptions']), 'A removed alias must need repair.');
            sinkholeTestAssertSame(
                false,
                str_contains($adapter->bypassAnchorText(), 'anchor '),
                'A removed alias must render the flat blocks with no exemption.',
            );

            $sinkholeStubLogs = [];
            $adapter->applyBypassAnchor();
            $adapter->applyBypassAnchor();
            $ignoredLogs = array_values(array_filter(
                $sinkholeStubLogs,
                static fn (string $log): bool => str_contains($log, 'saved block exemption is invalid'),
            ));
            sinkholeTestAssertSame(1, count($ignoredLogs), 'Ignored exemptions must be logged once.');
            sinkholeTestAssertSame(
                false,
                str_contains((string) file_get_contents($paths->bypassAnchorFile), 'anchor '),
                'The loaded anchor must keep every block without exemptions.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'Bypass pages classes privileges and translations are packaged' => static function (): void {
        $workspace = dirname(__DIR__);
        $plist = (string) file_get_contents($workspace . '/port/pkg-plist');
        $makefile = (string) file_get_contents($workspace . '/port/Makefile.template');
        $privileges = (string) file_get_contents(
            $workspace . '/port/files/usr/local/pkg/priv/sinkhole.priv.inc',
        );
        $catalogs = require($workspace . '/port/files/usr/local/pkg/sinkhole/Translations.php');

        foreach ([
            'pkg/sinkhole/BypassConfiguration.php',
            'pkg/sinkhole/BypassListStore.php',
            'pkg/sinkhole/BypassParser.php',
            'pkg/sinkhole/BypassRuleConfiguration.php',
            'pkg/sinkhole/BypassUpdater.php',
            'pkg/sinkhole/UnboundCustomOptions.php',
            'www/sinkhole-bypass.php',
            'www/sinkhole-bypass_edit.php',
        ] as $path) {
            sinkholeTestAssertContains($path, $plist, 'The package manifest must install ' . $path);
        }

        sinkholeTestAssertSame(false, str_contains($plist, 'sinkhole-redirect.php'), 'The old Redirect page must not be installed.');
        sinkholeTestAssertContains('/www/sinkhole-bypass.php', $makefile, 'The Bypass page must be staged.');
        sinkholeTestAssertContains('page-firewall-sinkhole-bypass-edit', $privileges, 'The editor needs its own privilege.');

        foreach ([
            'bypass',
            'bypass_interfaces_help',
            'bypass_discovery_help',
            'bypass_discovery_tls_required',
            'bypass_warning',
            'discovery_zone',
            'missing',
            'present',
            'revision_saved_bypass',
        ] as $key) {
            sinkholeTestAssertTrue(isset($catalogs['en_US'][$key]), 'The English Bypass catalog key must exist: ' . $key);
        }

        sinkholeTestAssertContains(
            '%1$s',
            $catalogs['en_US']['bypass_discovery_help'],
            'Discovery help must retain the live DNS Resolver SSL/TLS service state.',
        );
        sinkholeTestAssertContains(
            "certificate also lists the firewall's address",
            $catalogs['en_US']['bypass_discovery_help'],
            'Discovery help must explain verified discovery certificate addressing.',
        );
        sinkholeTestAssertContains(
            'RFC 9462',
            $catalogs['en_US']['bypass_discovery_help'],
            'Discovery help must identify the verified discovery standard.',
        );
    },
]);
