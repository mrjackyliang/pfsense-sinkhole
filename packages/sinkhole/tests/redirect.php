<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\RedirectConfiguration;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\PfSenseAdapter;
use PfSense\Sinkhole\Runtime\StateStore;

set_include_path(__DIR__ . '/stubs' . PATH_SEPARATOR . get_include_path());

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/stubs/config.inc');
require_once(__DIR__ . '/stubs/services.inc');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole.inc');

/**
 * Sinkhole Redirect Test - Paths.
 *
 * Keeps lifecycle markers and lock files inside one disposable test directory.
 *
 * @param string $root - Test root.
 *
 * @return PackagePaths
 *
 * @since 1.0.0
 */
function sinkholeRedirectTestPaths(string $root): PackagePaths
{
    return new PackagePaths([
        'persistent_directory' => $root . '/persistent',
        'runtime_root_directory' => $root . '/runtime',
        'module_source_file' => $root . '/sinkhole_unbound.py',
        'update_lock_file' => $root . '/sinkhole-update.lock',
        'runtime_lock_file' => $root . '/sinkhole-runtime.lock',
        'client_lock_file' => $root . '/sinkhole-clients.lock',
        'alert_lock_file' => $root . '/sinkhole-alerts.lock',
        'redirect_check_lock_file' => $root . '/sinkhole-redirect-check.lock',
        'redirect_check_state_file' => $root . '/sinkhole-redirect-check.json',
        'redirect_rule_error_file' => $root . '/rules.packages.sinkhole',
        'alert_repeat_state_file' => $root . '/sinkhole-alerts.json',
        'status_file' => $root . '/sinkhole-status.json',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/**
 * Sinkhole Redirect Test - Invalid Message.
 *
 * Captures one expected validation exception so cases can assert its reason.
 *
 * @param callable(): void $operation - Invalid operation.
 *
 * @return string
 *
 * @since 1.0.0
 */
function sinkholeRedirectTestInvalidMessage(callable $operation): string
{
    try {
        $operation();
    } catch (InvalidArgumentException $exception) {
        return $exception->getMessage();
    }

    throw new RuntimeException('The redirect operation did not reject invalid input.');
}

sinkholeTestRun([
    'redirect settings validate interfaces sources and aliases' => static function (): void {
        $interfaces = [
            'lan' => 'LAN',
            'opt1' => 'Guests',
        ];
        $aliases = [
            'Trusted_Hosts' => 'host',
            'Trusted_Networks' => 'network',
        ];
        $defaults = RedirectConfiguration::partition([], $interfaces, $aliases);

        sinkholeTestAssertSame(false, $defaults['enabled'], 'DNS redirect must default off.');
        sinkholeTestAssertSame(
            [],
            $defaults['interfaces'],
            'DNS redirect must default to no interfaces.',
        );
        sinkholeTestAssertSame(
            [],
            $defaults['exempt_destinations'],
            'An upgrade without destination exemptions must default to an empty list.',
        );

        $normalized = RedirectConfiguration::normalizeSubmission(
            true,
            ['lan', 'opt1'],
            implode(PHP_EOL, [
                '192.0.2.10',
                '2001:db8::10',
                '198.51.100.0/24',
                '2001:db8:1::/64',
                'Trusted_Hosts',
                'Trusted_Networks',
            ]),
            $interfaces,
            $aliases,
            implode(PHP_EOL, [
                '203.0.113.53',
                '2001:db8:53::/64',
                'Trusted_Networks',
            ]),
        );

        sinkholeTestAssertSame(true, $normalized['enabled'], 'The redirect must be enabled.');
        sinkholeTestAssertSame(
            ['lan', 'opt1'],
            $normalized['interfaces'],
            'Configured interfaces must preserve selection order.',
        );
        sinkholeTestAssertSame(
            [
                '192.0.2.10',
                '2001:db8::10',
                '198.51.100.0/24',
                '2001:db8:1::/64',
                'Trusted_Hosts',
                'Trusted_Networks',
            ],
            $normalized['exempt_sources'],
            'Addresses, networks, and existing aliases must normalize.',
        );
        sinkholeTestAssertSame(
            [
                '203.0.113.53',
                '2001:db8:53::/64',
                'Trusted_Networks',
            ],
            $normalized['exempt_destinations'],
            'Destination addresses, networks, and aliases must normalize.',
        );

        $missingDestinationAliasMessage = sinkholeRedirectTestInvalidMessage(
            static function () use ($interfaces, $aliases): void {
                RedirectConfiguration::normalizeSubmission(
                    true,
                    ['lan'],
                    '',
                    $interfaces,
                    $aliases,
                    'Missing_Destination',
                );
            },
        );
        sinkholeTestAssertContains(
            'existing host/network alias',
            $missingDestinationAliasMessage,
            'An exempt destination alias must exist before it can become rule text.',
        );

        $missingAliasMessage = sinkholeRedirectTestInvalidMessage(
            static function () use ($interfaces, $aliases): void {
                RedirectConfiguration::normalizeSubmission(
                    true,
                    ['lan'],
                    'Missing_Alias',
                    $interfaces,
                    $aliases,
                );
            },
        );
        sinkholeTestAssertContains(
            'existing host/network alias',
            $missingAliasMessage,
            'An alias must exist before it can become rule text.',
        );

        $unsupportedAliasMessage = sinkholeRedirectTestInvalidMessage(
            static function () use ($interfaces, $aliases): void {
                RedirectConfiguration::normalizeSubmission(
                    true,
                    ['lan'],
                    'Web_Ports',
                    $interfaces,
                    $aliases + ['Web_Ports' => 'port'],
                );
            },
        );
        sinkholeTestAssertContains(
            'existing host/network alias',
            $unsupportedAliasMessage,
            'A non-address alias must not become rule text.',
        );

        $nonAsciiMessage = sinkholeRedirectTestInvalidMessage(
            static function () use ($interfaces, $aliases): void {
                RedirectConfiguration::normalizeSubmission(
                    true,
                    ['lan'],
                    'café',
                    $interfaces,
                    $aliases,
                );
            },
        );
        sinkholeTestAssertContains(
            'ASCII',
            $nonAsciiMessage,
            'Exempt sources must remain ASCII-only.',
        );

        $missingInterfaceMessage = sinkholeRedirectTestInvalidMessage(
            static function () use ($interfaces, $aliases): void {
                RedirectConfiguration::normalizeSubmission(
                    true,
                    ['missing'],
                    '',
                    $interfaces,
                    $aliases,
                );
            },
        );
        sinkholeTestAssertContains(
            'not configured',
            $missingInterfaceMessage,
            'Unknown interfaces must be rejected.',
        );

        $noInterfaceMessage = sinkholeRedirectTestInvalidMessage(
            static function () use ($interfaces, $aliases): void {
                RedirectConfiguration::normalizeSubmission(
                    true,
                    [],
                    '',
                    $interfaces,
                    $aliases,
                );
            },
        );
        sinkholeTestAssertContains(
            'Choose at least one',
            $noInterfaceMessage,
            'An enabled redirect must select an interface.',
        );

        $partition = RedirectConfiguration::partition([
            'enabled' => 'on',
            'interfaces' => ['item' => ['lan', 'missing']],
            'exempt_sources' => ['item' => ['192.0.2.10', 'Missing_Alias']],
        ], $interfaces, $aliases);
        sinkholeTestAssertSame(
            ['lan'],
            $partition['interfaces'],
            'Valid saved values must remain available beside repair values.',
        );
        sinkholeTestAssertSame(
            ['lan', 'missing'],
            $partition['stored_interfaces'],
            'Invalid saved interfaces must remain available for repair.',
        );
        sinkholeTestAssertSame(
            2,
            count($partition['invalid_values']),
            'Every invalid saved interface and exempt source needs a clear reason.',
        );
    },
    'redirect storage round trip uses item values and reloads the filter' => static function (): void {
        global $sinkholeStubFilterConfigureCount;
        global $sinkholeStubInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'aliases' => [
                    'alias' => [
                        [
                            'name' => 'Trusted_Hosts',
                            'type' => 'host',
                            'address' => '192.0.2.20',
                        ],
                    ],
                ],
                'installedpackages' => [
                    'sinkhole' => [],
                ],
            ]);
            $sinkholeStubInterfaces = [
                'lan' => 'LAN',
                'opt1' => 'Guests',
            ];
            $paths = sinkholeRedirectTestPaths($directory);
            $adapter = new PfSenseAdapter($paths, new StateStore($paths->stateFile));

            pfsensePackageSinkholeAdapter($adapter);
            pfsensePackageSinkholeSaveRedirect([
                'enabled' => true,
                'interfaces' => ['lan', 'opt1'],
                'exempt_sources' => ['192.0.2.10', 'Trusted_Hosts'],
                'exempt_destinations' => ['203.0.113.53', 'Trusted_Hosts'],
            ]);

            sinkholeTestAssertSame(
                ['lan', 'opt1'],
                config_get_path('installedpackages/sinkhole/redirect/interfaces/item'),
                'Interfaces must survive the pfSense-equivalent XML round trip under item.',
            );
            sinkholeTestAssertSame(
                ['192.0.2.10', 'Trusted_Hosts'],
                config_get_path('installedpackages/sinkhole/redirect/exempt_sources/item'),
                'Exempt sources must survive the XML round trip under item.',
            );
            sinkholeTestAssertSame(
                ['203.0.113.53', 'Trusted_Hosts'],
                config_get_path('installedpackages/sinkhole/redirect/exempt_destinations/item'),
                'Exempt destinations must survive the XML round trip under item.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubFilterConfigureCount,
                'A redirect save must request one asynchronous filter reload.',
            );

            $stored = pfsensePackageSinkholeGetRedirectConfiguration();
            sinkholeTestAssertSame(true, $stored['enabled'], 'The stored enable flag must round trip.');
            sinkholeTestAssertSame(
                ['lan', 'opt1'],
                $stored['interfaces'],
                'The selected interfaces must round trip.',
            );
            sinkholeTestAssertSame(
                ['192.0.2.10', 'Trusted_Hosts'],
                $stored['exempt_sources'],
                'The exempt sources must round trip.',
            );
            sinkholeTestAssertSame(
                ['203.0.113.53', 'Trusted_Hosts'],
                $stored['exempt_destinations'],
                'The exempt destinations must round trip.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'redirect check cron follows package and redirect enablement' => static function (): void {
        global $sinkholeStubCronOperations;
        global $sinkholeStubInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'redirect' => [
                            'enabled' => 'on',
                            'interfaces' => ['item' => ['lan']],
                            'exempt_sources' => ['item' => []],
                        ],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $paths = sinkholeRedirectTestPaths($directory);

            pfsensePackageSinkholeAdapter(new PfSenseAdapter($paths));
            pfsensePackageSinkholeInstallCron();

            sinkholeTestAssertSame(
                [
                    PackagePaths::COMMAND . ' --redirect-check',
                    true,
                    '*',
                    '*',
                    '*',
                    '*',
                    '*',
                    'root',
                ],
                $sinkholeStubCronOperations[3],
                'An enabled redirect must install the root one-minute check.',
            );

            $scheduledCommands = [
                PackagePaths::COMMAND . ' --update',
                PackagePaths::COMMAND . ' --refresh-clients',
                PackagePaths::COMMAND . ' --alerts',
            ];
            $redirectCommand = PackagePaths::COMMAND . ' --redirect-check';

            foreach ($scheduledCommands as $scheduledCommand) {
                sinkholeTestAssertSame(
                    false,
                    str_contains($redirectCommand, $scheduledCommand)
                        || str_contains($scheduledCommand, $redirectCommand),
                    'The redirect-check command must not contain another fixed command.',
                );
            }

            file_put_contents($paths->redirectCheckStateFile, "fixture\n");
            file_put_contents($paths->redirectCheckLockFile, "fixture\n");
            config_set_path('installedpackages/sinkhole/redirect/enabled', '');

            pfsensePackageSinkholeInstallCron();

            sinkholeTestAssertSame(
                false,
                $sinkholeStubCronOperations[7][1],
                'Turning off the redirect must remove its minute check.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->redirectCheckStateFile),
                'Removing the check must delete its previous observation.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->redirectCheckLockFile),
                'Removing the check must delete its reusable lock.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'redirect rules use validated listener targets and ordered exemptions' => static function (): void {
        $ipv4Rules = RedirectConfiguration::ruleText([
            [
                'interface' => 'lan',
                'ipv4_interface' => 'em0',
                'ipv4_target' => '127.0.0.1',
                'ipv6_interface' => '',
                'ipv6_target' => '',
            ],
        ], [], []);
        sinkholeTestAssertSame(
            '# Sinkhole DNS redirect' . PHP_EOL
                . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 127.0.0.1 port 53' . PHP_EOL,
            $ipv4Rules,
            'An IPv4-only interface must receive only the inet redirect.',
        );

        $ipv6Rules = RedirectConfiguration::ruleText([
            [
                'interface' => 'lan',
                'ipv4_interface' => '',
                'ipv4_target' => '',
                'ipv6_interface' => 'em0',
                'ipv6_target' => '2001:db8::1',
            ],
        ], [], []);
        sinkholeTestAssertSame(
            '# Sinkhole DNS redirect' . PHP_EOL
                . 'rdr pass on em0 inet6 proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 2001:db8::1 port 53' . PHP_EOL,
            $ipv6Rules,
            'An IPv6 redirect must target the selected interface address.',
        );

        $bothRules = RedirectConfiguration::ruleText([
            [
                'interface' => 'lan',
                'ipv4_interface' => 'em0',
                'ipv4_target' => '192.0.2.1',
                'ipv6_interface' => 'em0',
                'ipv6_target' => '2001:db8::1',
            ],
        ], [
            '192.0.2.10',
            '2001:db8::/64',
            'Trusted_Hosts',
        ], [
            'Trusted_Hosts' => 'host',
            'Trusted_Dns' => 'host',
        ], [
            '203.0.113.53',
            'Trusted_Dns',
        ]);
        sinkholeTestAssertSame(
            '# Sinkhole DNS redirect' . PHP_EOL
                . 'no rdr on em0 inet proto { tcp udp } from { 192.0.2.10 '
                . '$Trusted_Hosts } to any port 53' . PHP_EOL
                . 'no rdr on em0 inet6 proto { tcp udp } from { 2001:db8::/64 '
                . '$Trusted_Hosts } to any port 53' . PHP_EOL
                . 'no rdr on em0 inet proto { tcp udp } from any to { 203.0.113.53 '
                . '$Trusted_Dns } port 53' . PHP_EOL
                . 'no rdr on em0 inet6 proto { tcp udp } from any to { '
                . '$Trusted_Dns } port 53' . PHP_EOL
                . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 192.0.2.1 port 53' . PHP_EOL
                . 'rdr pass on em0 inet6 proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 2001:db8::1 port 53' . PHP_EOL,
            $bothRules,
            'Source and destination exemptions must precede both family redirects.',
        );
        sinkholeTestAssertTrue(
            strpos($bothRules, 'no rdr on em0 inet proto { tcp udp } from {')
                < strpos($bothRules, 'no rdr on em0 inet proto { tcp udp } from any to {'),
            'The source exemption must remain before the destination exemption.',
        );
        sinkholeTestAssertTrue(
            strpos($bothRules, 'no rdr on em0 inet proto { tcp udp } from any to {')
                < strpos($bothRules, 'rdr pass on em0 inet proto'),
            'Both no-rdr exemptions must remain before redirect rules.',
        );
        sinkholeTestAssertSame(
            false,
            str_contains($bothRules . $ipv6Rules, '-> ::1 port'),
            'IPv6 loopback must never appear in redirect rule text.',
        );

        $ipv4OnlyExemptions = RedirectConfiguration::ruleText([
            [
                'interface' => 'lan',
                'ipv4_interface' => 'em0',
                'ipv4_target' => '192.0.2.1',
                'ipv6_interface' => 'em0',
                'ipv6_target' => '2001:db8::1',
            ],
        ], ['192.0.2.10'], [], ['203.0.113.53']);
        sinkholeTestAssertSame(
            '# Sinkhole DNS redirect' . PHP_EOL
                . 'no rdr on em0 inet proto { tcp udp } from { 192.0.2.10 } '
                . 'to any port 53' . PHP_EOL
                . 'no rdr on em0 inet proto { tcp udp } from any to { 203.0.113.53 } '
                . 'port 53' . PHP_EOL
                . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 192.0.2.1 port 53' . PHP_EOL
                . 'rdr pass on em0 inet6 proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 2001:db8::1 port 53' . PHP_EOL,
            $ipv4OnlyExemptions,
            'IPv4-only exemptions must emit exact inet lines and no inet6 exemption.',
        );

        $ipv6OnlyExemptions = RedirectConfiguration::ruleText([
            [
                'interface' => 'lan',
                'ipv4_interface' => 'em0',
                'ipv4_target' => '192.0.2.1',
                'ipv6_interface' => 'em0',
                'ipv6_target' => '2001:db8::1',
            ],
        ], ['2001:db8::10'], [], ['2001:db8:53::/64']);
        sinkholeTestAssertSame(
            '# Sinkhole DNS redirect' . PHP_EOL
                . 'no rdr on em0 inet6 proto { tcp udp } from { 2001:db8::10 } '
                . 'to any port 53' . PHP_EOL
                . 'no rdr on em0 inet6 proto { tcp udp } from any to { '
                . '2001:db8:53::/64 } port 53' . PHP_EOL
                . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 192.0.2.1 port 53' . PHP_EOL
                . 'rdr pass on em0 inet6 proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 2001:db8::1 port 53' . PHP_EOL,
            $ipv6OnlyExemptions,
            'IPv6-only exemptions must emit exact inet6 lines and no inet exemption.',
        );

        $aliasOnlyExemptions = RedirectConfiguration::ruleText([
            [
                'interface' => 'lan',
                'ipv4_interface' => 'em0',
                'ipv4_target' => '192.0.2.1',
                'ipv6_interface' => 'em0',
                'ipv6_target' => '2001:db8::1',
            ],
        ], ['Trusted_Hosts'], ['Trusted_Hosts' => 'host']);
        sinkholeTestAssertSame(
            '# Sinkhole DNS redirect' . PHP_EOL
                . 'no rdr on em0 inet proto { tcp udp } from { $Trusted_Hosts } '
                . 'to any port 53' . PHP_EOL
                . 'no rdr on em0 inet6 proto { tcp udp } from { $Trusted_Hosts } '
                . 'to any port 53' . PHP_EOL
                . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 192.0.2.1 port 53' . PHP_EOL
                . 'rdr pass on em0 inet6 proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 2001:db8::1 port 53' . PHP_EOL,
            $aliasOnlyExemptions,
            'An alias-only source list must emit exact lines for both families.',
        );

        $singleFamilyExemptions = RedirectConfiguration::ruleText([
            [
                'interface' => 'lan',
                'ipv4_interface' => 'em0',
                'ipv4_target' => '192.0.2.1',
                'ipv6_interface' => '',
                'ipv6_target' => '',
            ],
        ], ['192.0.2.10', '2001:db8::10', 'Trusted_Hosts'], [
            'Trusted_Hosts' => 'host',
        ]);
        sinkholeTestAssertSame(
            '# Sinkhole DNS redirect' . PHP_EOL
                . 'no rdr on em0 inet proto { tcp udp } from { 192.0.2.10 '
                . '$Trusted_Hosts } to any port 53' . PHP_EOL
                . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 192.0.2.1 port 53' . PHP_EOL,
            $singleFamilyExemptions,
            'A one-family interface must emit exact exemptions for only that family.',
        );
        sinkholeTestAssertSame(
            '',
            RedirectConfiguration::ruleText([
                [
                    'interface' => 'lan',
                    'ipv4_interface' => '',
                    'ipv4_target' => '',
                    'ipv6_interface' => '',
                    'ipv6_target' => '',
                ],
            ], [], []),
            'An interface without either address family must emit no rule block.',
        );
        sinkholeTestAssertSame(
            '',
            RedirectConfiguration::ruleText([
                [
                    'interface' => 'lan',
                    'ipv4_interface' => 'em0; pass all',
                    'ipv4_target' => '127.0.0.1',
                    'ipv6_interface' => '',
                    'ipv6_target' => '',
                ],
            ], [], []),
            'An unsafe real-interface token must never reach rule text.',
        );
        sinkholeTestAssertSame(
            '',
            RedirectConfiguration::ruleText([
                [
                    'interface' => 'lan',
                    'ipv4_interface' => '',
                    'ipv4_target' => '',
                    'ipv6_interface' => 'em0',
                    'ipv6_target' => '::1',
                ],
            ], [], []),
            'An IPv6 loopback target must be rejected even if supplied directly.',
        );
    },
    'resolver listeners choose family-specific redirect targets' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => [
                    'enable' => '',
                ],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = [
                'lan' => [
                    'ipv4' => '192.0.2.1',
                    'ipv6' => '2001:db8::1',
                ],
            ];
            $sinkholeStubRealInterfaces = ['lan' => 'em0'];
            $adapter = new PfSenseAdapter(sinkholeRedirectTestPaths($directory));

            $automatic = $adapter->getRedirectInterfaceDetails(['lan'])[0];
            sinkholeTestAssertSame(
                '127.0.0.1',
                $automatic['ipv4_target'],
                'All interfaces must use IPv4 loopback while Unbound listens there.',
            );
            sinkholeTestAssertSame(
                '2001:db8::1',
                $automatic['ipv6_target'],
                'All interfaces must use the selected interface IPv6 address.',
            );
            sinkholeTestAssertSame(
                '# Sinkhole DNS redirect' . PHP_EOL
                    . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                    . '-> 127.0.0.1 port 53' . PHP_EOL
                    . 'rdr pass on em0 inet6 proto { tcp udp } from any to ! (em0) port 53 '
                    . '-> 2001:db8::1 port 53' . PHP_EOL,
                RedirectConfiguration::ruleText([$automatic], [], []),
                'All listeners must emit exact IPv4-loopback and interface-IPv6 rules.',
            );

            config_set_path('unbound/active_interface', 'lo0');
            $localhostOnly = $adapter->getRedirectInterfaceDetails(['lan'])[0];
            sinkholeTestAssertSame(
                '127.0.0.1',
                $localhostOnly['ipv4_target'],
                'An explicit localhost listener must keep the IPv4 loopback target.',
            );
            sinkholeTestAssertSame(
                '',
                $localhostOnly['ipv6_target'],
                'A localhost-only Resolver must not produce an IPv6 interface rule.',
            );
            sinkholeTestAssertSame(
                '# Sinkhole DNS redirect' . PHP_EOL
                    . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                    . '-> 127.0.0.1 port 53' . PHP_EOL,
                RedirectConfiguration::ruleText([$localhostOnly], [], []),
                'A localhost-only listener must emit only the IPv4 loopback rule.',
            );

            config_set_path('unbound/active_interface', 'lan');
            $interfaceOnly = $adapter->getRedirectInterfaceDetails(['lan'])[0];
            sinkholeTestAssertSame(
                '192.0.2.1',
                $interfaceOnly['ipv4_target'],
                'An interface-only Resolver must use that interface IPv4 address.',
            );
            sinkholeTestAssertSame(
                '2001:db8::1',
                $interfaceOnly['ipv6_target'],
                'An interface-only Resolver must use that interface IPv6 address.',
            );
            sinkholeTestAssertSame(
                '# Sinkhole DNS redirect' . PHP_EOL
                    . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                    . '-> 192.0.2.1 port 53' . PHP_EOL
                    . 'rdr pass on em0 inet6 proto { tcp udp } from any to ! (em0) port 53 '
                    . '-> 2001:db8::1 port 53' . PHP_EOL,
                RedirectConfiguration::ruleText([$interfaceOnly], [], []),
                'An interface-only listener must emit exact interface-address rules.',
            );

            config_set_path('unbound/active_interface', '192.0.2.1');
            $addressOnly = $adapter->getRedirectInterfaceDetails(['lan'])[0];
            sinkholeTestAssertSame(
                '192.0.2.1',
                $addressOnly['ipv4_target'],
                'A literal listener must match the interface address.',
            );
            sinkholeTestAssertSame(
                '',
                $addressOnly['ipv6_target'],
                'A family without a matching literal listener must have no rule.',
            );
            sinkholeTestAssertSame(
                '# Sinkhole DNS redirect' . PHP_EOL
                    . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                    . '-> 192.0.2.1 port 53' . PHP_EOL,
                RedirectConfiguration::ruleText([$addressOnly], [], []),
                'A literal IPv4 listener must emit no IPv6 rule.',
            );

            config_set_path('unbound/active_interface', 'lan');
            unset($sinkholeStubInterfaceAddresses['lan']['ipv6']);
            $missingAddress = $adapter->getRedirectInterfaceDetails(['lan'])[0];
            sinkholeTestAssertSame(
                'no_address',
                $missingAddress['ipv6_reason'],
                'A missing family address must be reported separately.',
            );

            config_set_path('unbound/active_interface', 'opt1');
            $notListening = $adapter->getRedirectInterfaceDetails(['lan'])[0];
            sinkholeTestAssertSame(
                'resolver_not_listening',
                $notListening['ipv4_reason'],
                'A family without a Resolver listener must report that reason.',
            );
            sinkholeTestAssertSame(
                '',
                RedirectConfiguration::ruleText([$notListening], [], []),
                'An interface whose available families have no listeners must emit no rules.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'rule hook returns only active enabled NAT rules' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubParseConfigCount;
        global $sinkholeStubRealInterfaces;
        global $sinkholeStubRunningProcesses;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $configuration = [
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [
                            [
                                'enabled' => 'on',
                                'update_frequency' => 'daily',
                                'keep_settings' => 'on',
                            ],
                        ],
                        'redirect' => [
                            'enabled' => 'on',
                            'interfaces' => ['item' => ['lan']],
                            'exempt_sources' => ['item' => []],
                        ],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => 'pre_validator',
                    'python_script' => 'sinkhole',
                ],
                'system' => [
                    'unsaved_value' => 'disk',
                ],
            ];

            sinkholeStubReset($configuration);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = [
                'lan' => [
                    'ipv4' => '192.0.2.1',
                    'ipv4_prefix' => 24,
                ],
            ];
            $sinkholeStubRealInterfaces = ['lan' => 'em0'];
            $paths = sinkholeRedirectTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);

            pfsensePackageSinkholeAdapter($adapter);
            config_set_path('system/unsaved_value', 'memory');
            file_put_contents($paths->redirectRuleErrorFile, "leftover\n");

            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('filter'),
                'The package hook must return nothing for filter rules.',
            );
            sinkholeTestAssertTrue(
                is_file($paths->redirectRuleErrorFile),
                'A filter discovery call must leave the package error file alone.',
            );
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('pfearly'),
                'The package hook must return nothing for early rules.',
            );
            sinkholeTestAssertTrue(
                is_file($paths->redirectRuleErrorFile),
                'An early discovery call must leave the package error file alone.',
            );
            $expectedNatRules = $adapter->redirectRuleText();
            sinkholeTestAssertSame(
                $expectedNatRules,
                pfsensePackageSinkholeFilterRules('nat'),
                'The NAT hook text must remain exactly the redirect rule text.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->redirectRuleErrorFile),
                'The NAT discovery call must delete a leftover package error file.',
            );

            $symlinkTarget = $directory . '/symlink-target';
            file_put_contents($symlinkTarget, "keep\n");

            if (symlink($symlinkTarget, $paths->redirectRuleErrorFile) === false) {
                throw new RuntimeException('Unable to create the package error symlink fixture.');
            }

            pfsensePackageSinkholeFilterRules('nat');
            sinkholeTestAssertSame(
                false,
                is_link($paths->redirectRuleErrorFile),
                'The NAT discovery call must unlink a planted package error symlink.',
            );
            sinkholeTestAssertSame(
                "keep\n",
                file_get_contents($symlinkTarget),
                'Deleting the package error symlink must not follow its target.',
            );
            sinkholeTestAssertSame(
                'memory',
                config_get_path('system/unsaved_value'),
                'The rule hook must preserve pfSense\'s unsaved configuration.',
            );
            sinkholeTestAssertSame(
                0,
                $sinkholeStubParseConfigCount,
                'The rule hook must never refresh pfSense configuration.',
            );

            $sinkholeStubRunningProcesses['unbound'] = false;
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('nat'),
                'A stopped Resolver must suppress every redirect rule.',
            );
            $sinkholeStubRunningProcesses['unbound'] = true;

            config_set_path('unbound/python_script', 'other');
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('nat'),
                'An inactive integration must return no redirect rules.',
            );

            config_set_path('unbound/python_script', 'sinkhole');
            $stateStore->markRemoving();
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('nat'),
                'Removal intent must suppress redirect rules.',
            );

            $stateStore->clearRemoving();
            config_set_path('installedpackages/sinkhole/config/0/enabled', '');
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('nat'),
                'A disabled package must return no redirect rules.',
            );

            config_set_path('installedpackages/sinkhole/config/0/enabled', 'on');
            config_set_path('installedpackages/sinkhole/redirect/enabled', '');
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('nat'),
                'A disabled redirect must return no rules.',
            );

            config_set_path('installedpackages/sinkhole/redirect/enabled', 'on');
            config_set_path(
                'installedpackages/sinkhole/redirect/interfaces/item',
                ['missing'],
            );
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('nat'),
                'A redirect without a valid configured interface must return no rules.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'redirect check reloads after two mismatches and not before' => static function (): void {
        global $sinkholeStubFilterConfigureCount;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubRealInterfaces;

        $directory = sinkholeTestTemporaryDirectory();
        $lockHandle = null;

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'redirect' => [
                            'enabled' => 'on',
                            'interfaces' => ['item' => ['lan']],
                            'exempt_sources' => ['item' => []],
                        ],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => 'pre_validator',
                    'python_script' => 'sinkhole',
                ],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = [
                'lan' => [
                    'ipv4' => '192.0.2.1',
                    'ipv4_prefix' => 24,
                ],
            ];
            $sinkholeStubRealInterfaces = ['lan' => 'em0'];
            $paths = sinkholeRedirectTestPaths($directory);
            $rulesPath = $directory . '/rules.debug';
            $errorPath = $directory . '/rules.packages.sinkhole';
            $adapter = new PfSenseAdapter($paths);

            sinkholeTestAssertSame(
                'mismatch',
                $adapter->reconcileRedirectRules($rulesPath, $errorPath),
                'The first mismatch must only be recorded.',
            );
            sinkholeTestAssertSame(
                0,
                $sinkholeStubFilterConfigureCount,
                'One mismatch must not reload the filter.',
            );
            sinkholeTestAssertTrue(
                is_file($paths->redirectCheckStateFile),
                'The first mismatch must leave one transient observation.',
            );
            sinkholeTestAssertSame(
                0600,
                fileperms($paths->redirectCheckStateFile) & 0777,
                'The previous observation must be root-private.',
            );

            sinkholeTestAssertSame(
                'reloaded',
                $adapter->reconcileRedirectRules($rulesPath, $errorPath),
                'The second consecutive mismatch must request a filter reload.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubFilterConfigureCount,
                'Two mismatches must request exactly one asynchronous reload.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->redirectCheckStateFile),
                'A reload request must begin a fresh two-check sequence.',
            );

            $currentRuleText = $adapter->redirectRuleText();
            file_put_contents($rulesPath, '# generated' . PHP_EOL . $currentRuleText);
            file_put_contents($errorPath, "leftover parse error\n");
            sinkholeTestAssertSame(
                'matching',
                $adapter->reconcileRedirectRules($rulesPath, $errorPath),
                'Loaded rules with a leftover error file must need no reload.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubFilterConfigureCount,
                'A matching check must not request another reload.',
            );

            $outdatedRuleText = str_replace(
                '-> 127.0.0.1 port 53',
                '-> 192.0.2.99 port 53',
                $currentRuleText,
            );
            file_put_contents($rulesPath, '# generated' . PHP_EOL . $outdatedRuleText);
            sinkholeTestAssertSame(
                'mismatch',
                $adapter->reconcileRedirectRules($rulesPath, $errorPath),
                'An outdated loaded block must begin a fresh two-check sequence.',
            );
            sinkholeTestAssertSame(
                'reloaded',
                $adapter->reconcileRedirectRules($rulesPath, $errorPath),
                'An outdated loaded block must reload after two checks.',
            );
            sinkholeTestAssertSame(
                2,
                $sinkholeStubFilterConfigureCount,
                'The outdated text must request exactly one additional reload.',
            );

            $windowsRuleText = str_replace("\n", "\r\n", $currentRuleText);
            file_put_contents($rulesPath, "# generated\r\n" . $windowsRuleText);
            sinkholeTestAssertSame(
                'matching',
                $adapter->reconcileRedirectRules($rulesPath, $errorPath),
                'Equivalent CRLF rule text must count as current.',
            );
            sinkholeTestAssertSame(
                2,
                $sinkholeStubFilterConfigureCount,
                'Matching normalized text must not request another reload.',
            );

            $lockHandle = fopen($paths->redirectCheckLockFile, 'c+');

            if ($lockHandle === false || flock($lockHandle, LOCK_EX | LOCK_NB) === false) {
                throw new RuntimeException('Unable to hold the redirect-check lock fixture.');
            }

            sinkholeTestAssertSame(
                'locked',
                $adapter->reconcileRedirectRules($rulesPath, $errorPath),
                'A concurrent check must skip its non-blocking lock.',
            );
        } finally {
            if (is_resource($lockHandle)) {
                flock($lockHandle, LOCK_UN);
                fclose($lockHandle);
            }

            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'invalid source or destination exemptions pause and log once per set' => static function (): void {
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubLogs;
        global $sinkholeStubRealInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'redirect' => [
                            'enabled' => 'on',
                            'interfaces' => ['item' => ['lan']],
                            'exempt_sources' => ['item' => ['Missing_Source']],
                            'exempt_destinations' => ['item' => []],
                        ],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => 'pre_validator',
                    'python_script' => 'sinkhole',
                ],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
            $sinkholeStubRealInterfaces = ['lan' => 'em0'];
            $paths = sinkholeRedirectTestPaths($directory);
            $adapter = new PfSenseAdapter($paths);
            pfsensePackageSinkholeAdapter($adapter);

            foreach (range(1, 3) as $_) {
                sinkholeTestAssertSame(
                    '',
                    pfsensePackageSinkholeFilterRules('nat'),
                    'An invalid source exemption must pause every hook call.',
                );
                $adapter->reconcileRedirectRules(
                    $directory . '/rules.debug',
                    $paths->redirectRuleErrorFile,
                );
            }

            sinkholeTestAssertSame(
                1,
                count(array_filter(
                    $sinkholeStubLogs,
                    static fn(string $message): bool => str_contains(
                        $message,
                        'DNS redirect is paused',
                    ),
                )),
                'One invalid exemption set must log its pause once across hooks and checks.',
            );
            sinkholeTestAssertSame(
                1,
                count($adapter->getRedirectConfiguration()['invalid_exemptions']),
                'The invalid source must remain visible to Status and Redirect pages.',
            );

            config_set_path(
                'installedpackages/sinkhole/redirect/exempt_sources/item',
                [],
            );
            config_set_path(
                'installedpackages/sinkhole/redirect/exempt_destinations/item',
                ['Missing_Destination'],
            );
            sinkholeTestAssertSame(
                '',
                pfsensePackageSinkholeFilterRules('nat'),
                'An invalid destination exemption must also pause the redirect.',
            );
            sinkholeTestAssertSame(
                2,
                count(array_filter(
                    $sinkholeStubLogs,
                    static fn(string $message): bool => str_contains(
                        $message,
                        'DNS redirect is paused',
                    ),
                )),
                'A distinct invalid exemption set must produce one new pause log.',
            );

            $statusPage = (string) file_get_contents(
                __DIR__ . '/../port/files/usr/local/www/sinkhole-status.php',
            );
            sinkholeTestAssertContains(
                "'paused'",
                $statusPage,
                'Status must label an invalid-exemption redirect as paused.',
            );
            sinkholeTestAssertContains(
                '$redirectInvalidExemptions',
                $statusPage,
                'Status must render invalid exemption values.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'redirect check suppresses repeated rejected text and skips package locks' => static function (): void {
        global $sinkholeStubDirtySubsystems;
        global $sinkholeStubFilterConfigureCount;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;
        global $sinkholeStubLogs;
        global $sinkholeStubRealInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'redirect' => [
                            'enabled' => 'on',
                            'interfaces' => ['item' => ['lan']],
                            'exempt_sources' => ['item' => []],
                            'exempt_destinations' => ['item' => []],
                        ],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => 'pre_validator',
                    'python_script' => 'sinkhole',
                ],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $sinkholeStubInterfaceAddresses = [
                'lan' => [
                    'ipv4' => '192.0.2.1',
                ],
            ];
            $sinkholeStubRealInterfaces = ['lan' => 'em0'];
            $paths = sinkholeRedirectTestPaths($directory);
            $adapter = new PfSenseAdapter($paths);
            $rulesPath = $directory . '/rules.debug';
            $ruleText = $adapter->redirectRuleText();

            file_put_contents(
                $paths->redirectRuleErrorFile,
                '#There was an error while parsing the package filter rules.'
                    . PHP_EOL
                    . PHP_EOL
                    . $ruleText
                    . PHP_EOL,
            );

            foreach (range(1, 3) as $checkNumber) {
                sinkholeTestAssertSame(
                    'rejected',
                    $adapter->reconcileRedirectRules(
                        $rulesPath,
                        $paths->redirectRuleErrorFile,
                    ),
                    'Unchanged rejected text must suppress check ' . $checkNumber . '.',
                );
            }

            sinkholeTestAssertSame(
                0,
                $sinkholeStubFilterConfigureCount,
                'The same rejected rule text must never request another reload.',
            );
            sinkholeTestAssertSame(
                1,
                count(array_filter(
                    $sinkholeStubLogs,
                    static fn(string $message): bool => str_contains(
                        $message,
                        'pfSense rejected the current Sinkhole package rules',
                    ),
                )),
                'The same rejected rule text must log only once.',
            );

            config_set_path(
                'installedpackages/sinkhole/redirect/exempt_destinations/item',
                ['203.0.113.53'],
            );
            sinkholeTestAssertSame(
                'mismatch',
                $adapter->reconcileRedirectRules(
                    $rulesPath,
                    $paths->redirectRuleErrorFile,
                ),
                'Changed rule text must begin a fresh two-check sequence.',
            );
            sinkholeTestAssertSame(
                'reloaded',
                $adapter->reconcileRedirectRules(
                    $rulesPath,
                    $paths->redirectRuleErrorFile,
                ),
                'Changed rule text must reload after its second mismatch.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubFilterConfigureCount,
                'Changed rejected text must request exactly one reload.',
            );

            file_put_contents($paths->redirectCheckStateFile, "fixture\n");
            $sinkholeStubDirtySubsystems['packagelock'] = true;
            sinkholeTestAssertSame(
                'package-locked',
                $adapter->reconcileRedirectRules(
                    $rulesPath,
                    $paths->redirectRuleErrorFile,
                ),
                'A dirty package lock must skip redirect reconciliation.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->redirectCheckStateFile),
                'A package-locked check must keep no observation.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubFilterConfigureCount,
                'A package-locked check must not request a filter reload.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'integration disable removal and upgrade reload filter without losing settings' => static function (): void {
        global $sinkholeStubFilterConfigureCount;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'redirect' => [
                            'enabled' => 'on',
                            'interfaces' => ['item' => ['lan']],
                            'exempt_sources' => ['item' => []],
                        ],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => 'pre_validator',
                    'python_script' => 'sinkhole',
                ],
            ]);
            $paths = sinkholeRedirectTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);

            pfsensePackageSinkholeAdapter($adapter);
            $adapter->disableDnsResolverIntegration();
            sinkholeTestAssertSame(
                1,
                $sinkholeStubFilterConfigureCount,
                'Disabling integration must request a filter reload.',
            );

            pfsensePackageSinkholeMarkRemoving();
            sinkholeTestAssertSame(
                2,
                $sinkholeStubFilterConfigureCount,
                'Recording removal intent must request a filter reload.',
            );

            $stateStore->clearRemoving();
            putenv('PKG_UPGRADE=1');

            try {
                pfsensePackageSinkholePackageDeinstall();
            } finally {
                putenv('PKG_UPGRADE');
            }

            sinkholeTestAssertSame(
                'on',
                config_get_path('installedpackages/sinkhole/redirect/enabled'),
                'An upgrade deinstall must preserve redirect settings.',
            );
            sinkholeTestAssertSame(
                3,
                $sinkholeStubFilterConfigureCount,
                'An upgrade removal marker must remove loaded redirect rules.',
            );

            putenv('PKG_UPGRADE');
            file_put_contents($paths->redirectRuleErrorFile, "leftover\n");
            pfsensePackageSinkholeRemove(0);
            sinkholeTestAssertSame(
                false,
                file_exists($paths->redirectRuleErrorFile),
                'Ordinary removal must delete the leftover package rule error file.',
            );
        } finally {
            putenv('PKG_UPGRADE');
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'redirect status detects loaded rules and package parse errors' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $rulesPath = $directory . '/rules.debug';
            $errorPath = $directory . '/rules.packages.sinkhole';
            $adapter = new PfSenseAdapter(sinkholeRedirectTestPaths($directory));
            $loadedRuleText = '# Sinkhole DNS redirect' . PHP_EOL
                . 'rdr pass on em0 inet proto { tcp udp } from any to ! (em0) port 53 '
                . '-> 127.0.0.1 port 53' . PHP_EOL;

            file_put_contents(
                $rulesPath,
                '# generated' . PHP_EOL . $loadedRuleText,
            );
            $loaded = $adapter->redirectRuleStatus(
                $rulesPath,
                $errorPath,
                $loadedRuleText,
            );
            sinkholeTestAssertSame(true, $loaded['loaded'], 'Exact current text must be loaded.');
            sinkholeTestAssertSame(
                false,
                $loaded['out_of_date'],
                'Exact current text must not be reported as out of date.',
            );
            sinkholeTestAssertSame('', $loaded['parse_error'], 'No error file means no parse error.');

            $outdated = $adapter->redirectRuleStatus(
                $rulesPath,
                $errorPath,
                str_replace('127.0.0.1', '192.0.2.1', $loadedRuleText),
            );
            sinkholeTestAssertSame(
                false,
                $outdated['loaded'],
                'A present block with different text must not count as loaded.',
            );
            sinkholeTestAssertSame(
                true,
                $outdated['out_of_date'],
                'Status must identify a present block with different text as out of date.',
            );

            $unwanted = $adapter->redirectRuleStatus(
                $rulesPath,
                $errorPath,
                '',
            );
            sinkholeTestAssertSame(
                true,
                $unwanted['loaded'],
                'When no rules are wanted, a present Sinkhole block must still count as loaded.',
            );
            sinkholeTestAssertSame(
                true,
                $unwanted['out_of_date'],
                'A present Sinkhole block must be out of date when the hook wants no rules.',
            );

            file_put_contents(
                $errorPath,
                '#There was an error while parsing the package filter rules for '
                    . '/usr/local/pkg/sinkhole.inc.' . PHP_EOL,
            );
            $failed = $adapter->redirectRuleStatus(
                $rulesPath,
                $errorPath,
                $loadedRuleText,
            );
            sinkholeTestAssertSame(
                true,
                $failed['loaded'],
                'A leftover package error file must not override the loaded comment.',
            );
            sinkholeTestAssertSame(
                '',
                $failed['parse_error'],
                'Status must hide a leftover parse error while rules are loaded.',
            );

            file_put_contents($rulesPath, "# generated\n");
            file_put_contents(
                $errorPath,
                '#There was an error while parsing the package filter rules for '
                    . '/usr/local/pkg/sinkhole.inc.' . PHP_EOL
                    . PHP_EOL
                    . '# Sinkhole DNS redirect' . PHP_EOL,
            );
            $rejected = $adapter->redirectRuleStatus(
                $rulesPath,
                $errorPath,
                $loadedRuleText,
            );
            sinkholeTestAssertSame(
                false,
                $rejected['loaded'],
                'A missing generated comment must report the rules as unloaded.',
            );
            sinkholeTestAssertContains(
                'There was an error while parsing',
                $rejected['parse_error'],
                'Status must expose the current parse error while the block is missing.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'bypass page hook privilege and port files are packaged' => static function (): void {
        $workspace = __DIR__ . '/..';
        $packageXml = (string) file_get_contents(
            $workspace . '/port/files/usr/local/pkg/sinkhole.xml',
        );
        $packageInclude = (string) file_get_contents(
            $workspace . '/port/files/usr/local/pkg/sinkhole.inc',
        );
        $privileges = (string) file_get_contents(
            $workspace . '/port/files/usr/local/pkg/priv/sinkhole.priv.inc',
        );
        $bypassPage = (string) file_get_contents(
            $workspace . '/port/files/usr/local/www/sinkhole-bypass.php',
        );
        $bypassEditorPage = (string) file_get_contents(
            $workspace . '/port/files/usr/local/www/sinkhole-bypass_edit.php',
        );
        $plist = (string) file_get_contents($workspace . '/port/pkg-plist');
        $makefile = (string) file_get_contents($workspace . '/port/Makefile.template');

        sinkholeTestAssertContains(
            '<filter_rules_needed>pfsensePackageSinkholeFilterRules</filter_rules_needed>',
            $packageXml,
            'The package XML must register the NAT rule hook.',
        );
        sinkholeTestAssertContains(
            '<text>Bypass</text>',
            $packageXml,
            'The package XML must include the Bypass tab.',
        );
        $alertsTabPosition = strpos($packageXml, '<text>Alerts</text>');
        $bypassTabPosition = strpos($packageXml, '<text>Bypass</text>');
        $statusTabPosition = strpos($packageXml, '<text>Status</text>');
        sinkholeTestAssertTrue(
            is_int($alertsTabPosition)
                && is_int($bypassTabPosition)
                && is_int($statusTabPosition)
                && $alertsTabPosition < $bypassTabPosition
                && $bypassTabPosition < $statusTabPosition,
            'The Bypass tab must remain between Alerts and Status.',
        );
        sinkholeTestAssertContains(
            "'bypass' => '/sinkhole-bypass.php'",
            $packageInclude,
            'Custom pages must share the Bypass tab.',
        );
        sinkholeTestAssertContains(
            'page-firewall-sinkhole-bypass',
            $privileges,
            'The installed privilege map must grant the Bypass page.',
        );
        sinkholeTestAssertContains(
            'page-firewall-sinkhole-bypass-edit',
            $privileges,
            'The installed privilege map must grant the Bypass editor page.',
        );
        sinkholeTestAssertContains(
            '##|*IDENT=page-firewall-sinkhole-bypass',
            $bypassPage,
            'The Bypass page must carry its build-time privilege header.',
        );
        sinkholeTestAssertContains(
            '##|*IDENT=page-firewall-sinkhole-bypass-edit',
            $bypassEditorPage,
            'The Bypass editor must carry its build-time privilege header.',
        );
        sinkholeTestAssertContains(
            "pfsensePackageSinkholeTabs('bypass')",
            $bypassPage,
            'The Bypass page must activate its shared package tab.',
        );
        sinkholeTestAssertContains(
            "pfsensePackageSinkholeTranslate('exempt_destinations')",
            $bypassPage,
            'The Bypass page must retain the destination exemption field.',
        );
        sinkholeTestAssertContains(
            'pkg/sinkhole/RedirectConfiguration.php',
            $plist,
            'The redirect validator must be present in pkg-plist.',
        );
        sinkholeTestAssertContains(
            'www/sinkhole-bypass.php',
            $plist,
            'The Bypass page must be present in pkg-plist.',
        );
        sinkholeTestAssertContains(
            'www/sinkhole-bypass_edit.php',
            $plist,
            'The Bypass editor must be present in pkg-plist.',
        );
        sinkholeTestAssertContains(
            '/pkg/sinkhole/RedirectConfiguration.php',
            $makefile,
            'The port must install the redirect validator.',
        );
        sinkholeTestAssertContains(
            '/www/sinkhole-bypass.php',
            $makefile,
            'The port must install the Bypass page.',
        );
        sinkholeTestAssertContains(
            '/www/sinkhole-bypass_edit.php',
            $makefile,
            'The port must install the Bypass editor.',
        );
    },
]);
