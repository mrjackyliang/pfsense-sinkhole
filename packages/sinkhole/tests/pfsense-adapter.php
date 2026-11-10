<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\UnboundCustomOptions;
use PfSense\Sinkhole\Runtime\ClientMap;
use PfSense\Sinkhole\Runtime\ClientSource;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\FileSystem;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\PfSenseAdapter;
use PfSense\Sinkhole\Runtime\SavedListStore;
use PfSense\Sinkhole\Runtime\StateStore;

set_include_path(__DIR__ . '/stubs' . PATH_SEPARATOR . get_include_path());

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/stubs/config.inc');
require_once(__DIR__ . '/stubs/services.inc');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole.inc');

/**
 * Sinkhole Adapter Test - Paths.
 *
 * @param string $root - Test root.
 *
 * @return PackagePaths
 *
 * @since 1.0.0
 */
function sinkholeAdapterTestPaths(string $root): PackagePaths
{
    $sourceDirectory = $root . '/source';

    if (mkdir($sourceDirectory, 0700, true) === false) {
        throw new RuntimeException('Unable to create the module source directory.');
    }

    file_put_contents($sourceDirectory . '/sinkhole_unbound.py', "# test module\n");

    return new PackagePaths([
        'persistent_directory' => $root . '/persistent',
        'runtime_root_directory' => $root . '/runtime',
        'module_source_file' => $sourceDirectory . '/sinkhole_unbound.py',
        'update_lock_file' => $root . '/sinkhole-update.lock',
        'runtime_lock_file' => $root . '/sinkhole-runtime.lock',
        'client_lock_file' => $root . '/sinkhole-clients.lock',
        'alert_lock_file' => $root . '/sinkhole-alerts.lock',
        'redirect_check_lock_file' => $root . '/sinkhole-redirect-check.lock',
        'redirect_check_state_file' => $root . '/sinkhole-redirect-check.json',
        'redirect_rule_error_file' => $root . '/rules.packages.sinkhole',
        'alert_repeat_state_file' => $root . '/sinkhole-alerts.json',
        'catalog_cache_directory' => $root . '/catalog-cache',
        'command' => '/usr/local/sbin/sinkhole',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/**
 * Sinkhole Adapter Test - Client Source.
 *
 * Supplies an empty deterministic client inventory when Sync must publish its first
 * map without invoking host-specific neighbor commands.
 *
 * @since 1.0.0
 */
final class SinkholeAdapterTestClientSource implements ClientSource
{
    /** {@inheritDoc} @since 1.0.0 */
    public function getNetworks(): array
    {
        return [];
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function getDevices(): array
    {
        return [];
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function getInterfaceSubnets(): array
    {
        return [];
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function getInterfaceAddresses(): array
    {
        return [];
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function getBypassInterfaces(): array
    {
        return [];
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function getStaticMappings(): array
    {
        return [];
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function getArpEntries(): array
    {
        return [];
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function getNdpOutput(): string
    {
        return '';
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function getDhcpLeases(): array
    {
        return [];
    }

    /** {@inheritDoc} @since 1.0.0 */
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

    /** {@inheritDoc} @since 1.0.0 */
    public function usesMemoryFileSystem(): bool
    {
        return false;
    }

    /** {@inheritDoc} @since 1.0.0 */
    public function log(string $message): void
    {
        unset($message);
    }
}

/**
 * Sinkhole Adapter Test - Adapter With Client Map.
 *
 * Wires the production client-map publisher to deterministic local fixtures for
 * synchronization-order tests.
 *
 * @param PackagePaths $paths - Package paths.
 * @param StateStore|null $stateStore - State store.
 *
 * @return PfSenseAdapter
 *
 * @since 1.0.0
 */
function sinkholeAdapterTestWithClientMap(
    PackagePaths $paths,
    ?StateStore $stateStore = null,
): PfSenseAdapter {
    $stateStore ??= new StateStore($paths->stateFile);
    $clientMap = new ClientMap(
        $paths,
        new SinkholeAdapterTestClientSource(),
        $stateStore,
    );

    return new PfSenseAdapter($paths, $stateStore, 60, $clientMap);
}

/**
 * Sinkhole Adapter Test - Assert Unsaved Configuration Preserved.
 *
 * Changes one value only in memory before a pfSense-owned operation and verifies
 * that no configuration refresh replaced it with the last written value.
 *
 * @param callable(): void $operation - pfSense-owned operation.
 * @param string $label - Operation label.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeAdapterTestAssertUnsavedConfigurationPreserved(
    callable $operation,
    string $label,
): void {
    global $sinkholeStubParseConfigCount;

    config_set_path('system/unsaved_value', 'memory');

    $operation();

    sinkholeTestAssertSame(
        'memory',
        config_get_path('system/unsaved_value'),
        $label . ' must preserve pfSense\'s unsaved configuration.',
    );
    sinkholeTestAssertSame(
        0,
        $sinkholeStubParseConfigCount,
        $label . ' must not refresh pfSense configuration.',
    );
}

/**
 * Sinkhole Adapter Test - Post Deinstall Pass.
 *
 * Models the configuration-only pass that pfSense runs after pkg has deleted the
 * package files. No Sinkhole hook runs in this pass.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeAdapterTestPostDeinstall(): void
{
    $packages = config_get_path('installedpackages/package', []);

    if (!is_array($packages)) {
        return;
    }

    foreach ($packages as $index => $package) {
        if (
            !is_array($package)
            || !in_array(
                (string) ($package['internal_name'] ?? $package['name'] ?? ''),
                ['Sinkhole', 'sinkhole'],
                true,
            )
        ) {
            continue;
        }

        config_del_path('installedpackages/package/' . $index);
        write_config('Removed Sinkhole package.');

        return;
    }
}

sinkholeTestRun([
    'General package editor localizes English, translated and fallback languages' => static function (): void {
        foreach (['en_US', 'fr_FR', 'xx_XX'] as $locale) {
            sinkholeStubReset([
                'system' => ['language' => $locale],
            ]);
            $package = [
                'title' => 'Firewall/Sinkhole',
                'aftersaveredirect' => '/original',
                'tabs' => [
                    'tab' => [
                        ['text' => 'General'],
                        ['text' => 'Status'],
                    ],
                ],
                'fields' => [
                    'field' => [
                        [
                            'name' => 'General',
                        ],
                        [
                            'fielddescr' => 'Update Frequency',
                            'description' => 'Choose how often enabled block lists update.',
                            'options' => [
                                'option' => [
                                    ['name' => 'Hourly', 'value' => 'hourly'],
                                ],
                            ],
                        ],
                    ],
                ],
            ];

            pfsensePackageSinkholeLocalizePackageGui($package);

            if ($locale === 'fr_FR') {
                sinkholeTestAssertSame(
                    true,
                    $package['tabs']['tab'][0]['text'] !== 'General',
                    'A translated language must not render the English tab text.',
                );
            }

            sinkholeTestAssertSame(
                'Firewall/Sinkhole',
                $package['title'],
                'The page title must keep pfSense and Sinkhole product wording.',
            );
            sinkholeTestAssertSame(
                \PfSense\Sinkhole\Runtime\Translator::translateForLocale($locale, 'general'),
                $package['tabs']['tab'][0]['text'],
                'The General tab must render from the package catalog for ' . $locale . '.',
            );
            sinkholeTestAssertSame(
                \PfSense\Sinkhole\Runtime\Translator::translateForLocale($locale, 'status'),
                $package['tabs']['tab'][1]['text'],
                'Every tab must render from the package catalog for ' . $locale . '.',
            );
            sinkholeTestAssertSame(
                \PfSense\Sinkhole\Runtime\Translator::translateForLocale($locale, 'update_frequency'),
                $package['fields']['field'][1]['fielddescr'],
                'Generic editor field labels must use the package catalog.',
            );
            sinkholeTestAssertSame(
                \PfSense\Sinkhole\Runtime\Translator::translateForLocale($locale, 'hourly'),
                $package['fields']['field'][1]['options']['option'][0]['name'],
                'Generic editor option labels must use the package catalog.',
            );
            sinkholeTestAssertContains(
                rawurlencode(\PfSense\Sinkhole\Runtime\Translator::translateForLocale($locale, 'settings_saved_applying')),
                $package['aftersaveredirect'],
                'The generic editor save message must use the package catalog.',
            );
            sinkholeTestAssertSame(
                array_map(
                    static fn (string $key): string => \PfSense\Sinkhole\Runtime\Translator::translateForLocale($locale, $key),
                    ['general', 'lists', 'services', 'scopes', 'alerts', 'bypass', 'ip', 'status', 'about'],
                ),
                array_column(pfsensePackageSinkholeTabs('status'), 0),
                'Every shared page tab must render for ' . $locale . '.',
            );
        }
    },
    'stub reset clears every client discovery fixture' => static function (): void {
        global $sinkholeStubArpEntries;
        global $sinkholeStubDhcpLeaseArguments;
        global $sinkholeStubDhcpLeases;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;

        $sinkholeStubInterfaces = ['lan' => 'LAN'];
        $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
        $sinkholeStubArpEntries = [['ip-address' => '192.0.2.10']];
        $sinkholeStubDhcpLeases = [['ip' => '192.0.2.10']];
        $sinkholeStubDhcpLeaseArguments = [false];
        sinkholeStubReset([]);

        sinkholeTestAssertSame([], $sinkholeStubInterfaces, 'Interfaces must reset.');
        sinkholeTestAssertSame([], $sinkholeStubInterfaceAddresses, 'Addresses must reset.');
        sinkholeTestAssertSame([], $sinkholeStubArpEntries, 'ARP entries must reset.');
        sinkholeTestAssertSame([], $sinkholeStubDhcpLeases, 'Leases must reset.');
        sinkholeTestAssertSame([], $sinkholeStubDhcpLeaseArguments, 'Lease calls must reset.');
    },
    'configuration refresh is exclusive to explicit command-line mode' => static function (): void {
        global $sinkholeStubParseConfigCount;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'system' => [
                    'unsaved_value' => 'disk',
                ],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $requestAdapter = new PfSenseAdapter($paths);

            config_set_path('system/unsaved_value', 'memory');
            $requestAdapter->refreshConfiguration();

            sinkholeTestAssertSame(
                'memory',
                config_get_path('system/unsaved_value'),
                'A pfSense-owned adapter refresh must be a no-op.',
            );
            sinkholeTestAssertSame(
                0,
                $sinkholeStubParseConfigCount,
                'A pfSense-owned adapter must not parse config.xml.',
            );

            $commandAdapter = new PfSenseAdapter(
                $paths,
                commandLineMode: true,
            );
            $commandAdapter->refreshConfiguration();

            sinkholeTestAssertSame(
                'disk',
                config_get_path('system/unsaved_value'),
                'An explicit command-line adapter may load the written configuration.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubParseConfigCount,
                'Command-line refresh must use the pfSense parser once.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'sync install and resync hooks preserve unsaved configuration' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAdapterTestPaths($directory);
            $operations = [
                'Sync' => static function (): void {
                    pfsensePackageSinkholeSync(0);
                },
                'Install hook' => static function (): void {
                    pfsensePackageSinkholeInstall();
                },
                'Resync hook' => static function (): void {
                    pfsensePackageSinkholeSync(0);
                },
            ];

            foreach ($operations as $label => $operation) {
                sinkholeStubReset([
                    'installedpackages' => [
                        'sinkhole' => [
                            'config' => [[
                                'enabled' => '',
                                'update_frequency' => 'daily',
                            ]],
                        ],
                    ],
                    'unbound' => ['enable' => ''],
                    'system' => [
                        'unsaved_value' => 'disk',
                    ],
                ]);
                pfsensePackageSinkholeAdapter(new PfSenseAdapter($paths));

                sinkholeAdapterTestAssertUnsavedConfigurationPreserved(
                    $operation,
                    $label,
                );
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'install persists an in-memory filter hook before requesting a reload' => static function (): void {
        global $sinkholeStubOperations;
        global $sinkholeStubPersistedConfiguration;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => '',
                            'update_frequency' => 'daily',
                        ]],
                        'redirect' => [
                            'enabled' => 'on',
                            'interfaces' => ['item' => []],
                            'exempt_sources' => ['item' => []],
                            'exempt_destinations' => ['item' => []],
                        ],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $stateStore->markRemoving();
            pfsensePackageSinkholeAdapter(new PfSenseAdapter($paths, $stateStore));

            config_set_path(
                'installedpackages/sinkhole/filter_rule_function',
                'pfsensePackageSinkholeFilterRules',
            );
            pfsensePackageSinkholeInstall();

            sinkholeTestAssertSame(
                'pfsensePackageSinkholeFilterRules',
                $sinkholeStubPersistedConfiguration['installedpackages']['sinkhole']
                    ['filter_rule_function'] ?? null,
                'Install must persist the hook that pfSense registered only in memory.',
            );

            $firstReloadPosition = null;

            foreach ($sinkholeStubOperations as $position => $operation) {
                if (($operation['type'] ?? '') === 'filter_reload') {
                    $firstReloadPosition = $position;
                    break;
                }
            }

            sinkholeTestAssertTrue(
                is_int($firstReloadPosition) && $firstReloadPosition > 0,
                'The upgrade install must eventually request its filter reload.',
            );
            sinkholeTestAssertSame(
                'write',
                $sinkholeStubOperations[0]['type'] ?? null,
                'A configuration write must occur before any install-path reload.',
            );
            sinkholeTestAssertContains(
                'registered DNS redirect hook',
                $sinkholeStubOperations[0]['description'] ?? '',
                'The pre-reload write must explain why the hook is persisted.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'clean install reloads the filter only while redirect is enabled' => static function (): void {
        global $sinkholeStubFilterConfigureCount;
        global $sinkholeStubOperations;
        global $sinkholeStubUnboundConfigureCount;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            foreach ([false, true] as $redirectEnabled) {
                sinkholeStubReset([
                    'installedpackages' => [
                        'sinkhole' => [
                            'config' => [[
                                'enabled' => '',
                                'update_frequency' => 'daily',
                            ]],
                            'redirect' => [
                                'enabled' => ($redirectEnabled) ? 'on' : '',
                                'interfaces' => ['item' => []],
                                'exempt_sources' => ['item' => []],
                                'exempt_destinations' => ['item' => []],
                            ],
                        ],
                    ],
                    'unbound' => [
                        'enable' => '',
                        'custom_options' => base64_encode('verbosity: 1'),
                    ],
                    'system' => [],
                ]);
                $caseDirectory = $directory . '/' . (($redirectEnabled) ? 'enabled' : 'disabled');
                mkdir($caseDirectory, 0700, true);
                $paths = sinkholeAdapterTestPaths($caseDirectory);

                pfsensePackageSinkholeAdapter(new PfSenseAdapter($paths));
                pfsensePackageSinkholeInstall();

                sinkholeTestAssertSame(
                    ($redirectEnabled) ? 1 : 0,
                    $sinkholeStubFilterConfigureCount,
                    'Install must gate its filter reload on the saved redirect setting.',
                );
                sinkholeTestAssertSame(
                    'write',
                    $sinkholeStubOperations[0]['type'] ?? null,
                    'Every install must write the registered hook before a possible reload.',
                );
                sinkholeTestAssertSame(
                    'verbosity: 1',
                    base64_decode(
                        (string) config_get_path('unbound/custom_options'),
                        true,
                    ),
                    'A fresh install must not add a Discovery zone block.',
                );
                sinkholeTestAssertSame(
                    0,
                    $sinkholeStubUnboundConfigureCount,
                    'A fresh install with Discovery off must not restart Unbound.',
                );
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'custom WebGUI save handlers preserve unsaved configuration' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAdapterTestPaths($directory);
            $operations = [
                'Lists save' => static function (): void {
                    pfsensePackageSinkholeSaveLists([], []);
                },
                'Scopes save' => static function (): void {
                    pfsensePackageSinkholeSaveScopes([], []);
                },
                'Alerts save' => static function (): void {
                    pfsensePackageSinkholeSaveAlerts([]);
                },
                'Redirect save' => static function (): void {
                    pfsensePackageSinkholeSaveRedirect([
                        'enabled' => false,
                        'interfaces' => [],
                        'exempt_sources' => [],
                        'exempt_destinations' => [],
                    ]);
                },
            ];

            foreach ($operations as $label => $operation) {
                sinkholeStubReset([
                    'installedpackages' => [
                        'sinkhole' => [
                            'config' => [[
                                'enabled' => '',
                                'update_frequency' => 'daily',
                            ]],
                        ],
                    ],
                    'unbound' => ['enable' => ''],
                    'system' => [
                        'unsaved_value' => 'disk',
                    ],
                ]);
                pfsensePackageSinkholeAdapter(new PfSenseAdapter($paths));

                sinkholeAdapterTestAssertUnsavedConfigurationPreserved(
                    $operation,
                    $label,
                );
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'an older compiled manifest forces upgrade recompilation' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAdapterTestPaths($directory);
            $compiler = new Compiler($paths, new SavedListStore($paths));
            $compiler->compile([], []);
            $adapter = new PfSenseAdapter($paths);

            sinkholeTestAssertSame(
                false,
                $adapter->runtimeGenerationMissing(),
                'A current scoped manifest must be deployable.',
            );

            $manifestPath = $paths->runtimeDataDirectory . '/manifest.json';
            $manifest = json_decode(
                (string) file_get_contents($manifestPath),
                true,
                32,
                JSON_THROW_ON_ERROR,
            );
            $manifest['schema_version'] = 1;
            file_put_contents(
                $manifestPath,
                json_encode($manifest, JSON_THROW_ON_ERROR) . PHP_EOL,
            );

            sinkholeTestAssertSame(
                true,
                $adapter->runtimeGenerationMissing(),
                'An older manifest must enter Sync\'s compile-before-enable path.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'cron follows enablement and fixed frequency fields' => static function (): void {
        global $sinkholeStubCronOperations;
        global $sinkholeStubWrites;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAdapterTestPaths($directory);
            pfsensePackageSinkholeAdapter(new PfSenseAdapter($paths));

            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [
                            [
                                'enabled' => '',
                                'update_frequency' => 'daily',
                            ],
                        ],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            pfsensePackageSinkholeInstallCron();
            sinkholeTestAssertSame(
                4,
                count($sinkholeStubCronOperations),
                'A sync must reconcile all cron jobs while disabled.',
            );
            sinkholeTestAssertSame(
                false,
                $sinkholeStubCronOperations[0][1],
                'A disabled package must request no cron entry.',
            );
            sinkholeTestAssertSame(
                false,
                $sinkholeStubCronOperations[1][1],
                'A disabled package must remove the client refresh entry.',
            );
            sinkholeTestAssertSame(
                false,
                $sinkholeStubCronOperations[2][1],
                'A disabled package must remove the alert entry.',
            );
            sinkholeTestAssertSame(
                false,
                $sinkholeStubCronOperations[3][1],
                'A disabled package must remove the redirect-check entry.',
            );

            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [
                            [
                                'enabled' => 'on',
                                'update_frequency' => 'every_six_hours',
                            ],
                        ],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            pfsensePackageSinkholeInstallCron();
            $firstMinute = (int) $sinkholeStubCronOperations[0][2];
            sinkholeTestAssertTrue(
                $firstMinute >= 0 && $firstMinute <= 59,
                'The installation minute must be randomized within cron bounds.',
            );
            sinkholeTestAssertSame(
                [
                    PackagePaths::COMMAND . ' --update',
                    true,
                    (string) $firstMinute,
                    '*/6',
                    '*',
                    '*',
                    '*',
                    'root',
                ],
                $sinkholeStubCronOperations[0],
                'The six-hour frequency must use the persisted randomized minute.',
            );
            sinkholeTestAssertSame(1, count($sinkholeStubWrites), 'A new cron job writes once.');

            pfsensePackageSinkholeInstallCron();
            sinkholeTestAssertSame(
                (string) $firstMinute,
                $sinkholeStubCronOperations[4][2],
                'Repeated sync must retain the installation minute.',
            );
            sinkholeTestAssertSame(
                1,
                count($sinkholeStubWrites),
                'An unchanged cron entry must not write config.xml.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'cron commands remain distinct in reverse stored order' => static function (): void {
        global $sinkholeStubInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $networkIdentifier = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'networks' => ['item' => [[
                            'id' => $networkIdentifier,
                            'interface' => 'lan',
                            'lists' => [],
                            'allowed_domains' => [],
                            'enabled' => 'on',
                        ]]],
                    ],
                ],
                'cron' => ['item' => [
                    [
                        'minute' => '2',
                        'hour' => '*',
                        'mday' => '*',
                        'month' => '*',
                        'wday' => '*',
                        'who' => 'root',
                        'command' => PackagePaths::COMMAND . ' --refresh-clients',
                    ],
                    [
                        'minute' => '3',
                        'hour' => '3',
                        'mday' => '*',
                        'month' => '*',
                        'wday' => '*',
                        'who' => 'root',
                        'command' => PackagePaths::COMMAND . ' --update',
                    ],
                ]],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            pfsensePackageSinkholeAdapter(new PfSenseAdapter(
                sinkholeAdapterTestPaths($directory),
            ));

            pfsensePackageSinkholeInstallCron();
            $commands = array_column(config_get_path('cron/item', []), 'command');
            sort($commands, SORT_STRING);
            $expected = [
                PackagePaths::COMMAND . ' --refresh-clients',
                PackagePaths::COMMAND . ' --update',
            ];
            sort($expected, SORT_STRING);
            sinkholeTestAssertSame(
                $expected,
                $commands,
                'Installing either command must not overwrite the other prefix.',
            );

            pfsensePackageSinkholeDisableCron();
            sinkholeTestAssertSame(
                [],
                config_get_path('cron/item', []),
                'Disablement must remove both distinct commands in either order.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'client refresh cron follows enabled scopes' => static function (): void {
        global $sinkholeStubCronOperations;
        global $sinkholeStubInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $networkIdentifier = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'networks' => ['item' => [[
                            'id' => $networkIdentifier,
                            'interface' => 'lan',
                            'lists' => [],
                            'allowed_domains' => [],
                            'enabled' => 'on',
                        ]]],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            pfsensePackageSinkholeAdapter(new PfSenseAdapter(
                sinkholeAdapterTestPaths($directory),
            ));
            pfsensePackageSinkholeInstallCron();

            sinkholeTestAssertSame(
                [
                    PackagePaths::COMMAND . ' --refresh-clients',
                    true,
                    '*',
                    '*',
                    '*',
                    '*',
                    '*',
                    'root',
                ],
                $sinkholeStubCronOperations[1],
                'An enabled network must install the one-minute refresh job.',
            );

            config_set_path(
                'installedpackages/sinkhole/networks/item/0/enabled',
                '',
            );
            pfsensePackageSinkholeInstallCron();
            sinkholeTestAssertSame(
                false,
                $sinkholeStubCronOperations[5][1],
                'Disabling the last scope must remove the refresh job.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'alert cron follows enabled rules' => static function (): void {
        global $sinkholeStubCronOperations;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $ruleIdentifier = '44444444444444444444444444444444';
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'alerts' => ['item' => [[
                            'id' => $ruleIdentifier,
                            'descr' => 'Any block',
                            'lists_any' => 'on',
                            'clients_everyone' => 'on',
                            'repeat_minutes' => '60',
                            'notice' => 'on',
                            'remote' => 'on',
                            'enabled' => 'on',
                        ]]],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            pfsensePackageSinkholeAdapter(new PfSenseAdapter(
                sinkholeAdapterTestPaths($directory),
            ));
            pfsensePackageSinkholeInstallCron();
            sinkholeTestAssertSame(
                [
                    PackagePaths::COMMAND . ' --alerts',
                    true,
                    '*',
                    '*',
                    '*',
                    '*',
                    '*',
                    'root',
                ],
                $sinkholeStubCronOperations[2],
                'An enabled rule must install the one-minute alert job.',
            );

            config_set_path('installedpackages/sinkhole/alerts/item/0/enabled', '');
            pfsensePackageSinkholeInstallCron();
            sinkholeTestAssertSame(
                false,
                $sinkholeStubCronOperations[6][1],
                'Disabling the last rule must remove the alert job.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'client sources use local helpers and disable DHCP DNS lookups' => static function (): void {
        global $sinkholeStubArpEntries;
        global $sinkholeStubDhcpLeaseArguments;
        global $sinkholeStubDhcpLeases;
        global $sinkholeStubDhcpBackend;
        global $sinkholeStubInterfaceAddresses;
        global $sinkholeStubInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'dhcpd' => [
                    'lan' => ['staticmap' => [[
                        'mac' => '00:11:22:33:44:55',
                        'ipaddr' => '192.0.2.20',
                        'hostname' => 'fixture',
                    ]]],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN', 'opt1' => 'VLAN'];
            $sinkholeStubInterfaceAddresses = [
                'lan' => [
                    'ipv4' => '192.0.2.1',
                    'ipv4_prefix' => 24,
                    'ipv6' => '2001:db8:1::1',
                    'ipv6_prefix' => 64,
                ],
                'opt1' => [
                    'ipv4' => '169.254.10.1',
                    'ipv4_prefix' => 16,
                    'ipv6' => 'fe80::1',
                    'ipv6_prefix' => 64,
                ],
            ];
            $sinkholeStubArpEntries = [[
                'ip-address' => '192.0.2.21',
                'mac-address' => '00:11:22:33:44:55',
                'interface' => 'em0',
            ]];
            $adapter = new PfSenseAdapter(sinkholeAdapterTestPaths($directory));

            sinkholeTestAssertSame(
                [
                    'lan' => ['192.0.2.0/24', '2001:db8:1::/64'],
                    'opt1' => [],
                ],
                $adapter->getInterfaceSubnets(),
                'Interface addresses must become canonical CIDRs without link-local ranges.',
            );
            sinkholeTestAssertSame(
                'lan',
                $adapter->getStaticMappings()[0]['interface'],
                'Static mappings must carry their stable interface identity.',
            );
            sinkholeTestAssertSame(
                $sinkholeStubArpEntries,
                $adapter->getArpEntries(),
                'ARP must come from the pfSense helper unchanged.',
            );

            $iscLeases = ['lease' => [[
                'ip' => '192.0.2.22',
                'mac' => '00:11:22:33:44:55',
                'act' => 'active',
            ]]];
            $sinkholeStubDhcpLeases = $iscLeases;
            sinkholeTestAssertSame(
                $iscLeases,
                $adapter->getDhcpLeases(),
                'ISC lease arrays must pass through without DNS enrichment.',
            );
            $keaLeases = ['lease' => [[
                'ip' => '192.0.2.23',
                'mac' => '00:11:22:33:44:55',
                'act' => 'active',
                'starts' => '2026-01-01 00:00:00',
                'ends' => '2027-01-01 00:00:00',
            ]]];
            $sinkholeStubDhcpLeases = $keaLeases;
            sinkholeTestAssertSame(
                $keaLeases,
                $adapter->getDhcpLeases(),
                'Kea lease arrays must use the same local helper boundary.',
            );
            sinkholeTestAssertSame(
                [false, false],
                $sinkholeStubDhcpLeaseArguments,
                'Every DHCP helper call must pass false to prevent DNS lookups.',
            );
            sinkholeTestAssertSame(
                false,
                $adapter->getDhcpLeaseContext()['times_local'],
                'ISC lease timestamps must default to GMT.',
            );
            config_set_path('dhcpd/opt1/dhcpleaseinlocaltime', 'yes');
            sinkholeTestAssertSame(
                true,
                $adapter->getDhcpLeaseContext()['times_local'],
                'Any interface local-time setting must match pfSense lease conversion.',
            );
            config_del_path('dhcpd/opt1/dhcpleaseinlocaltime');
            $sinkholeStubDhcpBackend = 'kea';
            sinkholeTestAssertSame(
                true,
                $adapter->getDhcpLeaseContext()['times_local'],
                'Kea lease timestamps are always local on pfSense.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'python slot guard preserves another owner' => static function (): void {
        global $sinkholeStubUnboundConfigureCount;
        global $sinkholeStubWrites;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [
                            [
                                'enabled' => 'on',
                            ],
                        ],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => 'on',
                    'python_order' => 'pre_validator',
                    'python_script' => 'pfb_unbound',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $result = (new PfSenseAdapter($paths))->enableDnsResolverIntegration();

            sinkholeTestAssertSame(false, $result['active'], 'Sinkhole must not take an occupied slot.');
            sinkholeTestAssertSame('pfb_unbound', $result['owner'], 'The current owner must be reported.');
            sinkholeTestAssertSame(
                'pfb_unbound',
                config_get_path('unbound/python_script'),
                'The competing owner must remain unchanged.',
            );
            sinkholeTestAssertSame([], $sinkholeStubWrites, 'The guard must not write configuration.');
            sinkholeTestAssertSame(0, $sinkholeStubUnboundConfigureCount, 'The guard must not restart Unbound.');
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeScriptFile),
                'The guard must not install runtime files.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'previous resolver settings are saved once and restored' => static function (): void {
        global $sinkholeStubUnboundConfigureCount;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => 'validator iterator',
                    'python_script' => '',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);
            $result = $adapter->enableDnsResolverIntegration();

            sinkholeTestAssertSame(true, $result['active'], 'Sinkhole must take an available slot.');
            sinkholeTestAssertSame(
                true,
                config_path_enabled('unbound', 'python'),
                'An empty pfSense boolean element must remain enabled.',
            );
            sinkholeTestAssertSame(
                '',
                config_get_path('unbound/python'),
                'An already-enabled empty Python element must not be rewritten.',
            );
            sinkholeTestAssertSame(
                'pre_validator',
                config_get_path('unbound/python_order'),
                'The module order must be pre-validator.',
            );
            sinkholeTestAssertSame(
                'sinkhole',
                config_get_path('unbound/python_script'),
                'Sinkhole must own the script slot.',
            );
            sinkholeTestAssertTrue(is_readable($paths->runtimeScriptFile), 'The runtime module must exist.');
            sinkholeTestAssertSame(
                [
                    'python' => [
                        'present' => true,
                        'value' => '',
                    ],
                    'python_order' => [
                        'present' => true,
                        'value' => 'validator iterator',
                    ],
                    'python_script' => [
                        'present' => true,
                        'value' => '',
                    ],
                ],
                $stateStore->previousUnboundSettings(),
                'The initial Resolver settings must be saved.',
            );
            $generationName = '.sinkhole-generation-0123456789abcdef';
            $generationPath = $paths->runtimeStorageDirectory . '/' . $generationName;
            mkdir($generationPath, 0755);
            file_put_contents($generationPath . '/generation', "generation-status\n");
            file_put_contents(
                $generationPath . '/manifest.json',
                json_encode([
                    'schema_version' => Compiler::MANIFEST_SCHEMA_VERSION,
                    'bypass_file' => 'bypass.tsv',
                    'scopes' => [
                        'global' => [],
                        'networks' => [],
                        'devices' => [],
                    ],
                    'alerts' => [],
                    'bypass' => [
                        'interfaces' => [],
                        'block_encrypted_dns' => false,
                        'disable_firefox_doh' => false,
                        'disable_private_relay' => false,
                        'discovery' => 'off',
                        'discovery_hostname' => '',
                        'discovery_port' => 0,
                        'block_tor' => false,
                        'block_vpn' => false,
                    ],
                ], JSON_THROW_ON_ERROR) . PHP_EOL,
            );
            file_put_contents($generationPath . '/bypass.tsv', '');
            symlink('sinkhole.d/' . $generationName, $paths->runtimeDataDirectory);
            sinkholeTestAssertSame(
                true,
                $adapter->dnsResolverStatus(true)['active'],
                'Status must recognize an enabled empty pfSense boolean element.',
            );

            $adapter->enableDnsResolverIntegration();
            sinkholeTestAssertSame(
                [
                    'python' => [
                        'present' => true,
                        'value' => '',
                    ],
                    'python_order' => [
                        'present' => true,
                        'value' => 'validator iterator',
                    ],
                    'python_script' => [
                        'present' => true,
                        'value' => '',
                    ],
                ],
                $stateStore->previousUnboundSettings(),
                'Repeated enablement must not replace the recovery point.',
            );

            $adapter->disableDnsResolverIntegration();
            sinkholeTestAssertSame('', config_get_path('unbound/python'), 'Python mode must restore.');
            sinkholeTestAssertSame(
                'validator iterator',
                config_get_path('unbound/python_order'),
                'The prior module order must restore.',
            );
            sinkholeTestAssertSame('', config_get_path('unbound/python_script'), 'The prior slot must restore.');
            sinkholeTestAssertSame(null, $stateStore->previousUnboundSettings(), 'Restored state must clear.');
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeScriptFile),
                'The runtime module must be removed.',
            );
            sinkholeTestAssertSame(
                2,
                $sinkholeStubUnboundConfigureCount,
                'Enable and disable must reconfigure Unbound.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'absent resolver settings are deleted on restore' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => [
                    'enable' => '',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);
            $adapter->enableDnsResolverIntegration();

            sinkholeTestAssertSame(
                '',
                config_get_path('unbound/python'),
                'pfSense boolean enablement must re-read as an empty element.',
            );
            sinkholeTestAssertSame(
                [
                    'python' => ['present' => false, 'value' => null],
                    'python_order' => ['present' => false, 'value' => null],
                    'python_script' => ['present' => false, 'value' => null],
                ],
                $stateStore->previousUnboundSettings(),
                'The recovery point must distinguish every absent key.',
            );
            sinkholeTestAssertSame(
                [],
                config_get_path('system/earlyshellcmd', []),
                'A persistent /var installation must not install a boot restore command.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->mirrorRootDirectory),
                'A persistent /var installation must not retain a boot mirror.',
            );

            $adapter->disableDnsResolverIntegration();

            sinkholeTestAssertSame(
                ['enable' => ''],
                config_get_path('unbound', []),
                'Resolver keys absent before Sinkhole must be deleted without disabling it.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'earlyshellcmd remains single and idempotent' => static function (): void {
        global $sinkholeStubConfiguration;
        global $sinkholeStubWrites;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAdapterTestPaths($directory);
            $command = $paths->earlyShellCommand();
            sinkholeStubReset([
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => '',
                    'python_script' => '',
                ],
                'system' => [
                    'use_mfs_tmpvar' => 'on',
                    'earlyshellcmd' => [$command, '/bin/echo preserved', $command],
                ],
            ]);
            mkdir($paths->mirrorClientDirectory, 0755, true);
            $clientFixture = '{"schema_version":1,"clients":"fixture"}' . PHP_EOL;
            file_put_contents($paths->mirrorClientMapFile, $clientFixture);
            $adapter = new PfSenseAdapter($paths);
            $adapter->enableDnsResolverIntegration();
            $commands = config_get_path('system/earlyshellcmd', []);

            sinkholeTestAssertSame(
                1,
                count(array_keys($commands, $command, true)),
                'Enablement must leave exactly one restore command.',
            );
            sinkholeTestAssertTrue(
                in_array('/bin/echo preserved', $commands, true),
                'Unrelated early commands must be preserved.',
            );
            sinkholeTestAssertSame(
                $clientFixture,
                file_get_contents($paths->runtimeClientMapFile),
                'RAM-disk enablement must restore the mirrored client map.',
            );
            sinkholeTestAssertSame(
                0644,
                fileperms($paths->runtimeClientMapFile) & 0777,
                'The restored client map must retain its runtime mode.',
            );

            $writeCount = count($sinkholeStubWrites);
            $adapter->enableDnsResolverIntegration();
            sinkholeTestAssertSame(
                $writeCount,
                count($sinkholeStubWrites),
                'An idempotent enable must not create another config revision.',
            );
            sinkholeTestAssertSame(
                1,
                count(array_keys(config_get_path('system/earlyshellcmd', []), $command, true)),
                'An idempotent enable must retain one restore command.',
            );

            $adapter->disableDnsResolverIntegration();
            sinkholeTestAssertSame(
                ['/bin/echo preserved'],
                config_get_path('system/earlyshellcmd', []),
                'Disablement must remove only Sinkhole restore commands.',
            );

            $sinkholeStubConfiguration['system']['use_mfs_tmpvar'] = '';
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'uninstall removes persistent package data' => static function (): void {
        global $sinkholeStubUnboundConfigureCount;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [
                            [
                                'enabled' => 'on',
                            ],
                        ],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => '',
                    'python_script' => '',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $adapter = new PfSenseAdapter($paths);
            $adapter->enableDnsResolverIntegration();
            $adminOptions = 'verbosity: 1';
            config_set_path(
                'unbound/custom_options',
                base64_encode(UnboundCustomOptions::reconcileDiscoveryZone(
                    $adminOptions,
                    true,
                )),
            );
            $sinkholeStubUnboundConfigureCount = 0;
            file_put_contents($paths->persistentDirectory . '/saved.test', 'saved');

            $adapter->uninstall(false);

            sinkholeTestAssertSame(
                false,
                file_exists($paths->persistentDirectory),
                'Uninstall must remove all persistent package-owned data.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeScriptFile),
                'Uninstall must remove the runtime module.',
            );
            sinkholeTestAssertSame(
                null,
                config_get_path('installedpackages/sinkhole', null),
                'Keep Settings off must remove the package configuration record.',
            );
            sinkholeTestAssertSame(
                $adminOptions,
                base64_decode((string) config_get_path('unbound/custom_options'), true),
                'Removal with Keep Settings off must remove only the managed zone block.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubUnboundConfigureCount,
                'Removal with Keep Settings off must restart Unbound once.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'uninstall keeps saved settings and lists by default' => static function (): void {
        global $sinkholeStubUnboundConfigureCount;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [
                            [
                                'enabled' => 'on',
                                'keep_settings' => 'on',
                            ],
                        ],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => '',
                    'python_script' => '',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $adapter = new PfSenseAdapter($paths);
            $adapter->enableDnsResolverIntegration();
            $adminOptions = 'verbosity: 2';
            config_set_path(
                'unbound/custom_options',
                base64_encode(UnboundCustomOptions::reconcileDiscoveryZone(
                    $adminOptions,
                    true,
                )),
            );
            $sinkholeStubUnboundConfigureCount = 0;
            file_put_contents($paths->persistentDirectory . '/saved.test', 'saved');

            $adapter->uninstall(true);

            sinkholeTestAssertTrue(
                is_file($paths->persistentDirectory . '/saved.test'),
                'Keep Settings on must retain persistent package data.',
            );
            sinkholeTestAssertTrue(
                is_array(config_get_path('installedpackages/sinkhole', null)),
                'Keep Settings on must retain the configuration record.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeScriptFile),
                'Removal must always remove runtime integration files.',
            );
            sinkholeTestAssertSame(
                $adminOptions,
                base64_decode((string) config_get_path('unbound/custom_options'), true),
                'Removal with Keep Settings on must remove only the managed zone block.',
            );
            sinkholeTestAssertSame(
                1,
                $sinkholeStubUnboundConfigureCount,
                'Removal with Keep Settings on must restart Unbound once.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'both package removal passes are idempotent for either Keep Settings value' => static function (): void {
        global $sinkholeStubWriteConfigObserver;
        global $sinkholeStubWrites;

        foreach ([false, true] as $keepSettings) {
            $directory = sinkholeTestTemporaryDirectory();

            try {
                sinkholeStubReset([
                    'installedpackages' => [
                        'package' => [[
                            'name' => 'Sinkhole',
                            'internal_name' => 'Sinkhole',
                            'configurationfile' => 'sinkhole.xml',
                        ]],
                        'sinkhole' => [
                            'config' => [[
                                'enabled' => 'on',
                                'update_frequency' => 'daily',
                                'keep_settings' => $keepSettings ? 'on' : '',
                            ]],
                        ],
                    ],
                    'unbound' => [
                        'enable' => '',
                        'python' => '',
                        'python_order' => '',
                        'python_script' => '',
                    ],
                    'system' => [],
                ]);
                $paths = sinkholeAdapterTestPaths($directory);
                $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
                $adapter = new PfSenseAdapter($paths, $stateStore);
                pfsensePackageSinkholeAdapter($adapter);
                $adapter->enableDnsResolverIntegration();
                file_put_contents($paths->persistentDirectory . '/saved.test', 'saved');
                $observerCalls = 0;
                $observedDescriptions = [];
                $blockedStateWriters = 0;
                $sinkholeStubWriteConfigObserver = static function (
                    string $description,
                ) use (
                    $paths,
                    &$observerCalls,
                    &$observedDescriptions,
                    &$blockedStateWriters,
                ): void {
                    $observerCalls++;
                    $observedDescriptions[] = $description;
                    pfsensePackageSinkholeGetUpdateSchedule();

                    try {
                        $lateStore = new StateStore($paths->stateFile, $paths->statusFile);
                        $lateStore->markCompileNeeded();
                    } catch (RuntimeException) {
                        $blockedStateWriters++;
                    }

                    try {
                        $lateStore ??= new StateStore($paths->stateFile, $paths->statusFile);
                        $lateStore->recordClientMapError('late removal writer');
                    } catch (RuntimeException) {
                        $blockedStateWriters++;
                    }
                };

                pfsensePackageSinkholePackageDeinstall();

                sinkholeTestAssertSame(
                    $keepSettings,
                    is_array(config_get_path('installedpackages/sinkhole', null)),
                    'The pre-deinstall pass must apply the Keep Settings decision.',
                );
                sinkholeTestAssertSame(
                    $keepSettings,
                    file_exists($paths->persistentDirectory),
                    'The pre-deinstall pass must apply the persistent-data decision.',
                );
                sinkholeTestAssertTrue(
                    $observerCalls >= 1 && $blockedStateWriters === $observerCalls * 2,
                    'Removal-time config callbacks must not mutate persistent or status state.',
                );
                sinkholeTestAssertSame(
                    false,
                    in_array(
                        pfsensePackageSinkholeTranslate('revision_removed_settings'),
                        $observedDescriptions,
                        true,
                    ),
                    'The settings deletion must use pfSense write-only mode.',
                );
                sinkholeTestAssertSame(
                    false,
                    in_array(
                        pfsensePackageSinkholeTranslate('stable_update_schedule_saved'),
                        $sinkholeStubWrites,
                        true,
                    ),
                    'Removal must not save a replacement update schedule.',
                );

                if ($keepSettings === false) {
                    sinkholeTestAssertSame(
                        pfsensePackageSinkholeTranslate('revision_removed_settings'),
                        $sinkholeStubWrites[array_key_last($sinkholeStubWrites)],
                        'The settings-removal revision must be the last pre-deinstall write.',
                    );
                }

                sinkholeAdapterTestPostDeinstall();

                if ($keepSettings === false) {
                    $settingsRemovalIndex = array_search(
                        pfsensePackageSinkholeTranslate('revision_removed_settings'),
                        $sinkholeStubWrites,
                        true,
                    );
                    sinkholeTestAssertSame(
                        ['Removed Sinkhole package.'],
                        array_slice($sinkholeStubWrites, (int) $settingsRemovalIndex + 1),
                        'Only pfSense\'s post-deinstall revision may follow settings removal.',
                    );
                }

                $writesAfterBothPasses = $sinkholeStubWrites;

                pfsensePackageSinkholePackageDeinstall();
                sinkholeAdapterTestPostDeinstall();

                sinkholeTestAssertSame(
                    $writesAfterBothPasses,
                    $sinkholeStubWrites,
                    'Repeating both removal passes must not create another revision.',
                );
                sinkholeTestAssertSame(
                    $keepSettings,
                    is_array(config_get_path('installedpackages/sinkhole', null)),
                    'Repeated removal must preserve the Keep Settings result.',
                );
                sinkholeTestAssertSame(
                    $keepSettings,
                    file_exists($paths->persistentDirectory),
                    'Repeated removal must preserve the persistent-data result.',
                );

                if ($keepSettings === false) {
                    $lateLifecycleStore = new StateStore(
                        $paths->stateFile,
                        $paths->statusFile,
                    );
                    $lateLifecycleStore->requestStop();
                    $lateLifecycleStore->markRemoving();
                    $lateLifecycleStore->clearPreviousUnboundSettings();
                    $lateLifecycleStore->clearDeployment();
                    $lateLifecycleStore->consumeSyncPending();
                    $lateLifecycleStore->sweepTemporaryFiles();
                }

                sinkholeTestAssertSame(
                    $keepSettings,
                    file_exists($paths->stateFile) || file_exists($paths->stateFile . '.lock'),
                    'Late lifecycle writers must not recreate state or its reusable lock.',
                );
                sinkholeTestAssertSame(
                    false,
                    file_exists($paths->statusFile) || file_exists($paths->statusLockFile),
                    'Removal-time writers must not recreate status state or its lock.',
                );
            } finally {
                $sinkholeStubWriteConfigObserver = null;
                sinkholeTestRemoveTemporaryDirectory($directory);
            }
        }
    },
    'install remove and reinstall starts with fresh default state' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'package' => [[
                        'name' => 'Sinkhole',
                        'internal_name' => 'Sinkhole',
                        'configurationfile' => 'sinkhole.xml',
                    ]],
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                            'keep_settings' => '',
                        ]],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => '',
                    'python_script' => '',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);
            pfsensePackageSinkholeAdapter($adapter);
            $adapter->enableDnsResolverIntegration();
            $stateStore->recordCompileSuccess('old-generation', 1, str_repeat('a', 64));
            file_put_contents($paths->persistentDirectory . '/saved.test', 'saved');

            pfsensePackageSinkholePackageDeinstall();
            sinkholeAdapterTestPostDeinstall();

            config_set_path('installedpackages/package/0', [
                'name' => 'Sinkhole',
                'internal_name' => 'Sinkhole',
                'configurationfile' => 'sinkhole.xml',
            ]);
            config_set_path('installedpackages/sinkhole/config/0', [
                'enabled' => '',
                'update_frequency' => 'daily',
                'keep_settings' => 'on',
                'update_check_frequency' => 'never',
            ]);
            pfsensePackageSinkholeInstall();

            $freshState = (new StateStore($paths->stateFile, $paths->statusFile))->read();
            sinkholeTestAssertSame(
                false,
                file_exists($paths->persistentDirectory . '/saved.test'),
                'Reinstall must not recover data deleted by Keep Settings off.',
            );
            sinkholeTestAssertSame(
                1,
                $freshState['compile_request'],
                'Fresh state must start at request one.',
            );
            sinkholeTestAssertSame(
                0,
                $freshState['compiled_request'],
                'Fresh state must have no compiled request.',
            );
            sinkholeTestAssertSame(
                null,
                $freshState['compiled_generation'],
                'Fresh state must have no old generation.',
            );
            sinkholeTestAssertSame(
                false,
                $freshState['stop_requested'],
                'Install must clear stop intent.',
            );
            sinkholeTestAssertSame(
                false,
                $freshState['removing'],
                'Install must clear removal intent.',
            );
            sinkholeTestAssertSame(
                null,
                $freshState['cron_minute'],
                'Fresh state must have no list-update jitter yet.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'package upgrade deinstall keeps the complete installation' => static function (): void {
        global $sinkholeStubCronOperations;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [
                            [
                                'enabled' => 'on',
                                'keep_settings' => 'on',
                            ],
                        ],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => '',
                    'python_script' => '',
                    'custom_options' => base64_encode('verbosity: 3'),
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $adapter = sinkholeAdapterTestWithClientMap($paths);
            pfsensePackageSinkholeAdapter($adapter);
            $adapter->enableDnsResolverIntegration();
            file_put_contents($paths->persistentDirectory . '/saved.test', 'saved');
            mkdir($paths->catalogCacheDirectory, 0700);
            file_put_contents($paths->adGuardHomeCatalogCacheFile, 'cached');
            file_put_contents($paths->pfBlockerNgCatalogCacheFile, 'cached');
            file_put_contents($paths->serviceRegistryCacheFile, 'cached');
            putenv('PKG_UPGRADE=1');

            pfsensePackageSinkholePackageDeinstall();

            $stateStore = new StateStore($paths->stateFile);

            sinkholeTestAssertTrue(
                is_file($paths->runtimeScriptFile),
                'An upgrade deinstall must keep runtime integration in place.',
            );
            sinkholeTestAssertTrue(
                is_file($paths->persistentDirectory . '/saved.test'),
                'An upgrade deinstall must keep saved package data.',
            );
            sinkholeTestAssertTrue(
                is_file($paths->adGuardHomeCatalogCacheFile)
                    && is_file($paths->pfBlockerNgCatalogCacheFile)
                    && is_file($paths->serviceRegistryCacheFile),
                'An upgrade deinstall must keep catalog and service caches in place.',
            );
            sinkholeTestAssertSame(
                'sinkhole',
                config_get_path('unbound/python_script'),
                'An upgrade deinstall must keep Resolver ownership.',
            );
            sinkholeTestAssertSame(
                [],
                $sinkholeStubCronOperations,
                'An upgrade deinstall must leave the schedule untouched.',
            );
            sinkholeTestAssertSame(
                true,
                $stateStore->removing(),
                'An upgrade deinstall must leave the durable removal marker set.',
            );

            pfsensePackageSinkholeInstall();
            sinkholeTestAssertSame(
                false,
                $stateStore->removing(),
                'The following install hook must clear the removal marker.',
            );
            sinkholeTestAssertSame(
                'verbosity: 3',
                base64_decode((string) config_get_path('unbound/custom_options'), true),
                'An upgrade with Discovery off must not add a zone block.',
            );
        } finally {
            putenv('PKG_UPGRADE');
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'settings delete and resync do not mark package removal' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => '',
                    'python_script' => '',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $adapter = sinkholeAdapterTestWithClientMap($paths, $stateStore);
            pfsensePackageSinkholeAdapter($adapter);
            $adapter->enableDnsResolverIntegration();

            pfsensePackageSinkholeDelete();
            config_del_path('installedpackages/sinkhole/config/0');
            pfsensePackageSinkholeSync(0);

            sinkholeTestAssertSame(
                false,
                $stateStore->removing(),
                'A settings delete and its resync must not mark package removal.',
            );

            config_set_path('installedpackages/sinkhole/config/0', [
                'enabled' => 'on',
                'update_frequency' => 'daily',
            ]);
            pfsensePackageSinkholeSync(0);

            sinkholeTestAssertSame(
                'sinkhole',
                config_get_path('unbound/python_script'),
                'A later enabled Sync must restore Sinkhole integration.',
            );
            sinkholeTestAssertSame(
                false,
                $stateStore->removing(),
                'The later Sync must remain outside package removal.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'sync during removal only disables integration' => static function (): void {
        global $sinkholeStubBackgroundCommands;
        global $sinkholeStubCronOperations;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => '',
                    'python_script' => '',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);
            pfsensePackageSinkholeAdapter($adapter);
            $adapter->enableDnsResolverIntegration();
            $stateStore->markRemoving();

            pfsensePackageSinkholeSync(0);

            sinkholeTestAssertSame(
                '',
                config_get_path('unbound/python_script'),
                'A removal-time Sync must restore Resolver ownership.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeScriptFile),
                'A removal-time Sync must remove transient runtime integration.',
            );
            sinkholeTestAssertSame(
                false,
                $sinkholeStubCronOperations[array_key_last($sinkholeStubCronOperations)][1],
                'A removal-time Sync must only request a disabled schedule.',
            );
            sinkholeTestAssertSame(
                [],
                $sinkholeStubBackgroundCommands,
                'A removal-time Sync must not spawn an apply job.',
            );
            sinkholeTestAssertSame(true, $stateStore->removing(), 'Sync must retain removal intent.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'sync refreshes clients only for enabled scopes or Bypass DNS protection' => static function (): void {
        global $sinkholeStubBackgroundCommands;
        global $sinkholeStubInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $offPaths = sinkholeAdapterTestPaths($directory . '/off');
            mkdir($offPaths->runtimeClientDirectory, 0755, true);
            mkdir($offPaths->mirrorClientDirectory, 0755, true);
            file_put_contents($offPaths->runtimeClientMapFile, "{}\n");
            file_put_contents($offPaths->mirrorClientMapFile, "{}\n");
            pfsensePackageSinkholeAdapter(new PfSenseAdapter($offPaths));

            pfsensePackageSinkholeSync(0);

            sinkholeTestAssertSame(
                [],
                $sinkholeStubBackgroundCommands,
                'A fresh disabled installation must not launch background work.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($offPaths->runtimeClientMapFile),
                'Disabling every feature must remove the runtime client map on Sync.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($offPaths->mirrorClientMapFile),
                'Disabling every feature must remove the RAM-disk mirror on Sync.',
            );

            $scopeIdentifier = str_repeat('a', 32);
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'networks' => ['item' => [[
                            'id' => $scopeIdentifier,
                            'interface' => 'lan',
                            'lists' => [],
                            'allowed_domains' => [],
                            'enabled' => 'on',
                        ]]],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            pfsensePackageSinkholeAdapter(new PfSenseAdapter(
                sinkholeAdapterTestPaths($directory . '/scope'),
            ));

            pfsensePackageSinkholeSync(0);

            sinkholeTestAssertSame(
                [
                    PackagePaths::COMMAND . ' --apply',
                    PackagePaths::COMMAND . ' --refresh-clients',
                ],
                $sinkholeStubBackgroundCommands,
                'An enabled DNS scope must launch the client refresh.',
            );

            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => '',
                            'update_frequency' => 'daily',
                        ]],
                        'redirect' => [
                            'interfaces' => ['item' => ['lan']],
                        ],
                        'bypass' => [
                            'disable_firefox_doh' => 'on',
                            'discovery' => 'off',
                        ],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            pfsensePackageSinkholeAdapter(new PfSenseAdapter(
                sinkholeAdapterTestPaths($directory . '/bypass'),
            ));

            pfsensePackageSinkholeSync(0);

            sinkholeTestAssertSame(
                [
                    PackagePaths::COMMAND . ' --apply',
                    PackagePaths::COMMAND . ' --refresh-clients',
                ],
                $sinkholeStubBackgroundCommands,
                'Bypass DNS protection must launch the client refresh while DNS blocking is off.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'disabled resolver prevents integration and deployment eligibility' => static function (): void {
        global $sinkholeStubBackgroundCommands;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [
                            [
                                'enabled' => 'on',
                            ],
                        ],
                    ],
                ],
                'unbound' => [],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $adapter = new PfSenseAdapter($paths);
            $result = $adapter->enableDnsResolverIntegration();

            sinkholeTestAssertSame(false, $result['active'], 'A disabled Resolver must stay untouched.');
            sinkholeTestAssertSame(
                'DNS Resolver is disabled.',
                $result['reason'],
                'Enablement must report the disabled Resolver explicitly.',
            );
            sinkholeTestAssertSame(
                'DNS Resolver is disabled.',
                $adapter->dnsResolverStatus(true)['reason'],
                'Status must report the disabled Resolver explicitly.',
            );
            sinkholeTestAssertSame(
                false,
                $adapter->isIntegrationActive(),
                'A disabled Resolver must never be eligible for deployment.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeRootDirectory),
                'The disabled-Resolver path must not touch runtime storage.',
            );

            pfsensePackageSinkholeAdapter($adapter);
            pfsensePackageSinkholeSync();
            sinkholeTestAssertSame(
                [PackagePaths::COMMAND . ' --apply'],
                $sinkholeStubBackgroundCommands,
                'Global DNS blocking without a client scope must not refresh clients.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeRootDirectory),
                'Inactive sync must not create anything under the Unbound root.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'list saves enqueue fixed apply without a cache clear' => static function (): void {
        global $sinkholeStubBackgroundCommands;
        global $sinkholeStubCommands;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);
            $adapter->saveListConfiguration([], []);
            $adapter->runApplyInBackground();

            sinkholeTestAssertSame(
                [PackagePaths::COMMAND . ' --apply'],
                $sinkholeStubBackgroundCommands,
                'A list save must hand off one fixed apply command.',
            );
            sinkholeTestAssertSame(
                [],
                $sinkholeStubCommands,
                'Apply handoff must not invoke a cache clear.',
            );
            sinkholeTestAssertSame(
                true,
                $stateStore->compileStatus()['needed'],
                'A list save must increment compile intent before handoff.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'scope saves round trip repeated items and compile' => static function (): void {
        global $sinkholeStubInterfaces;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $listIdentifiers = [
                '11111111111111111111111111111111',
                '22222222222222222222222222222222',
                '33333333333333333333333333333333',
            ];
            $networkIdentifier = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
            $deviceIdentifier = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
            $alertIdentifier = '44444444444444444444444444444444';
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'lists' => [
                            'item' => [
                                [
                                    'id' => $listIdentifiers[0],
                                    'descr' => 'Jacky’s Café List',
                                    'url' => 'https://lists.example.invalid/scope-alpha.test',
                                    'enabled' => 'on',
                                    'global' => '',
                                ],
                                [
                                    'id' => $listIdentifiers[1],
                                    'descr' => 'Scope Beta',
                                    'url' => 'https://lists.example.invalid/scope-beta.test',
                                    'enabled' => 'on',
                                    'global' => '',
                                ],
                                [
                                    'id' => $listIdentifiers[2],
                                    'descr' => 'Scope Gamma',
                                    'url' => 'https://lists.example.invalid/scope-gamma.test',
                                    'enabled' => 'on',
                                    'global' => '',
                                ],
                            ],
                        ],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $sinkholeStubInterfaces = ['lan' => 'LAN'];
            $paths = sinkholeAdapterTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $adapter = new PfSenseAdapter($paths, $stateStore);

            pfsensePackageSinkholeAdapter($adapter);
            mkdir($paths->listDirectory, 0700, true);

            foreach ($listIdentifiers as $position => $listIdentifier) {
                file_put_contents(
                    $paths->listFile($listIdentifier),
                    "E\tscope-" . ($position + 1) . ".example.test\n",
                );
            }

            $networks = [
                $networkIdentifier => [
                    'id' => $networkIdentifier,
                    'interface' => 'lan',
                    'lists' => [$listIdentifiers[0], $listIdentifiers[1]],
                    'allowed_domains' => [
                        'network-one.example.test',
                        'network-two.example.test',
                    ],
                    'enabled' => true,
                ],
            ];
            $devices = [
                $deviceIdentifier => [
                    'id' => $deviceIdentifier,
                    'name' => 'Jacky’s Café iPhone',
                    'identifier_type' => 'ip',
                    'identifier' => '192.0.2.25',
                    'interface' => '',
                    'lists' => [$listIdentifiers[1], $listIdentifiers[2]],
                    'allowed_domains' => [
                        'device-one.example.test',
                        'device-two.example.test',
                    ],
                    'enabled' => true,
                ],
            ];
            $invalidNetworks = [[
                'row' => [
                    'id' => 'repair-network',
                    'interface' => 'missing',
                    'lists' => [$listIdentifiers[0], $listIdentifiers[2]],
                    'allowed_domains' => ['repair.example.test'],
                    'enabled' => 'on',
                ],
            ]];

            pfsensePackageSinkholeSaveScopes(
                $networks,
                $devices,
                $invalidNetworks,
            );

            sinkholeTestAssertSame(
                'Jacky’s Café List',
                config_get_path('installedpackages/sinkhole/lists/item/0/descr'),
                'A non-ASCII list name must survive the pfSense XML round trip in CDATA.',
            );
            sinkholeTestAssertSame(
                'Jacky’s Café iPhone',
                config_get_path('installedpackages/sinkhole/devices/item/0/descr'),
                'A non-ASCII device name must survive the pfSense XML round trip in CDATA.',
            );
            sinkholeTestAssertSame(
                [$listIdentifiers[0], $listIdentifiers[1]],
                config_get_path('installedpackages/sinkhole/networks/item/0/lists/item'),
                'Network list selections must survive pfSense XML serialization.',
            );
            sinkholeTestAssertSame(
                ['network-one.example.test', 'network-two.example.test'],
                config_get_path(
                    'installedpackages/sinkhole/networks/item/0/allowed_domains/item',
                ),
                'Network allowed domains must survive pfSense XML serialization.',
            );
            sinkholeTestAssertSame(
                [$listIdentifiers[1], $listIdentifiers[2]],
                config_get_path('installedpackages/sinkhole/devices/item/0/lists/item'),
                'Device list selections must survive pfSense XML serialization.',
            );
            sinkholeTestAssertSame(
                ['device-one.example.test', 'device-two.example.test'],
                config_get_path(
                    'installedpackages/sinkhole/devices/item/0/allowed_domains/item',
                ),
                'Device allowed domains must survive pfSense XML serialization.',
            );

            $scopeConfiguration = $adapter->getScopePartitions();

            sinkholeTestAssertSame(
                'Jacky’s Café List',
                $adapter->getLists()[0]['descr'],
                'The list reader must retain the new CDATA field.',
            );
            sinkholeTestAssertSame(
                'Jacky’s Café iPhone',
                $scopeConfiguration['devices'][$deviceIdentifier]['name'],
                'The device reader must normalize the new CDATA field.',
            );
            sinkholeTestAssertSame(
                $networks[$networkIdentifier]['lists'],
                $scopeConfiguration['networks'][$networkIdentifier]['lists'],
                'The network reader must unwrap repeated list items.',
            );
            sinkholeTestAssertSame(
                $devices[$deviceIdentifier]['allowed_domains'],
                $scopeConfiguration['devices'][$deviceIdentifier]['allowed_domains'],
                'The device reader must unwrap repeated allowed-domain items.',
            );
            sinkholeTestAssertSame(
                1,
                count($scopeConfiguration['invalid_networks']),
                'A malformed row must remain available for repair after the write.',
            );

            pfsensePackageSinkholeSaveScopes(
                $scopeConfiguration['networks'],
                $scopeConfiguration['devices'],
                $scopeConfiguration['invalid_networks'],
                $scopeConfiguration['invalid_devices'],
            );
            $scopeConfiguration = $adapter->getScopePartitions();

            sinkholeTestAssertSame(
                1,
                count($scopeConfiguration['invalid_networks']),
                'A preserved malformed row must survive another pfSense XML round trip.',
            );

            pfsensePackageSinkholeSaveAlerts([
                $alertIdentifier => [
                    'id' => $alertIdentifier,
                    'description' => 'Jacky’s Café alert',
                    'any_list' => false,
                    'lists' => [$listIdentifiers[1]],
                    'everyone' => false,
                    'networks' => [$networkIdentifier],
                    'devices' => [$deviceIdentifier],
                    'repeat_minutes' => 60,
                    'notice' => true,
                    'remote' => true,
                    'enabled' => true,
                ],
            ]);
            sinkholeTestAssertSame(
                'Jacky’s Café alert',
                config_get_path('installedpackages/sinkhole/alerts/item/0/descr'),
                'An alert description must survive the pfSense XML round trip in CDATA.',
            );
            sinkholeTestAssertSame(
                [$listIdentifiers[1]],
                config_get_path('installedpackages/sinkhole/alerts/item/0/lists/item'),
                'Alert list values must be stored under item.',
            );
            sinkholeTestAssertSame(
                [$networkIdentifier],
                config_get_path('installedpackages/sinkhole/alerts/item/0/networks/item'),
                'Alert network values must be stored under item.',
            );
            sinkholeTestAssertSame(
                [$deviceIdentifier],
                config_get_path('installedpackages/sinkhole/alerts/item/0/devices/item'),
                'Alert device values must be stored under item.',
            );
            $alertConfiguration = $adapter->getAlertPartitions();
            sinkholeTestAssertSame(
                'Jacky’s Café alert',
                $alertConfiguration['alerts'][$alertIdentifier]['description'],
                'The alert reader must normalize the CDATA description.',
            );

            pfsensePackageSinkholeSaveBlockedServices([
                'global' => ['invented-global-service', 'retired-invented-service'],
                'networks' => [$networkIdentifier => ['invented-network-service']],
                'devices' => [$deviceIdentifier => ['invented-device-service']],
            ]);
            sinkholeTestAssertSame(
                ['invented-global-service', 'retired-invented-service'],
                config_get_path('installedpackages/sinkhole/services/global/item'),
                'Global service IDs must survive the pfSense XML round trip under item.',
            );
            sinkholeTestAssertSame(
                ['invented-network-service'],
                config_get_path('installedpackages/sinkhole/services/networks/item/0/services/item'),
                'Network service IDs must survive the pfSense XML round trip under item.',
            );
            sinkholeTestAssertSame(
                ['invented-device-service'],
                config_get_path('installedpackages/sinkhole/services/devices/item/0/services/item'),
                'Device service IDs must survive the pfSense XML round trip under item.',
            );
            $blockedServices = $adapter->getBlockedServices();
            sinkholeTestAssertSame(
                ['invented-global-service', 'retired-invented-service'],
                $blockedServices['global'],
                'Unknown service IDs must remain readable for repair.',
            );

            $compiler = new Compiler(
                $paths,
                new SavedListStore($paths),
                $stateStore,
            );
            $result = $compiler->compile(
                $adapter->getLists(),
                $adapter->getAllowedDomains(),
                false,
                true,
                null,
                false,
                null,
                $scopeConfiguration['networks'],
                $scopeConfiguration['devices'],
                $alertConfiguration['alerts'],
                $blockedServices,
            );
            $manifest = json_decode(
                (string) file_get_contents($paths->runtimeDataDirectory . '/manifest.json'),
                true,
                32,
                JSON_THROW_ON_ERROR,
            );

            sinkholeTestAssertSame(3, $result['lists'], 'Every assigned list must compile.');
            sinkholeTestAssertSame(
                [
                    'id' => $alertIdentifier,
                    'lists' => [1],
                    'networks' => [$networkIdentifier],
                    'devices' => [$deviceIdentifier],
                ],
                $manifest['alerts'][$alertIdentifier],
                'The manifest must compile list bits and selected client scope IDs.',
            );
            sinkholeTestAssertSame(
                [$listIdentifiers[0], $listIdentifiers[1]],
                $manifest['scopes']['networks'][$networkIdentifier]['lists'],
                'The compiled network scope must retain its repeated list values.',
            );
            sinkholeTestAssertSame(
                [$listIdentifiers[1], $listIdentifiers[2]],
                $manifest['scopes']['devices'][$deviceIdentifier]['lists'],
                'The compiled device scope must retain its repeated list values.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'configuration stub rejects invalid XML element names' => static function (): void {
        sinkholeStubReset([
            'installedpackages' => [
                'sinkhole' => [
                    'invalid_children' => ['value'],
                ],
            ],
        ]);
        $threw = false;

        try {
            write_config('Invalid XML fixture.');
        } catch (RuntimeException) {
            $threw = true;
        }

        sinkholeTestAssertSame(
            true,
            $threw,
            'The stub must reject numeric child element names outside list tags.',
        );
    },
    'background cache clear waits for loaded generation and reloads Unbound' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubLogs;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            mkdir($paths->runtimeStateDirectory, 0755, true);
            file_put_contents($paths->loadedGenerationFile, "generation-reload\n");
            (new PfSenseAdapter($paths, null, 0))->reloadUnboundAfterDeploy(
                'generation-reload',
            );

            sinkholeTestAssertSame(
                '/usr/sbin/chroot -u unbound -g unbound / '
                . '/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf reload',
                PfSenseAdapter::UNBOUND_RELOAD_COMMAND,
                'The reload command constant must remain fixed.',
            );
            sinkholeTestAssertSame(
                [PfSenseAdapter::UNBOUND_RELOAD_COMMAND],
                $sinkholeStubCommands,
                'A loaded deployment must run only the fixed reload command.',
            );
            sinkholeTestAssertSame([], $sinkholeStubLogs, 'A loaded deployment must not time out.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'background cache clear timeout still reloads Unbound' => static function (): void {
        global $sinkholeStubCommands;
        global $sinkholeStubLogs;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            (new PfSenseAdapter($paths, null, 0))->reloadUnboundAfterDeploy(
                'generation-timeout',
            );

            sinkholeTestAssertSame(
                [PfSenseAdapter::UNBOUND_RELOAD_COMMAND],
                $sinkholeStubCommands,
                'A marker timeout must still run the fixed reload command.',
            );
            sinkholeTestAssertTrue(
                count(array_filter(
                    $sinkholeStubLogs,
                    static fn(string $message): bool => str_contains(
                        $message,
                        'reloading it to clear its cache anyway',
                    ),
                )) === 1,
                'A marker timeout must log one warning.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'timed-out sync retries once and applies its pending work' => static function (): void {
        global $sinkholeStubLogObserver;
        global $sinkholeStubLogs;

        $directory = sinkholeTestTemporaryDirectory();
        $runtimeHandle = null;

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $adapter = sinkholeAdapterTestWithClientMap($paths);
            pfsensePackageSinkholeAdapter($adapter);
            $runtimeHandle = fopen($paths->runtimeLockFile, 'c+');

            if ($runtimeHandle === false || flock($runtimeHandle, LOCK_EX | LOCK_NB) === false) {
                throw new RuntimeException('Unable to hold the runtime lock fixture.');
            }

            $sinkholeStubLogObserver = static function (string $message) use (
                &$runtimeHandle,
            ): void {
                if (
                    !str_contains($message, 'synchronization is pending')
                    || !is_resource($runtimeHandle)
                ) {
                    return;
                }

                flock($runtimeHandle, LOCK_UN);
                fclose($runtimeHandle);
                $runtimeHandle = null;
            };

            $startedAt = microtime(true);
            pfsensePackageSinkholeSync(0);
            $elapsed = microtime(true) - $startedAt;

            sinkholeTestAssertTrue($elapsed < 1.0, 'A zero-second test wait must remain bounded.');
            sinkholeTestAssertSame(
                false,
                (new StateStore($paths->stateFile))->syncPending(),
                'The one-shot retry must consume pending integration work.',
            );
            sinkholeTestAssertSame(
                true,
                file_exists($paths->runtimeScriptFile),
                'The one-shot retry must apply integration after acquiring the lock.',
            );
            sinkholeTestAssertTrue(
                count(array_filter(
                    $sinkholeStubLogs,
                    static fn(string $message): bool => str_contains(
                        $message,
                        'synchronization is pending',
                    ),
                )) >= 1,
                'A timed-out Sync must explain its pending state.',
            );
        } finally {
            $sinkholeStubLogObserver = null;

            if (is_resource($runtimeHandle)) {
                flock($runtimeHandle, LOCK_UN);
                fclose($runtimeHandle);
            }

            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'removal keeps persistent data while an update owns its lock' => static function (): void {
        global $sinkholeStubLogs;

        $directory = sinkholeTestTemporaryDirectory();
        $updateHandle = null;

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'keep_settings' => '',
                        ]],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => '',
                    'python_script' => '',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $adapter = new PfSenseAdapter($paths);
            pfsensePackageSinkholeAdapter($adapter);
            $adapter->enableDnsResolverIntegration();
            file_put_contents($paths->persistentDirectory . '/saved.test', 'saved');
            file_put_contents($paths->alertLockFile, '');
            file_put_contents($paths->clientLockFile, '');
            file_put_contents($paths->runtimeLockFile, '');
            file_put_contents($paths->statusFile, '{"status":"test"}');
            file_put_contents($paths->statusLockFile, '');
            mkdir($paths->catalogCacheDirectory, 0700);
            file_put_contents($paths->adGuardHomeCatalogCacheFile, 'cached');
            file_put_contents($paths->pfBlockerNgCatalogCacheFile, 'cached');
            file_put_contents($paths->serviceRegistryCacheFile, 'cached');
            $updateHandle = fopen($paths->updateLockFile, 'c+');

            if ($updateHandle === false || flock($updateHandle, LOCK_EX | LOCK_NB) === false) {
                throw new RuntimeException('Unable to hold the update lock fixture.');
            }

            pfsensePackageSinkholeRemove(0);

            sinkholeTestAssertTrue(
                is_file($paths->persistentDirectory . '/saved.test'),
                'A busy update lock must preserve saved data.',
            );
            sinkholeTestAssertTrue(
                is_array(config_get_path('installedpackages/sinkhole', null)),
                'A busy update lock must preserve package configuration.',
            );
            sinkholeTestAssertSame(
                '',
                config_get_path('unbound/python_script'),
                'Removal must still restore the Resolver.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeScriptFile),
                'Removal must still remove runtime integration.',
            );
            foreach ([
                $paths->alertLockFile,
                $paths->clientLockFile,
                $paths->runtimeLockFile,
                $paths->statusFile,
                $paths->statusLockFile,
            ] as $removedRuntimeFile) {
                sinkholeTestAssertSame(
                    false,
                    file_exists($removedRuntimeFile),
                    'Removal must delete the released lock and status files.',
                );
            }
            sinkholeTestAssertSame(
                false,
                file_exists($paths->adGuardHomeCatalogCacheFile)
                    || file_exists($paths->pfBlockerNgCatalogCacheFile)
                    || file_exists($paths->serviceRegistryCacheFile),
                'Package removal must delete all transient catalog caches.',
            );
            sinkholeTestAssertTrue(
                count(array_filter(
                    $sinkholeStubLogs,
                    static fn(string $message): bool => str_contains(
                        $message,
                        'keeping saved data',
                    ),
                )) >= 1,
                'Removal must log why persistent data was retained.',
            );
        } finally {
            if (is_resource($updateHandle)) {
                flock($updateHandle, LOCK_UN);
                fclose($updateHandle);
            }

            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'removal restores Resolver after an alert lock timeout' => static function (): void {
        global $sinkholeStubLogs;

        $directory = sinkholeTestTemporaryDirectory();
        $alertHandle = null;

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'keep_settings' => '',
                        ]],
                    ],
                ],
                'unbound' => [
                    'enable' => '',
                    'python' => '',
                    'python_order' => '',
                    'python_script' => '',
                ],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $adapter = new PfSenseAdapter($paths);
            pfsensePackageSinkholeAdapter($adapter);
            $adapter->enableDnsResolverIntegration();
            file_put_contents($paths->persistentDirectory . '/saved.test', 'saved');
            $alertHandle = fopen($paths->alertLockFile, 'c+');

            if ($alertHandle === false || flock($alertHandle, LOCK_EX | LOCK_NB) === false) {
                throw new RuntimeException('Unable to hold the alert lock fixture.');
            }

            pfsensePackageSinkholeRemove(0);

            sinkholeTestAssertSame(
                '',
                config_get_path('unbound/python_script'),
                'An alert timeout must not strand Resolver ownership.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->runtimeScriptFile),
                'An alert timeout must not strand runtime integration.',
            );
            sinkholeTestAssertTrue(
                is_file($paths->persistentDirectory . '/saved.test'),
                'A timed-out alert owner may keep only persistent data.',
            );
            sinkholeTestAssertTrue(
                count(array_filter(
                    $sinkholeStubLogs,
                    static fn(string $message): bool => str_contains(
                        $message,
                        'restoring the Resolver now',
                    ),
                )) >= 1,
                'Removal must explain that it proceeded after the timeout.',
            );
        } finally {
            if (is_resource($alertHandle)) {
                flock($alertHandle, LOCK_UN);
                fclose($alertHandle);
            }

            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'removing the last alert cron entry clears block history' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'alerts' => ['item' => []],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $adapter = new PfSenseAdapter($paths);
            pfsensePackageSinkholeAdapter($adapter);
            FileSystem::ensureDirectory($paths->runtimeStateDirectory, 0700);

            foreach ([
                $paths->eventsFile,
                $paths->eventsProcessingFile,
                $paths->eventsDroppedFile,
            ] as $path) {
                file_put_contents($path, "fixture\n");
            }

            file_put_contents($paths->alertRepeatStateFile, "{}\n");
            pfsensePackageSinkholeInstallCron();

            foreach ([
                $paths->eventsFile,
                $paths->eventsProcessingFile,
                $paths->eventsDroppedFile,
                $paths->alertRepeatStateFile,
            ] as $path) {
                sinkholeTestAssertSame(
                    false,
                    file_exists($path) || is_link($path),
                    'Last-rule cleanup must delete ' . $path . '.',
                );
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'uninstall removes repeat state even when integration cleanup fails' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            mkdir(dirname($paths->runtimeScriptFile), 0755, true);
            mkdir($paths->runtimeScriptFile, 0755);
            file_put_contents($paths->alertRepeatStateFile, "{}\n");
            file_put_contents($paths->statusFile, "{}\n");
            $adapter = new PfSenseAdapter($paths);
            $threw = false;
            set_error_handler(static fn(): bool => true);

            try {
                $adapter->uninstall(true, true);
            } catch (RuntimeException) {
                $threw = true;
            } finally {
                restore_error_handler();
            }

            sinkholeTestAssertTrue($threw, 'The runtime cleanup fixture must fail.');
            sinkholeTestAssertSame(
                false,
                file_exists($paths->alertRepeatStateFile),
                'Repeat state deletion must be an independent uninstall step.',
            );
            sinkholeTestAssertSame(
                false,
                file_exists($paths->statusFile),
                'Transient status must be removed independently too.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'runtime state deletion unlinks fixed names without following links' => static function (): void {
        global $sinkholeStubLogs;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $stateDirectory = $directory . '/state';
            $externalFile = $directory . '/external-marker';
            mkdir($stateDirectory, 0755);
            file_put_contents($externalFile, 'preserved');
            symlink($externalFile, $stateDirectory . '/loaded');
            file_put_contents(
                $stateDirectory . '/.loaded-0123456789abcdef0123456789abcdef',
                'temporary',
            );
            FileSystem::removeRuntimeStateDirectory($stateDirectory);

            sinkholeTestAssertSame(
                false,
                file_exists($stateDirectory),
                'Only fixed marker names must be removed before rmdir.',
            );
            sinkholeTestAssertTrue(
                is_file($externalFile),
                'A fixed marker symlink must not remove its target.',
            );

            $stubbornState = $directory . '/stubborn-state';
            $temporaryTarget = $directory . '/temporary-target';
            mkdir($stubbornState, 0755);
            file_put_contents($temporaryTarget, 'preserved');
            symlink(
                $temporaryTarget,
                $stubbornState . '/.loaded-fedcba9876543210fedcba9876543210',
            );
            $sinkholeStubLogs = [];
            FileSystem::removeRuntimeStateDirectory($stubbornState);
            sinkholeTestAssertTrue(
                is_link($stubbornState . '/.loaded-fedcba9876543210fedcba9876543210'),
                'A matching temporary-marker symlink must not be followed or unlinked.',
            );
            sinkholeTestAssertTrue(is_file($temporaryTarget), 'A temporary link target must remain.');
            sinkholeTestAssertTrue(
                count(array_filter(
                    $sinkholeStubLogs,
                    static fn(string $message): bool => str_contains(
                        $message,
                        'non-empty runtime state directory',
                    ),
                )) === 1,
                'A non-empty runtime state directory must log its failed rmdir.',
            );

            $externalDirectory = $directory . '/external-state';
            $stateLink = $directory . '/state-link';
            mkdir($externalDirectory, 0755);
            file_put_contents($externalDirectory . '/preserved', 'preserved');
            symlink($externalDirectory, $stateLink);
            FileSystem::removeRuntimeStateDirectory($stateLink);

            sinkholeTestAssertSame(false, is_link($stateLink), 'A state symlink must be unlinked.');
            sinkholeTestAssertTrue(
                is_file($externalDirectory . '/preserved'),
                'A state symlink target must never be traversed.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'runtime cleanup continues after an earlier removal failure' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            $stateStore = new StateStore($paths->stateFile);
            $stateStore->recordDeployment(
                'generation-cleanup',
                str_repeat('a', 64),
            );
            $stateStore->markCacheClearOwed('generation-cleanup');
            mkdir(dirname($paths->runtimeScriptFile), 0755, true);
            mkdir($paths->runtimeScriptFile, 0755);
            mkdir($paths->mirrorRootDirectory, 0755, true);
            file_put_contents($paths->mirrorRootDirectory . '/boot-copy', 'copy');
            $adapter = new PfSenseAdapter($paths, $stateStore);
            $threw = false;
            set_error_handler(static fn(): bool => true);

            try {
                $adapter->disableDnsResolverIntegration(true);
            } catch (RuntimeException) {
                $threw = true;
            } finally {
                restore_error_handler();
            }

            $state = $stateStore->read();
            sinkholeTestAssertTrue($threw, 'The first runtime removal failure must be reported.');
            sinkholeTestAssertSame(
                false,
                file_exists($paths->mirrorRootDirectory),
                'A module-removal failure must not leave the boot mirror behind.',
            );
            sinkholeTestAssertSame(
                null,
                $state['deployed_generation'],
                'Deployment state must clear after a runtime removal failure.',
            );
            sinkholeTestAssertSame(
                null,
                $state['flush_owed_generation'],
                'Disablement must clear cache-clear debt after a removal failure.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'sync compiles saved data before enabling Python without reload debt' => static function (): void {
        global $sinkholeStubConfigSetObserver;
        global $sinkholeStubCommands;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $identifier = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
            sinkholeStubReset([
                'installedpackages' => [
                    'sinkhole' => [
                        'config' => [[
                            'enabled' => 'on',
                            'update_frequency' => 'daily',
                        ]],
                        'lists' => [
                            'item' => [[
                                'id' => $identifier,
                                'descr' => 'Reinstall Example',
                                'url' => 'https://lists.example.invalid/reinstall.test',
                                'enabled' => 'on',
                            ]],
                        ],
                    ],
                ],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            mkdir($paths->listDirectory, 0700, true);
            file_put_contents(
                $paths->listFile($identifier),
                "E\treinstall.example.test\n",
            );
            $sawPythonEnable = false;
            $sinkholeStubConfigSetObserver = static function (
                string $path,
                mixed $value,
            ) use ($paths, &$sawPythonEnable): void {
                if ($path !== 'unbound/python' || $value !== true) {
                    return;
                }

                $sawPythonEnable = true;
                $generationPath = FileSystem::resolveManagedGeneration(
                    $paths->runtimeDataDirectory,
                    $paths->runtimeStorageDirectory,
                );
                sinkholeTestAssertTrue(
                    is_string($generationPath)
                    && is_file($generationPath . '/generation'),
                    'Saved data must be deployed before Python is enabled.',
                );
                sinkholeTestAssertTrue(
                    is_file($paths->runtimeClientMapFile),
                    'The client map must be published before Python is enabled.',
                );
            };
            pfsensePackageSinkholeAdapter(sinkholeAdapterTestWithClientMap($paths));

            pfsensePackageSinkholeSync(0);

            sinkholeTestAssertSame(true, $sawPythonEnable, 'Sync must enable the Python setting.');
            sinkholeTestAssertSame(
                'sinkhole',
                config_get_path('unbound/python_script'),
                'Sync must finish with Sinkhole owning the slot.',
            );
            sinkholeTestAssertSame(
                null,
                (new StateStore($paths->stateFile))->cacheClearOwedGeneration(),
                'A fresh Resolver start must satisfy the deployment cache clear.',
            );
            sinkholeTestAssertSame(
                false,
                in_array(PfSenseAdapter::UNBOUND_RELOAD_COMMAND, $sinkholeStubCommands, true),
                'Fresh deployment must not reload the newly started Resolver again.',
            );
        } finally {
            $sinkholeStubConfigSetObserver = null;
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'status validates the update PID file path and explains inactivity' => static function (): void {
        global $sinkholeStubValidPidFiles;

        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAdapterTestPaths($directory);
            file_put_contents($paths->updateLockFile, (string) getmypid());

            sinkholeTestAssertSame(
                true,
                pfsensePackageSinkholeUpdateRunning($paths),
                'A PID read from the update lock file must be reported as running.',
            );
            sinkholeTestAssertSame(
                [$paths->updateLockFile],
                $sinkholeStubValidPidFiles,
                'Status must pass the PID file path to pfSense validation.',
            );

            $presentation = pfsensePackageSinkholeStatusPresentation(
                [
                    'active' => false,
                    'owner' => '',
                    'reason' => 'DNS Resolver is disabled.',
                ],
                true,
                false,
                'The deployed content digest differs from the compiled content digest.',
                'generation-from-old-module',
            );
            sinkholeTestAssertSame(
                'Inactive: DNS Resolver is disabled.',
                $presentation['deployment_reason'],
                'Inactive deployment warnings must show the Resolver reason.',
            );
            sinkholeTestAssertSame(
                'Module not loaded.',
                $presentation['loaded_generation'],
                'An inactive integration must not present a stale loaded marker.',
            );

            $disabledPresentation = pfsensePackageSinkholeStatusPresentation(
                [
                    'active' => false,
                    'owner' => '',
                    'reason' => 'Sinkhole is disabled.',
                ],
                false,
                true,
                'The deployed content digest differs from the compiled content digest.',
                'generation-from-old-module',
            );
            sinkholeTestAssertSame(
                false,
                $disabledPresentation['deployment_needed'],
                'A deliberately disabled package must not report deployment pending.',
            );
            sinkholeTestAssertSame(
                '',
                $disabledPresentation['deployment_reason'],
                'A deliberately disabled package must not retain a deployment warning reason.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
]);
