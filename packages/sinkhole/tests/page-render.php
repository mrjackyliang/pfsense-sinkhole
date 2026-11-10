<?php

declare(strict_types=1);

use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\FileSystem;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\PfSenseAdapter;
use PfSense\Sinkhole\Runtime\StateStore;

require_once(__DIR__ . '/TestSupport.php');

/** @since 1.0.0 */
function sinkholePageRenderPaths(string $root): PackagePaths
{
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
        'alert_repeat_state_file' => $root . '/alerts.json',
        'catalog_cache_directory' => $root . '/catalogs',
        'ip_table_ipv4_file' => $root . '/sinkhole-ip-v4.txt',
        'ip_table_ipv6_file' => $root . '/sinkhole-ip-v6.txt',
        'ip_anchor_file' => $root . '/sinkhole-ip-anchor.conf',
        'ip_anchor_digest_file' => $root . '/sinkhole-ip-anchor.sha256',
        'bypass_table_ipv4_file' => $root . '/sinkhole-bypass-v4.txt',
        'bypass_table_ipv6_file' => $root . '/sinkhole-bypass-v6.txt',
        'bypass_anchor_file' => $root . '/sinkhole-bypass-anchor.conf',
        'bypass_anchor_digest_file' => $root . '/sinkhole-bypass-anchor.sha256',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/**
 * Returns one isolated page fixture.
 *
 * @return array{
 *     page: string,
 *     configuration: array<string, mixed>,
 *     get: array<string, string>,
 *     post: array<string, string>,
 *     privileges: list<string>,
 *     globals: array<string, mixed>,
 *     runtime: string,
 *     update_state: array<string, mixed>|null,
 *     expected_background_commands: list<string>,
 *     state: list<array{path: list<int|string>, expected?: mixed, expected_count?: int}>,
 *     expected: list<string>,
 *     unexpected: list<string>
 * }
 *
 * @since 1.0.0
 */
function sinkholePageRenderFixture(string $name): array
{
    $listOne = str_repeat('a', 32);
    $listTwo = str_repeat('b', 32);
    $listThree = str_repeat('c', 32);
    $networkOne = str_repeat('d', 32);
    $networkTwo = str_repeat('e', 32);
    $deviceOne = str_repeat('f', 32);
    $deviceTwo = str_repeat('1', 32);
    $alertOne = str_repeat('2', 32);
    $alertTwo = str_repeat('3', 32);
    $listRows = [
        [
            'id' => $listOne,
            'descr' => 'Invented enabled list',
            'url' => 'https://example.test/enabled.txt',
            'enabled' => 'on',
            'global' => 'on',
        ],
        [
            'id' => $listTwo,
            'descr' => 'Invented disabled list',
            'url' => 'https://example.test/disabled.txt',
            'enabled' => '',
            'global' => '',
        ],
    ];
    $ipListRows = [
        [
            'id' => $listOne,
            'descr' => 'Invented IPv4 list',
            'url' => 'https://example.test/ipv4.txt',
            'enabled' => 'on',
            'family' => 'ipv4',
        ],
        [
            'id' => $listTwo,
            'descr' => 'Invented IPv6 list',
            'url' => 'https://example.test/ipv6.txt',
            'enabled' => '',
            'family' => 'ipv6',
        ],
        [
            'id' => $listThree,
            'descr' => 'Invented dual-family list',
            'url' => 'https://example.test/both.txt',
            'enabled' => 'on',
            'family' => 'both',
        ],
    ];
    $bypassListRows = [
        [
            'id' => $listOne,
            'descr' => 'Invented encrypted DNS list',
            'url' => 'https://example.test/encrypted-dns.txt',
            'enabled' => 'on',
            'kind' => 'encrypted_dns',
        ],
        [
            'id' => $listTwo,
            'descr' => 'Invented VPN list',
            'url' => 'https://example.test/vpn.txt',
            'enabled' => '',
            'kind' => 'vpn',
        ],
    ];
    $networkRows = [
        [
            'id' => $networkOne,
            'interface' => 'lan',
            'lists' => ['item' => [$listOne]],
            'allowed_domains' => ['item' => []],
            'enabled' => 'on',
        ],
        [
            'id' => $networkTwo,
            'interface' => 'opt1',
            'lists' => ['item' => [$listTwo]],
            'allowed_domains' => ['item' => []],
            'enabled' => '',
        ],
    ];
    $deviceRows = [
        [
            'id' => $deviceOne,
            'descr' => 'Invented enabled device',
            'identifier_type' => 'ip',
            'identifier' => '192.0.2.10',
            'interface' => '',
            'lists' => ['item' => [$listOne]],
            'allowed_domains' => ['item' => []],
            'enabled' => 'on',
        ],
        [
            'id' => $deviceTwo,
            'descr' => 'Invented disabled device',
            'identifier_type' => 'mac',
            'identifier' => '02:00:00:00:00:02',
            'interface' => '',
            'lists' => ['item' => [$listTwo]],
            'allowed_domains' => ['item' => []],
            'enabled' => '',
        ],
    ];
    $alertRows = [
        [
            'id' => $alertOne,
            'descr' => 'Invented enabled alert',
            'lists_any' => 'on',
            'lists' => ['item' => []],
            'clients_everyone' => 'on',
            'networks' => ['item' => []],
            'devices' => ['item' => []],
            'repeat_minutes' => '60',
            'notice' => 'on',
            'remote' => '',
            'enabled' => 'on',
        ],
        [
            'id' => $alertTwo,
            'descr' => 'Invented disabled alert',
            'lists_any' => '',
            'lists' => ['item' => [$listOne]],
            'clients_everyone' => '',
            'networks' => ['item' => [$networkOne]],
            'devices' => ['item' => [$deviceOne]],
            'repeat_minutes' => '120',
            'notice' => '',
            'remote' => 'on',
            'enabled' => '',
        ],
    ];
    $configuration = [
        'aliases' => [
            'alias' => [],
        ],
        'installedpackages' => [
            'package' => [[
                'name' => 'Sinkhole',
                'version' => '0.0.15',
            ]],
            'sinkhole' => [
                'config' => [[
                    'enabled' => 'on',
                    'update_frequency' => 'daily',
                    'keep_settings' => 'on',
                ]],
                'lists' => ['item' => $listRows],
                'allowed_domains' => ['item' => ['allowed.example.test']],
                'networks' => ['item' => $networkRows],
                'devices' => ['item' => $deviceRows],
                'alerts' => ['item' => $alertRows],
                'services' => [
                    'global' => ['item' => [
                        'invented-video',
                        'retired-invented-service',
                        'icloud_private_relay',
                    ]],
                    'networks' => ['item' => [[
                        'id' => $networkOne,
                        'services' => ['item' => ['invented-video']],
                    ]]],
                    'devices' => ['item' => []],
                ],
                'redirect' => [
                    'enabled' => 'on',
                    'interfaces' => ['item' => ['lan']],
                    'exempt_sources' => ['item' => []],
                    'exempt_destinations' => ['item' => []],
                ],
                'bypass' => [
                    'block_tls_quic' => 'on',
                    'block_encrypted_dns' => 'on',
                    'disable_firefox_doh' => 'on',
                    'disable_private_relay' => 'on',
                    'discovery' => 'nodata',
                    'block_tor' => 'on',
                    'block_vpn' => 'on',
                    'block_vpn_ports' => 'on',
                    'lists' => ['item' => $bypassListRows],
                ],
                'ip' => [
                    'enabled' => 'on',
                    'interfaces' => ['item' => ['lan']],
                    'directions' => ['item' => ['inbound', 'outbound']],
                    'lists' => ['item' => $ipListRows],
                    'countries' => ['item' => []],
                    'account_id' => '12345',
                    'license_key' => 'invented-license-key',
                    'allowlist' => ['item' => []],
                ],
            ],
        ],
        'unbound' => [
            'enable' => 'on',
            'python' => 'on',
            'python_order' => 'pre_validator',
            'python_script' => 'sinkhole',
            'active_interface' => 'all',
            'custom_options' => base64_encode(
                '# Sinkhole: begin (managed by the Sinkhole package)' . "\n"
                    . 'server:' . "\n"
                    . 'local-zone: "_dns.resolver.arpa." transparent' . "\n"
                    . '# Sinkhole: end',
            ),
        ],
    ];

    $base = [
        'configuration' => $configuration,
        'get' => [],
        'post' => [],
        'privileges' => ['page-all'],
        'globals' => [
            'product_label' => 'pfSense CE',
            'product_version' => '2.9.0-RELEASE',
        ],
        'runtime' => 'none',
        'update_state' => null,
        'expected_background_commands' => [],
        'state' => [],
        'expected' => [],
        'unexpected' => [],
    ];

    if ($name === 'lists-list') {
        return array_replace($base, [
            'page' => 'sinkhole-lists.php',
            'state' => [[
                'path' => ['lists'],
                'expected_count' => 2,
            ]],
            'expected' => [
                'Invented enabled list',
                'Invented disabled list',
                'sinkhole-lists_edit.php?id=' . $listOne,
                'table-rowdblclickedit',
                'class="disabled"',
            ],
        ]);
    }

    if ($name === 'lists-catalog') {
        return array_replace($base, [
            'page' => 'sinkhole-lists.php',
            'get' => ['catalog' => '1'],
            'state' => [[
                'path' => ['catalogResults'],
                'expected_count' => 2,
            ]],
            'expected' => [
                'Invented Catalog Hosts',
                'Invented Catalog DNS',
                'Contents: Domains',
                'Group By',
                'All (2)',
                'Other (2)',
                'name="catalog_category"',
                'name="catalog_group_by"',
                'sinkhole-catalog-card',
                'fa-solid fa-arrows-rotate',
            ],
            'unexpected' => [
                'Invented Catalog Encrypted DNS',
                'Invented Catalog Tor',
                'Invented Catalog VPN',
            ],
        ]);
    }

    if ($name === 'lists-empty') {
        $emptyConfiguration = $configuration;
        $emptyConfiguration['installedpackages']['sinkhole']['lists']['item'] = [];

        return array_replace($base, [
            'page' => 'sinkhole-lists.php',
            'configuration' => $emptyConfiguration,
            'state' => [[
                'path' => ['lists'],
                'expected_count' => 0,
            ]],
            'expected' => ['<td colspan="6" class="text-muted">No block lists are configured.</td>'],
        ]);
    }

    if ($name === 'lists-edit-add' || $name === 'lists-edit') {
        $get = [];
        $state = [[
            'path' => ['editing'],
            'expected' => null,
        ]];

        if ($name === 'lists-edit') {
            $get['id'] = $listOne;
            $state[0] = [
                'path' => ['editing', 'id'],
                'expected' => $listOne,
            ];
        }

        return array_replace($base, [
            'page' => 'sinkhole-lists_edit.php',
            'get' => $get,
            'state' => $state,
            'expected' => ['data-sinkhole-test-form'],
        ]);
    }

    if ($name === 'scopes-list') {
        return array_replace($base, [
            'page' => 'sinkhole-scopes.php',
            'state' => [
                ['path' => ['networks'], 'expected_count' => 2],
                ['path' => ['devices'], 'expected_count' => 2],
            ],
            'expected' => [
                'Invented enabled device',
                'Invented disabled device',
                'sinkhole-scopes_edit.php?type=network&amp;id=' . $networkOne,
                'sinkhole-scopes_edit.php?type=device&amp;id=' . $deviceOne,
                'table-rowdblclickedit',
                'class="disabled"',
            ],
        ]);
    }

    if ($name === 'scopes-empty') {
        $emptyConfiguration = $configuration;
        $emptyConfiguration['installedpackages']['sinkhole']['networks']['item'] = [];
        $emptyConfiguration['installedpackages']['sinkhole']['devices']['item'] = [];

        return array_replace($base, [
            'page' => 'sinkhole-scopes.php',
            'configuration' => $emptyConfiguration,
            'state' => [
                ['path' => ['networks'], 'expected_count' => 0],
                ['path' => ['devices'], 'expected_count' => 0],
            ],
            'expected' => [
                '<td colspan="5" class="text-muted">No networks are configured.</td>',
                '<td colspan="7" class="text-muted">No devices are configured.</td>',
            ],
        ]);
    }

    if (in_array($name, [
        'scopes-edit-network-add',
        'scopes-edit-network',
        'scopes-edit-device-add',
        'scopes-edit-device',
    ], true)) {
        $scopeType = str_contains($name, 'device') ? 'device' : 'network';
        $get = ['type' => $scopeType];
        $editorConfiguration = $configuration;
        $state = [
            ['path' => ['scopeType'], 'expected' => $scopeType],
            ['path' => ['editing'], 'expected' => null],
        ];

        if ($name === 'scopes-edit-network') {
            $get['id'] = $networkOne;
            $state[1] = ['path' => ['editing', 'id'], 'expected' => $networkOne];
        } elseif ($name === 'scopes-edit-device') {
            $get['id'] = $deviceOne;
            $state[1] = ['path' => ['editing', 'id'], 'expected' => $deviceOne];
        } elseif ($name === 'scopes-edit-network-add') {
            $editorConfiguration['installedpackages']['sinkhole']['networks']['item'] = [
                $networkRows[1],
            ];
            $state[] = ['path' => ['networkInterface'], 'expected' => 'lan'];
            $state[] = ['path' => ['interfaceOptions'], 'expected' => ['lan' => 'LAN']];
        }

        return array_replace($base, [
            'page' => 'sinkhole-scopes_edit.php',
            'configuration' => $editorConfiguration,
            'get' => $get,
            'state' => $state,
            'expected' => ($scopeType === 'device')
                ? ["hideInput('device_identifier'", "hideInput('device_static_mapping'"]
                : ['data-sinkhole-test-form'],
        ]);
    }

    if ($name === 'services') {
        return array_replace($base, [
            'page' => 'sinkhole-services.php',
            'state' => [
                [
                    'path' => ['selectedScope'],
                    'expected' => 'global',
                ],
                [
                    'path' => ['unknownServices'],
                    'expected_count' => 1,
                ],
                [
                    'path' => ['selectedServices'],
                    'expected_count' => 2,
                ],
            ],
            'expected' => [
                'Invented Video',
                'Invented media',
                'retired-invented-service',
                'Needs Repair',
                'data:image/svg+xml;base64,',
                'class="chkboxlbl sinkhole-service-choice"',
                'fa-solid fa-arrows-rotate',
            ],
            'unexpected' => [
                'sinkhole-service-switch',
                'sinkhole-service-slider',
                'Invented Private Relay Service',
                'icloud_private_relay',
            ],
        ]);
    }

    if ($name === 'alerts-list') {
        return array_replace($base, [
            'page' => 'sinkhole-alerts.php',
            'state' => [[
                'path' => ['alerts'],
                'expected_count' => 2,
            ]],
            'expected' => [
                'Invented enabled alert',
                'Invented disabled alert',
                'sinkhole-alerts_edit.php?id=' . $alertOne,
                'table-rowdblclickedit',
                'class="disabled"',
            ],
        ]);
    }

    if ($name === 'alerts-empty') {
        $emptyConfiguration = $configuration;
        $emptyConfiguration['installedpackages']['sinkhole']['alerts']['item'] = [];

        return array_replace($base, [
            'page' => 'sinkhole-alerts.php',
            'configuration' => $emptyConfiguration,
            'state' => [[
                'path' => ['alerts'],
                'expected_count' => 0,
            ]],
            'expected' => ['<td colspan="8" class="text-muted">No alert rules are configured.</td>'],
        ]);
    }

    if ($name === 'alerts-edit-add' || $name === 'alerts-edit') {
        $get = [];
        $state = [[
            'path' => ['editing'],
            'expected' => null,
        ]];

        if ($name === 'alerts-edit') {
            $get['id'] = $alertOne;
            $state = [[
                'path' => ['editing', 'id'],
                'expected' => $alertOne,
            ]];
        }

        return array_replace($base, [
            'page' => 'sinkhole-alerts_edit.php',
            'get' => $get,
            'state' => $state,
            'expected' => [
                "hideInput('alert_lists\\\\[\\\\]'",
                "hideInput('alert_networks\\\\[\\\\]'",
                "hideInput('alert_devices\\\\[\\\\]'",
            ],
        ]);
    }

    if ($name === 'ip-list') {
        return array_replace($base, [
            'page' => 'sinkhole-ip.php',
            'state' => [[
                'path' => ['lists'],
                'expected_count' => 3,
            ]],
            'expected' => [
                'Invented IPv4 list',
                'Invented IPv6 list',
                'sinkhole-ip_edit.php?id=' . $listOne,
                'table-rowdblclickedit',
                'class="disabled"',
            ],
        ]);
    }

    if ($name === 'ip-catalog') {
        return array_replace($base, [
            'page' => 'sinkhole-ip.php',
            'get' => ['catalog' => '1'],
            'state' => [[
                'path' => ['catalogResults'],
                'expected_count' => 1,
            ]],
            'expected' => [
                'Invented Catalog IPv4',
                'Contents: IPv4 addresses',
                'Group By',
                'All (1)',
                'Other (1)',
                'name="catalog_category"',
                'name="catalog_group_by"',
                'sinkhole-catalog-card',
                'fa-solid fa-arrows-rotate',
            ],
            'unexpected' => [
                'Invented Catalog Encrypted IPv4',
                'Invented Catalog Tor',
                'Invented Catalog VPN',
            ],
        ]);
    }

    if ($name === 'ip-empty') {
        $emptyConfiguration = $configuration;
        $emptyConfiguration['installedpackages']['sinkhole']['ip']['lists']['item'] = [];

        return array_replace($base, [
            'page' => 'sinkhole-ip.php',
            'configuration' => $emptyConfiguration,
            'state' => [[
                'path' => ['lists'],
                'expected_count' => 0,
            ]],
            'expected' => ['<td colspan="5" class="text-muted">No IP lists are configured.</td>'],
        ]);
    }

    if ($name === 'ip-edit-add' || $name === 'ip-edit') {
        $get = [];
        $state = [[
            'path' => ['editing'],
            'expected' => null,
        ]];

        if ($name === 'ip-edit') {
            $get['id'] = $listThree;
            $state[0] = [
                'path' => ['editing', 'id'],
                'expected' => $listThree,
            ];
        }

        return array_replace($base, [
            'page' => 'sinkhole-ip_edit.php',
            'get' => $get,
            'state' => $state,
            'expected' => ['data-sinkhole-test-form'],
        ]);
    }

    if ($name === 'bypass-list') {
        return array_replace($base, [
            'page' => 'sinkhole-bypass.php',
            'state' => [[
                'path' => ['lists'],
                'expected_count' => 2,
            ]],
            'expected' => [
                'Invented encrypted DNS list',
                'Invented VPN list',
                'sinkhole-bypass_edit.php?id=' . $listOne,
                'table-rowdblclickedit',
                'class="disabled"',
                "hideInput('redirect_exempt_sources'",
            ],
        ]);
    }

    if ($name === 'bypass-empty') {
        $emptyConfiguration = $configuration;
        $emptyConfiguration['installedpackages']['sinkhole']['bypass']['lists']['item'] = [];

        return array_replace($base, [
            'page' => 'sinkhole-bypass.php',
            'configuration' => $emptyConfiguration,
            'state' => [[
                'path' => ['lists'],
                'expected_count' => 0,
            ]],
            'expected' => [
                '<td colspan="7" class="text-muted">No Bypass Lists are configured.</td>',
            ],
        ]);
    }

    if ($name === 'bypass-catalog') {
        return array_replace($base, [
            'page' => 'sinkhole-bypass.php',
            'get' => ['catalog' => '1'],
            'state' => [
                [
                    'path' => ['catalogResults'],
                    'expected_count' => 7,
                ],
                [
                    'path' => ['catalogGroups'],
                    'expected_count' => 3,
                ],
                [
                    'path' => ['catalogGroups', 0, 'key'],
                    'expected' => 'encrypted_dns',
                ],
                [
                    'path' => ['catalogGroups', 1, 'key'],
                    'expected' => 'tor',
                ],
                [
                    'path' => ['catalogGroups', 2, 'key'],
                    'expected' => 'vpn',
                ],
                [
                    'path' => ['catalogKindCounts', ''],
                    'expected' => 7,
                ],
                [
                    'path' => ['catalogKindCounts', 'encrypted_dns'],
                    'expected' => 4,
                ],
                [
                    'path' => ['catalogKindCounts', 'tor'],
                    'expected' => 1,
                ],
                [
                    'path' => ['catalogKindCounts', 'vpn'],
                    'expected' => 2,
                ],
            ],
            'expected' => [
                'Invented Catalog Encrypted DNS',
                'Invented Catalog Tor',
                'Invented Catalog VPN',
                'All (7)',
                'Encrypted DNS (4)',
                'Tor (1)',
                'VPN (2)',
                'Maintainer: catalog.example.test',
                'Source: AdGuard Home',
                'Source: pfBlockerNG',
                'Contents: Domains',
                'Contents: IPv4 addresses',
                'Contents: IPv6 addresses',
                'catalog_kind=encrypted_dns',
                'catalog_kind=tor',
                'catalog_kind=vpn',
                'name="catalog_kind"',
                'sinkhole-catalog-card',
                'fa-solid fa-arrows-rotate',
            ],
            'unexpected' => [
                'Invented Catalog Hosts',
                'Invented Catalog DNS',
                'Invented Catalog IPv4',
                'Group By',
                'Category:',
                'Kind:',
                'name="catalog_category"',
                'name="catalog_group_by"',
            ],
        ]);
    }

    if ($name === 'bypass-edit-add' || $name === 'bypass-edit') {
        $get = [];
        $state = [[
            'path' => ['editing'],
            'expected' => null,
        ]];

        if ($name === 'bypass-edit') {
            $get['id'] = $listOne;
            $state[0] = [
                'path' => ['editing', 'id'],
                'expected' => $listOne,
            ];
        }

        return array_replace($base, [
            'page' => 'sinkhole-bypass_edit.php',
            'get' => $get,
            'state' => $state,
            'expected' => ['data-sinkhole-test-form'],
        ]);
    }

    if ($name === 'ip-invalid-values') {
        $ipConfiguration = $configuration;
        $ipConfiguration['installedpackages']['sinkhole']['ip'] = [
            'enabled' => 'invented-invalid-enable',
            'interfaces' => ['item' => ['lan', 'invented-missing-interface']],
            'directions' => ['item' => ['inbound', 'invented-direction']],
            'lists' => ['item' => $ipListRows],
            'countries' => ['item' => ['US', 'invented-country']],
            'account_id' => 'invented-account',
            'license_key' => "invented\nlicense",
            'allowlist' => ['item' => ['192.0.2.0/24', 'invented-allowlist']],
        ];
        $state = [
            [
                'path' => ['configuration', 'invalid_values'],
                'expected_count' => 7,
            ],
        ];

        return array_replace($base, [
            'page' => 'sinkhole-ip.php',
            'configuration' => $ipConfiguration,
            'state' => $state,
            'expected' => ['Invalid Saved Values', 'IPv4', 'IPv6', 'IPv4 and IPv6'],
        ]);
    }

    if ($name === 'ip-invalid-settings') {
        $ipConfiguration = $configuration;
        $ipConfiguration['installedpackages']['sinkhole']['ip'] = 'invented-invalid-ip-settings';

        return array_replace($base, [
            'page' => 'sinkhole-ip.php',
            'configuration' => $ipConfiguration,
            'state' => [
                [
                    'path' => ['configuration', 'invalid_values'],
                    'expected_count' => 1,
                ],
                [
                    'path' => ['configuration', 'invalid_values', 0, 'field_key'],
                    'expected' => 'ip_country_blocking',
                ],
            ],
            'expected' => ['Invalid Saved Values', 'No IP lists are configured.'],
        ]);
    }

    if ($name === 'bypass-redirect-fields') {
        $redirectConfiguration = $configuration;
        $redirectConfiguration['installedpackages']['sinkhole']['redirect'] = [
            'enabled' => 'invented-invalid-enable',
            'interfaces' => ['item' => ['lan', 'invented-missing-interface']],
            'exempt_sources' => ['item' => ['192.0.2.10', 'Invented_Missing_Source']],
            'exempt_destinations' => [
                'item' => ['203.0.113.53', 'Invented_Missing_Destination'],
            ],
        ];

        return array_replace($base, [
            'page' => 'sinkhole-bypass.php',
            'configuration' => $redirectConfiguration,
            'state' => [
                [
                    'path' => ['redirect', 'invalid_values'],
                    'expected_count' => 4,
                ],
                [
                    'path' => ['redirect', 'invalid_values', 0, 'field_key'],
                    'expected' => 'enable',
                ],
                [
                    'path' => ['redirect', 'invalid_values', 1, 'field_key'],
                    'expected' => 'interface',
                ],
                [
                    'path' => ['redirect', 'invalid_values', 2, 'field_key'],
                    'expected' => 'exempt_source',
                ],
                [
                    'path' => ['redirect', 'invalid_values', 3, 'field_key'],
                    'expected' => 'exempt_destination',
                ],
            ],
            'expected' => [
                'Invalid Saved Values',
                'invented-missing-interface',
                'Invented_Missing_Source',
                'Invented_Missing_Destination',
            ],
        ]);
    }

    if ($name === 'bypass-redirect-collections') {
        $redirectConfiguration = $configuration;
        $redirectConfiguration['installedpackages']['sinkhole']['redirect'] = [
            'interfaces' => ['item' => 'invented-interface-collection'],
            'exempt_sources' => ['item' => 'invented-source-collection'],
            'exempt_destinations' => ['item' => 'invented-destination-collection'],
        ];

        return array_replace($base, [
            'page' => 'sinkhole-bypass.php',
            'configuration' => $redirectConfiguration,
            'state' => [
                [
                    'path' => ['redirect', 'invalid_values'],
                    'expected_count' => 3,
                ],
                [
                    'path' => ['redirect', 'invalid_values', 0, 'field_key'],
                    'expected' => 'interfaces',
                ],
                [
                    'path' => ['redirect', 'invalid_values', 1, 'field_key'],
                    'expected' => 'exempt_sources',
                ],
                [
                    'path' => ['redirect', 'invalid_values', 2, 'field_key'],
                    'expected' => 'exempt_destinations',
                ],
            ],
            'expected' => [
                'Invalid Saved Values',
                'invented-interface-collection',
                'invented-source-collection',
                'invented-destination-collection',
            ],
        ]);
    }

    if ($name === 'bypass-redirect-invalid-settings') {
        $redirectConfiguration = $configuration;
        $redirectConfiguration['installedpackages']['sinkhole']['redirect'] =
            'invented-invalid-redirect-settings';

        return array_replace($base, [
            'page' => 'sinkhole-bypass.php',
            'configuration' => $redirectConfiguration,
            'state' => [
                [
                    'path' => ['redirect', 'invalid_values'],
                    'expected_count' => 1,
                ],
                [
                    'path' => ['redirect', 'invalid_values', 0, 'field_key'],
                    'expected' => 'redirect_settings',
                ],
            ],
            'expected' => ['Invalid Saved Values', 'invented-invalid-redirect-settings'],
        ]);
    }

    if (
        $name === 'about-ce'
        || $name === 'about-plus'
        || $name === 'about-untested'
        || $name === 'about-no-release'
        || $name === 'about-http-failure'
        || $name === 'about-network-failure'
    ) {
        $globals = $base['globals'];
        $expectedEdition = 'CE';
        $expectedVersion = '2.9.0';
        $updateState = null;
        $updateStatus = 'Updates have not been checked yet.';
        $updateStatusIcon = 'fa-solid fa-circle-info';
        $unexpected = [];

        if ($name === 'about-plus') {
            $globals = [
                'product_label' => 'pfSense Plus',
                'product_version' => '26.03.1-RELEASE-p1',
            ];
            $expectedEdition = 'Plus';
            $expectedVersion = '26.03.1';
        } elseif ($name === 'about-untested') {
            $globals = [
                'product_label' => 'pfSense Plus',
                'product_version' => '25.11-RELEASE',
            ];
            $expectedEdition = 'Plus';
            $expectedVersion = '25.11';
        } elseif ($name === 'about-no-release') {
            $updateState = [
                'checked_at' => '2026-11-08T12:00:00+00:00',
                'last_error' => null,
            ];
            $updateStatus = 'No public release exists yet.';
            $unexpected[] = 'The last update check failed:';
        } elseif ($name === 'about-http-failure') {
            $updateState = [
                'checked_at' => '2026-11-08T12:00:00+00:00',
                'last_error' => 'GitHub returned HTTP status 500 for the update check.',
            ];
            $updateStatus = 'The last update check failed: GitHub returned HTTP status 500 for the update check.';
            $updateStatusIcon = 'fa-solid fa-circle-exclamation';
            $unexpected[] = 'No public release exists yet.';
        } elseif ($name === 'about-network-failure') {
            $updateState = [
                'checked_at' => '2026-11-08T12:00:00+00:00',
                'last_error' => 'The update check could not connect to GitHub: invented network failure.',
            ];
            $updateStatus = 'The last update check failed: The update check could not connect to GitHub: invented network failure.';
            $updateStatusIcon = 'fa-solid fa-circle-exclamation';
            $unexpected[] = 'No public release exists yet.';
        }

        $expected = [
            '0.0.15',
            'Peace of mind for parents and employers, right inside pfSense.',
            $updateStatus,
            $updateStatusIcon,
            'Check Now',
            'fa-solid fa-arrows-rotate',
            'pfSense CE 2.9.0',
            'pfSense CE 2.8.1',
            'pfSense Plus 26.07',
            'pfSense Plus 26.03.1',
            'Each tested release passed install, update, a blocking test, and removal end to end.',
            '<td colspan="2">',
            'This firewall',
        ];

        if ($name === 'about-untested') {
            $expected[] = 'pfSense Plus 25.11';
            $expected[] = 'Not tested';
        }

        return array_replace($base, [
            'page' => 'sinkhole-about.php',
            'globals' => $globals,
            'update_state' => $updateState,
            'state' => [
                [
                    'path' => ['packageVersion'],
                    'expected' => '0.0.15',
                ],
                [
                    'path' => ['currentEdition'],
                    'expected' => $expectedEdition,
                ],
                [
                    'path' => ['currentVersion'],
                    'expected' => $expectedVersion,
                ],
                [
                    'path' => ['testedReleases'],
                    'expected_count' => 4,
                ],
                [
                    'path' => ['currentReleaseTested'],
                    'expected' => $name !== 'about-untested',
                ],
            ],
            'expected' => $expected,
            'unexpected' => $unexpected,
        ]);
    }

    if (preg_match(
        '/^about-privilege-(render|post)-(about|general|page-all)$/',
        $name,
        $matches,
    ) === 1) {
        $requestType = $matches[1];
        $role = $matches[2];
        $privileges = match ($role) {
            'about' => ['page-firewall-sinkhole-about'],
            'general' => ['page-firewall-sinkhole-general'],
            'page-all' => ['page-all'],
        };
        $canManageUpdates = $role !== 'about';
        $updateState = [
            'checked_at' => '2026-11-08T12:00:00+00:00',
            'latest_version' => '0.0.16',
            'release_url' => 'https://github.com/mrjackyliang/pfsense-sinkhole/releases/tag/v0.0.16',
            'last_error' => null,
        ];
        $expected = ['0.0.15'];
        $unexpected = [];

        if ($requestType === 'render') {
            $expected[] = 'Version 0.0.16 is available.';
            $expected[] = 'What&#039;s New';

            if ($canManageUpdates) {
                $expected[] = 'Update to 0.0.16';
            } else {
                $unexpected[] = 'Update to 0.0.16';
                $unexpected[] = 'Check Now';
            }
        } elseif ($canManageUpdates === false) {
            $expected[] = 'What&#039;s New';
            $expected[] = 'The Sinkhole General settings privilege is required to check for or install package updates.';
            $unexpected[] = 'Update to 0.0.16';
            $unexpected[] = 'Check Now';
        } else {
            $expected[] = 'The update is starting.';
            $unexpected[] = 'Update to 0.0.16';
            $unexpected[] = 'Check Now';
        }

        return array_replace($base, [
            'page' => 'sinkhole-about.php',
            'post' => $requestType === 'post' ? ['self_update' => '1'] : [],
            'privileges' => $privileges,
            'update_state' => $updateState,
            'expected_background_commands' => (
                $requestType === 'post' && $canManageUpdates
            ) ? [PackagePaths::SELF_UPDATE_COMMAND] : [],
            'state' => [[
                'path' => ['canManageUpdates'],
                'expected' => $canManageUpdates,
            ]],
            'expected' => $expected,
            'unexpected' => $unexpected,
        ]);
    }

    if ($name === 'status-off') {
        $offConfiguration = $configuration;
        $offConfiguration['installedpackages']['sinkhole']['config'][0]['enabled'] = '';
        $offConfiguration['installedpackages']['sinkhole']['redirect']['enabled'] = '';
        $offConfiguration['installedpackages']['sinkhole']['ip']['enabled'] = '';
        foreach ([
            'block_tls_quic',
            'block_encrypted_dns',
            'disable_firefox_doh',
            'disable_private_relay',
            'block_tor',
            'block_vpn',
            'block_vpn_ports',
        ] as $field) {
            $offConfiguration['installedpackages']['sinkhole']['bypass'][$field] = '';
        }
        $offConfiguration['installedpackages']['sinkhole']['bypass']['discovery'] = 'off';

        return array_replace($base, [
            'page' => 'sinkhole-status.php',
            'configuration' => $offConfiguration,
            'state' => [
                [
                    'path' => ['resolverStatus', 'active'],
                    'expected' => false,
                ],
                [
                    'path' => ['resolverStatus', 'reason_key'],
                    'expected' => 'sinkhole_disabled',
                ],
                [
                    'path' => ['redirectEnabled'],
                    'expected' => false,
                ],
                [
                    'path' => ['ipConfiguration', 'enabled'],
                    'expected' => false,
                ],
                [
                    'path' => ['redirectRuleStatus', 'loaded'],
                    'expected' => false,
                ],
                [
                    'path' => ['ipRuleStatus', 'loaded'],
                    'expected' => false,
                ],
                [
                    'path' => ['bypassRuleStatus', 'loaded'],
                    'expected' => false,
                ],
                [
                    'path' => ['deploymentNeeded'],
                    'expected' => false,
                ],
            ],
            'expected' => ['Inactive: Sinkhole is disabled.', 'Off', 'No'],
            'unexpected' => ['Deployment pending:', 'Update Running', 'Removal in Progress'],
        ]);
    }

    if ($name === 'status-on') {
        return array_replace($base, [
            'page' => 'sinkhole-status.php',
            'runtime' => 'active',
            'state' => [
                [
                    'path' => ['resolverStatus', 'active'],
                    'expected' => true,
                ],
                [
                    'path' => ['redirectEnabled'],
                    'expected' => true,
                ],
                [
                    'path' => ['redirectPaused'],
                    'expected' => false,
                ],
                [
                    'path' => ['redirectRuleStatus', 'loaded'],
                    'expected' => true,
                ],
                [
                    'path' => ['ipRuleStatus', 'loaded'],
                    'expected' => true,
                ],
                [
                    'path' => ['bypassRuleStatus', 'loaded'],
                    'expected' => true,
                ],
                [
                    'path' => ['bypassConfiguration', 'discovery_zone_present'],
                    'expected' => true,
                ],
                [
                    'path' => ['compileNeeded'],
                    'expected' => false,
                ],
                [
                    'path' => ['deploymentNeeded'],
                    'expected' => false,
                ],
                [
                    'path' => ['updateRunning'],
                    'expected' => false,
                ],
                [
                    'path' => ['removing'],
                    'expected' => false,
                ],
            ],
            'expected' => [
                'On',
                'Yes',
                'Inbound',
                'Outbound',
                'IPv4 and IPv6',
                'IP Anchor',
                'Anchor Rule Count',
                'Bypass Lists',
                'Discovery Zone',
                'Present',
                'Firewall Rules Current',
                'Invented enabled device',
                'fa-solid fa-arrows-rotate',
            ],
            'unexpected' => ['Update Running', 'Removal in Progress'],
        ]);
    }

    if ($name === 'status-paused') {
        $pausedConfiguration = $configuration;
        $pausedConfiguration['installedpackages']['sinkhole']['redirect']['exempt_sources'] = [
            'item' => ['Invented_Missing_Source'],
        ];
        $pausedConfiguration['installedpackages']['sinkhole']['ip']['enabled'] = '';
        $pausedConfiguration['unbound']['python_script'] = 'another-package';

        return array_replace($base, [
            'page' => 'sinkhole-status.php',
            'configuration' => $pausedConfiguration,
            'runtime' => 'stale-rules',
            'state' => [
                [
                    'path' => ['resolverStatus', 'active'],
                    'expected' => false,
                ],
                [
                    'path' => ['resolverStatus', 'owner'],
                    'expected' => 'another-package',
                ],
                [
                    'path' => ['redirectPaused'],
                    'expected' => true,
                ],
                [
                    'path' => ['redirectInvalidExemptions'],
                    'expected_count' => 1,
                ],
                [
                    'path' => ['redirectRuleStatus', 'out_of_date'],
                    'expected' => true,
                ],
                [
                    'path' => ['ipRuleStatus', 'loaded'],
                    'expected' => false,
                ],
            ],
            'expected' => ['Paused', 'Out of Date', 'Invented_Missing_Source'],
        ]);
    }

    if ($name === 'status-pending') {
        $pendingConfiguration = $configuration;
        $pendingConfiguration['unbound']['custom_options'] = base64_encode('verbosity: 1');

        return array_replace($base, [
            'page' => 'sinkhole-status.php',
            'configuration' => $pendingConfiguration,
            'runtime' => 'pending',
            'state' => [
                [
                    'path' => ['compileNeeded'],
                    'expected' => true,
                ],
                [
                    'path' => ['deploymentNeeded'],
                    'expected' => true,
                ],
                [
                    'path' => ['updateRunning'],
                    'expected' => true,
                ],
                [
                    'path' => ['removing'],
                    'expected' => true,
                ],
                [
                    'path' => ['redirectRuleStatus', 'loaded'],
                    'expected' => false,
                ],
                [
                    'path' => ['ipRuleStatus', 'loaded'],
                    'expected' => false,
                ],
                [
                    'path' => ['bypassConfiguration', 'discovery_zone_present'],
                    'expected' => false,
                ],
            ],
            'expected' => [
                'Deployment pending: The deployed content digest differs from the compiled content digest.',
                'On',
                'No',
                'Discovery Zone',
                'Missing',
                'Update Running',
                'Removal in Progress',
            ],
        ]);
    }

    throw new InvalidArgumentException('Unknown page-render fixture: ' . $name);
}

/**
 * Sinkhole Page Render - Write File.
 *
 * Makes fixture setup fail immediately when a temporary state file cannot be
 * written, instead of reporting a misleading page-state assertion.
 *
 * @param string $path     - Path.
 * @param string $contents - Contents.
 *
 * @return void
 *
 * @throws RuntimeException When the fixture file cannot be written.
 *
 * @since 1.0.0
 */
function sinkholePageRenderWriteFile(string $path, string $contents): void
{
    if (file_put_contents($path, $contents) === false) {
        throw new RuntimeException('Unable to write a page-render fixture file.');
    }
}

/**
 * Sinkhole Page Render - Prepare Update State.
 *
 * Persists an invented release-check result for About-page display fixtures
 * without contacting GitHub or changing any package defaults.
 *
 * @param PackagePaths $paths       - Paths.
 * @param array<string, mixed>|null $updateState - Update state.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderPrepareUpdateState(
    PackagePaths $paths,
    ?array $updateState,
): void {
    if ($updateState === null) {
        return;
    }

    $directory = dirname($paths->updatesFile);

    if (!is_dir($directory) && mkdir($directory, 0700, true) === false) {
        throw new RuntimeException('Unable to prepare the page-render update-state directory.');
    }

    $contents = json_encode(
        $updateState,
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
    ) . PHP_EOL;

    sinkholePageRenderWriteFile($paths->updatesFile, $contents);
}

/**
 * Sinkhole Page Render - Prepare Catalogs.
 *
 * Creates fresh invented catalog records so the open catalog views render their
 * filters, status tables, grouped card grids and add actions without networking.
 *
 * @param PackagePaths $paths - Paths.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderPrepareCatalogs(PackagePaths $paths): void
{
    if (!is_dir($paths->catalogCacheDirectory)) {
        mkdir($paths->catalogCacheDirectory, 0700, true);
    }
    $adGuardContents = json_encode([
        'filters' => [
            [
                'filterKey' => 'invented_hosts',
                'filterId' => 1,
                'groupId' => 1,
                'name' => 'Invented Catalog Hosts',
                'description' => 'Invented host catalog description.',
                'homepage' => 'https://catalog.example.test/hosts',
                'downloadUrl' => 'https://catalog.example.test/hosts.txt',
                'tags' => ['invented'],
                'languages' => ['en'],
                'deprecated' => false,
                'version' => '1',
                'timeUpdated' => '2026-01-01T00:00:00Z',
            ],
            [
                'filterKey' => 'invented_encrypted_bypass',
                'filterId' => 2,
                'groupId' => 1,
                'name' => 'Invented Catalog Encrypted DNS',
                'description' => 'Invented encrypted catalog description.',
                'homepage' => 'https://catalog.example.test/encrypted',
                'downloadUrl' => 'https://catalog.example.test/encrypted.txt',
                'tags' => ['invented'],
                'languages' => ['en'],
                'deprecated' => false,
                'version' => '1',
                'timeUpdated' => '2026-01-01T00:00:00Z',
            ],
        ],
        'tags' => [],
        'groups' => [[
            'groupId' => 1,
            'groupName' => 'Invented Catalog Group',
        ]],
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $pfBlockerContents = json_encode([
        'description' => 'Invented catalog fixture.',
        'copyright' => 'Invented fixture.',
        'ipv4' => [
            'Invented Address Group' => [
                'description' => 'Invented address catalog description.',
                'feeds' => [[
                    'feed' => 'Invented Catalog IPv4',
                    'website' => 'https://catalog.example.test/ipv4',
                    'url' => 'https://catalog.example.test/ipv4.txt',
                    'header' => 'Invented header',
                ]],
            ],
            'DoH_IP' => [
                'description' => 'Invented encrypted IPv4 catalog description.',
                'feeds' => [[
                    'feed' => 'Invented Catalog Encrypted IPv4',
                    'website' => 'https://catalog.example.test/encrypted-ipv4',
                    'url' => 'https://catalog.example.test/encrypted-ipv4.txt',
                    'header' => 'Invented header',
                ]],
            ],
            'TOR' => [
                'description' => 'Invented Tor catalog description.',
                'feeds' => [[
                    'feed' => 'Invented Catalog Tor',
                    'website' => 'https://catalog.example.test/tor',
                    'url' => 'https://catalog.example.test/tor.txt',
                    'header' => 'Invented header',
                ]],
            ],
            'VPN_4' => [
                'description' => 'Invented IPv4 VPN catalog description.',
                'feeds' => [[
                    'feed' => 'Invented Catalog VPN',
                    'website' => 'https://catalog.example.test/vpn-ipv4',
                    'url' => 'https://catalog.example.test/vpn-ipv4.txt',
                    'header' => 'Invented header',
                ]],
            ],
        ],
        'ipv6' => [
            'DoH_6' => [
                'description' => 'Invented encrypted IPv6 catalog description.',
                'feeds' => [[
                    'feed' => 'Invented Catalog Encrypted IPv6',
                    'website' => 'https://catalog.example.test/encrypted-ipv6',
                    'url' => 'https://catalog.example.test/encrypted-ipv6.txt',
                    'header' => 'Invented header',
                ]],
            ],
            'VPN_6' => [
                'description' => 'Invented IPv6 VPN catalog description.',
                'feeds' => [[
                    'feed' => 'Invented Catalog VPN IPv6',
                    'website' => 'https://catalog.example.test/vpn-ipv6',
                    'url' => 'https://catalog.example.test/vpn-ipv6.txt',
                    'header' => 'Invented header',
                ]],
            ],
        ],
        'dnsbl' => [
            'Invented DNS Group' => [
                'description' => 'Invented DNS catalog description.',
                'info' => 'Invented information.',
                'action' => 'Invented action.',
                'cron' => 'Invented schedule.',
                'feeds' => [[
                    'feed' => 'Invented Catalog DNS',
                    'website' => 'https://catalog.example.test/dns',
                    'url' => 'https://catalog.example.test/dns.txt',
                    'header' => 'Invented header',
                ]],
            ],
            'DoH' => [
                'description' => 'Invented encrypted DNS catalog description.',
                'info' => 'Invented information.',
                'action' => 'Invented action.',
                'cron' => 'Invented schedule.',
                'feeds' => [[
                    'feed' => 'Invented Catalog Encrypted DNS Feed',
                    'website' => 'https://catalog.example.test/encrypted-dns',
                    'url' => 'https://catalog.example.test/encrypted-dns.txt',
                    'header' => 'Invented header',
                ]],
            ],
        ],
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $records = [
        [$paths->adGuardHomeCatalogCacheFile, 'adguard_home', $adGuardContents],
        [$paths->pfBlockerNgCatalogCacheFile, 'pfblockerng', $pfBlockerContents],
    ];

    foreach ($records as [$path, $source, $contents]) {
        sinkholePageRenderWriteFile(
            $path,
            json_encode([
                'schema_version' => 1,
                'source' => $source,
                'fetched_at' => time(),
                'contents' => $contents,
                'last_error' => '',
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL,
        );
    }
}

/** @since 1.0.0 */
function sinkholePageRenderPrepareServiceRegistry(PackagePaths $paths): void
{
    if (!is_dir($paths->catalogCacheDirectory)) {
        mkdir($paths->catalogCacheDirectory, 0700, true);
    }

    $contents = json_encode([
        'blocked_services' => [
            [
                'id' => 'invented-video',
                'name' => 'Invented Video',
                'group' => 'invented_media',
                'rules' => ['||invented-video.service.test^'],
                'icon_svg' => '<svg xmlns="http://www.w3.org/2000/svg"><path/></svg>',
            ],
            [
                'id' => 'icloud_private_relay',
                'name' => 'Invented Private Relay Service',
                'group' => 'invented_media',
                'rules' => ['||invented-private-relay.service.test^'],
                'icon_svg' => '<svg xmlns="http://www.w3.org/2000/svg"><path/></svg>',
            ],
        ],
        'groups' => [[
            'id' => 'invented_media',
        ]],
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    sinkholePageRenderWriteFile(
        $paths->serviceRegistryCacheFile,
        json_encode([
            'schema_version' => 1,
            'fetched_at' => time(),
            'contents' => $contents,
            'last_error' => '',
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL,
    );
}

/**
 * Sinkhole Page Render - Prepare Active Runtime.
 *
 * Builds the minimal deployed generation used by the real status loader and
 * records matching compile and deployment state for an active fixture.
 *
 * @param PackagePaths $paths      - Paths.
 * @param StateStore   $stateStore - State store.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderPrepareActiveRuntime(
    PackagePaths $paths,
    StateStore $stateStore,
): void {
    $generation = 'page-render-generation';
    $contentDigest = str_repeat('4', 64);
    $manifest = [
        'schema_version' => Compiler::MANIFEST_SCHEMA_VERSION,
        'generation' => $generation,
        'generated_at' => '2026-11-06T12:00:00+00:00',
        'content_digest' => $contentDigest,
        'domains_file' => 'domains.tsv',
        'bypass_file' => 'bypass.tsv',
        'allow_file' => 'allow.txt',
        'domain_count' => 0,
        'bypass_domain_count' => 0,
        'lists' => [],
        'scopes' => [
            'global' => ['lists' => [], 'allow' => 'allow.txt'],
            'networks' => [],
            'devices' => [],
        ],
        'alerts' => [],
        'bypass' => [
            'interfaces' => ['lan'],
            'block_encrypted_dns' => true,
            'disable_firefox_doh' => true,
            'disable_private_relay' => true,
            'discovery' => 'nodata',
            'discovery_hostname' => '',
            'discovery_port' => 0,
            'block_tor' => true,
            'block_vpn' => true,
        ],
    ];

    foreach (
        [
            $paths->persistentDirectory,
            $paths->runtimeRootDirectory,
            $paths->runtimeStorageDirectory,
            $paths->runtimeStateDirectory,
        ] as $directory
    ) {
        if (!is_dir($directory) && mkdir($directory, 0700, true) === false) {
            throw new RuntimeException('Unable to prepare a page-render fixture directory.');
        }
    }

    $temporaryDirectory = $paths->runtimeStorageDirectory . '/.sinkhole-new-page-render';

    if (mkdir($temporaryDirectory, 0700) === false) {
        throw new RuntimeException('Unable to prepare a page-render runtime generation.');
    }

    sinkholePageRenderWriteFile($temporaryDirectory . '/generation', $generation . PHP_EOL);
    sinkholePageRenderWriteFile($temporaryDirectory . '/domains.tsv', '');
    sinkholePageRenderWriteFile($temporaryDirectory . '/bypass.tsv', '');
    sinkholePageRenderWriteFile($temporaryDirectory . '/allow.txt', '');
    sinkholePageRenderWriteFile(
        $temporaryDirectory . '/manifest.json',
        json_encode($manifest, JSON_THROW_ON_ERROR) . PHP_EOL,
    );
    FileSystem::activateDirectory(
        $temporaryDirectory,
        $paths->runtimeStorageDirectory,
        $paths->runtimeDataDirectory,
    );
    sinkholePageRenderWriteFile($paths->runtimeScriptFile, '# page-render runtime' . PHP_EOL);
    sinkholePageRenderWriteFile($paths->loadedGenerationFile, $generation . PHP_EOL);
    $stateStore->recordCompileSuccess(
        $generation,
        $stateStore->compileRequest(),
        $contentDigest,
    );
    $stateStore->recordDeployment($generation, $contentDigest);
}

/**
 * Sinkhole Page Render - Prepare Runtime.
 *
 * Creates the files and durable state that each status fixture names before
 * the page reads them through its production loaders.
 *
 * @param string         $runtime    - Runtime.
 * @param PackagePaths   $paths      - Paths.
 * @param PfSenseAdapter $adapter    - Adapter.
 * @param StateStore     $stateStore - State store.
 * @param string         $rulesPath  - Rules path.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderPrepareRuntime(
    string $runtime,
    PackagePaths $paths,
    PfSenseAdapter $adapter,
    StateStore $stateStore,
    string $rulesPath,
): void {
    if ($runtime === 'none') {
        return;
    }

    if ($runtime === 'stale-rules') {
        sinkholePageRenderWriteFile(
            $rulesPath,
            "# Sinkhole DNS redirect\n",
        );

        return;
    }

    sinkholePageRenderPrepareActiveRuntime($paths, $stateStore);

    if ($runtime === 'active') {
        $redirectRules = $adapter->redirectRuleText();
        $ipRules = $adapter->ipRuleText();
        $bypassRules = $adapter->bypassRuleText();
        sinkholeTestAssertTrue($redirectRules !== '', 'The active fixture needs redirect rules.');
        sinkholeTestAssertTrue($ipRules !== '', 'The active fixture needs IP rules.');
        sinkholeTestAssertTrue($bypassRules !== '', 'The active fixture needs Bypass rules.');
        $adapter->applyIpAnchor();
        $adapter->applyBypassAnchor();
        sinkholePageRenderWriteFile(
            $rulesPath,
            $redirectRules . PHP_EOL . $ipRules . $bypassRules,
        );

        return;
    }

    if ($runtime === 'pending') {
        $stateStore->markCompileNeeded();
        $stateStore->recordCompileSuccess(
            'page-render-pending',
            $stateStore->compileRequest(),
            str_repeat('5', 64),
        );
        $stateStore->markCompileNeeded();
        $stateStore->markRemoving();
        sinkholePageRenderWriteFile($paths->updateLockFile, "12345\n");

        return;
    }

    throw new InvalidArgumentException('Unknown page-render runtime fixture: ' . $runtime);
}

/**
 * Sinkhole Page Render - State Value.
 *
 * Reads one nested variable produced by the included page so named fixtures
 * prove the real loader reached the intended branch.
 *
 * @param array<string, mixed> $variables - Variables created by the rendered page.
 * @param list<int|string>     $path      - Nested variable path.
 *
 * @return mixed
 *
 * @since 1.0.0
 */
function sinkholePageRenderStateValue(array $variables, array $path): mixed
{
    $value = $variables;

    foreach ($path as $segment) {
        if (!is_array($value) || !array_key_exists($segment, $value)) {
            throw new RuntimeException(
                'The rendered page did not create fixture state: '
                    . implode('.', array_map('strval', $path)),
            );
        }

        $value = $value[$segment];
    }

    return $value;
}

/**
 * Sinkhole Page Render - Assert State.
 *
 * Checks page-local values in addition to the pfSense-shaped offline form output.
 *
 * @param array<string, mixed> $variables  - Variables created by the rendered page.
 * @param list<array{path: list<int|string>, expected?: mixed, expected_count?: int}> $assertions - State assertions.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderAssertState(array $variables, array $assertions): void
{
    foreach ($assertions as $assertion) {
        $path = $assertion['path'];
        $label = implode('.', array_map('strval', $path));
        $value = sinkholePageRenderStateValue($variables, $path);

        if (array_key_exists('expected_count', $assertion)) {
            sinkholeTestAssertTrue(
                is_countable($value),
                'The rendered page fixture state must be countable: ' . $label,
            );
            sinkholeTestAssertSame(
                $assertion['expected_count'],
                count($value),
                'The rendered page fixture state count must match: ' . $label,
            );

            continue;
        }

        sinkholeTestAssertSame(
            $assertion['expected'] ?? null,
            $value,
            'The rendered page fixture state must match: ' . $label,
        );
    }
}

/**
 * Sinkhole Page Render - Class Tokens.
 *
 * @param string $tag - Opening HTML tag.
 *
 * @return list<string>
 *
 * @since 1.0.0
 */
function sinkholePageRenderClassTokens(string $tag): array
{
    if (preg_match('/\bclass\s*=\s*(["\'])(.*?)\1/is', $tag, $matches) !== 1) {
        return [];
    }
    $tokens = preg_split('/\s+/', trim(html_entity_decode(
        $matches[2],
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8',
    )));

    return is_array($tokens) ? array_values(array_filter($tokens, 'strlen')) : [];
}

/**
 * Sinkhole Page Render - Tag Attribute.
 *
 * Extracts one rendered HTML attribute without requiring the DOM extension.
 * Form assertions use it while walking submit-control ownership.
 *
 * @param string $tag       - Opening HTML tag.
 * @param string $attribute - Attribute name.
 *
 * @return string|null
 *
 * @since 1.0.0
 */
function sinkholePageRenderTagAttribute(string $tag, string $attribute): ?string
{
    $attributePattern = preg_quote($attribute, '/');
    $pattern = '/\b' . $attributePattern . '\s*=\s*(["\'])(.*?)\1/is';

    if (preg_match($pattern, $tag, $matches) !== 1) {
        return null;
    }

    return html_entity_decode(
        $matches[2],
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8',
    );
}

/**
 * Sinkhole Page Render - Assert Form Submissions.
 *
 * Verifies that GET forms never override a submit to POST and that every
 * Refresh submit is owned by a real POST form for pfSense CSRF injection.
 *
 * @param string $output      - Rendered page.
 * @param string $fixtureName - Fixture name.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderAssertFormSubmissions(
    string $output,
    string $fixtureName,
): void {
    preg_match_all('/<form\b[^>]*>/is', $output, $formMatches);
    $formMethods = [];

    foreach ($formMatches[0] as $formTag) {
        $formIdentifier = sinkholePageRenderTagAttribute($formTag, 'id');

        if ($formIdentifier === null || $formIdentifier === '') {
            continue;
        }
        $formMethod = sinkholePageRenderTagAttribute($formTag, 'method') ?? 'get';
        $formMethods[$formIdentifier] = strtolower($formMethod);
    }

    preg_match_all(
        '/<\/?form\b[^>]*>|<(?:button|input)\b[^>]*>/is',
        $output,
        $tokenMatches,
    );
    $formStack = [];

    foreach ($tokenMatches[0] as $token) {
        if (preg_match('/^<\s*\/\s*form\b/i', $token) === 1) {
            if ($formStack !== []) {
                array_pop($formStack);
            }

            continue;
        }

        if (preg_match('/^<\s*form\b/i', $token) === 1) {
            $formMethod = sinkholePageRenderTagAttribute($token, 'method') ?? 'get';
            $formStack[] = strtolower($formMethod);

            continue;
        }

        if (preg_match('/^<\s*(button|input)\b/i', $token, $controlMatches) !== 1) {
            continue;
        }
        $controlTag = strtolower($controlMatches[1]);
        $controlType = sinkholePageRenderTagAttribute($token, 'type');
        $normalizedControlType = ($controlType === null) ? null : strtolower($controlType);
        $isSubmitControl = $normalizedControlType === 'submit';

        if (
            $controlTag === 'button'
            && ($normalizedControlType === null || $normalizedControlType === '')
        ) {
            $isSubmitControl = true;
        }

        if ($isSubmitControl === false) {
            continue;
        }
        $ancestorMethod = null;

        if ($formStack !== []) {
            $ancestorMethod = $formStack[array_key_last($formStack)];
        }
        $formMethodAttribute = sinkholePageRenderTagAttribute($token, 'formmethod');
        $normalizedFormMethodAttribute = ($formMethodAttribute === null)
            ? null
            : strtolower($formMethodAttribute);

        sinkholeTestAssertSame(
            false,
            $ancestorMethod === 'get' && $normalizedFormMethodAttribute === 'post',
            'GET forms must not override submit controls to POST: ' . $fixtureName,
        );
        sinkholeTestAssertSame(
            null,
            $formMethodAttribute,
            'Rendered submit controls must not use formmethod: ' . $fixtureName,
        );

        $controlName = sinkholePageRenderTagAttribute($token, 'name');

        if ($controlName === null || str_starts_with($controlName, 'refresh_') === false) {
            continue;
        }
        $ownerMethod = $ancestorMethod;
        $ownerIdentifier = sinkholePageRenderTagAttribute($token, 'form');

        if ($ownerIdentifier !== null && $ownerIdentifier !== '') {
            sinkholeTestAssertTrue(
                array_key_exists($ownerIdentifier, $formMethods),
                'Refresh control form owner must exist: '
                    . $controlName
                    . ': '
                    . $fixtureName,
            );
            $ownerMethod = $formMethods[$ownerIdentifier] ?? null;
        }

        sinkholeTestAssertSame(
            'post',
            $ownerMethod,
            'Refresh controls must belong to POST forms: '
                . $controlName
                . ': '
                . $fixtureName,
        );
    }
}

/**
 * Sinkhole Page Render - Assert Panel Bodies.
 *
 * Walks rendered tags without requiring the DOM extension used by pfSense's base
 * image. A panel body may contain only the row and collection structures that
 * receive spacing from pfSense.css.
 *
 * @param string $output      - Rendered page.
 * @param string $fixtureName - Fixture name.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderAssertPanelBodies(string $output, string $fixtureName): void
{
    preg_match_all('/<!--.*?-->|<![^>]*>|<[^>]+>|[^<]+/s', $output, $matches);
    $stack = [];
    $voidTags = [
        'area',
        'base',
        'br',
        'col',
        'embed',
        'hr',
        'img',
        'input',
        'link',
        'meta',
        'param',
        'source',
        'track',
        'wbr',
    ];
    $allowedClasses = [
        'form-group',
        'table-responsive',
        'alert',
        'list-group',
        'collapse',
    ];

    foreach ($matches[0] as $token) {
        if (!str_starts_with($token, '<')) {
            $parent = end($stack);

            if (($parent['panel_body'] ?? false) === true) {
                sinkholeTestAssertSame(
                    '',
                    trim($token),
                    'Panel bodies must not contain direct text: ' . $fixtureName,
                );
            }

            continue;
        }

        if (str_starts_with($token, '<!--') || str_starts_with($token, '<!')) {
            continue;
        }

        if (preg_match('/^<\s*\/\s*([a-z0-9:-]+)/i', $token, $closing) === 1) {
            $closingTag = strtolower($closing[1]);

            while ($stack !== []) {
                $opened = array_pop($stack);

                if ($opened['tag'] === $closingTag) {
                    break;
                }
            }

            continue;
        }

        if (preg_match('/^<\s*([a-z0-9:-]+)/i', $token, $opening) !== 1) {
            continue;
        }
        $tag = strtolower($opening[1]);
        $classes = sinkholePageRenderClassTokens($token);
        $parent = end($stack);

        if (($parent['panel_body'] ?? false) === true) {
            $allowed = $tag === 'table'
                || array_intersect($allowedClasses, $classes) !== [];
            sinkholeTestAssertTrue(
                $allowed,
                'Panel bodies must use pfSense row or collection children; found '
                    . $tag
                    . ': '
                    . $fixtureName,
            );
        }
        $selfClosing = str_ends_with(rtrim($token), '/>')
            || in_array($tag, $voidTags, true);

        if (!$selfClosing) {
            $stack[] = [
                'tag' => $tag,
                'panel_body' => in_array('panel-body', $classes, true),
            ];
        }
    }
}

/**
 * Sinkhole Page Render - Assert Icons.
 *
 * @param string $output      - Rendered page.
 * @param string $fixtureName - Fixture name.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderAssertIcons(string $output, string $fixtureName): void
{
    preg_match_all('/\bclass\s*=\s*(["\'])(.*?)\1/is', $output, $matches);
    $bareStyles = ['fa', 'fas', 'far', 'fab'];
    $legacyNames = [
        'fa-arrow-circle-up',
        'fa-check-circle',
        'fa-check-square',
        'fa-circle-o',
        'fa-edit',
        'fa-exclamation-circle',
        'fa-external-link',
        'fa-info-circle',
        'fa-pause-circle',
        'fa-refresh',
        'fa-remove',
        'fa-times-circle',
        'fa-trash',
    ];

    foreach ($matches[2] as $classValue) {
        $tokens = preg_split('/\s+/', trim($classValue));

        if (!is_array($tokens)) {
            continue;
        }

        foreach (array_merge($bareStyles, $legacyNames) as $forbiddenClass) {
            sinkholeTestAssertSame(
                false,
                in_array($forbiddenClass, $tokens, true),
                'Rendered icons must use FontAwesome 6 classes; found '
                    . $forbiddenClass
                    . ': '
                    . $fixtureName,
            );
        }
    }
}

/**
 * Sinkhole Page Render - Assert Styles.
 *
 * @param string $output      - Rendered page.
 * @param string $fixtureName - Fixture name.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderAssertStyles(string $output, string $fixtureName): void
{
    sinkholeTestAssertSame(
        0,
        preg_match('/<style\b/i', $output),
        'Rendered pages must not contain page-local style blocks: ' . $fixtureName,
    );
    sinkholeTestAssertSame(
        0,
        preg_match(
            '/\bstyle\s*=\s*(["\'])[^"\']*(?:padding|margin)\s*:/is',
            $output,
        ),
        'Rendered pages must not use inline padding or margin: ' . $fixtureName,
    );
}

/**
 * Sinkhole Page Render - Assert Dependent Field Targets.
 *
 * Resolves JavaScript and selector escapes before requiring every pfSense
 * dependent-field helper to name an element rendered by the same page.
 *
 * @param string $output      - Rendered page.
 * @param string $fixtureName - Fixture name.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderAssertDependentFieldTargets(
    string $output,
    string $fixtureName,
): void {
    preg_match_all('/\bid\s*=\s*(["\'])(.*?)\1/is', $output, $idMatches);
    $elementIds = array_map(
        static fn (string $elementId): string => html_entity_decode(
            $elementId,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8',
        ),
        $idMatches[2] ?? [],
    );
    preg_match_all(
        '/\b(?:hideInput|hideSelect|hideCheckbox)\s*\(/',
        $output,
        $helperCalls,
    );
    preg_match_all(
        '/\b(hideInput|hideSelect|hideCheckbox)\s*\(\s*([\'\"])([^\'\"]+)\2/',
        $output,
        $helperMatches,
        PREG_SET_ORDER,
    );
    sinkholeTestAssertSame(
        count($helperCalls[0] ?? []),
        count($helperMatches),
        'Every dependent-field helper must use a static string id: ' . $fixtureName,
    );

    foreach ($helperMatches as $helperMatch) {
        $selectorId = stripcslashes($helperMatch[3]);
        $elementId = preg_replace('/\\\\(.)/s', '$1', $selectorId);

        sinkholeTestAssertTrue(
            is_string($elementId) && in_array($elementId, $elementIds, true),
            'Dependent-field helper target must match a rendered element id: '
                . $helperMatch[1]
                . '('
                . (is_string($elementId) ? $elementId : $helperMatch[3])
                . '): '
                . $fixtureName,
        );
    }
}

/**
 * Sinkhole Page Render - Worker.
 *
 * Renders one real page in an isolated process using persisted pfSense fixture
 * configuration plus temporary runtime files where the status page needs them.
 *
 * @param string $fixtureName - Fixture name.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholePageRenderWorker(string $fixtureName): void
{
    global $sinkholeStubBackgroundCommands;
    global $sinkholeStubGlobalValues;
    global $sinkholeStubInterfaceAddresses;
    global $sinkholeStubInterfaces;
    global $sinkholeStubRealInterfaces;
    global $sinkholeStubUserPrivileges;

    $root = sinkholeTestTemporaryDirectory();

    try {
        $workspace = dirname(__DIR__);
        $stubDirectory = __DIR__ . '/stubs';
        $packageDirectory = $workspace . '/port/files/usr/local/pkg';
        set_include_path($stubDirectory . PATH_SEPARATOR . get_include_path());
        require_once($stubDirectory . '/guiconfig.inc');
        require_once($packageDirectory . '/sinkhole.inc');
        $fixture = sinkholePageRenderFixture($fixtureName);
        sinkholeStubReset($fixture['configuration']);
        $sinkholeStubUserPrivileges = $fixture['privileges'];
        $sinkholeStubGlobalValues = $fixture['globals'];
        $sinkholeStubInterfaces = ['lan' => 'LAN', 'opt1' => 'OPT1'];
        $sinkholeStubInterfaceAddresses = [
            'lan' => ['ipv4' => '192.0.2.1', 'ipv6' => '2001:db8::1'],
            'opt1' => ['ipv4' => '198.51.100.1'],
        ];
        $sinkholeStubRealInterfaces = ['lan' => 'igc0', 'opt1' => 'igc1'];
        $paths = sinkholePageRenderPaths($root);
        sinkholePageRenderPrepareUpdateState($paths, $fixture['update_state']);
        $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
        $adapter = new PfSenseAdapter($paths, $stateStore);
        pfsensePackageSinkholeAdapter($adapter);

        if (in_array($fixtureName, ['lists-catalog', 'ip-catalog', 'bypass-catalog'], true)) {
            sinkholePageRenderPrepareCatalogs($paths);
        }

        if ($fixtureName === 'services') {
            sinkholePageRenderPrepareServiceRegistry($paths);
        }
        $sinkholePageRulesPath = $root . '/rules.debug';
        sinkholePageRenderPrepareRuntime(
            $fixture['runtime'],
            $paths,
            $adapter,
            $stateStore,
            $sinkholePageRulesPath,
        );
        $_GET = $fixture['get'];
        $_POST = $fixture['post'];
        $_SESSION = ['Username' => 'invented-operator'];
        $_SERVER['REQUEST_METHOD'] = $_POST === [] ? 'GET' : 'POST';
        $pagePath = $workspace . '/port/files/usr/local/www/' . $fixture['page'];
        $source = (string) file_get_contents($pagePath);
        $source = str_replace('/usr/local/pkg/', $packageDirectory . '/', $source);
        $source = str_replace(
            '$paths = new PackagePaths();',
            '$paths = pfsensePackageSinkholeAdapter()->packagePaths();',
            $source,
        );
        $source = str_replace(
            'pfsensePackageSinkholeRedirectStatus();',
            'pfsensePackageSinkholeRedirectStatus($sinkholePageRulesPath, $paths->redirectRuleErrorFile);',
            $source,
        );
        $renderPath = $root . '/' . $fixture['page'];
        sinkholePageRenderWriteFile($renderPath, $source);
        ob_start();

        try {
            include($renderPath);
            $output = (string) ob_get_clean();
        } catch (Throwable $throwable) {
            ob_end_clean();
            throw $throwable;
        }

        sinkholeTestAssertTrue($output !== '', 'The page must produce rendered output.');
        sinkholeTestAssertSame(
            $fixture['expected_background_commands'],
            $sinkholeStubBackgroundCommands,
            'The rendered page must launch only its expected background commands.',
        );
        sinkholePageRenderAssertState(get_defined_vars(), $fixture['state']);
        sinkholePageRenderAssertPanelBodies($output, $fixtureName);
        sinkholePageRenderAssertFormSubmissions($output, $fixtureName);
        sinkholePageRenderAssertIcons($output, $fixtureName);
        sinkholePageRenderAssertStyles($output, $fixtureName);
        sinkholePageRenderAssertDependentFieldTargets($output, $fixtureName);
        $defaultEmbeddedIconPattern = '/<(a|button)\b'
            . '(?=[^>]*class="[^"]*\bbtn-default\b)[^>]*>'
            . '(?:(?!<\/\1>).)*\bicon-embed-btn\b'
            . '(?:(?!<\/\1>).)*<\/\1>/is';

        sinkholeTestAssertSame(
            0,
            preg_match($defaultEmbeddedIconPattern, $output),
            'Rendered default buttons must not contain embedded-button icons: ' . $fixtureName,
        );

        foreach ($fixture['expected'] as $expected) {
            sinkholeTestAssertContains(
                $expected,
                $output,
                'The rendered page must contain its fixture state: ' . $expected,
            );
        }

        foreach ($fixture['unexpected'] as $unexpected) {
            sinkholeTestAssertSame(
                false,
                str_contains($output, $unexpected),
                'The rendered page must not contain stale markup: ' . $unexpected,
            );
        }

        if ($fixtureName === 'services') {
            sinkholeTestAssertSame(
                false,
                str_contains($output, '<svg'),
                'The Services page must never render registry SVG as inline markup.',
            );
        }

        if ($fixtureName === 'bypass-catalog') {
            sinkholeTestAssertTrue(
                substr_count($output, 'name="catalog_kind"') > 1,
                'The Bypass filter and Add forms must both retain the kind.',
            );
        }
    } finally {
        sinkholeTestRemoveTemporaryDirectory($root);
    }
}

/** @since 1.0.0 */
function sinkholePageRenderCase(string $fixtureName): void
{
    $process = proc_open(
        [PHP_BINARY, __FILE__, '--worker', $fixtureName],
        [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes,
    );

    if (!is_resource($process)) {
        throw new RuntimeException('Unable to start an isolated page-render worker.');
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
        'The page-render worker must finish without an exception: '
            . $fixtureName . PHP_EOL . $output . $error,
    );
}

if (($argv[1] ?? '') === '--worker') {
    sinkholePageRenderWorker((string) ($argv[2] ?? ''));

    exit(0);
}

$fixtures = [
    'lists-list',
    'lists-empty',
    'lists-catalog',
    'lists-edit-add',
    'lists-edit',
    'services',
    'scopes-list',
    'scopes-empty',
    'scopes-edit-network-add',
    'scopes-edit-network',
    'scopes-edit-device-add',
    'scopes-edit-device',
    'alerts-list',
    'alerts-empty',
    'alerts-edit-add',
    'alerts-edit',
    'ip-list',
    'ip-empty',
    'ip-catalog',
    'ip-edit-add',
    'ip-edit',
    'ip-invalid-values',
    'ip-invalid-settings',
    'bypass-list',
    'bypass-empty',
    'bypass-catalog',
    'bypass-edit-add',
    'bypass-edit',
    'bypass-redirect-fields',
    'bypass-redirect-collections',
    'bypass-redirect-invalid-settings',
    'status-off',
    'status-on',
    'status-paused',
    'status-pending',
    'about-ce',
    'about-plus',
    'about-untested',
    'about-no-release',
    'about-http-failure',
    'about-network-failure',
    'about-privilege-render-about',
    'about-privilege-render-general',
    'about-privilege-render-page-all',
    'about-privilege-post-about',
    'about-privilege-post-general',
    'about-privilege-post-page-all',
];
$cases = [
    'dependent-field helper targets resolve escaped ids and reject unknown ids' => static function (): void {
        sinkholePageRenderAssertDependentFieldTargets(
            "<select id=\"lists[]\"></select><script>hideInput('lists\\\\[\\\\]', true);</script>",
            'escaped-multi-select',
        );

        try {
            sinkholePageRenderAssertDependentFieldTargets(
                "<input id=\"known\"><script>hideInput('missing', true);</script>",
                'unknown-target',
            );
        } catch (RuntimeException $runtimeException) {
            sinkholeTestAssertContains(
                'missing',
                $runtimeException->getMessage(),
                'A wrong dependent-field id must identify the missing target.',
            );

            return;
        }

        throw new RuntimeException('A wrong dependent-field id must fail the render test.');
    },
];

foreach ($fixtures as $fixtureName) {
    $cases['page renders every computed state: ' . $fixtureName] = static function () use (
        $fixtureName,
    ): void {
        sinkholePageRenderCase($fixtureName);
    };
}

sinkholeTestRun($cases);
