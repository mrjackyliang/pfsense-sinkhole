<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\AlertConfiguration;
use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\ListConfiguration;
use PfSense\Sinkhole\Domain\ScopeConfiguration;
use PfSense\Sinkhole\Domain\Settings;
use PfSense\Sinkhole\Runtime\Translator;

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/DomainParser.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/AlertConfiguration.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ListConfiguration.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/ScopeConfiguration.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Settings.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Translator.php');

sinkholeTestRun([
    'supported list formats' => static function (): void {
        $parser = new DomainParser();
        $cases = [
            '0.0.0.0 Exact.Example.Test # comment' => ['exact.example.test', DomainParser::EXACT],
            '127.0.0.1 second.example.test' => ['second.example.test', DomainParser::EXACT],
            ':: ipv6.example.test' => ['ipv6.example.test', DomainParser::EXACT],
            'Plain.Example.Test.' => ['plain.example.test', DomainParser::EXACT],
            '_service.Example.Test' => ['_service.example.test', DomainParser::EXACT],
            'commented.example.test # trailing comment' => ['commented.example.test', DomainParser::EXACT],
            '0.0.0.0 ads.example.com ## note' => ['ads.example.com', DomainParser::EXACT],
            '||Tree.Example.Test^' => ['tree.example.test', DomainParser::SUBTREE],
            '||important.example.test^$important' => ['important.example.test', DomainParser::SUBTREE],
        ];

        foreach ($cases as $line => $expected) {
            $entry = $parser->parseLine($line);
            sinkholeTestAssertTrue(is_array($entry), 'A supported line must be accepted: ' . $line);
            sinkholeTestAssertSame($expected[0], $entry['domain'], 'The domain must normalize.');
            sinkholeTestAssertSame($expected[1], $entry['semantic'], 'The semantic must match.');
        }
    },
    'ignored list lines' => static function (): void {
        $parser = new DomainParser();
        $ignored = [
            '',
            '# comment',
            '! comment',
            '||example.test^$third-party',
            '||example.test^$important,third-party',
            '@@||example.test^',
            'example.com##.ad-slot',
            'example.com,example.org#@#.x',
            'example.org#@#.promoted',
            'example.net#?#div:has(a)',
            'example.com#$#body',
            'example.net#not-a-comment',
            '*.example.test',
            '/example/',
            '192.0.2.1',
            '2001:db8::1',
            '0.0.0.0 localhost',
            '127.0.0.1 localhost.localdomain',
            ':: ip6-loopback',
            ':: localhost6.localdomain6',
            'broadcasthost',
            'local',
            'localdomain',
            '-bad.example.test',
            'bad-.example.test',
            'two names.example.test',
            'com',
            'lan',
        ];

        foreach ($ignored as $line) {
            sinkholeTestAssertSame(null, $parser->parseLine($line), 'The line must be ignored: ' . $line);
        }
    },
    'hosts rows accept every name before the comment' => static function (): void {
        $entries = (new DomainParser())->parseLineEntries(
            '0.0.0.0 first.example.com _second.example.net ignored # comment',
        );

        sinkholeTestAssertSame(
            [
                ['domain' => 'first.example.com', 'semantic' => DomainParser::EXACT],
                ['domain' => '_second.example.net', 'semantic' => DomainParser::EXACT],
            ],
            $entries,
            'Every valid dotted hostname before a hash comment must be accepted.',
        );
    },
    'normalization and allowed domains' => static function (): void {
        sinkholeTestAssertSame(
            'mixed.example.test',
            DomainParser::normalizeDomain('  MiXeD.Example.Test.  '),
            'ASCII domains must normalize.',
        );

        if (function_exists('idn_to_ascii')) {
            sinkholeTestAssertSame(
                'xn--tst-qla.example',
                DomainParser::normalizeDomain('täst.example'),
                'IDNs must convert to punycode when intl is available.',
            );
        } else {
            sinkholeTestAssertSame(
                null,
                DomainParser::normalizeDomain('täst.example'),
                'IDNs must be rejected when conversion is unavailable.',
            );
        }

        $allowed = DomainParser::normalizeAllowedDomains(
            "Example.Test.\nsub.example.test\nEXAMPLE.TEST\ninvalid_name.test\nlan\n",
        );
        sinkholeTestAssertSame(
            ['example.test', 'invalid_name.test', 'sub.example.test'],
            $allowed['domains'],
            'Allowed domains must normalize, deduplicate, and sort.',
        );
        sinkholeTestAssertSame([5], $allowed['invalid_lines'], 'Invalid line numbers must be reported.');
    },
    'stream parser counts accepted and ignored lines' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $input = $directory . '/input.txt';
            $output = $directory . '/output.txt';
            file_put_contents(
                $input,
                "0.0.0.0 exact.example.test\n||tree.example.test^\n# comment\ninvalid-.example.test\n",
            );
            $result = (new DomainParser())->parseFile($input, $output);

            sinkholeTestAssertSame(2, $result['accepted'], 'Two lines must be accepted.');
            sinkholeTestAssertSame(2, $result['ignored'], 'Two lines must be ignored.');
            sinkholeTestAssertSame(
                "E\texact.example.test\nS\ttree.example.test\n",
                file_get_contents($output),
                'Normalized output must preserve exact and subtree semantics.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'list IDs and URLs are validated' => static function (): void {
        $identifier = ListConfiguration::generateIdentifier();
        $row = ListConfiguration::normalizeRow(
            $identifier,
            'Example Source',
            'https://lists.example.invalid/global.test',
            true,
        );

        sinkholeTestAssertSame($identifier, $row['id'], 'The stable identifier must be retained.');
        sinkholeTestAssertSame(true, $row['enabled'], 'The enabled flag must be retained.');

        $threw = false;

        try {
            ListConfiguration::normalizeRow(
                $identifier,
                'Example Source',
                'file:///tmp/source.test',
                true,
            );
        } catch (InvalidArgumentException) {
            $threw = true;
        }

        sinkholeTestAssertTrue($threw, 'Non-HTTP URLs must be rejected.');

        $threw = false;

        try {
            ListConfiguration::normalizeRow(
                $identifier,
                'Example Source',
                'https://lists.example.invalid/café.test',
                true,
            );
        } catch (InvalidArgumentException) {
            $threw = true;
        }

        sinkholeTestAssertTrue($threw, 'Non-ASCII URLs must be percent-encoded.');
    },
    'invalid saved rows are partitioned without stopping valid rows' => static function (): void {
        $identifier = '66666666666666666666666666666666';
        $partition = ListConfiguration::partitionLists([
            [
                'id' => $identifier,
                'descr' => 'Valid Example',
                'url' => 'https://lists.example.invalid/valid.test',
                'enabled' => 'on',
            ],
            [
                'id' => 'invalid',
                'descr' => 'Broken Example',
                'url' => 'https://lists.example.invalid/broken.test',
                'enabled' => 'on',
            ],
        ]);

        sinkholeTestAssertSame(
            [$identifier],
            array_keys($partition['lists']),
            'A valid saved row must remain usable.',
        );
        sinkholeTestAssertSame(1, count($partition['invalid_rows']), 'The bad row must be reported.');
        sinkholeTestAssertSame(
            1,
            $partition['invalid_rows'][0]['position'],
            'The repair UI must receive the original row position.',
        );
    },
    'global defaults on and scope assignments count list usage' => static function (): void {
        $identifier = '77777777777777777777777777777777';
        $partition = ListConfiguration::partitionLists([[
            'id' => $identifier,
            'descr' => 'Default Global Example',
            'url' => 'https://lists.example.invalid/default-global.test',
            'enabled' => 'on',
        ]]);
        $lists = $partition['lists'];
        $networkIdentifier = '88888888888888888888888888888888';
        $deviceIdentifier = '99999999999999999999999999999999';

        sinkholeTestAssertSame(
            true,
            $lists[$identifier]['global'],
            'A saved list without the Global field must remain global.',
        );
        sinkholeTestAssertSame(
            false,
            ListConfiguration::normalizeRow(
                $identifier,
                'Not Global',
                'https://lists.example.invalid/not-global.test',
                true,
                false,
            )['global'],
            'An unchecked Global field must remain off.',
        );
        sinkholeTestAssertSame(
            [$identifier => 2],
            ScopeConfiguration::listUsageCounts(
                $lists,
                [$networkIdentifier => ['lists' => [$identifier]]],
                [$deviceIdentifier => ['lists' => [$identifier]]],
            ),
            'Used by must count network and device assignments.',
        );
    },
    'network and device scope validation rejects stale or duplicate identities' => static function (): void {
        $listIdentifier = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
        $lists = [$listIdentifier => ['id' => $listIdentifier]];
        $interfaces = ['lan' => 'LAN', 'opt1' => 'VLAN'];
        $firstNetwork = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
        $secondNetwork = 'cccccccccccccccccccccccccccccccc';
        $networkPartition = ScopeConfiguration::partitionNetworks([
            [
                'id' => $firstNetwork,
                'interface' => 'lan',
                'lists' => [$listIdentifier],
                'allowed_domains' => [],
                'enabled' => 'on',
            ],
            [
                'id' => $secondNetwork,
                'interface' => 'lan',
                'lists' => [],
                'allowed_domains' => [],
                'enabled' => 'on',
            ],
            [
                'id' => 'dddddddddddddddddddddddddddddddd',
                'interface' => 'missing',
                'lists' => [],
                'allowed_domains' => [],
                'enabled' => 'on',
            ],
        ], $interfaces, $lists);

        sinkholeTestAssertSame(
            [$firstNetwork],
            array_keys($networkPartition['networks']),
            'Only the first row for a configured interface may remain valid.',
        );
        sinkholeTestAssertSame(
            2,
            count($networkPartition['invalid_rows']),
            'A duplicate interface and unknown interface must remain repair rows.',
        );

        $mapping = [[
            'interface' => 'lan',
            'mac' => '00:11:22:33:44:55',
            'ipaddr' => '192.0.2.20',
        ]];
        $devices = ScopeConfiguration::partitionDevices([
            [
                'id' => '11111111111111111111111111111111',
                'descr' => 'First',
                'identifier_type' => ScopeConfiguration::DEVICE_IP,
                'identifier' => '192.0.2.10',
                'interface' => '',
                'lists' => [],
                'allowed_domains' => [],
                'enabled' => 'on',
            ],
            [
                'id' => '22222222222222222222222222222222',
                'descr' => 'Duplicate',
                'identifier_type' => ScopeConfiguration::DEVICE_IP,
                'identifier' => '192.0.2.10',
                'interface' => '',
                'lists' => [],
                'allowed_domains' => [],
                'enabled' => 'on',
            ],
            [
                'id' => '33333333333333333333333333333333',
                'descr' => 'Bad IP',
                'identifier_type' => ScopeConfiguration::DEVICE_IP,
                'identifier' => '999.1.1.1',
                'interface' => '',
                'lists' => [],
                'allowed_domains' => [],
                'enabled' => 'on',
            ],
            [
                'id' => '44444444444444444444444444444444',
                'descr' => 'Bad MAC',
                'identifier_type' => ScopeConfiguration::DEVICE_MAC,
                'identifier' => 'not-a-mac',
                'interface' => '',
                'lists' => [],
                'allowed_domains' => [],
                'enabled' => 'on',
            ],
            [
                'id' => '55555555555555555555555555555555',
                'descr' => 'Stale Mapping',
                'identifier_type' => ScopeConfiguration::DEVICE_STATIC_MAPPING,
                'identifier' => '00:11:22:33:44:66',
                'interface' => 'lan',
                'lists' => [],
                'allowed_domains' => [],
                'enabled' => 'on',
            ],
        ], $mapping, $lists);

        sinkholeTestAssertSame(
            ['11111111111111111111111111111111'],
            array_keys($devices['devices']),
            'Only the first valid unique device identifier may remain active.',
        );
        sinkholeTestAssertSame(
            4,
            count($devices['invalid_rows']),
            'Bad IP, bad MAC, stale mapping, and duplicate identifiers must be repair rows.',
        );
    },
    'scope readers unwrap repeated items and accept empty elements' => static function (): void {
        $listIdentifier = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
        $lists = [$listIdentifier => ['id' => $listIdentifier]];
        $network = ScopeConfiguration::normalizeNetworkRow([
            'id' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'interface' => 'lan',
            'lists' => ['item' => [$listIdentifier]],
            'allowed_domains' => ['item' => ['network.example.test']],
            'enabled' => 'on',
        ], ['lan' => 'LAN'], $lists);
        $device = ScopeConfiguration::normalizeDeviceRow([
            'id' => 'cccccccccccccccccccccccccccccccc',
            'descr' => 'Empty Lists',
            'identifier_type' => ScopeConfiguration::DEVICE_IP,
            'identifier' => '192.0.2.10',
            'interface' => '',
            'lists' => '',
            'allowed_domains' => '',
            'enabled' => 'on',
        ], [], $lists);

        sinkholeTestAssertSame(
            [$listIdentifier],
            $network['lists'],
            'A stored item wrapper must become the direct network selection.',
        );
        sinkholeTestAssertSame(
            ['network.example.test'],
            $network['allowed_domains'],
            'A stored item wrapper must become the direct network allowlist.',
        );
        sinkholeTestAssertSame(
            [$listIdentifier],
            ScopeConfiguration::unwrapRepeatedItems(['item' => [$listIdentifier]]),
            'The repair form helper must expose stored repeated items directly.',
        );
        sinkholeTestAssertSame([], $device['lists'], 'An empty lists element must be empty.');
        sinkholeTestAssertSame(
            [],
            $device['allowed_domains'],
            'An empty allowed-domains element must be empty.',
        );
    },
    'alert rules validate selections defaults and unicode descriptions' => static function (): void {
        $listIdentifier = '11111111111111111111111111111111';
        $networkIdentifier = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
        $deviceIdentifier = 'dddddddddddddddddddddddddddddddd';
        $ruleIdentifier = '44444444444444444444444444444444';
        $row = AlertConfiguration::normalizeRow([
            'id' => $ruleIdentifier,
            'descr' => 'Jacky’s Café alert',
            'lists' => ['item' => [$listIdentifier]],
            'networks' => ['item' => [$networkIdentifier]],
            'devices' => ['item' => [$deviceIdentifier]],
            'repeat_minutes' => '90',
            'enabled' => 'on',
        ], [
            $listIdentifier => ['id' => $listIdentifier],
        ], [
            $networkIdentifier => ['id' => $networkIdentifier],
        ], [
            $deviceIdentifier => ['id' => $deviceIdentifier],
        ]);

        sinkholeTestAssertSame(
            'Jacky’s Café alert',
            $row['description'],
            'Unicode free text must remain intact.',
        );
        sinkholeTestAssertSame([$listIdentifier], $row['lists'], 'Stored list items must unwrap.');
        sinkholeTestAssertSame(true, $row['notice'], 'WebGUI notices default on.');
        sinkholeTestAssertSame(true, $row['remote'], 'Remote delivery defaults on.');
        sinkholeTestAssertSame(90, $row['repeat_minutes'], 'Repeat minutes must normalize.');
    },
    'alert rows retain deleted references for repair' => static function (): void {
        $base = [
            'id' => '44444444444444444444444444444444',
            'descr' => 'Repair me',
            'repeat_minutes' => '60',
            'notice' => 'on',
            'remote' => 'on',
            'enabled' => 'on',
            'clients_everyone' => 'on',
        ];
        $cases = [
            ['lists' => ['item' => ['11111111111111111111111111111111']]],
            [
                'lists_any' => 'on',
                'clients_everyone' => '',
                'networks' => ['item' => ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']],
            ],
            [
                'lists_any' => 'on',
                'clients_everyone' => '',
                'devices' => ['item' => ['dddddddddddddddddddddddddddddddd']],
            ],
        ];

        foreach ($cases as $position => $fields) {
            $partition = AlertConfiguration::partitionAlerts(
                [array_merge($base, $fields)],
                [],
                [],
                [],
            );
            sinkholeTestAssertSame([], $partition['alerts'], 'A stale rule must not be active.');
            sinkholeTestAssertSame(
                1,
                count($partition['invalid_rows']),
                'A stale list, network, or device must remain repairable at case '
                    . (string) $position
                    . '.',
            );
            sinkholeTestAssertContains(
                'no longer exists',
                $partition['invalid_rows'][0]['reason'],
                'The repair reason must name the missing reference.',
            );
        }
    },
    'allowed domains normalize from repeated elements' => static function (): void {
        $allowed = DomainParser::normalizeAllowedDomainValues([
            'Example.Test.',
            'sub.example.test',
            'EXAMPLE.TEST',
            'invalid_name.test',
            'lan',
        ]);

        sinkholeTestAssertSame(
            ['example.test', 'invalid_name.test', 'sub.example.test'],
            $allowed['domains'],
            'Repeated elements must normalize, deduplicate, and sort independently.',
        );
        sinkholeTestAssertSame(
            [5],
            $allowed['invalid_positions'],
            'Invalid repeated elements must retain one-based positions.',
        );
    },
    'keep settings distinguishes a missing record from an unchecked box' => static function (): void {
        sinkholeTestAssertSame(
            true,
            Settings::fromStorage([])['keep_settings'],
            'A missing settings record must keep package data by default.',
        );
        sinkholeTestAssertSame(
            false,
            Settings::fromStorage(['update_frequency' => 'daily'])['keep_settings'],
            'A saved record without the checkbox must delete package data.',
        );
        sinkholeTestAssertSame(
            true,
            Settings::fromStorage([
                'update_frequency' => 'daily',
                'keep_settings' => 'on',
            ])['keep_settings'],
            'A checked Keep Settings box must retain package data.',
        );
    },
    'translation catalog is complete used and placeholder safe' => static function (): void {
        $workspace = dirname(__DIR__);
        $catalogs = require(
            $workspace . '/port/files/usr/local/pkg/sinkhole/Translations.php'
        );
        $english = $catalogs['en_US'] ?? null;

        sinkholeTestAssertTrue(is_array($english), 'The English source catalog must exist.');
        sinkholeTestAssertSame(
            [
                'bs',
                'zh_CN',
                'zh_Hans_CN',
                'zh_Hans_HK',
                'zh_Hant_TW',
                'nl_NL',
                'en_US',
                'fr_FR',
                'de_DE',
                'it_IT',
                'ko_FR',
                'nb_NO',
                'pl_PL',
                'pt_PT',
                'pt_BR',
                'ru_RU',
                'es_ES',
                'es_AR',
            ],
            Translator::supportedLocales(),
            'The catalog must use pfSense exact language identifiers.',
        );
        sinkholeTestAssertSame(
            'Lists',
            Translator::translateForLocale('en_US', 'lists'),
            'English must render from its source catalog.',
        );
        sinkholeTestAssertSame(
            'Lists',
            Translator::translateForLocale('xx_XX', 'lists'),
            'An unknown identifier must fall back to English.',
        );
        $catalogProperty = (new ReflectionClass(Translator::class))->getProperty('catalogs');
        $loadedCatalogs = $catalogProperty->getValue();
        sinkholeTestAssertTrue(
            is_array($loadedCatalogs),
            'The translator catalogs must be loaded for the fallback fixture.',
        );
        $fixtureCatalogs = $loadedCatalogs;
        $fixtureCatalogs['fixture'] = ['about' => 'Fixture About'];

        try {
            $catalogProperty->setValue(null, $fixtureCatalogs);
            sinkholeTestAssertSame(
                'Fixture About',
                Translator::translateForLocale('fixture', 'about'),
                'The fallback fixture must select its translated value.',
            );
            sinkholeTestAssertSame(
                'Lists',
                Translator::translateForLocale('fixture', 'lists'),
                'A missing translated key must fall back to English.',
            );
        } finally {
            $catalogProperty->setValue(null, $loadedCatalogs);
        }

        $placeholderMismatchRejected = false;

        try {
            Translator::translateForLocale('en_US', 'support_number');
        } catch (RuntimeException $exception) {
            $placeholderMismatchRejected = str_contains(
                $exception->getMessage(),
                'expects 1 argument(s); received 0',
            );
        }

        sinkholeTestAssertSame(
            true,
            $placeholderMismatchRejected,
            'The translator must reject a call whose arguments do not match its placeholders.',
        );

        $placeholderSignature = static function (string $template): array {
            preg_match_all(
                '/%(?:([1-9][0-9]*)\$)?[-+ 0\'#]*[0-9]*(?:\.[0-9]+)?([bcdeEfFgGosuxX])/',
                $template,
                $matches,
                PREG_SET_ORDER,
            );
            $nextPosition = 1;
            $signature = [];

            foreach ($matches as $match) {
                $position = ($match[1] === '') ? $nextPosition : (int) $match[1];
                $signature[] = $position . ':' . $match[2];

                if ($match[1] === '') {
                    $nextPosition += 1;
                }
            }

            sort($signature);

            return $signature;
        };
        $literalTokens = static function (string $template): array {
            $withoutPlaceholders = preg_replace(
                '/%(?:[1-9][0-9]*\$)?[-+ 0\'#]*[0-9]*(?:\.[0-9]+)?[bcdeEfFgGosuxX]/',
                '',
                $template,
            );
            sinkholeTestAssertTrue(
                is_string($withoutPlaceholders),
                'Literal-token inspection must remove sprintf placeholders.',
            );
            preg_match_all(
                '/__SINKHOLE_[A-Z0-9_]+__'
                    . '|https?:\/\/[^\s\'"<>]+'
                    . '|\/(?:var|usr|tmp)\/[A-Za-z0-9._~!$&()*+,;=:@%\/-]+'
                    . '|(?<![A-Za-z0-9])pkg add -f(?![A-Za-z0-9])'
                    . '|--[a-z0-9][a-z0-9-]*'
                    . '|(?<![A-Za-z0-9])RFC 9462(?![A-Za-z0-9])'
                    . '|(?<![A-Za-z0-9])SHA-256(?![A-Za-z0-9])'
                    . '|(?<![A-Za-z0-9])github\.com(?![A-Za-z0-9])'
                    . '|(?<![A-Za-z0-9])(?:AdGuard Home|iCloud Private Relay|Private Relay|DNS over HTTPS|DNS over TLS|DNS over QUIC'
                    . '|Sinkhole|pfSense|Unbound|MaxMind|GeoLite2|pfBlockerNG|GitHub|Firefox'
                    . '|WireGuard|OpenVPN|IPsec|CARP|Tor|VPN|IPv4|IPv6|CIDR|DNS|HTTP|HTTPS|TLS|QUIC|SSL)(?![A-Za-z0-9])'
                    . '|#'
                    . '|(?<![A-Za-z0-9.])[0-9]+(?![A-Za-z0-9])/u',
                $withoutPlaceholders,
                $matches,
            );
            $tokens = $matches[0];
            sort($tokens);

            return $tokens;
        };
        $translatedLocales = [
            'bs',
            'zh_CN',
            'zh_Hans_CN',
            'zh_Hans_HK',
            'zh_Hant_TW',
            'nl_NL',
            'fr_FR',
            'de_DE',
            'it_IT',
            'ko_FR',
            'nb_NO',
            'pl_PL',
            'pt_PT',
            'pt_BR',
            'ru_RU',
            'es_ES',
            'es_AR',
        ];
        $englishKeys = array_keys($english);
        sort($englishKeys);

        foreach ($translatedLocales as $translatedLocale) {
            $translatedCatalog = $catalogs[$translatedLocale] ?? null;
            sinkholeTestAssertTrue(
                is_array($translatedCatalog),
                'The translated catalog must exist: ' . $translatedLocale,
            );
            $translatedKeys = array_keys($translatedCatalog);
            sort($translatedKeys);
            sinkholeTestAssertSame(
                [],
                array_values(array_diff($englishKeys, $translatedKeys)),
                'The translated catalog must not omit keys: ' . $translatedLocale,
            );
            sinkholeTestAssertSame(
                [],
                array_values(array_diff($translatedKeys, $englishKeys)),
                'The translated catalog must not add keys: ' . $translatedLocale,
            );

            foreach ($english as $catalogKey => $englishTemplate) {
                $translatedTemplate = $translatedCatalog[$catalogKey] ?? null;
                sinkholeTestAssertTrue(
                    is_string($translatedTemplate) && $translatedTemplate !== '',
                    'Every translated catalog value must be a non-empty string: '
                        . $translatedLocale . '/' . $catalogKey,
                );
                sinkholeTestAssertSame(
                    $placeholderSignature($englishTemplate),
                    $placeholderSignature($translatedTemplate),
                    'Translated placeholders must preserve positions and types: '
                        . $translatedLocale . '/' . $catalogKey,
                );
                sinkholeTestAssertSame(
                    $literalTokens($englishTemplate),
                    $literalTokens($translatedTemplate),
                    'Translated literal tokens must be preserved: '
                        . $translatedLocale . '/' . $catalogKey,
                );
            }
        }

        $sourceFiles = array_merge(
            glob($workspace . '/port/files/usr/local/pkg/sinkhole/*.php') ?: [],
            glob($workspace . '/port/files/usr/local/www/*.php') ?: [],
            [
                $workspace . '/port/files/usr/local/pkg/sinkhole.inc',
                $workspace . '/port/files/usr/local/sbin/sinkhole',
            ],
        );
        $source = '';

        foreach ($sourceFiles as $sourceFile) {
            if (str_ends_with($sourceFile, '/Translations.php')) {
                continue;
            }

            $contents = (string) file_get_contents($sourceFile);
            $auditedContents = str_replace(
                'return Translator::translate($key, $arguments);',
                '',
                $contents,
            );
            preg_match_all(
                '/(?<!function )(?:pfsensePackageSinkholeTranslate|Translator::translate)\(\s*+(?![\'\"])/',
                $auditedContents,
                $dynamicMatches,
            );
            sinkholeTestAssertSame(
                [],
                $dynamicMatches[0],
                'Computed translations must use a closed key map: ' . $sourceFile,
            );
            $source .= $contents . "\n";
        }

        preg_match_all(
            '/(?:pfsensePackageSinkholeTranslate|Translator::translate|new ValidationException)\(\s*[\'\"]([a-z][a-z0-9_]*)[\'\"]/',
            $source,
            $usedMatches,
        );

        foreach (array_unique($usedMatches[1]) as $usedKey) {
            sinkholeTestAssertTrue(
                array_key_exists($usedKey, $english),
                'Every directly used catalog key must exist: ' . $usedKey,
            );
        }

        foreach (array_keys($english) as $catalogKey) {
            sinkholeTestAssertTrue(
                preg_match(
                    '/[\'\"]' . preg_quote($catalogKey, '/') . '[\'\"]/',
                    $source,
                ) === 1,
                'Every English catalog key must be used: ' . $catalogKey,
            );
        }

        $mapConstant = (new ReflectionClass(Translator::class))->getReflectionConstant(
            'TRANSLATION_KEY_MAPS',
        );
        sinkholeTestAssertTrue(
            $mapConstant instanceof ReflectionClassConstant,
            'The translator must declare closed mappings for computed values.',
        );
        $translationKeyMaps = $mapConstant->getValue();
        sinkholeTestAssertTrue(
            is_array($translationKeyMaps),
            'The computed translation mappings must be arrays.',
        );

        foreach ($translationKeyMaps as $mapName => $mapping) {
            sinkholeTestAssertTrue(
                is_string($mapName) && is_array($mapping) && $mapping !== [],
                'Every computed translation mapping must be named and non-empty.',
            );

            foreach ($mapping as $value => $catalogKey) {
                sinkholeTestAssertTrue(
                    is_string($value)
                        && is_string($catalogKey)
                        && array_key_exists($catalogKey, $english),
                    'Every computed translation value must map to a declared key: '
                        . $mapName . '/' . (string) $value,
                );
                $template = $english[$catalogKey];
                preg_match_all(
                    '/%(?:([1-9][0-9]*)\$)?[-+ 0\'#]*[0-9]*(?:\.[0-9]+)?[bcdeEfFgGosuxX]/',
                    $template,
                    $mappedPlaceholderMatches,
                );
                $mappedPositions = array_values(array_filter(
                    $mappedPlaceholderMatches[1],
                    static fn(string $position): bool => $position !== '',
                ));
                $mappedArgumentCount = ($mappedPlaceholderMatches[0] === [])
                    ? 0
                    : (($mappedPositions === [])
                        ? count($mappedPlaceholderMatches[0])
                        : max(array_map('intval', $mappedPositions)));
                $mappedArguments = array_fill(0, $mappedArgumentCount, 1);

                sinkholeTestAssertSame(
                    Translator::translateForLocale('en_US', $catalogKey, $mappedArguments),
                    Translator::translateMapped(
                        $mapName,
                        $value,
                        $mappedArguments,
                    ),
                    'Every computed translation state must render: '
                        . $mapName . '/' . $value,
                );
            }
        }

        sinkholeTestAssertSame(
            'IPv4 and IPv6',
            Translator::translateMapped('ip_family', 'both'),
            'The stored both-family value must use its explicit display key.',
        );

        foreach ($english as $catalogKey => $template) {
            preg_match_all(
                '/%(?:([1-9][0-9]*)\$)?[-+ 0\'#]*[0-9]*(?:\.[0-9]+)?[bcdeEfFgGosuxX]/',
                $template,
                $placeholderMatches,
            );
            $positions = array_values(array_filter(
                $placeholderMatches[1],
                static fn(string $position): bool => $position !== '',
            ));
            $argumentCount = ($placeholderMatches[0] === [])
                ? 0
                : (($positions === [])
                    ? count($placeholderMatches[0])
                    : max(array_map('intval', $positions)));
            $arguments = array_fill(0, $argumentCount, 1);
            $renderedEnglish = Translator::translateForLocale(
                'en_US',
                $catalogKey,
                $arguments,
            );
            $renderedFallback = Translator::translateForLocale(
                'xx_XX',
                $catalogKey,
                $arguments,
            );

            sinkholeTestAssertTrue(
                $renderedEnglish !== '',
                'Every catalog value must render with its declared placeholders: '
                    . $catalogKey,
            );
            sinkholeTestAssertSame(
                $renderedEnglish,
                $renderedFallback,
                'Every page message must render through an unknown-locale English fallback: '
                    . $catalogKey,
            );
        }
    },
    'Sinkhole wording does not use the pfSense gettext catalog' => static function (): void {
        $workspace = dirname(__DIR__);
        $sourceFiles = array_merge(
            glob($workspace . '/port/files/usr/local/pkg/sinkhole/*.php') ?: [],
            glob($workspace . '/port/files/usr/local/www/*.php') ?: [],
            [
                $workspace . '/port/files/usr/local/pkg/sinkhole.inc',
                $workspace . '/port/files/usr/local/sbin/sinkhole',
            ],
        );
        $allowedPfSenseWords = ['Firewall', 'active', 'expired', 'reserved', 'Never'];

        foreach ($sourceFiles as $sourceFile) {
            $contents = (string) file_get_contents($sourceFile);
            preg_match_all('/gettext\(\s*[\'\"]([^\'\"]+)[\'\"]\s*\)/', $contents, $matches);

            foreach ($matches[1] as $wording) {
                sinkholeTestAssertTrue(
                    in_array($wording, $allowedPfSenseWords, true),
                    'Package wording must use Translator instead of gettext: ' . $wording,
                );
            }
        }
    },
    'installed privilege file grants all Sinkhole pages' => static function (): void {
        $workspace = dirname(__DIR__);
        $privilegePath = $workspace
            . '/port/files/usr/local/pkg/priv/sinkhole.priv.inc';
        $privileges = (string) file_get_contents($privilegePath);
        $plist = (string) file_get_contents($workspace . '/port/pkg-plist');
        $makefile = (string) file_get_contents($workspace . '/port/Makefile.template');
        $aboutPage = (string) file_get_contents(
            $workspace . '/port/files/usr/local/www/sinkhole-about.php',
        );
        $buildScript = (string) file_get_contents($workspace . '/scripts/build-package.sh');
        $commandScript = (string) file_get_contents(
            $workspace . '/port/files/usr/local/sbin/sinkhole',
        );
        $packageLogo = (string) file_get_contents(
            $workspace . '/port/files/usr/local/share/pfSense-pkg-Sinkhole/logo.svg',
        );

        foreach (
            [
                'page-firewall-sinkhole-general',
                'page-firewall-sinkhole-lists',
                'page-firewall-sinkhole-lists-edit',
                'page-firewall-sinkhole-services',
                'page-firewall-sinkhole-scopes',
                'page-firewall-sinkhole-scopes-edit',
                'page-firewall-sinkhole-alerts',
                'page-firewall-sinkhole-alerts-edit',
                'page-firewall-sinkhole-bypass',
                'page-firewall-sinkhole-bypass-edit',
                'page-firewall-sinkhole-ip',
                'page-firewall-sinkhole-ip-edit',
                'page-firewall-sinkhole-status',
                'page-firewall-sinkhole-about',
            ] as $identity
        ) {
            sinkholeTestAssertContains(
                $identity,
                $privileges,
                'The installed privilege map must grant every Sinkhole page.',
            );
        }

        sinkholeTestAssertContains(
            'pkg/priv/sinkhole.priv.inc',
            $plist,
            'The privilege file must be present in pkg-plist.',
        );
        sinkholeTestAssertContains(
            '/pkg/priv/sinkhole.priv.inc',
            $makefile,
            'The port must install the privilege file.',
        );
        sinkholeTestAssertContains(
            'www/sinkhole-about.php',
            $plist,
            'The About page must be present in pkg-plist.',
        );
        sinkholeTestAssertContains(
            'www/sinkhole-services.php',
            $plist,
            'The Services page must be present in pkg-plist.',
        );
        sinkholeTestAssertContains(
            '/www/sinkhole-services.php',
            $makefile,
            'The port must install the Services page.',
        );

        foreach ([
            'sinkhole-alerts_edit.php',
            'sinkhole-bypass_edit.php',
            'sinkhole-ip_edit.php',
            'sinkhole-lists_edit.php',
            'sinkhole-scopes_edit.php',
        ] as $editorPage) {
            sinkholeTestAssertContains(
                'www/' . $editorPage,
                $plist,
                'Every editor page must be present in pkg-plist.',
            );
            sinkholeTestAssertContains(
                '/www/' . $editorPage,
                $makefile,
                'The port must install every editor page.',
            );
        }
        sinkholeTestAssertContains(
            '/www/sinkhole-about.php',
            $makefile,
            'The port must install the About page.',
        );
        sinkholeTestAssertContains(
            'UpdateManager::installedVersion()',
            $aboutPage,
            'The About page must read the installed version through the update manager.',
        );
        sinkholeTestAssertContains(
            "pfsensePackageSinkholeTabs('about')",
            $aboutPage,
            'The About page must activate the final package tab.',
        );
        sinkholeTestAssertContains(
            'fa-brands fa-github',
            $aboutPage,
            'The About page must use Font Awesome 6-compatible brand classes.',
        );
        sinkholeTestAssertContains(
            'file_get_contents($packageLogoPath)',
            $aboutPage,
            'The About page must read its installed logo.',
        );
        sinkholeTestAssertContains(
            "'data:image/svg+xml;base64,'",
            $aboutPage,
            'The About page must render its SVG through a data URI.',
        );
        sinkholeTestAssertContains(
            'if ($testedReleases !== [])',
            $aboutPage,
            'An empty tested-release list must hide the release table.',
        );
        sinkholeTestAssertSame(
            false,
            str_contains($aboutPage, 'Important information'),
            'The About page must not include an Important information panel.',
        );
        sinkholeTestAssertSame(
            false,
            str_contains($aboutPage, 'Project Links'),
            'The About page must not include the former Project Links panel.',
        );
        sinkholeTestAssertContains(
            '${FILESDIR}${DATADIR}/logo.svg',
            $makefile,
            'The port must stage the package logo.',
        );
        sinkholeTestAssertContains(
            '%%DATADIR%%/logo.svg',
            $plist,
            'The package manifest must install the package logo.',
        );
        sinkholeTestAssertTrue(
            $packageLogo !== '',
            'The installed package logo must be present.',
        );
        sinkholeTestAssertContains(
            "WWW=\thttps://mrjackyliang.github.io/pfsense-sinkhole/",
            $makefile,
            'The port must publish the project website.',
        );
        sinkholeTestAssertContains(
            "pkg query -F \"\${artifact}\" '%q'",
            $buildScript,
            'The package build must query the rebuilt ABI.',
        );
        sinkholeTestAssertContains(
            "!= 'FreeBSD:*'",
            $buildScript,
            'The package build must require the any-FreeBSD ABI.',
        );
        sinkholeTestAssertContains(
            "pkg query -F \"\${artifact}\" '%V'",
            $buildScript,
            'The package build must query the vital flag.',
        );
        sinkholeTestAssertContains(
            "!= '1'",
            $buildScript,
            'The package build must require the vital flag.',
        );
        sinkholeTestAssertContains(
            "stable_artifact_name='pfSense-pkg-Sinkhole.pkg'",
            $buildScript,
            'The package build must write the stable-named release artifact.',
        );
        sinkholeTestAssertSame(
            1,
            substr_count($commandScript, '$adapter->refreshConfiguration();'),
            'The command must refresh only through its before-rerun callback.',
        );
        sinkholeTestAssertContains(
            "? 'Redirect check failed' : 'Update failed'",
            $commandScript,
            'A failed redirect check must use its own log message.',
        );
        sinkholeTestAssertSame(
            false,
            str_contains($privileges, '##|+PRIV'),
            'Build-time privilege headers do not belong in the installed map.',
        );
    },
]);
