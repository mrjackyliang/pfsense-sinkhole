<?php

declare(strict_types=1);

use PfSense\Sinkhole\Runtime\AlertProcessor;
use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\FileLock;
use PfSense\Sinkhole\Runtime\FileSystem;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\PfSenseAdapter;
use PfSense\Sinkhole\Runtime\StateStore;

set_include_path(__DIR__ . '/stubs' . PATH_SEPARATOR . get_include_path());

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/stubs/config.inc');
require_once(__DIR__ . '/stubs/services.inc');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole.inc');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/AlertProcessor.php');

const SINKHOLE_ALERT_TEST_LIST = '11111111111111111111111111111111';
const SINKHOLE_ALERT_TEST_RULE = '44444444444444444444444444444444';
const SINKHOLE_ALERT_TEST_NETWORK = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const SINKHOLE_ALERT_TEST_DEVICE = 'dddddddddddddddddddddddddddddddd';

/**
 * Sinkhole Alert Test - Paths.
 *
 * @param string $root - Disposable root.
 *
 * @return PackagePaths
 *
 * @since 1.0.0
 */
function sinkholeAlertTestPaths(string $root): PackagePaths
{
    return new PackagePaths([
        'persistent_directory' => $root . '/persistent',
        'runtime_root_directory' => $root . '/runtime',
        'module_source_file' => $root . '/source/sinkhole_unbound.py',
        'update_lock_file' => $root . '/sinkhole-update.lock',
        'runtime_lock_file' => $root . '/sinkhole-runtime.lock',
        'client_lock_file' => $root . '/sinkhole-clients.lock',
        'alert_lock_file' => $root . '/sinkhole-alerts.lock',
        'redirect_check_lock_file' => $root . '/sinkhole-redirect-check.lock',
        'redirect_check_state_file' => $root . '/sinkhole-redirect-check.json',
        'alert_repeat_state_file' => $root . '/sinkhole-alerts.json',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/**
 * Sinkhole Alert Test - Prepare Manifest.
 *
 * @param PackagePaths $paths - Test paths.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeAlertTestPrepareManifest(PackagePaths $paths): void
{
    FileSystem::ensureDirectory($paths->runtimeRootDirectory, 0700);
    FileSystem::ensureDirectory($paths->runtimeStorageDirectory, 0700);
    FileSystem::ensureDirectory($paths->runtimeStateDirectory, 0700);
    $generationName = '.sinkhole-generation-0123456789abcdef';
    $generationPath = $paths->runtimeStorageDirectory . '/' . $generationName;
    FileSystem::ensureDirectory($generationPath, 0700);
    $manifest = [
        'schema_version' => Compiler::MANIFEST_SCHEMA_VERSION,
        'generation' => 'alert-test-generation',
        'bypass_file' => 'bypass.tsv',
        'lists' => [
            SINKHOLE_ALERT_TEST_LIST => ['name' => 'Café List', 'bit' => 0],
        ],
        'scopes' => [
            'global' => ['lists' => [SINKHOLE_ALERT_TEST_LIST], 'allow' => 'allow.txt'],
            'networks' => [
                SINKHOLE_ALERT_TEST_NETWORK => [
                    'interface' => 'lan',
                    'lists' => [SINKHOLE_ALERT_TEST_LIST],
                    'allow' => 'allow-network-' . SINKHOLE_ALERT_TEST_NETWORK . '.txt',
                ],
            ],
            'devices' => [
                SINKHOLE_ALERT_TEST_DEVICE => [
                    'lists' => [SINKHOLE_ALERT_TEST_LIST],
                    'allow' => 'allow-device-' . SINKHOLE_ALERT_TEST_DEVICE . '.txt',
                ],
            ],
        ],
        'alerts' => [
            SINKHOLE_ALERT_TEST_RULE => [
                'id' => SINKHOLE_ALERT_TEST_RULE,
                'lists' => 'any',
                'networks' => 'any',
                'devices' => 'any',
            ],
        ],
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
    ];
    file_put_contents(
        $generationPath . '/manifest.json',
        json_encode($manifest, JSON_THROW_ON_ERROR) . PHP_EOL,
    );
    file_put_contents($generationPath . '/bypass.tsv', '');
    symlink(
        basename($paths->runtimeStorageDirectory) . '/' . $generationName,
        $paths->runtimeDataDirectory,
    );
}

/** @return array<string, array> @since 1.0.0 */
function sinkholeAlertTestRules(int $repeatMinutes = 60): array
{
    return [
        SINKHOLE_ALERT_TEST_RULE => [
            'id' => SINKHOLE_ALERT_TEST_RULE,
            'description' => 'Jacky’s Rule',
            'any_list' => true,
            'lists' => [],
            'everyone' => true,
            'networks' => [],
            'devices' => [],
            'repeat_minutes' => $repeatMinutes,
            'notice' => true,
            'remote' => true,
            'enabled' => true,
        ],
    ];
}

/**
 * Sinkhole Alert Test - Configure Rule IDs.
 *
 * @param PackagePaths $paths - Test paths.
 * @param list<string> $identifiers - Rule identifiers.
 *
 * @return array<string, array>
 *
 * @since 1.0.0
 */
function sinkholeAlertTestConfigureRuleIds(PackagePaths $paths, array $identifiers): array
{
    $manifestPath = $paths->runtimeDataDirectory . '/manifest.json';
    $manifest = json_decode(
        (string) file_get_contents($manifestPath),
        true,
        32,
        JSON_THROW_ON_ERROR,
    );
    $manifest['alerts'] = [];
    $rules = [];

    foreach ($identifiers as $index => $identifier) {
        $manifest['alerts'][$identifier] = [
            'id' => $identifier,
            'lists' => 'any',
            'networks' => 'any',
            'devices' => 'any',
        ];
        $rules[$identifier] = [
            'id' => $identifier,
            'description' => 'Rule ' . ($index + 1),
            'any_list' => true,
            'lists' => [],
            'everyone' => true,
            'networks' => [],
            'devices' => [],
            'repeat_minutes' => 60,
            'notice' => true,
            'remote' => false,
            'enabled' => true,
        ];
    }

    file_put_contents(
        $manifestPath,
        json_encode($manifest, JSON_THROW_ON_ERROR) . PHP_EOL,
    );

    return $rules;
}

/** @return array<string, array> @since 1.0.0 */
function sinkholeAlertTestLists(): array
{
    return [
        SINKHOLE_ALERT_TEST_LIST => [
            'id' => SINKHOLE_ALERT_TEST_LIST,
            'name' => 'Café List',
        ],
    ];
}

/** @return array<string, array> @since 1.0.0 */
function sinkholeAlertTestNetworks(): array
{
    return [
        SINKHOLE_ALERT_TEST_NETWORK => [
            'id' => SINKHOLE_ALERT_TEST_NETWORK,
            'interface' => 'lan',
        ],
    ];
}

/** @return array<string, array> @since 1.0.0 */
function sinkholeAlertTestDevices(): array
{
    return [
        SINKHOLE_ALERT_TEST_DEVICE => [
            'id' => SINKHOLE_ALERT_TEST_DEVICE,
            'name' => 'Kitchen Phone',
        ],
    ];
}

/**
 * Sinkhole Alert Test - Event.
 *
 * @param string $name - Query name.
 * @param string $rule - Rule ID.
 *
 * @return array
 *
 * @since 1.0.0
 */
function sinkholeAlertTestEvent(
    string $name = 'blocked.example.test',
    string $rule = SINKHOLE_ALERT_TEST_RULE,
): array {
    return [
        't' => 900,
        'client' => '192.0.2.10',
        'device' => SINKHOLE_ALERT_TEST_DEVICE,
        'network' => SINKHOLE_ALERT_TEST_NETWORK,
        'name' => $name,
        'cname' => null,
        'rules' => [$rule],
        'lists' => [SINKHOLE_ALERT_TEST_LIST],
    ];
}

/**
 * Sinkhole Alert Test - Write Events.
 *
 * @param PackagePaths $paths - Test paths.
 * @param list<string|array> $lines - Raw lines or event objects.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeAlertTestWriteEvents(PackagePaths $paths, array $lines): void
{
    $contents = '';

    foreach ($lines as $line) {
        $contents .= is_string($line)
            ? $line . PHP_EOL
            : json_encode($line, JSON_THROW_ON_ERROR) . PHP_EOL;
    }

    file_put_contents($paths->eventsFile, $contents);
    chmod($paths->eventsFile, 0600);
}

/**
 * Sinkhole Alert Test - Run Processor.
 *
 * @param AlertProcessor $processor - Processor.
 * @param array<string, array>|null $rules - Rule override.
 *
 * @return array
 *
 * @since 1.0.0
 */
function sinkholeAlertTestRun(
    AlertProcessor $processor,
    ?array $rules = null,
): array {
    return $processor->run(
        $rules ?? sinkholeAlertTestRules(),
        sinkholeAlertTestLists(),
        sinkholeAlertTestNetworks(),
        sinkholeAlertTestDevices(),
        ['lan' => 'LAN'],
    );
}

sinkholeTestRun([
    'alert delivery uses exact pfSense channel arguments' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
            $notices = [];
            $remote = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile),
                static function (...$arguments) use (&$notices): void {
                    $notices[] = $arguments;
                },
                static function (string $message) use (&$remote): void {
                    $remote[] = $message;
                },
                static fn(): int => 1000,
                static fn(): string => 'sinkhole-test-notice',
            );
            $result = sinkholeAlertTestRun($processor);
            $message = 'Sinkhole blocked blocked.example.test for Kitchen Phone on LAN '
                . '(list Café List, rule Jacky’s Rule).';
            sinkholeTestAssertSame(
                [[
                    'sinkhole-test-notice',
                    $message,
                    'Sinkhole',
                    '/sinkhole-alerts.php',
                    1,
                    true,
                ]],
                $notices,
                'file_notice() must receive the exact local-only arguments.',
            );
            sinkholeTestAssertSame([$message], $remote, 'Remote delivery must receive the same text.');
            sinkholeTestAssertSame(1, $result['notifications_sent'], 'One logical alert must send.');
            sinkholeTestAssertSame(
                0600,
                fileperms($paths->alertRepeatStateFile) & 0777,
                'Repeat state must remain mode 0600.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'alert delivery honors each per-rule channel choice' => static function (): void {
        $cases = [
            'notice only' => [true, false, 1, 0, 1],
            'remote only' => [false, true, 0, 1, 1],
            'neither channel' => [false, false, 0, 0, 0],
        ];

        foreach ($cases as $label => $expected) {
            $directory = sinkholeTestTemporaryDirectory();

            try {
                $paths = sinkholeAlertTestPaths($directory);
                sinkholeAlertTestPrepareManifest($paths);
                sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
                $notices = [];
                $remote = [];
                $rules = sinkholeAlertTestRules();
                $rules[SINKHOLE_ALERT_TEST_RULE]['notice'] = $expected[0];
                $rules[SINKHOLE_ALERT_TEST_RULE]['remote'] = $expected[1];
                $processor = new AlertProcessor(
                    $paths,
                    new StateStore($paths->stateFile),
                    static function (...$arguments) use (&$notices): void {
                        $notices[] = $arguments;
                    },
                    static function (string $message) use (&$remote): void {
                        $remote[] = $message;
                    },
                    static fn(): int => 1000,
                    static fn(): string => 'channel-choice-test',
                );
                $result = sinkholeAlertTestRun($processor, $rules);
                sinkholeTestAssertSame(
                    $expected[2],
                    count($notices),
                    $label . ' must make the expected WebGUI calls.',
                );
                sinkholeTestAssertSame(
                    $expected[3],
                    count($remote),
                    $label . ' must make the expected remote calls.',
                );
                sinkholeTestAssertSame(
                    $expected[4],
                    $result['notifications_sent'],
                    $label . ' must report the expected logical delivery count.',
                );
            } finally {
                sinkholeTestRemoveTemporaryDirectory($directory);
            }
        }
    },
    'alert repeat window suppresses and later permits the same key' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            $now = 1000;
            $messages = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile),
                static function (...$arguments) use (&$messages): void {
                    $messages[] = $arguments[1];
                },
                static function (string $message): void {
                    unset($message);
                },
                static function () use (&$now): int {
                    return $now;
                },
                static fn(): string => 'repeat-test',
            );
            $rules = sinkholeAlertTestRules(1);
            sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
            sinkholeAlertTestRun($processor, $rules);
            $now = 1059;
            sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
            sinkholeAlertTestRun($processor, $rules);
            $now = 1060;
            sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
            sinkholeAlertTestRun($processor, $rules);
            sinkholeTestAssertSame(2, count($messages), 'The repeat window must suppress only the middle event.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'alert burst stays within twenty messages and summarizes overflow' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            $events = [];

            for ($index = 0; $index < 25; $index++) {
                $events[] = sinkholeAlertTestEvent('blocked-' . $index . '.example.test');
            }

            sinkholeAlertTestWriteEvents($paths, $events);
            $messages = [];
            $rules = sinkholeAlertTestRules();
            $rules[SINKHOLE_ALERT_TEST_RULE]['remote'] = false;
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile),
                static function (...$arguments) use (&$messages): void {
                    $messages[] = $arguments[1];
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'burst-test',
            );
            $result = sinkholeAlertTestRun($processor, $rules);
            sinkholeTestAssertSame(20, count($messages), 'A run must send at most twenty messages.');
            sinkholeTestAssertSame(20, $result['notifications_sent'], 'Status must use the same cap.');
            sinkholeTestAssertSame(
                'Sinkhole: 6 more blocks for rule Jacky’s Rule in the last minute',
                $messages[19],
                'Overflow must fold into one per-rule summary within the cap.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'alert reader skips malformed and unknown lines' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            sinkholeAlertTestWriteEvents($paths, [
                '{broken',
                sinkholeAlertTestEvent(
                    'unknown.example.test',
                    '99999999999999999999999999999999',
                ),
                sinkholeAlertTestEvent(),
            ]);
            $messages = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile),
                static function (...$arguments) use (&$messages): void {
                    $messages[] = $arguments[1];
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'reader-test',
            );
            $result = sinkholeAlertTestRun($processor);
            sinkholeTestAssertSame(3, $result['events_read'], 'Every input line must be counted.');
            sinkholeTestAssertSame(1, $result['bad_lines'], 'Malformed JSON must be counted.');
            sinkholeTestAssertSame(1, $result['unknown_lines'], 'Unknown IDs must be counted.');
            sinkholeTestAssertSame(1, count($messages), 'The known valid event must still send.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'alert reader never follows a symlinked event file' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            $target = $directory . '/outside-events';
            file_put_contents(
                $target,
                json_encode(sinkholeAlertTestEvent(), JSON_THROW_ON_ERROR) . PHP_EOL,
            );
            symlink($target, $paths->eventsFile);
            $messages = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile),
                static function (...$arguments) use (&$messages): void {
                    $messages[] = $arguments[1];
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'symlink-test',
            );
            $result = sinkholeAlertTestRun($processor);
            sinkholeTestAssertSame([], $messages, 'A symlink target must never be read.');
            sinkholeTestAssertSame(
                json_encode(sinkholeAlertTestEvent(), JSON_THROW_ON_ERROR) . PHP_EOL,
                file_get_contents($target),
                'Rejecting the link must leave its target untouched.',
            );
            sinkholeTestAssertContains('unsafe', (string) $result['error'], 'The unsafe event path must be reported.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'one failed alert channel does not stop the other' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
            $remote = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile),
                static function (...$arguments): void {
                    unset($arguments);
                    throw new RuntimeException('notice unavailable');
                },
                static function (string $message) use (&$remote): void {
                    $remote[] = $message;
                },
                static fn(): int => 1000,
                static fn(): string => 'failure-test',
            );
            $result = sinkholeAlertTestRun($processor);
            sinkholeTestAssertSame(1, count($remote), 'Remote delivery must continue after notice failure.');
            sinkholeTestAssertSame(1, $result['notifications_sent'], 'One successful channel sends the alert.');
            sinkholeTestAssertContains('notice unavailable', (string) $result['error'], 'The failed channel must be reported.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'alert time budget stops later channels and preserves the batch' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
            $elapsed = 0.0;
            $notices = [];
            $remote = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
                static function (...$arguments) use (&$elapsed, &$notices): void {
                    $notices[] = $arguments[1];
                    $elapsed = 41.0;
                },
                static function (string $message) use (&$remote): void {
                    $remote[] = $message;
                },
                static fn(): int => 1000,
                static fn(): string => 'time-budget-test',
                static fn(): int => 0,
                static function () use (&$elapsed): float {
                    return $elapsed;
                },
            );
            $result = sinkholeAlertTestRun($processor);

            sinkholeTestAssertSame(1, count($notices), 'The in-budget notice must send.');
            sinkholeTestAssertSame([], $remote, 'No channel may start after the budget is spent.');
            sinkholeTestAssertSame(
                true,
                $result['time_budget_exhausted'],
                'The run must report its exhausted budget.',
            );
            sinkholeTestAssertTrue(
                is_file($paths->eventsProcessingFile),
                'An incomplete batch must remain for the next run.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'hourly rule cap sends one final summary and holds later messages' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            $messages = [];
            $store = new StateStore($paths->stateFile, $paths->statusFile);
            $rules = sinkholeAlertTestRules();
            $rules[SINKHOLE_ALERT_TEST_RULE]['remote'] = false;
            $processor = new AlertProcessor(
                $paths,
                $store,
                static function (...$arguments) use (&$messages): void {
                    $messages[] = $arguments[1];
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'hourly-cap-test',
                static fn(): int => 0,
            );

            for ($run = 0; $run < 3; $run++) {
                $events = [];

                for ($index = 0; $index < 20; $index++) {
                    $events[] = sinkholeAlertTestEvent(sprintf(
                        'hour-%d-%d.example.test',
                        $run,
                        $index,
                    ));
                }

                sinkholeAlertTestWriteEvents($paths, $events);
                sinkholeAlertTestRun($processor, $rules);
            }

            sinkholeTestAssertSame(60, count($messages), 'A rule must send at most sixty in one hour.');
            sinkholeTestAssertContains(
                'this hour',
                $messages[59],
                'The reserved final slot must summarize hourly overflow.',
            );
            sinkholeAlertTestWriteEvents($paths, [
                sinkholeAlertTestEvent('hour-held-1.example.test'),
                sinkholeAlertTestEvent('hour-held-2.example.test'),
            ]);
            $result = sinkholeAlertTestRun($processor, $rules);
            sinkholeTestAssertSame(60, count($messages), 'Later messages in the hour must not send.');
            sinkholeTestAssertSame(2, $result['notifications_held_back'], 'Held messages must reach Status.');
            sinkholeTestAssertSame(
                2,
                $store->alertStatus()['notifications_held_back'],
                'Runtime status must retain the held-back count.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'unread notice cap leaves remote delivery independent' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            sinkholeAlertTestWriteEvents($paths, [
                sinkholeAlertTestEvent('notice-1.example.test'),
                sinkholeAlertTestEvent('notice-2.example.test'),
                sinkholeAlertTestEvent('notice-3.example.test'),
            ]);
            $notices = [];
            $remote = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
                static function (...$arguments) use (&$notices): void {
                    $notices[] = $arguments[1];
                },
                static function (string $message) use (&$remote): void {
                    $remote[] = $message;
                },
                static fn(): int => 1000,
                static fn(): string => 'notice-cap-test',
                static fn(): int => 49,
            );
            $result = sinkholeAlertTestRun($processor);

            sinkholeTestAssertSame(1, count($notices), 'Only one more unread notice may be added.');
            sinkholeTestAssertSame(3, count($remote), 'Remote delivery has its own budget.');
            sinkholeTestAssertSame(2, $result['notifications_held_back'], 'Skipped notices must be counted.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'event counts are occurrences and stale events are discarded' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            $current = sinkholeAlertTestEvent('counted.example.test');
            $current['count'] = 4;
            $stale = sinkholeAlertTestEvent('stale.example.test');
            $stale['t'] = 399;
            $stale['count'] = 5;
            sinkholeAlertTestWriteEvents($paths, [$current, $stale]);
            $messages = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
                static function (...$arguments) use (&$messages): void {
                    $messages[] = $arguments[1];
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'count-test',
            );
            $result = sinkholeAlertTestRun($processor);

            sinkholeTestAssertSame(9, $result['events_read'], 'Count must expand event occurrences.');
            sinkholeTestAssertSame(5, $result['events_stale'], 'Stale occurrences must be counted.');
            sinkholeTestAssertSame(1, count($messages), 'Only the current coalesced event may notify.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'unknown network identifiers never enter notification text' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
            $messages = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
                static function (...$arguments) use (&$messages): void {
                    $messages[] = $arguments[1];
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'unknown-network-test',
            );
            $processor->run(
                sinkholeAlertTestRules(),
                sinkholeAlertTestLists(),
                [],
                sinkholeAlertTestDevices(),
                [],
            );

            sinkholeTestAssertContains(
                'on an unknown network',
                $messages[0],
                'An absent configuration network must use fixed text.',
            );
            sinkholeTestAssertSame(
                false,
                str_contains($messages[0], 'lan'),
                'The manifest interface must never be reflected.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'alert reader waits for the watcher file lock' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();
        $eventHandle = null;

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
            $eventHandle = fopen($paths->eventsFile, 'r+b');
            sinkholeTestAssertTrue(is_resource($eventHandle), 'The writer fixture must open.');
            sinkholeTestAssertSame(
                true,
                flock($eventHandle, LOCK_EX | LOCK_NB),
                'The writer fixture must own its append lock.',
            );
            $messages = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
                static function (...$arguments) use (&$messages): void {
                    $messages[] = $arguments[1];
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'reader-lock-test',
                static fn(): int => 0,
                static fn(): float => 0.0,
                static function (int $microseconds) use (&$eventHandle): void {
                    unset($microseconds);

                    if (is_resource($eventHandle)) {
                        flock($eventHandle, LOCK_UN);
                        fclose($eventHandle);
                        $eventHandle = null;
                    }
                },
            );
            sinkholeAlertTestRun($processor);

            sinkholeTestAssertSame(1, count($messages), 'The reader must consume after the writer unlocks.');
            sinkholeTestAssertSame(
                false,
                file_exists($paths->eventsProcessingFile),
                'The consumed batch must be removed.',
            );
        } finally {
            if (is_resource($eventHandle)) {
                flock($eventHandle, LOCK_UN);
                fclose($eventHandle);
            }

            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'combined overflow summary records rules beyond the run cap' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            $identifiers = [];

            for ($index = 1; $index <= 25; $index++) {
                $identifiers[] = str_pad(dechex($index), 32, '0', STR_PAD_LEFT);
            }

            $rules = sinkholeAlertTestConfigureRuleIds($paths, $identifiers);
            $event = sinkholeAlertTestEvent('many-rules.example.test');
            $event['rules'] = $identifiers;
            sinkholeAlertTestWriteEvents($paths, [$event]);
            $messages = [];
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
                static function (...$arguments) use (&$messages): void {
                    $messages[] = $arguments[1];
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'combined-summary-test',
            );
            sinkholeAlertTestRun($processor, $rules);
            $repeat = json_decode(
                (string) file_get_contents($paths->alertRepeatStateFile),
                true,
                32,
                JSON_THROW_ON_ERROR,
            );

            sinkholeTestAssertSame(20, count($messages), 'The run cap must remain twenty.');
            sinkholeTestAssertSame(
                'Sinkhole: 6 more blocks across 6 rules in the last minute',
                $messages[19],
                'Rules beyond the detail cap need one combined summary.',
            );
            sinkholeTestAssertSame(
                25,
                count($repeat['entries']),
                'Every detailed or summarized rule key must enter repeat state.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'repeat and runtime status files write only in their proper place' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            $store = new StateStore($paths->stateFile, $paths->statusFile);
            $store->markCompileNeeded();
            $persistentHash = hash_file('sha256', $paths->stateFile);
            sinkholeAlertTestWriteEvents($paths, [sinkholeAlertTestEvent()]);
            $processor = new AlertProcessor(
                $paths,
                $store,
                static function (...$arguments): void {
                    unset($arguments);
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'write-change-test',
            );
            sinkholeAlertTestRun($processor);
            $repeatInode = fileinode($paths->alertRepeatStateFile);
            sinkholeAlertTestRun($processor);
            $store->recordClientMapSuccess(
                '2026-11-06T12:00:00+00:00',
                '2026-11-06T11:59:00+00:00',
                str_repeat('a', 64),
            );

            sinkholeTestAssertSame(
                $repeatInode,
                fileinode($paths->alertRepeatStateFile),
                'An unchanged repeat document must not be replaced.',
            );
            sinkholeTestAssertSame(
                $persistentHash,
                hash_file('sha256', $paths->stateFile),
                'Alert status must not rewrite persistent state.',
            );
            sinkholeTestAssertSame(
                '2026-11-06T12:00:00+00:00',
                $store->clientMapStatus()['refreshed_at'],
                'Client-map rebuild status must use the runtime document.',
            );
            sinkholeTestAssertSame(
                0644,
                fileperms($paths->statusFile) & 0777,
                'Runtime status must be mode 0644.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'FIFO event inputs are rejected without blocking' => static function (): void {
        if (!function_exists('posix_mkfifo')) {
            return;
        }

        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            sinkholeAlertTestPrepareManifest($paths);
            sinkholeTestAssertSame(
                true,
                posix_mkfifo($paths->eventsFile, 0600),
                'The FIFO fixture must be created.',
            );
            $processor = new AlertProcessor(
                $paths,
                new StateStore($paths->stateFile, $paths->statusFile),
                static function (...$arguments): void {
                    unset($arguments);
                },
                static function (string $message): void {
                    unset($message);
                },
                static fn(): int => 1000,
                static fn(): string => 'fifo-test',
            );
            $result = sinkholeAlertTestRun($processor);

            sinkholeTestAssertContains('unsafe', (string) $result['error'], 'A FIFO must be rejected.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'alert lock skips a concurrent run without blocking' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeAlertTestPaths($directory);
            $handle = fopen($paths->alertLockFile, 'x+b');
            sinkholeTestAssertTrue(is_resource($handle), 'The test lock must open.');
            sinkholeTestAssertSame(true, flock($handle, LOCK_EX | LOCK_NB), 'The test lock must be held.');
            $lock = new FileLock($paths->alertLockFile);
            sinkholeTestAssertSame(false, $lock->acquire(), 'A second alert run must exit at once.');
            flock($handle, LOCK_UN);
            fclose($handle);
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'removal deletes alert events and repeat state by fixed names' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();

        try {
            sinkholeStubReset([
                'installedpackages' => ['sinkhole' => ['config' => [[]]]],
                'unbound' => ['enable' => ''],
                'system' => [],
            ]);
            $paths = sinkholeAlertTestPaths($directory);
            FileSystem::ensureDirectory($paths->runtimeStateDirectory, 0700);

            foreach ([$paths->eventsFile, $paths->eventsProcessingFile, $paths->eventsDroppedFile] as $path) {
                file_put_contents($path, "fixture\n");
            }

            file_put_contents($paths->alertRepeatStateFile, "{}\n");
            (new PfSenseAdapter($paths))->uninstall(true);

            foreach ([
                $paths->eventsFile,
                $paths->eventsProcessingFile,
                $paths->eventsDroppedFile,
                $paths->alertRepeatStateFile,
            ] as $path) {
                sinkholeTestAssertSame(false, file_exists($path) || is_link($path), 'Removal must delete ' . $path . '.');
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
]);
