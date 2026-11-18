<?php

declare(strict_types=1);

use PfSense\Sinkhole\Domain\BypassParser;
use PfSense\Sinkhole\Domain\DomainParser;
use PfSense\Sinkhole\Domain\IpParser;
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
use PfSense\Sinkhole\Runtime\UpdateLog;
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
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/UpdateLog.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Updater.php');

/**
 * Sinkhole Update Log Test - Fixture Download Client.
 *
 * Serves invented list bodies by URL and fails every other URL with an error
 * that repeats the URL and the password, so the log's reductions are exercised.
 *
 * @since 1.2.0
 */
final class SinkholeUpdateLogFixtureDownloadClient implements DownloadClient
{
    /**
     * Sinkhole Update Log Test - Constructor.
     *
     * Responses are keyed by the exact configured URL, including any query.
     *
     * @param array<string, string> $responses - Response bodies by URL.
     *
     * @since 1.2.0
     */
    public function __construct(private readonly array $responses)
    {
    }

    /**
     * Sinkhole Update Log Test - Download.
     *
     * Writes the fixture body, or fails with a message carrying the URL and any
     * password the caller supplied.
     *
     * @param string      $url             - URL.
     * @param string      $destinationPath - Destination path.
     * @param int         $maximumBytes    - Maximum bytes.
     * @param string|null $username        - Username.
     * @param string|null $password        - Password.
     *
     * @return array{success: bool, bytes: int, error: string|null}
     *
     * @since 1.2.0
     */
    public function download(
        string $url,
        string $destinationPath,
        int $maximumBytes,
        ?string $username = null,
        ?string $password = null,
    ): array {
        unset($username);
        $contents = $this->responses[$url] ?? null;

        if (!is_string($contents) || strlen($contents) > $maximumBytes) {
            return [
                'success' => false,
                'bytes' => 0,
                'error' => 'Invented transport failure for '
                    . $url
                    . (($password === null) ? '' : ' with ' . $password),
            ];
        }

        $bytes = file_put_contents($destinationPath, $contents);

        return is_int($bytes)
            ? ['success' => true, 'bytes' => $bytes, 'error' => null]
            : ['success' => false, 'bytes' => 0, 'error' => 'Invented fixture write failed.'];
    }
}

/**
 * Sinkhole Update Log Test - Paths.
 *
 * Every package path, including the update log, lives under one temporary root.
 *
 * @param string $root - Test root.
 *
 * @return PackagePaths
 *
 * @since 1.2.0
 */
function sinkholeUpdateLogTestPaths(string $root): PackagePaths
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
        'update_log_file' => $root . '/sinkhole-update.log',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/**
 * Sinkhole Update Log Test - Clock.
 *
 * Returns a clock that advances a quarter second per reading from a fixed start,
 * so durations are stable.
 *
 * @return Closure(): float
 *
 * @since 1.2.0
 */
function sinkholeUpdateLogTestClock(): Closure
{
    $now = 1763294400.0;

    return static function () use (&$now): float {
        $now += 0.25;

        return $now;
    };
}

/**
 * Sinkhole Update Log Test - Configuration.
 *
 * Builds an invented configuration with DNS, Bypass and IP blocking on, one
 * working and one failing list for each, and a MaxMind key to keep secret.
 *
 * @return array<string, mixed>
 *
 * @since 1.2.0
 */
function sinkholeUpdateLogTestConfiguration(): array
{
    return [
        'unbound' => [
            'enable' => 'on',
            'python' => 'on',
            'python_order' => 'pre_validator',
            'python_script' => 'sinkhole',
            'enablessl' => '',
        ],
        'installedpackages' => ['sinkhole' => [
            'config' => [[
                'enabled' => 'on',
                'update_frequency' => 'daily',
                'keep_settings' => 'on',
            ]],
            'lists' => ['item' => [
                [
                    'id' => str_repeat('a', 32),
                    'descr' => 'Invented good list',
                    'url' => 'https://lists.example.test/good.txt?key=invented-list-token',
                    'enabled' => 'on',
                    'global' => 'on',
                ],
                [
                    'id' => str_repeat('b', 32),
                    'descr' => 'Invented broken list',
                    'url' => 'https://broken.example.test/missing.txt?key=invented-list-token',
                    'enabled' => 'on',
                    'global' => 'on',
                ],
            ]],
            'redirect' => [
                'interfaces' => ['item' => ['lan']],
            ],
            'bypass' => [
                'block_tls_quic' => 'on',
                'block_encrypted_dns' => 'on',
                'disable_firefox_doh' => '',
                'disable_private_relay' => '',
                'discovery' => 'off',
                'block_tor' => '',
                'block_vpn' => '',
                'block_vpn_ports' => '',
                'lists' => ['item' => [[
                    'id' => str_repeat('c', 32),
                    'descr' => 'Invented resolver list',
                    'url' => 'https://bypass.example.test/resolvers.txt',
                    'enabled' => 'on',
                    'kind' => 'encrypted_dns',
                ]]],
            ],
            'ip' => [
                'enabled' => 'on',
                'interfaces' => ['item' => ['lan']],
                'directions' => ['item' => ['outbound']],
                'lists' => ['item' => [[
                    'id' => str_repeat('d', 32),
                    'descr' => 'Invented address list',
                    'url' => 'https://ip.example.test/addresses.txt',
                    'enabled' => 'on',
                    'family' => 'ipv4',
                ]]],
                'countries' => ['item' => ['DE']],
                'account_id' => '424242',
                'license_key' => 'invented-license-key-value',
                'allowlist' => ['item' => []],
            ],
        ]],
    ];
}

/**
 * Sinkhole Update Log Test - Updater.
 *
 * Wires the production updater classes to the stubbed pfSense adapter and the
 * fixture download client, all sharing one update log.
 *
 * @param PackagePaths $paths     - Paths.
 * @param UpdateLog    $updateLog - Update log.
 *
 * @return Updater
 *
 * @since 1.2.0
 */
function sinkholeUpdateLogTestUpdater(PackagePaths $paths, UpdateLog $updateLog): Updater
{
    global $sinkholeStubInterfaces;
    global $sinkholeStubInterfaceAddresses;
    global $sinkholeStubRealInterfaces;

    sinkholeStubReset(sinkholeUpdateLogTestConfiguration());
    $sinkholeStubInterfaces = ['lan' => 'LAN'];
    $sinkholeStubInterfaceAddresses = ['lan' => ['ipv4' => '192.0.2.1']];
    $sinkholeStubRealInterfaces = ['lan' => 'igc0'];

    $stateStore = new StateStore($paths->stateFile, $paths->statusFile);
    $adapter = new PfSenseAdapter($paths, $stateStore, 0);
    $savedStore = new SavedListStore($paths);
    $bypassStore = new BypassListStore($paths);
    $compiler = new Compiler($paths, $savedStore, $stateStore, null, $bypassStore);
    $downloadClient = new SinkholeUpdateLogFixtureDownloadClient([
        'https://lists.example.test/good.txt?key=invented-list-token' => "ads.example.com\ntracker.example.com\n",
        'https://bypass.example.test/resolvers.txt' => "doh.example.net\n203.0.113.5\n",
        'https://ip.example.test/addresses.txt' => "198.51.100.0/24\n198.51.100.7\nnot-an-address\n",
    ]);

    pfsensePackageSinkholeAdapter($adapter);

    return new Updater(
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
            $updateLog,
        ),
        new BypassUpdater(
            $adapter,
            $downloadClient,
            new BypassParser(),
            $bypassStore,
            $paths,
            $compiler,
            $updateLog,
        ),
        $updateLog,
    );
}

/**
 * Sinkhole Update Log Test - Contents.
 *
 * @param string $path - Log path.
 *
 * @return string
 *
 * @since 1.2.0
 */
function sinkholeUpdateLogTestContents(string $path): string
{
    $contents = file_get_contents($path);

    sinkholeTestAssertTrue(is_string($contents), 'The update log must be readable.');

    return (string) $contents;
}

sinkholeTestRun([
    'update log writes every milestone of a full run' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeUpdateLogTestPaths($root);
            $updateLog = new UpdateLog($paths->updateLogFile, sinkholeUpdateLogTestClock());
            $updater = sinkholeUpdateLogTestUpdater($paths, $updateLog);

            $updateLog->begin('manual');
            $result = $updater->run(true, false);
            $updateLog->finish($result);
            $updateLog->close();

            $contents = sinkholeUpdateLogTestContents($paths->updateLogFile);
            $lines = explode("\n", rtrim($contents, "\n"));

            fwrite(STDOUT, 'SAMPLE normal run:' . PHP_EOL . $contents);

            foreach ($lines as $line) {
                sinkholeTestAssertSame(
                    1,
                    preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S/', $line),
                    'Every update-log line must start with a local timestamp: ' . $line,
                );
            }

            sinkholeTestAssertSame(
                'Update started (manual).',
                substr($lines[0], 20),
                'The first line must name the run trigger.',
            );

            foreach ([
                'Downloading Bypass List "Invented resolver list" from bypass.example.test.',
                'Bypass List "Invented resolver list": 2 entries (domains: 1, networks: 1), 0 skipped, changed.',
                'Loaded the Bypass firewall rules with 1 IPv4 and 0 IPv6 table entries.',
                'Downloading block list "Invented good list" from lists.example.test.',
                'Block list "Invented good list": 2 entries, 0 skipped, changed.',
                'Downloading block list "Invented broken list" from broken.example.test.',
                'Block list "Invented broken list" failed; it has no saved copy yet: '
                    . 'Invented transport failure for broken.example.test',
                'Compiling DNS blocking data.',
                'Compiled generation ',
                ' with 2 block-list names and 1 Bypass name.',
                'Downloading IP list "Invented address list" from ip.example.test.',
                'IP list "Invented address list": 2 networks, 1 skipped, changed.',
                'Downloading GeoLite2 Country data from download.maxmind.com.',
                'GeoLite2 Country update failed; using the last good copy if one exists: '
                    . 'Invented transport failure for download.maxmind.com with [redacted]',
                'Loaded the IP blocking rules with 1 IPv4 and 0 IPv6 context table entries.',
            ] as $milestone) {
                sinkholeTestAssertContains(
                    $milestone,
                    $contents,
                    'The update log must record the milestone: ' . $milestone,
                );
            }

            sinkholeTestAssertSame(
                1,
                preg_match(
                    '/ Update finished in \d+\.\d s: 4 attempted, 3 successful, 2 failed\.$/',
                    $lines[count($lines) - 1],
                ),
                'The last line must close the run with its duration and totals.',
            );

            foreach ([
                'invented-list-token',
                'invented-license-key-value',
                '?key=',
                'https://',
                '/good.txt',
                '424242',
            ] as $secret) {
                sinkholeTestAssertSame(
                    false,
                    str_contains($contents, $secret),
                    'The update log must not contain credentials, paths or queries: ' . $secret,
                );
            }
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'update log records a failed run and is replaced by the next run' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeUpdateLogTestPaths($root);
            $updateLog = new UpdateLog($paths->updateLogFile, sinkholeUpdateLogTestClock());

            $updateLog->begin('scheduled');
            $updateLog->line('Downloading block list "Invented list" from lists.example.test.');
            $updateLog->fail('IP blocking settings contain values that need repair.');
            $firstContents = sinkholeUpdateLogTestContents($paths->updateLogFile);
            $firstRead = UpdateLog::read($paths->updateLogFile, 0);

            fwrite(STDOUT, 'SAMPLE failed run:' . PHP_EOL . $firstContents);

            sinkholeTestAssertContains(
                'Update started (scheduled).',
                $firstContents,
                'A scheduled run must say so.',
            );
            sinkholeTestAssertSame(
                1,
                preg_match(
                    '/ Update failed after \d+\.\d s: IP blocking settings contain values that need repair\.\n$/',
                    $firstContents,
                ),
                'A failed run must end with its reason.',
            );

            $updateLog->begin('apply');
            $updateLog->line('Applying settings saved while the update ran.');
            $secondContents = sinkholeUpdateLogTestContents($paths->updateLogFile);
            $secondRead = UpdateLog::read($paths->updateLogFile, $firstRead['offset'], $firstRead['run']);
            $status = lstat($paths->updateLogFile);

            sinkholeTestAssertSame(
                false,
                str_contains($secondContents, 'need repair'),
                'A new run must replace the previous run\'s log.',
            );
            sinkholeTestAssertContains(
                'Update started (settings change).',
                $secondContents,
                'An apply run must name its trigger.',
            );
            sinkholeTestAssertTrue(
                $secondRead['run'] !== $firstRead['run'],
                'A replaced log must report a new run identifier.',
            );
            sinkholeTestAssertSame(true, $secondRead['reset'], 'A replaced log must tell the reader to reset.');
            sinkholeTestAssertSame(
                $secondContents,
                $secondRead['text'],
                'A reset read must return the new run from its first byte.',
            );
            sinkholeTestAssertSame(
                0600,
                is_array($status) ? ($status['mode'] & 0777) : null,
                'The update log must be private to its owner.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'update log stops at its size cap with one truncation line' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $path = $root . '/sinkhole-update.log';
            $updateLog = new UpdateLog($path, sinkholeUpdateLogTestClock());
            $message = 'Downloading block list "' . str_repeat('x', 200) . '" from lists.example.test.';

            $updateLog->begin('manual');

            for ($index = 0; $index < 2000; $index++) {
                $updateLog->line($message);
            }

            $updateLog->finish([
                'status' => 'completed',
                'attempted' => 2000,
                'updated' => 2000,
                'failed' => 0,
            ]);
            $contents = sinkholeUpdateLogTestContents($path);

            sinkholeTestAssertTrue(
                strlen($contents) <= UpdateLog::MAXIMUM_BYTES,
                'The update log must never exceed its hard size cap.',
            );
            sinkholeTestAssertSame(
                1,
                substr_count($contents, UpdateLog::TRUNCATED_MESSAGE),
                'The update log must write exactly one truncation line.',
            );
            sinkholeTestAssertSame(
                1,
                preg_match('/Update finished in [^\n]+: 2000 attempted, 2000 successful, 0 failed\.\n$/', $contents),
                'The closing line must still fit after truncation.',
            );

            $longLog = new UpdateLog($root . '/long.log', sinkholeUpdateLogTestClock());
            $longLog->begin('manual');
            $longLog->line(str_repeat('y', 5000) . "\r\nInjected\x07line");
            $longContents = sinkholeUpdateLogTestContents($root . '/long.log');
            $longLines = explode("\n", rtrim($longContents, "\n"));

            sinkholeTestAssertSame(2, count($longLines), 'Control characters must not split a log line.');
            sinkholeTestAssertTrue(
                strlen($longLines[1]) <= UpdateLog::MAXIMUM_LINE_BYTES + 20,
                'One message must be capped to the line limit.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'update log reduces URLs and redacts registered secrets' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $path = $root . '/sinkhole-update.log';
            $updateLog = new UpdateLog($path, sinkholeUpdateLogTestClock());

            $updateLog->begin('manual');
            $updateLog->addSecret('invented-secret-key');
            $updateLog->line(
                'Failed: https://operator:hunter2@feeds.example.test:8443/private/list.txt?token=abc#frag'
                . ' and ftp://mirror.example.test/x then invented-secret-key and '
                . rawurlencode('invented-secret-key'),
            );
            $contents = sinkholeUpdateLogTestContents($path);

            sinkholeTestAssertContains(
                'Failed: feeds.example.test and mirror.example.test then [redacted] and [redacted]',
                $contents,
                'URLs must reduce to their host and secrets must be redacted.',
            );

            foreach (['operator', 'hunter2', 'token=abc', '/private', '8443', 'invented-secret-key'] as $secret) {
                sinkholeTestAssertSame(
                    false,
                    str_contains($contents, $secret),
                    'The update log must not keep: ' . $secret,
                );
            }

            sinkholeTestAssertSame(
                'lists.example.test',
                UpdateLog::host('https://Lists.Example.Test/a.txt?b=c'),
                'The host helper must return the lowercase host only.',
            );
            sinkholeTestAssertSame(
                'an unknown host',
                UpdateLog::host('not a url'),
                'An unparsable URL must not leak into the log.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'update log read returns complete lines from an offset' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $path = $root . '/sinkhole-update.log';
            $missing = UpdateLog::read($path, 0);
            $missingWithOffset = UpdateLog::read($path, 12, 'abcdefabcdefabcd');

            sinkholeTestAssertSame(
                ['run' => '', 'size' => 0, 'offset' => 0, 'text' => '', 'reset' => false],
                $missing,
                'A missing log must read as empty.',
            );
            sinkholeTestAssertSame(true, $missingWithOffset['reset'], 'A vanished log must reset the reader.');

            file_put_contents($path, "first line\nsecond line\npartial");

            $whole = UpdateLog::read($path, 0);
            $tail = UpdateLog::read($path, 11, $whole['run']);
            $past = UpdateLog::read($path, 4096, $whole['run']);
            $small = UpdateLog::read($path, 0, $whole['run'], 15);

            sinkholeTestAssertSame("first line\nsecond line\n", $whole['text'], 'Only complete lines are returned.');
            sinkholeTestAssertSame(23, $whole['offset'], 'The offset must stop after the last complete line.');
            sinkholeTestAssertSame(1, preg_match(UpdateLog::RUN_PATTERN, $whole['run']), 'The run identifier must be hexadecimal.');
            sinkholeTestAssertSame("second line\n", $tail['text'], 'A read must continue from its offset.');
            sinkholeTestAssertSame(false, $tail['reset'], 'The same run must not reset.');
            sinkholeTestAssertSame(true, $past['reset'], 'An offset past the end must reset.');
            sinkholeTestAssertSame("first line\nsecond line\n", $past['text'], 'A reset read must start over.');
            sinkholeTestAssertSame("first line\n", $small['text'], 'A capped read must end on a line boundary.');
            sinkholeTestAssertSame(11, $small['offset'], 'A capped read must return the next offset.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'update log endpoint returns JSON fields, offsets and resets and rejects invalid input' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            $paths = sinkholeUpdateLogTestPaths($root);
            $updateLog = new UpdateLog($paths->updateLogFile, sinkholeUpdateLogTestClock());

            sinkholeUpdateLogTestUpdater($paths, $updateLog);

            $empty = pfsensePackageSinkholeUpdateLogResponse($paths, ['update_log' => '1']);

            sinkholeTestAssertSame(200, $empty['status'], 'A request without a log must succeed.');
            sinkholeTestAssertSame(
                ['running', 'run', 'offset', 'size', 'text', 'reset', 'summary'],
                array_keys($empty['body']),
                'The endpoint must return the documented fields.',
            );
            sinkholeTestAssertSame(false, $empty['body']['running'], 'No update holds the lock.');
            sinkholeTestAssertSame('', $empty['body']['text'], 'No log means no text.');
            sinkholeTestAssertSame(
                [
                    'compile_needed',
                    'compiled_generation',
                    'deployment_needed',
                    'deployed_generation',
                    'loaded_generation',
                    'update_running',
                ],
                array_keys((array) $empty['body']['summary']),
                'The endpoint must return the live Summary cells.',
            );
            sinkholeTestAssertSame('No', $empty['body']['summary']['update_running'], 'The idle Summary cell must say No.');

            $updateLog->begin('manual');
            $updateLog->line('Compiling DNS blocking data.');
            file_put_contents($paths->updateLockFile, "12345\n");

            $first = pfsensePackageSinkholeUpdateLogResponse($paths, ['update_log' => '1', 'offset' => '0']);
            $firstBody = $first['body'];

            sinkholeTestAssertSame(true, $firstBody['running'], 'A held update lock must report a running update.');
            sinkholeTestAssertSame('Yes', $firstBody['summary']['update_running'], 'The running Summary cell must say Yes.');
            sinkholeTestAssertContains('Update started (manual).', $firstBody['text'], 'The first poll returns the run.');
            sinkholeTestAssertSame(strlen($firstBody['text']), $firstBody['offset'], 'The offset must follow the text.');

            $updateLog->line('Deployed generation invented to the DNS Resolver.');

            $next = pfsensePackageSinkholeUpdateLogResponse($paths, [
                'update_log' => '1',
                'offset' => (string) $firstBody['offset'],
                'run' => $firstBody['run'],
            ]);

            sinkholeTestAssertSame(false, $next['body']['reset'], 'A poll on the same run must not reset.');
            sinkholeTestAssertSame(
                1,
                preg_match('/^\S+ \S+ Deployed generation invented to the DNS Resolver\.\n$/', $next['body']['text']),
                'A poll must return only the new line.',
            );

            $stale = pfsensePackageSinkholeUpdateLogResponse($paths, [
                'update_log' => '1',
                'offset' => (string) $next['body']['offset'],
                'run' => 'abcdefabcdefabcd',
            ]);

            sinkholeTestAssertSame(true, $stale['body']['reset'], 'A different run must reset the reader.');
            sinkholeTestAssertContains('Update started (manual).', $stale['body']['text'], 'A reset returns the whole run.');

            foreach (
                [
                    ['offset' => '-1'],
                    ['offset' => 'abc'],
                    ['offset' => '1.5'],
                    ['offset' => '9999999999'],
                    ['offset' => ['0']],
                    ['offset' => ''],
                    ['offset' => '0', 'run' => 'not-a-run'],
                    ['offset' => '0', 'run' => ['abcdefabcdefabcd']],
                ] as $invalidQuery
            ) {
                $invalid = pfsensePackageSinkholeUpdateLogResponse(
                    $paths,
                    ['update_log' => '1'] + $invalidQuery,
                );

                sinkholeTestAssertSame(
                    400,
                    $invalid['status'],
                    'Invalid input must be rejected: ' . json_encode($invalidQuery),
                );
                sinkholeTestAssertSame(
                    ['error'],
                    array_keys($invalid['body']),
                    'A rejected request must return only an error.',
                );
            }

            $encoded = json_encode(
                $first['body'],
                JSON_HEX_TAG
                    | JSON_HEX_AMP
                    | JSON_HEX_APOS
                    | JSON_HEX_QUOT
                    | JSON_INVALID_UTF8_SUBSTITUTE
                    | JSON_UNESCAPED_SLASHES
                    | JSON_UNESCAPED_UNICODE,
            );

            sinkholeTestAssertTrue(is_string($encoded), 'The endpoint body must encode as JSON.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'status page serves the update log endpoint read-only behind its privilege' => static function (): void {
        $source = sinkholeUpdateLogTestContents(
            __DIR__ . '/../port/files/usr/local/www/sinkhole-status.php',
        );
        $endpointPosition = strpos($source, "if (isset(\$_GET['update_log'])) {");
        $postPosition = strpos($source, "if (\$_SERVER['REQUEST_METHOD'] === 'POST' && isset(\$_POST['update_now'])) {");

        sinkholeTestAssertContains(
            '##|*MATCH=sinkhole-status.php*',
            $source,
            'The endpoint must share the Status page privilege.',
        );
        sinkholeTestAssertTrue(
            is_int($endpointPosition) && is_int($postPosition) && $endpointPosition < $postPosition,
            'The endpoint must answer before the Update Now handler can run.',
        );

        foreach ([
            "require_once('guiconfig.inc');",
            "header('Content-Type: application/json; charset=UTF-8');",
            "header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');",
            "if ((\$_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {",
            "header('Allow: GET');",
            "'status' => 405,",
            'JSON_HEX_TAG',
        ] as $marker) {
            sinkholeTestAssertContains($marker, $source, 'The endpoint must contain: ' . $marker);
        }
    },
]);
