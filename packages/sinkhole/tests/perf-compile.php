<?php

declare(strict_types=1);

use PfSense\Sinkhole\Runtime\Compiler;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\SavedListStore;
use PfSense\Sinkhole\Runtime\StateStore;

require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/Compiler.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/SavedListStore.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/StateStore.php');

/**
 * Perf Compile - Paths.
 *
 * Places every package path under one scratch root so the measured compile never
 * touches a real installation.
 *
 * @param string $root - Scratch root.
 *
 * @return PackagePaths
 *
 * @since 1.2.0
 */
function sinkholePerfCompilePaths(string $root): PackagePaths
{
    return new PackagePaths([
        'persistent_directory' => $root . '/persistent',
        'runtime_root_directory' => $root . '/runtime',
        'module_source_file' => $root . '/source/sinkhole_unbound.py',
        'update_lock_file' => $root . '/sinkhole-update.lock',
        'runtime_lock_file' => $root . '/sinkhole-runtime.lock',
        'client_lock_file' => $root . '/sinkhole-clients.lock',
        'alert_lock_file' => $root . '/sinkhole-alerts.lock',
        'alert_repeat_state_file' => $root . '/sinkhole-alerts.json',
        'command' => '/usr/local/sbin/sinkhole',
        'runtime_user' => '',
        'runtime_group' => '',
        'storage_user' => '',
        'storage_group' => '',
    ]);
}

/**
 * Perf Compile - Name.
 *
 * Builds a deterministic invented name of typical block-list length, so lists can
 * overlap by sharing positions.
 *
 * @param int $position - Name position.
 *
 * @return string
 *
 * @since 1.2.0
 */
function sinkholePerfCompileName(int $position): string
{
    $zone = $position % 9973;

    return 'host' . $position . '.zone' . $zone . '.example' . ($zone % 17) . '.com';
}

/**
 * Perf Compile - Save List.
 *
 * Streams one normalized list straight to its saved copy, with every seventh name
 * written as a subtree rule.
 *
 * @param SavedListStore $store      - Saved list store.
 * @param string         $identifier - List identifier.
 * @param int            $first      - First name position.
 * @param int            $count      - Name count.
 *
 * @return void
 *
 * @since 1.2.0
 */
function sinkholePerfCompileSaveList(
    SavedListStore $store,
    string $identifier,
    int $first,
    int $count,
): void {
    $temporaryPath = $store->createTemporaryFile('.perf-');
    $handle = fopen($temporaryPath, 'wb');

    if ($handle === false) {
        throw new RuntimeException('Unable to write a perf list.');
    }

    $buffer = '';

    for ($position = $first; $position < $first + $count; $position++) {
        $semantic = ($position % 7 === 0) ? 'S' : 'E';
        $buffer .= $semantic . "\t" . sinkholePerfCompileName($position) . "\n";

        if (strlen($buffer) >= 1048576) {
            fwrite($handle, $buffer);
            $buffer = '';
        }
    }

    fwrite($handle, $buffer);
    fclose($handle);

    $store->commitSuccessfulDownload($identifier, $temporaryPath, [
        'url' => 'https://lists.example.invalid/' . $identifier . '.test',
        'fetched_at' => '2026-01-01T00:00:00+00:00',
        'entries' => $count,
        'sha256' => str_repeat('0', 64),
        'last_attempt' => '2026-01-01T00:00:00+00:00',
        'last_error' => null,
    ]);
}

$root = $argv[1] ?? '';
$uniqueNames = (int) ($argv[2] ?? '0');

if ($root === '' || $uniqueNames < 1) {
    fwrite(STDERR, 'Usage: php perf-compile.php <scratch-root> <unique-names>' . PHP_EOL);

    exit(1);
}

$paths = sinkholePerfCompilePaths($root);
$store = new SavedListStore($paths);
$identifiers = [
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'cccccccccccccccccccccccccccccccc',
];
$firstCount = intdiv($uniqueNames * 60, 100);
$secondStart = intdiv($uniqueNames * 45, 100);
$secondCount = $uniqueNames - $secondStart - intdiv($uniqueNames, 20);
$thirdStart = $uniqueNames - intdiv($uniqueNames, 20);
$thirdCount = intdiv($uniqueNames, 20);

sinkholePerfCompileSaveList($store, $identifiers[0], 0, $firstCount);
sinkholePerfCompileSaveList($store, $identifiers[1], $secondStart, $secondCount);
sinkholePerfCompileSaveList($store, $identifiers[2], $thirdStart, $thirdCount);

$lists = [];

foreach ($identifiers as $identifier) {
    $lists[$identifier] = [
        'id' => $identifier,
        'descr' => 'Perf ' . $identifier,
        'url' => 'https://lists.example.invalid/' . $identifier . '.test',
        'enabled' => 'on',
    ];
}

gc_collect_cycles();
memory_reset_peak_usage();

$startedAt = hrtime(true);
$result = (new Compiler($paths, $store, new StateStore($paths->stateFile)))->compile($lists, []);
$elapsedSeconds = (hrtime(true) - $startedAt) / 1e9;
$generationPath = $paths->runtimeDataDirectory;

echo json_encode([
    'unique_names' => $result['domains'],
    'list_entries' => $firstCount + $secondCount + $thirdCount,
    'compile_seconds' => round($elapsedSeconds, 2),
    'php_peak_bytes' => memory_get_peak_usage(true),
    'php_memory_limit' => ini_get('memory_limit'),
    'index_bytes' => filesize($generationPath . '/domains.index'),
    'tsv_bytes' => filesize($generationPath . '/domains.tsv'),
    'runtime_directory' => $generationPath,
], JSON_UNESCAPED_SLASHES) . PHP_EOL;
