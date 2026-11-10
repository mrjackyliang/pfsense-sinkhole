<?php

declare(strict_types=1);

use PfSense\Sinkhole\Runtime\AlertProcessor;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\StateStore;

require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/AlertProcessor.php');

if (count($argv) !== 2) {
    fwrite(STDERR, 'Usage: e2e-alert.php ROOT' . PHP_EOL);

    exit(64);
}

$root = $argv[1];
$paths = new PackagePaths([
    'persistent_directory' => $root . '/persistent',
    'runtime_root_directory' => $root . '/runtime',
    'alert_repeat_state_file' => $root . '/sinkhole-alerts.json',
    'alert_lock_file' => $root . '/sinkhole-alerts.lock',
]);
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
    static fn(): int => 1760000000,
    static fn(): string => 'sinkhole-e2e-notice',
);
$result = $processor->run(
    ['44444444444444444444444444444444' => [
        'id' => '44444444444444444444444444444444',
        'description' => 'Device alert',
        'any_list' => false,
        'lists' => ['99999999999999999999999999999999'],
        'everyone' => false,
        'networks' => [],
        'devices' => ['dddddddddddddddddddddddddddddddd'],
        'repeat_minutes' => 60,
        'notice' => true,
        'remote' => true,
        'enabled' => true,
    ]],
    ['99999999999999999999999999999999' => [
        'id' => '99999999999999999999999999999999',
        'name' => 'Device Example',
    ]],
    ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' => [
        'id' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'interface' => 'lan',
    ]],
    ['dddddddddddddddddddddddddddddddd' => [
        'id' => 'dddddddddddddddddddddddddddddddd',
        'name' => 'Lab Phone',
    ]],
    ['lan' => 'LAN'],
);

fwrite(STDOUT, json_encode([
    'result' => $result,
    'notices' => $notices,
    'remote' => $remote,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . PHP_EOL);
