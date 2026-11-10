<?php

declare(strict_types=1);

use PfSense\Sinkhole\Runtime\FileLock;
use PfSense\Sinkhole\Runtime\TestedReleases;
use PfSense\Sinkhole\Runtime\UpdateManager;

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/FileLock.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/TestedReleases.php');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/UpdateManager.php');

$sinkholeUpdateCatalog = require(
    __DIR__ . '/../port/files/usr/local/pkg/sinkhole/Translations.php'
);

/** @var list<array> */
$sinkholeUpdateNotices = [];

/** @var list<string> */
$sinkholeUpdateClosedNotices = [];

if (!function_exists('file_notice')) {
    /**
     * Sinkhole Update Test - File Notice.
     *
     * @return void
     *
     * @since 1.0.0
     */
    function file_notice(
        string $id,
        string $notice,
        string $category = 'General',
        string $url = '',
        int $priority = 1,
        bool $localOnly = false,
    ): void {
        global $sinkholeUpdateNotices;

        $sinkholeUpdateNotices[] = compact(
            'id',
            'notice',
            'category',
            'url',
            'priority',
            'localOnly',
        );
    }
}

if (!function_exists('close_notice')) {
    /**
     * Sinkhole Update Test - Close Notice.
     *
     * @return void
     *
     * @since 1.0.0
     */
    function close_notice(string $id): void
    {
        global $sinkholeUpdateClosedNotices;

        $sinkholeUpdateClosedNotices[] = $id;
    }
}

/**
 * Sinkhole Update Test - Assert Failure.
 *
 * @param callable(): mixed $callback - Operation expected to fail.
 * @param string $message - Exact expected message.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeUpdateAssertFailure(callable $callback, string $message): void
{
    try {
        $callback();
    } catch (RuntimeException $runtimeException) {
        sinkholeTestAssertSame(
            $message,
            $runtimeException->getMessage(),
            'The update failure must remain actionable.',
        );

        return;
    }

    throw new RuntimeException('The update operation was expected to fail.');
}

/**
 * Sinkhole Update Test - Find SSH Keygen.
 *
 * @return string|null
 *
 * @since 1.0.0
 */
function sinkholeUpdateFindSshKeygen(): ?string
{
    if (is_file('/usr/bin/ssh-keygen') && is_executable('/usr/bin/ssh-keygen')) {
        return '/usr/bin/ssh-keygen';
    }

    $path = getenv('PATH');

    foreach (is_string($path) ? explode(PATH_SEPARATOR, $path) : [] as $directory) {
        $candidate = $directory . '/ssh-keygen';

        if ($directory !== '' && is_file($candidate) && is_executable($candidate)) {
            return $candidate;
        }
    }

    return null;
}

/**
 * Sinkhole Update Test - Write SSH Keygen Stub.
 *
 * @return array{command: string, arguments: string, stdin: string}
 *
 * @since 1.0.0
 */
function sinkholeUpdateWriteSshKeygenStub(
    string $directory,
    string $name,
    int $exitCode,
): array {
    $command = $directory . '/' . $name;
    $arguments = $command . '.arguments';
    $standardInput = $command . '.stdin';
    $contents = implode("\n", [
        '#!/bin/sh',
        'printf \'%s\\n\' "$@" > ' . escapeshellarg($arguments),
        'cat > ' . escapeshellarg($standardInput),
        'exit ' . $exitCode,
        '',
    ]);

    if (file_put_contents($command, $contents) === false || chmod($command, 0700) === false) {
        throw new RuntimeException('Unable to create the ssh-keygen test stub.');
    }

    return compact('command', 'arguments', 'standardInput') + [
        'stdin' => $standardInput,
    ];
}

/**
 * Sinkhole Update Test - Release.
 *
 * @return array
 *
 * @since 1.0.0
 */
function sinkholeUpdateRelease(bool $withDigest = true, bool $withSignature = true): array
{
    $version = '2.1.0';
    $packageName = UpdateManager::PACKAGE_NAME . '-' . $version . '.pkg';
    $assets = [[
        'name' => $packageName,
        'url' => UpdateManager::DOWNLOAD_PREFIX . 'v' . $version . '/' . $packageName,
        'digest' => $withDigest ? 'sha256:' . str_repeat('a', 64) : null,
    ]];

    if (!$withDigest) {
        $assets[] = [
            'name' => $packageName . '.sha256',
            'url' => UpdateManager::DOWNLOAD_PREFIX . 'v' . $version . '/' . $packageName . '.sha256',
            'digest' => null,
        ];
    }

    if ($withSignature) {
        $assets[] = [
            'name' => $packageName . '.sig',
            'url' => UpdateManager::DOWNLOAD_PREFIX . 'v' . $version . '/' . $packageName . '.sig',
            'digest' => null,
        ];
    }

    return [
        'tag' => 'v' . $version,
        'version' => $version,
        'release_url' => 'https://github.com/mrjackyliang/pfsense-sinkhole/releases/tag/v' . $version,
        'published_at' => '2026-11-06T12:00:00Z',
        'assets' => $assets,
    ];
}

$cases = [
    'stable schedules map every configured frequency' => static function (): void {
        $values = [17, 4, 2, 23];
        $calls = 0;
        $schedule = UpdateManager::stableCronSchedule(
            [],
            static function (int $minimum, int $maximum) use (&$values, &$calls): int {
                $value = $values[$calls] ?? $minimum;
                $calls++;

                if ($value < $minimum || $value > $maximum) {
                    throw new RuntimeException('The deterministic schedule value is invalid.');
                }

                return $value;
            },
        );

        sinkholeTestAssertSame(
            ['minute' => 17, 'hour' => 4, 'weekday' => 2, 'monthday' => 23],
            $schedule,
            'The randomized schedule must contain every stable component.',
        );
        sinkholeTestAssertSame(4, $calls, 'Each missing component must be generated once.');
        sinkholeTestAssertSame(
            $schedule,
            UpdateManager::stableCronSchedule(array_map('strval', $schedule), static function (): never {
                throw new RuntimeException('A valid schedule must not be randomized again.');
            }),
            'Stored numeric strings must reuse the same schedule.',
        );
        sinkholeTestAssertSame(['17', '4', '*', '*', '*'], UpdateManager::cronFields('daily', $schedule), 'Daily must use the stable time.');
        sinkholeTestAssertSame(['17', '4', '*', '*', '2'], UpdateManager::cronFields('weekly', $schedule), 'Weekly must use the stable weekday.');
        sinkholeTestAssertSame(['17', '4', '23', '*', '*'], UpdateManager::cronFields('monthly', $schedule), 'Monthly must use the stable month day.');
        sinkholeTestAssertSame(null, UpdateManager::cronFields('never', $schedule), 'Never must remove scheduled checks.');
    },
    '404 means no public release while other request failures remain errors' => static function (): void {
        sinkholeTestAssertSame(
            true,
            UpdateManager::isNoPublicReleaseStatus(404),
            'GitHub HTTP 404 must represent a repository without a public release.',
        );
        sinkholeTestAssertSame(
            false,
            UpdateManager::isNoPublicReleaseStatus(500),
            'Other GitHub HTTP errors must remain failures.',
        );
        sinkholeTestAssertSame(
            false,
            UpdateManager::isNoPublicReleaseStatus(0),
            'Network failures without an HTTP response must remain failures.',
        );
    },
    'notices are emitted once per version and remote delivery is opt in' => static function (): void {
        global $sinkholeUpdateClosedNotices;
        global $sinkholeUpdateNotices;

        $sinkholeUpdateNotices = [];
        $sinkholeUpdateClosedNotices = [];
        $state = UpdateManager::synchronizeNotice([], '2.0.0', '2.1.0', false);

        sinkholeTestAssertSame(1, count($sinkholeUpdateNotices), 'A new version must create one bell notice.');
        sinkholeTestAssertSame(true, $sinkholeUpdateNotices[0]['localOnly'], 'Remote delivery must be off by default.');
        sinkholeTestAssertSame(UpdateManager::ABOUT_PAGE, $sinkholeUpdateNotices[0]['url'], 'The notice must link to About.');
        sinkholeTestAssertSame('2.1.0', $state['notified_version'], 'The noticed version must persist.');

        $state = UpdateManager::synchronizeNotice($state, '2.0.0', '2.1.0', true);
        sinkholeTestAssertSame(1, count($sinkholeUpdateNotices), 'The same version must not create another notice.');

        $state = UpdateManager::synchronizeNotice($state, '2.0.0', '2.2.0', true);
        sinkholeTestAssertSame(2, count($sinkholeUpdateNotices), 'A later version must create one notice.');
        sinkholeTestAssertSame(false, $sinkholeUpdateNotices[1]['localOnly'], 'The explicit opt-in must enable remote delivery.');

        UpdateManager::synchronizeNotice($state, '2.2.0', '2.2.0', true);
        sinkholeTestAssertSame([UpdateManager::NOTICE_ID], $sinkholeUpdateClosedNotices, 'A current installation must close the notice.');
    },
    'release assets enforce URLs digests checksums and size caps' => static function (): void {
        $release = sinkholeUpdateRelease();
        $assets = UpdateManager::selectUpdateAssets($release);

        sinkholeTestAssertSame('sha256:' . str_repeat('a', 64), $assets['digest'], 'The API SHA-256 must take precedence.');
        sinkholeTestAssertSame(null, $assets['checksum'], 'An API digest must not download a checksum asset.');
        sinkholeTestAssertTrue(is_array($assets['signature']), 'The exact signature asset must be selected.');
        sinkholeTestAssertSame(true, UpdateManager::isAllowedAssetUrl($assets['package']['url']), 'The repository path must be allowed.');
        sinkholeTestAssertSame(false, UpdateManager::isAllowedAssetUrl('https://example.com/package.pkg'), 'Another host must be rejected.');
        sinkholeTestAssertSame(true, UpdateManager::isAllowedAssetUrl('http://vm.test/releases/package.pkg', 'http://vm.test/releases/'), 'The explicit test prefix must work.');

        $release['assets'][0]['url'] = 'https://example.com/package.pkg';
        sinkholeUpdateAssertFailure(
            static fn (): array => UpdateManager::selectUpdateAssets($release),
            'The release contains an asset URL outside the trusted repository path.',
        );

        $fallback = UpdateManager::selectUpdateAssets(sinkholeUpdateRelease(false));
        sinkholeTestAssertSame(null, $fallback['digest'], 'A missing API digest must use the checksum fallback.');
        sinkholeTestAssertTrue(is_array($fallback['checksum']), 'The exact .sha256 asset must be selected.');

        $withoutChecksum = sinkholeUpdateRelease(false);
        unset($withoutChecksum['assets'][1]);
        $withoutChecksum['assets'] = array_values($withoutChecksum['assets']);
        sinkholeUpdateAssertFailure(
            static fn (): array => UpdateManager::selectUpdateAssets($withoutChecksum),
            'The release provides neither a GitHub SHA-256 digest nor the required checksum asset '
                . UpdateManager::PACKAGE_NAME
                . '-2.1.0.pkg.sha256. The installed version was kept.',
        );

        $reflection = new ReflectionClass(UpdateManager::class);
        sinkholeTestAssertSame(64 * 1024 * 1024, $reflection->getReflectionConstant('PACKAGE_DOWNLOAD_LIMIT')?->getValue(), 'Packages must be capped at 64 MiB.');
        sinkholeTestAssertSame(64 * 1024, $reflection->getReflectionConstant('AUXILIARY_DOWNLOAD_LIMIT')?->getValue(), 'Small assets must be capped at 64 KiB.');
        $source = (string) file_get_contents(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/UpdateManager.php');
        sinkholeTestAssertContains('CURLOPT_MAXFILESIZE_LARGE => $byteLimit', $source, 'cURL must enforce the declared size limit.');
        sinkholeTestAssertContains('$downloadedCount > $byteLimit', $source, 'The progress callback must enforce the size limit too.');
    },
    'digest verification accepts only exact SHA-256 data' => static function (): void {
        $path = tempnam(sys_get_temp_dir(), 'sinkhole-digest-');

        if ($path === false) {
            throw new RuntimeException('Unable to create the digest fixture.');
        }

        try {
            file_put_contents($path, 'package payload');
            $hash = hash_file('sha256', $path);
            $digest = 'sha256:' . $hash;

            sinkholeTestAssertSame(true, UpdateManager::verifyDigest($path, $digest), 'A matching digest must pass.');
            sinkholeTestAssertSame(false, UpdateManager::verifyDigest($path, 'sha256:' . str_repeat('0', 64)), 'A mismatched digest must fail.');
            sinkholeTestAssertSame($digest, UpdateManager::checksumDigest($hash . PHP_EOL), 'A hash-only checksum must normalize.');
            sinkholeTestAssertSame(null, UpdateManager::checksumDigest($hash . '  package.pkg'), 'A filename-bearing checksum must fail closed.');
        } finally {
            @unlink($path);
        }
    },
    'signature requirements distinguish keyed and unkeyed releases' => static function (): void {
        $key = 'AAAAC3NzaC1lZDI1NTE5AAAAIEcEuM8O7kQQkKHAgao93cat1D9++Xd8gX4JXKEza6HH';
        $unsignedAssets = UpdateManager::selectUpdateAssets(sinkholeUpdateRelease(true, false));
        $root = sinkholeTestTemporaryDirectory();
        $trustFile = $root . '/release-signing.pub';

        try {
            file_put_contents($trustFile, "# No release key is configured.\n");
            $unkeyed = UpdateManager::readSigningKeys($trustFile);
            sinkholeTestAssertSame([], $unkeyed, 'A comment-only installed trust list must be unkeyed.');
            UpdateManager::assertSignatureRequirements($unsignedAssets, $unkeyed);
            sinkholeUpdateAssertFailure(
                static fn () => UpdateManager::assertSignatureRequirements($unsignedAssets, [$key]),
                'Release asset ' . UpdateManager::PACKAGE_NAME . '-2.1.0.pkg.sig is missing, so the update was not installed.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'signature verifier binds the principal namespace and package bytes' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $package = $root . '/' . UpdateManager::PACKAGE_NAME . '-2.1.0.pkg';
        $signature = $package . '.sig';
        $key = 'AAAAC3NzaC1lZDI1NTE5AAAAIEcEuM8O7kQQkKHAgao93cat1D9++Xd8gX4JXKEza6HH';

        try {
            file_put_contents($package, 'signed package fixture');
            file_put_contents($signature, 'signature fixture');
            $stub = sinkholeUpdateWriteSshKeygenStub($root, 'ssh-keygen-stub', 0);
            $manager = new UpdateManager(
                installedVersion: '2.0.0',
                signingKeysFile: $root . '/keys.pub',
                sshKeygenCommand: $stub['command'],
            );
            $manager->verifyReleaseSignature($package, $signature, [$key], $root);
            $arguments = (string) file_get_contents($stub['arguments']);

            sinkholeTestAssertContains("-I\n" . UpdateManager::PACKAGE_NAME . "\n", $arguments, 'The package principal must be fixed.');
            sinkholeTestAssertContains("-n\n" . UpdateManager::PACKAGE_NAME . "\n", $arguments, 'The signature namespace must be fixed.');
            sinkholeTestAssertSame(file_get_contents($package), file_get_contents($stub['stdin']), 'Package bytes must reach ssh-keygen on standard input.');
            sinkholeTestAssertSame(0600, fileperms($root . '/allowed_signers') & 0777, 'Allowed signers must be private.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'real OpenSSH accepts signed releases and rejects wrong keys and tampering' => static function (): void {
        $sshKeygen = sinkholeUpdateFindSshKeygen();

        if ($sshKeygen === null) {
            fwrite(STDOUT, 'SKIP ssh-keygen is unavailable; real signature fixtures were not exercised.' . PHP_EOL);

            return;
        }

        $root = sinkholeTestTemporaryDirectory();
        $package = $root . '/' . UpdateManager::PACKAGE_NAME . '-2.1.0.pkg';
        $signature = $package . '.sig';
        $keyA = $root . '/release-key-a';
        $keyB = $root . '/release-key-b';

        try {
            file_put_contents($package, 'signed release package');

            foreach ([$keyA, $keyB] as $keyPath) {
                $command = sprintf(
                    '%s -q -t ed25519 -N %s -f %s',
                    escapeshellarg($sshKeygen),
                    escapeshellarg(''),
                    escapeshellarg($keyPath),
                );
                exec($command, $output, $exitCode);

                if ($exitCode !== 0) {
                    throw new RuntimeException('Unable to generate a release signing fixture.');
                }
            }

            $signCommand = sprintf(
                '%s -Y sign -f %s -n %s %s',
                escapeshellarg($sshKeygen),
                escapeshellarg($keyA),
                escapeshellarg(UpdateManager::PACKAGE_NAME),
                escapeshellarg($package),
            );
            exec($signCommand, $signOutput, $signExitCode);

            if ($signExitCode !== 0) {
                throw new RuntimeException('Unable to sign the release fixture.');
            }

            $trustedKey = UpdateManager::readSigningKeys($keyA . '.pub');
            $wrongKey = UpdateManager::readSigningKeys($keyB . '.pub');
            $manager = new UpdateManager('2.0.0', signingKeysFile: $keyA . '.pub', sshKeygenCommand: $sshKeygen);
            $manager->verifyReleaseSignature($package, $signature, $trustedKey, $root);

            sinkholeUpdateAssertFailure(
                static fn () => $manager->verifyReleaseSignature($package, $signature, $wrongKey, $root),
                'The release signature does not match this package\'s signing key, so the update was not installed.',
            );

            file_put_contents($package, 'tampered release package');
            sinkholeUpdateAssertFailure(
                static fn () => $manager->verifyReleaseSignature($package, $signature, $trustedKey, $root),
                'The release signature does not match this package\'s signing key, so the update was not installed.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'package lock prevents concurrent update operations' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $path = $root . '/update.lock';
        $lock = new FileLock($path);
        $process = null;
        $pipes = [];

        try {
            $child = <<<'PHP'
$handle = fopen($argv[1], 'c+b');
flock($handle, LOCK_EX);
fwrite(STDOUT, "ready\n");
fflush(STDOUT);
fgets(STDIN);
flock($handle, LOCK_UN);
fclose($handle);
PHP;
            $process = proc_open(
                [PHP_BINARY, '-r', $child, $path],
                [
                    0 => ['pipe', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ],
                $pipes,
            );

            if (!is_resource($process) || trim((string) fgets($pipes[1])) !== 'ready') {
                throw new RuntimeException('The concurrent lock fixture did not start.');
            }

            sinkholeTestAssertSame(false, $lock->acquire(), 'A concurrent package operation must not acquire the lock.');
            fwrite($pipes[0], "release\n");
            fclose($pipes[0]);
            fclose($pipes[1]);
            $childError = stream_get_contents($pipes[2]);
            fclose($pipes[2]);
            $exitCode = proc_close($process);
            $process = null;
            sinkholeTestAssertSame('', $childError, 'The concurrent lock fixture must not report an error.');
            sinkholeTestAssertSame(0, $exitCode, 'The concurrent lock fixture must exit cleanly.');
            sinkholeTestAssertSame(true, $lock->acquire(), 'The lock must be reusable after release.');
        } finally {
            $lock->release();

            if (is_resource($process)) {
                if (isset($pipes[0]) && is_resource($pipes[0])) {
                    fwrite($pipes[0], "release\n");
                    fclose($pipes[0]);
                }

                foreach ([1, 2] as $pipeIndex) {
                    if (isset($pipes[$pipeIndex]) && is_resource($pipes[$pipeIndex])) {
                        fclose($pipes[$pipeIndex]);
                    }
                }

                proc_terminate($process);
                proc_close($process);
            }

            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'CLI and About page expose only the reviewed update flow' => static function (): void {
        $cli = (string) file_get_contents(__DIR__ . '/../port/files/usr/local/sbin/sinkhole');
        $about = (string) file_get_contents(__DIR__ . '/../port/files/usr/local/www/sinkhole-about.php');
        $manager = (string) file_get_contents(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/UpdateManager.php');
        $selfUpdate = substr($manager, (int) strpos($manager, 'public function selfUpdate'));

        sinkholeTestAssertTrue(str_starts_with($cli, "#!/usr/local/bin/php\n"), 'The CLI shebang must not pass -f to PHP.');
        sinkholeTestAssertContains("case '--check-updates'", $cli, 'The CLI must expose release checks.');
        sinkholeTestAssertContains("case '--self-update'", $cli, 'The CLI must expose self-update.');
        sinkholeTestAssertContains('NOVA_PFSENSE_UPDATE_RELEASES_API', $cli, 'Tests must be able to override the API.');
        sinkholeTestAssertContains('NOVA_PFSENSE_UPDATE_DOWNLOAD_PREFIX', $cli, 'Tests must be able to override the download prefix.');
        sinkholeTestAssertSame(false, str_contains($cli, 'NOVA_PFSENSE_UPDATE_SIGNING'), 'The signing key path must never be environment-controlled.');
        sinkholeTestAssertContains('new FileLock($paths->updateLockFile)', $cli, 'Release work must use the package lock.');
        sinkholeTestAssertContains("'add',\n                '-f'", $selfUpdate, 'Self-update must install with pkg add -f.');
        sinkholeTestAssertTrue(strpos($selfUpdate, '$this->verifyReleaseSignature(') < strpos($selfUpdate, '$this->verifyPackageMetadata('), 'Signature verification must precede pkg query -F.');
        sinkholeTestAssertContains('UpdateManager::installedVersion()', $about, 'The About page must read the installed version through the update manager.');
        sinkholeTestAssertContains("getUserEntry((string) (\$_SESSION['Username'] ?? ''))", $about, 'The About page must resolve the logged-in pfSense user.');
        sinkholeTestAssertContains("'page-firewall-sinkhole-general'", $about, 'Update actions must require the General settings privilege.');
        sinkholeTestAssertContains("userHasPrivilege(\$currentUser, 'page-all')", $about, 'Update actions must permit page-all administrators.');
        sinkholeTestAssertContains("config_get_path('installedpackages/package', [])", $manager, 'The update manager must read the installed package version first.');
        sinkholeTestAssertContains("parse_xml_config_pkg(\$packageInfoPath, 'pfsensepkgs')", $manager, 'The update manager must fall back to the installed info.xml version.');

        foreach ([
            "'check_updates',",
            "'self_update',",
            'UpdateManager::queueSelfUpdate',
            'mwexec_bg(PackagePaths::SELF_UPDATE_COMMAND)',
            "window.fetch('sinkhole-about.php?update_status=1'",
            "'update_checks_off'",
            "'updates_not_checked'",
            "'no_public_release'",
            "'last_update_check_failed'",
            "'version_available'",
            "'up_to_date_checked'",
        ] as $marker) {
            sinkholeTestAssertContains($marker, $about, 'The About update section is missing ' . $marker . '.');
        }
    },
    'update catalog declares every operator-visible state' => static function () use (
        $sinkholeUpdateCatalog,
    ): void {
        $catalog = $sinkholeUpdateCatalog['en_US'] ?? [];

        foreach ([
            'check_now',
            'update_to_version',
            'update_checks_off',
            'updates_not_checked',
            'no_public_release',
            'another_package_operation_running',
            'package_update_privilege_required',
            'release_signature_invalid',
            'signature_asset_missing',
            'release_asset_too_large',
            'package_digest_mismatch',
            'version_installed',
        ] as $key) {
            sinkholeTestAssertTrue(isset($catalog[$key]), 'The English catalog is missing ' . $key . '.');
        }
    },
    'About tested releases and catalog match the verified platforms' => static function () use (
        $sinkholeUpdateCatalog,
    ): void {
        sinkholeTestAssertSame(
            [
                [
                    'edition' => 'CE',
                    'version' => '2.9.0',
                    'freebsd' => '16.0',
                ],
                [
                    'edition' => 'CE',
                    'version' => '2.8.1',
                    'freebsd' => '15.0',
                ],
                [
                    'edition' => 'Plus',
                    'version' => '26.07',
                    'freebsd' => '16.0',
                ],
                [
                    'edition' => 'Plus',
                    'version' => '26.03.1',
                    'freebsd' => '16.0',
                ],
            ],
            TestedReleases::RELEASES,
            'The About release registry must retain CE first, then Plus, newest first within each edition.',
        );

        $catalog = $sinkholeUpdateCatalog['en_US'] ?? [];

        foreach (
            [
                'tested_pfsense_releases',
                'release',
                'this_firewall',
                'not_tested',
                'tested_release_footnote',
            ] as $key
        ) {
            sinkholeTestAssertTrue(
                isset($catalog[$key]),
                'The English catalog is missing About release key ' . $key . '.',
            );
        }
    },
];

sinkholeTestRun($cases);

fwrite(STDOUT, 'Update checks, notices, limits, locking, checksums, and signatures passed.' . PHP_EOL);
