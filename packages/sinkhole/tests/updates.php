<?php

declare(strict_types=1);

use PfSense\Sinkhole\Runtime\DownloadClient;
use PfSense\Sinkhole\Runtime\FileLock;
use PfSense\Sinkhole\Runtime\GitHubReleaseSource;
use PfSense\Sinkhole\Runtime\PackagePaths;
use PfSense\Sinkhole\Runtime\ReleaseSource;
use PfSense\Sinkhole\Runtime\ReleaseUpdateLockRunner;
use PfSense\Sinkhole\Runtime\TestedReleases;
use PfSense\Sinkhole\Runtime\Translator;
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

/** @var array<int|string, array<string, string>> @since 1.2.3 */
$sinkholeUpdateStoredNotices = [];

/** @var int|null @since 1.2.3 */
$sinkholeUpdateNoticeTime = null;

if (!function_exists('file_notice')) {
    /**
     * Sinkhole Update Test - File Notice.
     *
     * Keeps raw call arguments for delivery assertions while maintaining the
     * same encoded timestamp-keyed queue as pfSense.
     *
     * @return void
     *
     * @since 1.2.3
     */
    function file_notice(
        string $id,
        string $notice,
        string $category = 'General',
        string $url = '',
        int $priority = 1,
        bool $localOnly = false,
    ): void {
        global $sinkholeUpdateNoticeTime;
        global $sinkholeUpdateNotices;
        global $sinkholeUpdateStoredNotices;

        $sinkholeUpdateNotices[] = compact(
            'id',
            'notice',
            'category',
            'url',
            'priority',
            'localOnly',
        );
        $noticeTime = $sinkholeUpdateNoticeTime ?? time();

        while (array_key_exists($noticeTime, $sinkholeUpdateStoredNotices)) {
            $noticeTime++;
        }

        $sinkholeUpdateStoredNotices[$noticeTime] = [
            'id' => htmlentities($id),
            'notice' => htmlentities($notice),
            'url' => htmlentities($url),
            'category' => htmlentities($category),
            'priority' => htmlentities((string) $priority),
        ];
    }
}

if (!function_exists('get_notices')) {
    /**
     * Sinkhole Update Test - Get Notices.
     *
     * Mirrors pfSense's false return for a missing or empty notice queue while
     * exposing timestamp-keyed entries to update tests.
     *
     * @return array<int|string, array<string, string>>|false
     *
     * @since 1.2.3
     */
    function get_notices(): array|false
    {
        global $sinkholeUpdateStoredNotices;

        return count($sinkholeUpdateStoredNotices) === 0
            ? false
            : $sinkholeUpdateStoredNotices;
    }
}

if (!function_exists('close_notice')) {
    /**
     * Sinkhole Update Test - Close Notice.
     *
     * Removes only one queue-key or stored-identifier match so duplicate update
     * IDs follow pfSense's close semantics.
     *
     * @param string $id - Notice identifier.
     *
     * @return void
     *
     * @since 1.2.3
     */
    function close_notice(string $id): void
    {
        global $sinkholeUpdateClosedNotices;
        global $sinkholeUpdateStoredNotices;

        $sinkholeUpdateClosedNotices[] = $id;

        if ($id === 'all') {
            $sinkholeUpdateStoredNotices = [];

            return;
        }

        if (array_key_exists($id, $sinkholeUpdateStoredNotices)) {
            unset($sinkholeUpdateStoredNotices[$id]);

            return;
        }

        foreach ($sinkholeUpdateStoredNotices as $noticeQueueKey => $notice) {
            if (($notice['id'] ?? null) !== $id) {
                continue;
            }

            unset($sinkholeUpdateStoredNotices[$noticeQueueKey]);

            return;
        }
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
 * Sinkhole Update Test - Hold Lock.
 *
 * A child process owns the advisory lock because FileLock deliberately shares
 * nested handles inside one PHP process.
 *
 * @param string $path - Lock file path.
 *
 * @return array{process: resource, pipes: array<int, resource>}
 *
 * @since 1.3.0
 */
function sinkholeUpdateHoldLock(string $path): array
{
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

    return [
        'process' => $process,
        'pipes' => $pipes,
    ];
}

/**
 * Sinkhole Update Test - Release Held Lock.
 *
 * Signals the child fixture and verifies that it relinquishes the advisory lock
 * cleanly before the disposable test directory is removed.
 *
 * @param array{process: resource, pipes: array<int, resource>}|null $fixture - Lock fixture.
 *
 * @return void
 *
 * @since 1.3.0
 */
function sinkholeUpdateReleaseHeldLock(?array &$fixture): void
{
    if ($fixture === null) {
        return;
    }

    $process = $fixture['process'];
    $pipes = $fixture['pipes'];
    $fixture = null;

    fwrite($pipes[0], "release\n");
    fclose($pipes[0]);
    fclose($pipes[1]);
    $childError = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);

    sinkholeTestAssertSame('', $childError, 'The concurrent lock fixture must not report an error.');
    sinkholeTestAssertSame(0, $exitCode, 'The concurrent lock fixture must exit cleanly.');
}

/**
 * Sinkhole Update Test - Run CLI.
 *
 * Rewrites only the installed package include prefix so argument validation can
 * execute from the source tree without a pfSense installation.
 *
 * @param list<string> $arguments - CLI arguments after the executable name.
 *
 * @return array{exit_code: int, stdout: string, stderr: string}
 *
 * @since 1.3.0
 */
function sinkholeUpdateRunCli(array $arguments): array
{
    $sourcePath = __DIR__ . '/../port/files/usr/local/sbin/sinkhole';
    $packageDirectory = realpath(__DIR__ . '/../port/files/usr/local/pkg/sinkhole');
    $temporaryPath = tempnam(sys_get_temp_dir(), 'sinkhole-cli-');

    if (!is_string($packageDirectory) || $temporaryPath === false) {
        throw new RuntimeException('Unable to prepare the CLI fixture.');
    }

    $source = (string) file_get_contents($sourcePath);
    $source = preg_replace('/\A#![^\n]*\n/', '', $source);

    if (!is_string($source)) {
        throw new RuntimeException('Unable to normalize the CLI fixture.');
    }

    $source = str_replace(
        '/usr/local/pkg/sinkhole/',
        $packageDirectory . '/',
        $source,
    );

    if (file_put_contents($temporaryPath, $source) === false) {
        @unlink($temporaryPath);

        throw new RuntimeException('Unable to write the CLI fixture.');
    }

    try {
        $process = proc_open(
            array_merge([PHP_BINARY, $temporaryPath], $arguments),
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
        );

        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start the CLI fixture.');
        }

        fclose($pipes[0]);
        $standardOutput = stream_get_contents($pipes[1]);
        $standardError = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        return [
            'exit_code' => $exitCode,
            'stdout' => is_string($standardOutput) ? $standardOutput : '',
            'stderr' => is_string($standardError) ? $standardError : '',
        ];
    } finally {
        @unlink($temporaryPath);
    }
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

/**
 * Sinkhole Update Test - Release Download Client.
 *
 * Answers release requests from canned responses without a network and records
 * each request, so tests can prove the endpoints, headers, and limits used.
 *
 * @since 1.3.3
 */
final class SinkholeUpdateReleaseDownloadClient implements DownloadClient
{
    /** @var list<array{url: string, headers: list<string>, user_agent: string, destination: string|null, maximum_bytes: int}> @since 1.3.3 */
    public array $requests = [];

    /** @var array Next request result. @since 1.3.3 */
    public array $response = [
        'started' => true,
        'failure' => null,
        'completed' => true,
        'status' => 200,
        'body' => '{}',
        'error' => '',
        'too_large' => false,
    ];

    /** @var string Body written to a destination file. @since 1.3.3 */
    public string $fileBody = '';

    /** {@inheritDoc} @since 1.3.3 */
    public function download(
        string $url,
        string $destinationPath,
        int $maximumBytes,
        ?string $username = null,
        ?string $password = null,
    ): array {
        throw new RuntimeException('List downloads are not part of the update tests.');
    }

    /** {@inheritDoc} @since 1.3.3 */
    public function request(
        string $url,
        array $headers,
        string $userAgent,
        ?string $destinationPath = null,
        int $maximumBytes = 0,
    ): array {
        $this->requests[] = [
            'url' => $url,
            'headers' => $headers,
            'user_agent' => $userAgent,
            'destination' => $destinationPath,
            'maximum_bytes' => $maximumBytes,
        ];

        if ($destinationPath !== null && $this->response['started'] === true) {
            file_put_contents($destinationPath, $this->fileBody);
        }

        return $this->response;
    }
}

/**
 * Sinkhole Update Test - Release Source.
 *
 * Serves one canned project-owned release so update checks are proven to use only
 * the release source.
 *
 * @since 1.3.3
 */
final class SinkholeUpdateFixtureReleaseSource implements ReleaseSource
{
    /** @var int @since 1.3.3 */
    public int $latestRequests = 0;

    /** @since 1.3.3 */
    public function __construct(private readonly array $release)
    {
    }

    /** {@inheritDoc} @since 1.3.3 */
    public function assetUrlPrefix(): string
    {
        return UpdateManager::DOWNLOAD_PREFIX;
    }

    /** {@inheritDoc} @since 1.3.3 */
    public function releaseAssetUrl(string $version, string $fileName): string
    {
        return UpdateManager::DOWNLOAD_PREFIX . 'v' . $version . '/' . $fileName;
    }

    /** {@inheritDoc} @since 1.3.3 */
    public function fetchLatestRelease(): array
    {
        $this->latestRequests++;

        return $this->release;
    }

    /** {@inheritDoc} @since 1.3.3 */
    public function downloadAsset(string $url, string $path, int $byteLimit): void
    {
        throw new RuntimeException('Update checks must not download assets.');
    }
}

$cases = [
    'a release is offered only once its package, checksum, and signature are attached' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();

        try {
            file_put_contents(
                $root . '/keys.pub',
                'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEcEuM8O7kQQkKHAgao93cat1D9++Xd8gX4JXKEza6HH' . PHP_EOL,
            );
            $signed = new UpdateManager(installedVersion: '2.0.0', signingKeysFile: $root . '/keys.pub');
            $complete = sinkholeUpdateRelease();
            $bare = $complete;
            $bare['assets'] = [];

            sinkholeTestAssertSame(true, $signed->releaseInstallable($complete), 'A release with its package, checksum, and signature is installable.');
            sinkholeTestAssertSame(false, $signed->releaseInstallable($bare), 'A release whose build hasn\'t attached files yet must not be offered.');
            sinkholeTestAssertSame(
                false,
                $signed->releaseInstallable(sinkholeUpdateRelease(true, false)),
                'With signing keys installed, a release without its signature must not be offered.',
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
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
    'manual checks suppress notices while scheduled checks emit each version once' => static function (): void {
        global $sinkholeUpdateClosedNotices;
        global $sinkholeUpdateNoticeTime;
        global $sinkholeUpdateNotices;
        global $sinkholeUpdateStoredNotices;

        $sinkholeUpdateNotices = [];
        $sinkholeUpdateClosedNotices = [];
        $sinkholeUpdateNoticeTime = 1_700_000_000;
        $sinkholeUpdateStoredNotices = [];
        $manualState = UpdateManager::synchronizeNotice(
            [],
            '2.0.0',
            '2.1.0',
            true,
            false,
        );

        sinkholeTestAssertSame(0, count($sinkholeUpdateNotices), 'A manual check must not file a notice.');
        sinkholeTestAssertSame('2.1.0', $manualState['notified_version'], 'A manual check must remember the version as notified.');

        $state = UpdateManager::synchronizeNotice(
            $manualState,
            '2.0.0',
            '2.1.0',
            false,
            true,
        );

        sinkholeTestAssertSame(0, count($sinkholeUpdateNotices), 'A scheduled check must not announce a version already seen manually.');

        $state = UpdateManager::synchronizeNotice($state, '2.0.0', '2.2.0', false, true);

        sinkholeTestAssertSame(1, count($sinkholeUpdateNotices), 'A scheduled check must create one bell notice for a new version.');
        sinkholeTestAssertSame(true, $sinkholeUpdateNotices[0]['localOnly'], 'Remote delivery must be off by default.');
        sinkholeTestAssertSame(UpdateManager::ABOUT_PAGE, $sinkholeUpdateNotices[0]['url'], 'The notice must link to About.');
        sinkholeTestAssertSame('2.2.0', $state['notified_version'], 'The noticed version must persist.');

        $state = UpdateManager::synchronizeNotice($state, '2.0.0', '2.2.0', true, true);
        sinkholeTestAssertSame(1, count($sinkholeUpdateNotices), 'The same version must not create another notice.');

        $state = UpdateManager::synchronizeNotice($state, '2.0.0', '2.3.0', true, true);
        sinkholeTestAssertSame(2, count($sinkholeUpdateNotices), 'A later version must create one notice.');
        sinkholeTestAssertSame(false, $sinkholeUpdateNotices[1]['localOnly'], 'The explicit opt-in must enable remote delivery.');

        UpdateManager::synchronizeNotice($state, '2.3.0', '2.3.0', true, true);
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
        $source = (string) file_get_contents(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/CurlDownloadClient.php');
        sinkholeTestAssertContains('$options[CURLOPT_MAXFILESIZE_LARGE] = $maximumBytes;', $source, 'cURL must enforce the declared size limit.');
        sinkholeTestAssertContains('$downloadedCount > $maximumBytes', $source, 'The progress callback must enforce the size limit too.');
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
    'release checks ignore a package task lock' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $releasePath = $root . '/release.lock';
        $packagePath = $root . '/update.lock';
        $fixture = null;

        try {
            $fixture = sinkholeUpdateHoldLock($packagePath);
            $operationRan = false;
            $runner = new ReleaseUpdateLockRunner(
                new FileLock($releasePath),
                null,
                $root . '/update-status.json',
                0,
                0,
            );
            $result = $runner->run(
                false,
                static function () use (&$operationRan): array {
                    $operationRan = true;

                    return ['latest_version' => '2.1.0'];
                },
            );

            sinkholeTestAssertSame(true, $result['completed'], 'A check must run while the package task lock is held.');
            sinkholeTestAssertSame(true, $operationRan, 'The release-check callback must execute.');
            sinkholeTestAssertSame('2.1.0', $result['state']['latest_version'] ?? null, 'The check result must pass through the lock runner.');
        } finally {
            sinkholeUpdateReleaseHeldLock($fixture);
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'release checks report a busy release operation' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $releasePath = $root . '/release.lock';
        $fixture = null;

        try {
            $fixture = sinkholeUpdateHoldLock($releasePath);
            $runner = new ReleaseUpdateLockRunner(
                new FileLock($releasePath),
                null,
                $root . '/update-status.json',
                0,
                0,
            );
            $result = $runner->run(
                false,
                static function (): array {
                    throw new RuntimeException('A busy release lock must skip the check.');
                },
            );

            sinkholeTestAssertSame(false, $result['completed'], 'A busy release lock must skip the operation.');
            sinkholeTestAssertSame(
                Translator::translate('release_operation_running'),
                $result['message'],
                'A busy release lock must use its dedicated translated message.',
            );
        } finally {
            sinkholeUpdateReleaseHeldLock($fixture);
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'self-update waits for a package task and fails after the injected timeout' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $releasePath = $root . '/release.lock';
        $packagePath = $root . '/update.lock';
        $statusPath = $root . '/update-status.json';
        $fixture = null;

        try {
            UpdateManager::queueSelfUpdate('2.1.0', $statusPath);
            UpdateManager::markQueuedSelfUpdateWaiting(
                Translator::translate('update_waiting_for_task'),
                $statusPath,
            );
            $waitingStatus = UpdateManager::readStatusState($statusPath, '2.0.0');

            sinkholeTestAssertSame('running', $waitingStatus['state'] ?? null, 'The package-lock wait must remain in progress.');
            sinkholeTestAssertSame(
                Translator::translate('update_waiting_for_task'),
                $waitingStatus['message'] ?? null,
                'The About progress line must explain the package-task wait.',
            );

            UpdateManager::queueSelfUpdate('2.1.0', $statusPath);
            $queuedStatus = UpdateManager::readStatusState($statusPath, '2.0.0');
            $fixture = sinkholeUpdateHoldLock($packagePath);
            $runner = new ReleaseUpdateLockRunner(
                new FileLock($releasePath),
                new FileLock($packagePath),
                $statusPath,
                0,
                1,
            );
            $startedAt = microtime(true);
            $result = $runner->run(
                true,
                static function (): array {
                    throw new RuntimeException('A timed-out package lock must skip self-update.');
                },
            );
            $elapsed = microtime(true) - $startedAt;
            $status = UpdateManager::readStatusState($statusPath, '2.0.0');

            sinkholeTestAssertTrue($elapsed >= 0.9, 'Self-update must wait for the injected package-lock timeout.');
            sinkholeTestAssertSame(false, $result['completed'], 'A busy package task must prevent installation.');
            sinkholeTestAssertSame(
                Translator::translate('update_task_still_running'),
                $result['message'],
                'A package-lock timeout must use its dedicated translated message.',
            );
            sinkholeTestAssertSame('failed', $status['state'] ?? null, 'The queued job must fail after the wait expires.');
            sinkholeTestAssertSame($result['message'], $status['message'] ?? null, 'The failed job must expose the timeout message.');
            sinkholeTestAssertSame('2.1.0', $status['version'] ?? null, 'The failed job must preserve its queued version.');
            sinkholeTestAssertSame($queuedStatus['started_at'] ?? null, $status['started_at'] ?? null, 'Waiting must preserve the queued start time.');
        } finally {
            sinkholeUpdateReleaseHeldLock($fixture);
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    '--no-notice without --check-updates is a usage error' => static function (): void {
        $result = sinkholeUpdateRunCli(['--no-notice']);

        sinkholeTestAssertSame(64, $result['exit_code'], 'The notice flag alone must return the usage-error exit code.');
        sinkholeTestAssertSame('', $result['stdout'], 'The invalid notice flag must not write normal output.');
        sinkholeTestAssertSame(
            Translator::translate('cli_options_mutually_exclusive') . PHP_EOL,
            $result['stderr'],
            'The invalid notice flag must use the existing usage error.',
        );

        $selfUpdateResult = sinkholeUpdateRunCli(['--self-update', '--no-notice']);

        sinkholeTestAssertSame(64, $selfUpdateResult['exit_code'], 'The notice flag must be rejected with self-update.');
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
        sinkholeTestAssertContains("case '--no-notice'", $cli, 'The CLI must expose notice-free manual checks.');
        sinkholeTestAssertContains("case '--self-update'", $cli, 'The CLI must expose self-update.');
        sinkholeTestAssertContains('NOVA_PFSENSE_UPDATE_RELEASES_API', $cli, 'Tests must be able to override the API.');
        sinkholeTestAssertContains('NOVA_PFSENSE_UPDATE_DOWNLOAD_PREFIX', $cli, 'Tests must be able to override the download prefix.');
        sinkholeTestAssertSame(false, str_contains($cli, 'NOVA_PFSENSE_UPDATE_SIGNING'), 'The signing key path must never be environment-controlled.');
        sinkholeTestAssertContains('new FileLock($paths->releaseLockFile)', $cli, 'Release work must use the release lock.');
        sinkholeTestAssertContains('$selfUpdate ? new FileLock($paths->updateLockFile) : null', $cli, 'Only self-update may construct the package task lock.');
        sinkholeTestAssertContains('$manager->check($remoteNotifications, $fileNotice)', $cli, 'The check must receive its explicit notice choice.');
        sinkholeTestAssertContains("'add',\n                '-f'", $selfUpdate, 'Self-update must install with pkg add -f.');
        sinkholeTestAssertTrue(strpos($selfUpdate, '$this->verifyReleaseSignature(') < strpos($selfUpdate, '$this->verifyPackageMetadata('), 'Signature verification must precede pkg query -F.');
        sinkholeTestAssertContains('UpdateManager::installedVersion()', $about, 'The About page must read the installed version through the update manager.');
        sinkholeTestAssertContains("getUserEntry((string) (\$_SESSION['Username'] ?? ''))", $about, 'The About page must resolve the logged-in pfSense user.');
        sinkholeTestAssertContains("'page-firewall-sinkhole-general'", $about, 'Update actions must require the General settings privilege.');
        sinkholeTestAssertContains("userHasPrivilege(\$currentUser, 'page-all')", $about, 'Update actions must permit page-all administrators.');
        sinkholeTestAssertContains('PackagePaths::MANUAL_UPDATE_CHECK_COMMAND', $about, 'The About page must use the notice-free check command.');
        sinkholeTestAssertContains("'release_operation_running'", $about, 'The About page must recognize a busy release lock.');
        sinkholeTestAssertContains('Platform::adapter()->installedPackages()', $manager, 'The update manager must read the installed package version first.');
        sinkholeTestAssertContains("Platform::adapter()->parsePackageXml(\$packageInfoPath, 'pfsensepkgs')", $manager, 'The update manager must fall back to the installed info.xml version.');
        sinkholeTestAssertSame(false, (bool) preg_match('/\bcurl_[a-z_]+\s*\(/', $manager), 'The update manager must reach GitHub only through its release source.');

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

        sinkholeTestAssertSame(
            PackagePaths::UPDATE_CHECK_COMMAND . ' --no-notice',
            PackagePaths::MANUAL_UPDATE_CHECK_COMMAND,
            'The manual command must extend the scheduled check without changing cron.',
        );
    },
    'running install settles once pfSense reports its version' => static function (): void {
        $directory = sinkholeTestTemporaryDirectory();
        $statusPath = $directory . '/update-status.json';

        try {
            UpdateManager::queueSelfUpdate('1.2.0', $statusPath);

            $runningStatus = UpdateManager::readStatusState($statusPath, '1.1.0');

            sinkholeTestAssertSame('running', $runningStatus['state'] ?? null, 'An install must stay running until pfSense reports the new version.');

            $settledStatus = UpdateManager::readStatusState($statusPath, 'v1.2.0');

            sinkholeTestAssertSame('succeeded', $settledStatus['state'] ?? null, 'A running install must settle once pfSense reports its version.');
            sinkholeTestAssertSame('1.2.0', $settledStatus['version'] ?? null, 'The settled status must keep the installed version.');
            sinkholeTestAssertTrue(is_string($settledStatus['finished_at'] ?? null), 'The settled status must record when it finished.');

            $savedStatus = UpdateManager::readStatusState($statusPath, '1.1.0');

            sinkholeTestAssertSame('succeeded', $savedStatus['state'] ?? null, 'The settled status must be saved for later reads.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($directory);
        }
    },
    'update catalog declares every operator-visible state' => static function () use (
        $sinkholeUpdateCatalog,
    ): void {
        $catalog = $sinkholeUpdateCatalog['en_US'] ?? [];
        $newKeys = [
            'release_operation_running',
            'update_waiting_for_task',
            'update_task_still_running',
        ];

        foreach ($sinkholeUpdateCatalog as $locale => $localeCatalog) {
            foreach ($newKeys as $key) {
                sinkholeTestAssertTrue(
                    isset($localeCatalog[$key]),
                    'The ' . $locale . ' catalog is missing ' . $key . '.',
                );
            }

            sinkholeTestAssertContains(
                '--no-notice',
                $localeCatalog['cli_usage'] ?? '',
                'The ' . $locale . ' CLI usage must include --no-notice.',
            );
        }

        foreach ([
            'check_now',
            'update_to_version',
            'update_checks_off',
            'updates_not_checked',
            'no_public_release',
            'another_package_operation_running',
            'release_operation_running',
            'update_waiting_for_task',
            'update_task_still_running',
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
                    'version' => '2.9.1',
                    'freebsd' => '16.0',
                ],
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
                    'version' => '26.07.1',
                    'freebsd' => '16.0',
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
    'the GitHub release source owns the endpoints and parses releases' => static function (): void {
        $client = new SinkholeUpdateReleaseDownloadClient();
        $client->response['body'] = (string) json_encode([
            'tag_name' => 'v2.1.0',
            'html_url' => 'https://github.com/mrjackyliang/pfsense-sinkhole/releases/tag/v2.1.0',
            'published_at' => '2026-11-06T12:00:00Z',
            'assets' => [[
                'name' => 'pfSense-pkg-Sinkhole-2.1.0.pkg',
                'browser_download_url' => GitHubReleaseSource::DOWNLOAD_PREFIX . 'v2.1.0/pfSense-pkg-Sinkhole-2.1.0.pkg',
                'digest' => 'sha256:' . str_repeat('a', 64),
            ]],
        ]);
        $source = new GitHubReleaseSource(downloadClient: $client);
        $release = $source->fetchLatestRelease();

        sinkholeTestAssertSame('2.1.0', $release['version'], 'The source must normalize the release tag.');
        sinkholeTestAssertSame(GitHubReleaseSource::RELEASES_API, $client->requests[0]['url'], 'The latest release must come from the GitHub API.');
        sinkholeTestAssertSame(
            ['Accept: application/vnd.github+json', 'X-GitHub-Api-Version: 2022-11-28'],
            $client->requests[0]['headers'],
            'Release metadata must ask for the GitHub API format.',
        );
        sinkholeTestAssertSame('pfSense-pkg-Sinkhole', $client->requests[0]['user_agent'], 'Release requests must identify the package.');
        sinkholeTestAssertSame(null, $client->requests[0]['destination'], 'Release metadata must be returned in memory.');
        sinkholeTestAssertSame(
            GitHubReleaseSource::DOWNLOAD_PREFIX . 'v2.1.0/pfSense-pkg-Sinkhole-2.1.0.pkg.sha256',
            $source->releaseAssetUrl('2.1.0', 'pfSense-pkg-Sinkhole-2.1.0.pkg.sha256'),
            'Release files must live under their tag directory.',
        );
        sinkholeTestAssertSame(UpdateManager::RELEASES_API, GitHubReleaseSource::RELEASES_API, 'The update manager must reuse the source endpoint.');
        sinkholeTestAssertSame(true, GitHubReleaseSource::isAllowedReleaseUrl($release['release_url']), 'Repository release pages must be allowed.');
        sinkholeTestAssertSame(false, GitHubReleaseSource::isAllowedReleaseUrl('https://example.com/releases/tag/v2.1.0'), 'Other release pages must be rejected.');

        $client->response['status'] = 404;

        try {
            $source->fetchLatestRelease();

            throw new RuntimeException('A missing release must fail.');
        } catch (RuntimeException $runtimeException) {
            sinkholeTestAssertSame(true, UpdateManager::isNoPublicReleaseStatus($runtimeException->getCode()), 'HTTP 404 must stay recognizable as no public release.');
        }

        $client->response['status'] = 429;
        sinkholeUpdateAssertFailure(
            static fn (): array => $source->fetchLatestRelease(),
            Translator::translate('github_rate_limited'),
        );

        $client->response = [
            'started' => true,
            'failure' => null,
            'completed' => false,
            'status' => 0,
            'body' => null,
            'error' => 'Invented transport failure',
            'too_large' => false,
        ];
        sinkholeUpdateAssertFailure(
            static fn (): array => $source->fetchLatestRelease(),
            Translator::translate('update_connection_failed', ['Invented transport failure']),
        );
    },
    'the GitHub release source downloads assets through the download client' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $client = new SinkholeUpdateReleaseDownloadClient();
        $source = new GitHubReleaseSource(downloadClient: $client);
        $path = $root . '/package.pkg';

        try {
            $client->fileBody = 'invented package bytes';
            $source->downloadAsset('https://downloads.example.test/package.pkg', $path, 1024);

            sinkholeTestAssertSame('invented package bytes', file_get_contents($path), 'A downloaded asset must reach its private path.');
            sinkholeTestAssertSame(['Accept: application/octet-stream'], $client->requests[0]['headers'], 'Asset downloads must ask for the raw file.');
            sinkholeTestAssertSame(1024, $client->requests[0]['maximum_bytes'], 'Asset downloads must pass their size limit.');

            $client->response['too_large'] = true;
            sinkholeUpdateAssertFailure(
                static function () use ($source, $path): void {
                    $source->downloadAsset('https://downloads.example.test/package.pkg', $path, 4);
                },
                Translator::translate('release_asset_too_large'),
            );
            sinkholeTestAssertSame(false, file_exists($path), 'An oversized asset must be removed.');

            $client->response['too_large'] = false;
            $client->response['status'] = 404;

            try {
                $source->downloadAsset('https://downloads.example.test/package.pkg', $path, 1024);

                throw new RuntimeException('A missing asset must fail.');
            } catch (RuntimeException $runtimeException) {
                sinkholeTestAssertSame(404, $runtimeException->getCode(), 'A missing asset must keep its HTTP status.');
                sinkholeTestAssertSame(false, file_exists($path), 'A missing asset download must be removed.');
            }

            $client->response = [
                'started' => false,
                'failure' => 'destination',
                'completed' => false,
                'status' => 0,
                'body' => null,
                'error' => '',
                'too_large' => false,
            ];
            sinkholeUpdateAssertFailure(
                static function () use ($source, $path): void {
                    $source->downloadAsset('https://downloads.example.test/package.pkg', $path, 1024);
                },
                Translator::translate('release_asset_private_file_failed'),
            );

            $client->response['failure'] = 'configure';
            sinkholeUpdateAssertFailure(
                static function () use ($source, $path): void {
                    $source->downloadAsset('https://downloads.example.test/package.pkg', $path, 1024);
                },
                Translator::translate('update_request_initialize_failed'),
            );
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
    'update checks read releases only from their release source' => static function (): void {
        $root = sinkholeTestTemporaryDirectory();
        $source = new SinkholeUpdateFixtureReleaseSource(sinkholeUpdateRelease());

        try {
            $manager = new UpdateManager(
                installedVersion: '2.0.0',
                releaseSource: $source,
                updatesFile: $root . '/updates.json',
                statusFile: $root . '/update-status.json',
                signingKeysFile: $root . '/missing.pub',
            );
            $state = $manager->check(false, false);

            sinkholeTestAssertSame(1, $source->latestRequests, 'The check must ask its release source once.');
            sinkholeTestAssertSame('2.1.0', $state['latest_version'], 'The check must save the source release.');
            sinkholeTestAssertSame($state, UpdateManager::readUpdatesState($root . '/updates.json'), 'The check must persist the state it returns.');
        } finally {
            sinkholeTestRemoveTemporaryDirectory($root);
        }
    },
];

sinkholeTestRun($cases);

fwrite(STDOUT, 'Update checks, notices, limits, locking, checksums, and signatures passed.' . PHP_EOL);
