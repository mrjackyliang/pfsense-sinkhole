<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use RuntimeException;

/**
 * Restore Heal.
 *
 * Holds the configuration-restore recovery program that every package built from
 * Nova shares byte for byte, plus the verified package cache it reads and writes.
 *
 * @since 1.3.0
 */
final class RestoreHeal
{
    /**
     * Short package name shared by the log tag, cache folder, and pidfile.
     *
     * @since 1.3.0
     */
    public const SHORT_NAME = 'sinkhole';

    /**
     * GitHub repository that publishes the pinned release packages.
     *
     * @since 1.3.0
     */
    public const REPOSITORY = 'mrjackyliang/pfsense-sinkhole';

    /**
     * Persistent cache folder restored with the firewall configuration.
     *
     * @since 1.3.0
     */
    public const DIRECTORY = '/conf/' . self::SHORT_NAME . '/restore-heal';

    /**
     * Pidfile that daemon(8) holds locked while one recovery run is working.
     *
     * A second run started by the next quarter-hour exits at once instead of
     * downloading or installing alongside the first.
     *
     * @since 1.3.0
     */
    public const PID_FILE = '/var/run/' . self::SHORT_NAME . '-restore-heal.pid';

    /**
     * Largest command FreeBSD cron accepts, excluding its terminating NUL.
     *
     * @since 1.3.0
     */
    public const COMMAND_MAX_LENGTH = 999;

    /**
     * Recovery program shared byte for byte by every package built from Nova.
     *
     * Arguments: package name, repository, SHA-256, version, short name. It defers
     * while pfSense restores packages, exits when the package is installed, reuses a
     * verified cached copy, otherwise downloads and verifies the pinned release into
     * the cache, then installs it. Every step logs under "<short name>-restore-heal".
     *
     * @since 1.3.0
     */
    public const SCRIPT = 'p=$1;r=$2;h=$3;v=$4;g=$5-restore-heal;d=/conf/$5/restore-heal;n=$p-$v.pkg;c=$d/$n;t=$c.tmp;L(){ /usr/bin/logger -t $g "$1 $v";};[ -e /conf/needs_package_sync ]&&{ L deferred;exit 0;};/usr/local/sbin/pkg info -e $p&&exit 0;k(){ [ "$(/sbin/sha256 -q $1 2>/dev/null)" = $h ];};if k $c;then L cache;else /bin/rm -f $t;L fetch;/bin/mkdir -p $d&&/usr/bin/fetch -q -T 30 -o $t https://github.com/$r/releases/download/v$v/$n||{ /bin/rm -f $t;L fetch-failed;exit 1;};k $t||{ /bin/rm -f $t;L checksum-failed;exit 1;};/bin/rm -f $d/*.pkg;/bin/mv -f $t $c||{ L cache-failed;exit 1;};fi;L install;/usr/local/sbin/pkg add -f $c >/dev/null 2>&1||{ L install-failed;exit 1;};L installed';

    /**
     * Restore Heal - Command.
     *
     * Builds the detached cron command from already validated values.
     *
     * @param string $marker - Package-owned cron marker.
     * @param string $packageName - pkg package name.
     * @param string $sha256 - Lowercase SHA-256 of the pinned package.
     * @param string $version - Pinned release version.
     *
     * @return string
     *
     * @throws RuntimeException When the command would not fit in cron.
     *
     * @since 1.3.0
     */
    public static function command(
        string $marker,
        string $packageName,
        string $sha256,
        string $version,
    ): string {
        $arguments = array_map(
            static fn (string $argument): string => escapeshellarg($argument),
            [$packageName, self::REPOSITORY, $sha256, $version, self::SHORT_NAME],
        );
        $command = $marker
            . ' /usr/sbin/daemon -f -p '
            . self::PID_FILE
            . ' /bin/sh -c '
            . escapeshellarg(self::SCRIPT)
            . ' rh '
            . implode(' ', $arguments);

        if (strlen($command) > self::COMMAND_MAX_LENGTH) {
            throw new RuntimeException('Restore-heal command exceeds cron limits.');
        }

        return $command;
    }

    /**
     * Restore Heal - Command Pin.
     *
     * Reads the SHA-256 and version from a command in the current format.
     *
     * @param string $command - Stored cron command.
     *
     * @return array{sha256: string, version: string}|null
     *
     * @since 1.3.0
     */
    public static function commandPin(string $command): ?array
    {
        if (preg_match("/ rh '[^']+' '[^']+' '([a-f0-9]{64})' '([^']+)' '[^']+'\\z/", $command, $matches) !== 1) {
            return null;
        }

        return [
            'sha256' => $matches[1],
            'version' => $matches[2],
        ];
    }

    /**
     * Restore Heal - Cache File Name.
     *
     * @param string $packageName - pkg package name.
     * @param string $version - Release version.
     *
     * @return string
     *
     * @since 1.3.0
     */
    public static function cacheFileName(string $packageName, string $version): string
    {
        return $packageName . '-' . $version . '.pkg';
    }

    /**
     * Restore Heal - Prune Cache.
     *
     * Deletes cached files other than the current version's package, including
     * interrupted downloads and older versions.
     *
     * @param string $packageName - pkg package name.
     * @param string $version - Installed release version.
     * @param string $directory - Cache folder.
     *
     * @return void
     *
     * @since 1.3.0
     */
    public static function pruneCache(
        string $packageName,
        string $version,
        string $directory = self::DIRECTORY,
    ): void {
        $keep = self::cacheFileName($packageName, $version);

        foreach (self::entries($directory) as $entry) {
            if ($entry !== $keep) {
                @unlink($directory . '/' . $entry);
            }
        }
    }

    /**
     * Restore Heal - Remove Cache.
     *
     * Deletes the cache folder after a deliberate package removal.
     *
     * @param string $directory - Cache folder.
     *
     * @return void
     *
     * @since 1.3.0
     */
    public static function removeCache(string $directory = self::DIRECTORY): void
    {
        foreach (self::entries($directory) as $entry) {
            @unlink($directory . '/' . $entry);
        }

        if (is_dir($directory) && !is_link($directory)) {
            @rmdir($directory);
        }
    }

    /**
     * Restore Heal - Store Verified Package.
     *
     * Copies a package that already passed the release checksum and signature
     * checks into the cache, then prunes older cached files.
     *
     * @param string $packagePath - Verified package file.
     * @param string $packageName - pkg package name.
     * @param string $version - Its release version.
     * @param string $directory - Cache folder.
     *
     * @return void
     *
     * @throws RuntimeException When the cache cannot be written.
     *
     * @since 1.3.0
     */
    public static function storeVerifiedPackage(
        string $packagePath,
        string $packageName,
        string $version,
        string $directory = self::DIRECTORY,
    ): void {
        if (preg_match('/^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/', $version) !== 1) {
            throw new RuntimeException('The cached release version is invalid.');
        }

        if (is_link($directory) || (file_exists($directory) && !is_dir($directory))) {
            throw new RuntimeException('The restore-heal cache folder is invalid.');
        }

        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to create the restore-heal cache folder.');
        }

        @chmod($directory, 0700);

        $target = $directory . '/' . self::cacheFileName($packageName, $version);
        $temporary = $target . '.tmp';

        @unlink($temporary);

        if (!@copy($packagePath, $temporary) || !@chmod($temporary, 0600) || !@rename($temporary, $target)) {
            @unlink($temporary);

            throw new RuntimeException('Unable to write the restore-heal package cache.');
        }

        self::pruneCache($packageName, $version, $directory);
    }

    /**
     * Restore Heal - Entries.
     *
     * @param string $directory - Cache folder.
     *
     * @return list<string>
     *
     * @since 1.3.0
     * @private
     */
    private static function entries(string $directory): array
    {
        if (!is_dir($directory) || is_link($directory)) {
            return [];
        }

        $entries = @scandir($directory);

        if ($entries === false) {
            return [];
        }

        return array_values(array_filter(
            $entries,
            static fn (string $entry): bool => $entry !== '.'
                && $entry !== '..'
                && is_file($directory . '/' . $entry),
        ));
    }
}
