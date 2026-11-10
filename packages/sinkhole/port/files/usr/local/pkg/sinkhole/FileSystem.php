<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use RuntimeException;

/**
 * File System.
 *
 * Provides fixed-path operations for compiler generations without following
 * untrusted symlinks or placing temporary files in Unbound's writable root.
 *
 * @since 1.0.0
 */
final class FileSystem
{
    /**
     * File System - Managed Generation Prefix.
     *
     * Active data lives in root-owned directories carrying this fixed prefix.
     *
     * @since 1.0.0
     * @private
     */
    private const MANAGED_GENERATION_PREFIX = '.sinkhole-generation-';

    /**
     * File System - Ensure Directory.
     *
     * Creates one package-owned directory with its final mode and rejects non-
     * directory entries without changing a path that already existed.
     *
     * @param string $path - Directory path.
     * @param int    $mode - Directory mode.
     *
     * @return void
     *
     * @throws RuntimeException When the directory cannot be prepared.
     *
     * @since 1.0.0
     */
    public static function ensureDirectory(string $path, int $mode): void
    {
        self::createDirectoryIfMissing($path, $mode);
    }

    /**
     * File System - Ensure Owned Directory If Missing.
     *
     * Existing Unbound directories keep their owner and mode. A missing directory is
     * created with the same owner and mode pfSense uses for the Resolver chroot.
     *
     * @param string $path  - Directory path.
     * @param int    $mode  - New-directory mode.
     * @param string $user  - New-directory owner.
     * @param string $group - New-directory group.
     *
     * @return void
     *
     * @throws RuntimeException When the directory cannot be prepared.
     *
     * @since 1.0.0
     */
    public static function ensureOwnedDirectoryIfMissing(
        string $path,
        int $mode,
        string $user,
        string $group,
    ): void {
        if (self::createDirectoryIfMissing($path, $mode) === false) {
            return;
        }

        if ($user !== '' && lchown($path, $user) === false) {
            throw new RuntimeException('Unable to set the runtime directory owner.');
        }

        if ($group !== '' && lchgrp($path, $group) === false) {
            throw new RuntimeException('Unable to set the runtime directory group.');
        }

        self::assertDirectoryMode($path, $mode, 'Unable to verify the runtime directory.');
    }

    /**
     * File System - Ensure Owned Directory.
     *
     * Package-private storage must remain root-owned even though its parent chroot is
     * writable by Unbound. Tests may omit owner names in disposable directories.
     *
     * @param string $path  - Directory path.
     * @param int    $mode  - Directory mode.
     * @param string $user  - Required owner.
     * @param string $group - Required group.
     *
     * @return void
     *
     * @throws RuntimeException When ownership cannot be enforced.
     *
     * @since 1.0.0
     */
    public static function ensureOwnedDirectory(
        string $path,
        int $mode,
        string $user,
        string $group,
    ): void {
        if (self::createDirectoryIfMissing($path, $mode) === false) {
            return;
        }

        if ($user !== '' && lchown($path, $user) === false) {
            throw new RuntimeException('Unable to set the package directory owner.');
        }

        if ($group !== '' && lchgrp($path, $group) === false) {
            throw new RuntimeException('Unable to set the package directory group.');
        }

        self::assertDirectoryMode($path, $mode, 'Unable to verify the package directory.');
    }

    /**
     * File System - Ensure Replaceable Owned Directory.
     *
     * The Unbound-owned state path may be replaced by an unsafe entry. Removing that
     * fixed entry before creation avoids following a link placed in the chroot.
     *
     * @param string $path  - Directory path.
     * @param int    $mode  - Directory mode.
     * @param string $user  - Required owner for a new directory.
     * @param string $group - Required group for a new directory.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public static function ensureReplaceableOwnedDirectory(
        string $path,
        int $mode,
        string $user,
        string $group,
    ): void {
        $status = @lstat($path);

        if (is_array($status) && ($status['mode'] & 0170000) !== 0040000) {
            self::removeDirectory($path);
        }

        self::ensureOwnedDirectoryIfMissing($path, $mode, $user, $group);
    }

    /**
     * File System - Create Temporary Directory.
     *
     * Random names and exclusive "mkdir" calls avoid the file-to-directory race in
     * "tempnam" followed by unlinking.
     *
     * @param string $parent - Parent directory.
     * @param string $prefix - Fixed name prefix.
     * @param int    $mode   - Directory mode.
     *
     * @return string
     *
     * @throws RuntimeException When no directory can be created.
     *
     * @since 1.0.0
     */
    public static function createTemporaryDirectory(string $parent, string $prefix, int $mode): string
    {
        $parentStatus = @lstat($parent);

        if (!is_array($parentStatus) || ($parentStatus['mode'] & 0170000) !== 0040000) {
            throw new RuntimeException('The temporary parent directory is invalid.');
        }

        $previousMask = umask((~$mode) & 0777);

        try {
            for ($attempt = 0; $attempt < 10; $attempt++) {
                $path = $parent . '/' . $prefix . bin2hex(random_bytes(16));

                if (@mkdir($path, $mode)) {
                    self::assertDirectoryMode(
                        $path,
                        $mode,
                        'Unable to verify a temporary directory.',
                    );

                    return $path;
                }
            }
        } finally {
            umask($previousMask);
        }

        throw new RuntimeException('Unable to create a package directory.');
    }

    /**
     * File System - Create Temporary File.
     *
     * Opens a new regular file exclusively under a umask that gives it the final
     * mode, so no later permission change can follow a substituted symlink.
     *
     * @param string $parent - Parent directory.
     * @param string $prefix - Fixed name prefix.
     * @param int    $mode   - File mode.
     *
     * @return string
     *
     * @throws RuntimeException When no file can be created.
     *
     * @since 1.0.0
     */
    public static function createTemporaryFile(string $parent, string $prefix, int $mode): string
    {
        $parentStatus = @lstat($parent);

        if (!is_array($parentStatus) || ($parentStatus['mode'] & 0170000) !== 0040000) {
            throw new RuntimeException('The temporary parent directory is invalid.');
        }

        $previousMask = umask((~$mode) & 0777);

        try {
            for ($attempt = 0; $attempt < 10; $attempt++) {
                $path = $parent . '/' . $prefix . bin2hex(random_bytes(16));
                $handle = @fopen($path, 'x+b');

                if ($handle === false) {
                    continue;
                }

                fclose($handle);

                return $path;
            }
        } finally {
            umask($previousMask);
        }

        throw new RuntimeException('Unable to create a temporary file.');
    }

    /**
     * File System - Copy Directory.
     *
     * Copies only regular files and directories into a fresh compiler-owned tree.
     * The generation stamp is copied last so readers never see an incomplete source.
     *
     * @param string $source        - Source directory.
     * @param string $destination   - Destination directory.
     * @param int    $directoryMode - Directory mode.
     * @param int    $fileMode      - File mode.
     *
     * @return void
     *
     * @throws RuntimeException When any entry cannot be copied.
     *
     * @since 1.0.0
     */
    public static function copyDirectory(
        string $source,
        string $destination,
        int $directoryMode,
        int $fileMode,
    ): void {
        if (is_link($source) || is_dir($source) === false) {
            throw new RuntimeException('The compiler output directory is invalid.');
        }

        self::ensureDirectory($destination, $directoryMode);

        $entries = scandir($source);

        if ($entries === false) {
            throw new RuntimeException('Unable to read the compiler output directory.');
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..' || $entry === 'generation') {
                continue;
            }

            $sourcePath = $source . '/' . $entry;
            $destinationPath = $destination . '/' . $entry;

            if (is_link($sourcePath)) {
                throw new RuntimeException('The compiler output contains a symlink.');
            }

            if (is_dir($sourcePath)) {
                self::copyDirectory(
                    $sourcePath,
                    $destinationPath,
                    $directoryMode,
                    $fileMode,
                );

                continue;
            }

            self::copyRegularFile($sourcePath, $destinationPath, $fileMode);
        }

        $generationSource = $source . '/generation';

        if (is_file($generationSource) && is_link($generationSource) === false) {
            self::copyRegularFile(
                $generationSource,
                $destination . '/generation',
                $fileMode,
            );
        }
    }

    /**
     * File System - Activate Directory.
     *
     * Moves one complete temporary tree to a managed generation and atomically
     * replaces the active relative link. Old and orphaned generations are removed.
     *
     * @param string $temporaryPath  - Complete temporary directory.
     * @param string $storagePath    - Root-owned generation directory.
     * @param string $activeLinkPath - Active link visible inside the chroot.
     *
     * @return void
     *
     * @throws RuntimeException When activation cannot complete.
     *
     * @since 1.0.0
     */
    public static function activateDirectory(
        string $temporaryPath,
        string $storagePath,
        string $activeLinkPath,
    ): void {
        if (
            dirname($temporaryPath) !== $storagePath
            || dirname($storagePath) !== dirname($activeLinkPath)
        ) {
            throw new RuntimeException('The compiled data directory is not on the target filesystem.');
        }

        $suffix = bin2hex(random_bytes(8));
        $generationName = self::MANAGED_GENERATION_PREFIX . $suffix;
        $generationPath = $storagePath . '/' . $generationName;
        $temporaryLinkPath = $storagePath . '/.sinkhole-link-' . $suffix;
        $relativeTarget = basename($storagePath) . '/' . $generationName;
        $oldGenerationPath = self::resolveManagedGeneration($activeLinkPath, $storagePath);
        $activeStatus = @lstat($activeLinkPath);

        if (
            is_array($activeStatus)
            && ($activeStatus['mode'] & 0170000) !== 0120000
        ) {
            throw new RuntimeException('The active compiled data path is invalid.');
        }

        if (rename($temporaryPath, $generationPath) === false) {
            throw new RuntimeException('Unable to prepare the compiled data generation.');
        }

        if (symlink($relativeTarget, $temporaryLinkPath) === false) {
            rename($generationPath, $temporaryPath);

            throw new RuntimeException('Unable to create the compiled data link.');
        }

        if (rename($temporaryLinkPath, $activeLinkPath) === false) {
            if (file_exists($temporaryLinkPath) || is_link($temporaryLinkPath)) {
                unlink($temporaryLinkPath);
            }

            rename($generationPath, $temporaryPath);

            throw new RuntimeException('Unable to activate the compiled data directory.');
        }

        if ($oldGenerationPath !== null && $oldGenerationPath !== $generationPath) {
            self::removeDirectory($oldGenerationPath);
        }

        self::removeInactiveGenerations($storagePath, $generationPath);
    }

    /**
     * File System - Resolve Managed Generation.
     *
     * Reads an active link once and resolves only the current package generation
     * target inside the root-owned storage directory.
     *
     * @param string $activeLinkPath - Active symlink.
     * @param string $storagePath    - Root-owned generation directory.
     *
     * @return string|null
     *
     * @since 1.0.0
     */
    public static function resolveManagedGeneration(
        string $activeLinkPath,
        string $storagePath,
    ): ?string {
        if (is_link($activeLinkPath) === false) {
            return null;
        }

        $target = readlink($activeLinkPath);

        if (!is_string($target)) {
            return null;
        }

        $generationPattern = preg_quote(self::MANAGED_GENERATION_PREFIX, '/');
        $storageName = preg_quote(basename($storagePath), '/');

        if (preg_match('/^' . $storageName . '\/(' . $generationPattern . '[a-f0-9]{16})$/D', $target, $matches) === 1) {
            return $storagePath . '/' . $matches[1];
        }

        return null;
    }

    /**
     * File System - Remove Activated Directory.
     *
     * Removes the active link and its validated generation without following any
     * unrelated link target.
     *
     * @param string $activeLinkPath - Active symlink.
     * @param string $storagePath    - Root-owned generation directory.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public static function removeActivatedDirectory(
        string $activeLinkPath,
        string $storagePath,
    ): void {
        $generationPath = self::resolveManagedGeneration($activeLinkPath, $storagePath);

        self::removeDirectory($activeLinkPath);

        if ($generationPath !== null) {
            self::removeDirectory($generationPath);
        }

        self::removeInactiveGenerations($storagePath, null);
    }

    /**
     * File System - Remove Runtime State Directory.
     *
     * The Unbound-owned directory is untrusted: removal unlinks only known marker
     * names, never traverses children, and unlinks a substituted directory link.
     *
     * @param string $path - Runtime state directory path.
     *
     * @return void
     *
     * @throws RuntimeException When a fixed marker cannot be removed.
     *
     * @since 1.0.0
     */
    public static function removeRuntimeStateDirectory(string $path): void
    {
        $status = @lstat($path);

        if (!is_array($status)) {
            return;
        }

        if (($status['mode'] & 0170000) !== 0040000) {
            if (unlink($path) === false) {
                throw new RuntimeException('Unable to remove the runtime state path.');
            }

            return;
        }

        foreach (['loaded', 'events', 'events.processing', 'events-dropped'] as $fileName) {
            $filePath = $path . '/' . $fileName;
            $fileStatus = @lstat($filePath);

            if (!is_array($fileStatus)) {
                continue;
            }

            if (($fileStatus['mode'] & 0170000) === 0040000) {
                throw new RuntimeException('The runtime state marker is not a file.');
            }

            if (unlink($filePath) === false) {
                throw new RuntimeException('Unable to remove a runtime state marker.');
            }
        }

        $entries = scandir($path);

        if ($entries === false) {
            throw new RuntimeException('Unable to inspect the runtime state directory.');
        }

        foreach ($entries as $entry) {
            if (preg_match('/^\.(?:loaded|events-dropped)-[a-f0-9]{32}$/D', $entry) !== 1) {
                continue;
            }

            $temporaryPath = $path . '/' . $entry;
            $temporaryStatus = @lstat($temporaryPath);

            if (
                !is_array($temporaryStatus)
                || ($temporaryStatus['mode'] & 0170000) !== 0100000
            ) {
                continue;
            }

            if (unlink($temporaryPath) === false) {
                throw new RuntimeException('Unable to remove a runtime state marker temporary file.');
            }
        }

        if (@rmdir($path) === false) {
            $message = 'Sinkhole: Unable to remove the non-empty runtime state directory.';

            if (function_exists('log_error')) {
                log_error($message);
            } else {
                error_log($message);
            }
        }
    }

    /**
     * File System - Remove Fixed File.
     *
     * Removes one package-owned fixed name without following a symlink and rejects
     * a substituted directory.
     *
     * @param string $path - Fixed file path.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public static function removeFixedFile(string $path): void
    {
        $status = @lstat($path);

        if (!is_array($status)) {
            return;
        }

        if (($status['mode'] & 0170000) === 0040000) {
            throw new RuntimeException('A package-owned file was replaced by a directory.');
        }

        if (@unlink($path) === false) {
            throw new RuntimeException('Unable to remove a package-owned file.');
        }
    }

    /**
     * File System - Remove Directory.
     *
     * Recursively removes regular package paths while unlinking, never following,
     * symbolic links.
     *
     * @param string $path - Directory path.
     *
     * @return void
     *
     * @throws RuntimeException When an entry cannot be removed.
     *
     * @since 1.0.0
     */
    public static function removeDirectory(string $path): void
    {
        $status = @lstat($path);

        if (!is_array($status)) {
            return;
        }

        if (($status['mode'] & 0170000) !== 0040000) {
            if (unlink($path) === false) {
                throw new RuntimeException('Unable to remove package file.');
            }

            return;
        }

        $entries = scandir($path);

        if ($entries === false) {
            throw new RuntimeException('Unable to read package directory.');
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            self::removeDirectory($path . '/' . $entry);
        }

        if (rmdir($path) === false) {
            throw new RuntimeException('Unable to remove package directory.');
        }
    }

    /**
     * File System - Sweep Stale Entries.
     *
     * Removes only direct children with fixed package prefixes while unlinking any
     * symbolic link instead of traversing it.
     *
     * @param string       $parent   - Package-owned parent directory.
     * @param list<string> $prefixes - Fixed stale-entry prefixes.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public static function sweepStaleEntries(string $parent, array $prefixes): void
    {
        $status = @lstat($parent);

        if (!is_array($status) || ($status['mode'] & 0170000) !== 0040000) {
            return;
        }

        $entries = scandir($parent);

        if ($entries === false) {
            throw new RuntimeException('Unable to inspect package leftovers.');
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            foreach ($prefixes as $prefix) {
                if (str_starts_with($entry, $prefix)) {
                    self::removeDirectory($parent . '/' . $entry);

                    break;
                }
            }
        }
    }

    /**
     * File System - Directory Size.
     *
     * Counts regular compiler output without following links so deployment space
     * checks cannot be redirected outside the completed build tree.
     *
     * @param string $path - Directory path.
     *
     * @return int
     *
     * @since 1.0.0
     */
    public static function directorySize(string $path): int
    {
        $status = @lstat($path);

        if (!is_array($status) || ($status['mode'] & 0170000) !== 0040000) {
            throw new RuntimeException('The compiler output directory is invalid.');
        }

        $entries = scandir($path);

        if ($entries === false) {
            throw new RuntimeException('Unable to inspect compiler output.');
        }

        $size = 0;

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $entryPath = $path . '/' . $entry;
            $entryStatus = @lstat($entryPath);

            if (!is_array($entryStatus)) {
                throw new RuntimeException('Unable to inspect compiler output.');
            }

            if (($entryStatus['mode'] & 0170000) === 0040000) {
                $size += self::directorySize($entryPath);

                continue;
            }

            if (($entryStatus['mode'] & 0170000) !== 0100000) {
                throw new RuntimeException('The compiler output contains an invalid file.');
            }

            $size += $entryStatus['size'];
        }

        return $size;
    }

    /**
     * File System - Is Regular File.
     *
     * Uses one lstat result so Status and lifecycle checks reject symbolic links.
     *
     * @param string $path - File path.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public static function isRegularFile(string $path): bool
    {
        $status = @lstat($path);

        return is_array($status) && ($status['mode'] & 0170000) === 0100000;
    }

    /**
     * File System - Copy Regular File.
     *
     * Creates the destination exclusively under its final mode, preventing symlink
     * substitution during a later permission change.
     *
     * @param string $source      - Source file.
     * @param string $destination - Destination file.
     * @param int    $mode        - Destination mode.
     *
     * @return void
     *
     * @throws RuntimeException When the copy cannot complete.
     *
     * @since 1.0.0
     * @private
     */
    private static function copyRegularFile(string $source, string $destination, int $mode): void
    {
        if (is_link($source) || is_file($source) === false) {
            throw new RuntimeException('The compiler output contains an invalid file.');
        }

        $sourceHandle = fopen($source, 'rb');
        $destinationHandle = false;

        $previousMask = umask((~$mode) & 0777);

        try {
            $destinationHandle = @fopen($destination, 'x+b');
        } finally {
            umask($previousMask);
        }

        if ($sourceHandle === false || $destinationHandle === false) {
            if (is_resource($sourceHandle)) {
                fclose($sourceHandle);
            }

            if (is_resource($destinationHandle)) {
                fclose($destinationHandle);
            }

            throw new RuntimeException('Unable to copy compiler output.');
        }

        try {
            if (
                stream_copy_to_stream($sourceHandle, $destinationHandle) === false
                || fflush($destinationHandle) === false
            ) {
                throw new RuntimeException('Unable to copy compiler output.');
            }

            if (function_exists('fsync') && fsync($destinationHandle) === false) {
                throw new RuntimeException('Unable to synchronize compiler output.');
            }
        } finally {
            fclose($sourceHandle);
            fclose($destinationHandle);
        }
    }

    /**
     * File System - Remove Inactive Generations.
     *
     * Deletes only validated managed directory names inside the fixed storage root.
     *
     * @param string      $storagePath          - Root-owned generation directory.
     * @param string|null $activeGenerationPath - Generation path to retain.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private static function removeInactiveGenerations(
        string $storagePath,
        ?string $activeGenerationPath,
    ): void {
        if (is_dir($storagePath) === false || is_link($storagePath)) {
            return;
        }

        $entries = scandir($storagePath);

        if ($entries === false) {
            throw new RuntimeException('Unable to read the generation directory.');
        }

        $prefix = preg_quote(self::MANAGED_GENERATION_PREFIX, '/');

        foreach ($entries as $entry) {
            if (preg_match('/^' . $prefix . '[a-f0-9]{16}$/D', $entry) !== 1) {
                continue;
            }

            $generationPath = $storagePath . '/' . $entry;

            if ($generationPath !== $activeGenerationPath) {
                self::removeDirectory($generationPath);
            }
        }
    }

    /**
     * File System - Create Directory If Missing.
     *
     * Returns whether this call created the final path. A directory that wins a
     * concurrent creation race is validated but never has its mode or owner changed
     * by the caller.
     *
     * @param string $path - Directory path.
     * @param int    $mode - New-directory mode.
     *
     * @return bool
     *
     * @throws RuntimeException When the path is not a directory or cannot be created.
     *
     * @since 1.0.0
     * @private
     */
    private static function createDirectoryIfMissing(string $path, int $mode): bool
    {
        $status = @lstat($path);

        if (is_array($status)) {
            if (($status['mode'] & 0170000) !== 0040000) {
                throw new RuntimeException('The package directory is invalid.');
            }

            return false;
        }

        $previousMask = umask((~$mode) & 0777);

        try {
            $created = @mkdir($path, $mode, true);
        } finally {
            umask($previousMask);
        }

        $status = @lstat($path);

        if ($created === false) {
            if (is_array($status) && ($status['mode'] & 0170000) === 0040000) {
                return false;
            }

            throw new RuntimeException('Unable to create package directory.');
        }

        if (
            !is_array($status)
            || ($status['mode'] & 0170000) !== 0040000
            || ($status['mode'] & 0777) !== $mode
        ) {
            throw new RuntimeException('Unable to create package directory.');
        }

        return true;
    }

    /**
     * File System - Assert Directory Mode.
     *
     * Verifies a newly created path through lstat after ownership changes without
     * applying a later mode change to an entry that may have been substituted.
     *
     * @param string $path    - Directory path.
     * @param int    $mode    - Required mode.
     * @param string $message - Failure message.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private static function assertDirectoryMode(string $path, int $mode, string $message): void
    {
        $status = @lstat($path);

        if (
            !is_array($status)
            || ($status['mode'] & 0170000) !== 0040000
            || ($status['mode'] & 0777) !== $mode
        ) {
            throw new RuntimeException($message);
        }
    }
}
