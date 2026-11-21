<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

/**
 * Release Source.
 *
 * Update checks, self-updates, and restore-heal pins read releases only through
 * this interface. Each release is a project-owned array, so the release host's API
 * shape stays inside its adapter.
 *
 * Release arrays hold "tag", "version", "release_url", "published_at", and
 * "assets", a list of name, url, and digest entries. Failures are RuntimeException
 * instances whose code carries the HTTP status when the server answered.
 *
 * @since 1.3.3
 */
interface ReleaseSource
{
    /**
     * Release Source - Asset URL Prefix.
     *
     * Asset selection rejects any package, checksum, or signature outside it.
     *
     * @return string
     *
     * @since 1.3.3
     */
    public function assetUrlPrefix(): string;

    /**
     * Release Source - Release Asset URL.
     *
     * Returns the immutable download URL of one file attached to one release.
     *
     * @param string $version - Normalized release version.
     * @param string $fileName - Attached file name.
     *
     * @return string
     *
     * @since 1.3.3
     */
    public function releaseAssetUrl(string $version, string $fileName): string;

    /**
     * Release Source - Fetch Latest Release.
     *
     * @return array{tag: string, version: string, release_url: string, published_at: string, assets: list<array{name: string, url: string, digest: string|null}>}
     *
     * @throws \RuntimeException When the request or response is invalid.
     *
     * @since 1.3.3
     */
    public function fetchLatestRelease(): array;

    /**
     * Release Source - Download Asset.
     *
     * Downloads one release asset into a private file, which is removed again
     * whenever the transfer fails.
     *
     * @param string $url - Validated asset URL.
     * @param string $path - Private destination path.
     * @param int $byteLimit - Largest accepted size.
     *
     * @return void
     *
     * @throws \RuntimeException When transport or HTTP validation fails.
     *
     * @since 1.3.3
     */
    public function downloadAsset(string $url, string $path, int $byteLimit): void;
}
