<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

/**
 * Download Client.
 *
 * Separates HTTP transport from updater policy so fallback behavior can be tested
 * without network access.
 *
 * @since 1.0.0
 */
interface DownloadClient
{
    /**
     * Download Client - Download.
     *
     * Implementations write only to the caller's temporary path and report a bounded
     * result without replacing a saved list.
     *
     * @param string $url             - Validated HTTP or HTTPS URL.
     * @param string $destinationPath - Temporary destination path.
     * @param int    $maximumBytes    - Maximum response size.
     * @param string|null $username - Optional HTTP basic-auth user.
     * @param string|null $password - Optional HTTP basic-auth password.
     *
     * @return array{success: bool, bytes: int, error: string|null}
     *
     * @since 1.0.0
     */
    public function download(
        string $url,
        string $destinationPath,
        int $maximumBytes,
        ?string $username = null,
        ?string $password = null,
    ): array;
}
