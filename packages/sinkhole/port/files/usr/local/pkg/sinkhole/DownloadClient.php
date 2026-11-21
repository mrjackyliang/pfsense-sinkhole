<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

/**
 * Download Client.
 *
 * Separates HTTP transport from updater policy so fallback behavior can be tested
 * without network access. Every outbound HTTP request in the package goes through
 * this interface.
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

    /**
     * Download Client - Request.
     *
     * Sends one short GET request through pfSense's proxy with strict TLS and at
     * most three redirects, for release metadata and assets. The body streams into
     * the destination file when one is given, and returns otherwise.
     *
     * Failure names the step that stopped the request before it was sent:
     * "destination" (file), "initialize" (transport), or "configure" (options).
     *
     * @param string $url - Validated HTTP or HTTPS URL.
     * @param list<string> $headers - Request header lines.
     * @param string $userAgent - User agent to send.
     * @param string|null $destinationPath - Private file the body streams into.
     * @param int $maximumBytes - Largest accepted streamed body; 0 means no limit.
     *
     * @return array{started: bool, failure: string|null, completed: bool, status: int, body: string|null, error: string, too_large: bool}
     *
     * @since 1.3.3
     */
    public function request(
        string $url,
        array $headers,
        string $userAgent,
        ?string $destinationPath = null,
        int $maximumBytes = 0,
    ): array;
}
