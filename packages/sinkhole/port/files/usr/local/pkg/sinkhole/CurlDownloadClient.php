<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

require_once(__DIR__ . '/DownloadClient.php');

/**
 * Curl Download Client.
 *
 * Downloads untrusted list content with verified TLS, fixed timeouts, restricted
 * protocols, and an enforced byte limit.
 *
 * @since 1.0.0
 */
final class CurlDownloadClient implements DownloadClient
{
    /**
     * Curl Download Client - User Agent.
     *
     * The FreeBSD port substitutes its staged package version at install time.
     *
     * @since 1.0.0
     */
    public const USER_AGENT = 'Sinkhole-for-pfSense/%%PKGVERSION%%';

    /**
     * Curl Download Client - Download.
     *
     * The write callback stops before the response can exceed the configured cap and
     * partial files are removed on every failed transfer.
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
    ): array {
        if (!function_exists('curl_init')) {
            return [
                'success' => false,
                'bytes' => 0,
                'error' => 'The cURL extension is unavailable.',
            ];
        }

        $destinationHandle = fopen($destinationPath, 'wb');

        if ($destinationHandle === false) {
            return [
                'success' => false,
                'bytes' => 0,
                'error' => 'Unable to create a temporary download.',
            ];
        }

        $curlHandle = curl_init($url);

        if ($curlHandle === false) {
            fclose($destinationHandle);

            return [
                'success' => false,
                'bytes' => 0,
                'error' => 'Unable to initialize cURL.',
            ];
        }

        $bytes = 0;
        $oversized = false;
        $requestSettings = $this->requestSettings($url);

        curl_setopt($curlHandle, CURLOPT_CONNECTTIMEOUT, 15);
        curl_setopt($curlHandle, CURLOPT_TIMEOUT, 600);
        curl_setopt($curlHandle, CURLOPT_LOW_SPEED_LIMIT, 1024);
        curl_setopt($curlHandle, CURLOPT_LOW_SPEED_TIME, 60);
        curl_setopt($curlHandle, CURLOPT_ENCODING, '');
        curl_setopt($curlHandle, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curlHandle, CURLOPT_MAXREDIRS, 5);
        curl_setopt($curlHandle, CURLOPT_FAILONERROR, true);
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($curlHandle, CURLOPT_CAPATH, '/etc/ssl/certs/');
        curl_setopt($curlHandle, CURLOPT_USERAGENT, $requestSettings['user_agent']);

        if ($username !== null && $password !== null) {
            curl_setopt($curlHandle, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            curl_setopt($curlHandle, CURLOPT_USERPWD, $username . ':' . $password);
        }
        curl_setopt(
            $curlHandle,
            CURLOPT_WRITEFUNCTION,
            static function (mixed $unusedHandle, string $chunk) use (
                $destinationHandle,
                $maximumBytes,
                &$bytes,
                &$oversized,
            ): int {
                $chunkLength = strlen($chunk);

                if ($bytes + $chunkLength > $maximumBytes) {
                    $oversized = true;

                    return 0;
                }

                $written = fwrite($destinationHandle, $chunk);

                if ($written === false) {
                    return 0;
                }

                $bytes += $written;

                return $written;
            },
        );

        if (defined('CURLOPT_PROTOCOLS_STR')) {
            curl_setopt($curlHandle, CURLOPT_PROTOCOLS_STR, $requestSettings['protocols']);
            curl_setopt(
                $curlHandle,
                CURLOPT_REDIR_PROTOCOLS_STR,
                $requestSettings['redirect_protocols'],
            );
        } else {
            curl_setopt($curlHandle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            $redirectProtocols = ($requestSettings['redirect_protocols'] === 'https')
                ? CURLPROTO_HTTPS
                : (CURLPROTO_HTTP | CURLPROTO_HTTPS);

            curl_setopt($curlHandle, CURLOPT_REDIR_PROTOCOLS, $redirectProtocols);
        }

        if ($requestSettings['proxy_url'] !== '') {
            curl_setopt($curlHandle, CURLOPT_PROXY, $requestSettings['proxy_url']);

            if ($requestSettings['proxy_port'] !== '') {
                curl_setopt($curlHandle, CURLOPT_PROXYPORT, $requestSettings['proxy_port']);
            }

            if ($requestSettings['proxy_credentials'] !== '') {
                if (defined('CURLAUTH_ANY') && defined('CURLAUTH_ANYSAFE')) {
                    curl_setopt($curlHandle, CURLOPT_PROXYAUTH, CURLAUTH_ANY | CURLAUTH_ANYSAFE);
                }

                curl_setopt(
                    $curlHandle,
                    CURLOPT_PROXYUSERPWD,
                    $requestSettings['proxy_credentials'],
                );
            }
        }

        $result = curl_exec($curlHandle);
        $curlError = curl_error($curlHandle);

        curl_close($curlHandle);
        fclose($destinationHandle);

        if ($result === false) {
            if (file_exists($destinationPath)) {
                unlink($destinationPath);
            }

            return [
                'success' => false,
                'bytes' => $bytes,
                'error' => ($oversized)
                    ? sprintf(
                        'The download exceeds the %s size limit.',
                        self::sizeLimitLabel($maximumBytes),
                    )
                    : (($curlError === '') ? 'The download failed.' : $curlError),
            ];
        }

        return [
            'success' => true,
            'bytes' => $bytes,
            'error' => null,
        ];
    }

    /**
     * Curl Download Client - Request Settings.
     *
     * Exposes transport policy for offline tests while matching pfSense's
     * "set_curlproxy" keys and credential encoding.
     *
     * @param string $url - Validated source URL.
     *
     * @return array{
     *     protocols: string,
     *     redirect_protocols: string,
     *     user_agent: string,
     *     proxy_url: string,
     *     proxy_port: string,
     *     proxy_credentials: string
     * }
     *
     * @since 1.0.0
     */
    public function requestSettings(string $url): array
    {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        $proxyUrl = '';
        $proxyPort = '';
        $proxyUser = '';
        $proxyPassword = '';

        if (function_exists('config_get_path')) {
            $configuredProxyUrl = config_get_path('system/proxyurl', '');
            $configuredProxyPort = config_get_path('system/proxyport', '');
            $configuredProxyUser = config_get_path('system/proxyuser', '');
            $configuredProxyPassword = config_get_path('system/proxypass', '');
            $proxyUrl = is_string($configuredProxyUrl) ? $configuredProxyUrl : '';
            $proxyPort = is_string($configuredProxyPort) ? $configuredProxyPort : '';
            $proxyUser = is_string($configuredProxyUser) ? $configuredProxyUser : '';
            $proxyPassword = is_string($configuredProxyPassword) ? $configuredProxyPassword : '';
        }

        $proxyCredentials = '';

        if ($proxyUser !== '' && $proxyPassword !== '') {
            $proxyCredentials = rawurlencode($proxyUser) . ':' . rawurlencode($proxyPassword);
        }

        return [
            'protocols' => 'http,https',
            'redirect_protocols' => ($scheme === 'https') ? 'https' : 'http,https',
            'user_agent' => self::USER_AGENT,
            'proxy_url' => $proxyUrl,
            'proxy_port' => $proxyPort,
            'proxy_credentials' => $proxyCredentials,
        ];
    }

    /**
     * Curl Download Client - Size Limit Label.
     *
     * Keeps existing list diagnostics at 64 MiB while accurately reporting the
     * smaller catalog limit supplied through the same client.
     *
     * @param int $maximumBytes - Configured byte cap.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function sizeLimitLabel(int $maximumBytes): string
    {
        if ($maximumBytes > 0 && $maximumBytes % 1048576 === 0) {
            return (string) intdiv($maximumBytes, 1048576) . ' MiB';
        }

        return (string) $maximumBytes . ' bytes';
    }
}
