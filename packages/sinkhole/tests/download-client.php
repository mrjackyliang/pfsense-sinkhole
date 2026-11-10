<?php

declare(strict_types=1);

use PfSense\Sinkhole\Runtime\CurlDownloadClient;

require_once(__DIR__ . '/TestSupport.php');
require_once(__DIR__ . '/stubs/config.inc');
require_once(__DIR__ . '/../port/files/usr/local/pkg/sinkhole/CurlDownloadClient.php');

sinkholeTestRun([
    'https redirects cannot downgrade' => static function (): void {
        sinkholeStubReset(['system' => []]);
        $settings = (new CurlDownloadClient())->requestSettings(
            'https://lists.example.invalid/global.test',
        );

        sinkholeTestAssertSame('http,https', $settings['protocols'], 'Source protocols must stay bounded.');
        sinkholeTestAssertSame(
            'https',
            $settings['redirect_protocols'],
            'An HTTPS source may follow only HTTPS redirects.',
        );
        sinkholeTestAssertSame(
            'Sinkhole-for-pfSense/%%PKGVERSION%%',
            $settings['user_agent'],
            'The port must substitute the staged package version.',
        );
    },
    'http redirects and pfSense proxy settings are represented' => static function (): void {
        sinkholeStubReset([
            'system' => [
                'proxyurl' => 'proxy.example.test',
                'proxyport' => '3128',
                'proxyuser' => 'user name',
                'proxypass' => 'p@ss/word',
            ],
        ]);
        $settings = (new CurlDownloadClient())->requestSettings(
            'http://lists.example.invalid/global.test',
        );

        sinkholeTestAssertSame(
            'http,https',
            $settings['redirect_protocols'],
            'An HTTP source may redirect only within HTTP and HTTPS.',
        );
        sinkholeTestAssertSame(
            'proxy.example.test',
            $settings['proxy_url'],
            'The System proxy host must be used.',
        );
        sinkholeTestAssertSame('3128', $settings['proxy_port'], 'The System proxy port must be used.');
        sinkholeTestAssertSame(
            'user%20name:p%40ss%2Fword',
            $settings['proxy_credentials'],
            'Proxy credentials must match pfSense credential encoding.',
        );
    },
]);
