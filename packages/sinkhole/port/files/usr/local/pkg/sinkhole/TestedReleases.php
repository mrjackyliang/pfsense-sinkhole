<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

/**
 * Tested pfSense releases.
 *
 * Keeps verified platform versions in one package-owned list so the About page
 * can label the current firewall without treating the broad ABI as support.
 *
 * @since 1.0.0
 */
final class TestedReleases
{
    /**
     * Tested releases with CE first, then Plus, newest first within each edition.
     *
     * The owner updates this list only after the complete disposable-firewall
     * verification passes for each pfSense and FreeBSD combination.
     *
     * @var list<array{edition: 'CE'|'Plus', version: string, freebsd: string}>
     *
     * @since 1.0.0
     */
    public const RELEASES = [
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
    ];
}
