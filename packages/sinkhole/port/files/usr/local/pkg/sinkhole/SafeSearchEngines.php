<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

/**
 * SafeSearch Engines.
 *
 * Fixed table of the search engines whose safe mode can be locked through DNS.
 * Each choice rewrites exact names to the engine's documented safe host. Qwant
 * publishes no working safe host, so its only choice blocks the engine.
 *
 * @since 1.1.0
 */
final class SafeSearchEngines
{
    /** @var string @since 1.1.0 */
    public const YOUTUBE_MODERATE = 'youtube_moderate';

    /** @var string @since 1.1.0 */
    public const YOUTUBE_STRICT = 'youtube_strict';

    /**
     * SafeSearch Engines - Google Search Domains.
     *
     * Google's published search domains plus the few older country domains it
     * still serves. Each becomes ``google.<suffix>`` and ``www.google.<suffix>``.
     *
     * @since 1.1.0
     */
    private const GOOGLE_SUFFIXES = [
        'ad', 'ae', 'al', 'am', 'as', 'at', 'az', 'ba',
        'be', 'bf', 'bg', 'bi', 'bj', 'bs', 'bt', 'by',
        'ca', 'cat', 'cd', 'cf', 'cg', 'ch', 'ci', 'cl',
        'cm', 'cn', 'co', 'co.ao', 'co.bw', 'co.ck', 'co.cr', 'co.id',
        'co.il', 'co.in', 'co.jp', 'co.ke', 'co.kr', 'co.ls', 'co.ma', 'co.mz',
        'co.nz', 'co.th', 'co.tz', 'co.ug', 'co.uk', 'co.uz', 'co.ve', 'co.vi',
        'co.za', 'co.zm', 'co.zw', 'com', 'com.af', 'com.ag', 'com.ai', 'com.ar',
        'com.au', 'com.bd', 'com.bh', 'com.bn', 'com.bo', 'com.br', 'com.bz', 'com.co',
        'com.cu', 'com.cy', 'com.do', 'com.ec', 'com.eg', 'com.et', 'com.fj', 'com.gh',
        'com.gi', 'com.gt', 'com.hk', 'com.jm', 'com.kh', 'com.kw', 'com.lb', 'com.ly',
        'com.mm', 'com.mt', 'com.mx', 'com.my', 'com.na', 'com.nf', 'com.ng', 'com.ni',
        'com.np', 'com.om', 'com.pa', 'com.pe', 'com.pg', 'com.ph', 'com.pk', 'com.pr',
        'com.py', 'com.qa', 'com.sa', 'com.sb', 'com.sg', 'com.sl', 'com.sv', 'com.tj',
        'com.tr', 'com.tw', 'com.ua', 'com.uy', 'com.vc', 'com.vn', 'cv', 'cz',
        'de', 'dj', 'dk', 'dm', 'dz', 'ee', 'es', 'fi',
        'fm', 'fr', 'ga', 'ge', 'gg', 'gl', 'gm', 'gp',
        'gr', 'gy', 'hn', 'hr', 'ht', 'hu', 'ie', 'im',
        'iq', 'is', 'it', 'je', 'jo', 'kg', 'ki', 'kz',
        'la', 'li', 'lk', 'lt', 'lu', 'lv', 'md', 'me',
        'mg', 'mk', 'ml', 'mn', 'ms', 'mu', 'mv', 'mw',
        'ne', 'nl', 'no', 'nr', 'nu', 'pl', 'pn', 'ps',
        'pt', 'ro', 'rs', 'ru', 'rw', 'sc', 'se', 'sh',
        'si', 'sk', 'sm', 'sn', 'so', 'sr', 'st', 'td',
        'tg', 'tk', 'tl', 'tm', 'tn', 'to', 'tt', 'vg',
        'vu', 'ws',
    ];

    /**
     * SafeSearch Engines - Yandex Search Domains.
     *
     * Each becomes ``<domain>`` and ``www.<domain>``.
     *
     * @since 1.1.0
     */
    private const YANDEX_DOMAINS = [
        'ya.ru', 'yandex.az', 'yandex.by', 'yandex.co.il', 'yandex.com', 'yandex.com.am',
        'yandex.com.ge', 'yandex.com.ru', 'yandex.com.tr', 'yandex.de', 'yandex.ee',
        'yandex.eu', 'yandex.fi', 'yandex.fr', 'yandex.kz', 'yandex.lt', 'yandex.lv',
        'yandex.md', 'yandex.net', 'yandex.org', 'yandex.pl', 'yandex.ru', 'yandex.tj',
        'yandex.tm', 'yandex.uz', 'xn--d1acpjx3f.xn--p1ai',
    ];

    /**
     * SafeSearch Engines - YouTube Names.
     *
     * @since 1.1.0
     */
    private const YOUTUBE_NAMES = [
        'youtube.com', 'www.youtube.com', 'm.youtube.com', 'youtubei.googleapis.com',
        'youtube.googleapis.com', 'www.youtube-nocookie.com', 'youtube-ui.l.google.com',
    ];

    /**
     * SafeSearch Engines - Choices.
     *
     * Stable choice identifiers in display order. ``target`` is empty for a choice
     * that blocks the engine. Both YouTube choices share the same names; a client
     * with both receives Strict.
     *
     * @since 1.1.0
     */
    private const CHOICES = [
        'google' => ['engine' => 'google', 'target' => 'forcesafesearch.google.com'],
        self::YOUTUBE_MODERATE => ['engine' => 'youtube', 'target' => 'restrictmoderate.youtube.com'],
        self::YOUTUBE_STRICT => ['engine' => 'youtube', 'target' => 'restrict.youtube.com'],
        'bing' => ['engine' => 'bing', 'target' => 'strict.bing.com'],
        'duckduckgo' => ['engine' => 'duckduckgo', 'target' => 'safe.duckduckgo.com'],
        'brave' => ['engine' => 'brave', 'target' => 'forcesafe.search.brave.com'],
        'startpage' => ['engine' => 'startpage', 'target' => 'safe.startpage.com'],
        'ecosia' => ['engine' => 'ecosia', 'target' => 'strict-safe-search.ecosia.org'],
        'yandex' => ['engine' => 'yandex', 'target' => 'familysearch.yandex.ru'],
        'pixabay' => ['engine' => 'pixabay', 'target' => 'safesearch.pixabay.com'],
        'qwant' => ['engine' => 'qwant', 'target' => ''],
    ];

    /**
     * SafeSearch Engines - Identifiers.
     *
     * @return list<string>
     *
     * @since 1.1.0
     */
    public static function identifiers(): array
    {
        return array_keys(self::CHOICES);
    }

    /**
     * SafeSearch Engines - Is Identifier.
     *
     * @param mixed $value - Untrusted value.
     *
     * @return bool
     *
     * @since 1.1.0
     */
    public static function isIdentifier(mixed $value): bool
    {
        return is_string($value) && array_key_exists($value, self::CHOICES);
    }

    /**
     * SafeSearch Engines - Engine.
     *
     * @param string $identifier - Choice identifier.
     *
     * @return string
     *
     * @since 1.1.0
     */
    public static function engine(string $identifier): string
    {
        return self::CHOICES[$identifier]['engine'] ?? '';
    }

    /**
     * SafeSearch Engines - Target.
     *
     * @param string $identifier - Choice identifier.
     *
     * @return string Empty when the choice blocks the engine.
     *
     * @since 1.1.0
     */
    public static function target(string $identifier): string
    {
        return self::CHOICES[$identifier]['target'] ?? '';
    }

    /**
     * SafeSearch Engines - Names.
     *
     * @param string $engine - Engine identifier.
     *
     * @return list<string> Exact lowercase names rewritten for the engine.
     *
     * @since 1.1.0
     */
    public static function names(string $engine): array
    {
        return match ($engine) {
            'google' => array_merge(...array_map(
                static fn(string $suffix): array => ['google.' . $suffix, 'www.google.' . $suffix],
                self::GOOGLE_SUFFIXES,
            )),
            'youtube' => self::YOUTUBE_NAMES,
            'bing' => ['bing.com', 'www.bing.com', 'edgeservices.bing.com'],
            'duckduckgo' => ['duckduckgo.com', 'www.duckduckgo.com', 'start.duckduckgo.com'],
            'brave' => ['search.brave.com'],
            'startpage' => ['startpage.com', 'www.startpage.com'],
            'ecosia' => ['ecosia.org', 'www.ecosia.org'],
            'yandex' => array_merge(...array_map(
                static fn(string $domain): array => [$domain, 'www.' . $domain],
                self::YANDEX_DOMAINS,
            )),
            'pixabay' => ['pixabay.com', 'www.pixabay.com'],
            'qwant' => ['qwant.com', 'www.qwant.com', 'api.qwant.com', 'lite.qwant.com'],
            default => [],
        };
    }

    /**
     * SafeSearch Engines - Normalize Selection.
     *
     * Keeps known choices in display order and keeps only Strict when both
     * YouTube choices arrive together.
     *
     * @param mixed $value - Untrusted list of choice identifiers.
     *
     * @return list<string>
     *
     * @since 1.1.0
     */
    public static function normalizeSelection(mixed $value): array
    {
        if (is_array($value) && count($value) === 1 && array_key_exists('item', $value)) {
            $value = $value['item'];
        }

        if (is_string($value) && $value !== '') {
            $value = [$value];
        }

        $selected = [];

        foreach (is_array($value) ? $value : [] as $identifier) {
            if (self::isIdentifier($identifier)) {
                $selected[$identifier] = true;
            }
        }

        if (isset($selected[self::YOUTUBE_STRICT])) {
            unset($selected[self::YOUTUBE_MODERATE]);
        }

        return array_values(array_filter(
            self::identifiers(),
            static fn(string $identifier): bool => isset($selected[$identifier]),
        ));
    }
}
