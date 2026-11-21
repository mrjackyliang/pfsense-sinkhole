<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use PfSense\Sinkhole\Domain\Catalog;
use RuntimeException;
use stdClass;

require_once(__DIR__ . '/Catalog.php');

/**
 * pfBlockerNG Feed Source.
 *
 * Owns the pfBlockerNG feed catalog published in pfSense's FreeBSD-ports GitHub
 * repository: its raw URL and its JSON layout. Callers receive only normalized
 * catalog entries, so an upstream format change touches this file alone.
 *
 * @since 1.3.3
 */
final class PfBlockerNgFeedSource
{
    /**
     * pfBlockerNG Feed Source - Feeds URL.
     *
     * This fixed endpoint is never derived from request or downloaded data.
     *
     * @var string
     *
     * @since 1.3.3
     */
    public const FEEDS_URL = 'https://raw.githubusercontent.com/pfsense/FreeBSD-ports/devel/'
        . 'net/pfSense-pkg-pfBlockerNG-devel/files/usr/local/www/pfblockerng/'
        . 'pfblockerng_feeds.json';

    /**
     * pfBlockerNG Feed Source - Parse DNS Feeds.
     *
     * Traverses only DNS groups, using each group description for its feeds and
     * ignoring IP sections and alternate URLs reserved for later milestones.
     *
     * @param string $contents - Complete JSON document.
     *
     * @return list<array>
     *
     * @throws RuntimeException When the document has no DNS section.
     *
     * @since 1.3.3
     */
    public static function parseDnsFeeds(string $contents): array
    {
        $document = Catalog::decodeDocument($contents);

        if (!isset($document->dnsbl) || !$document->dnsbl instanceof stdClass) {
            throw new RuntimeException('The pfBlockerNG catalog is invalid.');
        }

        $entries = [];
        $groupCount = 0;
        $feedCount = 0;

        foreach (get_object_vars($document->dnsbl) as $groupNameValue => $groupValue) {
            if (
                $groupCount >= Catalog::MAXIMUM_GROUPS
                || $feedCount >= Catalog::MAXIMUM_ENTRIES
            ) {
                break;
            }

            $groupCount++;

            if (!$groupValue instanceof stdClass) {
                continue;
            }

            if (
                !is_string($groupValue->description ?? null)
                || !is_array($groupValue->feeds ?? null)
            ) {
                continue;
            }

            $group = Catalog::normalizeText($groupNameValue, Catalog::MAXIMUM_GROUP_BYTES);
            $description = Catalog::normalizeText(
                $groupValue->description,
                Catalog::MAXIMUM_DESCRIPTION_BYTES,
            );

            if ($group === null || $group === '' || $description === null) {
                continue;
            }

            foreach ($groupValue->feeds as $feed) {
                if ($feedCount >= Catalog::MAXIMUM_ENTRIES) {
                    break;
                }

                $feedCount++;

                if (
                    !$feed instanceof stdClass
                    || !is_string($feed->feed ?? null)
                    || !is_string($feed->url ?? null)
                ) {
                    continue;
                }

                $homepageValue = $feed->website ?? '';

                if (!is_string($homepageValue)) {
                    continue;
                }

                $name = Catalog::normalizeText($feed->feed, Catalog::MAXIMUM_NAME_BYTES);
                $url = Catalog::normalizeListUrl($feed->url);

                if ($name === null || $name === '' || $url === null) {
                    continue;
                }

                $homepage = Catalog::normalizeHomepage($homepageValue);
                $entries[] = [
                    'name' => $name,
                    'description' => $description,
                    'homepage' => $homepage,
                    'url' => $url,
                    'source' => Catalog::sourceLabels()[Catalog::SOURCE_PFBLOCKERNG],
                    'contents' => Catalog::contentsForSourceSection(
                        Catalog::SOURCE_PFBLOCKERNG,
                        'dnsbl',
                    ),
                    'group' => $group,
                    'tags' => [],
                    'category' => Catalog::categoryForGroup(Catalog::SOURCE_PFBLOCKERNG, $group),
                    'maintainer' => Catalog::maintainer($homepage),
                    'source_key' => Catalog::SOURCE_PFBLOCKERNG,
                    'catalog_section' => 'dnsbl',
                    'catalog_key' => $group,
                ];
            }
        }

        return $entries;
    }

    /**
     * pfBlockerNG Feed Source - Parse IP Feeds.
     *
     * Reads only the ``ipv4`` and ``ipv6`` sections. Bypass selects its fixed IP
     * groups from this full parse before the ordinary IP catalog removes them.
     *
     * @param string $contents - Complete pfBlockerNG JSON document.
     *
     * @return list<array>
     *
     * @throws RuntimeException When the document has no IP section.
     *
     * @since 1.3.3
     */
    public static function parseIpFeeds(string $contents): array
    {
        $document = Catalog::decodeDocument($contents);
        $entries = [];
        $groupCount = 0;
        $feedCount = 0;

        foreach (['ipv4', 'ipv6'] as $family) {
            $section = $document->{$family} ?? null;

            if (!$section instanceof stdClass) {
                continue;
            }

            foreach (get_object_vars($section) as $groupNameValue => $groupValue) {
                if ($groupCount >= Catalog::MAXIMUM_GROUPS || $feedCount >= Catalog::MAXIMUM_ENTRIES) {
                    break 2;
                }

                $groupCount++;

                if (
                    !$groupValue instanceof stdClass
                    || !is_string($groupValue->description ?? null)
                    || !is_array($groupValue->feeds ?? null)
                ) {
                    continue;
                }

                $group = Catalog::normalizeText($groupNameValue, Catalog::MAXIMUM_GROUP_BYTES);
                $description = Catalog::normalizeText(
                    $groupValue->description,
                    Catalog::MAXIMUM_DESCRIPTION_BYTES,
                );

                if ($group === null || $group === '' || $description === null) {
                    continue;
                }

                foreach ($groupValue->feeds as $feed) {
                    if ($feedCount >= Catalog::MAXIMUM_ENTRIES) {
                        break;
                    }

                    $feedCount++;

                    if (
                        !$feed instanceof stdClass
                        || !is_string($feed->feed ?? null)
                        || !is_string($feed->url ?? null)
                    ) {
                        continue;
                    }

                    $website = $feed->website ?? '';
                    $name = Catalog::normalizeText($feed->feed, Catalog::MAXIMUM_NAME_BYTES);
                    $url = Catalog::normalizeListUrl($feed->url);

                    if (!is_string($website) || $name === null || $name === '' || $url === null) {
                        continue;
                    }

                    $homepage = Catalog::normalizeHomepage($website);
                    $entries[] = [
                        'name' => $name,
                        'description' => $description,
                        'homepage' => $homepage,
                        'url' => $url,
                        'source' => Catalog::sourceLabels()[Catalog::SOURCE_PFBLOCKERNG],
                        'contents' => Catalog::contentsForSourceSection(
                            Catalog::SOURCE_PFBLOCKERNG,
                            $family,
                        ),
                        'group' => $group,
                        'tags' => [],
                        'family' => $family,
                        'category' => Catalog::CATEGORY_OTHER,
                        'maintainer' => Catalog::maintainer($homepage),
                        'source_key' => Catalog::SOURCE_PFBLOCKERNG,
                        'catalog_section' => $family,
                        'catalog_key' => $group,
                    ];
                }
            }
        }

        if ($entries === [] && !isset($document->ipv4) && !isset($document->ipv6)) {
            throw new RuntimeException('The pfBlockerNG IP catalog is invalid.');
        }

        return $entries;
    }
}
