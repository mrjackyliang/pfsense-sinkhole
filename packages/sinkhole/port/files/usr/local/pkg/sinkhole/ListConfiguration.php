<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

require_once(__DIR__ . '/ValidationException.php');

/**
 * List Configuration.
 *
 * Validates stable IDs, display names, URLs, and enablement before any list reaches
 * storage, the downloader, or generated Unbound data.
 *
 * @since 1.0.0
 */
final class ListConfiguration
{
    /**
     * List Configuration - Generate Identifier.
     *
     * A cryptographically random lowercase hexadecimal key remains stable through
     * edits and safely forms package-owned filenames.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function generateIdentifier(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * List Configuration - Normalize Lists.
     *
     * pfSense stores rows as a numeric list; runtime callers receive a stable-ID map.
     * Associative input remains accepted only when its key matches the row ID.
     *
     * @param mixed $value - Persisted list map.
     *
     * @return array<string, array{id: string, name: string, url: string, enabled: bool, global: bool}>
     *
     * @since 1.0.0
     */
    public static function normalizeLists(mixed $value): array
    {
        return self::partitionLists($value)['lists'];
    }

    /**
     * List Configuration - Partition Lists.
     *
     * Valid rows continue through updates and compilation while malformed saved rows
     * remain available to the WebGUI with their original value and failure reason.
     *
     * @param mixed $value - Persisted list rows.
     *
     * @return array{
     *     lists: array<string, array{id: string, name: string, url: string, enabled: bool, global: bool}>,
     *     invalid_rows: list<array{
     *         position: int,
     *         id: string,
     *         name: string,
     *         url: string,
     *         enabled: bool,
     *         global: bool,
     *         reason: string,
     *         reason_key: string,
     *         reason_arguments: array<int, scalar|null>,
     *         row: mixed
     *     }>
     * }
     *
     * @since 1.0.0
     */
    public static function partitionLists(mixed $value): array
    {
        if ($value === null || $value === '') {
            return [
                'lists' => [],
                'invalid_rows' => [],
            ];
        }

        if (!is_array($value)) {
            return [
                'lists' => [],
                'invalid_rows' => [self::invalidRow(
                    0,
                    $value,
                    new ValidationException('saved_block_lists_invalid'),
                )],
            ];
        }

        $lists = [];
        $invalidRows = [];
        $position = 0;

        foreach ($value as $storageKey => $row) {
            try {
                if (!is_array($row)) {
                    throw new ValidationException('saved_block_list_invalid');
                }

                $rowIdentifier = is_string($row['id'] ?? null) ? $row['id'] : '';

                if (is_string($storageKey) && $storageKey !== $rowIdentifier) {
                    throw new ValidationException('saved_block_list_identifier_changed');
                }

                if (isset($lists[$rowIdentifier])) {
                    throw new ValidationException('saved_block_list_identifier_duplicated');
                }

                $lists[$rowIdentifier] = self::normalizeRow(
                    $rowIdentifier,
                    is_string($row['descr'] ?? null) ? $row['descr'] : '',
                    is_string($row['url'] ?? null) ? $row['url'] : '',
                    ($row['enabled'] ?? '') === 'on' || ($row['enabled'] ?? null) === true,
                    !array_key_exists('global', $row)
                        || ($row['global'] ?? '') === 'on'
                        || ($row['global'] ?? null) === true,
                );
            } catch (ValidationException $exception) {
                $invalidRows[] = self::invalidRow($position, $row, $exception);
            }

            $position++;
        }

        return [
            'lists' => $lists,
            'invalid_rows' => $invalidRows,
        ];
    }

    /**
     * List Configuration - Normalize Row.
     *
     * Both the custom WebGUI page and runtime configuration reader use this one
     * validation contract.
     *
     * @param string $identifier - Stable list identifier.
     * @param string $name       - Display name.
     * @param string $url        - Source URL.
     * @param bool   $enabled    - Enabled flag.
     * @param bool   $global     - Whether the global scope uses the list.
     *
     * @return array{id: string, name: string, url: string, enabled: bool, global: bool}
     *
     * @throws InvalidArgumentException When any value is invalid.
     *
     * @since 1.0.0
     */
    public static function normalizeRow(
        string $identifier,
        string $name,
        string $url,
        bool $enabled,
        bool $global = true,
    ): array {
        if (preg_match('/^[a-f0-9]{32}$/D', $identifier) !== 1) {
            throw new ValidationException('block_list_identifier_invalid');
        }

        $name = trim($name);

        if (
            $name === ''
            || strlen($name) > 128
            || preg_match('//u', $name) !== 1
            || preg_match('/[\x00-\x1f\x7f]/', $name) === 1
        ) {
            throw new ValidationException('block_list_name_invalid');
        }

        $url = trim($url);

        if (
            strlen($url) > 4096
            || preg_match('/^[\x21-\x7e]+$/D', $url) !== 1
            || filter_var($url, FILTER_VALIDATE_URL) === false
        ) {
            throw new ValidationException('block_list_url_invalid');
        }

        $urlParts = parse_url($url);
        $scheme = is_array($urlParts) ? strtolower((string) ($urlParts['scheme'] ?? '')) : '';

        if (
            !is_array($urlParts)
            || !in_array($scheme, ['http', 'https'], true)
            || isset($urlParts['host']) === false
            || isset($urlParts['user'])
            || isset($urlParts['pass'])
        ) {
            throw new ValidationException('block_list_url_scheme_invalid');
        }

        return [
            'id' => $identifier,
            'name' => $name,
            'url' => $url,
            'enabled' => $enabled,
            'global' => $global,
        ];
    }

    /**
     * List Configuration - Invalid Row.
     *
     * Extracts display-safe scalar fields without trusting the malformed row's shape.
     *
     * @param int    $position - Persisted row position.
     * @param mixed  $row      - Original row.
     * @param ValidationException $exception - Validation failure.
     *
     * @return array{
     *     position: int,
     *     id: string,
     *     name: string,
     *     url: string,
     *     enabled: bool,
     *     global: bool,
     *     reason: string,
     *     reason_key: string,
     *     reason_arguments: array<int, scalar|null>,
     *     row: mixed
     * }
     *
     * @since 1.0.0
     * @private
     */
    private static function invalidRow(
        int $position,
        mixed $row,
        ValidationException $exception,
    ): array
    {
        return [
            'position' => $position,
            'id' => is_array($row) && is_string($row['id'] ?? null) ? $row['id'] : '',
            'name' => is_array($row) && is_string($row['descr'] ?? null) ? $row['descr'] : '',
            'url' => is_array($row) && is_string($row['url'] ?? null) ? $row['url'] : '',
            'enabled' => is_array($row)
                && (($row['enabled'] ?? '') === 'on' || ($row['enabled'] ?? null) === true),
            'global' => !is_array($row)
                || !array_key_exists('global', $row)
                || ($row['global'] ?? '') === 'on'
                || ($row['global'] ?? null) === true,
            'reason' => $exception->getMessage(),
            'reason_key' => $exception->messageKey(),
            'reason_arguments' => $exception->messageArguments(),
            'row' => $row,
        ];
    }
}
