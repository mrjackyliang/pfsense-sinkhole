<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

require_once(__DIR__ . '/ScopeConfiguration.php');
require_once(__DIR__ . '/ValidationException.php');

/**
 * Redirect Configuration.
 *
 * Validates DNS redirect settings independently from rule rendering so malformed
 * saved values remain repairable without reaching pf rule text.
 *
 * @since 1.0.0
 */
final class RedirectConfiguration
{
    /**
     * Redirect Configuration - Partition.
     *
     * Returns valid runtime values and display-safe descriptions of malformed saved
     * values so the WebGUI can keep them available for repair.
     *
     * @param mixed $value - Persisted redirect settings.
     * @param array<string, string> $interfaces - Configured interfaces.
     * @param array<string, string> $aliases - Existing host and network aliases.
     *
     * @return array{
     *     enabled: bool,
     *     interfaces: list<string>,
     *     exempt_sources: list<string>,
     *     exempt_destinations: list<string>,
     *     stored_interfaces: list<string>,
     *     stored_exempt_sources: list<string>,
     *     stored_exempt_destinations: list<string>,
     *     invalid_values: list<array{field: string, field_key: string, value: string, reason: string, reason_key: string, reason_arguments: array<int, scalar|null>}>,
     *     invalid_exemptions: list<array{field: string, field_key: string, value: string, reason: string, reason_key: string, reason_arguments: array<int, scalar|null>}>
     * }
     *
     * @since 1.0.0
     */
    public static function partition(mixed $value, array $interfaces, array $aliases): array
    {
        $result = [
            'enabled' => false,
            'interfaces' => [],
            'exempt_sources' => [],
            'exempt_destinations' => [],
            'stored_interfaces' => [],
            'stored_exempt_sources' => [],
            'stored_exempt_destinations' => [],
            'invalid_values' => [],
            'invalid_exemptions' => [],
        ];

        if ($value === null || $value === '' || $value === []) {
            return $result;
        }

        if (!is_array($value)) {
            $result['invalid_values'][] = self::invalidValue(
                'redirect_settings',
                $value,
                new ValidationException('saved_redirect_settings_invalid'),
            );

            return $result;
        }

        $enabledValue = $value['enabled'] ?? '';

        if ($enabledValue === 'on' || $enabledValue === true) {
            $result['enabled'] = true;
        } elseif ($enabledValue !== '' && $enabledValue !== false && $enabledValue !== null) {
            $result['invalid_values'][] = self::invalidValue(
                'enable',
                $enabledValue,
                new ValidationException('redirect_enable_value_invalid'),
            );
        }

        $interfaceValues = self::unwrapItems($value['interfaces'] ?? []);

        if (!is_array($interfaceValues)) {
            $result['stored_interfaces'][] = self::displayValue($interfaceValues);
            $result['invalid_values'][] = self::invalidValue(
                'interfaces',
                $interfaceValues,
                new ValidationException('saved_redirect_interfaces_invalid'),
            );
        } else {
            $selectedInterfaces = [];

            foreach (array_values($interfaceValues) as $interfaceValue) {
                $displayValue = self::displayValue($interfaceValue);
                $result['stored_interfaces'][] = $displayValue;

                if (
                    !is_string($interfaceValue)
                    || preg_match('/^[\x21-\x7e]+$/D', $interfaceValue) !== 1
                    || !array_key_exists($interfaceValue, $interfaces)
                ) {
                    $result['invalid_values'][] = self::invalidValue(
                        'interface',
                        $interfaceValue,
                        new ValidationException('redirect_interface_not_configured'),
                    );

                    continue;
                }

                $selectedInterfaces[$interfaceValue] = true;
            }

            $result['interfaces'] = array_keys($selectedInterfaces);
        }

        $sourcePartition = self::partitionExemptions(
            $value['exempt_sources'] ?? [],
            $aliases,
            'exempt_sources',
            'exempt_source',
            'source',
        );
        $result['exempt_sources'] = $sourcePartition['values'];
        $result['stored_exempt_sources'] = $sourcePartition['stored'];
        $result['invalid_values'] = array_merge(
            $result['invalid_values'],
            $sourcePartition['invalid'],
        );
        $result['invalid_exemptions'] = array_merge(
            $result['invalid_exemptions'],
            $sourcePartition['invalid'],
        );

        $destinationPartition = self::partitionExemptions(
            $value['exempt_destinations'] ?? [],
            $aliases,
            'exempt_destinations',
            'exempt_destination',
            'destination',
        );
        $result['exempt_destinations'] = $destinationPartition['values'];
        $result['stored_exempt_destinations'] = $destinationPartition['stored'];
        $result['invalid_values'] = array_merge(
            $result['invalid_values'],
            $destinationPartition['invalid'],
        );
        $result['invalid_exemptions'] = array_merge(
            $result['invalid_exemptions'],
            $destinationPartition['invalid'],
        );

        if ($result['enabled'] === true && count($result['interfaces']) === 0) {
            $result['invalid_values'][] = self::invalidValue(
                'interfaces',
                '',
                new ValidationException('redirect_interface_required'),
            );
        }

        return $result;
    }

    /**
     * Redirect Configuration - Normalize Submission.
     *
     * Applies the saved-settings contract to one WebGUI submission and rejects the
     * write when any row needs repair.
     *
     * @param bool $enabled - Requested redirect state.
     * @param mixed $interfacesValue - Submitted interfaces.
     * @param string $exemptSourcesText - Submitted exempt-source lines.
     * @param array<string, string> $interfaces - Configured interfaces.
     * @param array<string, string> $aliases - Existing host and network aliases.
     * @param string $exemptDestinationsText - Submitted exempt-destination lines.
     *
     * @return array{enabled: bool, interfaces: list<string>, exempt_sources: list<string>, exempt_destinations: list<string>}
     *
     * @throws InvalidArgumentException When a submitted setting is invalid.
     *
     * @since 1.0.0
     */
    public static function normalizeSubmission(
        bool $enabled,
        mixed $interfacesValue,
        string $exemptSourcesText,
        array $interfaces,
        array $aliases,
        string $exemptDestinationsText = '',
    ): array {
        if (!is_array($interfacesValue)) {
            throw new ValidationException('redirect_interface_selection_invalid');
        }

        $sourceValues = self::nonEmptyLines($exemptSourcesText, 'exempt_sources_invalid');
        $destinationValues = self::nonEmptyLines(
            $exemptDestinationsText,
            'exempt_destinations_invalid',
        );

        $partition = self::partition([
            'enabled' => ($enabled) ? 'on' : '',
            'interfaces' => [
                'item' => array_values($interfacesValue),
            ],
            'exempt_sources' => [
                'item' => $sourceValues,
            ],
            'exempt_destinations' => [
                'item' => $destinationValues,
            ],
        ], $interfaces, $aliases);

        if (count($partition['invalid_values']) > 0) {
            $invalidValue = $partition['invalid_values'][0];

            throw new ValidationException(
                $invalidValue['reason_key'],
                $invalidValue['reason_arguments'],
            );
        }

        return [
            'enabled' => $partition['enabled'],
            'interfaces' => $partition['interfaces'],
            'exempt_sources' => $partition['exempt_sources'],
            'exempt_destinations' => $partition['exempt_destinations'],
        ];
    }

    /**
     * Redirect Configuration - Rule Text.
     *
     * Renders only validated interface names, addresses, networks, and alias macro
     * names into the package NAT hook returned to pfSense.
     *
     * @param list<array{interface: string, ipv4_interface: string, ipv4_target?: string, ipv6_interface: string, ipv6_target?: string}> $interfaceDetails - Addressed real interfaces and targets.
     * @param list<string> $exemptSources - Valid exempt sources.
     * @param array<string, string> $aliases - Existing host and network aliases.
     * @param list<string> $exemptDestinations - Valid exempt destinations.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public static function ruleText(
        array $interfaceDetails,
        array $exemptSources,
        array $aliases,
        array $exemptDestinations = [],
    ): string {
        $normalizedSources = [];

        foreach ($exemptSources as $exemptSource) {
            $normalizedSource = self::normalizeExemption(
                $exemptSource,
                $aliases,
                'source',
            );
            $normalizedSources[$normalizedSource] = true;
        }

        $normalizedDestinations = [];

        foreach ($exemptDestinations as $exemptDestination) {
            $normalizedDestination = self::normalizeExemption(
                $exemptDestination,
                $aliases,
                'destination',
            );
            $normalizedDestinations[$normalizedDestination] = true;
        }

        $formattedSources = [
            'inet' => [],
            'inet6' => [],
        ];

        foreach (array_keys($normalizedSources) as $normalizedSource) {
            if (isset($aliases[$normalizedSource])) {
                $formattedSources['inet'][] = '$' . $normalizedSource;
                $formattedSources['inet6'][] = '$' . $normalizedSource;

                continue;
            }

            $sourceAddress = explode('/', $normalizedSource, 2)[0];
            $sourceFamily = (filter_var(
                $sourceAddress,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4,
            ) !== false) ? 'inet' : 'inet6';
            $formattedSources[$sourceFamily][] = $normalizedSource;
        }

        $formattedDestinations = [
            'inet' => [],
            'inet6' => [],
        ];

        foreach (array_keys($normalizedDestinations) as $normalizedDestination) {
            if (isset($aliases[$normalizedDestination])) {
                $formattedDestinations['inet'][] = '$' . $normalizedDestination;
                $formattedDestinations['inet6'][] = '$' . $normalizedDestination;

                continue;
            }

            $destinationAddress = explode('/', $normalizedDestination, 2)[0];
            $destinationFamily = (filter_var(
                $destinationAddress,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4,
            ) !== false) ? 'inet' : 'inet6';
            $formattedDestinations[$destinationFamily][] = $normalizedDestination;
        }

        $rules = [];

        foreach ($interfaceDetails as $interfaceDetail) {
            $ipv4Interface = self::normalizeRealInterface(
                (is_string($interfaceDetail['ipv4_interface'] ?? null))
                    ? $interfaceDetail['ipv4_interface']
                    : '',
            );
            $ipv6Interface = self::normalizeRealInterface(
                (is_string($interfaceDetail['ipv6_interface'] ?? null))
                    ? $interfaceDetail['ipv6_interface']
                    : '',
            );
            $ipv4Target = self::normalizeTargetAddress(
                (is_string($interfaceDetail['ipv4_target'] ?? null))
                    ? $interfaceDetail['ipv4_target']
                    : '',
                FILTER_FLAG_IPV4,
            );
            $ipv6Target = self::normalizeTargetAddress(
                (is_string($interfaceDetail['ipv6_target'] ?? null))
                    ? $interfaceDetail['ipv6_target']
                    : '',
                FILTER_FLAG_IPV6,
            );

            if ($ipv6Target === '::1') {
                $ipv6Target = '';
            }

            if ($ipv4Target === '') {
                $ipv4Interface = '';
            }

            if ($ipv6Target === '') {
                $ipv6Interface = '';
            }

            $familyInterfaces = [
                'inet' => $ipv4Interface,
                'inet6' => $ipv6Interface,
            ];

            foreach ($familyInterfaces as $family => $familyInterface) {
                if ($familyInterface !== '' && count($formattedSources[$family]) > 0) {
                    $sourceText = implode(' ', $formattedSources[$family]);
                    $rules[] = 'no rdr on '
                        . $familyInterface
                        . ' '
                        . $family
                        . ' proto { tcp udp } from { '
                        . $sourceText
                        . ' } to any port 53';
                }
            }

            foreach ($familyInterfaces as $family => $familyInterface) {
                if ($familyInterface !== '' && count($formattedDestinations[$family]) > 0) {
                    $destinationText = implode(' ', $formattedDestinations[$family]);
                    $rules[] = 'no rdr on '
                        . $familyInterface
                        . ' '
                        . $family
                        . ' proto { tcp udp } from any to { '
                        . $destinationText
                        . ' } port 53';
                }
            }

            if ($ipv4Interface !== '') {
                $rules[] = 'rdr pass on '
                    . $ipv4Interface
                    . ' inet proto { tcp udp } from any to ! ('
                    . $ipv4Interface
                    . ') port 53 -> '
                    . $ipv4Target
                    . ' port 53';
            }

            if ($ipv6Interface !== '') {
                $rules[] = 'rdr pass on '
                    . $ipv6Interface
                    . ' inet6 proto { tcp udp } from any to ! ('
                    . $ipv6Interface
                    . ') port 53 -> '
                    . $ipv6Target
                    . ' port 53';
            }
        }

        if (count($rules) === 0) {
            return '';
        }

        return '# Sinkhole DNS redirect' . PHP_EOL
            . implode(PHP_EOL, $rules)
            . PHP_EOL;
    }

    /**
     * Redirect Configuration - Partition Exemptions.
     *
     * Keeps valid normalized values, original display values, and repair reasons
     * together for one source or destination list.
     *
     * @param mixed $value - Persisted exemption list.
     * @param array<string, string> $aliases - Existing host and network aliases.
     * @param string $pluralFieldKey - Plural field catalog key.
     * @param string $singularFieldKey - Singular field catalog key.
     * @param string $kind - Exemption kind used in validation messages.
     *
     * @return array{
     *     values: list<string>,
     *     stored: list<string>,
     *     invalid: list<array{field: string, field_key: string, value: string, reason: string, reason_key: string, reason_arguments: array<int, scalar|null>}>
     * }
     *
     * @since 1.0.0
     * @private
     */
    private static function partitionExemptions(
        mixed $value,
        array $aliases,
        string $pluralFieldKey,
        string $singularFieldKey,
        string $kind,
    ): array {
        $values = self::unwrapItems($value);
        $result = [
            'values' => [],
            'stored' => [],
            'invalid' => [],
        ];

        if (!is_array($values)) {
            $result['stored'][] = self::displayValue($values);
            $result['invalid'][] = self::invalidValue(
                $pluralFieldKey,
                $values,
                new ValidationException(match ($kind) {
                    'source' => 'saved_exempt_sources_invalid',
                    'destination' => 'saved_exempt_destinations_invalid',
                }),
            );

            return $result;
        }

        $normalizedValues = [];
        foreach (array_values($values) as $item) {
            $result['stored'][] = self::displayValue($item);

            try {
                if (!is_string($item)) {
                    throw new ValidationException(match ($kind) {
                        'source' => 'exempt_source_invalid',
                        'destination' => 'exempt_destination_invalid',
                    });
                }

                $normalizedValue = self::normalizeExemption($item, $aliases, $kind);
                $normalizedValues[$normalizedValue] = true;
            } catch (ValidationException $exception) {
                $result['invalid'][] = self::invalidValue(
                    $singularFieldKey,
                    $item,
                    $exception,
                );
            }
        }

        $result['values'] = array_keys($normalizedValues);

        return $result;
    }

    /**
     * Redirect Configuration - Non-Empty Lines.
     *
     * @param string $text - Submitted textarea value.
     * @param string $errorMessageKey - Failure catalog key.
     *
     * @return list<string>
     *
     * @throws InvalidArgumentException When the text cannot be split.
     *
     * @since 1.0.0
     * @private
     */
    private static function nonEmptyLines(string $text, string $errorMessageKey): array
    {
        $lines = preg_split('/\r\n|\r|\n/', $text);

        if (!is_array($lines)) {
            throw new ValidationException($errorMessageKey);
        }

        $values = [];

        foreach ($lines as $line) {
            if (trim($line) !== '') {
                $values[] = $line;
            }
        }

        return $values;
    }

    /**
     * Redirect Configuration - Normalize Exemption.
     *
     * Canonicalizes literal addresses and CIDR text while accepting only existing,
     * pf-safe host or network alias names.
     *
     * @param string $value - Source or destination value.
     * @param array<string, string> $aliases - Existing host and network aliases.
     * @param string $kind - Human-readable exemption kind.
     *
     * @return string
     *
     * @throws InvalidArgumentException When the exemption is unsupported.
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeExemption(
        string $value,
        array $aliases,
        string $kind,
    ): string
    {
        $value = trim($value);

        if (
            $value === ''
            || strlen($value) > 128
            || preg_match('/^[\x21-\x7e]+$/D', $value) !== 1
        ) {
            throw new ValidationException(match ($kind) {
                'source' => 'exempt_source_ascii_required',
                'destination' => 'exempt_destination_ascii_required',
            });
        }

        if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
            return self::normalizeIpAddress($value, $kind);
        }

        $cidrParts = explode('/', $value);

        if (count($cidrParts) === 2 && ctype_digit($cidrParts[1])) {
            $packed = (filter_var($cidrParts[0], FILTER_VALIDATE_IP) === false)
                ? false
                : inet_pton($cidrParts[0]);
            $maximumPrefix = (is_string($packed)) ? strlen($packed) * 8 : -1;
            $prefix = (int) $cidrParts[1];

            if (is_string($packed) && $prefix <= $maximumPrefix) {
                return self::normalizeIpAddress($cidrParts[0], $kind) . '/' . $prefix;
            }
        }

        if (
            isset($aliases[$value])
            && in_array($aliases[$value], ['host', 'network'], true)
            && preg_match('/^[A-Za-z0-9_]{1,31}$/D', $value) === 1
            && preg_match('/^(?:[0-9]+|_+)$/D', $value) !== 1
        ) {
            return $value;
        }

        throw new ValidationException(match ($kind) {
            'source' => 'exempt_source_value_invalid',
            'destination' => 'exempt_destination_value_invalid',
        });
    }

    /**
     * Redirect Configuration - Normalize Target Address.
     *
     * Invalid or wrong-family targets suppress their rule instead of reaching pf.
     *
     * @param string $value - Resolver listener target.
     * @param int $familyFlag - PHP address-family validation flag.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeTargetAddress(string $value, int $familyFlag): string
    {
        if (filter_var($value, FILTER_VALIDATE_IP, $familyFlag) === false) {
            return '';
        }

        $packed = inet_pton($value);
        $normalized = ($packed === false) ? false : inet_ntop($packed);

        return ($normalized === false) ? '' : strtolower($normalized);
    }

    /**
     * Redirect Configuration - Normalize IP Address.
     *
     * Uses PHP's binary address functions to produce one canonical rule token.
     *
     * @param string $value - Address value.
     * @param string $kind - Human-readable exemption kind.
     *
     * @return string
     *
     * @throws InvalidArgumentException When conversion fails.
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeIpAddress(string $value, string $kind): string
    {
        $packed = inet_pton($value);
        $normalized = ($packed === false) ? false : inet_ntop($packed);

        if ($normalized === false) {
            throw new ValidationException(match ($kind) {
                'source' => 'exempt_source_address_invalid',
                'destination' => 'exempt_destination_address_invalid',
            });
        }

        return strtolower($normalized);
    }

    /**
     * Redirect Configuration - Normalize Real Interface.
     *
     * Rejects every metacharacter that could escape an interface token in pf text.
     * An empty value means the selected interface has no address in that family.
     *
     * @param string $value - Real interface name.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function normalizeRealInterface(string $value): string
    {
        if ($value === '') {
            return '';
        }

        if (preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/D', $value) !== 1) {
            return '';
        }

        return $value;
    }

    /**
     * Redirect Configuration - Unwrap Items.
     *
     * Accepts pfSense's repeated ``item`` wrapper and direct list input without
     * accepting any other named-child shape.
     *
     * @param mixed $value - Stored values.
     *
     * @return mixed
     *
     * @since 1.0.0
     * @private
     */
    private static function unwrapItems(mixed $value): mixed
    {
        return ScopeConfiguration::unwrapRepeatedItems($value);
    }

    /**
     * Redirect Configuration - Invalid Value.
     *
     * Bounds a scalar representation for safe repair-table rendering while keeping
     * the original configuration untouched until a valid save replaces it.
     *
     * @param string $fieldKey - Field catalog key.
     * @param mixed $value - Original value.
     * @param ValidationException $exception - Validation failure.
     *
     * @return array{field: string, field_key: string, value: string, reason: string, reason_key: string, reason_arguments: array<int, scalar|null>}
     *
     * @since 1.0.0
     * @private
     */
    private static function invalidValue(
        string $fieldKey,
        mixed $value,
        ValidationException $exception,
    ): array
    {
        return [
            'field' => $fieldKey,
            'field_key' => $fieldKey,
            'value' => self::displayValue($value),
            'reason' => $exception->getMessage(),
            'reason_key' => $exception->messageKey(),
            'reason_arguments' => $exception->messageArguments(),
        ];
    }

    /**
     * Redirect Configuration - Display Value.
     *
     * Converts malformed scalar or structured input to bounded text for the WebGUI.
     *
     * @param mixed $value - Original value.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private static function displayValue(mixed $value): string
    {
        if (is_scalar($value) || $value === null) {
            return substr((string) $value, 0, 256);
        }

        $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return substr((is_string($encoded)) ? $encoded : '[invalid value]', 0, 256);
    }
}
