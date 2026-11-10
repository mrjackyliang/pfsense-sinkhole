<?php

declare(strict_types=1);

/**
 * Stub PID-file validation calls.
 *
 * @var list<string>
 *
 * @since 1.0.0
 */
$sinkholeStubValidPidFiles = [];

/** @var array<string, string> @since 1.0.0 */
$sinkholeStubInterfaces = [];

/** @var array<string, array{ipv4?: string, ipv4_prefix?: int, ipv6?: string, ipv6_prefix?: int}> @since 1.0.0 */
$sinkholeStubInterfaceAddresses = [];

/** @var array<string, string|array<string, string>> @since 1.0.0 */
$sinkholeStubRealInterfaces = [];

/** @var list<array> @since 1.0.0 */
$sinkholeStubArpEntries = [];

/** @var array @since 1.0.0 */
$sinkholeStubDhcpLeases = [];

/** @var list<bool> @since 1.0.0 */
$sinkholeStubDhcpLeaseArguments = [];

/** @var string @since 1.0.0 */
$sinkholeStubDhcpBackend = 'isc';

/** @return bool @since 1.0.0 */
function dhcp_is_backend(string $backend): bool
{
    global $sinkholeStubDhcpBackend;

    return $sinkholeStubDhcpBackend === $backend;
}

/**
 * Sinkhole Stub - Is Valid PID.
 *
 * Models pfSense's file-path API by reading the PID from the supplied file.
 *
 * @param string $pidFile - PID file path.
 *
 * @return bool
 *
 * @since 1.0.0
 */
function isvalidpid(string $pidFile): bool
{
    global $sinkholeStubValidPidFiles;

    $sinkholeStubValidPidFiles[] = $pidFile;
    $contents = @file_get_contents($pidFile);

    return is_string($contents)
        && ctype_digit(trim($contents))
        && (int) trim($contents) > 0;
}

/** @return array<string, string> @since 1.0.0 */
function get_configured_interface_with_descr(bool $includeDisabled = false): array
{
    global $sinkholeStubInterfaces;
    unset($includeDisabled);

    return $sinkholeStubInterfaces;
}

/** @return string|false @since 1.0.0 */
function get_interface_ip(string $interface): string|false
{
    global $sinkholeStubInterfaceAddresses;

    return $sinkholeStubInterfaceAddresses[$interface]['ipv4'] ?? false;
}

/** @return int|false @since 1.0.0 */
function get_interface_subnet(string $interface): int|false
{
    global $sinkholeStubInterfaceAddresses;

    return $sinkholeStubInterfaceAddresses[$interface]['ipv4_prefix'] ?? false;
}

/** @return string|false @since 1.0.0 */
function get_interface_ipv6(string $interface): string|false
{
    global $sinkholeStubInterfaceAddresses;

    return $sinkholeStubInterfaceAddresses[$interface]['ipv6'] ?? false;
}

/** @return int|false @since 1.0.0 */
function get_interface_subnetv6(string $interface): int|false
{
    global $sinkholeStubInterfaceAddresses;

    return $sinkholeStubInterfaceAddresses[$interface]['ipv6_prefix'] ?? false;
}

/** @return string|false @since 1.0.0 */
function get_real_interface(
    string $interface = 'wan',
    string $family = 'all',
    bool $realIpv6Interface = false,
    bool $flush = false,
): string|false {
    global $sinkholeStubRealInterfaces;
    unset($realIpv6Interface, $flush);

    $value = $sinkholeStubRealInterfaces[$interface] ?? $interface;

    if (is_string($value)) {
        return $value;
    }

    return $value[$family] ?? $value['all'] ?? false;
}

/** @return list<array> @since 1.0.0 */
function system_get_arp_table(): array
{
    global $sinkholeStubArpEntries;

    return $sinkholeStubArpEntries;
}

/** @return array @since 1.0.0 */
function system_get_dhcpleases(?bool $dnsAvailable = null): array
{
    global $sinkholeStubDhcpLeaseArguments;
    global $sinkholeStubDhcpLeases;

    if ($dnsAvailable !== false) {
        throw new RuntimeException('system_get_dhcpleases() must receive false.');
    }

    $sinkholeStubDhcpLeaseArguments[] = $dnsAvailable;

    return $sinkholeStubDhcpLeases;
}
