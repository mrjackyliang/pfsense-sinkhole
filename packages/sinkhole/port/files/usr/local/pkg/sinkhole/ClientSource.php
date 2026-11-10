<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

/**
 * Client Source.
 *
 * Supplies local pfSense interface, neighbor, lease, and static-mapping data to the
 * client map builder without permitting DNS or network lookups.
 *
 * @since 1.0.0
 */
interface ClientSource
{
    /**
     * Client Source - Networks.
     *
     * @return array<string, array>
     *
     * @since 1.0.0
     */
    public function getNetworks(): array;

    /**
     * Client Source - Devices.
     *
     * @return array<string, array>
     *
     * @since 1.0.0
     */
    public function getDevices(): array;

    /**
     * Client Source - Interface Subnets.
     *
     * @return array<string, list<string>>
     *
     * @since 1.0.0
     */
    public function getInterfaceSubnets(): array;

    /**
     * Client Source - Interface Addresses.
     *
     * @return array<string, list<string>>
     *
     * @since 1.0.0
     */
    public function getInterfaceAddresses(): array;

    /**
     * Client Source - Bypass Interfaces.
     *
     * Returns the validated logical interfaces selected by the shared Bypass page
     * control. The client map resolves them through the same subnet snapshot used
     * for network scopes.
     *
     * @return list<string>
     *
     * @since 1.0.0
     */
    public function getBypassInterfaces(): array;

    /**
     * Client Source - Static Mappings.
     *
     * @return list<array>
     *
     * @since 1.0.0
     */
    public function getStaticMappings(): array;

    /**
     * Client Source - ARP Entries.
     *
     * @return list<array>
     *
     * @since 1.0.0
     */
    public function getArpEntries(): array;

    /**
     * Client Source - NDP Output.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function getNdpOutput(): string;

    /**
     * Client Source - DHCP Leases.
     *
     * @return array
     *
     * @since 1.0.0
     */
    public function getDhcpLeases(): array;

    /**
     * Client Source - DHCP Lease Context.
     *
     * Mirrors pfSense's translated state labels and whether its lease helper
     * converted ISC timestamps from GMT to the firewall's local time.
     *
     * @return array{
     *     times_local: bool,
     *     active: string,
     *     expired: string,
     *     reserved: string,
     *     never: string
     * }
     *
     * @since 1.0.0
     */
    public function getDhcpLeaseContext(): array;

    /**
     * Client Source - Uses Memory File System.
     *
     * @return bool
     *
     * @since 1.0.0
     */
    public function usesMemoryFileSystem(): bool;

    /**
     * Client Source - Log.
     *
     * @param string $message - Message.
     *
     * @return void
     *
     * @since 1.0.0
     */
    public function log(string $message): void;
}
