<?php

declare(strict_types=1);

/**
 * Sinkhole Stub - Get Dynamic Nameservers.
 *
 * Records the interface filter and returns invented dynamically learned servers
 * without reading pfSense runtime files.
 *
 * @param string $interface - Optional interface filter.
 *
 * @return list<mixed>
 *
 * @since 1.0.0
 */
function get_dynamic_nameservers(string $interface = ''): array
{
    global $sinkholeStubDynamicNameserverArguments;
    global $sinkholeStubDynamicNameservers;

    $sinkholeStubDynamicNameserverArguments[] = $interface;

    return $sinkholeStubDynamicNameservers;
}
