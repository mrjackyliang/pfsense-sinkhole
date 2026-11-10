<?php

declare(strict_types=1);

/**
 * Sinkhole Stub - Return Gateways Array.
 *
 * Records the inclusion flags and returns invented resolved runtime gateways to
 * adapter tests without loading pfSense's gateway implementation.
 *
 * @param bool $disabled - Whether disabled gateways are included.
 * @param bool $localhost - Whether localhost placeholders are included.
 * @param bool $inactive - Whether inactive gateways are included.
 *
 * @return array<string|int, array<string, mixed>>
 *
 * @since 1.0.0
 */
function return_gateways_array(
    bool $disabled = false,
    bool $localhost = false,
    bool $inactive = false,
): array {
    global $sinkholeStubGatewayArguments;
    global $sinkholeStubGatewayRows;

    $sinkholeStubGatewayArguments[] = [
        'disabled' => $disabled,
        'localhost' => $localhost,
        'inactive' => $inactive,
    ];

    return $sinkholeStubGatewayRows;
}
