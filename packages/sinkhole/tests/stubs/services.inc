<?php

declare(strict_types=1);

/**
 * Sinkhole Stub - Configure Cron.
 *
 * @return void
 *
 * @since 1.2.3
 */
function configure_cron(): void
{
    global $sinkholeStubConfigureCronCount;

    $sinkholeStubConfigureCronCount++;
}

/**
 * Sinkhole Stub - Configure Unbound.
 *
 * @return void
 *
 * @since 1.0.0
 */
function services_unbound_configure(): void
{
    global $sinkholeStubUnboundConfigureCount;

    $sinkholeStubUnboundConfigureCount++;
}

/**
 * Sinkhole Stub - Configure Filter.
 *
 * @return void
 *
 * @since 1.0.0
 */
function filter_configure(): void
{
    global $sinkholeStubFilterConfigureCount;
    global $sinkholeStubOperations;

    $sinkholeStubFilterConfigureCount++;
    $sinkholeStubOperations[] = [
        'type' => 'filter_reload',
    ];
}
