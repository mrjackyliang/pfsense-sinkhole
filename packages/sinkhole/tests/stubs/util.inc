<?php

declare(strict_types=1);

/**
 * Stub running processes.
 *
 * @var array<string, bool>
 *
 * @since 1.0.0
 */
$sinkholeStubRunningProcesses = [
    'unbound' => true,
];

/**
 * Stub dirty subsystems.
 *
 * @var array<string, bool>
 *
 * @since 1.0.0
 */
$sinkholeStubDirtySubsystems = [];

/**
 * Sinkhole Stub - Is Process Running.
 *
 * Models pfSense's fixed-name process lookup for Resolver-aware redirect rules.
 *
 * @param string $process - Process name.
 *
 * @return bool
 *
 * @since 1.0.0
 */
function is_process_running(string $process): bool
{
    global $sinkholeStubRunningProcesses;

    return ($sinkholeStubRunningProcesses[$process] ?? false) === true;
}

/**
 * Sinkhole Stub - Is Subsystem Dirty.
 *
 * @param string $subsystem - pfSense subsystem name.
 *
 * @return bool
 *
 * @since 1.0.0
 */
function is_subsystem_dirty(string $subsystem): bool
{
    global $sinkholeStubDirtySubsystems;

    return ($sinkholeStubDirtySubsystems[$subsystem] ?? false) === true;
}
