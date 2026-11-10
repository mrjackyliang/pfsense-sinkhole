<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

/**
 * Sinkhole Stub - Execute Command.
 *
 * Captures fixed pfctl state reads while leaving unrelated native command tests
 * on PHP's real execution boundary.
 *
 * @param string                  $command    - Fixed command.
 * @param array<int, string>|null $output     - Captured output lines.
 * @param int|null                $resultCode - Command exit code.
 *
 * @return string|false
 *
 * @since 1.0.0
 */
function exec(
    string $command,
    ?array &$output = null,
    ?int &$resultCode = null,
): string|false {
    global $sinkholeStubCommands;
    global $sinkholeStubExecOutputs;
    global $sinkholeStubExecStatuses;
    global $sinkholeStubBypassAnchorLoaded;
    global $sinkholeStubIpAnchorLoaded;

    $rulesCommand = '/sbin/pfctl -a \'sinkhole/ip\' -sr 2>/dev/null';
    $tablesCommand = '/sbin/pfctl -a \'sinkhole/ip\' -sT 2>/dev/null';
    $bypassRulesCommand = '/sbin/pfctl -a \'sinkhole/bypass\' -sr 2>/dev/null';
    $bypassTablesCommand = '/sbin/pfctl -a \'sinkhole/bypass\' -sT 2>/dev/null';
    $parentAnchorsCommand = '/sbin/pfctl -a \'sinkhole\' -sA 2>/dev/null';
    $rootAnchorsCommand = '/sbin/pfctl -sA 2>/dev/null';
    $stateCommands = [
        $rulesCommand,
        $tablesCommand,
        $bypassRulesCommand,
        $bypassTablesCommand,
        $parentAnchorsCommand,
        $rootAnchorsCommand,
    ];

    if (in_array($command, $stateCommands, true) === false) {
        return \exec($command, $output, $resultCode);
    }

    $sinkholeStubCommands[] = $command;
    $commandOutput = $sinkholeStubExecOutputs[$command] ?? null;

    if (!is_array($commandOutput)) {
        if ($command === $rulesCommand && $sinkholeStubIpAnchorLoaded === true) {
                $commandOutput = [
                    'block drop in quick on igc0 from any to <sinkhole_block_v4>',
                ];
        } elseif ($command === $tablesCommand && $sinkholeStubIpAnchorLoaded === true) {
                $commandOutput = ['sinkhole_block_v4', 'sinkhole_block_v6'];
        } elseif ($command === $bypassRulesCommand && $sinkholeStubBypassAnchorLoaded === true) {
            $commandOutput = [
                'block drop in quick on igc0 inet proto tcp from any to ! (self) port 853',
            ];
        } elseif ($command === $bypassTablesCommand && $sinkholeStubBypassAnchorLoaded === true) {
            $commandOutput = ['sinkhole_bypass_v4', 'sinkhole_bypass_v6'];
        } elseif ($command === $parentAnchorsCommand || $command === $rootAnchorsCommand) {
            $commandOutput = [];

            if ($sinkholeStubIpAnchorLoaded === true) {
                $commandOutput[] = 'sinkhole/ip';
            }

            if ($sinkholeStubBypassAnchorLoaded === true) {
                $commandOutput[] = 'sinkhole/bypass';
            }
        } else {
            $commandOutput = [];
        }
    }

    $commandStatus = $sinkholeStubExecStatuses[$command]
        ?? (($commandOutput !== []) ? 0 : 1);
    $output ??= [];

    foreach ($commandOutput as $commandOutputLine) {
        $output[] = $commandOutputLine;
    }

    $resultCode = $commandStatus;

    if (count($commandOutput) === 0) {
        return '';
    }

    return $commandOutput[array_key_last($commandOutput)];
}
