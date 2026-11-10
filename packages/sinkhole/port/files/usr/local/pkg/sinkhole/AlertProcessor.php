<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

use Closure;
use JsonException;
use PfSense\Sinkhole\Domain\DomainParser;
use RuntimeException;
use Throwable;

require_once(__DIR__ . '/AtomicFile.php');
require_once(__DIR__ . '/DomainParser.php');
require_once(__DIR__ . '/FileSystem.php');
require_once(__DIR__ . '/PackagePaths.php');
require_once(__DIR__ . '/StateStore.php');
require_once(__DIR__ . '/Translator.php');

/**
 * Alert Processor.
 *
 * Rotates the Unbound event file, validates every untrusted record, enforces repeat
 * and hourly limits, and delivers bounded notifications through pfSense channels.
 *
 * @since 1.0.0
 */
final class AlertProcessor
{
    /** @since 1.0.0 */
    public const MAXIMUM_EVENT_FILE_BYTES = 1048576;

    /** @since 1.0.0 */
    public const MAXIMUM_NOTIFICATIONS = 20;

    /** @since 1.0.0 */
    public const TIME_BUDGET_SECONDS = 40;

    /** @since 1.0.0 */
    public const MAXIMUM_NOTIFICATIONS_PER_RULE_PER_HOUR = 60;

    /** @since 1.0.0 */
    public const MAXIMUM_UNREAD_NOTICES = 50;

    /** @since 1.0.0 */
    public const STALE_EVENT_SECONDS = 600;

    /** @since 1.0.0 */
    private const MAXIMUM_EVENT_COUNT = 1000000;

    /** @since 1.0.0 */
    private const PROCESSING_LOCK_WAIT_SECONDS = 1.0;

    /** @since 1.0.0 */
    private const REPEAT_STATE_SCHEMA_VERSION = 2;

    /** @var Closure(string, string, string, string, int, bool): mixed @since 1.0.0 */
    private readonly Closure $noticeSender;

    /** @var Closure(string): mixed @since 1.0.0 */
    private readonly Closure $remoteSender;

    /** @var Closure(): int @since 1.0.0 */
    private readonly Closure $clock;

    /** @var Closure(): float @since 1.0.0 */
    private readonly Closure $monotonicClock;

    /** @var Closure(int): void @since 1.0.0 */
    private readonly Closure $sleeper;

    /** @var Closure(): int @since 1.0.0 */
    private readonly Closure $noticeCounter;

    /** @var Closure(): string @since 1.0.0 */
    private readonly Closure $noticeIdentifierFactory;

    /**
     * Alert Processor - Constructor.
     *
     * Optional callables make channel behavior and time deterministic in tests.
     *
     * @param PackagePaths $paths - Package paths.
     * @param StateStore $stateStore - Operational status store.
     * @param callable|null $noticeSender - WebGUI notice sender.
     * @param callable|null $remoteSender - Remote notification sender.
     * @param callable|null $clock - Epoch-second clock.
     * @param callable|null $noticeIdentifierFactory - Unique notice ID factory.
     * @param callable|null $noticeCounter - Unread Sinkhole notice counter.
     * @param callable|null $monotonicClock - Elapsed-time clock.
     * @param callable|null $sleeper - Bounded lock-wait sleeper.
     *
     * @since 1.0.0
     */
    public function __construct(
        private readonly PackagePaths $paths,
        private readonly StateStore $stateStore,
        ?callable $noticeSender = null,
        ?callable $remoteSender = null,
        ?callable $clock = null,
        ?callable $noticeIdentifierFactory = null,
        ?callable $noticeCounter = null,
        ?callable $monotonicClock = null,
        ?callable $sleeper = null,
    ) {
        $this->noticeSender = Closure::fromCallable($noticeSender ?? static function (
            string $identifier,
            string $message,
            string $category,
            string $url,
            int $priority,
            bool $localOnly,
        ): mixed {
            return file_notice($identifier, $message, $category, $url, $priority, $localOnly);
        });
        $this->remoteSender = Closure::fromCallable(
            $remoteSender ?? static fn(string $message): mixed => notify_all_remote($message),
        );
        $this->clock = Closure::fromCallable($clock ?? static fn(): int => time());
        $this->noticeIdentifierFactory = Closure::fromCallable(
            $noticeIdentifierFactory
                ?? static fn(): string => 'sinkhole-' . bin2hex(random_bytes(16)),
        );
        $this->noticeCounter = Closure::fromCallable(
            $noticeCounter ?? static function (): int {
                if (!function_exists('get_notices')) {
                    return 0;
                }

                $notices = get_notices('Sinkhole');

                return is_array($notices) ? count($notices) : 0;
            },
        );
        $this->monotonicClock = Closure::fromCallable(
            $monotonicClock ?? static fn(): float => hrtime(true) / 1_000_000_000,
        );
        $this->sleeper = Closure::fromCallable(
            $sleeper ?? static function (int $microseconds): void {
                usleep($microseconds);
            },
        );
    }

    /**
     * Alert Processor - Run.
     *
     * @param array<string, array> $rules - Current valid alert rules.
     * @param array<string, array> $lists - Current valid block lists.
     * @param array<string, array> $networks - Current valid network scopes.
     * @param array<string, array> $devices - Current valid device scopes.
     * @param array<string, string> $interfaces - Interface descriptions.
     *
     * @return array{
     *     events_read: int,
     *     events_stale: int,
     *     notifications_sent: int,
     *     notifications_held_back: int,
     *     bad_lines: int,
     *     unknown_lines: int,
     *     events_dropped: int,
     *     time_budget_exhausted: bool,
     *     error: string|null
     * }
     *
     * @since 1.0.0
     */
    public function run(
        array $rules,
        array $lists,
        array $networks,
        array $devices,
        array $interfaces,
    ): array {
        $now = ($this->clock)();
        $deadline = ($this->monotonicClock)() + self::TIME_BUDGET_SECONDS;
        $eventsRead = 0;
        $eventsStale = 0;
        $notificationsSent = 0;
        $notificationsHeldBack = 0;
        $badLines = 0;
        $unknownLines = 0;
        $timeBudgetExhausted = false;
        $errors = [];
        $dropped = $this->readDroppedCount($errors);

        try {
            $manifest = $this->readManifest();
            $repeatDocument = $this->readRepeatState($errors);
            $originalRepeatDocument = $repeatDocument;
            $repeatDocument = $this->pruneRepeatState($repeatDocument, $rules, $now);
            $batch = $this->readRotatedEvents(
                $manifest,
                $eventsRead,
                $badLines,
                $unknownLines,
                $errors,
                $deadline,
            );
            $allActionsHandled = $batch['consumable'];

            if ($batch['processing'] && !$batch['consumable']) {
                $allActionsHandled = false;
                $timeBudgetExhausted = !$this->hasTimeRemaining($deadline);
            } else {
                $candidates = $this->notificationCandidates(
                    $batch['events'],
                    $manifest,
                    $rules,
                    $lists,
                    $networks,
                    $devices,
                    $interfaces,
                    $repeatDocument['entries'],
                    $now,
                    $eventsStale,
                );
                $messages = $this->boundedMessages($candidates, $rules);
                $actions = $this->hourlyActions(
                    $messages,
                    $rules,
                    $repeatDocument['hourly'],
                    intdiv($now, 3600),
                );
                $unreadNotices = $this->unreadNoticeCount($errors);

                foreach ($actions as $action) {
                    if (!$this->hasTimeRemaining($deadline)) {
                        $timeBudgetExhausted = true;
                        $allActionsHandled = false;

                        break;
                    }

                    if ($action['type'] === 'suppress') {
                        $notificationsHeldBack += $action['held_back'];
                        $this->recordRepeatKeys(
                            $repeatDocument['entries'],
                            $action['message']['keys'],
                            $now,
                        );

                        continue;
                    }

                    $delivery = $this->deliver(
                        $action['message'],
                        $rules,
                        $errors,
                        $deadline,
                        $unreadNotices,
                    );
                    $notificationsHeldBack += $delivery['held_back'];

                    if ($delivery['budget_exhausted']) {
                        if ($delivery['delivered']) {
                            $notificationsSent++;

                            foreach ($action['hourly_updates'] as $ruleIdentifier => $hourlyState) {
                                $repeatDocument['hourly'][$ruleIdentifier] = $hourlyState;
                            }
                        }

                        $timeBudgetExhausted = true;
                        $allActionsHandled = false;

                        break;
                    }

                    if ($delivery['delivered']) {
                        $notificationsSent++;

                        foreach ($action['hourly_updates'] as $ruleIdentifier => $hourlyState) {
                            $repeatDocument['hourly'][$ruleIdentifier] = $hourlyState;
                        }
                    }

                    if ($delivery['handled']) {
                        $this->recordRepeatKeys(
                            $repeatDocument['entries'],
                            $action['message']['keys'],
                            $now,
                        );
                    }
                }

                $this->writeRepeatState($originalRepeatDocument, $repeatDocument);

                if ($batch['processing'] && $batch['consumable'] && $allActionsHandled) {
                    FileSystem::removeFixedFile($this->paths->eventsProcessingFile);
                }
            }
        } catch (Throwable $throwable) {
            $errors[] = $throwable->getMessage();
        }

        if ($badLines > 0) {
            $errors[] = Translator::translate('alert_invalid_event_lines', [$badLines]);
        }

        if ($unknownLines > 0) {
            $errors[] = Translator::translate('alert_unknown_event_identifiers', [$unknownLines]);
        }

        $lastError = count($errors) > 0
            ? implode(' ', array_values(array_unique($errors)))
            : null;
        $completedAt = gmdate('c', $now);

        try {
            $this->stateStore->recordAlertStatus(
                $completedAt,
                $eventsRead,
                $eventsStale,
                $notificationsSent,
                $notificationsHeldBack,
                $dropped,
                $lastError,
            );
        } catch (Throwable $throwable) {
            $lastError = ($lastError === null ? '' : $lastError . ' ')
                . Translator::translate('alert_status_save_failed', [
                    $throwable->getMessage(),
                ]);
        }

        return [
            'events_read' => $eventsRead,
            'events_stale' => $eventsStale,
            'notifications_sent' => $notificationsSent,
            'notifications_held_back' => $notificationsHeldBack,
            'bad_lines' => $badLines,
            'unknown_lines' => $unknownLines,
            'events_dropped' => $dropped,
            'time_budget_exhausted' => $timeBudgetExhausted,
            'error' => $lastError,
        ];
    }

    /**
     * Alert Processor - Read Manifest.
     *
     * Opens read/write so a substituted FIFO cannot block the root alert job. The
     * handle is used only for reads after its inode and type match the earlier lstat.
     *
     * @return array
     *
     * @since 1.0.0
     * @private
     */
    private function readManifest(): array
    {
        $generation = FileSystem::resolveManagedGeneration(
            $this->paths->runtimeDataDirectory,
            $this->paths->runtimeStorageDirectory,
        );

        if ($generation === null) {
            throw new RuntimeException('The current Sinkhole manifest is unavailable.');
        }

        $path = $generation . '/manifest.json';
        $before = @lstat($path);

        if (
            !is_array($before)
            || ($before['mode'] & 0170000) !== 0100000
            || $before['size'] > self::MAXIMUM_EVENT_FILE_BYTES
        ) {
            throw new RuntimeException('The current Sinkhole manifest is invalid.');
        }

        $handle = @fopen($path, 'r+b');

        if ($handle === false) {
            throw new RuntimeException('The current Sinkhole manifest is unavailable.');
        }

        try {
            $after = fstat($handle);

            if (!$this->sameRegularFile($before, $after, self::MAXIMUM_EVENT_FILE_BYTES)) {
                throw new RuntimeException('The current Sinkhole manifest changed while opening.');
            }

            $contents = stream_get_contents($handle, self::MAXIMUM_EVENT_FILE_BYTES + 1);
        } finally {
            fclose($handle);
        }

        try {
            $manifest = is_string($contents)
                ? json_decode($contents, true, 32, JSON_THROW_ON_ERROR)
                : null;
        } catch (JsonException $exception) {
            throw new RuntimeException('The current Sinkhole manifest is invalid.', 0, $exception);
        }

        if (
            !is_array($manifest)
            || !is_array($manifest['lists'] ?? null)
            || !is_array($manifest['scopes'] ?? null)
            || !is_array($manifest['scopes']['networks'] ?? null)
            || !is_array($manifest['scopes']['devices'] ?? null)
            || !is_array($manifest['alerts'] ?? null)
        ) {
            throw new RuntimeException('The current Sinkhole manifest is invalid.');
        }

        return $manifest;
    }

    /**
     * Alert Processor - Read Rotated Events.
     *
     * @param array $manifest - Current manifest.
     * @param int $eventsRead - Mutable event count.
     * @param int $badLines - Mutable malformed-line count.
     * @param int $unknownLines - Mutable unknown-ID count.
     * @param list<string> $errors - Mutable errors.
     * @param float $deadline - Monotonic run deadline.
     *
     * @return array{events: list<array>, processing: bool, consumable: bool}
     *
     * @since 1.0.0
     * @private
     */
    private function readRotatedEvents(
        array $manifest,
        int &$eventsRead,
        int &$badLines,
        int &$unknownLines,
        array &$errors,
        float $deadline,
    ): array {
        if (@lstat($this->paths->eventsProcessingFile) === false) {
            if (@lstat($this->paths->eventsFile) === false) {
                return ['events' => [], 'processing' => false, 'consumable' => true];
            }

            if (@rename($this->paths->eventsFile, $this->paths->eventsProcessingFile) === false) {
                $errors[] = 'Unable to rotate the Sinkhole event file.';

                return ['events' => [], 'processing' => false, 'consumable' => false];
            }
        }

        $processing = $this->readProcessingFile($errors, $deadline);

        if (!$processing['consumable']) {
            return ['events' => [], 'processing' => true, 'consumable' => false];
        }

        $events = [];

        foreach ($processing['lines'] as $line) {
            $eventCount = 1;
            $event = $this->decodeEvent($line, $manifest, $unknownLines, $eventCount);
            $eventsRead += $eventCount;

            if ($event === null) {
                $badLines++;

                continue;
            }

            if ($event === false) {
                continue;
            }

            $events[] = $event;
        }

        return ['events' => $events, 'processing' => true, 'consumable' => true];
    }

    /**
     * Alert Processor - Read Processing File.
     *
     * @param list<string> $errors - Mutable errors.
     * @param float $deadline - Monotonic run deadline.
     *
     * @return array{lines: list<string>, consumable: bool}
     *
     * @since 1.0.0
     * @private
     */
    private function readProcessingFile(array &$errors, float $deadline): array
    {
        $path = $this->paths->eventsProcessingFile;
        $before = @lstat($path);

        if (
            !is_array($before)
            || ($before['mode'] & 0170000) !== 0100000
            || $before['size'] > self::MAXIMUM_EVENT_FILE_BYTES
        ) {
            $errors[] = 'The rotated Sinkhole event file is unsafe or oversized.';

            return ['lines' => [], 'consumable' => true];
        }

        $handle = @fopen($path, 'r+b');

        if ($handle === false) {
            $errors[] = 'Unable to open the rotated Sinkhole event file.';

            return ['lines' => [], 'consumable' => false];
        }

        $locked = false;

        try {
            $after = fstat($handle);

            if (!$this->sameRegularFile($before, $after, self::MAXIMUM_EVENT_FILE_BYTES)) {
                $errors[] = 'The rotated Sinkhole event file changed while opening.';

                return ['lines' => [], 'consumable' => true];
            }

            $lockDeadline = min(
                $deadline,
                ($this->monotonicClock)() + self::PROCESSING_LOCK_WAIT_SECONDS,
            );

            while (!flock($handle, LOCK_EX | LOCK_NB)) {
                if (($this->monotonicClock)() >= $lockDeadline) {
                    $errors[] = 'Timed out waiting for the Sinkhole event writer.';

                    return ['lines' => [], 'consumable' => false];
                }

                ($this->sleeper)(1000);
            }

            $locked = true;
            $afterLock = fstat($handle);

            if (!$this->sameRegularFile($before, $afterLock, self::MAXIMUM_EVENT_FILE_BYTES)) {
                $errors[] = 'The rotated Sinkhole event file changed while locking.';

                return ['lines' => [], 'consumable' => true];
            }

            $lines = [];

            while (($line = fgets($handle, self::MAXIMUM_EVENT_FILE_BYTES + 1)) !== false) {
                $lines[] = $line;
            }

            if (!feof($handle)) {
                $errors[] = 'Unable to finish reading the rotated Sinkhole event file.';

                return ['lines' => [], 'consumable' => false];
            }

            return ['lines' => $lines, 'consumable' => true];
        } finally {
            if ($locked) {
                flock($handle, LOCK_UN);
            }

            fclose($handle);
        }
    }

    /**
     * Alert Processor - Decode Event.
     *
     * Null means malformed; false means well-formed but unknown to the current
     * manifest.
     *
     * @param string $line - Untrusted JSON line.
     * @param array $manifest - Current manifest.
     * @param int $unknownLines - Mutable unknown-ID count.
     * @param int $eventCount - Mutable normalized occurrence count.
     *
     * @return array|false|null
     *
     * @since 1.0.0
     * @private
     */
    private function decodeEvent(
        string $line,
        array $manifest,
        int &$unknownLines,
        int &$eventCount,
    ): array|false|null {
        try {
            $event = json_decode($line, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!is_array($event)) {
            return null;
        }

        $count = $event['count'] ?? 1;

        if (!is_int($count) || $count < 1 || $count > self::MAXIMUM_EVENT_COUNT) {
            return null;
        }

        $eventCount = $count;
        $name = is_string($event['name'] ?? null)
            ? DomainParser::normalizeDomain($event['name'])
            : null;
        $cname = $event['cname'] ?? null;
        $client = $event['client'] ?? null;
        $device = $event['device'] ?? null;
        $network = $event['network'] ?? null;

        if (
            !is_int($event['t'] ?? null)
            || $event['t'] < 0
            || !is_string($client)
            || filter_var($client, FILTER_VALIDATE_IP) === false
            || $name === null
            || ($cname !== null && (!is_string($cname) || DomainParser::normalizeDomain($cname) === null))
            || ($device !== null && !is_string($device))
            || ($network !== null && !is_string($network))
            || !is_array($event['rules'] ?? null)
            || !array_is_list($event['rules'])
            || !is_array($event['lists'] ?? null)
            || !array_is_list($event['lists'])
        ) {
            return null;
        }

        if (is_string($cname)) {
            $cname = DomainParser::normalizeDomain($cname);

            if ($cname === $name) {
                $cname = null;
            }
        }

        $knownLists = [];

        foreach ($event['lists'] as $identifier) {
            if (!is_string($identifier)) {
                return null;
            }

            if (isset($manifest['lists'][$identifier])) {
                $knownLists[$identifier] = true;
            }
        }

        $knownRules = [];

        foreach ($event['rules'] as $identifier) {
            if (!is_string($identifier)) {
                return null;
            }

            if (isset($manifest['alerts'][$identifier])) {
                $knownRules[$identifier] = true;
            }
        }

        $deviceKnown = $device === null || isset($manifest['scopes']['devices'][$device]);
        $networkKnown = $network === null || isset($manifest['scopes']['networks'][$network]);

        if (
            count($knownLists) === 0
            || count($knownRules) === 0
            || !$deviceKnown
            || !$networkKnown
        ) {
            $unknownLines++;

            return false;
        }

        return [
            't' => $event['t'],
            'count' => $count,
            'client' => $client,
            'device' => $device,
            'network' => $network,
            'name' => $name,
            'cname' => $cname,
            'rules' => array_keys($knownRules),
            'lists' => array_keys($knownLists),
        ];
    }

    /**
     * Alert Processor - Notification Candidates.
     *
     * @param int $eventsStale - Mutable stale occurrence count.
     *
     * @return list<array{rule: string, text: string, key: array, block_count: int}>
     *
     * @since 1.0.0
     * @private
     */
    private function notificationCandidates(
        array $events,
        array $manifest,
        array $rules,
        array $lists,
        array $networks,
        array $devices,
        array $interfaces,
        array $repeatState,
        int $now,
        int &$eventsStale,
    ): array {
        $candidates = [];
        $candidateIndexes = [];

        foreach ($events as $event) {
            if ($event['t'] < $now - self::STALE_EVENT_SECONDS) {
                $eventsStale += $event['count'];

                continue;
            }

            foreach ($event['rules'] as $ruleIdentifier) {
                $rule = $rules[$ruleIdentifier] ?? null;

                if (!is_array($rule) || ($rule['enabled'] ?? false) !== true) {
                    continue;
                }

                $clientKey = is_string($event['device']) ? $event['device'] : $event['client'];
                $flatKey = $ruleIdentifier . "\0" . $clientKey . "\0" . $event['name'];
                $lastSent = $repeatState[$ruleIdentifier][$clientKey][$event['name']] ?? null;
                $window = (int) ($rule['repeat_minutes'] ?? 60) * 60;

                if (is_int($lastSent) && $lastSent > $now - $window) {
                    continue;
                }

                if (isset($candidateIndexes[$flatKey])) {
                    $index = $candidateIndexes[$flatKey];
                    $candidates[$index]['block_count'] += $event['count'];
                    $candidates[$index]['key']['count'] += $event['count'];

                    continue;
                }

                $listIdentifier = $this->messageListIdentifier(
                    $event['lists'],
                    $manifest['alerts'][$ruleIdentifier],
                    $manifest['lists'],
                );

                if ($listIdentifier === null || !isset($lists[$listIdentifier])) {
                    continue;
                }

                $candidateIndexes[$flatKey] = count($candidates);
                $candidates[] = [
                    'rule' => $ruleIdentifier,
                    'text' => $this->detailMessage(
                        $event,
                        $rule,
                        $lists[$listIdentifier],
                        $networks,
                        $devices,
                        $interfaces,
                    ),
                    'key' => [
                        'rule' => $ruleIdentifier,
                        'client' => $clientKey,
                        'name' => $event['name'],
                        'count' => $event['count'],
                    ],
                    'block_count' => $event['count'],
                ];
            }
        }

        return $candidates;
    }

    /**
     * Alert Processor - Message List Identifier.
     *
     * @return string|null
     *
     * @since 1.0.0
     * @private
     */
    private function messageListIdentifier(array $eventLists, array $manifestRule, array $manifestLists): ?string
    {
        $selection = $manifestRule['lists'] ?? [];

        foreach ($eventLists as $identifier) {
            if (!isset($manifestLists[$identifier])) {
                continue;
            }

            if ($selection === 'any') {
                return $identifier;
            }

            $bit = $manifestLists[$identifier]['bit'] ?? null;

            if (is_int($bit) && is_array($selection) && in_array($bit, $selection, true)) {
                return $identifier;
            }
        }

        return null;
    }

    /**
     * Alert Processor - Detail Message.
     *
     * Network labels come only from current configuration. A manifest identifier
     * absent from configuration is never reflected into notification text.
     *
     * @return string
     *
     * @since 1.0.0
     * @private
     */
    private function detailMessage(
        array $event,
        array $rule,
        array $list,
        array $networks,
        array $devices,
        array $interfaces,
    ): string {
        $clientDescription = $event['client'];

        if (is_string($event['device']) && isset($devices[$event['device']])) {
            $clientDescription = (string) ($devices[$event['device']]['name'] ?? $event['client']);
        }

        $networkDescription = Translator::translate('unknown_network');

        if (is_string($event['network']) && isset($networks[$event['network']])) {
            $interface = $networks[$event['network']]['interface'] ?? null;

            if (is_string($interface) && isset($interfaces[$interface])) {
                $networkDescription = $interfaces[$interface];
            }
        }

        $arguments = [
            $event['name'],
            $clientDescription,
            $networkDescription,
            (string) ($list['name'] ?? ''),
            (string) ($rule['description'] ?? ''),
        ];

        if (is_string($event['cname'])) {
            array_splice($arguments, 1, 0, [$event['cname']]);

            return Translator::translate('alert_detail_cname', $arguments);
        }

        return Translator::translate('alert_detail_direct', $arguments);
    }

    /**
     * Alert Processor - Bounded Messages.
     *
     * @return list<array{rules: list<string>, text: string, keys: list<array>, block_count: int}>
     *
     * @since 1.0.0
     * @private
     */
    private function boundedMessages(array $candidates, array $rules): array
    {
        if (count($candidates) <= self::MAXIMUM_NOTIFICATIONS) {
            return array_map(static fn(array $candidate): array => [
                'rules' => [$candidate['rule']],
                'text' => $candidate['text'],
                'keys' => [$candidate['key']],
                'block_count' => $candidate['block_count'],
            ], $candidates);
        }

        $detailCount = self::MAXIMUM_NOTIFICATIONS - 1;
        $summaryGroups = [];
        $perRuleSummariesFit = false;

        while ($detailCount >= 0) {
            $summaryGroups = [];

            foreach (array_slice($candidates, $detailCount) as $candidate) {
                $summaryGroups[$candidate['rule']][] = $candidate;
            }

            if ($detailCount + count($summaryGroups) <= self::MAXIMUM_NOTIFICATIONS) {
                $perRuleSummariesFit = true;

                break;
            }

            $detailCount--;
        }

        if (!$perRuleSummariesFit) {
            $detailCount = self::MAXIMUM_NOTIFICATIONS - 1;
        }

        $messages = [];

        foreach (array_slice($candidates, 0, $detailCount) as $candidate) {
            $messages[] = [
                'rules' => [$candidate['rule']],
                'text' => $candidate['text'],
                'keys' => [$candidate['key']],
                'block_count' => $candidate['block_count'],
            ];
        }

        if ($perRuleSummariesFit) {
            foreach ($summaryGroups as $ruleIdentifier => $group) {
                $keys = array_column($group, 'key');
                $blockCount = array_sum(array_column($group, 'block_count'));
                $description = (string) ($rules[$ruleIdentifier]['description'] ?? $ruleIdentifier);
                $messages[] = [
                    'rules' => [$ruleIdentifier],
                    'text' => Translator::translate('alert_minute_rule_summary', [
                        $blockCount,
                        $description,
                    ]),
                    'keys' => $keys,
                    'block_count' => $blockCount,
                ];
            }

            return $messages;
        }

        $overflow = array_slice($candidates, $detailCount);
        $overflowRules = [];
        $overflowKeys = [];
        $overflowCount = 0;

        foreach ($overflow as $candidate) {
            $overflowRules[$candidate['rule']] = true;
            $overflowKeys[] = $candidate['key'];
            $overflowCount += $candidate['block_count'];
        }

        $messages[] = [
            'rules' => array_keys($overflowRules),
            'text' => Translator::translate('alert_minute_cross_rule_summary', [
                $overflowCount,
                count($overflowRules),
            ]),
            'keys' => $overflowKeys,
            'block_count' => $overflowCount,
        ];

        return $messages;
    }

    /**
     * Alert Processor - Hourly Actions.
     *
     * The sixtieth slot is reserved for an hourly overflow summary. This keeps the
     * strict per-rule total at no more than sixty notifications, including summary.
     *
     * @return list<array{type: string, message: array, hourly_updates: array, held_back: int}>
     *
     * @since 1.0.0
     * @private
     */
    private function hourlyActions(
        array $messages,
        array $rules,
        array $hourlyState,
        int $hour,
    ): array {
        $actions = [];
        $working = $hourlyState;
        $consumed = [];
        $detailLimit = self::MAXIMUM_NOTIFICATIONS_PER_RULE_PER_HOUR - 1;

        foreach ($messages as $index => $message) {
            if (isset($consumed[$index])) {
                continue;
            }

            if (count($message['rules']) !== 1) {
                $updates = [];
                $allowed = true;

                foreach ($message['rules'] as $ruleIdentifier) {
                    $entry = $this->hourlyEntry($working, $ruleIdentifier, $hour);

                    if (
                        $entry['summary_sent']
                        || $entry['sent'] >= self::MAXIMUM_NOTIFICATIONS_PER_RULE_PER_HOUR
                    ) {
                        $allowed = false;

                        break;
                    }

                    $entry['sent']++;

                    if ($entry['sent'] >= self::MAXIMUM_NOTIFICATIONS_PER_RULE_PER_HOUR) {
                        $entry['summary_sent'] = true;
                    }

                    $updates[$ruleIdentifier] = $entry;
                }

                if (!$allowed) {
                    $actions[] = [
                        'type' => 'suppress',
                        'message' => $message,
                        'hourly_updates' => [],
                        'held_back' => 1,
                    ];

                    continue;
                }

                foreach ($updates as $ruleIdentifier => $entry) {
                    $working[$ruleIdentifier] = $entry;
                }

                $actions[] = [
                    'type' => 'send',
                    'message' => $message,
                    'hourly_updates' => $updates,
                    'held_back' => 0,
                ];

                continue;
            }

            $ruleIdentifier = $message['rules'][0];
            $entry = $this->hourlyEntry($working, $ruleIdentifier, $hour);

            if (
                $entry['summary_sent']
                || $entry['sent'] >= self::MAXIMUM_NOTIFICATIONS_PER_RULE_PER_HOUR
            ) {
                $actions[] = [
                    'type' => 'suppress',
                    'message' => $message,
                    'hourly_updates' => [],
                    'held_back' => 1,
                ];

                continue;
            }

            if ($entry['sent'] < $detailLimit) {
                $entry['sent']++;
                $working[$ruleIdentifier] = $entry;
                $actions[] = [
                    'type' => 'send',
                    'message' => $message,
                    'hourly_updates' => [$ruleIdentifier => $entry],
                    'held_back' => 0,
                ];

                continue;
            }

            $summaryKeys = [];
            $summaryCount = 0;

            foreach ($messages as $summaryIndex => $summaryMessage) {
                if (
                    $summaryIndex < $index
                    || isset($consumed[$summaryIndex])
                    || $summaryMessage['rules'] !== [$ruleIdentifier]
                ) {
                    continue;
                }

                $consumed[$summaryIndex] = true;
                array_push($summaryKeys, ...$summaryMessage['keys']);
                $summaryCount += $summaryMessage['block_count'];
            }

            $description = (string) ($rules[$ruleIdentifier]['description'] ?? $ruleIdentifier);
            $summary = [
                'rules' => [$ruleIdentifier],
                'text' => Translator::translate('alert_hourly_rule_summary', [
                    $summaryCount,
                    $description,
                ]),
                'keys' => $summaryKeys,
                'block_count' => $summaryCount,
            ];
            $entry['sent'] = self::MAXIMUM_NOTIFICATIONS_PER_RULE_PER_HOUR;
            $entry['summary_sent'] = true;
            $working[$ruleIdentifier] = $entry;
            $actions[] = [
                'type' => 'send',
                'message' => $summary,
                'hourly_updates' => [$ruleIdentifier => $entry],
                'held_back' => 0,
            ];
        }

        return $actions;
    }

    /**
     * Alert Processor - Hourly Entry.
     *
     * @return array{hour: int, sent: int, summary_sent: bool}
     *
     * @since 1.0.0
     * @private
     */
    private function hourlyEntry(array $hourlyState, string $ruleIdentifier, int $hour): array
    {
        $entry = $hourlyState[$ruleIdentifier] ?? null;

        if (!is_array($entry) || ($entry['hour'] ?? null) !== $hour) {
            return ['hour' => $hour, 'sent' => 0, 'summary_sent' => false];
        }

        return $entry;
    }

    /**
     * Alert Processor - Deliver.
     *
     * @param array $message - Bounded notification message.
     * @param array<string, array> $rules - Current valid alert rules.
     * @param list<string> $errors - Mutable errors.
     * @param float $deadline - Monotonic run deadline.
     * @param int $unreadNotices - Mutable unread Sinkhole notice count.
     *
     * @return array{delivered: bool, handled: bool, held_back: int, budget_exhausted: bool}
     *
     * @since 1.0.0
     * @private
     */
    private function deliver(
        array $message,
        array $rules,
        array &$errors,
        float $deadline,
        int &$unreadNotices,
    ): array {
        $notice = false;
        $remote = false;

        foreach ($message['rules'] as $ruleIdentifier) {
            $rule = $rules[$ruleIdentifier] ?? null;

            if (!is_array($rule)) {
                continue;
            }

            $notice = $notice || ($rule['notice'] ?? false) === true;
            $remote = $remote || ($rule['remote'] ?? false) === true;
        }

        $delivered = false;
        $handled = false;
        $heldBack = 0;

        if ($notice) {
            if (!$this->hasTimeRemaining($deadline)) {
                return [
                    'delivered' => false,
                    'handled' => false,
                    'held_back' => 0,
                    'budget_exhausted' => true,
                ];
            }

            if ($unreadNotices >= self::MAXIMUM_UNREAD_NOTICES) {
                $heldBack++;
                $handled = true;
            } else {
                try {
                    ($this->noticeSender)(
                        ($this->noticeIdentifierFactory)(),
                        $message['text'],
                        'Sinkhole',
                        '/sinkhole-alerts.php',
                        1,
                        true,
                    );
                    $unreadNotices++;
                    $delivered = true;
                    $handled = true;
                } catch (Throwable $throwable) {
                    $errors[] = 'WebGUI notice failed: ' . $throwable->getMessage();
                }
            }
        }

        if ($remote) {
            if (!$this->hasTimeRemaining($deadline)) {
                return [
                    'delivered' => $delivered,
                    'handled' => $handled,
                    'held_back' => $heldBack,
                    'budget_exhausted' => true,
                ];
            }

            try {
                ($this->remoteSender)($message['text']);
                $delivered = true;
                $handled = true;
            } catch (Throwable $throwable) {
                $errors[] = 'Remote notification failed: ' . $throwable->getMessage();
            }
        }

        return [
            'delivered' => $delivered,
            'handled' => $handled,
            'held_back' => $heldBack,
            'budget_exhausted' => false,
        ];
    }

    /**
     * Alert Processor - Unread Notice Count.
     *
     * @param list<string> $errors - Mutable errors.
     *
     * @return int
     *
     * @since 1.0.0
     * @private
     */
    private function unreadNoticeCount(array &$errors): int
    {
        try {
            $count = ($this->noticeCounter)();

            if ($count < 0) {
                throw new RuntimeException('The unread notice count is invalid.');
            }

            return $count;
        } catch (Throwable $throwable) {
            $errors[] = 'Unable to count WebGUI notices: ' . $throwable->getMessage();

            return self::MAXIMUM_UNREAD_NOTICES;
        }
    }

    /**
     * Alert Processor - Prune Repeat State.
     *
     * @return array{entries: array, hourly: array}
     *
     * @since 1.0.0
     * @private
     */
    private function pruneRepeatState(array $document, array $rules, int $now): array
    {
        $prunedEntries = [];

        foreach ($document['entries'] as $ruleIdentifier => $clients) {
            $rule = $rules[$ruleIdentifier] ?? null;

            if (!is_array($rule) || ($rule['enabled'] ?? false) !== true || !is_array($clients)) {
                continue;
            }

            $cutoff = $now - ((int) ($rule['repeat_minutes'] ?? 60) * 60);

            foreach ($clients as $client => $names) {
                if (!is_string($client) || !is_array($names)) {
                    continue;
                }

                foreach ($names as $name => $lastSent) {
                    if (is_string($name) && is_int($lastSent) && $lastSent > $cutoff) {
                        $prunedEntries[$ruleIdentifier][$client][$name] = $lastSent;
                    }
                }
            }
        }

        $currentHour = intdiv($now, 3600);
        $prunedHourly = [];

        foreach ($document['hourly'] as $ruleIdentifier => $entry) {
            $rule = $rules[$ruleIdentifier] ?? null;

            if (
                is_array($rule)
                && ($rule['enabled'] ?? false) === true
                && is_array($entry)
                && ($entry['hour'] ?? null) === $currentHour
            ) {
                $prunedHourly[$ruleIdentifier] = $entry;
            }
        }

        return ['entries' => $prunedEntries, 'hourly' => $prunedHourly];
    }

    /**
     * Alert Processor - Read Repeat State.
     *
     * @param list<string> $errors - Mutable errors.
     *
     * @return array{entries: array, hourly: array}
     *
     * @since 1.0.0
     * @private
     */
    private function readRepeatState(array &$errors): array
    {
        $empty = ['entries' => [], 'hourly' => []];
        $before = @lstat($this->paths->alertRepeatStateFile);

        if (!is_array($before)) {
            return $empty;
        }

        if (
            ($before['mode'] & 0170000) !== 0100000
            || ($before['mode'] & 0777) !== 0600
            || $before['size'] > self::MAXIMUM_EVENT_FILE_BYTES
        ) {
            $errors[] = 'The Sinkhole alert repeat state is unsafe.';

            return $empty;
        }

        $handle = @fopen($this->paths->alertRepeatStateFile, 'r+b');

        if ($handle === false) {
            $errors[] = 'Unable to read the Sinkhole alert repeat state.';

            return $empty;
        }

        try {
            $after = fstat($handle);

            if (!$this->sameRegularFile($before, $after, self::MAXIMUM_EVENT_FILE_BYTES)) {
                $errors[] = 'The Sinkhole alert repeat state changed while opening.';

                return $empty;
            }

            $contents = stream_get_contents($handle, self::MAXIMUM_EVENT_FILE_BYTES + 1);
        } finally {
            fclose($handle);
        }

        try {
            $document = is_string($contents)
                ? json_decode($contents, true, 32, JSON_THROW_ON_ERROR)
                : null;
        } catch (JsonException) {
            $errors[] = 'The Sinkhole alert repeat state is invalid.';

            return $empty;
        }

        if (!is_array($document) || !is_array($document['entries'] ?? null)) {
            $errors[] = 'The Sinkhole alert repeat state is invalid.';

            return $empty;
        }

        $schemaVersion = $document['schema_version'] ?? null;

        if ($schemaVersion === 1) {
            return ['entries' => $document['entries'], 'hourly' => []];
        }

        if (
            $schemaVersion !== self::REPEAT_STATE_SCHEMA_VERSION
            || !is_array($document['hourly'] ?? null)
        ) {
            $errors[] = 'The Sinkhole alert repeat state is invalid.';

            return $empty;
        }

        foreach ($document['hourly'] as $ruleIdentifier => $entry) {
            if (
                !is_string($ruleIdentifier)
                || !is_array($entry)
                || !is_int($entry['hour'] ?? null)
                || !is_int($entry['sent'] ?? null)
                || $entry['sent'] < 0
                || $entry['sent'] > self::MAXIMUM_NOTIFICATIONS_PER_RULE_PER_HOUR
                || !is_bool($entry['summary_sent'] ?? null)
            ) {
                $errors[] = 'The Sinkhole alert repeat state is invalid.';

                return $empty;
            }
        }

        return ['entries' => $document['entries'], 'hourly' => $document['hourly']];
    }

    /**
     * Alert Processor - Write Repeat State.
     *
     * @param array $before - Original canonical repeat document.
     * @param array $after - Updated canonical repeat document.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function writeRepeatState(array $before, array $after): void
    {
        if ($before === $after) {
            return;
        }

        if (count($after['entries']) === 0 && count($after['hourly']) === 0) {
            FileSystem::removeFixedFile($this->paths->alertRepeatStateFile);

            return;
        }

        try {
            $contents = json_encode(
                [
                    'schema_version' => self::REPEAT_STATE_SCHEMA_VERSION,
                    'entries' => (object) $after['entries'],
                    'hourly' => (object) $after['hourly'],
                ],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $exception) {
            throw new RuntimeException('Unable to encode Sinkhole alert repeat state.', 0, $exception);
        }

        AtomicFile::write($this->paths->alertRepeatStateFile, $contents . PHP_EOL, 0600);
    }

    /**
     * Alert Processor - Record Repeat Keys.
     *
     * @param array $entries - Mutable repeat entries.
     * @param list<array> $keys - Delivered or summarized keys.
     * @param int $now - Run time.
     *
     * @return void
     *
     * @since 1.0.0
     * @private
     */
    private function recordRepeatKeys(array &$entries, array $keys, int $now): void
    {
        foreach ($keys as $key) {
            $entries[$key['rule']][$key['client']][$key['name']] = $now;
        }
    }

    /**
     * Alert Processor - Read Dropped Count.
     *
     * @param list<string> $errors - Mutable errors.
     *
     * @return int
     *
     * @since 1.0.0
     * @private
     */
    private function readDroppedCount(array &$errors): int
    {
        $before = @lstat($this->paths->eventsDroppedFile);

        if (!is_array($before)) {
            return 0;
        }

        if (($before['mode'] & 0170000) !== 0100000 || $before['size'] > 64) {
            $errors[] = 'The Sinkhole dropped-event marker is unsafe.';

            return 0;
        }

        $handle = @fopen($this->paths->eventsDroppedFile, 'r+b');

        if ($handle === false) {
            $errors[] = 'Unable to read the Sinkhole dropped-event marker.';

            return 0;
        }

        try {
            $after = fstat($handle);

            if (!$this->sameRegularFile($before, $after, 64)) {
                $errors[] = 'The Sinkhole dropped-event marker changed while opening.';

                return 0;
            }

            $contents = stream_get_contents($handle, 65);
        } finally {
            fclose($handle);
        }

        $value = is_string($contents) ? trim($contents) : '';

        if (preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) !== 1) {
            $errors[] = 'The Sinkhole dropped-event marker is invalid.';

            return 0;
        }

        $count = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);

        if (!is_int($count)) {
            $errors[] = 'The Sinkhole dropped-event marker is invalid.';

            return 0;
        }

        return $count;
    }

    /**
     * Alert Processor - Same Regular File.
     *
     * @param array $before - lstat result.
     * @param array|false $after - fstat result.
     * @param int $maximumBytes - Maximum accepted size.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function sameRegularFile(array $before, array|false $after, int $maximumBytes): bool
    {
        return is_array($after)
            && ($after['mode'] & 0170000) === 0100000
            && $after['dev'] === $before['dev']
            && $after['ino'] === $before['ino']
            && $after['size'] <= $maximumBytes;
    }

    /**
     * Alert Processor - Has Time Remaining.
     *
     * @param float $deadline - Monotonic run deadline.
     *
     * @return bool
     *
     * @since 1.0.0
     * @private
     */
    private function hasTimeRemaining(float $deadline): bool
    {
        return ($this->monotonicClock)() < $deadline;
    }
}
