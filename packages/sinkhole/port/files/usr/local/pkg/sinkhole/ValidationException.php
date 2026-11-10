<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Domain;

use InvalidArgumentException;
use PfSense\Sinkhole\Runtime\Translator;

require_once(__DIR__ . '/Translator.php');

/**
 * Validation Exception.
 *
 * Carries a stable translation key and positional arguments from domain validation
 * to a page while retaining an English exception message for system logs.
 *
 * @since 1.0.0
 */
final class ValidationException extends InvalidArgumentException
{
    /** @var array<int, scalar|null> @since 1.0.0 */
    private array $messageArguments;

    /**
     * Validation Exception - Constructor.
     *
     * @param string $messageKey - Stable catalog key.
     * @param array<int, scalar|null> $messageArguments - Positional message arguments.
     *
     * @since 1.0.0
     */
    public function __construct(
        private readonly string $messageKey,
        array $messageArguments = [],
    ) {
        $this->messageArguments = array_values($messageArguments);

        parent::__construct(Translator::translateForLocale(
            Translator::DEFAULT_LOCALE,
            $messageKey,
            $this->messageArguments,
        ));
    }

    /**
     * Returns the stable catalog key.
     *
     * @return string
     *
     * @since 1.0.0
     */
    public function messageKey(): string
    {
        return $this->messageKey;
    }

    /**
     * Returns the positional catalog arguments.
     *
     * @return array<int, scalar|null>
     *
     * @since 1.0.0
     */
    public function messageArguments(): array
    {
        return $this->messageArguments;
    }
}
