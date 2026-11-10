<?php

declare(strict_types=1);

use PfSense\Sinkhole\Runtime\FileSystem;

/**
 * Sinkhole Test - Assert Same.
 *
 * @param mixed $expected - Expected value.
 * @param mixed $actual   - Actual value.
 * @param string $message - Failure context.
 *
 * @return void
 *
 * @throws RuntimeException When values differ.
 *
 * @since 1.0.0
 */
function sinkholeTestAssertSame(mixed $expected, mixed $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(
            $message
            . PHP_EOL
            . 'Expected: '
            . var_export($expected, true)
            . PHP_EOL
            . 'Actual: '
            . var_export($actual, true),
        );
    }
}

/**
 * Sinkhole Test - Assert True.
 *
 * @param bool $condition - Condition under test.
 * @param string $message - Failure context.
 *
 * @return void
 *
 * @throws RuntimeException When the condition is false.
 *
 * @since 1.0.0
 */
function sinkholeTestAssertTrue(bool $condition, string $message): void
{
    sinkholeTestAssertSame(true, $condition, $message);
}

/**
 * Sinkhole Test - Assert Contains.
 *
 * @param string $needle   - Required substring.
 * @param string $haystack - Complete value.
 * @param string $message  - Failure context.
 *
 * @return void
 *
 * @throws RuntimeException When the substring is absent.
 *
 * @since 1.0.0
 */
function sinkholeTestAssertContains(string $needle, string $haystack, string $message): void
{
    sinkholeTestAssertTrue(str_contains($haystack, $needle), $message);
}

/**
 * Sinkhole Test - Temporary Directory.
 *
 * @return string
 *
 * @throws RuntimeException When the directory cannot be created.
 *
 * @since 1.0.0
 */
function sinkholeTestTemporaryDirectory(): string
{
    $path = sys_get_temp_dir() . '/sinkhole-test-' . bin2hex(random_bytes(8));

    if (mkdir($path, 0700) === false) {
        throw new RuntimeException('Unable to create a test directory.');
    }

    return $path;
}

/**
 * Sinkhole Test - Remove Temporary Directory.
 *
 * @param string $path - Test-owned path.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeTestRemoveTemporaryDirectory(string $path): void
{
    if (class_exists(FileSystem::class)) {
        FileSystem::removeDirectory($path);

        return;
    }

    if (is_dir($path) === false) {
        return;
    }

    $entries = scandir($path);

    if ($entries === false) {
        throw new RuntimeException('Unable to read a test directory.');
    }

    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }

        $entryPath = $path . '/' . $entry;

        if (is_dir($entryPath)) {
            sinkholeTestRemoveTemporaryDirectory($entryPath);
        } elseif (unlink($entryPath) === false) {
            throw new RuntimeException('Unable to remove a test file.');
        }
    }

    if (rmdir($path) === false) {
        throw new RuntimeException('Unable to remove a test directory.');
    }
}

/**
 * Sinkhole Test - Run Cases.
 *
 * @param array<string, callable(): void> $cases - Named test cases.
 *
 * @return void
 *
 * @since 1.0.0
 */
function sinkholeTestRun(array $cases): void
{
    foreach ($cases as $name => $case) {
        $case();
        fwrite(STDOUT, 'PASS ' . $name . PHP_EOL);
    }
}
