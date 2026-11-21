<?php

declare(strict_types=1);

namespace PfSense\Sinkhole\Runtime;

require_once(__DIR__ . '/PlatformAdapter.php');

/**
 * Platform.
 *
 * Hands static helpers such as configuration partitions, the translator, the
 * filesystem helper, and update checks the shared platform adapter, so they never
 * call pfSense functions themselves.
 *
 * @since 1.3.3
 */
final class Platform
{
    /**
     * Platform - Adapter Instance.
     *
     * Null means the production adapter has not been created yet.
     *
     * @var PlatformAdapter|null
     *
     * @since 1.3.3
     * @private
     */
    private static ?PlatformAdapter $adapter = null;

    /**
     * Platform - Adapter.
     *
     * Returns the shared adapter, creating the pfSense adapter on first use. The
     * adapter file loads only then, so including a domain class never pulls in the
     * whole pfSense integration.
     *
     * @return PlatformAdapter
     *
     * @since 1.3.3
     */
    public static function adapter(): PlatformAdapter
    {
        if (self::$adapter === null) {
            require_once(__DIR__ . '/PfSenseAdapter.php');

            self::$adapter = new PfSenseAdapter();
        }

        return self::$adapter;
    }

    /**
     * Platform - Replace.
     *
     * Tests swap in a fake adapter, and null restores the production adapter on the
     * next use.
     *
     * @param PlatformAdapter|null $adapter - Replacement adapter.
     *
     * @return void
     *
     * @since 1.3.3
     */
    public static function replace(?PlatformAdapter $adapter): void
    {
        self::$adapter = $adapter;
    }
}
