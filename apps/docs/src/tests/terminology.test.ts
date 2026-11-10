import { registerTerminologySuite } from '@cbnventures/nova/rules/vitest';
import * as vitest from 'vitest';

/**
 * Tests - Terminology.
 *
 * This site self-checks its Terminology components THROUGH the published kit.
 * The suite logic lives in @cbnventures/nova/rules/vitest; this wrapper
 * supplies the configuration that reproduces this site's conventions.
 *
 * @since 0.20.0
 */
registerTerminologySuite({
  vitest,
  enable: [
    'terminology-title-attr-present',
    'terminology-to-attr-present',
    'terminology-children-nonempty',
    'terminology-to-points-to-base',
    'terminology-component-validation',
  ],
  terminologyPath: 'docs/reference/terminology.mdx',
  expectedBase: '/docs/reference/terminology',
});
