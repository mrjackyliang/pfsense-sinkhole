import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

/**
 * Sidebars - Sidebars.
 *
 * Defines the documentation navigation tree by reader task.
 *
 * @since 0.0.0
 */
const sidebars: SidebarsConfig = {
  docs: [
    {
      type: 'category',
      label: 'Start Here',
      items: [
        'intro',
        'installation',
        'first-run',
        'compatibility',
      ],
    },
    {
      type: 'category',
      label: 'Configure',
      items: [
        'configure/lists',
        'configure/blocked-services',
        'configure/scopes',
        'configure/alerts',
        'configure/bypass-protection',
        'configure/ip-and-country-blocking',
      ],
    },
    {
      type: 'category',
      label: 'Operate',
      items: [
        'operate/status',
        'operate/troubleshooting',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        'reference/terminology',
        'reference/settings',
        'reference/command-line-and-files',
        'reference/package-lifecycle',
        'reference/updates',
      ],
    },
    {
      type: 'category',
      label: 'Safety',
      items: [
        'safety/how-updates-work',
        'safety/testing-and-verification',
      ],
    },
    {
      type: 'category',
      label: 'Contributing',
      items: ['contributing/build-and-release'],
    },
  ],
};

export default sidebars;
