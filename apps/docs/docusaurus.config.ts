import { NovaIdentity } from '@cbnventures/nova/toolkit';

import type { DocusaurusNovaConfig } from '@cbnventures/docusaurus-preset-nova/types/config';

/**
 * Docusaurus - Identity.
 *
 * Reads the documentation identity from the generated Nova configuration.
 * Fallbacks keep the site runnable when project metadata is unavailable.
 *
 * @since 0.0.0
 */
const identity = new NovaIdentity().forDocs();

/**
 * Docusaurus - Config.
 *
 * Configures Sinkhole's documentation site with Nova's selected preset.
 *
 * @since 0.0.0
 */
const config: DocusaurusNovaConfig = {
  title: identity['title'] ?? '',
  tagline: identity['tagline'] ?? 'Scoped DNS, IP, and country blocking for pfSense.',
  url: identity['url'] ?? 'https://www.example.com',
  baseUrl: identity['baseUrl'] ?? '/',
  favicon: './favicon.ico',
  organizationName: identity['organizationName'] ?? 'your-org',
  projectName: identity['projectName'] ?? 'pfsense-sinkhole',
  trailingSlash: true,
  onBrokenLinks: 'throw',

  headTags: [
    {
      tagName: 'link',
      attributes: {
        rel: 'apple-touch-icon',
        sizes: '180x180',
        href: `${identity['baseUrl'] ?? '/'}apple-touch-icon.png`,
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'icon',
        type: 'image/png',
        sizes: '96x96',
        href: `${identity['baseUrl'] ?? '/'}favicon-96x96.png`,
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'icon',
        type: 'image/svg+xml',
        href: `${identity['baseUrl'] ?? '/'}favicon.svg`,
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'manifest',
        href: `${identity['baseUrl'] ?? '/'}site.webmanifest`,
      },
    },
  ],

  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en-US',
    locales: [
      'bs',
      'zh-CN',
      'zh-Hans-CN',
      'zh-Hans-HK',
      'zh-Hant-TW',
      'nl-NL',
      'en-US',
      'fr-FR',
      'de-DE',
      'it-IT',
      'ko-KR',
      'nb-NO',
      'pl-PL',
      'pt-PT',
      'pt-BR',
      'ru-RU',
      'es-ES',
      'es-AR',
    ],
    localeConfigs: {
      'bs': {
        label: 'Bosnian',
        htmlLang: 'bs',
      },
      'zh-CN': {
        label: 'Chinese',
        htmlLang: 'zh-CN',
      },
      'zh-Hans-CN': {
        label: 'Chinese (Simplified, China)',
        htmlLang: 'zh-Hans-CN',
      },
      'zh-Hans-HK': {
        label: 'Chinese (Simplified, Hong Kong SAR China)',
        htmlLang: 'zh-Hans-HK',
      },
      'zh-Hant-TW': {
        label: 'Chinese (Traditional, Taiwan)',
        htmlLang: 'zh-Hant-TW',
      },
      'nl-NL': {
        label: 'Dutch',
        htmlLang: 'nl-NL',
      },
      'en-US': {
        label: 'English',
        htmlLang: 'en-US',
      },
      'fr-FR': {
        label: 'French',
        htmlLang: 'fr-FR',
      },
      'de-DE': {
        label: 'German (Germany)',
        htmlLang: 'de-DE',
      },
      'it-IT': {
        label: 'Italian',
        htmlLang: 'it-IT',
      },
      'ko-KR': {
        label: 'Korean',
        htmlLang: 'ko-KR',
      },
      'nb-NO': {
        label: 'Norwegian Bokmål',
        htmlLang: 'nb-NO',
      },
      'pl-PL': {
        label: 'Polish',
        htmlLang: 'pl-PL',
      },
      'pt-PT': {
        label: 'Portuguese',
        htmlLang: 'pt-PT',
      },
      'pt-BR': {
        label: 'Portuguese (Brazil)',
        htmlLang: 'pt-BR',
      },
      'ru-RU': {
        label: 'Russian',
        htmlLang: 'ru-RU',
      },
      'es-ES': {
        label: 'Spanish',
        htmlLang: 'es-ES',
      },
      'es-AR': {
        label: 'Spanish (Argentina)',
        htmlLang: 'es-AR',
      },
    },
  },

  presets: [[
    '@cbnventures/docusaurus-preset-nova',
    {
      preset: 'sentinel',
      overrides: {
        colors: {
          primary: {
            light: '#0f766e',
            dark: '#2dd4bf',
          },
          secondary: {
            light: '#b45309',
            dark: '#fbbf24',
          },
        },
      },
      plugins: {
        blog: false,
        docs: {
          sidebarPath: './sidebars.ts',
          routeBasePath: 'docs',
        },
      },
      search: {},
    },
  ]],

  themeConfig: {
    site: {
      logo: {
        alt: 'Sinkhole for pfSense',
        src: {
          light: `${identity['baseUrl'] ?? '/'}images/navbar.svg`,
          dark: undefined,
        },
        href: '/',
      },
      image: '/thumbnails/brand.png',
      metadata: [
        {
          name: 'description',
          content: identity['metaDescription'] ?? '',
        },
        {
          name: 'twitter:card',
          content: 'summary_large_image',
        },
      ],
    },
    navbar: {
      title: 'Sinkhole',
      items: [
        {
          label: 'Home',
          position: 'left',
          to: '/',
          icon: 'lucide:house',
        },
        {
          label: 'Guides',
          position: 'left',
          type: 'docSidebar',
          sidebarId: 'docs',
          icon: 'lucide:book-open',
        },
        {
          label: 'Status',
          position: 'left',
          to: '/docs/operate/status',
          icon: 'lucide:activity',
        },
        {
          label: 'Troubleshooting',
          position: 'left',
          to: '/docs/operate/troubleshooting',
          icon: 'lucide:life-buoy',
        },
      ],
    },
    errorPages: {
      notFound: {
        title: 'This page was not found.',
        description: 'The link may be out of date, or the page may have moved.',
        backHomeLabel: 'Go to the overview',
        backHomeHref: '/docs/intro/',
      },
      errorPageContent: {
        title: 'This page could not be loaded.',
        retryLabel: 'Reload the page',
      },
      error: {
        retryLabel: 'Try again',
      },
    },
    footer: {
      socialLinks: [],
      sections: {
        learn: [
          {
            label: 'Install Sinkhole',
            href: '/docs/installation',
          },
          {
            label: 'Lists and saved copies',
            href: '/docs/configure/lists',
          },
          {
            label: 'Scopes and allowed domains',
            href: '/docs/configure/scopes',
          },
          {
            label: 'Status',
            href: '/docs/operate/status',
          },
          {
            label: 'Troubleshooting',
            href: '/docs/operate/troubleshooting',
          },
        ],
        resources: [
          {
            label: 'How updates work',
            href: '/docs/safety/how-updates-work',
          },
          {
            label: 'Testing and verification',
            href: '/docs/safety/testing-and-verification',
          },
          {
            label: 'pfSense documentation',
            href: 'https://docs.netgate.com/pfsense/en/latest/',
          },
          {
            label: 'Source code',
            href: 'https://github.com/mrjackyliang/pfsense-sinkhole',
          },
        ],
      },
      layout: {
        learn: {
          title: 'Guides',
          section: 'learn',
        },
        resources: {
          title: 'Resources',
          section: 'resources',
        },
      },
      copyright: identity['copyright'],
      credit: true,
    },
  },
};

export default config;
