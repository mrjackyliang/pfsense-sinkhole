import {
  Features,
  Hero,
  Stats,
} from '@cbnventures/docusaurus-preset-nova/blocks';
import { translate } from '@docusaurus/Translate';
import Layout from '@theme/Layout';

import type { Pages_Index_Home_Returns } from '../types/pages/index.d.ts';

/**
 * Pages - Home.
 *
 * Composes a preset-native documentation landing page without the article and
 * table-of-contents frame used by ordinary MDX pages.
 *
 * @returns {Pages_Index_Home_Returns}
 *
 * @since 0.0.0
 */
function Home(): Pages_Index_Home_Returns {
  return (
    <Layout>
      <Hero
        eyebrow={translate({
          id: 'homepage.hero.eyebrow',
          message: 'Native pfSense package',
        })}
        heading={translate({
          id: 'homepage.hero.heading',
          message: 'Choose what every network and device can reach.',
        })}
        tagline={translate({
          id: 'homepage.hero.tagline',
          message: 'Apply saved DNS lists to the whole network, one VLAN, or one device, with intentional alerts and no second box.',
        })}
        ctaLabel={translate({
          id: 'homepage.hero.ctaLabel',
          message: 'Install Sinkhole',
        })}
        ctaLink="/docs/installation"
        secondaryCtaLabel={translate({
          id: 'homepage.hero.secondaryCtaLabel',
          message: 'Plan your scopes',
        })}
        secondaryCtaLink="/docs/configure/scopes"
      />
      <main id="capabilities">
        <Stats
          heading={translate({
            id: 'homepage.stats.heading',
            message: 'One firewall, policy at every useful level',
          })}
          description={translate({
            id: 'homepage.stats.description',
            message: 'Sinkhole keeps policy local and makes its operating boundaries explicit.',
          })}
          surface="alt"
          items={[
            {
              value: '3',
              label: translate({
                id: 'homepage.stats.policyScopes',
                message: 'Policy scopes',
              }),
              color: 'primary',
            },
            {
              value: '3',
              label: translate({
                id: 'homepage.stats.dnsListFormats',
                message: 'DNS list formats',
              }),
              color: 'accent',
            },
            {
              value: '1 day',
              label: translate({
                id: 'homepage.stats.catalogCache',
                message: 'Catalog cache',
              }),
              color: 'primary',
            },
            {
              value: '1',
              label: translate({
                id: 'homepage.stats.unboundSlot',
                message: 'Unbound module slot',
              }),
              color: 'accent',
            },
          ]}
        />
        <Features
          heading={translate({
            id: 'homepage.features.heading',
            message: 'Control that stays on the firewall',
          })}
          items={[
            {
              icon: 'lucide:network',
              title: translate({
                id: 'homepage.features.scopes.title',
                message: 'Scope every decision',
              }),
              description: translate({
                id: 'homepage.features.scopes.description',
                message: 'Apply lists and allowed domains globally, by interface or VLAN, and by device.',
              }),
            },
            {
              icon: 'lucide:hard-drive-download',
              title: translate({
                id: 'homepage.features.savedLists.title',
                message: 'Keep last-good copies',
              }),
              description: translate({
                id: 'homepage.features.savedLists.description',
                message: 'Answer DNS from saved local lists through restarts, reloads, and failed downloads.',
              }),
            },
            {
              icon: 'lucide:bell-ring',
              title: translate({
                id: 'homepage.features.alerts.title',
                message: 'Alert on purpose',
              }),
              description: translate({
                id: 'homepage.features.alerts.description',
                message: 'Notify only for the lists, networks, and devices selected in each rule.',
              }),
            },
            {
              icon: 'lucide:route',
              title: translate({
                id: 'homepage.features.redirect.title',
                message: 'Protect DNS paths',
              }),
              description: translate({
                id: 'homepage.features.redirect.description',
                message: 'Optionally redirect plain DNS or block common encrypted-DNS and tunnel bypasses on selected interfaces.',
              }),
            },
            {
              icon: 'lucide:search',
              title: translate({
                id: 'homepage.features.catalogs.title',
                message: 'Search, then decide',
              }),
              description: translate({
                id: 'homepage.features.catalogs.description',
                message: 'Search supported catalogs on demand without bundling or recommending a list.',
              }),
            },
            {
              icon: 'lucide:shield',
              title: translate({
                id: 'homepage.features.ipCountry.title',
                message: 'Block addresses and countries',
              }),
              description: translate({
                id: 'homepage.features.ipCountry.description',
                message: 'Apply IP lists and GeoLite2 country policy through the isolated sinkhole/ip anchor.',
              }),
            },
          ]}
        />
      </main>
    </Layout>
  );
}

export default Home;
