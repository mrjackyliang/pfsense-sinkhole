import {
  BlogPreview,
  BrowserFrame,
  Canvas,
  Features,
  Showcase,
  Spotlight,
} from '@cbnventures/docusaurus-preset-nova/blocks';
import Head from '@docusaurus/Head';
import Link from '@docusaurus/Link';
import Translate, { translate } from '@docusaurus/Translate';
import blockedServicesOne from '@locale-docs/configure/_assets_/blocked-services-1.png';
import scopesOne from '@locale-docs/configure/_assets_/scopes-1.png';
import statusOne from '@locale-docs/operate/_assets_/status-1.png';
import Layout from '@theme/Layout';

import styles from './index.module.css';

import type { Pages_Index_Home_Returns } from '../types/pages/index.d.ts';

/**
 * Pages - Home.
 *
 * Introduces the package through a scoped DNS decision, the controls that stay on
 * the firewall, and the latest blog posts.
 *
 * @returns {Pages_Index_Home_Returns}
 *
 * @since 0.0.0
 */
function Home(): Pages_Index_Home_Returns {
  return (
    <Layout description={translate({
      id: 'home.meta.description',
      message: 'Apply saved DNS lists to the whole network, one VLAN, or one device, with intentional alerts and no second box.',
      description: 'Homepage metadata description.',
    })}
    >
      <Head>
        <title>
          {translate({
            id: 'home.meta.title',
            message: 'Sinkhole for pfSense - Scoped DNS, IP, and Country Blocking',
            description: 'Homepage browser title.',
          })}
        </title>
      </Head>

      <main>
        <Canvas container="full" surface="default" className={styles['hero-section']}>
          <div className={styles['hero']}>
            <div className={styles['hero-inner']}>
              <div className={styles['hero-grid']}>
                <div className={styles['hero-content']}>
                  <p className="nova-hero-eyebrow">
                    <Translate id="home.hero.eyebrow" description="Short label above the homepage headline.">
                      Native pfSense package
                    </Translate>
                  </p>
                  <h1 className="nova-hero-heading">
                    <Translate id="home.hero.heading" description="Homepage headline about scoped DNS blocking.">
                      Choose what every network and device can reach.
                    </Translate>
                  </h1>
                  <p className="nova-hero-tagline">
                    <Translate id="home.hero.tagline" description="Homepage summary of package behavior.">
                      Apply saved DNS lists to the whole network, one VLAN, or one device, with intentional alerts and no second box.
                    </Translate>
                  </p>
                  <div className="nova-hero-actions">
                    <Link className="nova-cta-primary" to="/docs/installation/">
                      <Translate id="home.hero.primaryAction" description="Primary homepage call to action.">
                        Get Started
                      </Translate>
                    </Link>
                    <Link className="nova-cta-secondary" to="/docs/intro/">
                      <Translate id="home.hero.secondaryAction" description="Secondary homepage call to action.">
                        Learn More
                      </Translate>
                    </Link>
                  </div>
                </div>

                <div
                  className={styles['decision-preview']}
                  role="group"
                  aria-label={translate({
                    id: 'home.preview.ariaLabel',
                    message: 'Example DNS decision for a device on a VLAN',
                    description: 'Accessible label for the homepage DNS decision preview.',
                  })}
                >
                  <div className={styles['decision-header']}>
                    <span className={styles['decision-dot']} />
                    <span className={styles['decision-dot']} />
                    <span className={styles['decision-dot']} />
                    <span className={styles['decision-title']}>
                      <Translate id="home.preview.title" description="Title of the homepage DNS decision preview.">
                        DNS Decision
                      </Translate>
                    </span>
                    <span className={styles['decision-badge']}>
                      <Translate id="home.preview.blocked" description="Blocked state in the DNS decision preview.">
                        Blocked
                      </Translate>
                    </span>
                  </div>
                  <div className={styles['decision-body']}>
                    <div className={styles['decision-row']}>
                      <span className={styles['decision-label']}>
                        <Translate id="home.preview.query" description="Queried-name label in the DNS decision preview.">
                          Query
                        </Translate>
                      </span>
                      <code>ads.example.net</code>
                    </div>
                    <div className={styles['decision-row']}>
                      <span className={styles['decision-label']}>
                        <Translate id="home.preview.client" description="Client-address label in the DNS decision preview.">
                          Client
                        </Translate>
                      </span>
                      <code>192.168.20.14</code>
                    </div>
                    <div className={styles['decision-row']}>
                      <span className={styles['decision-label']}>
                        <Translate id="home.preview.network" description="Network-scope label in the DNS decision preview.">
                          Network
                        </Translate>
                      </span>
                      <code>KIDS · VLAN 20</code>
                    </div>
                    <ol className={styles['decision-ladder']}>
                      <li>
                        <span>
                          <Translate id="home.preview.deviceLists" description="Device-list step in the DNS decision preview.">
                            Device lists
                          </Translate>
                        </span>
                        <span className={styles['step-pass']}>
                          <Translate id="home.preview.noMatch" description="No-match result of a decision step.">
                            No match
                          </Translate>
                        </span>
                      </li>
                      <li className={styles['step-decided']}>
                        <span>
                          <Translate id="home.preview.networkLists" description="Network-list step in the DNS decision preview.">
                            Network lists
                          </Translate>
                        </span>
                        <span className={styles['step-blocked']}>
                          <Translate id="home.preview.blocked" description="Blocked state in the DNS decision preview.">
                            Blocked
                          </Translate>
                        </span>
                      </li>
                      <li>
                        <span>
                          <Translate id="home.preview.globalLists" description="Global-list step in the DNS decision preview.">
                            Global lists
                          </Translate>
                        </span>
                        <span className={styles['step-skipped']}>
                          <Translate id="home.preview.notReached" description="Result of a decision step that was never checked.">
                            Not reached
                          </Translate>
                        </span>
                      </li>
                    </ol>
                  </div>
                  <div className={styles['decision-result']}>
                    <span>✓</span>
                    <span>
                      <code>0.0.0.0</code>
                      {' · '}
                      <code>::</code>
                      {' · '}
                      <Translate id="home.preview.result" description="Result shown below the DNS decision preview.">
                        answered from saved lists
                      </Translate>
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Canvas>

        <Features
          items={[
            {
              icon: 'lucide:network',
              title: translate({
                id: 'home.features.scopes.title',
                message: 'Scope Every Decision',
                description: 'Feature title for global, network, and device scopes.',
              }),
              description: translate({
                id: 'home.features.scopes.description',
                message: 'Apply lists and allowed domains globally, by interface or VLAN, and by device.',
                description: 'Feature summary for global, network, and device scopes.',
              }),
            },
            {
              icon: 'lucide:hard-drive-download',
              title: translate({
                id: 'home.features.savedLists.title',
                message: 'Keep Last-Good Copies',
                description: 'Feature title for saved list copies.',
              }),
              description: translate({
                id: 'home.features.savedLists.description',
                message: 'Answer DNS from saved local lists through restarts, reloads, and failed downloads.',
                description: 'Feature summary for saved list copies.',
              }),
            },
            {
              icon: 'lucide:bell-ring',
              title: translate({
                id: 'home.features.alerts.title',
                message: 'Alert on Purpose',
                description: 'Feature title for alert rules.',
              }),
              description: translate({
                id: 'home.features.alerts.description',
                message: 'Notify only for the lists, networks, and devices selected in each rule.',
                description: 'Feature summary for alert rules.',
              }),
            },
            {
              icon: 'lucide:route',
              title: translate({
                id: 'home.features.redirect.title',
                message: 'Protect DNS Paths',
                description: 'Feature title for bypass protection.',
              }),
              description: translate({
                id: 'home.features.redirect.description',
                message: 'Optionally redirect plain DNS or block common encrypted-DNS and tunnel bypasses on selected interfaces.',
                description: 'Feature summary for bypass protection.',
              }),
            },
            {
              icon: 'lucide:search',
              title: translate({
                id: 'home.features.catalogs.title',
                message: 'Search, Then Decide',
                description: 'Feature title for catalog search.',
              }),
              description: translate({
                id: 'home.features.catalogs.description',
                message: 'Search supported catalogs on demand without bundling or recommending a list.',
                description: 'Feature summary for catalog search.',
              }),
            },
            {
              icon: 'lucide:shield',
              title: translate({
                id: 'home.features.ipCountry.title',
                message: 'Block Addresses and Countries',
                description: 'Feature title for IP and country blocking.',
              }),
              description: translate({
                id: 'home.features.ipCountry.description',
                message: 'Apply IP lists and GeoLite2 country policy through the isolated sinkhole/ip anchor.',
                description: 'Feature summary for IP and country blocking.',
              }),
            },
          ]}
        />

        <Spotlight
          surface="alt"
          className={styles['shot-spotlight']}
          heading={translate({
            id: 'home.showcase.heading',
            message: 'Inside the pfSense WebGUI',
            description: 'Heading above the WebGUI screenshots on the front page.',
          })}
        >
          <Showcase
            tabsLabel={translate({
              id: 'home.showcase.tabsLabel',
              message: 'Sinkhole pages',
              description: 'Accessible label for the screenshot tabs on the front page.',
            })}
            items={[
              {
                label: translate({
                  id: 'home.showcase.scopes.label',
                  message: 'Scopes',
                  description: 'Front page screenshot tab for the Scopes page.',
                }),
                heading: translate({
                  id: 'home.showcase.scopes.heading',
                  message: 'Different rules for each network and device',
                  description: 'Front page heading for the Scopes page screenshot.',
                }),
                description: translate({
                  id: 'home.showcase.scopes.description',
                  message: 'Give a network or a single device its own lists and allowed domains. Every DNS query follows the most specific scope that matches it.',
                  description: 'Front page description for the Scopes page screenshot.',
                }),
                link: {
                  label: translate({
                    id: 'home.showcase.scopes.link',
                    message: 'Set Up Scopes',
                    description: 'Front page link from the Scopes screenshot to its guide.',
                  }),
                  to: '/docs/configure/scopes/',
                },
                content: (
                  <BrowserFrame
                    className={styles['shot-frame']}
                    title={translate({
                      id: 'home.showcase.scopes.title',
                      message: 'pfSense.home.arpa - Firewall: Sinkhole: Scopes',
                      description: 'Browser tab title of the Scopes screenshot on the front page, as the pfSense WebGUI shows it.',
                    })}
                    url="192.168.1.1/sinkhole-scopes.php"
                    favicon="/images/pfsense-favicon.ico"
                  >
                    <img
                      src={scopesOne}
                      alt={translate({
                        id: 'home.showcase.scopes.alt',
                        message: 'Sinkhole Scopes page with a LAN network scope and three device scopes',
                        description: 'Alt text for the Scopes page screenshot on the front page.',
                      })}
                      width={1024}
                      height={768}
                    />
                  </BrowserFrame>
                ),
              },
              {
                label: translate({
                  id: 'home.showcase.services.label',
                  message: 'Services',
                  description: 'Front page screenshot tab for the Blocked Services page.',
                }),
                heading: translate({
                  id: 'home.showcase.services.heading',
                  message: 'Block a whole service with one click',
                  description: 'Front page heading for the Blocked Services page screenshot.',
                }),
                description: translate({
                  id: 'home.showcase.services.description',
                  message: 'Pick games, social media, streaming, and other services from a cached registry, for everyone or for one network or device. Allowed domains still win.',
                  description: 'Front page description for the Blocked Services page screenshot.',
                }),
                link: {
                  label: translate({
                    id: 'home.showcase.services.link',
                    message: 'Block Services',
                    description: 'Front page link from the Blocked Services screenshot to its guide.',
                  }),
                  to: '/docs/configure/blocked-services/',
                },
                content: (
                  <BrowserFrame
                    className={styles['shot-frame']}
                    title={translate({
                      id: 'home.showcase.services.title',
                      message: 'pfSense.home.arpa - Firewall: Sinkhole: Services',
                      description: 'Browser tab title of the Blocked Services screenshot on the front page, as the pfSense WebGUI shows it.',
                    })}
                    url="192.168.1.1/sinkhole-services.php"
                    favicon="/images/pfsense-favicon.ico"
                  >
                    <img
                      src={blockedServicesOne}
                      alt={translate({
                        id: 'home.showcase.services.alt',
                        message: 'Sinkhole Blocked Services page showing gaming services for a device scope',
                        description: 'Alt text for the Blocked Services page screenshot on the front page.',
                      })}
                      width={1024}
                      height={1268}
                    />
                  </BrowserFrame>
                ),
              },
              {
                label: translate({
                  id: 'home.showcase.status.label',
                  message: 'Status',
                  description: 'Front page screenshot tab for the Status page.',
                }),
                heading: translate({
                  id: 'home.showcase.status.heading',
                  message: 'Know what is loaded and what is out of date',
                  description: 'Front page heading for the Status page screenshot.',
                }),
                description: translate({
                  id: 'home.showcase.status.description',
                  message: 'Status shows every list with its entry count and last update, plus the scopes, networks, and devices Sinkhole is applying right now.',
                  description: 'Front page description for the Status page screenshot.',
                }),
                link: {
                  label: translate({
                    id: 'home.showcase.status.link',
                    message: 'Read the Status Page',
                    description: 'Front page link from the Status screenshot to its guide.',
                  }),
                  to: '/docs/operate/status/',
                },
                content: (
                  <BrowserFrame
                    className={styles['shot-frame']}
                    title={translate({
                      id: 'home.showcase.status.title',
                      message: 'pfSense.home.arpa - Firewall: Sinkhole: Status',
                      description: 'Browser tab title of the Status screenshot on the front page, as the pfSense WebGUI shows it.',
                    })}
                    url="192.168.1.1/sinkhole-status.php"
                    favicon="/images/pfsense-favicon.ico"
                  >
                    <img
                      src={statusOne}
                      alt={translate({
                        id: 'home.showcase.status.alt',
                        message: 'Sinkhole Status page with the lists, scopes, networks, and devices panels',
                        description: 'Alt text for the Status page screenshot on the front page.',
                      })}
                      width={1024}
                      height={929}
                    />
                  </BrowserFrame>
                ),
              },
            ]}
          />
        </Spotlight>

        <BlogPreview
          heading={translate({
            id: 'home.blogPreview.heading',
            message: 'From the Blog',
            description: 'Heading above the homepage blog preview.',
          })}
          description={translate({
            id: 'home.blogPreview.description',
            message: 'Launches, milestones, and what\'s new in Sinkhole for pfSense.',
            description: 'Summary below the homepage blog preview heading.',
          })}
          auto={true}
          limit={3}
          sort="newest"
        />
      </main>
    </Layout>
  );
}

export default Home;
