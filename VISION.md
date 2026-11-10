# VISION.md

## Purpose

### Origin

Jacky Liang runs pfSense and wanted different blocking for different parts of the network:
a list for the kids, a list for guests, and global lists for everyone. The worry behind it
is concrete: children reaching sites that aren't meant for them, and guests downloading
illegal content, the kind of blocking a company applies to its own network.

pfBlockerNG, the official pfSense package for this, didn't work out, and it can't give
each VLAN its own DNS block lists. The fallback became plain Unbound in pfSense's DNS
Resolver with response policy zones. It works, but every firewall restart or reload means
about ten minutes without internet while the lists load, because the previous lists aren't
kept for DNS to use in the meantime. AdGuard Home and Pi-hole solve parts of this, but both
need their own host outside pfSense, and neither is built for it.

After about a year with that setup, Sinkhole is the package Jacky needs and couldn't find.
It fills a gap the pfSense community doesn't have covered.

### Problem Statement

DNS blocking on pfSense today means one set of block lists for every client, or
hand-written Unbound configuration with no interface. Giving a kids' VLAN, a guest VLAN or
a single device its own lists takes a separate DNS server on another host. Administrators
can't choose which blocks notify them, and in the setups behind this project, every restart
or reload left the network without DNS while the lists loaded.

### Target Audience

- **Audience** — Networking professionals who run pfSense: parents protecting kids and
  guests on a home network, and employers controlling employee and guest networks. pfSense
  users are network people already, so they know VLANs, interfaces and the DNS Resolver.
- **Non-audience** — People who don't run pfSense. Anyone who wants a stand-alone DNS
  filter on its own host is better served by Pi-hole or AdGuard Home.

### Value Proposition

Peace of mind for parents and employers. Administrators choose block lists for the whole
network, a VLAN or a single device, get alerts only where they set them, and stay in
control of their network. The lists are saved on the firewall, so DNS answers right after a
restart or reload, all inside pfSense with no second box. Sinkhole is an upgrade over what
pfSense users run today, not a new kind of tool.

## Product Direction

### Principles

- **The network never waits on the lists** — DNS answers from the last saved lists. Updates
  download in the background, and a failed download keeps the previous lists.
- **Control at any scope** — The same controls work for the whole network, one VLAN or one
  device, flexible enough for the strictest parental-control or workplace policy.
- **Alerts on purpose** — An alert fires only for the list, VLAN or device an administrator
  picked, never for every block.
- **Native to pfSense** — Everything runs on the firewall and is configured in the pfSense
  WebGUI. Nothing depends on a second box or an outside service.
- **The administrator decides** — Behavior that changes how devices reach DNS, such as
  redirecting their queries, is a setting the administrator turns on.
- **Neutral about lists** — The project publishes no block lists, and its documentation
  recommends none. The WebGUI can search popular lists, the way AdGuard Home does.
- **Built for networking professionals** — The WebGUI stays terse and factual, without
  recommendation badges or hand-holding.

### Scope

- Block lists that apply to the whole network, a VLAN or a single device.
- Lists saved on the firewall, so DNS keeps answering from them through restarts, reloads
  and failed downloads.
- Alerts for chosen lists, VLANs or devices, delivered through pfSense's own notification
  system.
- An optional DNS redirect that sends devices' DNS queries to the firewall, replacing
  hand-made redirect rules.
- A search of popular block lists in the WebGUI, so administrators can add them without
  hunting for URLs.
- IP address and country blocking, for administrators who want it.
- The WebGUI and the docs in all 18 languages pfSense offers.

### Explicit Non-Goals

- **Hosting or curating block lists** — Sinkhole creates no list URLs of its own;
  administrators add the sources they trust.
- **Recommending lists in the documentation** — The docs explain how to add and search for
  lists without promoting any.
- **Running outside pfSense** — No companion server, appliance or cloud service.
- **Its own notification channels** — Alerts use pfSense's notification system, which
  already delivers to the services administrators set up there.
- **Silent DNS redirection by default** — The redirect stays off until an administrator
  turns it on, because it changes how every device on the network reaches DNS.
- **An alert for every block** — Alerts are scoped, so they stay worth reading.

## Product Design

### Core Capabilities

Administrators add block lists by URL or pick them from a search of popular lists.
Sinkhole downloads each list, keeps the last good copy on the firewall, and applies lists
by scope: global lists to every client, VLAN lists to that VLAN, and device lists to one
device. DNS answers from the saved copies, so a restart, a reload or a failed download
never leaves the network waiting. When a query matches a list and scope the administrator
chose to watch, pfSense sends a notification. The optional redirect keeps devices from
going around the firewall's DNS, and IP and country blocking cover traffic that DNS
blocking can't reach.

Decided with Jacky on 2026-11-05:
- **DNS Resolver hook** — Sinkhole runs as an Unbound Python module, the way pfBlockerNG
  does, and loads only local files when Unbound starts.
- **Scopes** — The scopes form a hierarchy: global (network-wide), then VLAN, then device.
  A VLAN gets the global lists plus its own, and a device gets its VLAN's lists plus its
  own. Each level can also allow specific domains, so a false positive doesn't force
  dropping a whole list.
- **Devices** — A device is identified by IP address, DHCP static mapping or MAC address.
- **List formats** — The standard ones: hosts files, plain domain lists and adblock-style
  domain rules.
- **Blocked answer** — A blocked name answers with the null address (`0.0.0.0` / `::`).
- **Catalogs and country data** — The same sources the top blockers use, fetched at run time
  and never bundled: AdGuard Home's list registry for DNS lists, pfBlockerNG's feed catalog
  for IP lists, and MaxMind GeoLite2 with the administrator's own account and license key.

### User Experience

1. Install Sinkhole from its release package and open its page in the pfSense WebGUI.
2. Add lists by URL or from the popular-list search, and assign them to the whole network,
   VLANs or devices.
3. Choose which lists, VLANs or devices send alerts, and turn on the DNS redirect if
   devices shouldn't get around it.
4. From then on, DNS answers right away after every restart or reload, and the
   administrator hears only about the blocks they asked about.

The first impression should be control: the administrator sees what each network and
device gets, and nothing happens behind their back.

### Domain Model

| Concept              | Meaning                                                                      |
|----------------------|------------------------------------------------------------------------------|
| Block list           | A list source the administrator adds by URL or from the popular-list search. |
| Saved list           | The last good copy of a block list, kept on the firewall and used for DNS.   |
| Scope                | Where a list applies: global, then VLAN, then device, as a hierarchy.        |
| Device               | One client, identified by IP address, DHCP static mapping or MAC address.    |
| Assignment           | The link between block lists and the scopes they apply to.                   |
| Allowed domain       | A domain a scope lets through even when a list it inherits blocks it.        |
| Alert rule           | A list and scope whose blocks send a pfSense notification.                   |
| DNS redirect         | The optional setting that sends devices' DNS queries to the firewall.        |
| IP and country lists | Address-based blocking for administrators who want it.                       |

## Positioning

### Alternatives

- **pfBlockerNG** — The official pfSense package, with DNS blocking, IP lists and country
  blocking together, and a large community. Its DNS blocking uses one set of lists for every
  client; Python mode adds a group policy that only exempts devices by IP.
- **Plain Unbound in the DNS Resolver** — No extra package, and Unbound's response policy
  zones can load lists directly. Per-network rules and saved copies exist only when an
  administrator writes them into Custom Options by hand, with no interface or alerts.
- **Pi-hole** — Groups give different clients their own lists, behind a mature dashboard. It
  needs its own machine or VM outside pfSense.
- **AdGuard Home** — Per-client settings, client-scoped filtering rules and a built-in
  picker of popular lists. It also needs its own host, and there is no official pfSense
  package for it.
- **Doing nothing** — Keep the current setup and live with the restart outage and one set of
  lists for everyone.

### Differentiators

- Block lists per VLAN and per device, configured in the pfSense WebGUI, with no second box.
- DNS that answers right after a restart or reload, from lists saved on the firewall.
- Alerts limited to the lists, VLANs and devices an administrator chooses, through pfSense
  notifications.
- A built-in DNS redirect that replaces hand-made rules, off until the administrator turns
  it on.
- One package for DNS blocking, popular-list search, and IP and country blocking.

## Risks and Future

### Risks

- **DNS Resolver restarts** — pfSense rewrites and restarts its DNS Resolver when related
  settings change, so Sinkhole has to survive those restarts and pfSense upgrades without
  losing its lists.
- **Scope** — IP and country blocking roughly doubles what the first release has to build
  and test, and Jacky won't use it himself.
- **Country data** — MaxMind's GeoLite2, which pfBlockerNG also uses, needs the
  administrator's own MaxMind account and license key. Sinkhole never ships one.
- **Popular-list search** — The search reads AdGuard Home's list registry (GPL-3.0) and
  pfBlockerNG's feed catalog (Apache-2.0). Their terms and availability aren't Sinkhole's to
  control, so both are fetched at run time and never bundled.
- **One Python script** — pfSense's DNS Resolver runs a single Python script, and
  pfBlockerNG's DNS blocking uses the same slot, so the two can't block DNS at the same
  time.
- **Per-device answers and Unbound's cache** — Unbound answers cached names before any
  module sees them. Names on a list are never cached, so one device's answer can't reach
  another.
- **Bypass** — DNS-over-HTTPS, hardcoded resolvers and VPNs can get around DNS blocking, and
  a redirect on the DNS port can't catch DNS-over-HTTPS.
- **Privacy** — Blocks and alerts reveal what people try to visit, so that data stays on the
  firewall apart from the notifications an administrator sets up.

### Open Questions

- How the redirect treats DNS-over-TLS and DNS-over-HTTPS.

### Roadmap

1. Saved lists, so DNS answers right after a restart or reload, starting with global lists.
2. Per-VLAN and per-device lists.
3. Alerts for chosen lists, VLANs and devices.
4. The optional DNS redirect.
5. The popular-list search.
6. IP and country blocking.
7. The WebGUI and the docs in pfSense's 18 languages, once the WebGUI's wording is final.

The first three are the core. If time runs short, IP and country blocking waits first,
then the popular-list search, since administrators can still paste list URLs.

### Success Criteria

- Jacky replaces his own Unbound setup and DNS redirect rules with Sinkhole.
- A restart or reload no longer takes DNS down.
- Kids, guests and employees each get the lists meant for them, and alerts arrive only
  where they were set.
- Failure looks like restarts that still wait on downloads, or per-VLAN lists that still
  need hand-written configuration.

## Marketing Copy

### Tagline

Peace of mind for parents and employers, right inside pfSense.

### Elevator Pitch

Sinkhole blocks unwanted websites on your pfSense network, with separate block lists for
each network or device. It keeps the lists on the firewall, so DNS answers right after a
restart or reload while updates download in the background. Alerts come through pfSense's
own notifications, only for the lists, networks and devices you choose. An optional
redirect keeps devices from going around it, and IP and country blocking are there when you
need them.

### Key Features

- **Lists for every scope** — Give the whole network, a VLAN or a single device its own
  block lists.
- **No waiting after a restart** — Saved lists answer DNS right away while new ones download.
- **Alerts you choose** — Get a pfSense notification only for the lists, networks and
  devices you pick.
- **Built-in redirect** — Send every device's DNS to the firewall without hand-made rules.
- **Popular-list search** — Find widely used block lists from the WebGUI.
- **IP and country blocking** — Block by address or country when DNS blocking isn't enough.

### Voice

- **Use** — "block list", "network" or "VLAN", "device", "in control", "peace of mind",
  and plain descriptions of what happens.
- **Avoid** — Promises of complete protection, since DNS blocking can be bypassed; naming or
  recommending specific block lists; hype words such as "revolutionary"; hand-holding labels
  such as "Recommended".

## Glossary

| Term                | Definition                                                                         |
|---------------------|------------------------------------------------------------------------------------|
| DNS sinkhole        | Answering a blocked name with an address that leads nowhere, so the request stops. |
| DNS Resolver        | pfSense's Unbound-based DNS service.                                               |
| Block list          | A list of names or addresses to block, added by URL or from the search.            |
| Saved list          | The last good copy of a block list, kept on the firewall.                          |
| Scope               | Where a block list applies: the whole network, a VLAN or a single device.          |
| Global lists        | Block lists that apply to every client on the network.                             |
| Alert rule          | A list and scope whose blocks send a pfSense notification.                         |
| DNS redirect        | The optional setting that sends devices' DNS queries to the firewall.              |
| Popular-list search | The WebGUI search of widely used block lists, like AdGuard Home's picker.          |

## Additional Vision Notes

### Notifications and ntfy

Sinkhole sends alerts only through pfSense's notification system. Administrators who want
alerts in ntfy can receive them through ntfy-reverse-proxy, Jacky's companion project.
