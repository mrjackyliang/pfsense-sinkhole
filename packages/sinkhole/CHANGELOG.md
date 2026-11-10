# pfsense-pkg-sinkhole

## 1.0.1 - 2026-11-10

### UPDATED
- Release packages are built, signed, and attached to the GitHub release by the same publish workflow that deploys the documentation.

## 1.0.0 - 2026-11-10

### ADDED
- One package that installs on any supported pfSense release, marked vital so pfSense upgrades keep it installed; remove it with pkg delete -f.
- A guard that leaves the DNS Resolver's Python module to pfBlockerNG's DNSBL when it owns it, and removal that restores the previous DNS Resolver settings, with a Keep Settings option that keeps lists and settings.
- A Status tab with the deployment, list update, scope, alert, Bypass, IP, and service state, and an About tab with the package version, project links, the pfSense releases each version was tested on, and ways to support the project.
- Alerts for blocked lookups on chosen lists, networks, or devices, sent once per device and domain through pfSense notifications.
- A Services tab that blocks whole services per scope from a public services registry, cached on the firewall so list updates never wait on the network.
- A catalog search for popular DNS and IP block lists, fetched at run time and shown as cards grouped by category or maintainer.
- Update checks that raise a pfSense notification and an Update button on the About tab that installs the latest release after checking its SHA-256 and its signature.
- Package-owned WebGUI, status, notification, and runtime translations for all 18 pfSense language choices.
- Saved copies of every list, so DNS answers from the last good data right after a DNS Resolver restart or a reboot, RAM-disk installs included, and a failed download keeps the previous copy.
- Network and device scopes, so each network gets the global lists plus its own and each device, matched by IP address, DHCP static mapping, or MAC address, gets its network's lists plus its own, with allowed domains at every level.
- IP and country blocking with IP lists and MaxMind GeoLite2 country data under the administrator's own license key, loaded into a Sinkhole firewall anchor that stays in place across filter reloads.
- A native installable pfSense package that blocks domains through the DNS Resolver using block lists in hosts, plain domain, and adblock formats, answers blocked names with 0.0.0.0 and ::, and loads new list data without restarting the DNS Resolver.
- A Bypass tab, with everything off by default, that keeps devices on chosen interfaces from going around Sinkhole: it can send plain DNS to the firewall, block DNS over TLS and QUIC to other servers, block encrypted-DNS providers, Tor relays and VPN providers from lists the admin adds by URL or from the Bypass catalog, block standard VPN ports, turn off Firefox's automatic DNS over HTTPS and iCloud Private Relay, and answer encrypted-DNS discovery.
