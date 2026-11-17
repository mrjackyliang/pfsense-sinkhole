# pfsense-pkg-sinkhole

## 1.2.1 - 2026-11-17

### FIXED
- An update installed from the About tab now shows as installed once pfSense reports the new version, instead of spinning on "Installing version" when the install replaced the package before the update could finish.
- IP lists published as one JSON object per line, such as the Spamhaus DROP feeds that the pfBlockerNG catalog now links to, load their networks from each "cidr" field instead of failing with "The download contains no valid IP networks."

## 1.2.0 - 2026-11-17

### UPDATED
- The Lists box on a network or device scope can be dragged taller to show more lists.
- Add from Catalog is now a button next to Add under the Lists, IP and Bypass tables, replacing the mostly empty panel at the bottom of each page.
- Block and Bypass names now load from a memory-mapped index, raising the limit from 2 million to 10 million unique names at about 18 bytes each, and Status shows Compiled Names against the limit.
- New lists, including ones added from the catalog, start with Global unticked.

### FIXED
- DNS Redirect loads its rules whenever Sinkhole and the DNS Resolver are running, even while pfBlockerNG or another script holds the Resolver's Python Module, and Status and the Bypass tab warn when Redirect is on but not loaded.
- Changing a list's URL now discards the copy saved from the old URL, even when the first download from the new URL fails.
- The notes under the Safe Addresses and Devices tables now show as info boxes below the panel, like the rest of pfSense.

### ADDED
- An Update Log on the Status page that follows each update live, from downloads through deploy, with no refreshing.
- Exempt Sources and Exempt Destinations for the Bypass blocks (TLS and QUIC, Providers, Tor, VPN providers, standard VPN ports), taking addresses, networks, or aliases.

## 1.1.0 - 2026-11-16

### UPDATED
- Sinkhole stays inactive while pfBlockerNG is installed and enabled, including when its DNSBL runs in Unbound mode.

### FIXED
- Korean on pfSense Plus (ko_KR) now shows Sinkhole's pages in Korean instead of English.

### ADDED
- A Resolver section on the General tab sets rebind exceptions (such as plex.direct) and the expired-answer lifetime and wait, written into Sinkhole's managed Custom options block.
- A SafeSearch tab locks Google (every country domain), YouTube (Moderate or Strict), Bing, DuckDuckGo, Brave Search, Startpage, Ecosia, Yandex and Pixabay into their safe modes per scope, and can block Qwant.

## 1.0.2 - 2026-11-11

### FIXED
- A failed RAM-disk boot restore is written to the system log under `sinkhole` and raises a pfSense notice once Sinkhole starts, instead of failing silently.

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
