"""Sinkhole Unbound Python module.

The module loads only compiler-owned chroot files and never performs network I/O.

Since: UNRELEASED
"""

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import threading
import time
from typing import Any, Final


DATA_DIRECTORY: Final[str] = "sinkhole"
MANIFEST_PATH = os.path.join(DATA_DIRECTORY, "manifest.json")
DOMAINS_PATH = os.path.join(DATA_DIRECTORY, "domains.tsv")
BYPASS_PATH = os.path.join(DATA_DIRECTORY, "bypass.tsv")
ALLOW_PATH = os.path.join(DATA_DIRECTORY, "allow.txt")
GENERATION_PATH = os.path.join(DATA_DIRECTORY, "generation")
LOADED_GENERATION_PATH = os.path.join("sinkhole-state", "loaded")
EVENTS_PATH = os.path.join("sinkhole-state", "events")
EVENTS_DROPPED_PATH = os.path.join("sinkhole-state", "events-dropped")
CLIENT_MAP_PATH = os.path.join("sinkhole-clients", "clients.json")
WATCH_INTERVAL_SECONDS: Final[float] = 2.0
BLOCK_TTL_SECONDS: Final[int] = 60
MAXIMUM_UNIQUE_NAMES: Final[int] = 2_000_000
MAXIMUM_CLIENT_MAP_BYTES: Final[int] = 4_194_304
MAXIMUM_EVENT_FILE_BYTES: Final[int] = 1_048_576
MAXIMUM_QUEUED_EVENTS: Final[int] = 10_000
CLIENT_LOOKUP_CACHE_SIZE: Final[int] = 4_096
MANIFEST_SCHEMA_VERSION: Final[int] = 3
CLIENT_MAP_SCHEMA_VERSION: Final[int] = 2
STASH_VERSION: Final[int] = 4
STASH_ATTRIBUTE: Final[str] = "_sinkhole_unbound_policy_stash"
BYPASS_KIND_BITS: Final[dict[str, int]] = {
    "encrypted_dns": 1,
    "tor": 2,
    "vpn": 4,
}
FIREFOX_DOH_SIGNAL: Final[str] = "use-application-dns.net"
PRIVATE_RELAY_SIGNALS: Final[frozenset[str]] = frozenset(
    ("mask.icloud.com", "mask-h2.icloud.com")
)
DDR_NAME: Final[str] = "_dns.resolver.arpa"
RR_TYPE_SVCB_VALUE: Final[int] = 64
_COMPILED_NAME_PATTERN = re.compile(
    r"(?=.{1,253}\Z)"
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z"
)


class _LoadStopped(Exception):
    """Internal loader cancellation signal."""


class SinkholeData:
    """Immutable compiled policy shared by query callbacks."""

    __slots__ = (
        "generation",
        "domains",
        "allowed",
        "global_mask",
        "network_allowed",
        "network_masks",
        "device_allowed",
        "device_masks",
        "bypass_domains",
        "bypass_interfaces",
        "bypass_enabled_mask",
        "disable_firefox_doh",
        "disable_private_relay",
        "discovery",
        "discovery_hostname",
        "discovery_port",
        "list_count",
        "list_ids_by_bit",
        "alert_rules",
    )

    def __init__(
        self,
        generation: str,
        domains: dict[str, tuple[int, int]],
        allowed: frozenset[str],
        global_mask: int,
        network_allowed: dict[str, frozenset[str]],
        network_masks: dict[str, int],
        device_allowed: dict[str, frozenset[str]],
        device_masks: dict[str, int],
        bypass_domains: dict[str, tuple[int, int]],
        bypass_interfaces: frozenset[str],
        bypass_enabled_mask: int,
        disable_firefox_doh: bool,
        disable_private_relay: bool,
        discovery: str,
        discovery_hostname: str,
        discovery_port: int,
        list_count: int,
        list_ids_by_bit: tuple[str, ...],
        alert_rules: tuple[
            tuple[
                str,
                int | None,
                frozenset[str] | None,
                frozenset[str] | None,
            ],
            ...,
        ],
    ) -> None:
        """Initialize one complete policy generation."""

        self.generation = generation
        self.domains = domains
        self.allowed = allowed
        self.global_mask = global_mask
        self.network_allowed = network_allowed
        self.network_masks = network_masks
        self.device_allowed = device_allowed
        self.device_masks = device_masks
        self.bypass_domains = bypass_domains
        self.bypass_interfaces = bypass_interfaces
        self.bypass_enabled_mask = bypass_enabled_mask
        self.disable_firefox_doh = disable_firefox_doh
        self.disable_private_relay = disable_private_relay
        self.discovery = discovery
        self.discovery_hostname = discovery_hostname
        self.discovery_port = discovery_port
        self.list_count = list_count
        self.list_ids_by_bit = list_ids_by_bit
        self.alert_rules = alert_rules

    def match(self, name: str) -> tuple[bool, bool]:
        """Return whether ``name`` is listed and blocked in the global scope."""

        listed_mask = 0
        exact_masks = self.domains.get(name)

        if exact_masks is not None:
            listed_mask |= exact_masks[0]

        for candidate in _parents(name):
            masks = self.domains.get(candidate)

            if masks is not None:
                listed_mask |= masks[1]

        return listed_mask != 0, (listed_mask & self.global_mask) != 0

    def is_allowed(self, name: str) -> bool:
        """Return whether ``name`` or one of its parents is allowed."""

        return any(candidate in self.allowed for candidate in _parents(name))

    def listed_mask(self, name: str) -> int:
        """Return all exact and subtree list memberships for one name."""

        listed_mask = 0
        exact_masks = self.domains.get(name)

        if exact_masks is not None:
            listed_mask |= exact_masks[0]

        for candidate in _parents(name):
            masks = self.domains.get(candidate)

            if masks is not None:
                listed_mask |= masks[1]

        return listed_mask

    def is_listed(self, name: str) -> bool:
        """Return whether a name appears in any compiled scope list."""

        return self.listed_mask(name) != 0

    def bypass_mask(self, name: str) -> int:
        """Return exact and inherited Bypass List kind memberships."""

        listed_mask = 0
        exact_masks = self.bypass_domains.get(name)

        if exact_masks is not None:
            listed_mask |= exact_masks[0]

        for candidate in _parents(name):
            masks = self.bypass_domains.get(candidate)

            if masks is not None:
                listed_mask |= masks[1]

        return listed_mask

    def is_bypass_listed(self, name: str) -> bool:
        """Return whether a name occurs in effective Bypass List data."""

        return self.bypass_mask(name) != 0

    def bypass_signal_action(
        self,
        name: str,
        interface_name: str | None,
    ) -> str | None:
        """Return the mandatory interface-scoped signal answer, if any."""

        if name == DDR_NAME and self.discovery != "off":
            if interface_name not in self.bypass_interfaces:
                return "nxdomain"

            if self.discovery == "nodata":
                return "nodata"

            if self.discovery == "advertise":
                return "svcb"

        if interface_name not in self.bypass_interfaces:
            return None

        if self.disable_firefox_doh and (
            name == FIREFOX_DOH_SIGNAL
            or name.endswith("." + FIREFOX_DOH_SIGNAL)
        ):
            return "nxdomain"

        if self.disable_private_relay and name in PRIVATE_RELAY_SIGNALS:
            return "nxdomain"

        return None

    def bypass_blocks_name(
        self,
        name: str,
        interface_name: str | None,
    ) -> bool:
        """Return whether an effective Bypass List blocks this interface client."""

        return (
            interface_name in self.bypass_interfaces
            and self.bypass_mask(name) & self.bypass_enabled_mask != 0
        )

    def has_bypass_policy_name(self, name: str) -> bool:
        """Return whether cache storage could bypass an interface decision."""

        return (
            self.is_bypass_listed(name)
            or (
                self.disable_firefox_doh
                and (
                    name == FIREFOX_DOH_SIGNAL
                    or name.endswith("." + FIREFOX_DOH_SIGNAL)
                )
            )
            or (self.disable_private_relay and name in PRIVATE_RELAY_SIGNALS)
            or (self.discovery != "off" and name == DDR_NAME)
        )

    def decision(
        self,
        name: str,
        device_id: str | None,
        network_id: str | None,
    ) -> str:
        """Apply device, network, and global policy in binding precedence order."""

        return self.decision_details(name, device_id, network_id)[0]

    def decision_details(
        self,
        name: str,
        device_id: str | None,
        network_id: str | None,
    ) -> tuple[str, int]:
        """Return the decision and list mask at the deciding policy level."""

        listed_mask = self.listed_mask(name)

        if device_id in self.device_masks:
            if _name_is_allowed(name, self.device_allowed[device_id]):
                return "allow", 0

            blocking_mask = listed_mask & self.device_masks[device_id]

            if blocking_mask:
                return "block", blocking_mask

        if network_id in self.network_masks:
            if _name_is_allowed(name, self.network_allowed[network_id]):
                return "allow", 0

            blocking_mask = listed_mask & self.network_masks[network_id]

            if blocking_mask:
                return "block", blocking_mask

        if _name_is_allowed(name, self.allowed):
            return "allow", 0

        blocking_mask = listed_mask & self.global_mask

        if blocking_mask:
            return "block", blocking_mask

        return "pass", 0

    def matching_alerts(
        self,
        blocking_mask: int,
        device_id: str | None,
        network_id: str | None,
    ) -> tuple[str, ...]:
        """Return enabled compiled rules matching one blocked decision."""

        matched: list[str] = []

        for rule_id, list_mask, networks, devices in self.alert_rules:
            if list_mask is not None and blocking_mask & list_mask == 0:
                continue

            if networks is None and devices is None:
                matched.append(rule_id)
                continue

            if (
                (device_id is not None and devices is not None and device_id in devices)
                or (
                    network_id is not None
                    and networks is not None
                    and network_id in networks
                )
            ):
                matched.append(rule_id)

        return tuple(matched)

    def blocking_list_ids(self, blocking_mask: int) -> tuple[str, ...]:
        """Translate one deciding mask back to stable list identifiers."""

        return tuple(
            identifier
            for bit, identifier in enumerate(self.list_ids_by_bit)
            if blocking_mask & (1 << bit)
        )


class ClientMapData:
    """Validated client addresses and longest-prefix network assignments."""

    __slots__ = ("digest", "devices", "networks", "interfaces")

    def __init__(
        self,
        digest: str | None,
        devices: dict[str, str],
        networks: tuple[tuple[Any, str], ...],
        interfaces: tuple[tuple[Any, str], ...],
    ) -> None:
        """Initialize one immutable-enough map published by the watcher."""

        self.digest = digest
        self.devices = devices
        self.networks = networks
        self.interfaces = interfaces


def _empty_client_map() -> ClientMapData:
    """Return a map that assigns no client to a configured scope."""

    return ClientMapData(None, {}, (), ())


_active_data: Any | None = None
_generation_id: str | None = None
_failed_generation_id: str | None = None
_last_reload_error: str | None = None
_reload_lock = threading.Lock()
_loader_thread: threading.Thread | None = None
_watcher_thread: threading.Thread | None = None
_stop_event = threading.Event()
_lifecycle_token = object()
_query_response_error_logged = False
_active_client_map: Any = _empty_client_map()
_client_map_digest: str | None = None
_last_client_map_error: str | None = None
_client_lookup_cache: dict[
    str,
    tuple[str | None, str | None, str | None],
] = {}
_event_lock = threading.Lock()
_event_queue: list[dict[str, Any]] = []
_events_dropped = 0
_persisted_events_dropped = 0


def _parents(name: str) -> tuple[str, ...]:
    """Return parent candidates from most specific to least specific."""

    labels = name.split(".")

    return tuple(".".join(labels[index:]) for index in range(len(labels)))


def _name_is_allowed(name: str, allowed: frozenset[str]) -> bool:
    """Return whether a name or one of its parents is in one allow set."""

    return any(candidate in allowed for candidate in _parents(name))


def _normalize_query_name(value: Any) -> str | None:
    """Normalize a live query name without rejecting unusual child labels."""

    if not isinstance(value, str):
        return None

    name = value.lower().rstrip(".")

    if name == "" or len(name) > 253:
        return None

    return name


def _normalize_compiled_name(value: Any) -> str | None:
    """Validate one compiler name with the PHP parser's anchored rules."""

    if not isinstance(value, str) or _COMPILED_NAME_PATTERN.fullmatch(value) is None:
        return None

    return value


def _read_generation() -> str:
    """Read and validate the generation stamp content."""

    with open(GENERATION_PATH, "r", encoding="ascii") as generation_file:
        generation = generation_file.read(256).strip()

    if generation == "":
        raise ValueError("the generation stamp is empty")

    return generation


def _mask_for_bits(
    value: str,
    valid_bits: frozenset[int],
    cache: dict[str, int] | None = None,
) -> int:
    """Convert a validated bit column to a mask, memoizing repeated columns."""

    if cache is not None and value in cache:
        return cache[value]

    if value == "":
        mask = 0
    else:
        mask = 0
        seen_bits: set[int] = set()

        for raw_bit in value.split(","):
            if raw_bit == "" or not raw_bit.isascii() or not raw_bit.isdecimal():
                raise ValueError("a domain row references an invalid list bit")

            bit = int(raw_bit)

            if str(bit) != raw_bit or bit not in valid_bits or bit in seen_bits:
                raise ValueError("a domain row references an invalid list bit")

            seen_bits.add(bit)
            mask |= 1 << bit

    if cache is not None:
        cache[value] = mask

    return mask


def _mask_for_bypass_kinds(value: str, enabled_mask: int) -> int:
    """Convert a compiler kind column to a validated bit mask."""

    if value == "":
        return 0

    mask = 0
    previous = ""

    for kind in value.split(","):
        bit = BYPASS_KIND_BITS.get(kind)

        if bit is None or kind <= previous or mask & bit != 0:
            raise ValueError("a Bypass domain row references an invalid kind")

        if enabled_mask & bit == 0:
            raise ValueError("a Bypass domain row references a disabled kind")

        previous = kind
        mask |= bit

    return mask


def _load_bypass_manifest(
    value: Any,
) -> tuple[
    frozenset[str],
    int,
    bool,
    bool,
    str,
    str,
    int,
]:
    """Validate interface-scoped Bypass answer metadata."""

    if not isinstance(value, dict):
        raise ValueError("the manifest Bypass configuration is invalid")

    interfaces = value.get("interfaces")

    if (
        not isinstance(interfaces, list)
        or any(
            not isinstance(interface, str)
            or re.fullmatch(r"[a-z0-9_.:-]{1,64}", interface, re.IGNORECASE)
            is None
            for interface in interfaces
        )
        or len(set(interfaces)) != len(interfaces)
    ):
        raise ValueError("the manifest Bypass interfaces are invalid")

    boolean_fields = (
        "block_encrypted_dns",
        "disable_firefox_doh",
        "disable_private_relay",
        "block_tor",
        "block_vpn",
    )

    if any(not isinstance(value.get(field), bool) for field in boolean_fields):
        raise ValueError("the manifest Bypass flags are invalid")

    discovery = value.get("discovery")
    hostname = value.get("discovery_hostname")
    port = value.get("discovery_port")

    if (
        discovery not in ("off", "nodata", "advertise")
        or not isinstance(hostname, str)
        or not isinstance(port, int)
        or isinstance(port, bool)
    ):
        raise ValueError("the manifest Discovery configuration is invalid")

    if discovery == "advertise":
        if _normalize_compiled_name(hostname) != hostname or port != 853:
            raise ValueError("the manifest Discovery endpoint is invalid")
    elif hostname != "" or port != 0:
        raise ValueError("an inactive Discovery endpoint must be empty")

    enabled_mask = 0

    if value["block_encrypted_dns"]:
        enabled_mask |= BYPASS_KIND_BITS["encrypted_dns"]

    if value["block_tor"]:
        enabled_mask |= BYPASS_KIND_BITS["tor"]

    if value["block_vpn"]:
        enabled_mask |= BYPASS_KIND_BITS["vpn"]

    return (
        frozenset(interfaces),
        enabled_mask,
        value["disable_firefox_doh"],
        value["disable_private_relay"],
        discovery,
        hostname,
        port,
    )


def _check_stopped(stop_event: threading.Event | None, row_number: int) -> None:
    """Cancel a background loader at bounded 10,000-row checkpoints."""

    if row_number % 10_000 == 0 and stop_event is not None and stop_event.is_set():
        raise _LoadStopped()


def _scope_mask(value: Any, bits: dict[str, int], description: str) -> int:
    """Validate one scope list selection and convert it to a bit mask."""

    if not isinstance(value, list) or any(
        not isinstance(identifier, str) for identifier in value
    ):
        raise ValueError(f"the {description} scope is invalid")

    mask = 0
    seen: set[str] = set()

    for identifier in value:
        bit = bits.get(identifier)

        if bit is None or identifier in seen:
            raise ValueError(f"the {description} scope references an unknown list")

        seen.add(identifier)
        mask |= 1 << bit

    return mask


def _allow_path(filename: Any) -> str:
    """Validate a compiler-owned allow filename and resolve it in the generation."""

    if (
        not isinstance(filename, str)
        or re.fullmatch(
            r"allow(?:-(?:network|device)-[a-f0-9]{32})?\.txt",
            filename,
        )
        is None
    ):
        raise ValueError("a scope allow filename is invalid")

    if filename == os.path.basename(ALLOW_PATH):
        return ALLOW_PATH

    return os.path.join(DATA_DIRECTORY, filename)


def _read_allowed(
    filename: Any,
    stop_event: threading.Event | None,
) -> frozenset[str]:
    """Load one normalized compiler-owned scope allow file."""

    allowed: set[str] = set()

    with open(_allow_path(filename), "r", encoding="ascii") as allow_file:
        for line_number, line in enumerate(allow_file, start=1):
            _check_stopped(stop_event, line_number)
            raw_domain = line.rstrip("\r\n")

            if raw_domain == "":
                continue

            domain = _normalize_compiled_name(raw_domain)

            if domain is None:
                raise ValueError(f"allow row {line_number} is invalid")

            allowed.add(domain)

    return frozenset(allowed)


def _load_scope_group(
    value: Any,
    bits: dict[str, int],
    kind: str,
) -> tuple[dict[str, int], dict[str, Any]]:
    """Validate network or device manifest scopes without loading allow files yet."""

    if not isinstance(value, dict):
        raise ValueError(f"the {kind} scope map is invalid")

    masks: dict[str, int] = {}
    allow_files: dict[str, Any] = {}

    for identifier, scope in value.items():
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[a-f0-9]{32}", identifier) is None
            or not isinstance(scope, dict)
        ):
            raise ValueError(f"the {kind} scope map is invalid")

        if kind == "network" and (
            not isinstance(scope.get("interface"), str)
            or scope.get("interface") == ""
        ):
            raise ValueError("a network scope interface is invalid")

        masks[identifier] = _scope_mask(scope.get("lists"), bits, kind)
        allow_files[identifier] = scope.get("allow")

    return masks, allow_files


def _load_alerts(
    value: Any,
    valid_bits: frozenset[int],
    network_ids: frozenset[str],
    device_ids: frozenset[str],
) -> tuple[
    tuple[
        str,
        int | None,
        frozenset[str] | None,
        frozenset[str] | None,
    ],
    ...,
]:
    """Validate compiled alert rules and build immutable matching records."""

    if value is None:
        return ()

    if not isinstance(value, dict):
        raise ValueError("the manifest alert map is invalid")

    rules: list[
        tuple[
            str,
            int | None,
            frozenset[str] | None,
            frozenset[str] | None,
        ]
    ] = []

    for identifier, record in value.items():
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[a-f0-9]{32}", identifier) is None
            or not isinstance(record, dict)
            or record.get("id") != identifier
        ):
            raise ValueError("the manifest alert map is invalid")

        raw_lists = record.get("lists")

        if raw_lists == "any":
            list_mask = None
        elif isinstance(raw_lists, list):
            list_mask = 0
            seen_bits: set[int] = set()

            for bit in raw_lists:
                if (
                    not isinstance(bit, int)
                    or isinstance(bit, bool)
                    or bit not in valid_bits
                    or bit in seen_bits
                ):
                    raise ValueError("an alert rule list selection is invalid")

                seen_bits.add(bit)
                list_mask |= 1 << bit

            if list_mask == 0:
                raise ValueError("an alert rule has no effective block list")
        else:
            raise ValueError("an alert rule list selection is invalid")

        raw_networks = record.get("networks")
        raw_devices = record.get("devices")

        if raw_networks == "any" and raw_devices == "any":
            networks = None
            devices = None
        elif isinstance(raw_networks, list) and isinstance(raw_devices, list):
            if (
                any(not isinstance(value, str) for value in raw_networks)
                or any(not isinstance(value, str) for value in raw_devices)
                or len(set(raw_networks)) != len(raw_networks)
                or len(set(raw_devices)) != len(raw_devices)
                or any(value not in network_ids for value in raw_networks)
                or any(value not in device_ids for value in raw_devices)
                or (len(raw_networks) == 0 and len(raw_devices) == 0)
            ):
                raise ValueError("an alert rule client selection is invalid")

            networks = frozenset(raw_networks)
            devices = frozenset(raw_devices)
        else:
            raise ValueError("an alert rule client selection is invalid")

        rules.append((identifier, list_mask, networks, devices))

    return tuple(rules)


def _load_data(stop_event: threading.Event | None = None) -> SinkholeData:
    """Parse and validate one complete compiler generation."""

    generation_before = _read_generation()

    with open(MANIFEST_PATH, "r", encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)

    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION
    ):
        raise ValueError("the manifest schema is unsupported")

    if manifest.get("generation") != generation_before:
        raise ValueError("the manifest and generation stamp do not match")

    if manifest.get("bypass_file") != os.path.basename(BYPASS_PATH):
        raise ValueError("the manifest Bypass filename is invalid")

    manifest_domain_count = manifest.get("domain_count")

    if (
        not isinstance(manifest_domain_count, int)
        or isinstance(manifest_domain_count, bool)
        or manifest_domain_count < 0
        or manifest_domain_count > MAXIMUM_UNIQUE_NAMES
    ):
        raise ValueError("the manifest domain count is invalid")

    manifest_bypass_domain_count = manifest.get("bypass_domain_count")

    if (
        not isinstance(manifest_bypass_domain_count, int)
        or isinstance(manifest_bypass_domain_count, bool)
        or manifest_bypass_domain_count < 0
        or manifest_bypass_domain_count > MAXIMUM_UNIQUE_NAMES
        or manifest_domain_count + manifest_bypass_domain_count
        > MAXIMUM_UNIQUE_NAMES
    ):
        raise ValueError("the manifest Bypass domain count is invalid")

    (
        bypass_interfaces,
        bypass_enabled_mask,
        disable_firefox_doh,
        disable_private_relay,
        discovery,
        discovery_hostname,
        discovery_port,
    ) = _load_bypass_manifest(manifest.get("bypass"))

    manifest_lists = manifest.get("lists")

    if not isinstance(manifest_lists, dict):
        raise ValueError("the manifest list map is invalid")

    bits: dict[str, int] = {}

    for identifier, list_record in manifest_lists.items():
        if (
            not isinstance(identifier, str)
            or len(identifier) != 32
            or any(character not in "0123456789abcdef" for character in identifier)
            or not isinstance(list_record, dict)
        ):
            raise ValueError("the manifest list map is invalid")

        bit = list_record.get("bit")

        if (
            not isinstance(bit, int)
            or isinstance(bit, bool)
            or bit < 0
            or bit >= len(manifest_lists)
            or bit in bits.values()
        ):
            raise ValueError("the manifest list bit is invalid")

        bits[identifier] = bit

    scopes = manifest.get("scopes")

    if not isinstance(scopes, dict):
        raise ValueError("the manifest scope map is invalid")

    global_scope = scopes.get("global")

    if not isinstance(global_scope, dict):
        raise ValueError("the global scope is invalid")

    global_mask = _scope_mask(global_scope.get("lists"), bits, "global")
    network_masks, network_allow_files = _load_scope_group(
        scopes.get("networks"),
        bits,
        "network",
    )
    device_masks, device_allow_files = _load_scope_group(
        scopes.get("devices"),
        bits,
        "device",
    )

    valid_bits = frozenset(bits.values())
    try:
        alerts = _load_alerts(
            manifest.get("alerts"),
            valid_bits,
            frozenset(network_masks),
            frozenset(device_masks),
        )
    except BaseException as exception:
        alerts = ()
        _log_reload_error(
            f"alert rules disabled: {_failure_message(exception)}"
        )
    mask_cache: dict[str, int] = {}
    mask_tuples: dict[tuple[int, int], tuple[int, int]] = {}
    domains: dict[str, tuple[int, int]] = {}

    with open(DOMAINS_PATH, "r", encoding="ascii") as domains_file:
        for line_number, line in enumerate(domains_file, start=1):
            _check_stopped(stop_event, line_number)

            if len(domains) >= MAXIMUM_UNIQUE_NAMES:
                raise ValueError("the domains file exceeds the unique-name limit")

            fields = line.rstrip("\r\n").split("\t")

            if len(fields) != 3:
                raise ValueError(f"domain row {line_number} is invalid")

            domain = _normalize_compiled_name(fields[0])

            if domain is None or domain in domains:
                raise ValueError(f"domain row {line_number} is invalid")

            exact_mask = _mask_for_bits(fields[1], valid_bits, mask_cache)
            subtree_mask = _mask_for_bits(fields[2], valid_bits, mask_cache)

            if exact_mask == 0 and subtree_mask == 0:
                raise ValueError(f"domain row {line_number} has no list membership")

            masks = (exact_mask, subtree_mask)
            domains[domain] = mask_tuples.setdefault(masks, masks)

    if stop_event is not None and stop_event.is_set():
        raise _LoadStopped()

    if len(domains) != manifest_domain_count:
        raise ValueError("the manifest domain count does not match the domains file")

    bypass_masks: dict[tuple[int, int], tuple[int, int]] = {}
    bypass_domains: dict[str, tuple[int, int]] = {}

    with open(BYPASS_PATH, "r", encoding="ascii") as bypass_file:
        for line_number, line in enumerate(bypass_file, start=1):
            _check_stopped(stop_event, line_number)

            if len(domains) + len(bypass_domains) >= MAXIMUM_UNIQUE_NAMES:
                raise ValueError("the Bypass file exceeds the unique-name limit")

            fields = line.rstrip("\r\n").split("\t")

            if len(fields) != 3:
                raise ValueError(f"Bypass row {line_number} is invalid")

            domain = _normalize_compiled_name(fields[0])

            if domain is None or domain in bypass_domains:
                raise ValueError(f"Bypass row {line_number} is invalid")

            exact_mask = _mask_for_bypass_kinds(fields[1], bypass_enabled_mask)
            subtree_mask = _mask_for_bypass_kinds(fields[2], bypass_enabled_mask)

            if exact_mask == 0 and subtree_mask == 0:
                raise ValueError(
                    f"Bypass row {line_number} has no kind membership"
                )

            masks = (exact_mask, subtree_mask)
            bypass_domains[domain] = bypass_masks.setdefault(masks, masks)

    if len(bypass_domains) != manifest_bypass_domain_count:
        raise ValueError(
            "the manifest Bypass domain count does not match the Bypass file"
        )

    allowed = _read_allowed(global_scope.get("allow"), stop_event)
    network_allowed = {
        identifier: _read_allowed(filename, stop_event)
        for identifier, filename in network_allow_files.items()
    }
    device_allowed = {
        identifier: _read_allowed(filename, stop_event)
        for identifier, filename in device_allow_files.items()
    }

    if stop_event is not None and stop_event.is_set():
        raise _LoadStopped()

    generation_after = _read_generation()

    if generation_after != generation_before:
        raise ValueError("the compiler generation changed during load")

    return SinkholeData(
        generation=generation_before,
        domains=domains,
        allowed=allowed,
        global_mask=global_mask,
        network_allowed=network_allowed,
        network_masks=network_masks,
        device_allowed=device_allowed,
        device_masks=device_masks,
        bypass_domains=bypass_domains,
        bypass_interfaces=bypass_interfaces,
        bypass_enabled_mask=bypass_enabled_mask,
        disable_firefox_doh=disable_firefox_doh,
        disable_private_relay=disable_private_relay,
        discovery=discovery,
        discovery_hostname=discovery_hostname,
        discovery_port=discovery_port,
        list_count=len(bits),
        list_ids_by_bit=tuple(
            identifier
            for identifier, _bit in sorted(bits.items(), key=lambda item: item[1])
        ),
        alert_rules=alerts,
    )


def _log_loaded(prefix: str, data: Any) -> None:
    """Log a bounded generation summary."""

    log_info(
        "sinkhole: "
        f"{prefix} generation {data.generation}, "
        f"{data.list_count} lists, {len(data.domains)} domains, "
        f"{len(data.bypass_domains)} Bypass domains, "
        f"{len(data.allowed)} allowed domains"
    )


def _log_reload_error(message: str) -> None:
    """Log a repeated loader or callback error only once."""

    global _last_reload_error

    if message == _last_reload_error:
        return

    _last_reload_error = message
    log_info(f"sinkhole: {message}")


def _failure_message(exception: BaseException) -> str:
    """Return a bounded, non-empty exception summary."""

    try:
        detail = str(exception)
    except BaseException:
        detail = exception.__class__.__name__

    if detail == "":
        detail = exception.__class__.__name__

    return detail[:500]


def _clear_client_lookup_cache() -> None:
    """Discard bounded address decisions after either runtime input changes."""

    _client_lookup_cache.clear()


def _normalize_client_address(value: Any) -> tuple[str, Any]:
    """Parse one client address and collapse IPv4-mapped IPv6 to IPv4."""

    if not isinstance(value, str):
        raise ValueError("a client map address is invalid")

    address = ipaddress.ip_address(value)

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped

    return str(address), address


def _read_client_map_document() -> dict[str, Any]:
    """Read and digest-check one bounded regular client map document."""

    path_status = os.lstat(CLIENT_MAP_PATH)

    if not stat.S_ISREG(path_status.st_mode) or path_status.st_size > MAXIMUM_CLIENT_MAP_BYTES:
        raise ValueError("the client map is missing, unsafe, or oversized")

    with open(CLIENT_MAP_PATH, "r", encoding="utf-8") as client_file:
        document = json.load(client_file)

    if (
        not isinstance(document, dict)
        or document.get("schema_version") != CLIENT_MAP_SCHEMA_VERSION
    ):
        raise ValueError("the client map schema is unsupported")

    generated_at = document.get("generated_at")
    digest = document.get("content_digest")
    networks = document.get("networks")
    interfaces = document.get("interfaces")
    devices = document.get("devices")
    conflicts = document.get("conflicts")

    if (
        not isinstance(generated_at, str)
        or generated_at == ""
        or not isinstance(digest, str)
        or re.fullmatch(r"[a-f0-9]{64}", digest) is None
        or not isinstance(networks, list)
        or not isinstance(interfaces, list)
        or not isinstance(devices, dict)
        or not isinstance(conflicts, list)
    ):
        raise ValueError("the client map is invalid")

    semantic = {
        "networks": networks,
        "interfaces": interfaces,
        "devices": devices,
        "conflicts": conflicts,
    }
    encoded = json.dumps(
        semantic,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    if hashlib.sha256(encoded).hexdigest() != digest:
        raise ValueError("the client map content digest is invalid")

    return document


def _client_map_from_document(document: dict[str, Any], data: Any) -> ClientMapData:
    """Validate addresses and ignore IDs absent from the active manifest."""

    known_networks = set(data.network_masks)
    known_devices = set(data.device_masks)
    known_interfaces = set(data.bypass_interfaces)
    networks: list[tuple[Any, str]] = []
    interfaces: list[tuple[Any, str]] = []
    devices: dict[str, str] = {}

    for record in document["networks"]:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("id"), str)
            or re.fullmatch(r"[a-f0-9]{32}", record["id"]) is None
            or not isinstance(record.get("cidrs"), list)
        ):
            raise ValueError("a client map network is invalid")

        if record["id"] not in known_networks:
            continue

        parsed_networks: list[Any] = []

        for value in record["cidrs"]:
            if not isinstance(value, str):
                raise ValueError("a client map CIDR is invalid")

            parsed_networks.append(ipaddress.ip_network(value, strict=False))

        networks.extend((network, record["id"]) for network in parsed_networks)

    for record in document["interfaces"]:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("name"), str)
            or re.fullmatch(
                r"[a-z0-9_.:-]{1,64}",
                record["name"],
                re.IGNORECASE,
            )
            is None
            or not isinstance(record.get("cidrs"), list)
        ):
            raise ValueError("a client map Bypass interface is invalid")

        if record["name"] not in known_interfaces:
            continue

        parsed_interfaces: list[Any] = []

        for value in record["cidrs"]:
            if not isinstance(value, str):
                raise ValueError("a client map interface CIDR is invalid")

            parsed_interfaces.append(ipaddress.ip_network(value, strict=False))

        interfaces.extend(
            (network, record["name"]) for network in parsed_interfaces
        )

    for raw_address, device_id in document["devices"].items():
        if (
            not isinstance(raw_address, str)
            or not isinstance(device_id, str)
            or re.fullmatch(r"[a-f0-9]{32}", device_id) is None
        ):
            raise ValueError("a client map device assignment is invalid")

        if device_id not in known_devices:
            continue

        normalized, _address = _normalize_client_address(raw_address)
        devices.setdefault(normalized, device_id)

    for conflict in document["conflicts"]:
        if (
            not isinstance(conflict, dict)
            or not isinstance(conflict.get("address"), str)
            or not isinstance(conflict.get("winner"), str)
            or not isinstance(conflict.get("devices"), list)
            or any(not isinstance(identifier, str) for identifier in conflict["devices"])
        ):
            raise ValueError("a client map conflict is invalid")

        _normalize_client_address(conflict["address"])

    networks.sort(key=lambda item: item[0].prefixlen, reverse=True)
    interfaces.sort(key=lambda item: item[0].prefixlen, reverse=True)

    return ClientMapData(
        document["content_digest"],
        devices,
        tuple(networks),
        tuple(interfaces),
    )


def _load_client_map(data: Any) -> ClientMapData:
    """Synchronously load the current map against known manifest scope IDs."""

    return _client_map_from_document(_read_client_map_document(), data)


def _log_client_map_error(message: str) -> None:
    """Log one missing or bad map state once until the state changes."""

    global _last_client_map_error

    if message == _last_client_map_error:
        return

    _last_client_map_error = message
    log_info(f"sinkhole: {message}")


def _activate_client_map(client_map: ClientMapData) -> None:
    """Publish one validated map and invalidate every cached address decision."""

    global _active_client_map
    global _client_map_digest
    global _last_client_map_error

    _active_client_map = client_map
    _client_map_digest = client_map.digest
    _last_client_map_error = None
    _clear_client_lookup_cache()


def _refresh_client_map_if_changed(data: Any) -> None:
    """Reload changed map content while retaining the last good map on failure."""

    try:
        document = _read_client_map_document()

        if document["content_digest"] == _client_map_digest:
            return

        client_map = _client_map_from_document(document, data)
    except BaseException as exception:
        _log_client_map_error(
            f"client map is unavailable: {_failure_message(exception)}"
        )
        return

    _activate_client_map(client_map)


def _lookup_client_scopes(
    raw_address: str,
    client_map: ClientMapData,
) -> tuple[str | None, str | None, str | None]:
    """Return device, network, and Bypass interface IDs using one cache."""

    cached = _client_lookup_cache.get(raw_address)

    if cached is not None:
        return cached

    normalized, address = _normalize_client_address(raw_address)
    device_id = client_map.devices.get(normalized)
    network_id = None
    interface_name = None

    for network, candidate_id in client_map.networks:
        if address.version == network.version and address in network:
            network_id = candidate_id
            break

    for network, candidate_name in client_map.interfaces:
        if address.version == network.version and address in network:
            interface_name = candidate_name
            break

    result = (device_id, network_id, interface_name)

    if len(_client_lookup_cache) >= CLIENT_LOOKUP_CACHE_SIZE:
        try:
            eviction_address = next(iter(_client_lookup_cache), None)

            if eviction_address is not None:
                _client_lookup_cache.pop(eviction_address, None)
        except RuntimeError:
            pass

    _client_lookup_cache[raw_address] = result

    return result


def _write_state_marker(
    path: str,
    value: str,
    prefix: str,
    mode: int = 0o644,
) -> None:
    """Atomically replace one marker in the pre-created Unbound state directory."""

    directory = os.path.dirname(path)
    temporary_path = ""
    descriptor: int | None = None

    for _attempt in range(10):
        candidate = os.path.join(directory, f".{prefix}-{os.urandom(16).hex()}")

        try:
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                mode,
            )
            temporary_path = candidate
            break
        except FileExistsError:
            continue

    if descriptor is None:
        raise OSError(f"unable to create the {prefix} marker")

    try:
        contents = f"{value}\n".encode("ascii")
        offset = 0

        while offset < len(contents):
            written = os.write(descriptor, contents[offset:])

            if written <= 0:
                raise OSError(f"unable to write the {prefix} marker")

            offset += written

        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary_path, path)
        temporary_path = ""
    finally:
        if descriptor is not None:
            os.close(descriptor)

        if temporary_path != "":
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _report_loaded_generation(generation: str) -> None:
    """Report a loaded generation without changing active data on marker failure."""

    try:
        _write_state_marker(LOADED_GENERATION_PATH, generation, "loaded")
    except BaseException as exception:
        _log_reload_error(
            f"unable to report loaded generation: {_failure_message(exception)}"
        )


def _read_dropped_marker() -> int:
    """Read the cumulative drop marker without following a substituted link."""

    try:
        before = os.lstat(EVENTS_DROPPED_PATH)
    except FileNotFoundError:
        return 0

    if not stat.S_ISREG(before.st_mode) or before.st_size > 64:
        raise ValueError("the dropped-event marker is unsafe")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(EVENTS_DROPPED_PATH, flags)

    try:
        after = os.fstat(descriptor)

        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size > 64
        ):
            raise ValueError("the dropped-event marker changed while opening")

        contents = os.read(descriptor, 65).decode("ascii").strip()
    finally:
        os.close(descriptor)

    if re.fullmatch(r"0|[1-9][0-9]*", contents) is None:
        raise ValueError("the dropped-event marker is invalid")

    return int(contents)


def _persist_dropped_marker() -> None:
    """Persist the drop count only when its marker value changes."""

    global _persisted_events_dropped

    with _event_lock:
        dropped = _events_dropped
        persisted = _persisted_events_dropped

    if dropped == 0 or dropped == persisted:
        return

    try:
        _write_state_marker(
            EVENTS_DROPPED_PATH,
            str(dropped),
            "events-dropped",
            0o600,
        )
    except BaseException as exception:
        _log_reload_error(
            f"unable to save dropped-event count: {_failure_message(exception)}"
        )
    else:
        with _event_lock:
            _persisted_events_dropped = dropped


def _queue_block_event(
    data: Any,
    client_address: str,
    device_id: str | None,
    network_id: str | None,
    query_name: str,
    cname: str | None,
    blocking_mask: int,
) -> None:
    """Queue one matching block after only a five-millisecond bounded wait."""

    global _events_dropped

    try:
        rules = data.matching_alerts(blocking_mask, device_id, network_id)

        if len(rules) == 0:
            return

        lists = data.blocking_list_ids(blocking_mask)

        if len(lists) == 0:
            return

        normalized_client, _address = _normalize_client_address(client_address)
        event = {
            "t": int(time.time()),
            "count": 1,
            "client": normalized_client,
            "device": device_id,
            "network": network_id,
            "name": query_name,
            "cname": cname if cname != query_name else None,
            "rules": list(rules),
            "lists": list(lists),
        }

        if not _event_lock.acquire(timeout=0.005):
            return

        try:
            if len(_event_queue) >= MAXIMUM_QUEUED_EVENTS:
                _events_dropped += 1
                return

            _event_queue.append(event)
        finally:
            _event_lock.release()
    except BaseException:
        return


def _restore_unwritten_events(events: list[dict[str, Any]]) -> None:
    """Put an unwritten watcher batch back before events queued during the write."""

    global _event_queue
    global _events_dropped

    if len(events) == 0:
        return

    with _event_lock:
        combined = events + _event_queue

        if len(combined) > MAXIMUM_QUEUED_EVENTS:
            discarded = combined[MAXIMUM_QUEUED_EVENTS:]
            _events_dropped += sum(_event_count(event) for event in discarded)
            combined = combined[:MAXIMUM_QUEUED_EVENTS]

        _event_queue = combined


def _write_all(descriptor: int, contents: bytes) -> None:
    """Append one complete encoded event or raise on a short-write failure."""

    offset = 0

    while offset < len(contents):
        written = os.write(descriptor, contents[offset:])

        if written <= 0:
            raise OSError("unable to append a Sinkhole event")

        offset += written


def _event_count(event: dict[str, Any]) -> int:
    """Return one validated-enough in-memory occurrence count."""

    count = event.get("count", 1)

    if isinstance(count, int) and not isinstance(count, bool) and count > 0:
        return count

    return 1


def _coalesce_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold identical client, name, and rule matches within one watcher tick."""

    coalesced: list[dict[str, Any]] = []
    indexes: dict[tuple[Any, Any, tuple[Any, ...]], int] = {}

    for event in events:
        raw_rules = event.get("rules")
        rules = tuple(raw_rules) if isinstance(raw_rules, list) else ()
        key = (event.get("client"), event.get("name"), rules)
        index = indexes.get(key)

        if index is None:
            copied = dict(event)
            copied["count"] = _event_count(event)
            indexes[key] = len(coalesced)
            coalesced.append(copied)
            continue

        coalesced[index]["count"] = (
            _event_count(coalesced[index]) + _event_count(event)
        )

    return coalesced


def _add_dropped(count: int) -> None:
    """Change the cumulative drop counter only while holding its queue lock."""

    global _events_dropped

    with _event_lock:
        _events_dropped += count


def _flush_events() -> None:
    """Append one queue snapshot under the file cap, retaining failures in memory."""

    global _event_queue
    with _event_lock:
        events = _coalesce_events(_event_queue)
        _event_queue = []

    if len(events) == 0:
        _persist_dropped_marker()
        return

    descriptor: int | None = None
    unwritten = events
    file_locked = False

    try:
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(EVENTS_PATH, flags, 0o600)
        file_status = os.fstat(descriptor)

        if not stat.S_ISREG(file_status.st_mode):
            raise OSError("the Sinkhole event path is not a regular file")

        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _restore_unwritten_events(events)
            unwritten = []
            return

        file_locked = True
        current_size = file_status.st_size

        for index, event in enumerate(events):
            encoded = (
                json.dumps(
                    event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")

            if current_size + len(encoded) > MAXIMUM_EVENT_FILE_BYTES:
                _add_dropped(_event_count(event))
                unwritten = events[index + 1 :]
                continue

            unwritten = events[index:]
            _write_all(descriptor, encoded)
            current_size += len(encoded)
            unwritten = events[index + 1 :]

        os.fsync(descriptor)
        unwritten = []
    except BaseException as exception:
        _restore_unwritten_events(unwritten)
        _log_reload_error(
            f"unable to append alert events: {_failure_message(exception)}"
        )
    finally:
        if descriptor is not None:
            try:
                if file_locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)

                os.close(descriptor)
            except BaseException:
                pass

        _persist_dropped_marker()


def _activate_loaded_data(data: Any, prefix: str) -> None:
    """Publish one complete data object and its content generation."""

    global _active_data
    global _failed_generation_id
    global _generation_id
    global _last_reload_error
    global _client_map_digest

    _active_data = data
    _generation_id = data.generation
    _failed_generation_id = None
    _last_reload_error = None
    _client_map_digest = None
    _clear_client_lookup_cache()
    _report_loaded_generation(data.generation)
    _log_loaded(prefix, data)


def _reload_worker(
    generation_id: str,
    lifecycle_token: object,
    stop_event: threading.Event,
    reload_lock: threading.Lock,
) -> None:
    """Load one requested generation and publish only for its originating lifecycle."""

    global _failed_generation_id

    try:
        loaded = _load_data(stop_event)

        if stop_event.is_set() or lifecycle_token is not _lifecycle_token:
            return

        if loaded.generation != generation_id or _read_generation() != generation_id:
            return

        _activate_loaded_data(loaded, "reloaded")
    except _LoadStopped:
        return
    except BaseException as exception:
        if not stop_event.is_set() and lifecycle_token is _lifecycle_token:
            _failed_generation_id = generation_id
            _log_reload_error(
                f"compiler data reload failed: {_failure_message(exception)}"
            )
    finally:
        reload_lock.release()


def _start_reload(generation_id: str) -> None:
    """Start at most one background load for the watcher-observed generation."""

    global _loader_thread

    if generation_id in (_generation_id, _failed_generation_id):
        return

    reload_lock = _reload_lock

    if not reload_lock.acquire(blocking=False):
        return

    if generation_id in (_generation_id, _failed_generation_id):
        reload_lock.release()
        return

    lifecycle_token = _lifecycle_token
    stop_event = _stop_event

    try:
        loader_thread = threading.Thread(
            target=_reload_worker,
            args=(generation_id, lifecycle_token, stop_event, reload_lock),
            name="sinkhole-loader",
            daemon=True,
        )
        _loader_thread = loader_thread
        loader_thread.start()
    except BaseException as exception:
        reload_lock.release()
        _log_reload_error(
            f"unable to start compiler data reload: {_failure_message(exception)}"
        )


def _watch_worker(lifecycle_token: object, stop_event: threading.Event) -> None:
    """Watch generation content and request loads without depending on queries."""

    while not stop_event.wait(WATCH_INTERVAL_SECONDS):
        if lifecycle_token is not _lifecycle_token:
            return

        _flush_events()

        try:
            generation_id = _read_generation()
        except BaseException as exception:
            _log_reload_error(
                f"compiler data is unavailable: {_failure_message(exception)}"
            )
            continue

        if lifecycle_token is not _lifecycle_token:
            return

        _start_reload(generation_id)

        data = _active_data
        if data is not None:
            _refresh_client_map_if_changed(data)


def _start_watcher() -> None:
    """Start the lifecycle-owned generation watcher."""

    global _watcher_thread

    lifecycle_token = _lifecycle_token
    stop_event = _stop_event

    try:
        watcher_thread = threading.Thread(
            target=_watch_worker,
            args=(lifecycle_token, stop_event),
            name="sinkhole-watcher",
            daemon=True,
        )
        _watcher_thread = watcher_thread
        watcher_thread.start()
    except BaseException as exception:
        _log_reload_error(
            f"unable to start compiler data watcher: {_failure_message(exception)}"
        )


def _answer_rrsets(rep: Any) -> list[Any]:
    """Return only answer-section RRsets from Unbound's ``reply_info`` wrapper."""

    answer_count = int(rep.an_numrrsets)

    if answer_count < 0 or answer_count > int(rep.rrset_count):
        raise ValueError("the cached answer RRset count is invalid")

    return [rep.rrsets[index] for index in range(answer_count)]


def _response_cache_rrsets(rep: Any) -> list[Any]:
    """Return validated answer and additional RRsets from an upstream response."""

    answer_count = int(rep.an_numrrsets)
    authority_count = int(rep.ns_numrrsets)
    additional_count = int(rep.ar_numrrsets)
    rrset_count = int(rep.rrset_count)
    additional_start = answer_count + authority_count
    additional_end = additional_start + additional_count

    if (
        answer_count < 0
        or authority_count < 0
        or additional_count < 0
        or answer_count > rrset_count
        or additional_start > rrset_count
        or additional_end > rrset_count
    ):
        raise ValueError("the upstream response RRset counts are invalid")

    answer_rrsets = [rep.rrsets[index] for index in range(answer_count)]
    additional_rrsets = [
        rep.rrsets[index] for index in range(additional_start, additional_end)
    ]

    return answer_rrsets + additional_rrsets


def _rrset_owner(rrset: Any) -> str | None:
    """Return a normalized packed-RRset owner name."""

    return _normalize_query_name(rrset.rk.dname_str)


def _log_query_response_error_once(message: str) -> None:
    """Log only the first upstream response callback failure in one lifecycle."""

    global _query_response_error_logged

    if _query_response_error_logged:
        return

    _query_response_error_logged = True

    try:
        log_info(f"sinkhole: {message}")
    except BaseException:
        pass


def _query_response_callback(qstate: Any, response: Any, **kwargs: Any) -> bool:
    """Prevent storage when an upstream answer passes through any listed owner."""

    del kwargs

    try:
        data = _active_data

        if data is None:
            return True

        if response is None:
            return True

        rep = getattr(response, "rep", None)

        if rep is None:
            return True

        for rrset in _response_cache_rrsets(rep):
            owner = _rrset_owner(rrset)

            if owner is None:
                continue

            if data.is_listed(owner) or data.has_bypass_policy_name(owner):
                qstate.no_cache_store = 1
                break
    except BaseException as exception:
        _log_query_response_error_once(
            "upstream response cache check failed: "
            f"{_failure_message(exception)}"
        )

    return True


def get_q_ip(qstate: Any) -> str:
    """Return the client address, or an empty string for internal subqueries."""

    try:
        reply = qstate.mesh_info.reply_list

        while reply is not None:
            address = reply.query_reply.addr

            if address is not None:
                return str(address)

            reply = reply.next
    except (AttributeError, TypeError):
        return ""

    return ""


def _wire_name_to_rr_text(wire_name: Any) -> str:
    """Return an exact DNS presentation name from an uncompressed wire name."""

    if not isinstance(wire_name, (bytes, bytearray, memoryview)):
        raise ValueError("the query name wire value is unavailable")

    wire = bytes(wire_name)
    labels: list[str] = []
    offset = 0

    while offset < len(wire):
        label_length = wire[offset]
        offset += 1

        if label_length == 0:
            if offset != len(wire):
                raise ValueError("the query name has trailing wire data")

            return ".".join(labels) + "."

        if label_length > 63 or offset + label_length > len(wire):
            raise ValueError("the query name wire value is invalid")

        label = wire[offset : offset + label_length]
        offset += label_length
        labels.append(
            "".join(
                chr(value)
                if (
                    48 <= value <= 57
                    or 65 <= value <= 90
                    or 97 <= value <= 122
                    or value in (45, 95)
                )
                else f"\\{value:03d}"
                for value in label
            )
        )

    raise ValueError("the query name wire value has no root label")


def _finish_blocked_query(module_id: int, qstate: Any) -> bool:
    """Replace the response with the normal sinkhole answer for the original query."""

    query_name = _wire_name_to_rr_text(qstate.qinfo.qname)
    query_type = qstate.qinfo.qtype
    message = DNSMessage(query_name, query_type, RR_CLASS_IN, PKT_QR | PKT_RA)

    if query_type == RR_TYPE_A:
        message.answer.append(f"{query_name} {BLOCK_TTL_SECONDS} IN A 0.0.0.0")
    elif query_type == RR_TYPE_AAAA:
        message.answer.append(f"{query_name} {BLOCK_TTL_SECONDS} IN AAAA ::")

    if not message.set_return_msg(qstate):
        qstate.ext_state[module_id] = MODULE_ERROR
        return True

    qstate.return_rcode = RCODE_NOERROR
    qstate.return_msg.rep.security = 2
    qstate.ext_state[module_id] = MODULE_FINISHED

    return True


def _finish_empty_query(module_id: int, qstate: Any, rcode: int) -> bool:
    """Return an authoritative empty local answer with the requested response code."""

    message = DNSMessage(
        qstate.qinfo.qname_str,
        qstate.qinfo.qtype,
        RR_CLASS_IN,
        PKT_QR | PKT_RA,
    )

    if not message.set_return_msg(qstate):
        qstate.ext_state[module_id] = MODULE_ERROR
        return True

    qstate.return_rcode = rcode
    qstate.return_msg.rep.security = 2
    qstate.ext_state[module_id] = MODULE_FINISHED

    return True


def _finish_discovery_advertisement(
    module_id: int,
    qstate: Any,
    hostname: str,
    port: int,
) -> bool:
    """Return the compiler-validated DDR SVCB answer for DNS over TLS."""

    if qstate.qinfo.qtype not in (RR_TYPE_SVCB_VALUE, 255):
        return _finish_empty_query(module_id, qstate, RCODE_NOERROR)

    query_name = qstate.qinfo.qname_str
    message = DNSMessage(
        query_name,
        qstate.qinfo.qtype,
        RR_CLASS_IN,
        PKT_QR | PKT_RA,
    )
    message.answer.append(
        f"{query_name} {BLOCK_TTL_SECONDS} IN SVCB "
        f"1 {hostname}. alpn=dot port={port}"
    )

    if not message.set_return_msg(qstate):
        qstate.ext_state[module_id] = MODULE_ERROR
        return True

    qstate.return_rcode = RCODE_NOERROR
    qstate.return_msg.rep.security = 2
    qstate.ext_state[module_id] = MODULE_FINISHED

    return True


def _finish_bypass_action(
    module_id: int,
    qstate: Any,
    data: Any,
    action: str,
) -> bool:
    """Build one NXDOMAIN, NODATA, or SVCB Bypass signal answer."""

    if action == "nxdomain":
        return _finish_empty_query(module_id, qstate, RCODE_NXDOMAIN)

    if action == "nodata":
        return _finish_empty_query(module_id, qstate, RCODE_NOERROR)

    if action == "svcb":
        return _finish_discovery_advertisement(
            module_id,
            qstate,
            data.discovery_hostname,
            data.discovery_port,
        )

    raise ValueError("the Bypass answer action is invalid")


def _moddone_policy(
    qstate: Any,
    data: Any,
    client_map: ClientMapData,
    query_name: str,
) -> tuple[
    bool,
    tuple[str, str, str | None, str | None, int] | None,
]:
    """Evaluate query then answer owners for the originating client scopes."""

    return_message = getattr(qstate, "return_msg", None)
    rep = getattr(return_message, "rep", None)

    if rep is None:
        return False, None

    listed_owner = False
    blocked: tuple[str, str, str | None, str | None, int] | None = None
    client_address = get_q_ip(qstate)
    device_id = None
    network_id = None
    interface_name = None
    query_decision = "pass"

    if client_address != "":
        device_id, network_id, interface_name = _lookup_client_scopes(
            client_address,
            client_map,
        )
        query_decision = data.decision(query_name, device_id, network_id)

    for rrset in _answer_rrsets(rep):
        owner = _rrset_owner(rrset)

        if owner is None:
            continue

        if data.is_listed(owner) or data.is_bypass_listed(owner):
            listed_owner = True

        if (
            client_address != ""
            and query_decision != "allow"
            and blocked is None
        ):
            decision, blocking_mask = data.decision_details(
                owner,
                device_id,
                network_id,
            )

            if decision == "block":
                blocked = (
                    client_address,
                    owner,
                    device_id,
                    network_id,
                    blocking_mask,
                )
            elif (
                decision != "allow"
                and data.bypass_blocks_name(owner, interface_name)
            ):
                blocked = (
                    client_address,
                    owner,
                    device_id,
                    network_id,
                    0,
                )

    return listed_owner, blocked


def _valid_stash(value: Any) -> bool:
    """Validate the versioned interpreter-lifetime stash without class identity checks."""

    if not isinstance(value, dict) or value.get("version") != STASH_VERSION:
        return False

    data = value.get("data")
    generation = value.get("generation")

    return (
        isinstance(generation, str)
        and data is not None
        and getattr(data, "generation", None) == generation
        and hasattr(data, "match")
        and hasattr(data, "is_allowed")
        and hasattr(data, "is_listed")
        and hasattr(data, "decision")
        and hasattr(data, "decision_details")
        and hasattr(data, "bypass_signal_action")
        and hasattr(data, "bypass_blocks_name")
        and hasattr(data, "has_bypass_policy_name")
        and hasattr(data, "matching_alerts")
        and hasattr(data, "blocking_list_ids")
        and isinstance(value.get("events"), list)
        and isinstance(value.get("events_dropped"), int)
        and not isinstance(value.get("events_dropped"), bool)
        and 0 <= value.get("events_dropped")
    )


def init_standard(module_id: int, environment: Any) -> bool:
    """Initialize policy, reusing interpreter-stashed data across Unbound reloads."""

    global _active_data
    global _active_client_map
    global _client_map_digest
    global _failed_generation_id
    global _generation_id
    global _last_client_map_error
    global _last_reload_error
    global _lifecycle_token
    global _loader_thread
    global _reload_lock
    global _stop_event
    global _watcher_thread
    global _query_response_error_logged
    global _event_lock
    global _event_queue
    global _events_dropped
    global _persisted_events_dropped

    _active_data = None
    _generation_id = None
    _failed_generation_id = None
    _last_reload_error = None
    _loader_thread = None
    _watcher_thread = None
    _reload_lock = threading.Lock()
    _stop_event = threading.Event()
    _lifecycle_token = object()
    _query_response_error_logged = False
    _active_client_map = _empty_client_map()
    _client_map_digest = None
    _last_client_map_error = None
    _clear_client_lookup_cache()
    _event_lock = threading.Lock()

    with _event_lock:
        _event_queue = []
        _events_dropped = 0
        _persisted_events_dropped = 0

    try:
        registration_succeeded = register_inplace_cb_query_response(
            _query_response_callback,
            environment,
            module_id,
        )

        if not registration_succeeded:
            _log_query_response_error_once(
                "unable to register upstream response cache check: "
                "registration was refused"
            )
    except BaseException as exception:
        _log_query_response_error_once(
            "unable to register upstream response cache check: "
            f"{_failure_message(exception)}"
        )

    stash = getattr(sys, STASH_ATTRIBUTE, None)

    try:
        delattr(sys, STASH_ATTRIBUTE)
    except AttributeError:
        pass

    try:
        current_generation = _read_generation()
    except BaseException as exception:
        current_generation = None
        _log_reload_error(
            f"compiler data is unavailable: {_failure_message(exception)}"
        )

    if _valid_stash(stash):
        stashed_data = stash["data"]
        stashed_events = stash["events"]

        if all(isinstance(event, dict) for event in stashed_events):
            with _event_lock:
                _event_queue = stashed_events[:MAXIMUM_QUEUED_EVENTS]
                _events_dropped = stash["events_dropped"] + sum(
                    _event_count(event)
                    for event in stashed_events[MAXIMUM_QUEUED_EVENTS:]
                )

        _activate_loaded_data(stashed_data, "restored")

        stashed_client_map = stash.get("client_map")

        if (
            stashed_client_map is not None
            and hasattr(stashed_client_map, "devices")
            and hasattr(stashed_client_map, "networks")
            and hasattr(stashed_client_map, "interfaces")
            and hasattr(stashed_client_map, "digest")
        ):
            _activate_client_map(stashed_client_map)
    elif current_generation is not None:
        try:
            loaded = _load_data(_stop_event)
        except BaseException as exception:
            _failed_generation_id = current_generation
            _log_reload_error(
                f"compiler data initial load failed: {_failure_message(exception)}"
            )
        else:
            _activate_loaded_data(loaded, "loaded")

    try:
        persisted_drops = _read_dropped_marker()

        with _event_lock:
            _events_dropped = max(_events_dropped, persisted_drops)
            _persisted_events_dropped = persisted_drops
    except BaseException as exception:
        _log_reload_error(
            f"dropped-event marker is unavailable: {_failure_message(exception)}"
        )

    if _active_data is None:
        log_info("sinkhole: started without readable compiler data; queries will pass through")
    else:
        try:
            _activate_client_map(_load_client_map(_active_data))
        except BaseException as exception:
            _log_client_map_error(
                f"client map is unavailable: {_failure_message(exception)}"
            )

    _start_watcher()

    return True


def deinit(module_id: int) -> bool:
    """Stop and join watcher work, then stash data for the next script execution."""

    del module_id

    _stop_event.set()
    watcher_thread = _watcher_thread

    if watcher_thread is not None and watcher_thread is not threading.current_thread():
        watcher_thread.join()

    loader_thread = _loader_thread

    if loader_thread is not None and loader_thread is not threading.current_thread():
        loader_thread.join()

    _flush_events()

    if _active_data is not None:
        with _event_lock:
            stashed_events = list(_event_queue)
            stashed_drops = _events_dropped

        setattr(
            sys,
            STASH_ATTRIBUTE,
            {
                "version": STASH_VERSION,
                "generation": _active_data.generation,
                "data": _active_data,
                "client_map": _active_client_map,
                "events": stashed_events,
                "events_dropped": stashed_drops,
            },
        )

    return True


def inform_super(module_id: int, qstate: Any, superqstate: Any, qdata: Any) -> bool:
    """Accept completion notifications for internal subqueries."""

    del module_id
    del qstate
    del superqstate
    del qdata

    return True


def operate(module_id: int, event: int, qstate: Any, qdata: Any) -> bool:
    """Apply direct-query and downstream CNAME-owner blocking rules."""

    del qdata

    if event == MODULE_EVENT_MODDONE:
        data = _active_data
        client_map = _active_client_map
        query_name = _normalize_query_name(qstate.qinfo.qname_str)

        try:
            if data is not None and query_name is not None:
                listed_owner, blocked = _moddone_policy(
                    qstate,
                    data,
                    client_map,
                    query_name,
                )

                if listed_owner and getattr(qstate, "no_cache_store", 0) == 0:
                    try:
                        invalidateQueryInCache(qstate, qstate.qinfo)
                    except BaseException as exception:
                        _log_reload_error(
                            "unable to expire listed downstream answer: "
                            f"{_failure_message(exception)}"
                        )

                if blocked is not None:
                    result = _finish_blocked_query(module_id, qstate)
                    (
                        client_address,
                        blocked_owner,
                        device_id,
                        network_id,
                        blocking_mask,
                    ) = blocked

                    if (
                        qstate.ext_state[module_id] == MODULE_FINISHED
                        and blocking_mask != 0
                    ):
                        _queue_block_event(
                            data,
                            client_address,
                            device_id,
                            network_id,
                            query_name,
                            blocked_owner if blocked_owner != query_name else None,
                            blocking_mask,
                        )

                    return result
        except BaseException as exception:
            _log_reload_error(
                f"downstream answer check failed: {_failure_message(exception)}"
            )

        qstate.ext_state[module_id] = MODULE_FINISHED
        return True

    if event not in (MODULE_EVENT_NEW, MODULE_EVENT_PASS):
        qstate.ext_state[module_id] = MODULE_ERROR
        return True

    data = _active_data

    if data is None:
        qstate.ext_state[module_id] = MODULE_WAIT_MODULE
        return True

    query_name = _normalize_query_name(qstate.qinfo.qname_str)

    if query_name is None:
        qstate.ext_state[module_id] = MODULE_WAIT_MODULE
        return True

    if data.is_listed(query_name) or data.has_bypass_policy_name(query_name):
        qstate.no_cache_store = 1

    client_address = get_q_ip(qstate)

    if client_address == "":
        try:
            bypass_action = data.bypass_signal_action(query_name, None)

            if bypass_action is not None:
                return _finish_bypass_action(
                    module_id,
                    qstate,
                    data,
                    bypass_action,
                )
        except BaseException as exception:
            _log_reload_error(
                f"internal query policy check failed: {_failure_message(exception)}"
            )

    if client_address != "":
        try:
            device_id, network_id, interface_name = _lookup_client_scopes(
                client_address,
                _active_client_map,
            )

            bypass_action = data.bypass_signal_action(
                query_name,
                interface_name,
            )

            if bypass_action is not None:
                return _finish_bypass_action(
                    module_id,
                    qstate,
                    data,
                    bypass_action,
                )

            decision, blocking_mask = data.decision_details(
                query_name,
                device_id,
                network_id,
            )

            if decision == "block":
                result = _finish_blocked_query(module_id, qstate)

                if qstate.ext_state[module_id] == MODULE_FINISHED:
                    _queue_block_event(
                        data,
                        client_address,
                        device_id,
                        network_id,
                        query_name,
                        None,
                        blocking_mask,
                    )

                return result

            if (
                decision != "allow"
                and data.bypass_blocks_name(query_name, interface_name)
            ):
                return _finish_blocked_query(module_id, qstate)
        except BaseException as exception:
            _log_reload_error(
                f"client policy lookup failed: {_failure_message(exception)}"
            )

    qstate.ext_state[module_id] = MODULE_WAIT_MODULE

    return True
