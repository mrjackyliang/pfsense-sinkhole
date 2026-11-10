"""Tests for the Sinkhole Unbound Python module.

Since: UNRELEASED
"""

from __future__ import annotations

from collections.abc import Iterator
import fcntl
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from typing import Any


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "port"
    / "files"
    / "usr"
    / "local"
    / "pkg"
    / "sinkhole"
    / "sinkhole_unbound.py"
)
LIST_IDENTIFIER = "11111111111111111111111111111111"


class ExecutedModule:
    """Expose a source file executed in an embedded-interpreter namespace.

    Since: UNRELEASED
    """

    def __init__(self, path: Path) -> None:
        """Execute source directly without registering an imported module.

        Args:
            path: Python source path.

        Since: UNRELEASED
        """

        namespace: dict[str, Any] = {}
        source = path.read_text(encoding="utf-8")
        exec(compile(source, str(path), "exec"), namespace)
        object.__setattr__(self, "_namespace", namespace)

    def __getattr__(self, name: str) -> Any:
        """Read one executed global.

        Args:
            name: Global name.

        Returns:
            Executed global value.

        Since: UNRELEASED
        """

        try:
            return self._namespace[name]
        except KeyError as exception:
            raise AttributeError(name) from exception

    def __setattr__(self, name: str, value: Any) -> None:
        """Replace one executed global.

        Args:
            name: Global name.
            value: Replacement value.

        Since: UNRELEASED
        """

        self._namespace[name] = value


class CoordinatedClientCache(
    dict[str, tuple[str | None, str | None, str | None]]
):
    """Coordinate one stale eviction candidate with a clearing thread.

    The regression test uses this dictionary to force the cache-clear race at the
    exact boundary between choosing an eviction key and removing it.

    Since:
        1.0.0
    """

    def __init__(
        self,
        eviction_started: threading.Event,
        cache_cleared: threading.Event,
    ) -> None:
        """Initialize one coordinated eviction.

        Args:
            eviction_started: Eviction started.
            cache_cleared: Cache cleared.

        Since:
            1.0.0
        """

        super().__init__()

        self._eviction_started = eviction_started
        self._cache_cleared = cache_cleared
        self._coordinate_eviction = True

    def __iter__(self) -> Iterator[str]:
        """Return one key that another thread removes before the caller uses it.

        Returns:
            Iterator containing the coordinated key.

        Since:
            1.0.0
        """

        iterator = super().__iter__()

        if self._coordinate_eviction is False:
            return iterator

        try:
            eviction_address = next(iterator)
        except StopIteration:
            return iterator

        self._coordinate_eviction = False

        self._eviction_started.set()

        if self._cache_cleared.wait(timeout=2.0) is False:
            raise RuntimeError("the cache-clear thread did not run")

        return iter((eviction_address,))


class FakeDnsMessage:
    """Capture DNS responses created by the module.

    Since: UNRELEASED
    """

    created: list["FakeDnsMessage"] = []

    def __init__(self, name: str, query_type: int, query_class: int, flags: int) -> None:
        """Store message arguments and initialize the answer section.

        Args:
            name: Query name.
            query_type: Query type.
            query_class: Query class.
            flags: DNS flags.

        Since: UNRELEASED
        """

        self.name = name
        self.query_type = query_type
        self.query_class = query_class
        self.flags = flags
        self.answer: list[str] = []
        self.rep = types.SimpleNamespace(security=None)
        self.created.append(self)

    def set_return_msg(self, qstate: Any) -> bool:
        """Attach this message to a fake query state.

        Args:
            qstate: Fake query state.

        Returns:
            Always ``True``.

        Since: UNRELEASED
        """

        qstate.return_msg = self

        return True


class SinkholeUnboundTest(unittest.TestCase):
    """Exercise matching, loading, and embedded-interpreter behavior.

    Since: UNRELEASED
    """

    def setUp(self) -> None:
        """Execute a fresh module namespace with stubbed Unbound globals.

        Since: UNRELEASED
        """

        self.temporary_directory = tempfile.TemporaryDirectory()
        temporary_path = Path(self.temporary_directory.name)
        self.data_directory = temporary_path / "sinkhole"
        self.state_directory = temporary_path / "sinkhole-state"
        self.client_directory = temporary_path / "sinkhole-clients"
        self.data_directory.mkdir()
        self.state_directory.mkdir()
        self.client_directory.mkdir()
        self.module = ExecutedModule(MODULE_PATH)
        self.module.DATA_DIRECTORY = str(self.data_directory)
        self.module.MANIFEST_PATH = str(self.data_directory / "manifest.json")
        self.module.DOMAINS_PATH = str(self.data_directory / "domains.tsv")
        self.module.BYPASS_PATH = str(self.data_directory / "bypass.tsv")
        self.module.ALLOW_PATH = str(self.data_directory / "allow.txt")
        self.module.GENERATION_PATH = str(self.data_directory / "generation")
        self.module.LOADED_GENERATION_PATH = str(self.state_directory / "loaded")
        self.module.EVENTS_PATH = str(self.state_directory / "events")
        self.module.EVENTS_DROPPED_PATH = str(
            self.state_directory / "events-dropped"
        )
        self.module.CLIENT_MAP_PATH = str(self.client_directory / "clients.json")
        self.module.WATCH_INTERVAL_SECONDS = 0.01
        self.module.DNSMessage = FakeDnsMessage
        self.module.RR_TYPE_A = 1
        self.module.RR_TYPE_AAAA = 28
        self.module.RR_TYPE_CNAME = 5
        self.module.RR_CLASS_IN = 1
        self.module.PKT_QR = 1
        self.module.PKT_RA = 2
        self.module.PKT_AA = 4
        self.module.RCODE_NOERROR = 0
        self.module.RCODE_NXDOMAIN = 3
        self.module.MODULE_EVENT_NEW = 10
        self.module.MODULE_EVENT_PASS = 11
        self.module.MODULE_EVENT_MODDONE = 12
        self.module.MODULE_FINISHED = 20
        self.module.MODULE_WAIT_MODULE = 21
        self.module.MODULE_ERROR = 22
        self.module.ntohs = lambda value: value
        self.invalidated_queries: list[tuple[Any, Any]] = []
        self.module.invalidateQueryInCache = (
            lambda qstate, qinfo: self.invalidated_queries.append((qstate, qinfo))
        )
        self.logs: list[str] = []
        self.module.log_info = self.logs.append
        self.registrations: list[tuple[Any, Any, int]] = []
        self.module.register_inplace_cb_query_response = (
            lambda callback, environment, module_id: (
                self.registrations.append((callback, environment, module_id)) or 1
            )
        )
        FakeDnsMessage.created = []

        if hasattr(sys, self.module.STASH_ATTRIBUTE):
            delattr(sys, self.module.STASH_ATTRIBUTE)

    def tearDown(self) -> None:
        """Wait for any loader and remove temporary compiler data.

        Since: UNRELEASED
        """

        self.module.deinit(0)

        if hasattr(sys, self.module.STASH_ATTRIBUTE):
            delattr(sys, self.module.STASH_ATTRIBUTE)

        self.temporary_directory.cleanup()

    def write_data(
        self,
        generation: str,
        domains: list[tuple[str, str, str]],
        allowed: list[str] | None = None,
        include_list: bool = True,
        domain_count: int | None = None,
        bypass_domains: list[tuple[str, str, str]] | None = None,
        bypass: dict[str, Any] | None = None,
    ) -> None:
        """Write one compiler-format generation.

        Args:
            generation: Generation identifier.
            domains: Domain, exact bits, and subtree bits.
            allowed: Allowed domain names.
            include_list: Whether to define the fixture list.
            domain_count: Optional manifest count override.

        Since: UNRELEASED
        """

        lists = (
            {
                LIST_IDENTIFIER: {
                    "name": "Example",
                    "bit": 0,
                }
            }
            if include_list
            else {}
        )
        bypass_domains = bypass_domains or []
        bypass = bypass or {
            "interfaces": [],
            "block_encrypted_dns": False,
            "disable_firefox_doh": False,
            "disable_private_relay": False,
            "discovery": "off",
            "block_tor": False,
            "block_vpn": False,
            "discovery_hostname": "",
            "discovery_port": 0,
        }
        manifest = {
            "schema_version": 3,
            "generation": generation,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "domains_file": "domains.tsv",
            "allow_file": "allow.txt",
            "domain_count": len(domains) if domain_count is None else domain_count,
            "bypass_file": "bypass.tsv",
            "bypass_domain_count": len(bypass_domains),
            "bypass": bypass,
            "lists": lists,
            "scopes": {
                "global": {
                    "lists": [LIST_IDENTIFIER] if include_list else [],
                    "allow": "allow.txt",
                },
                "networks": {},
                "devices": {},
            },
        }
        (self.data_directory / "manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        (self.data_directory / "domains.tsv").write_text(
            "".join(f"{domain}\t{exact}\t{subtree}\n" for domain, exact, subtree in domains),
            encoding="ascii",
        )
        (self.data_directory / "bypass.tsv").write_text(
            "".join(
                f"{domain}\t{exact}\t{subtree}\n"
                for domain, exact, subtree in bypass_domains
            ),
            encoding="ascii",
        )
        (self.data_directory / "allow.txt").write_text(
            "".join(f"{domain}\n" for domain in (allowed or [])),
            encoding="ascii",
        )
        (self.data_directory / "generation").write_text(
            f"{generation}\n",
            encoding="ascii",
        )

    def wait_for_loader(self) -> None:
        """Wait for the current asynchronous reload to finish.

        Since: UNRELEASED
        """

        loader_thread = self.module._loader_thread
        self.assertIsNotNone(loader_thread)
        loader_thread.join(timeout=3.0)
        self.assertFalse(loader_thread.is_alive())

    def bypass_configuration(self, **overrides: Any) -> dict[str, Any]:
        """Return one complete compiler-format Bypass configuration."""

        configuration: dict[str, Any] = {
            "interfaces": ["lan"],
            "block_encrypted_dns": False,
            "disable_firefox_doh": False,
            "disable_private_relay": False,
            "discovery": "off",
            "block_tor": False,
            "block_vpn": False,
            "discovery_hostname": "",
            "discovery_port": 0,
        }
        configuration.update(overrides)

        return configuration

    def wait_for_generation(self, generation: str) -> None:
        """Wait for the watcher to publish one generation.

        Args:
            generation: Expected generation.

        Since: UNRELEASED
        """

        deadline = time.monotonic() + 3.0

        while time.monotonic() < deadline:
            data = self.module._active_data

            if data is not None and data.generation == generation:
                return

            time.sleep(0.005)

        self.fail(f"watcher did not load {generation}")

    def wait_for_client_digest(self, digest: str) -> None:
        """Wait for the watcher to publish one client-map digest.

        Args:
            digest: Expected digest.

        Since: UNRELEASED
        """

        deadline = time.monotonic() + 3.0

        while time.monotonic() < deadline:
            if self.module._active_client_map.digest == digest:
                return

            time.sleep(0.005)

        self.fail(f"watcher did not load client map {digest}")

    def write_client_map(
        self,
        networks: list[dict[str, Any]],
        devices: dict[str, str],
        conflicts: list[dict[str, Any]] | None = None,
        interfaces: list[dict[str, Any]] | None = None,
    ) -> str:
        """Write one digest-valid client map and return its semantic digest.

        Args:
            networks: Network IDs and CIDRs.
            devices: Exact address assignments.
            conflicts: Optional conflict records.

        Returns:
            Content digest.

        Since: UNRELEASED
        """

        semantic = {
            "networks": networks,
            "interfaces": interfaces or [],
            "devices": devices,
            "conflicts": conflicts or [],
        }
        digest = hashlib.sha256(
            json.dumps(
                semantic,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        document = {
            "schema_version": 2,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "content_digest": digest,
            **semantic,
        }
        (self.client_directory / "clients.json").write_text(
            json.dumps(document),
            encoding="utf-8",
        )

        return digest

    def write_scoped_data(
        self,
        generation: str,
        include_alerts: bool = False,
    ) -> dict[str, str]:
        """Write a three-level policy fixture used by scope decision tests.

        Args:
            generation: Generation identifier.
            include_alerts: Whether to include matching alert rules.

        Returns:
            Stable list, scope, and rule IDs.

        Since: UNRELEASED
        """

        identifiers = {
            "device_list": "11111111111111111111111111111111",
            "network_list": "22222222222222222222222222222222",
            "global_list": "33333333333333333333333333333333",
            "network_a": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "network_b": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "device": "dddddddddddddddddddddddddddddddd",
            "any_rule": "44444444444444444444444444444444",
            "network_rule": "55555555555555555555555555555555",
            "device_rule": "66666666666666666666666666666666",
        }
        domains = [
            ("device-allow.example.test", "0,1,2", ""),
            ("device-list.example.test", "0,1,2", ""),
            ("network-allow.example.test", "1,2", ""),
            ("network-list.example.test", "1,2", ""),
            ("global-allow.example.test", "2", ""),
            ("global-list.example.test", "2", ""),
            ("cname-network.example.test", "1", ""),
        ]
        manifest = {
            "schema_version": 3,
            "generation": generation,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "domains_file": "domains.tsv",
            "allow_file": "allow.txt",
            "domain_count": len(domains),
            "bypass_file": "bypass.tsv",
            "bypass_domain_count": 0,
            "bypass": {
                "interfaces": [],
                "block_encrypted_dns": False,
                "disable_firefox_doh": False,
                "disable_private_relay": False,
                "discovery": "off",
                "block_tor": False,
                "block_vpn": False,
                "discovery_hostname": "",
                "discovery_port": 0,
            },
            "lists": {
                identifiers["device_list"]: {"name": "Device", "bit": 0},
                identifiers["network_list"]: {"name": "Network", "bit": 1},
                identifiers["global_list"]: {"name": "Global", "bit": 2},
            },
            "scopes": {
                "global": {
                    "lists": [identifiers["global_list"]],
                    "allow": "allow.txt",
                },
                "networks": {
                    identifiers["network_a"]: {
                        "interface": "lan",
                        "lists": [identifiers["network_list"]],
                        "allow": f"allow-network-{identifiers['network_a']}.txt",
                    },
                    identifiers["network_b"]: {
                        "interface": "opt1",
                        "lists": [],
                        "allow": f"allow-network-{identifiers['network_b']}.txt",
                    },
                },
                "devices": {
                    identifiers["device"]: {
                        "lists": [identifiers["device_list"]],
                        "allow": f"allow-device-{identifiers['device']}.txt",
                    }
                },
            },
            "alerts": {
                identifiers["any_rule"]: {
                    "id": identifiers["any_rule"],
                    "lists": "any",
                    "networks": "any",
                    "devices": "any",
                },
                identifiers["network_rule"]: {
                    "id": identifiers["network_rule"],
                    "lists": [1],
                    "networks": [identifiers["network_a"]],
                    "devices": [],
                },
                identifiers["device_rule"]: {
                    "id": identifiers["device_rule"],
                    "lists": [0],
                    "networks": [],
                    "devices": [identifiers["device"]],
                },
            }
            if include_alerts
            else {},
        }
        (self.data_directory / "manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        (self.data_directory / "domains.tsv").write_text(
            "".join(
                f"{domain}\t{exact}\t{subtree}\n"
                for domain, exact, subtree in domains
            ),
            encoding="ascii",
        )
        (self.data_directory / "bypass.tsv").write_text("", encoding="ascii")
        (self.data_directory / "allow.txt").write_text(
            "network-list.example.test\nglobal-allow.example.test\n",
            encoding="ascii",
        )
        (self.data_directory / f"allow-network-{identifiers['network_a']}.txt").write_text(
            "device-list.example.test\nnetwork-allow.example.test\n",
            encoding="ascii",
        )
        (self.data_directory / f"allow-network-{identifiers['network_b']}.txt").write_text(
            "",
            encoding="ascii",
        )
        (self.data_directory / f"allow-device-{identifiers['device']}.txt").write_text(
            "device-allow.example.test\n",
            encoding="ascii",
        )
        (self.data_directory / "generation").write_text(
            f"{generation}\n",
            encoding="ascii",
        )

        return identifiers

    def query_state(
        self,
        name: str,
        query_type: int,
        address: str | None = "192.0.2.10",
        wire_name: bytes | None = None,
    ) -> Any:
        """Create a fake Unbound query state.

        Args:
            name: Query name.
            query_type: Query type.
            address: Client address, or ``None`` for an internal subquery.
            wire_name: Optional exact wire-format query name.

        Returns:
            Mutable namespace matching fields used by the module.

        Since: UNRELEASED
        """

        reply = None

        if address is not None:
            reply = types.SimpleNamespace(
                query_reply=types.SimpleNamespace(addr=address),
                next=None,
            )

        if wire_name is None:
            labels = name.rstrip(".").split(".")
            wire_name = b"".join(
                bytes((len(label.encode("ascii")),)) + label.encode("ascii")
                for label in labels
            ) + b"\x00"

        return types.SimpleNamespace(
            qinfo=types.SimpleNamespace(
                qname=wire_name,
                qname_len=len(wire_name),
                qname_str=name,
                qtype=query_type,
            ),
            mesh_info=types.SimpleNamespace(reply_list=reply),
            ext_state={},
            no_cache_store=0,
            return_rcode=None,
            return_msg=None,
        )

    def reply_info(self, records: list[tuple[str, int]]) -> Any:
        """Create a fake ``reply_info`` answer section.

        Args:
            records: Owner names and host-order RR types.

        Returns:
            Object exposing the SWIG reply and packed-key attributes.

        Since: UNRELEASED
        """

        return self.sectioned_reply_info(records, [], [])

    def sectioned_reply_info(
        self,
        answers: list[tuple[str, int]],
        authorities: list[tuple[str, int]],
        additionals: list[tuple[str, int]],
    ) -> Any:
        """Create fake answer, authority, and additional RRset sections.

        Args:
            answers: Answer owner names and types.
            authorities: Authority owner names and types.
            additionals: Additional owner names and types.

        Returns:
            Object exposing section counts and packed RRsets.

        Since: UNRELEASED
        """

        records = answers + authorities + additionals
        rrsets = [
            types.SimpleNamespace(
                rk=types.SimpleNamespace(dname_str=owner, type=record_type)
            )
            for owner, record_type in records
        ]

        return types.SimpleNamespace(
            an_numrrsets=len(answers),
            ns_numrrsets=len(authorities),
            ar_numrrsets=len(additionals),
            rrset_count=len(rrsets),
            rrsets=rrsets,
        )

    def initialize(self) -> None:
        """Synchronously initialize the module against current test files.

        Since: UNRELEASED
        """

        self.assertTrue(self.module.init_standard(0, object()))
        self.assertIsNotNone(self.module._active_data)

    def read_events(self) -> list[dict[str, Any]]:
        """Read flushed event lines from the disposable state directory.

        Returns:
            Decoded event objects.

        Since: UNRELEASED
        """

        event_path = self.state_directory / "events"

        if event_path.exists() is False:
            return []

        return [
            json.loads(line)
            for line in event_path.read_text(encoding="utf-8").splitlines()
        ]

    def reexecute_source(self) -> None:
        """Execute the script again in the same dictionary, as pythonmod does.

        Since: UNRELEASED
        """

        source = MODULE_PATH.read_text(encoding="utf-8")
        exec(compile(source, str(MODULE_PATH), "exec"), self.module._namespace)
        self.module.DATA_DIRECTORY = str(self.data_directory)
        self.module.MANIFEST_PATH = str(self.data_directory / "manifest.json")
        self.module.DOMAINS_PATH = str(self.data_directory / "domains.tsv")
        self.module.BYPASS_PATH = str(self.data_directory / "bypass.tsv")
        self.module.ALLOW_PATH = str(self.data_directory / "allow.txt")
        self.module.GENERATION_PATH = str(self.data_directory / "generation")
        self.module.LOADED_GENERATION_PATH = str(self.state_directory / "loaded")
        self.module.EVENTS_PATH = str(self.state_directory / "events")
        self.module.EVENTS_DROPPED_PATH = str(
            self.state_directory / "events-dropped"
        )
        self.module.CLIENT_MAP_PATH = str(self.client_directory / "clients.json")
        self.module.WATCH_INTERVAL_SECONDS = 0.01
        self.module.RCODE_NXDOMAIN = 3
        self.module.invalidateQueryInCache = (
            lambda qstate, qinfo: self.invalidated_queries.append((qstate, qinfo))
        )
        self.module.register_inplace_cb_query_response = (
            lambda callback, environment, module_id: (
                self.registrations.append((callback, environment, module_id)) or 1
            )
        )

    def test_blocked_types_return_sinkhole_or_nodata(self) -> None:
        """A, AAAA, and MX receive sinkhole or NODATA responses.

        Since: UNRELEASED
        """

        self.write_data("generation-a", [("example.test", "0", "")])
        self.initialize()
        expectations = [
            (self.module.RR_TYPE_A, "0.0.0.0"),
            (self.module.RR_TYPE_AAAA, "::"),
            (15, None),
        ]

        for query_type, answer_value in expectations:
            with self.subTest(query_type=query_type):
                qstate = self.query_state("example.test.", query_type)
                self.assertTrue(
                    self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)
                )
                self.assertEqual(self.module.MODULE_FINISHED, qstate.ext_state[0])
                self.assertEqual(self.module.RCODE_NOERROR, qstate.return_rcode)
                self.assertEqual(1, qstate.no_cache_store)
                self.assertEqual(2, qstate.return_msg.rep.security)

                if answer_value is None:
                    self.assertEqual([], qstate.return_msg.answer)
                else:
                    self.assertIn(answer_value, qstate.return_msg.answer[0])

    def test_blocked_answers_escape_unusual_wire_labels(self) -> None:
        """Blocked owners preserve spaces and high bytes from the query wire name."""

        self.write_data("generation-unusual-wire", [("example.test", "", "0")])
        self.initialize()
        cases = [
            (
                "odd label.example.test.",
                b"\x09odd label\x07example\x04test\x00",
                self.module.RR_TYPE_A,
                r"odd\032label.example.test. 60 IN A 0.0.0.0",
            ),
            (
                "?.example.test.",
                b"\x01\x80\x07example\x04test\x00",
                self.module.RR_TYPE_AAAA,
                r"\128.example.test. 60 IN AAAA ::",
            ),
        ]

        for display_name, wire_name, query_type, expected_answer in cases:
            with self.subTest(wire_name=wire_name):
                qstate = self.query_state(
                    display_name,
                    query_type,
                    wire_name=wire_name,
                )
                self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)

                self.assertEqual(self.module.MODULE_FINISHED, qstate.ext_state[0])
                self.assertEqual(self.module.RCODE_NOERROR, qstate.return_rcode)
                self.assertEqual(1, qstate.no_cache_store)
                self.assertEqual(expected_answer, qstate.return_msg.answer[0])
                self.assertEqual(
                    expected_answer.split(" 60 IN ", maxsplit=1)[0],
                    qstate.return_msg.name,
                )

    def test_bypass_defaults_leave_signal_names_untouched(self) -> None:
        """A fresh or upgraded configuration installs no special DNS answers."""

        self.write_data("generation-bypass-off", [])
        self.write_client_map([], {})
        self.initialize()

        for name in (
            "use-application-dns.net.",
            "mask.icloud.com.",
            "mask-h2.icloud.com.",
            "_dns.resolver.arpa.",
        ):
            with self.subTest(name=name):
                qstate = self.query_state(name, self.module.RR_TYPE_A)
                self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)
                self.assertEqual(self.module.MODULE_WAIT_MODULE, qstate.ext_state[0])
                self.assertIsNone(qstate.return_msg)
                self.assertEqual(0, qstate.no_cache_store)

    def test_bypass_signals_use_nxdomain_only_on_selected_interfaces(self) -> None:
        """Mozilla and Apple signals override allows only for selected clients."""

        self.write_data(
            "generation-bypass-signals",
            [],
            ["use-application-dns.net", "mask.icloud.com"],
            bypass=self.bypass_configuration(
                disable_firefox_doh=True,
                disable_private_relay=True,
            ),
        )
        self.write_client_map(
            [],
            {},
            interfaces=[{"name": "lan", "cidrs": ["192.0.2.0/24"]}],
        )
        self.initialize()

        for name in (
            "use-application-dns.net.",
            "child.use-application-dns.net.",
            "mask.icloud.com.",
            "mask-h2.icloud.com.",
        ):
            with self.subTest(name=name):
                qstate = self.query_state(name, self.module.RR_TYPE_A, "192.0.2.10")
                self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)
                self.assertEqual(self.module.MODULE_FINISHED, qstate.ext_state[0])
                self.assertEqual(self.module.RCODE_NXDOMAIN, qstate.return_rcode)
                self.assertEqual([], qstate.return_msg.answer)

        off_interface = self.query_state(
            "use-application-dns.net.",
            self.module.RR_TYPE_A,
            "198.51.100.10",
        )
        self.module.operate(0, self.module.MODULE_EVENT_NEW, off_interface, None)
        self.assertEqual(self.module.MODULE_WAIT_MODULE, off_interface.ext_state[0])
        self.assertIsNone(off_interface.return_msg)

    def test_bypass_list_names_respect_allowed_domains_and_interface_scope(self) -> None:
        """Provider, Tor, and VPN names block after ordinary allowed-domain policy."""

        self.write_data(
            "generation-bypass-lists",
            [],
            ["allowed.provider.example.test"],
            bypass_domains=[
                ("provider.example.test", "", "encrypted_dns"),
                ("relay.example.test", "tor", ""),
                ("tunnel.example.test", "vpn", ""),
            ],
            bypass=self.bypass_configuration(
                block_encrypted_dns=True,
                block_tor=True,
                block_vpn=True,
            ),
        )
        self.write_client_map(
            [],
            {},
            interfaces=[{"name": "lan", "cidrs": ["192.0.2.0/24"]}],
        )
        self.initialize()

        allowed = self.query_state(
            "allowed.provider.example.test.",
            self.module.RR_TYPE_A,
        )
        self.module.operate(0, self.module.MODULE_EVENT_NEW, allowed, None)
        self.assertEqual(self.module.MODULE_WAIT_MODULE, allowed.ext_state[0])

        for name in (
            "blocked.provider.example.test.",
            "relay.example.test.",
            "tunnel.example.test.",
        ):
            with self.subTest(name=name):
                qstate = self.query_state(name, self.module.RR_TYPE_A)
                self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)
                self.assertEqual(self.module.MODULE_FINISHED, qstate.ext_state[0])
                self.assertIn("0.0.0.0", qstate.return_msg.answer[0])

        off_interface = self.query_state(
            "relay.example.test.",
            self.module.RR_TYPE_A,
            "198.51.100.10",
        )
        self.module.operate(0, self.module.MODULE_EVENT_NEW, off_interface, None)
        self.assertEqual(self.module.MODULE_WAIT_MODULE, off_interface.ext_state[0])

    def test_discovery_can_return_nodata(self) -> None:
        """DDR NODATA is a successful empty response on the selected interface."""

        self.write_data(
            "generation-ddr-nodata",
            [],
            bypass=self.bypass_configuration(discovery="nodata"),
        )
        self.write_client_map(
            [],
            {},
            interfaces=[{"name": "lan", "cidrs": ["192.0.2.0/24"]}],
        )
        self.initialize()
        qstate = self.query_state("_dns.resolver.arpa.", self.module.RR_TYPE_A)
        self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)

        self.assertEqual(self.module.MODULE_FINISHED, qstate.ext_state[0])
        self.assertEqual(self.module.RCODE_NOERROR, qstate.return_rcode)
        self.assertEqual([], qstate.return_msg.answer)
        self.assertEqual(1, qstate.no_cache_store)

    def test_discovery_returns_nxdomain_outside_selected_interfaces(self) -> None:
        """DDR keeps Unbound's former NXDOMAIN answer outside Bypass scope."""

        self.write_data(
            "generation-ddr-outside-scope",
            [],
            bypass=self.bypass_configuration(discovery="nodata"),
        )
        self.write_client_map(
            [],
            {},
            interfaces=[{"name": "lan", "cidrs": ["192.0.2.0/24"]}],
        )
        self.initialize()

        for address in ("198.51.100.10", None):
            with self.subTest(address=address):
                qstate = self.query_state(
                    "_dns.resolver.arpa.",
                    self.module.RR_TYPE_A,
                    address,
                )
                self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)
                self.assertEqual(self.module.MODULE_FINISHED, qstate.ext_state[0])
                self.assertEqual(self.module.RCODE_NXDOMAIN, qstate.return_rcode)
                self.assertEqual([], qstate.return_msg.answer)
                self.assertEqual(1, qstate.no_cache_store)

    def test_discovery_can_advertise_dns_over_tls_with_svcb(self) -> None:
        """DDR SVCB uses the validated certificate hostname and port 853."""

        self.write_data(
            "generation-ddr-svcb",
            [],
            bypass=self.bypass_configuration(
                discovery="advertise",
                discovery_hostname="resolver.example.test",
                discovery_port=853,
            ),
        )
        self.write_client_map(
            [],
            {},
            interfaces=[{"name": "lan", "cidrs": ["192.0.2.0/24"]}],
        )
        self.initialize()
        qstate = self.query_state("_dns.resolver.arpa.", 64)
        self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)

        self.assertEqual(self.module.MODULE_FINISHED, qstate.ext_state[0])
        self.assertEqual(self.module.RCODE_NOERROR, qstate.return_rcode)
        self.assertEqual(1, qstate.no_cache_store)
        self.assertEqual(
            [
                "_dns.resolver.arpa. 60 IN SVCB "
                "1 resolver.example.test. alpn=dot port=853"
            ],
            qstate.return_msg.answer,
        )

    def test_scope_decision_order_matrix(self) -> None:
        """All six policy checks and the final pass execute in binding order.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data("generation-scope-order")
        self.write_client_map(
            [
                {"id": identifiers["network_a"], "cidrs": ["192.0.2.0/24"]},
                {"id": identifiers["network_b"], "cidrs": ["198.51.100.0/24"]},
            ],
            {"192.0.2.10": identifiers["device"]},
        )
        self.initialize()
        data = self.module._active_data
        device_id = identifiers["device"]
        network_id = identifiers["network_a"]
        matrix = {
            "device-allow.example.test": "allow",
            "device-list.example.test": "block",
            "network-allow.example.test": "allow",
            "network-list.example.test": "block",
            "global-allow.example.test": "allow",
            "global-list.example.test": "block",
            "otherwise.example.test": "pass",
        }

        for name, expected in matrix.items():
            with self.subTest(name=name):
                self.assertEqual(
                    expected,
                    data.decision(name, device_id, network_id),
                )

    def test_alert_events_match_rules_and_deciding_list_level(self) -> None:
        """Only matching blocks emit the deciding level's list identifiers.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data(
            "generation-alert-events",
            include_alerts=True,
        )
        self.write_client_map(
            [{"id": identifiers["network_a"], "cidrs": ["192.0.2.0/24"]}],
            {"192.0.2.10": identifiers["device"]},
        )
        self.initialize()

        for name, address in [
            ("device-list.example.test.", "192.0.2.10"),
            ("network-list.example.test.", "192.0.2.10"),
            ("global-list.example.test.", "192.0.2.10"),
            ("otherwise.example.test.", "192.0.2.10"),
            ("device-allow.example.test.", "192.0.2.10"),
            ("global-list.example.test.", None),
        ]:
            qstate = self.query_state(name, self.module.RR_TYPE_A, address)
            self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)

        self.module._flush_events()
        events = self.read_events()
        self.assertEqual(3, len(events))
        self.assertEqual(
            [identifiers["device_list"]],
            events[0]["lists"],
        )
        self.assertEqual(
            [identifiers["any_rule"], identifiers["device_rule"]],
            events[0]["rules"],
        )
        self.assertEqual(
            [identifiers["network_list"]],
            events[1]["lists"],
        )
        self.assertEqual(
            [identifiers["any_rule"], identifiers["network_rule"]],
            events[1]["rules"],
        )
        self.assertEqual([identifiers["global_list"]], events[2]["lists"])
        self.assertEqual([identifiers["any_rule"]], events[2]["rules"])
        self.assertTrue(all(event["cname"] is None for event in events))

    def test_cname_alert_event_names_blocked_owner(self) -> None:
        """A downstream CNAME block records the query and blocked owner.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data(
            "generation-alert-cname",
            include_alerts=True,
        )
        self.write_client_map(
            [{"id": identifiers["network_a"], "cidrs": ["192.0.2.0/24"]}],
            {},
        )
        self.initialize()
        qstate = self.query_state(
            "alias.example.test.",
            self.module.RR_TYPE_A,
            "192.0.2.44",
        )
        qstate.return_msg = types.SimpleNamespace(
            rep=self.reply_info(
                [("cname-network.example.test.", self.module.RR_TYPE_A)]
            )
        )

        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, qstate, None)
        self.module._flush_events()
        events = self.read_events()
        self.assertEqual(1, len(events))
        self.assertEqual("alias.example.test", events[0]["name"])
        self.assertEqual("cname-network.example.test", events[0]["cname"])
        self.assertEqual([identifiers["network_list"]], events[0]["lists"])
        self.assertEqual(
            [identifiers["any_rule"], identifiers["network_rule"]],
            events[0]["rules"],
        )

    def test_same_blocking_owner_does_not_set_cname(self) -> None:
        """An event never describes the query name as its own CNAME owner.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data(
            "generation-alert-same-owner",
            include_alerts=True,
        )
        self.write_client_map(
            [{"id": identifiers["network_a"], "cidrs": ["192.0.2.0/24"]}],
            {},
        )
        self.initialize()
        self.module._queue_block_event(
            self.module._active_data,
            "192.0.2.44",
            None,
            identifiers["network_a"],
            "cname-network.example.test",
            "cname-network.example.test",
            1 << 1,
        )
        self.module._flush_events()

        self.assertIsNone(self.read_events()[0]["cname"])

    def test_watcher_coalesces_identical_blocks_with_counts(self) -> None:
        """One chatty name leaves room for another event in the same tick.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data(
            "generation-alert-coalesce",
            include_alerts=True,
        )
        self.write_client_map([], {})
        self.module.WATCH_INTERVAL_SECONDS = 60.0
        self.initialize()

        for _index in range(5):
            self.module._queue_block_event(
                self.module._active_data,
                "192.0.2.10",
                None,
                None,
                "global-list.example.test",
                None,
                1 << 2,
            )

        self.module._queue_block_event(
            self.module._active_data,
            "192.0.2.11",
            None,
            None,
            "global-list.example.test",
            None,
            1 << 2,
        )
        self.module._flush_events()
        events = self.read_events()

        self.assertEqual(2, len(events))
        self.assertEqual(5, events[0]["count"])
        self.assertEqual(1, events[1]["count"])

    def test_brief_queue_lock_contention_waits_without_a_drop(self) -> None:
        """The DNS path tolerates a short watcher snapshot lock hold.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data(
            "generation-alert-queue-lock",
            include_alerts=True,
        )
        self.write_client_map([], {})
        self.module.WATCH_INTERVAL_SECONDS = 60.0
        self.initialize()
        lock_held = threading.Event()

        def briefly_hold_lock() -> None:
            with self.module._event_lock:
                lock_held.set()
                time.sleep(0.002)

        holder = threading.Thread(target=briefly_hold_lock)
        holder.start()
        self.assertTrue(lock_held.wait(timeout=1.0))
        self.module._queue_block_event(
            self.module._active_data,
            "192.0.2.10",
            None,
            None,
            "global-list.example.test",
            None,
            1 << 2,
        )
        holder.join()

        self.assertEqual(1, len(self.module._event_queue))
        self.assertEqual(0, self.module._events_dropped)

    def test_watcher_retains_batch_while_reader_holds_file_lock(self) -> None:
        """The append side retries rather than writing through the reader lock.

        Since: UNRELEASED
        """

        self.write_scoped_data(
            "generation-alert-file-lock",
            include_alerts=True,
        )
        self.write_client_map([], {})
        self.module.WATCH_INTERVAL_SECONDS = 60.0
        self.initialize()
        self.module._queue_block_event(
            self.module._active_data,
            "192.0.2.10",
            None,
            None,
            "global-list.example.test",
            None,
            1 << 2,
        )
        event_path = self.state_directory / "events"

        with event_path.open("a+b") as event_file:
            fcntl.flock(event_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.module._flush_events()
            self.assertEqual(1, len(self.module._event_queue))
            fcntl.flock(event_file.fileno(), fcntl.LOCK_UN)

        self.module._flush_events()
        self.assertEqual([], self.module._event_queue)
        self.assertEqual(1, len(self.read_events()))

    def test_dropped_marker_is_written_only_when_its_value_changes(self) -> None:
        """Unchanged drop totals do not replace the marker every watcher tick.

        Since: UNRELEASED
        """

        calls: list[tuple[str, str]] = []
        original_write = self.module._write_state_marker

        def counted_write(path: str, value: str, prefix: str, mode: int = 0o644) -> None:
            calls.append((path, value))
            original_write(path, value, prefix, mode)

        self.module._write_state_marker = counted_write

        with self.module._event_lock:
            self.module._events_dropped = 3

        self.module._persist_dropped_marker()
        self.module._persist_dropped_marker()

        self.assertEqual([(self.module.EVENTS_DROPPED_PATH, "3")], calls)

    def test_bad_alert_section_disables_events_but_keeps_blocking(self) -> None:
        """Malformed alert metadata cannot make the policy fail open.

        Since: UNRELEASED
        """

        self.write_scoped_data(
            "generation-bad-alert-section",
            include_alerts=True,
        )
        manifest_path = self.data_directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["alerts"] = ["invalid"]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.write_client_map([], {})
        self.initialize()
        qstate = self.query_state(
            "global-list.example.test.",
            self.module.RR_TYPE_A,
            "192.0.2.10",
        )

        self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)
        self.module._flush_events()

        self.assertEqual(self.module.MODULE_FINISHED, qstate.ext_state[0])
        self.assertEqual([], self.read_events())
        self.assertEqual(
            1,
            sum("alert rules disabled" in message for message in self.logs),
        )

    def test_event_queue_and_file_caps_count_drops(self) -> None:
        """Queue and file bounds discard new events and persist the counter.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data(
            "generation-alert-bounds",
            include_alerts=True,
        )
        self.write_client_map([], {})
        self.module.WATCH_INTERVAL_SECONDS = 60.0
        self.initialize()
        data = self.module._active_data

        for _index in range(self.module.MAXIMUM_QUEUED_EVENTS + 1):
            self.module._queue_block_event(
                data,
                "192.0.2.10",
                None,
                None,
                "global-list.example.test",
                None,
                1 << 2,
            )

        self.assertEqual(self.module.MAXIMUM_QUEUED_EVENTS, len(self.module._event_queue))
        self.assertEqual(1, self.module._events_dropped)
        self.module.MAXIMUM_EVENT_FILE_BYTES = 0
        self.module._flush_events()
        self.assertEqual([], self.module._event_queue)
        self.assertEqual(
            self.module.MAXIMUM_QUEUED_EVENTS + 1,
            self.module._events_dropped,
        )
        self.assertEqual(
            str(self.module._events_dropped),
            (self.state_directory / "events-dropped").read_text(
                encoding="ascii"
            ).strip(),
        )

    def test_watcher_flushes_events(self) -> None:
        """The existing watcher appends queued events without another query.

        Since: UNRELEASED
        """

        self.write_data(
            "generation-watcher-event",
            [("blocked.example.test", "0", "")],
        )
        manifest_path = self.data_directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        rule_id = "44444444444444444444444444444444"
        manifest["alerts"] = {
            rule_id: {
                "id": rule_id,
                "lists": "any",
                "networks": "any",
                "devices": "any",
            }
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.initialize()
        qstate = self.query_state("blocked.example.test.", self.module.RR_TYPE_A)
        self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)
        deadline = time.monotonic() + 2.0

        while time.monotonic() < deadline and self.read_events() == []:
            time.sleep(0.005)

        self.assertEqual(1, len(self.read_events()))

    def test_deinit_flushes_and_stashes_unwritten_events(self) -> None:
        """Deinit flushes first and a failed write survives same-interpreter reload.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data(
            "generation-alert-stash",
            include_alerts=True,
        )
        self.write_client_map([], {})
        self.initialize()
        self.module.EVENTS_PATH = str(self.state_directory)
        self.module._queue_block_event(
            self.module._active_data,
            "192.0.2.10",
            None,
            None,
            "global-list.example.test",
            None,
            1 << 2,
        )
        self.module._events_dropped = 7
        self.assertTrue(self.module.deinit(0))
        self.reexecute_source()
        self.assertTrue(self.module.init_standard(0, object()))
        self.assertEqual(1, len(self.module._event_queue))
        self.assertEqual(7, self.module._events_dropped)
        self.module._flush_events()
        self.assertEqual(1, len(self.read_events()))

    def test_dns_path_does_not_raise_when_event_file_is_unwritable(self) -> None:
        """A watcher write failure never escapes into blocking query handling.

        Since: UNRELEASED
        """

        self.write_data(
            "generation-unwritable-events",
            [("blocked.example.test", "0", "")],
        )
        manifest_path = self.data_directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        rule_id = "44444444444444444444444444444444"
        manifest["alerts"] = {
            rule_id: {
                "id": rule_id,
                "lists": "any",
                "networks": "any",
                "devices": "any",
            }
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.initialize()
        self.module.EVENTS_PATH = str(self.state_directory)
        qstate = self.query_state("blocked.example.test.", self.module.RR_TYPE_A)

        self.assertTrue(
            self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)
        )
        self.assertEqual(self.module.MODULE_FINISHED, qstate.ext_state[0])
        self.module._flush_events()
        self.assertEqual(1, len(self.module._event_queue))

    def test_client_lookup_uses_longest_prefix_and_ipv4_mapped_addresses(self) -> None:
        """Exact devices beat networks and overlapping networks use longest prefix.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data("generation-client-lookup")
        self.write_client_map(
            [
                {"id": identifiers["network_a"], "cidrs": ["192.0.2.0/24"]},
                {"id": identifiers["network_b"], "cidrs": ["192.0.2.0/25"]},
            ],
            {"192.0.2.20": identifiers["device"]},
        )
        self.initialize()
        client_map = self.module._active_client_map

        self.assertEqual(
            (identifiers["device"], identifiers["network_b"], None),
            self.module._lookup_client_scopes("192.0.2.20", client_map),
        )
        self.assertEqual(
            (identifiers["device"], identifiers["network_b"], None),
            self.module._lookup_client_scopes("::ffff:192.0.2.20", client_map),
        )
        self.assertEqual(
            (None, identifiers["network_a"], None),
            self.module._lookup_client_scopes("192.0.2.200", client_map),
        )

    def test_watcher_reloads_client_map_and_clears_lookup_cache(self) -> None:
        """A changed digest publishes new scopes and clears prior address decisions.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data("generation-map-watch")
        self.write_client_map(
            [{"id": identifiers["network_a"], "cidrs": ["192.0.2.0/24"]}],
            {},
        )
        self.initialize()
        self.assertEqual(
            (None, identifiers["network_a"], None),
            self.module._lookup_client_scopes(
                "192.0.2.44",
                self.module._active_client_map,
            ),
        )
        self.assertNotEqual({}, self.module._client_lookup_cache)
        digest = self.write_client_map(
            [{"id": identifiers["network_b"], "cidrs": ["192.0.2.0/24"]}],
            {},
        )
        self.wait_for_client_digest(digest)

        self.assertEqual({}, self.module._client_lookup_cache)
        self.assertEqual(
            (None, identifiers["network_b"], None),
            self.module._lookup_client_scopes(
                "192.0.2.44",
                self.module._active_client_map,
            ),
        )

    def test_client_lookup_cache_eviction_survives_concurrent_clear(self) -> None:
        """A watcher clear cannot turn bounded cache eviction into a failed lookup.

        Since:
            1.0.0
        """

        eviction_started = threading.Event()
        cache_cleared = threading.Event()
        cache = CoordinatedClientCache(eviction_started, cache_cleared)
        client_map = self.module.ClientMapData(None, {}, (), ())
        failures: list[BaseException] = []
        self.module.CLIENT_LOOKUP_CACHE_SIZE = 8
        self.module._client_lookup_cache = cache

        for address_suffix in range(8):
            address = f"192.0.2.{address_suffix}"

            self.assertEqual(
                (None, None, None),
                self.module._lookup_client_scopes(address, client_map),
            )

        def clear_cache() -> None:
            """Clear the cache after lookup chooses its eviction candidate."""

            if eviction_started.wait(timeout=2.0) is False:
                failures.append(RuntimeError("the eviction did not start"))

                return

            cache.clear()
            cache_cleared.set()

        clear_thread = threading.Thread(target=clear_cache)

        clear_thread.start()

        for address_suffix in range(8, 64):
            address = f"192.0.2.{address_suffix}"

            try:
                result = self.module._lookup_client_scopes(address, client_map)
            except BaseException as exception:
                failures.append(exception)

                break

            self.assertEqual((None, None, None), result)

        clear_thread.join(timeout=2.0)

        self.assertFalse(clear_thread.is_alive())
        self.assertEqual([], failures)

    def test_bad_client_map_keeps_last_good_and_logs_once(self) -> None:
        """Malformed map content never replaces the last validated client mapping.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data("generation-map-bad")
        digest = self.write_client_map(
            [{"id": identifiers["network_a"], "cidrs": ["192.0.2.0/24"]}],
            {},
        )
        self.initialize()
        (self.client_directory / "clients.json").write_text("{bad", encoding="utf-8")
        deadline = time.monotonic() + 3.0

        while time.monotonic() < deadline:
            failures = [
                message
                for message in self.logs
                if "client map is unavailable" in message
            ]

            if failures:
                break

            time.sleep(0.005)

        time.sleep(0.05)
        self.assertEqual(digest, self.module._active_client_map.digest)
        self.assertEqual(
            1,
            len(
                [
                    message
                    for message in self.logs
                    if "client map is unavailable" in message
                ]
            ),
        )

    def test_unknown_client_map_scope_ids_are_ignored(self) -> None:
        """Valid map records unknown to the manifest cannot acquire policy.

        Since: UNRELEASED
        """

        self.write_scoped_data("generation-map-unknown")
        unknown_network = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        unknown_device = "ffffffffffffffffffffffffffffffff"
        self.write_client_map(
            [{"id": unknown_network, "cidrs": ["not-a-cidr"]}],
            {"not-an-address": unknown_device},
        )
        self.initialize()

        self.assertEqual(
            (None, None, None),
            self.module._lookup_client_scopes(
                "192.0.2.10",
                self.module._active_client_map,
            ),
        )

    def test_cname_owner_decisions_are_per_client_and_query_allow_wins(self) -> None:
        """CNAME owners block by client while a query-level device allow passes.

        Since: UNRELEASED
        """

        identifiers = self.write_scoped_data("generation-cname-clients")
        self.write_client_map(
            [
                {"id": identifiers["network_a"], "cidrs": ["192.0.2.0/24"]},
                {"id": identifiers["network_b"], "cidrs": ["198.51.100.0/24"]},
            ],
            {"192.0.2.10": identifiers["device"]},
        )
        self.initialize()
        answer = self.reply_info(
            [("cname-network.example.test.", self.module.RR_TYPE_A)]
        )

        network_a = self.query_state(
            "alias.example.test.",
            self.module.RR_TYPE_A,
            "192.0.2.44",
        )
        network_a.return_msg = types.SimpleNamespace(rep=answer)
        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, network_a, None)
        self.assertIn("0.0.0.0", network_a.return_msg.answer[0])

        network_b = self.query_state(
            "alias.example.test.",
            self.module.RR_TYPE_A,
            "198.51.100.44",
        )
        network_b_response = types.SimpleNamespace(rep=answer)
        network_b.return_msg = network_b_response
        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, network_b, None)
        self.assertIs(network_b_response, network_b.return_msg)

        allowed_device = self.query_state(
            "device-allow.example.test.",
            self.module.RR_TYPE_A,
            "192.0.2.10",
        )
        allowed_response = types.SimpleNamespace(rep=answer)
        allowed_device.return_msg = allowed_response
        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, allowed_device, None)
        self.assertIs(allowed_response, allowed_device.return_msg)

    def test_subtree_allow_and_unusual_child_matching(self) -> None:
        """Allow roots pass while underscore children of listed roots stay listed.

        Since: UNRELEASED
        """

        self.write_data(
            "generation-b",
            [("example.test", "", "0")],
            ["allowed.example.test"],
        )
        self.initialize()
        allowed_state = self.query_state(
            "child.allowed.example.test.",
            self.module.RR_TYPE_A,
        )
        unusual_state = self.query_state("_x.example.test.", self.module.RR_TYPE_A)

        self.module.operate(0, self.module.MODULE_EVENT_NEW, allowed_state, None)
        self.module.operate(0, self.module.MODULE_EVENT_NEW, unusual_state, None)

        self.assertEqual(self.module.MODULE_WAIT_MODULE, allowed_state.ext_state[0])
        self.assertEqual(1, allowed_state.no_cache_store)
        self.assertIsNone(allowed_state.return_msg)
        self.assertEqual(self.module.MODULE_FINISHED, unusual_state.ext_state[0])
        self.assertEqual(1, unusual_state.no_cache_store)

    def test_internal_subquery_is_not_blocked_but_is_not_cached(self) -> None:
        """A listed name with no client address always passes without cache storage.

        Since: UNRELEASED
        """

        self.write_data("generation-c", [("example.test", "0", "")])
        self.initialize()
        qstate = self.query_state("example.test.", self.module.RR_TYPE_A, None)

        self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)

        self.assertEqual(self.module.MODULE_WAIT_MODULE, qstate.ext_state[0])
        self.assertEqual(1, qstate.no_cache_store)
        self.assertIsNone(qstate.return_msg)

    def test_zero_lists_load_and_block_nothing(self) -> None:
        """An object-valued empty list map is valid and blocks no names.

        Since: UNRELEASED
        """

        self.write_data("generation-zero", [], include_list=False)
        self.initialize()
        qstate = self.query_state("example.test.", self.module.RR_TYPE_A)

        self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)

        self.assertEqual(self.module.MODULE_WAIT_MODULE, qstate.ext_state[0])
        self.assertEqual(0, qstate.no_cache_store)
        self.assertEqual(
            "generation-zero",
            (self.state_directory / "loaded").read_text(encoding="ascii").strip(),
        )

    def test_missing_startup_data_does_not_block_resolver(self) -> None:
        """Missing local files log an error and leave every query untouched.

        Since: UNRELEASED
        """

        self.assertTrue(self.module.init_standard(0, object()))
        self.assertIsNone(self.module._active_data)
        qstate = self.query_state("example.test.", self.module.RR_TYPE_A)

        self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)

        self.assertEqual(self.module.MODULE_WAIT_MODULE, qstate.ext_state[0])
        self.assertEqual(0, qstate.no_cache_store)
        self.assertIsNone(qstate.return_msg)
        self.assertTrue(any("pass through" in message for message in self.logs))

    def test_reload_swaps_valid_data_and_suppresses_failed_generation(self) -> None:
        """A valid content change swaps once and one bad stamp is not reparsed.

        Since: UNRELEASED
        """

        self.write_data("generation-d1", [("old.example.test", "0", "")])
        self.initialize()
        first_mtime = os.stat(self.module.GENERATION_PATH).st_mtime_ns
        self.write_data("generation-d2", [("new.example.test", "0", "")])
        os.utime(
            self.module.GENERATION_PATH,
            ns=(first_mtime, first_mtime),
        )
        self.wait_for_generation("generation-d2")

        self.assertEqual("generation-d2", self.module._active_data.generation)
        self.assertIn("new.example.test", self.module._active_data.domains)
        original_load = self.module._load_data
        load_count = 0

        def counted_load(stop_event: threading.Event | None = None) -> Any:
            nonlocal load_count
            load_count += 1

            return original_load(stop_event)

        self.module._load_data = counted_load
        (self.data_directory / "generation").write_text(
            "generation-d3\n",
            encoding="ascii",
        )
        deadline = time.monotonic() + 3.0

        while (
            self.module._failed_generation_id != "generation-d3"
            and time.monotonic() < deadline
        ):
            time.sleep(0.005)

        time.sleep(0.05)

        self.assertEqual(1, load_count)
        self.assertEqual("generation-d2", self.module._active_data.generation)
        self.assertTrue(any("reload failed" in message for message in self.logs))

    def test_memory_error_keeps_current_generation(self) -> None:
        """Memory exhaustion is caught and leaves the current policy active.

        Since: UNRELEASED
        """

        self.write_data("generation-e1", [("old.example.test", "0", "")])
        self.initialize()

        def fail_load(_stop_event: threading.Event | None = None) -> Any:
            raise MemoryError("simulated exhaustion")

        self.module._load_data = fail_load
        self.write_data("generation-e2", [("new.example.test", "0", "")])
        deadline = time.monotonic() + 3.0

        while (
            self.module._failed_generation_id != "generation-e2"
            and time.monotonic() < deadline
        ):
            time.sleep(0.005)

        self.assertEqual("generation-e1", self.module._active_data.generation)
        self.assertTrue(any("simulated exhaustion" in message for message in self.logs))

    def test_concurrent_queries_never_wait_while_watcher_loads(self) -> None:
        """Queries use old data immediately while the watcher owns one slow load.

        Since: UNRELEASED
        """

        self.write_data("generation-f1", [("old.example.test", "0", "")])
        self.initialize()
        original_load = self.module._load_data
        load_started = threading.Event()
        release_load = threading.Event()
        count_lock = threading.Lock()
        load_count = 0

        def slow_load(stop_event: threading.Event | None = None) -> Any:
            nonlocal load_count

            with count_lock:
                load_count += 1

            load_started.set()
            release_load.wait(timeout=2.0)

            return original_load(stop_event)

        self.module._load_data = slow_load
        self.write_data("generation-f2", [("new.example.test", "0", "")])
        self.assertTrue(load_started.wait(timeout=1.0))
        durations: list[float] = []
        states: list[Any] = []

        def query() -> None:
            qstate = self.query_state("old.example.test.", self.module.RR_TYPE_A)
            started = time.monotonic()
            self.module.operate(0, self.module.MODULE_EVENT_NEW, qstate, None)
            durations.append(time.monotonic() - started)
            states.append(qstate)

        query_threads = [threading.Thread(target=query) for _index in range(40)]

        try:
            for worker in query_threads:
                worker.start()

            for worker in query_threads:
                worker.join(timeout=1.0)

            self.assertTrue(all(not worker.is_alive() for worker in query_threads))
            self.assertEqual(40, len(durations))
            self.assertLess(max(durations), 0.25)
            self.assertTrue(
                all(
                    state.ext_state[0] == self.module.MODULE_FINISHED
                    for state in states
                )
            )
            self.assertEqual(1, load_count)
        finally:
            release_load.set()

        self.wait_for_loader()
        self.assertEqual("generation-f2", self.module._active_data.generation)

    def test_cold_start_loads_synchronously_before_init_returns(self) -> None:
        """A cold start publishes readable compiler data synchronously.

        Since: UNRELEASED
        """

        self.write_data("generation-cold", [("cold.example.net", "0", "")])
        original_load = self.module._load_data
        load_finished = False

        def counted_load(stop_event: threading.Event | None = None) -> Any:
            nonlocal load_finished
            loaded = original_load(stop_event)
            load_finished = True

            return loaded

        self.module._load_data = counted_load

        self.assertTrue(self.module.init_standard(0, object()))
        self.assertTrue(load_finished)
        self.assertEqual("generation-cold", self.module._active_data.generation)

    def test_watcher_loads_new_stamp_without_queries(self) -> None:
        """The watcher publishes changed stamp content without query activity.

        Since: UNRELEASED
        """

        self.write_data("generation-watch-1", [("old.example.net", "0", "")])
        self.initialize()
        self.write_data("generation-watch-2", [("new.example.net", "0", "")])

        self.wait_for_generation("generation-watch-2")

        self.assertIn("new.example.net", self.module._active_data.domains)

    def test_moddone_invalidates_listed_owners_and_blocks_only_eligible_client(self) -> None:
        """Listed answer owners expire once and block only eligible client replies.

        Since: UNRELEASED
        """

        self.write_data(
            "generation-moddone",
            [("blocked.example.net", "", "0")],
            ["allowed.example.org"],
        )
        self.initialize()
        answer = self.reply_info(
            [
                ("alias.example.org.", self.module.RR_TYPE_CNAME),
                ("blocked.example.net.", self.module.RR_TYPE_A),
            ]
        )

        client = self.query_state("alias.example.org.", self.module.RR_TYPE_A)
        client.return_msg = types.SimpleNamespace(rep=answer)
        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, client, None)
        self.assertEqual(self.module.MODULE_FINISHED, client.ext_state[0])
        self.assertIn("0.0.0.0", client.return_msg.answer[0])
        self.assertEqual([(client, client.qinfo)], self.invalidated_queries)

        internal = self.query_state(
            "alias.example.org.",
            self.module.RR_TYPE_A,
            None,
        )
        internal_response = types.SimpleNamespace(rep=answer)
        internal.return_msg = internal_response
        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, internal, None)
        self.assertIs(internal_response, internal.return_msg)
        self.assertEqual((internal, internal.qinfo), self.invalidated_queries[-1])
        self.assertEqual(2, len(self.invalidated_queries))

        allowed = self.query_state(
            "child.allowed.example.org.",
            self.module.RR_TYPE_A,
        )
        allowed_response = types.SimpleNamespace(rep=answer)
        allowed.return_msg = allowed_response
        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, allowed, None)
        self.assertIs(allowed_response, allowed.return_msg)
        self.assertEqual((allowed, allowed.qinfo), self.invalidated_queries[-1])
        self.assertEqual(3, len(self.invalidated_queries))

        clean = self.query_state("clean.example.org.", self.module.RR_TYPE_A)
        clean_response = types.SimpleNamespace(
            rep=self.reply_info([("clean.example.org.", self.module.RR_TYPE_A)])
        )
        clean.return_msg = clean_response
        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, clean, None)
        self.assertIs(clean_response, clean.return_msg)
        self.assertEqual(3, len(self.invalidated_queries))

    def test_query_response_callback_prevents_listed_answer_and_additional_storage(
        self,
    ) -> None:
        """Listed answer or additional owners disable storage, but authority does not.

        Since: UNRELEASED
        """

        self.write_data(
            "generation-response-callback",
            [("listed.example.net", "0", "")],
        )
        self.initialize()
        callback = self.registrations[-1][0]
        listed_answer = self.query_state("query.example.org.", self.module.RR_TYPE_A)
        listed_additional = self.query_state(
            "query.example.org.",
            self.module.RR_TYPE_A,
        )
        listed_authority = self.query_state(
            "query.example.org.",
            self.module.RR_TYPE_A,
        )
        unlisted = self.query_state("query.example.org.", self.module.RR_TYPE_A)

        self.assertTrue(
            callback(
                listed_answer,
                types.SimpleNamespace(
                    rep=self.sectioned_reply_info(
                        [("listed.example.net.", self.module.RR_TYPE_A)],
                        [],
                        [],
                    )
                ),
            )
        )
        self.assertTrue(
            callback(
                listed_additional,
                types.SimpleNamespace(
                    rep=self.sectioned_reply_info(
                        [],
                        [],
                        [("listed.example.net.", self.module.RR_TYPE_A)],
                    )
                ),
            )
        )
        self.assertTrue(
            callback(
                listed_authority,
                types.SimpleNamespace(
                    rep=self.sectioned_reply_info(
                        [],
                        [("listed.example.net.", 2)],
                        [],
                    )
                ),
            )
        )
        self.assertTrue(
            callback(
                unlisted,
                types.SimpleNamespace(
                    rep=self.sectioned_reply_info(
                        [("clean.example.org.", self.module.RR_TYPE_A)],
                        [],
                        [],
                    )
                ),
            )
        )

        self.assertEqual(1, listed_answer.no_cache_store)
        self.assertEqual(1, listed_additional.no_cache_store)
        self.assertEqual(0, listed_authority.no_cache_store)
        self.assertEqual(0, unlisted.no_cache_store)

    def test_query_response_callback_is_registered_each_init_and_never_raises(
        self,
    ) -> None:
        """Every lifecycle quietly ignores absent and fails open on malformed responses.

        Since: UNRELEASED
        """

        self.write_data(
            "generation-response-registration",
            [("listed.example.net", "0", "")],
        )
        first_environment = object()
        second_environment = object()
        self.assertTrue(self.module.init_standard(3, first_environment))
        first_callback = self.registrations[-1][0]
        malformed = types.SimpleNamespace(
            rep=types.SimpleNamespace(
                an_numrrsets=2,
                ns_numrrsets=0,
                ar_numrrsets=0,
                rrset_count=1,
                rrsets=[],
            )
        )
        qstate = self.query_state("query.example.org.", self.module.RR_TYPE_A)

        self.assertTrue(first_callback(qstate, None))
        self.assertTrue(first_callback(qstate, types.SimpleNamespace()))
        self.assertEqual(
            [],
            [
                message
                for message in self.logs
                if "upstream response cache check failed" in message
            ],
        )
        self.assertTrue(first_callback(qstate, malformed))
        self.assertTrue(first_callback(qstate, malformed))
        self.assertEqual(
            1,
            len(
                [
                    message
                    for message in self.logs
                    if "upstream response cache check failed" in message
                ]
            ),
        )

        self.assertTrue(self.module.deinit(3))
        self.assertTrue(self.module.init_standard(4, second_environment))
        self.assertEqual(2, len(self.registrations))
        self.assertIs(first_environment, self.registrations[0][1])
        self.assertEqual(3, self.registrations[0][2])
        self.assertIs(second_environment, self.registrations[1][1])
        self.assertEqual(4, self.registrations[1][2])

    def test_query_response_registration_failure_logs_once_and_continues(self) -> None:
        """A registration exception logs one warning without failing initialization.

        Since: UNRELEASED
        """

        def fail_registration(
            _callback: Any,
            _environment: Any,
            _module_id: int,
        ) -> None:
            raise RuntimeError("simulated registration failure")

        self.module.register_inplace_cb_query_response = fail_registration
        self.write_data(
            "generation-response-registration-failure",
            [("listed.example.net", "0", "")],
        )

        self.assertTrue(self.module.init_standard(0, object()))
        self.assertEqual(
            1,
            len(
                [
                    message
                    for message in self.logs
                    if "unable to register upstream response cache check" in message
                ]
            ),
        )

    def test_query_response_refused_registration_logs_once_and_continues(self) -> None:
        """A refused registration logs one warning without failing initialization.

        Since: UNRELEASED
        """

        def refuse_registration(
            _callback: Any,
            _environment: Any,
            _module_id: int,
        ) -> int:
            return 0

        self.module.register_inplace_cb_query_response = refuse_registration
        self.write_data(
            "generation-response-registration-refused",
            [("listed.example.net", "0", "")],
        )

        self.assertTrue(self.module.init_standard(0, object()))
        self.assertEqual(
            1,
            len(
                [
                    message
                    for message in self.logs
                    if "unable to register upstream response cache check" in message
                ]
            ),
        )

    def test_moddone_expires_only_answers_that_were_cacheable(self) -> None:
        """MODDONE skips invalidation after an upstream callback disabled storage.

        Since: UNRELEASED
        """

        self.write_data(
            "generation-moddone-cacheable",
            [("listed.example.net", "0", "")],
        )
        self.initialize()
        answer = self.reply_info(
            [("listed.example.net.", self.module.RR_TYPE_A)]
        )
        cached = self.query_state("alias.example.org.", self.module.RR_TYPE_A, None)
        cached.return_msg = types.SimpleNamespace(rep=answer)
        not_stored = self.query_state(
            "alias.example.org.",
            self.module.RR_TYPE_A,
            None,
        )
        not_stored.no_cache_store = 1
        not_stored.return_msg = types.SimpleNamespace(rep=answer)

        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, cached, None)
        self.module.operate(0, self.module.MODULE_EVENT_MODDONE, not_stored, None)

        self.assertEqual([(cached, cached.qinfo)], self.invalidated_queries)

    def test_deinit_stops_and_joins_watcher_and_running_loader(self) -> None:
        """No watcher or loader survives module deinitialization.

        Since: UNRELEASED
        """

        self.write_data("generation-stop-1", [("old.example.net", "0", "")])
        self.initialize()
        started = threading.Event()
        stopped = threading.Event()

        def cancellable_load(stop_event: threading.Event | None = None) -> Any:
            self.assertIsNotNone(stop_event)
            started.set()

            while not stop_event.is_set():
                time.sleep(0.001)

            stopped.set()
            raise self.module._LoadStopped()

        self.module._load_data = cancellable_load
        self.write_data("generation-stop-2", [("new.example.net", "0", "")])
        self.assertTrue(started.wait(timeout=1.0))
        loader_thread = self.module._loader_thread
        watcher_thread = self.module._watcher_thread
        self.assertTrue(self.module.deinit(0))
        self.assertTrue(stopped.is_set())
        self.assertIsNotNone(loader_thread)
        self.assertFalse(loader_thread.is_alive())
        self.assertIsNotNone(watcher_thread)
        self.assertFalse(watcher_thread.is_alive())

    def test_same_dictionary_reload_reuses_matching_stash_without_parsing(self) -> None:
        """A matching stashed generation is reused by identity after script re-exec.

        Since: UNRELEASED
        """

        self.write_data("generation-stash", [("cached.example.net", "0", "")])
        self.initialize()
        stashed_data = self.module._active_data
        self.module.deinit(0)
        self.reexecute_source()

        def unexpected_load(_stop_event: threading.Event | None = None) -> Any:
            raise AssertionError("matching stash was reparsed")

        self.module._load_data = unexpected_load
        self.assertTrue(self.module.init_standard(0, object()))
        self.assertIs(stashed_data, self.module._active_data)
        self.assertFalse(hasattr(sys, self.module.STASH_ATTRIBUTE))

    def test_init_clears_invalid_stash(self) -> None:
        """Initialization deletes an invalid interpreter stash immediately.

        Since: UNRELEASED
        """

        setattr(sys, self.module.STASH_ATTRIBUTE, {"version": -1})
        self.write_data("generation-invalid-stash", [("fresh.example.net", "0", "")])

        self.assertTrue(self.module.init_standard(0, object()))

        self.assertFalse(hasattr(sys, self.module.STASH_ATTRIBUTE))
        self.assertEqual("generation-invalid-stash", self.module._active_data.generation)

    def test_same_dictionary_reload_serves_stash_during_background_load(self) -> None:
        """A changed generation loads behind the immediately restored stashed policy.

        Since: UNRELEASED
        """

        self.write_data("generation-stash-1", [("old.example.net", "0", "")])
        self.initialize()
        stashed_data = self.module._active_data
        self.module.deinit(0)
        self.write_data("generation-stash-2", [("new.example.net", "0", "")])
        self.reexecute_source()
        original_load = self.module._load_data
        started = threading.Event()
        release = threading.Event()

        def slow_load(stop_event: threading.Event | None = None) -> Any:
            started.set()
            release.wait(timeout=2.0)

            return original_load(stop_event)

        self.module._load_data = slow_load
        self.assertTrue(self.module.init_standard(0, object()))
        self.assertTrue(started.wait(timeout=1.0))
        self.assertIs(stashed_data, self.module._active_data)
        release.set()
        self.wait_for_loader()
        self.assertEqual("generation-stash-2", self.module._active_data.generation)

    def test_loader_from_previous_script_execution_cannot_publish(self) -> None:
        """A stale loader token cannot overwrite data from a later script execution.

        Since: UNRELEASED
        """

        self.write_data("generation-token-1", [("old.example.net", "0", "")])
        self.initialize()
        original_load = self.module._load_data
        started = threading.Event()
        release = threading.Event()

        def slow_old_load(stop_event: threading.Event | None = None) -> Any:
            started.set()
            release.wait(timeout=2.0)

            return original_load(stop_event)

        self.module._load_data = slow_old_load
        self.write_data("generation-token-2", [("new.example.net", "0", "")])
        self.assertTrue(started.wait(timeout=1.0))
        stale_thread = self.module._loader_thread
        self.reexecute_source()
        self.assertTrue(self.module.init_standard(0, object()))
        current_data = self.module._active_data
        release.set()
        self.assertIsNotNone(stale_thread)
        stale_thread.join(timeout=2.0)
        self.assertFalse(stale_thread.is_alive())
        self.assertIs(current_data, self.module._active_data)

    def test_compiler_validation_rejects_oversized_manifest(self) -> None:
        """The module refuses data claiming more than two million unique names.

        Since: UNRELEASED
        """

        self.write_data(
            "generation-large",
            [],
            include_list=False,
            domain_count=self.module.MAXIMUM_UNIQUE_NAMES + 1,
        )

        self.assertTrue(self.module.init_standard(0, object()))

        self.assertIsNone(self.module._active_data)
        self.assertTrue(any("domain count is invalid" in message for message in self.logs))

    def test_get_q_ip_reads_mesh_reply_address(self) -> None:
        """Client lookup follows the pfBlockerNG mesh reply-list path.

        Since: UNRELEASED
        """

        qstate = self.query_state("example.test.", self.module.RR_TYPE_A, "198.51.100.9")

        self.assertEqual("198.51.100.9", self.module.get_q_ip(qstate))


if __name__ == "__main__":
    unittest.main()
