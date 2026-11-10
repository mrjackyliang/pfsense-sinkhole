"""Cross-language Sinkhole compiler and Unbound module test.

Since: UNRELEASED
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import types
from pathlib import Path
from typing import Any


LIST_IDENTIFIER = "77777777777777777777777777777777"
NETWORK_LIST_IDENTIFIER = "88888888888888888888888888888888"
DEVICE_LIST_IDENTIFIER = "99999999999999999999999999999999"
NETWORK_A_IDENTIFIER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
NETWORK_B_IDENTIFIER = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
DEVICE_IDENTIFIER = "dddddddddddddddddddddddddddddddd"
ALERT_RULE_IDENTIFIER = "44444444444444444444444444444444"
MODULE_RELATIVE_PATH = Path(
    "port/files/usr/local/pkg/sinkhole/sinkhole_unbound.py"
)


class FakeDnsMessage:
    """Capture a response built by the Unbound module.

    Since: UNRELEASED
    """

    def __init__(self, name: str, query_type: int, query_class: int, flags: int) -> None:
        """Initialize one fake DNS message.

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

    def set_return_msg(self, qstate: Any) -> bool:
        """Attach the fake response.

        Args:
            qstate: Query state.

        Returns:
            Always ``True``.

        Since: UNRELEASED
        """

        qstate.return_msg = self

        return True


class ModuleNamespace:
    """Attribute access for a directly executed namespace dictionary.

    Since: UNRELEASED
    """

    def __init__(self, source_path: Path) -> None:
        """Execute the module without importlib or sys.modules registration.

        Args:
            source_path: Installed module source.

        Since: UNRELEASED
        """

        namespace: dict[str, Any] = {}
        source = source_path.read_text(encoding="utf-8")
        exec(compile(source, str(source_path), "exec"), namespace)
        object.__setattr__(self, "_namespace", namespace)

    def __getattr__(self, name: str) -> Any:
        """Read an executed global.

        Args:
            name: Global name.

        Returns:
            Global value.

        Since: UNRELEASED
        """

        try:
            return self._namespace[name]
        except KeyError as exception:
            raise AttributeError(name) from exception

    def __setattr__(self, name: str, value: Any) -> None:
        """Replace an executed global.

        Args:
            name: Global name.
            value: Replacement value.

        Since: UNRELEASED
        """

        self._namespace[name] = value


def write_python_generation(root: Path, scenario: str) -> None:
    """Write compiler-format data when PHP tests are explicitly skipped.

    Args:
        root: Scenario root.
        scenario: Initial, reload, or zero scenario.

    Since: UNRELEASED
    """

    runtime_root = root / "runtime"
    storage = runtime_root / "sinkhole.d"
    storage.mkdir(parents=True, exist_ok=True)
    suffixes = {
        "initial": "1111111111111111",
        "reload": "2222222222222222",
        "zero": "3333333333333333",
    }
    generation_directory = storage / f".sinkhole-generation-{suffixes[scenario]}"
    generation_directory.mkdir()

    if scenario == "initial":
        domains = [
            ("_service.example.com", "0", ""),
            ("adblock.example.net", "", "0"),
            ("ads.example.com", "0", ""),
            ("hosts.example.com", "0", ""),
            ("plain.example.org", "0", ""),
            ("second.example.net", "0", ""),
            ("tree.example.net", "", "0"),
            ("network-a.example.test", "1", ""),
            ("device-a.example.test", "2", ""),
        ]
        allowed = ["allowed.tree.example.net"]
        lists = {
            LIST_IDENTIFIER: {"name": "End-to-End Example", "bit": 0},
            NETWORK_LIST_IDENTIFIER: {"name": "Network Example", "bit": 1},
            DEVICE_LIST_IDENTIFIER: {"name": "Device Example", "bit": 2},
        }
        global_lists = [LIST_IDENTIFIER]
        network_scopes = {
            NETWORK_A_IDENTIFIER: {
                "interface": "lan",
                "lists": [NETWORK_LIST_IDENTIFIER],
                "allow": f"allow-network-{NETWORK_A_IDENTIFIER}.txt",
            },
            NETWORK_B_IDENTIFIER: {
                "interface": "opt1",
                "lists": [],
                "allow": f"allow-network-{NETWORK_B_IDENTIFIER}.txt",
            },
        }
        device_scopes = {
            DEVICE_IDENTIFIER: {
                "lists": [DEVICE_LIST_IDENTIFIER],
                "allow": f"allow-device-{DEVICE_IDENTIFIER}.txt",
            }
        }
        alerts = {
            ALERT_RULE_IDENTIFIER: {
                "id": ALERT_RULE_IDENTIFIER,
                "lists": [2],
                "networks": [],
                "devices": [DEVICE_IDENTIFIER],
            }
        }
    elif scenario == "reload":
        domains = [("reloaded.example.org", "0", "")]
        allowed = []
        lists = {LIST_IDENTIFIER: {"name": "End-to-End Example", "bit": 0}}
        global_lists = [LIST_IDENTIFIER]
        network_scopes = {}
        device_scopes = {}
        alerts = {}
    else:
        domains = []
        allowed = []
        lists = {}
        global_lists = []
        network_scopes = {}
        device_scopes = {}
        alerts = {}

    generation = f"python-{scenario}"
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
        "lists": lists,
        "scopes": {
            "global": {
                "lists": global_lists,
                "allow": "allow.txt",
            },
            "networks": network_scopes,
            "devices": device_scopes,
        },
        "alerts": alerts,
    }
    (generation_directory / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    (generation_directory / "domains.tsv").write_text(
        "".join(f"{domain}\t{exact}\t{subtree}\n" for domain, exact, subtree in domains),
        encoding="ascii",
    )
    (generation_directory / "bypass.tsv").write_text("", encoding="ascii")
    (generation_directory / "allow.txt").write_text(
        "".join(f"{domain}\n" for domain in allowed),
        encoding="ascii",
    )

    if scenario == "initial":
        (generation_directory / f"allow-network-{NETWORK_A_IDENTIFIER}.txt").write_text(
            "",
            encoding="ascii",
        )
        (generation_directory / f"allow-network-{NETWORK_B_IDENTIFIER}.txt").write_text(
            "",
            encoding="ascii",
        )
        (generation_directory / f"allow-device-{DEVICE_IDENTIFIER}.txt").write_text(
            "",
            encoding="ascii",
        )
    (generation_directory / "generation").write_text(
        f"{generation}\n",
        encoding="ascii",
    )
    temporary_link = runtime_root / ".sinkhole-e2e-link"

    if temporary_link.is_symlink():
        temporary_link.unlink()

    temporary_link.symlink_to(f"sinkhole.d/{generation_directory.name}")
    os.replace(temporary_link, runtime_root / "sinkhole")

    for candidate in storage.glob(".sinkhole-generation-*"):
        if candidate != generation_directory:
            shutil.rmtree(candidate)

    client_directory = runtime_root / "sinkhole-clients"
    client_directory.mkdir(mode=0o755, exist_ok=True)
    client_semantic = {
        "networks": (
            [
                {"id": NETWORK_A_IDENTIFIER, "cidrs": ["192.0.2.0/24"]},
                {"id": NETWORK_B_IDENTIFIER, "cidrs": ["198.51.100.0/24"]},
            ]
            if scenario == "initial"
            else []
        ),
        "interfaces": [],
        "devices": (
            {"192.0.2.10": DEVICE_IDENTIFIER}
            if scenario == "initial"
            else {}
        ),
        "conflicts": [],
    }
    client_digest = hashlib.sha256(
        json.dumps(
            client_semantic,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    (client_directory / "clients.json").write_text(
        json.dumps({
            "schema_version": 2,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "content_digest": client_digest,
            **client_semantic,
        }),
        encoding="utf-8",
    )


def execute_module(source_path: Path, scenario_root: Path) -> ModuleNamespace:
    """Configure one fresh embedded-style module namespace.

    Args:
        source_path: Real Unbound module source.
        scenario_root: Compiler scenario root.

    Returns:
        Configured namespace wrapper.

    Since: UNRELEASED
    """

    module = ModuleNamespace(source_path)
    data_directory = scenario_root / "runtime" / "sinkhole"
    state_directory = scenario_root / "runtime" / "sinkhole-state"
    state_directory.mkdir(mode=0o755, exist_ok=True)
    module.DATA_DIRECTORY = str(data_directory)
    module.MANIFEST_PATH = str(data_directory / "manifest.json")
    module.DOMAINS_PATH = str(data_directory / "domains.tsv")
    module.BYPASS_PATH = str(data_directory / "bypass.tsv")
    module.ALLOW_PATH = str(data_directory / "allow.txt")
    module.GENERATION_PATH = str(data_directory / "generation")
    module.LOADED_GENERATION_PATH = str(state_directory / "loaded")
    module.EVENTS_PATH = str(state_directory / "events")
    module.EVENTS_DROPPED_PATH = str(state_directory / "events-dropped")
    module.CLIENT_MAP_PATH = str(
        scenario_root / "runtime" / "sinkhole-clients" / "clients.json"
    )
    module.WATCH_INTERVAL_SECONDS = 0.01
    module.DNSMessage = FakeDnsMessage
    module.RR_TYPE_A = 1
    module.RR_TYPE_AAAA = 28
    module.RR_TYPE_CNAME = 5
    module.RR_CLASS_IN = 1
    module.PKT_QR = 1
    module.PKT_RA = 2
    module.PKT_AA = 4
    module.RCODE_NOERROR = 0
    module.RCODE_NXDOMAIN = 3
    module.MODULE_EVENT_NEW = 10
    module.MODULE_EVENT_PASS = 11
    module.MODULE_EVENT_MODDONE = 12
    module.MODULE_FINISHED = 20
    module.MODULE_WAIT_MODULE = 21
    module.MODULE_ERROR = 22
    module.ntohs = lambda value: value
    module.invalidateQueryInCache = lambda _qstate, _qinfo: None
    module.register_inplace_cb_query_response = (
        lambda _callback, _environment, _module_id: 1
    )
    module.log_info = lambda _message: None

    if not module.init_standard(0, object()):
        raise AssertionError("The Unbound module did not initialize.")

    return module


def query_state(
    name: str,
    query_type: int,
    client: bool | str = True,
) -> Any:
    """Build one fake query.

    Args:
        name: Query name.
        query_type: Query type.
        client: Whether the query has a default client, or its address.

    Returns:
        Mutable query state.

    Since: UNRELEASED
    """

    reply = None

    if client:
        address = "192.0.2.44" if client is True else client
        reply = types.SimpleNamespace(
            query_reply=types.SimpleNamespace(addr=address),
            next=None,
        )

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


def operate(
    module: ModuleNamespace,
    name: str,
    query_type: int,
    client: bool | str = True,
) -> Any:
    """Run one query through the real module.

    Args:
        module: Executed module.
        name: Query name.
        query_type: Query type.
        client: Whether the query has a default client, or its address.

    Returns:
        Resulting query state.

    Since: UNRELEASED
    """

    state = query_state(name, query_type, client)
    module.operate(0, module.MODULE_EVENT_NEW, state, None)

    return state


def assert_blocked(
    module: ModuleNamespace,
    name: str,
    query_type: int = 1,
    client: bool | str = True,
) -> Any:
    """Assert that a client query is blocked.

    Args:
        module: Executed module.
        name: Query name.
        query_type: Query type.
        client: Whether the query has a default client, or its address.

    Returns:
        Blocked query state.

    Since: UNRELEASED
    """

    state = operate(module, name, query_type, client)
    assert state.ext_state[0] == module.MODULE_FINISHED, name
    assert state.no_cache_store == 1, name

    return state


def recompile_with_php(workspace: Path, temporary_root: Path) -> None:
    """Run the real PHP parser, store, and compiler for the reload scenario.

    Args:
        workspace: Package workspace.
        temporary_root: Host temporary root.

    Since: UNRELEASED
    """

    mode = os.environ["SINKHOLE_E2E_PHP_MODE"]

    if mode == "local":
        command = [
            "php",
            str(workspace / "tests/e2e-compile.php"),
            str(temporary_root / "active"),
            "reload",
        ]
    elif mode == "docker":
        image = os.environ.get("PHP_TEST_IMAGE", "php:8.3-cli-alpine")
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            f"{workspace}:/workspace:ro",
            "--volume",
            f"{temporary_root}:/e2e",
            image,
            "php",
            "/workspace/tests/e2e-compile.php",
            "/e2e/active",
            "reload",
        ]
    else:
        raise AssertionError(f"Unknown PHP mode: {mode}")

    subprocess.run(command, check=True)


def run_alert_job_with_php(workspace: Path, temporary_root: Path) -> dict[str, Any]:
    """Run the real PHP alert reader against the module-written event file.

    Args:
        workspace: Package workspace.
        temporary_root: Host temporary root.

    Returns:
        Decoded alert-job result and channel calls.

    Since: UNRELEASED
    """

    mode = os.environ["SINKHOLE_E2E_PHP_MODE"]

    if mode == "local":
        command = [
            "php",
            str(workspace / "tests/e2e-alert.php"),
            str(temporary_root / "active"),
        ]
    elif mode == "docker":
        image = os.environ.get("PHP_TEST_IMAGE", "php:8.3-cli-alpine")
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            f"{workspace}:/workspace:ro",
            "--volume",
            f"{temporary_root}:/e2e",
            image,
            "php",
            "/workspace/tests/e2e-alert.php",
            "/e2e/active",
        ]
    else:
        raise AssertionError(f"Unknown PHP mode: {mode}")

    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )

    return json.loads(completed.stdout)


def run(python_only: bool) -> None:
    """Exercise required answers, zero lists, and a live reload.

    Args:
        python_only: Generate equivalent fixture data without PHP.

    Since: UNRELEASED
    """

    workspace = Path(__file__).resolve().parents[1]
    owned_temporary: tempfile.TemporaryDirectory[str] | None = None

    if python_only:
        owned_temporary = tempfile.TemporaryDirectory(prefix="sinkhole-e2e-python-")
        temporary_root = Path(owned_temporary.name)
        write_python_generation(temporary_root / "active", "initial")
        write_python_generation(temporary_root / "zero", "zero")
    else:
        temporary_root = Path(os.environ["SINKHOLE_E2E_TEMP"])

    module: ModuleNamespace | None = None
    zero_module: ModuleNamespace | None = None

    try:
        source_path = workspace / MODULE_RELATIVE_PATH
        module = execute_module(source_path, temporary_root / "active")
        assert_blocked(module, "hosts.example.com.")
        assert_blocked(module, "second.example.net.")
        assert_blocked(module, "_service.example.com.")
        assert_blocked(module, "plain.example.org.")
        assert_blocked(module, "adblock.example.net.")
        assert_blocked(module, "ads.example.com.")
        assert_blocked(module, "child.tree.example.net.")
        assert_blocked(module, "_x.tree.example.net.")
        assert_blocked(module, "network-a.example.test.", client="192.0.2.44")
        network_b_state = operate(
            module,
            "network-a.example.test.",
            1,
            "198.51.100.44",
        )
        assert network_b_state.ext_state[0] == module.MODULE_WAIT_MODULE
        assert network_b_state.no_cache_store == 1
        assert_blocked(module, "device-a.example.test.", client="192.0.2.10")
        module._flush_events()
        event_path = temporary_root / "active" / "runtime" / "sinkhole-state" / "events"
        events = [
            json.loads(line)
            for line in event_path.read_text(encoding="utf-8").splitlines()
        ]
        assert len(events) == 1
        assert events[0]["client"] == "192.0.2.10"
        assert events[0]["device"] == DEVICE_IDENTIFIER
        assert events[0]["network"] == NETWORK_A_IDENTIFIER
        assert events[0]["name"] == "device-a.example.test"
        assert events[0]["count"] == 1
        assert events[0]["rules"] == [ALERT_RULE_IDENTIFIER]
        assert events[0]["lists"] == [DEVICE_LIST_IDENTIFIER]
        expected_notification = (
            "Sinkhole blocked device-a.example.test for Lab Phone on LAN "
            "(list Device Example, rule Device alert)."
        )

        if python_only:
            event_path.unlink()
        else:
            alert_output = run_alert_job_with_php(workspace, temporary_root)
            assert alert_output["result"]["notifications_sent"] == 1
            assert alert_output["remote"] == [expected_notification]
            assert alert_output["notices"] == [[
                "sinkhole-e2e-notice",
                expected_notification,
                "Sinkhole",
                "/sinkhole-alerts.php",
                1,
                True,
            ]]
        network_device_name = operate(
            module,
            "device-a.example.test.",
            1,
            "192.0.2.44",
        )
        assert network_device_name.ext_state[0] == module.MODULE_WAIT_MODULE
        assert network_device_name.no_cache_store == 1
        network_b_device_name = operate(
            module,
            "device-a.example.test.",
            1,
            "198.51.100.44",
        )
        assert network_b_device_name.ext_state[0] == module.MODULE_WAIT_MODULE
        assert network_b_device_name.no_cache_store == 1
        allowed_state = operate(module, "child.allowed.tree.example.net.", 1)
        assert allowed_state.ext_state[0] == module.MODULE_WAIT_MODULE
        assert allowed_state.no_cache_store == 1
        mx_state = assert_blocked(module, "hosts.example.com.", 15)
        assert mx_state.return_msg.answer == []
        internal_state = operate(module, "hosts.example.com.", 1, client=False)
        assert internal_state.ext_state[0] == module.MODULE_WAIT_MODULE
        assert internal_state.no_cache_store == 1

        for cosmetic_name in (
            "example.com.",
            "example.org.",
            "cosmetic.example.com.",
            "cosmetic.example.org.",
            "cosmetic.example.net.",
            "style.example.com.",
        ):
            cosmetic_state = operate(module, cosmetic_name, 1)
            assert cosmetic_state.ext_state[0] == module.MODULE_WAIT_MODULE
            assert cosmetic_state.no_cache_store == 0

        zero_module = execute_module(source_path, temporary_root / "zero")
        zero_state = operate(zero_module, "hosts.example.com.", 1)
        assert zero_state.ext_state[0] == zero_module.MODULE_WAIT_MODULE
        assert zero_state.no_cache_store == 0

        if python_only:
            write_python_generation(temporary_root / "active", "reload")
        else:
            recompile_with_php(workspace, temporary_root)

        expected_generation = (
            temporary_root / "active" / "runtime" / "sinkhole" / "generation"
        ).read_text(encoding="ascii").strip()
        deadline = time.monotonic() + 5.0

        while time.monotonic() < deadline:
            active_data = module._active_data

            if active_data is not None and active_data.generation == expected_generation:
                break

            time.sleep(0.01)
        else:
            raise AssertionError("The watcher did not load the recompiled generation.")

        assert_blocked(module, "reloaded.example.org.")
        old_state = operate(module, "hosts.example.com.", 1)
        assert old_state.ext_state[0] == module.MODULE_WAIT_MODULE
        assert old_state.no_cache_store == 0
    finally:
        if module is not None:
            module.deinit(0)

        if zero_module is not None:
            zero_module.deinit(0)

        if owned_temporary is not None:
            owned_temporary.cleanup()

    if python_only:
        print("PASS embedded Unbound module end-to-end scenarios")
    else:
        print("PASS PHP compiler to embedded Unbound module end to end")


def main() -> None:
    """Parse runner mode and execute the end-to-end assertions.

    Since: UNRELEASED
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("--python-only", action="store_true")
    arguments = parser.parse_args()
    run(arguments.python_only)


if __name__ == "__main__":
    main()
