"""Tests for the two-router hop-by-hop troubleshooting records and reports."""
import ipaddress
import threading

import pytest

from app import troubleshoot
from app.routing import UnsupportedInput
from app.troubleshoot import RecordNotFound, RecordStore, analyze

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.troubleshoot import store  # noqa: E402

client = TestClient(app)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

# rtr-a steers its default traffic to rtr-b over the 192.0.2.0/24 inter-router
# link (eth1, peer 192.0.2.2); sources in 172.16.0.0/12 take policy table 100
# and leave directly over eth2.  rtr-b uses the same link on eth0 (peer
# 192.0.2.1) and has its own uplink over eth1.
A_RULES = [
    {"priority": 0, "src": "all", "table": "local"},
    {"priority": 100, "src": "172.16.0.0/12", "table": "100"},
    {"priority": 32766, "src": "all", "table": "main"},
]
A_ROUTES = [
    {"dst": "192.0.2.0/24", "dev": "eth1", "table": "main", "scope": "link"},
    {"dst": "default", "gateway": "192.0.2.2", "dev": "eth1", "table": "main"},
    {"dst": "203.0.113.0/24", "type": "blackhole", "table": "main"},
    {"dst": "default", "gateway": "198.51.100.1", "dev": "eth2", "table": "100"},
]

B_RULES = [{"priority": 0, "src": "all", "table": "local"},
           {"priority": 100, "src": "all", "table": "main"}]
B_ROUTES = [
    {"dst": "192.0.2.0/24", "dev": "eth0", "table": "main", "scope": "link"},
    {"dst": "198.51.100.0/24", "gateway": "203.0.113.9", "dev": "eth1",
     "table": "main"},
    {"dst": "default", "gateway": "203.0.113.1", "dev": "eth1", "table": "main"},
]


def make_record(st: RecordStore, a_routes=A_ROUTES, b_routes=B_ROUTES,
                a_rules=A_RULES, b_rules=B_RULES):
    rec = st.create(
        "test site",
        [("rtr-a", "eth1", "192.0.2.2"), ("rtr-b", "eth0", "192.0.2.1")],
        "rtr-a",
    )
    st.put_snapshot(rec.record_id, "rtr-a", a_rules, a_routes)
    st.put_snapshot(rec.record_id, "rtr-b", b_rules, b_routes)
    return rec.record_id


def diagnose(st, record_id, src, dst):
    return analyze(st.capture(record_id), src, dst)


def conclusion_map(report):
    return {
        (seg["source_cidr"], seg["destination_cidr"]): seg["conclusion"]
        for seg in report["segments"]
    }


@pytest.fixture(autouse=True)
def clean_store():
    store.reset()
    yield
    store.reset()


# ---------------------------------------------------------------------------
# record lifecycle
# ---------------------------------------------------------------------------

def test_create_record_lists_entry_and_egresses():
    resp = client.post(
        "/troubleshoot/records",
        json={
            "name": "site-a",
            "entry_device": "rtr-a",
            "devices": [
                {"name": "rtr-a", "egress_dev": "eth1", "egress_gateway": "192.0.2.2"},
                {"name": "rtr-b", "egress_dev": "eth0", "egress_gateway": "192.0.2.1"},
            ],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["version"] == 0
    devices = {d["name"]: d for d in body["devices"]}
    assert devices["rtr-a"]["entry"] is True
    assert devices["rtr-b"]["entry"] is False
    assert devices["rtr-a"]["egress_to_peer"] == {"dev": "eth1", "gateway": "192.0.2.2"}
    assert devices["rtr-a"]["has_snapshot"] is False

    got = client.get(f"/troubleshoot/records/{body['record_id']}")
    assert got.status_code == 200
    assert got.json()["record_id"] == body["record_id"]


@pytest.mark.parametrize(
    "payload, needle, status",
    [
        (
            {"entry_device": "rtr-a", "devices": [
                {"name": "rtr-a", "egress_dev": "eth1", "egress_gateway": None}]},
            "exactly two", 400,
        ),
        (
            {"entry_device": "rtr-a", "devices": [
                {"name": "rtr-a", "egress_dev": "eth1"},
                {"name": "rtr-b", "egress_dev": "eth0"}]},
            "egress_gateway", 422,
        ),
        (
            {"entry_device": "rtr-c", "devices": [
                {"name": "rtr-a", "egress_dev": "eth1", "egress_gateway": None},
                {"name": "rtr-b", "egress_dev": "eth0", "egress_gateway": None}]},
            "entry_device", 400,
        ),
        (
            {"entry_device": "rtr-a", "devices": [
                {"name": "rtr-a", "egress_dev": "eth1", "egress_gateway": None},
                {"name": "rtr-a", "egress_dev": "eth0", "egress_gateway": None}]},
            "duplicate", 400,
        ),
        (
            {"entry_device": "rtr-a", "devices": [
                {"name": "rtr-a", "egress_dev": "eth1", "egress_gateway": "not-an-ip"},
                {"name": "rtr-b", "egress_dev": "eth0", "egress_gateway": None}]},
            "gateway", 400,
        ),
    ],
)
def test_invalid_record_definitions_rejected(payload, needle, status):
    resp = client.post("/troubleshoot/records", json=payload)
    assert resp.status_code == status, resp.text
    assert needle in resp.text


def test_unknown_record_is_404():
    assert client.get("/troubleshoot/records/nope").status_code == 404
    assert (
        client.put(
            "/troubleshoot/records/nope/devices/rtr-a/snapshot",
            json={"rules": [], "routes": []},
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/troubleshoot/records/nope/diagnose",
            params={"source_cidr": "0.0.0.0/0", "destination_cidr": "0.0.0.0/0"},
        ).status_code
        == 404
    )


def test_snapshot_for_unknown_device_is_404():
    resp = client.post(
        "/troubleshoot/records",
        json={"entry_device": "a", "devices": [
            {"name": "a", "egress_dev": "eth0", "egress_gateway": None},
            {"name": "b", "egress_dev": "eth0", "egress_gateway": None}]},
    )
    rid = resp.json()["record_id"]
    bad = client.put(
        f"/troubleshoot/records/{rid}/devices/c/snapshot",
        json={"rules": [], "routes": []},
    )
    assert bad.status_code == 404


def test_snapshot_accepted_bumps_version_and_rejected_leaves_it():
    resp = client.post(
        "/troubleshoot/records",
        json={"entry_device": "a", "devices": [
            {"name": "a", "egress_dev": "eth0", "egress_gateway": "192.0.2.2"},
            {"name": "b", "egress_dev": "eth0", "egress_gateway": "192.0.2.1"}]},
    )
    rid = resp.json()["record_id"]

    ok = client.put(
        f"/troubleshoot/records/{rid}/devices/a/snapshot",
        json={"rules": A_RULES, "routes": A_ROUTES},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["snapshot_version"] == 1
    assert ok.json()["record"]["version"] == 1
    assert {d["name"]: d["has_snapshot"] for d in ok.json()["record"]["devices"]} == {
        "a": True, "b": False,
    }

    bad = client.put(
        f"/troubleshoot/records/{rid}/devices/a/snapshot",
        json={"rules": A_RULES,
              "routes": A_ROUTES + [{"dst": "x", "type": "prohibit", "table": "main"}]},
    )
    assert bad.status_code == 400
    after = client.get(f"/troubleshoot/records/{rid}").json()
    assert after["version"] == 1  # unchanged
    dev_a = {d["name"]: d for d in after["devices"]}["a"]
    assert dev_a["snapshot_version"] == 1
    assert dev_a["has_snapshot"] is True


# ---------------------------------------------------------------------------
# diagnosis: every conclusion
# ---------------------------------------------------------------------------

def test_flow_reaches_peer_and_leaves_the_pair():
    st = RecordStore()
    rid = make_record(st)
    report = diagnose(st, rid, "10.0.0.0/24", "198.51.100.0/24")
    (seg,) = report["segments"]
    assert seg["conclusion"] == "left_devices"
    assert seg["terminal_device"] == "rtr-b"
    acts = [h["action"] for h in seg["hops"]]
    assert acts == ["transit_to_peer", "exit_pair"]
    # rtr-a uses its main table towards the peer; rtr-b its /24 exit on eth1
    assert seg["hops"][0]["basis"]["table"] == "main"
    assert seg["hops"][0]["result"] == {
        "type": "unicast", "dev": "eth1", "gateway": "192.0.2.2"
    }
    assert seg["hops"][1]["result"] == {
        "type": "unicast", "dev": "eth1", "gateway": "203.0.113.9"
    }
    assert report["summary"]["total_pairs"] == str(256 * 256)
    assert report["summary"]["covered_pairs"] == report["summary"]["total_pairs"]


def test_policy_routing_table_on_entry_is_still_followed():
    """Sources in 172.16.0.0/12 take rtr-a's table 100 and leave with no peer hop."""
    st = RecordStore()
    rid = make_record(st)
    report = diagnose(st, rid, "172.16.0.0/12", "198.51.100.0/24")
    (seg,) = report["segments"]
    assert seg["conclusion"] == "left_devices"
    assert [h["device"] for h in seg["hops"]] == ["rtr-a"]
    assert seg["hops"][0]["basis"]["table"] == "100"
    assert seg["hops"][0]["result"] == {
        "type": "unicast", "dev": "eth2", "gateway": "198.51.100.1"
    }


def test_same_egress_dev_with_other_gateway_counts_as_leaving():
    """The configured gateway distinguishes the peer hop from another uplink."""
    st = RecordStore()
    rid = make_record(st)
    st.put_snapshot(
        rid, "rtr-b", B_RULES,
        [{"dst": "192.0.2.0/24", "dev": "eth0", "table": "main"},
         {"dst": "198.51.100.0/24", "gateway": "203.0.113.9", "dev": "eth0",
          "table": "main"}],
    )
    (seg,) = diagnose(st, rid, "10.0.0.0/24", "198.51.100.0/24")["segments"]
    assert [h["action"] for h in seg["hops"]] == ["transit_to_peer", "exit_pair"]
    assert seg["hops"][1]["result"]["gateway"] == "203.0.113.9"


def test_blackhole_on_entry_is_reported_at_that_device():
    st = RecordStore()
    rid = make_record(st)
    report = diagnose(st, rid, "10.0.0.0/24", "203.0.113.0/24")
    seg = report["segments"][0]
    assert seg["conclusion"] == "blackhole"
    assert seg["terminal_device"] == "rtr-a"
    assert seg["hops"][-1]["action"] == "blackhole"
    assert seg["hops"][-1]["basis"]["route_prefix"] == "203.0.113.0/24"


def test_no_route_is_distinguished_from_blackhole():
    b_routes = [{"dst": "192.0.2.0/24", "dev": "eth0", "table": "main"}]
    st = RecordStore()
    rid = make_record(st, b_routes=b_routes)
    report = diagnose(st, rid, "10.0.0.0/24", "198.51.100.254/32")
    seg = report["segments"][0]
    assert seg["conclusion"] == "no_route"
    assert seg["terminal_device"] == "rtr-b"
    assert seg["hops"][-1]["action"] == "no_route"
    # the 198.51.100.0/24 route was removed from rtr-b, so b has no route
    assert seg["hops"][-1]["basis"]["route_type"] == "no_route"


def test_loop_when_both_routers_point_back_at_each_other():
    # Both devices send everything for 198.51.100.0/24 to each other, so the
    # packet bounces between them until the hop limit would expire.
    a_routes = [
        {"dst": "192.0.2.0/24", "dev": "eth1", "table": "main"},
        {"dst": "198.51.100.0/24", "gateway": "192.0.2.2", "dev": "eth1",
         "table": "main"},
    ]
    b_routes = [
        {"dst": "192.0.2.0/24", "dev": "eth0", "table": "main"},
        {"dst": "198.51.100.0/24", "gateway": "192.0.2.1", "dev": "eth0",
         "table": "main"},
    ]
    st = RecordStore()
    rid = make_record(st, a_routes=a_routes, b_routes=b_routes)
    report = diagnose(st, rid, "10.0.0.0/24", "198.51.100.0/24")
    seg = report["segments"][0]
    assert seg["conclusion"] == "loop"
    assert [h["device"] for h in seg["hops"]] == ["rtr-a", "rtr-b"]
    assert seg["terminal_device"] == "rtr-a"


def test_pending_snapshot_only_when_traffic_reaches_that_device():
    st = RecordStore()
    rec = st.create(
        "pending",
        [("rtr-a", "eth1", "192.0.2.2"), ("rtr-b", "eth0", "192.0.2.1")],
        "rtr-a",
    )
    # Only rtr-a has a snapshot; rtr-b does not.
    st.put_snapshot(rec.record_id, "rtr-a", A_RULES, A_ROUTES)
    report = diagnose(st, rec.record_id, "10.0.0.0/24", "203.0.113.0/24")
    seg = report["segments"][0]
    # 203.0.113.0/24 is blackholed on rtr-a: never reaches rtr-b, so not pending.
    assert seg["conclusion"] == "blackhole"

    report = diagnose(st, rec.record_id, "10.0.0.0/24", "198.51.100.0/24")
    seg = report["segments"][0]
    assert seg["conclusion"] == "pending_snapshot"
    assert seg["terminal_device"] == "rtr-b"
    assert seg["hops"][-1]["action"] == "pending_snapshot"
    assert seg["hops"][-1]["snapshot_version"] is None


def test_pending_entry_device_never_marks_unreached_peer():
    st = RecordStore()
    rec = st.create(
        "entry pending",
        [("rtr-a", "eth1", "192.0.2.2"), ("rtr-b", "eth0", "192.0.2.1")],
        "rtr-a",
    )
    st.put_snapshot(rec.record_id, "rtr-b", B_RULES, B_ROUTES)
    report = diagnose(st, rec.record_id, "10.0.0.0/24", "198.51.100.0/24")
    seg = report["segments"][0]
    assert seg["conclusion"] == "pending_snapshot"
    assert seg["terminal_device"] == "rtr-a"
    assert [h["device"] for h in seg["hops"]] == ["rtr-a"]


def test_no_snapshots_at_all_still_reports_pending_for_the_entry():
    st = RecordStore()
    rec = st.create(
        "empty",
        [("rtr-a", "eth1", None), ("rtr-b", "eth0", None)],
        "rtr-a",
    )
    report = diagnose(st, rec.record_id, "all", "default")
    (seg,) = report["segments"]
    assert seg["conclusion"] == "pending_snapshot"
    assert seg["terminal_device"] == "rtr-a"
    assert seg["source_cidr"] == "0.0.0.0/0"
    assert seg["destination_cidr"] == "0.0.0.0/0"
    assert seg["address_pairs"] == report["summary"]["total_pairs"] == str(2**64)
    assert report["version"] == 0
    assert all(not d["has_snapshot"] for d in report["devices"])


def test_report_version_is_captured_generation_and_devices_carry_versions():
    st = RecordStore()
    rid = make_record(st)
    report = diagnose(st, rid, "10.0.0.0/24", "198.51.100.0/24")
    assert report["version"] == 2
    versions = {d["name"]: d["snapshot_version"] for d in report["devices"]}
    assert versions == {"rtr-a": 1, "rtr-b": 2}
    for hop in report["segments"][0]["hops"]:
        assert hop["snapshot_version"] in (1, 2)


# ---------------------------------------------------------------------------
# symbolic coverage
# ---------------------------------------------------------------------------

def test_slash_zero_query_is_cheap_and_fully_covered():
    st = RecordStore()
    rid = make_record(st)
    report = diagnose(st, rid, "0.0.0.0/0", "0.0.0.0/0")
    assert report["summary"]["total_pairs"] == str(2**64)
    assert report["summary"]["covered_pairs"] == str(2**64)
    # symbolic, not per-address: a handful of prefixes yields a bounded report
    assert 0 < report["summary"]["segment_count"] < 2000
    # every pair of CIDR segments must be disjoint
    seen = set()
    for seg in report["segments"]:
        s = ipaddress.IPv4Network(seg["source_cidr"])
        d = ipaddress.IPv4Network(seg["destination_cidr"])
        for other_s, other_d in seen:
            assert not (s.overlaps(other_s) and d.overlaps(other_d))
        seen.add((s, d))
    total = sum(int(seg["address_pairs"]) for seg in report["segments"])
    assert total == 2**64


def test_segments_partition_matches_bruteforce_on_small_space():
    """Compare the symbolic segments with a per-address tracer on a /26 x /25."""
    st = RecordStore()
    rid = make_record(
        st,
        a_routes=[
            {"dst": "192.0.2.0/24", "dev": "eth1", "table": "main"},
            {"dst": "default", "gateway": "192.0.2.2", "dev": "eth1",
             "table": "main"},
            {"dst": "203.0.113.0/25", "type": "blackhole", "table": "main"},
        ],
        b_routes=[
            {"dst": "192.0.2.0/24", "dev": "eth0", "table": "main"},
            # half of the queried destination space bounces back to rtr-a
            {"dst": "198.51.100.0/26", "gateway": "192.0.2.1", "dev": "eth0",
             "table": "main"},
            {"dst": "198.51.100.64/26", "type": "blackhole", "table": "main"},
            {"dst": "198.51.100.128/25", "gateway": "203.0.113.9", "dev": "eth1",
             "table": "main"},
        ],
        a_rules=[{"priority": 0, "src": "all", "table": "local"},
                 {"priority": 100, "src": "all", "table": "main"}],
        b_rules=[{"priority": 0, "src": "all", "table": "local"},
                 {"priority": 100, "src": "all", "table": "main"}],
    )
    src_net = ipaddress.IPv4Network("10.0.0.0/26")
    dst_net = ipaddress.IPv4Network("198.51.100.0/25")
    report = diagnose(st, rid, str(src_net), str(dst_net))
    assert report["summary"]["covered_pairs"] == str(64 * 128)
    conclusions = {seg["conclusion"] for seg in report["segments"]}
    assert conclusions == {"loop", "blackhole"}
    assert report["summary"]["segment_count"] >= 2

    by_addr: dict[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address], str] = {}
    for seg in report["segments"]:
        s_net = ipaddress.IPv4Network(seg["source_cidr"])
        d_net = ipaddress.IPv4Network(seg["destination_cidr"])
        for s in s_net:
            for d in d_net:
                key = (s, d)
                assert key not in by_addr  # disjoint, non-overlapping segments
                by_addr[key] = seg["conclusion"]
    assert len(by_addr) == 64 * 128

    # Cross-check every pair against a direct two-hop simulation.
    captured = st.capture(rid)
    devices = {d.config.name: d for d in captured.devices}
    policies = {n: d.policy for n, d in devices.items()}
    for (s, d), conclusion in by_addr.items():
        expected = _brute_conclusion(s, d, devices, policies)
        assert conclusion == expected, (s, d, conclusion, expected)


def test_random_topologies_match_bruteforce():
    """Random dual-router policies must agree with a per-address tracer.

    Covers rule src/dst selectors, throw, blackhole, loops, both directions of
    the inter-router link and devices with a still-pending snapshot.
    """
    rng = __import__("random").Random(20261122)
    prefixes = ["0.0.0.0/0", "192.0.2.0/24", "192.0.2.0/25", "192.0.2.128/25"]
    src_net = ipaddress.IPv4Network("10.0.0.0/26")
    dst_net = ipaddress.IPv4Network("192.0.2.0/26")

    def random_snapshot():
        rules = [{"priority": 100, "src": "all", "table": "main"}]
        if rng.random() < 0.5:
            rules = [{"priority": 100, "src": rng.choice(
                ["10.0.0.0/27", "10.0.0.32/27", "10.0.0.0/26"]), "table": "main"}]
        if rng.random() < 0.3:
            rules.append({"priority": 200, "src": "all", "table": "200"})
        routes = []
        used = set()
        for _ in range(rng.randint(1, 4)):
            prefix = rng.choice(prefixes)
            if prefix in used:
                continue
            used.add(prefix)
            kind = rng.random()
            if kind < 0.6:
                route = {"dst": prefix, "dev": rng.choice(["eth1", "eth2"]),
                         "table": "main"}
                gw = rng.choice([None, "192.0.2.1", "192.0.2.2", "203.0.113.1"])
                if gw is not None:
                    route["gateway"] = gw
                routes.append(route)
            elif kind < 0.85:
                routes.append({"dst": prefix, "type": "blackhole", "table": "main"})
            else:
                routes.append({"dst": prefix, "type": "throw", "table": "main"})
        return rules, routes

    for _ in range(30):
        st = RecordStore()
        rec = st.create(
            "random",
            [("rtr-a", "eth1", rng.choice([None, "192.0.2.2"])),
             ("rtr-b", "eth2", rng.choice([None, "192.0.2.1"]))],
            "rtr-a",
        )
        rules_a, routes_a = random_snapshot()
        rules_b, routes_b = random_snapshot()
        st.put_snapshot(rec.record_id, "rtr-a", rules_a, routes_a)
        if rng.random() < 0.8:  # sometimes leave rtr-b pending
            st.put_snapshot(rec.record_id, "rtr-b", rules_b, routes_b)

        report = diagnose(st, rec.record_id, str(src_net), str(dst_net))
        captured = st.capture(rec.record_id)
        devices = {d.config.name: d for d in captured.devices}
        policies = {n: d.policy for n, d in devices.items()}

        by_addr = {}
        for seg in report["segments"]:
            s_net = ipaddress.IPv4Network(seg["source_cidr"])
            d_net = ipaddress.IPv4Network(seg["destination_cidr"])
            for s in s_net:
                for d in d_net:
                    assert (s, d) not in by_addr  # disjoint CIDR pairs
                    by_addr[(s, d)] = seg["conclusion"]
        assert len(by_addr) == 64 * 64
        for (s, d), conclusion in by_addr.items():
            expected = _brute_conclusion(s, d, devices, policies)
            assert conclusion == expected, (s, d, conclusion, expected)


def _brute_conclusion(s, d, devices, policies):
    def decide(policy, src, dst):
        for rule in policy.rules:
            if src in rule.src and dst in rule.dst:
                best = None
                for route in policy.tables.get(rule.table, ()):
                    if dst in route.prefix and (
                        best is None or route.prefix.prefixlen > best.prefix.prefixlen
                    ):
                        best = route
                if best is None or best.rtype == "throw":
                    continue
                return (best.rtype, best.dev, best.gateway)
        return ("no_route", None, None)

    current = "rtr-a"
    seen = []
    while True:
        device = devices[current]
        if device.policy is None:
            return "pending_snapshot"
        if current in seen:
            return "loop"
        seen.append(current)
        kind, dev, gw = decide(policies[current], s, d)
        if kind == "blackhole":
            return "blackhole"
        if kind == "no_route":
            return "no_route"
        cfg = device.config
        if dev == cfg.egress_dev and (
            cfg.egress_gateway is None or gw == cfg.egress_gateway
        ):
            current = "rtr-b" if current == "rtr-a" else "rtr-a"
            continue
        return "left_devices"


# ---------------------------------------------------------------------------
# concurrency: corrections during a diagnosis
# ---------------------------------------------------------------------------

def test_diagnosis_uses_one_version_while_corrections_arrive(monkeypatch):
    """A report must reflect exactly one captured generation.

    The symbolic partition is paused mid-flight while a correction is
    submitted, then resumed: the in-flight report must still describe the
    captured version, while a new query uses the corrected one.
    """
    st = RecordStore()
    rid = make_record(st)
    assert st.get(rid).generation == 2

    reached = threading.Event()
    resume = threading.Event()
    original = troubleshoot.routing.partition_rectangles
    calls = {"n": 0}

    def slow_partition(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            reached.set()
            assert resume.wait(timeout=30), "correction thread did not resume us"
        return original(*args, **kwargs)

    monkeypatch.setattr(troubleshoot.routing, "partition_rectangles", slow_partition)

    holder = {}

    def run_diagnosis():
        captured = st.capture(rid)
        holder["version"] = captured.version
        holder["report"] = analyze(captured, "10.0.0.0/24", "198.51.100.0/24")

    worker = threading.Thread(target=run_diagnosis)
    worker.start()
    assert reached.wait(timeout=30), "diagnosis never reached the partition step"

    # The correction is accepted while the first diagnosis is blocked.  It
    # replaces (not adds to) rtr-b's routes, so no duplicate prefix.
    corrected_b = [
        {"dst": "192.0.2.0/24", "dev": "eth0", "table": "main"},
        {"dst": "198.51.100.0/24", "type": "blackhole", "table": "main"},
    ]
    accepted = st.put_snapshot(rid, "rtr-b", B_RULES, corrected_b)
    assert accepted[1].version == 3
    resume.set()
    worker.join(timeout=30)
    assert not worker.is_alive()

    assert holder["version"] == 2
    report = holder["report"]
    assert report["version"] == 2  # in-flight report is from the old generation
    assert report["segments"][0]["conclusion"] == "left_devices"
    assert st.get(rid).generation == 3

    # A new query uses the new version and sees the correction.
    newer = diagnose(st, rid, "10.0.0.0/24", "198.51.100.0/24")
    assert newer["version"] == 3
    assert newer["segments"][0]["conclusion"] == "blackhole"
    assert newer["segments"][0]["terminal_device"] == "rtr-b"


def test_invalid_correction_keeps_old_version_for_later_queries():
    st = RecordStore()
    rid = make_record(st)
    with pytest.raises(UnsupportedInput):
        st.put_snapshot(
            rid, "rtr-b", B_RULES,
            [{"dst": "default", "type": "prohibit", "table": "main"}],
        )
    assert st.get(rid).generation == 2
    report = diagnose(st, rid, "10.0.0.0/24", "198.51.100.0/24")
    assert report["version"] == 2
    assert report["segments"][0]["conclusion"] == "left_devices"


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

def test_http_diagnose_end_to_end_and_bad_cidr():
    created = client.post(
        "/troubleshoot/records",
        json={"entry_device": "rtr-a", "devices": [
            {"name": "rtr-a", "egress_dev": "eth1", "egress_gateway": "192.0.2.2"},
            {"name": "rtr-b", "egress_dev": "eth0", "egress_gateway": "192.0.2.1"}]},
    ).json()
    rid = created["record_id"]
    for name, rules, routes in (
        ("rtr-a", A_RULES, A_ROUTES), ("rtr-b", B_RULES, B_ROUTES)
    ):
        assert client.put(
            f"/troubleshoot/records/{rid}/devices/{name}/snapshot",
            json={"rules": rules, "routes": routes},
        ).status_code == 200

    report = client.post(
        f"/troubleshoot/records/{rid}/diagnose",
        params={"source_cidr": "10.0.0.0/24", "destination_cidr": "198.51.100.0/24"},
    )
    assert report.status_code == 200, report.text
    body = report.json()
    assert body["version"] == 2
    assert body["segments"][0]["conclusion"] == "left_devices"
    assert body["query"] == {
        "source_cidr": "10.0.0.0/24", "destination_cidr": "198.51.100.0/24"
    }

    bad = client.post(
        f"/troubleshoot/records/{rid}/diagnose",
        params={"source_cidr": "10.0.0.0/33", "destination_cidr": "0.0.0.0/0"},
    )
    assert bad.status_code == 400
    assert "source_cidr" in bad.json()["detail"]


def test_diagnose_requires_query_parameters():
    st = RecordStore()
    rid = make_record(st)
    resp = client.post(f"/troubleshoot/records/{rid}/diagnose")
    assert resp.status_code == 422


def test_invalid_snapshot_returns_400_from_engine():
    st = RecordStore()
    rid = make_record(st)
    with pytest.raises(UnsupportedInput):
        st.put_snapshot(rid, "rtr-a", A_RULES, [{"dst": "default", "nexthops": []}])
    with pytest.raises(RecordNotFound):
        st.capture("missing")


# ---------------------------------------------------------------------------
# merge helper (coverage must not depend on it)
# ---------------------------------------------------------------------------

def test_merge_combines_sibling_cidrs_of_equal_value():
    rects = {}
    for chunk in ("10.0.0.0/25", "10.0.0.128/25"):
        rects[(ipaddress.IPv4Network(chunk), ipaddress.IPv4Network("192.0.2.0/24"))] = (
            "sig", "left_devices", [], "rtr-b", "detail",
        )
    merged = troubleshoot._merge_rectangles(rects)
    assert list(merged) == [
        (ipaddress.IPv4Network("10.0.0.0/24"), ipaddress.IPv4Network("192.0.2.0/24"))
    ]
