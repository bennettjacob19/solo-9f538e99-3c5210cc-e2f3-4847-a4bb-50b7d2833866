"""Two-router hop-by-hop troubleshooting on top of the routing engine.

The precheck API answers "what changes between two snapshots".  This module
answers the on-call question instead: "for traffic entering one of two Linux
routers, at which hop does it stop, and why?"

Model
-----
* A *record* names exactly two routers, one of them the entry, and for each
  router the egress interface + next-hop gateway that leads to the other
  router (the inter-router link).  The record also stores whichever IPv4
  routing snapshots (``ip -j -4 rule show`` / ``ip -j -4 route show table all``)
  have been submitted so far.
* Snapshots are versioned.  Every successful submission increments the
  record's generation; a rejected submission changes nothing.  Diagnosis
  captures the whole record atomically, so a report always reflects one
  generation even if corrections arrive while it is being computed, and the
  generation number is part of the report.
* Diagnosis partitions the query (source CIDR x destination CIDR) symbolically
  into disjoint CIDR pairs, never per address, so ``/0 x /0`` is cheap.  For
  each rectangle the flow is followed hop by hop and classified as:
  ``left_devices`` (forwarded out of the pair), ``blackhole``, ``no_route``,
  ``loop`` or ``pending_snapshot``.  The last one is reported only when the
  traffic actually reaches a device whose snapshot is missing.

Thread safety
-------------
Records live in memory and are immutable values.  Writers and the capture step
are serialized by a re-entrant lock; the symbolic computation runs after the
capture, outside the lock, so corrections can be submitted while a diagnosis
is running without affecting the in-flight report.
"""
from __future__ import annotations

import ipaddress
import json
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence

from . import routing
from .routing import (
    BLACKHOLE,
    NO_ROUTE,
    ParsedPolicy,
    Result,
    Unicast,
    result_json,
)


class RecordError(ValueError):
    """Base class for troubleshooting errors that map to HTTP 400."""


class InvalidRecord(RecordError):
    """The record definition (devices / entry / egress) is not usable."""


class RecordNotFound(LookupError):
    """No record with the given id."""


class DeviceNotFound(LookupError):
    """The record has no device with the given name."""


# Conclusions, in the order used by the documentation.
CONCLUSION_LEFT = "left_devices"
CONCLUSION_BLACKHOLE = "blackhole"
CONCLUSION_NO_ROUTE = "no_route"
CONCLUSION_LOOP = "loop"
CONCLUSION_PENDING = "pending_snapshot"
CONCLUSIONS = (
    CONCLUSION_LEFT,
    CONCLUSION_BLACKHOLE,
    CONCLUSION_NO_ROUTE,
    CONCLUSION_LOOP,
    CONCLUSION_PENDING,
)

HOP_TRANSIT = "transit_to_peer"
HOP_EXIT = "exit_pair"
HOP_BLACKHOLE = "blackhole"
HOP_NO_ROUTE = "no_route"
HOP_PENDING = "pending_snapshot"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# immutable record model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeviceConfig:
    """One of the two routers and its configured exit towards the other."""

    name: str
    egress_dev: str
    egress_gateway: Optional[str]


@dataclass(frozen=True)
class DeviceSnapshot:
    """Latest accepted snapshot for a device (``policy`` is None until then)."""

    policy: Optional[ParsedPolicy]
    version: int


@dataclass(frozen=True)
class Record:
    record_id: str
    name: Optional[str]
    entry_device: str
    devices: tuple[DeviceConfig, ...]
    snapshots: Mapping[str, DeviceSnapshot]
    generation: int
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class CapturedDevice:
    config: DeviceConfig
    policy: Optional[ParsedPolicy]
    snapshot_version: int


@dataclass(frozen=True)
class CapturedRecord:
    """Consistent, immutable view of one record at one generation."""

    record_id: str
    name: Optional[str]
    entry_device: str
    version: int
    devices: tuple[CapturedDevice, ...]


def _normalize_gateway(value: Optional[str], what: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise InvalidRecord(f"{what}: egress gateway must be a non-empty string or null")
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ValueError as exc:
        raise InvalidRecord(f"{what}: invalid IPv4 egress gateway {value!r}") from exc


def _build_devices(
    devices: Sequence[tuple[str, str, Optional[str]]],
) -> tuple[DeviceConfig, ...]:
    if len(devices) != 2:
        raise InvalidRecord(
            f"a record must have exactly two devices, got {len(devices)}"
        )
    built: list[DeviceConfig] = []
    seen: set[str] = set()
    for idx, (name, dev, gateway) in enumerate(devices):
        what = f"device #{idx}"
        if not isinstance(name, str) or not name.strip():
            raise InvalidRecord(f"{what}: name must be a non-empty string")
        clean_name = name.strip()
        if clean_name in seen:
            raise InvalidRecord(f"{what}: duplicate device name {clean_name!r}")
        seen.add(clean_name)
        if not isinstance(dev, str) or not dev.strip():
            raise InvalidRecord(
                f"{what} ({clean_name}): 'egress_dev' must name the interface "
                "that leads to the peer"
            )
        built.append(
            DeviceConfig(
                name=clean_name,
                egress_dev=dev.strip(),
                egress_gateway=_normalize_gateway(gateway, f"{what} ({clean_name})"),
            )
        )
    return tuple(built)


# ---------------------------------------------------------------------------
# in-memory, generation-aware store
# ---------------------------------------------------------------------------

class RecordStore:
    """Thread-safe in-memory store; every accepted snapshot bumps generation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, Record] = {}

    # -- writers ---------------------------------------------------------
    def create(
        self,
        name: Optional[str],
        devices: Sequence[tuple[str, str, Optional[str]]],
        entry_device: str,
    ) -> Record:
        built = _build_devices(devices)
        names = [device.name for device in built]
        if not isinstance(entry_device, str) or entry_device.strip() not in names:
            raise InvalidRecord(
                f"entry_device must be one of {names}, got {entry_device!r}"
            )
        now = _utc_now()
        record = Record(
            record_id=uuid.uuid4().hex,
            name=name.strip() if isinstance(name, str) and name.strip() else None,
            entry_device=entry_device.strip(),
            devices=built,
            snapshots=MappingProxyType(
                {
                    device.name: DeviceSnapshot(policy=None, version=0)
                    for device in built
                }
            ),
            generation=0,
            created_at=now,
            updated_at=now,
        )
        with self._lock:
            self._records[record.record_id] = record
        return record

    def put_snapshot(
        self,
        record_id: str,
        device: str,
        rules: Any,
        routes: Any,
    ) -> tuple[Record, DeviceSnapshot]:
        """Validate then atomically install a snapshot.

        Validation happens *before* the mutation, so an invalid correction
        leaves both the previous snapshot and the record generation untouched.
        """
        with self._lock:
            record = self._records.get(record_id)
        if record is None:
            raise RecordNotFound(f"unknown record {record_id!r}")
        if device not in record.snapshots:
            raise DeviceNotFound(
                f"record {record_id!r} has no device {device!r} "
                f"(devices: {[d.name for d in record.devices]})"
            )
        # Raises routing.UnsupportedInput on any invalid content; nothing has
        # been written at this point.
        policy = routing.compile_policy(rules, routes, f"device {device}")
        with self._lock:
            record = self._records.get(record_id)
            if record is None:  # pragma: no cover - records are never deleted
                raise RecordNotFound(f"unknown record {record_id!r}")
            generation = record.generation + 1
            snapshot = DeviceSnapshot(policy=policy, version=generation)
            snapshots = dict(record.snapshots)
            snapshots[device] = snapshot
            updated = replace(
                record,
                snapshots=MappingProxyType(snapshots),
                generation=generation,
                updated_at=_utc_now(),
            )
            self._records[record_id] = updated
            return updated, snapshot

    # -- readers ---------------------------------------------------------
    def get(self, record_id: str) -> Record:
        with self._lock:
            record = self._records.get(record_id)
        if record is None:
            raise RecordNotFound(f"unknown record {record_id!r}")
        return record

    def capture(self, record_id: str) -> CapturedRecord:
        """Atomically freeze the record for one diagnosis generation."""
        with self._lock:
            record = self._records.get(record_id)
            if record is None:
                raise RecordNotFound(f"unknown record {record_id!r}")
            devices = tuple(
                CapturedDevice(
                    config=device,
                    policy=record.snapshots[device.name].policy,
                    snapshot_version=record.snapshots[device.name].version,
                )
                for device in record.devices
            )
            return CapturedRecord(
                record_id=record.record_id,
                name=record.name,
                entry_device=record.entry_device,
                version=record.generation,
                devices=devices,
            )

    def reset(self) -> None:
        """Drop all records (used by tests)."""
        with self._lock:
            self._records.clear()


store = RecordStore()


# ---------------------------------------------------------------------------
# views shared with the API layer
# ---------------------------------------------------------------------------

def _device_view(device: DeviceConfig) -> dict:
    return {
        "name": device.name,
        "egress_to_peer": {
            "dev": device.egress_dev,
            "gateway": device.egress_gateway,
        },
    }


def record_view(record: Record) -> dict:
    devices = []
    for config in record.devices:
        snap = record.snapshots[config.name]
        view = _device_view(config)
        view.update(
            {
                "entry": config.name == record.entry_device,
                "has_snapshot": snap.policy is not None,
                "snapshot_version": snap.version if snap.policy is not None else None,
                "rules_submitted": (
                    snap.policy.submitted_rule_count if snap.policy else None
                ),
                "routes_submitted": (
                    snap.policy.submitted_route_count if snap.policy else None
                ),
            }
        )
        devices.append(view)
    return {
        "record_id": record.record_id,
        "name": record.name,
        "entry_device": record.entry_device,
        "version": record.generation,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "devices": devices,
    }


# ---------------------------------------------------------------------------
# hop-by-hop analysis
# ---------------------------------------------------------------------------

def _same_gateway(route_gateway: Optional[str], configured: str) -> bool:
    # Both were validated as IPv4 addresses when the policy was built.
    return route_gateway is not None and (
        ipaddress.IPv4Address(route_gateway) == ipaddress.IPv4Address(configured)
    )


def _towards_peer(config: DeviceConfig, result: Unicast) -> bool:
    """Does this forwarding result point down the configured inter-router link?

    A null configured gateway acts as a wildcard on the interface only; when a
    gateway is configured the route's next hop must match it exactly.
    """
    if result.dev != config.egress_dev:
        return False
    if config.egress_gateway is None:
        return True
    return _same_gateway(result.gateway, config.egress_gateway)


def _hop(
    device: CapturedDevice,
    action: str,
    result: Optional[Result],
    basis: Optional[dict],
    note: str,
) -> dict:
    return {
        "device": device.config.name,
        "action": action,
        "result": result_json(result) if result is not None else None,
        "basis": basis,
        "snapshot_version": (
            device.snapshot_version if device.policy is not None else None
        ),
        "note": note,
    }


def _trace(
    decisions: Mapping[str, tuple[Result, dict]],
    devices: Mapping[str, CapturedDevice],
    entry_device: str,
) -> tuple[str, list[dict], str, str]:
    """Follow one constant rectangle through the two-device topology.

    ``decisions`` holds each snapshot-equipped device's constant result and
    routing basis for the rectangle.  Returns
    ``(conclusion, hops, terminal_device, detail)``.
    """
    names = tuple(devices)
    visited: list[str] = []
    hops: list[dict] = []
    current = entry_device

    while True:
        device = devices[current]
        if device.policy is None:
            hops.append(
                _hop(
                    device,
                    HOP_PENDING,
                    None,
                    None,
                    "traffic reaches this device but no routing snapshot "
                    "has been submitted",
                )
            )
            return (
                CONCLUSION_PENDING,
                hops,
                current,
                f"traffic reaches {current}, whose snapshot is still pending",
            )

        if current in visited:
            return (
                CONCLUSION_LOOP,
                hops,
                current,
                f"traffic returns to {current}: the two devices route it "
                "back and forth",
            )
        visited.append(current)

        result, basis = decisions[current]
        if result == BLACKHOLE:
            hops.append(
                _hop(device, HOP_BLACKHOLE, result, basis, "dropped by a blackhole route")
            )
            return (
                CONCLUSION_BLACKHOLE,
                hops,
                current,
                f"traffic is blackholed on {current}",
            )
        if result == NO_ROUTE:
            hops.append(
                _hop(device, HOP_NO_ROUTE, result, basis, "no usable route")
            )
            return (
                CONCLUSION_NO_ROUTE,
                hops,
                current,
                f"traffic has no route on {current}",
            )

        assert isinstance(result, Unicast)
        if _towards_peer(device.config, result):
            peer = next(name for name in names if name != current)
            hops.append(
                _hop(
                    device,
                    HOP_TRANSIT,
                    result,
                    basis,
                    f"forwarded to {peer} over {result.dev}"
                    + (
                        f" via {result.gateway}"
                        if result.gateway is not None
                        else " (on-link)"
                    ),
                )
            )
            current = peer
            continue

        hops.append(
            _hop(
                device,
                HOP_EXIT,
                result,
                basis,
                f"forwarded out of the two-device pair over {result.dev}"
                + (
                    f" via {result.gateway}"
                    if result.gateway is not None
                    else " (on-link)"
                ),
            )
        )
        return (
            CONCLUSION_LEFT,
            hops,
            current,
            f"traffic leaves the two devices at {current}",
        )


# ---------------------------------------------------------------------------
# rectangle merging (keeps the report readable without changing coverage)
# ---------------------------------------------------------------------------

# A rectangle value is (signature, conclusion, hops, terminal_device, detail).
_RectValue = tuple[str, str, list[dict], str, str]


def _merge_once(
    rects: dict[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network], _RectValue],
    dim: str,
) -> dict[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network], _RectValue]:
    """Merge CIDR-sibling rectangles with identical values along one axis."""
    groups: dict[
        tuple[str, ipaddress.IPv4Network], dict[ipaddress.IPv4Network, _RectValue]
    ] = {}
    for (src, dst), value in rects.items():
        if dim == "dst":
            other, along = src, dst
        else:
            other, along = dst, src
        groups.setdefault((value[0], other), {})[along] = value

    merged: dict[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network], _RectValue] = {}
    for (_, other), by_len in groups.items():
        pool = dict(by_len)
        changed = True
        while changed:
            changed = False
            for net in sorted(pool, key=lambda n: n.prefixlen, reverse=True):
                if net not in pool or net.prefixlen == 0:
                    continue
                sibling_int = int(net.network_address) ^ (1 << (32 - net.prefixlen))
                sibling = ipaddress.IPv4Network((sibling_int, net.prefixlen))
                if sibling in pool:
                    value = pool.pop(net)
                    pool.pop(sibling)
                    pool[net.supernet()] = value
                    changed = True
        for net, value in pool.items():
            key = (other, net) if dim == "dst" else (net, other)
            merged[key] = value
    return merged


def _merge_rectangles(
    rects: dict[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network], _RectValue],
) -> dict[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network], _RectValue]:
    current = dict(rects)
    while True:
        count = len(current)
        current = _merge_once(current, "dst")
        current = _merge_once(current, "src")
        if len(current) == count:
            return current


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def _pair_count(
    src: ipaddress.IPv4Network, dst: ipaddress.IPv4Network
) -> int:
    return 1 << (64 - src.prefixlen - dst.prefixlen)


def analyze(
    captured: CapturedRecord,
    source_cidr: Any,
    destination_cidr: Any,
) -> dict:
    """Diagnose a captured record over ``source_cidr x destination_cidr``.

    Works on the frozen :class:`CapturedRecord`, so callers can keep
    submitting corrections while this runs.
    """
    src_net = routing.parse_prefix(source_cidr, "source_cidr")
    dst_net = routing.parse_prefix(destination_cidr, "destination_cidr")

    devices = {device.config.name: device for device in captured.devices}
    if captured.entry_device not in devices:  # pragma: no cover - store invariant
        raise InvalidRecord(f"entry device {captured.entry_device!r} is not in the record")
    policies: dict[str, ParsedPolicy] = {
        name: device.policy
        for name, device in devices.items()
        if device.policy is not None
    }

    cells = routing.partition_rectangles(src_net, dst_net, policies)

    rects: dict[
        tuple[ipaddress.IPv4Network, ipaddress.IPv4Network], _RectValue
    ] = {}
    for src, dst, decisions in cells:
        conclusion, hops, terminal, detail = _trace(
            decisions, devices, captured.entry_device
        )
        # Normalized signature: includes the routing basis so two rectangles
        # are merged only when every reported field (per-hop result and
        # rule/table/prefix) is identical.
        signature = json.dumps(
            [
                conclusion,
                terminal,
                [
                    [
                        hop["device"],
                        hop["action"],
                        hop["result"],
                        hop["basis"],
                        hop["snapshot_version"],
                    ]
                    for hop in hops
                ],
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
        rects[(src, dst)] = (signature, conclusion, hops, terminal, detail)

    rects = _merge_rectangles(rects)

    segments = []
    covered = 0
    per_conclusion: dict[str, int] = {name: 0 for name in CONCLUSIONS}
    for (src, dst), (_, conclusion, hops, terminal, detail) in sorted(
        rects.items(),
        key=lambda item: (
            int(item[0][0].network_address),
            item[0][0].prefixlen,
            int(item[0][1].network_address),
            item[0][1].prefixlen,
        ),
    ):
        count = _pair_count(src, dst)
        covered += count
        per_conclusion[conclusion] += count
        segments.append(
            {
                "source_cidr": str(src),
                "destination_cidr": str(dst),
                "address_pairs": str(count),
                "example": {
                    "source": str(src.network_address),
                    "destination": str(dst.network_address),
                },
                "conclusion": conclusion,
                "terminal_device": terminal,
                "detail": detail,
                "hops": hops,
            }
        )

    total = _pair_count(src_net, dst_net)
    if covered != total:  # pragma: no cover - guards the symbolic partition
        raise AssertionError(
            f"symbolic partition covers {covered} of {total} address pairs"
        )

    device_reports = []
    for config in captured.devices:
        view = _device_view(config.config)
        view.update(
            {
                "entry": config.config.name == captured.entry_device,
                "has_snapshot": config.policy is not None,
                "snapshot_version": (
                    config.snapshot_version if config.policy is not None else None
                ),
                "rules_submitted": (
                    config.policy.submitted_rule_count if config.policy else None
                ),
                "routes_submitted": (
                    config.policy.submitted_route_count if config.policy else None
                ),
            }
        )
        device_reports.append(view)

    return {
        "record_id": captured.record_id,
        "name": captured.name,
        "version": captured.version,
        "entry_device": captured.entry_device,
        "query": {
            "source_cidr": str(src_net),
            "destination_cidr": str(dst_net),
        },
        "devices": device_reports,
        "summary": {
            "source_cidr": str(src_net),
            "destination_cidr": str(dst_net),
            "total_pairs": str(total),
            "covered_pairs": str(covered),
            "segment_count": len(segments),
            "conclusions": {
                name: str(per_conclusion[name])
                for name in CONCLUSIONS
                if per_conclusion[name]
            },
        },
        "segments": segments,
    }
