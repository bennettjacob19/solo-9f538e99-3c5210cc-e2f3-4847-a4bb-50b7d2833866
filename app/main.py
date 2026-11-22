"""FastAPI application exposing the dual-egress routing precheck and
hop-by-hop troubleshooting."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse

from . import routing, troubleshoot
from .models import (
    DiagnoseReport,
    PrecheckRequest,
    PrecheckResponse,
    RecordCreateRequest,
    RecordView,
    SnapshotAccepted,
    SnapshotRequest,
)

app = FastAPI(
    title="Dual-Egress Routing Precheck",
    version="1.1.0",
    description=(
        "Counts how many (source, destination) address pairs change their "
        "forwarding result between two Linux IPv4 policy-routing snapshots, "
        "and diagnoses hop by hop where traffic stops between two routers of "
        "a dual-egress site.\n\n"
        "Precheck: submit the parsed JSON of `ip -j -4 rule show` and "
        "`ip -j -4 route show table all` (before and after the planned change) "
        "plus a source and destination IPv4 CIDR. The local table and rules "
        "pointing to it are ignored; computation is symbolic, so `/0` CIDRs "
        "are cheap. Unsupported features (multipath, fwmark selectors, "
        "non-unicast/throw/blackhole routes, ...) are rejected with HTTP 400.\n\n"
        "Troubleshoot: create a record naming the two routers, their entry "
        "device and each router's egress interface/gateway towards the other, "
        "submit one IPv4 snapshot per device, then diagnose a source/destination "
        "CIDR pair. Reports are computed from one captured record generation and "
        "state that version; corrections submitted while a diagnosis runs become "
        "the next version and do not alter the in-flight report."
    ),
)


@app.get("/", include_in_schema=False)
def index() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/healthz", tags=["meta"])
def healthz() -> dict:
    return {"status": "ok"}


@app.post(
    "/precheck",
    response_model=PrecheckResponse,
    tags=["precheck"],
    responses={
        200: {"description": "Changed address pairs grouped by before/after result"},
        400: {"description": "Unsupported or invalid input"},
        422: {"description": "Request body does not match the schema"},
    },
)
def precheck(req: PrecheckRequest) -> dict:
    try:
        return routing.run_precheck(
            req.source_cidr,
            req.destination_cidr,
            req.before.rules,
            req.before.routes,
            req.after.rules,
            req.after.routes,
        )
    except routing.UnsupportedInput as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# troubleshooting records
# ---------------------------------------------------------------------------

def _record_not_found(exc: LookupError) -> HTTPException:
    return HTTPException(status_code=404, detail=str(exc))


@app.post(
    "/troubleshoot/records",
    response_model=RecordView,
    status_code=201,
    tags=["troubleshoot"],
    responses={
        201: {"description": "Record created; both snapshots start as pending"},
        400: {"description": "Invalid record definition"},
        422: {"description": "Request body does not match the schema"},
    },
)
def create_record(req: RecordCreateRequest) -> dict:
    """Create a two-router record: entry device plus both egresses to the peer."""
    try:
        record = troubleshoot.store.create(
            req.name,
            [(d.name, d.egress_dev, d.egress_gateway) for d in req.devices],
            req.entry_device,
        )
    except troubleshoot.InvalidRecord as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return troubleshoot.record_view(record)


@app.get(
    "/troubleshoot/records/{record_id}",
    response_model=RecordView,
    tags=["troubleshoot"],
    responses={404: {"description": "Unknown record"}},
)
def get_record(record_id: str) -> dict:
    """Show a record: egress parameters, snapshot state and current version."""
    try:
        return troubleshoot.record_view(troubleshoot.store.get(record_id))
    except troubleshoot.RecordNotFound as exc:
        raise _record_not_found(exc) from exc


@app.put(
    "/troubleshoot/records/{record_id}/devices/{device}/snapshot",
    response_model=SnapshotAccepted,
    tags=["troubleshoot"],
    responses={
        200: {"description": "Snapshot accepted as the next record version"},
        400: {"description": "Unsupported or invalid snapshot; nothing changed"},
        404: {"description": "Unknown record or device"},
        422: {"description": "Request body does not match the schema"},
    },
)
def put_snapshot(record_id: str, device: str, req: SnapshotRequest) -> dict:
    """Submit or correct one device's snapshot; success bumps the version."""
    try:
        record, snapshot = troubleshoot.store.put_snapshot(
            record_id, device, req.rules, req.routes
        )
    except troubleshoot.RecordNotFound as exc:
        raise _record_not_found(exc) from exc
    except troubleshoot.DeviceNotFound as exc:
        raise _record_not_found(exc) from exc
    except routing.UnsupportedInput as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "record": troubleshoot.record_view(record),
        "device": device,
        "snapshot_version": snapshot.version,
    }


@app.post(
    "/troubleshoot/records/{record_id}/diagnose",
    response_model=DiagnoseReport,
    tags=["troubleshoot"],
    responses={
        200: {"description": "Hop-by-hop report for one captured record version"},
        400: {"description": "Invalid query CIDR"},
        404: {"description": "Unknown record"},
        422: {"description": "Query parameters missing or malformed"},
    },
)
def diagnose(record_id: str, source_cidr: str, destination_cidr: str) -> dict:
    """Diagnose `source_cidr x destination_cidr`; both may be `0.0.0.0/0`."""
    try:
        captured = troubleshoot.store.capture(record_id)
    except troubleshoot.RecordNotFound as exc:
        raise _record_not_found(exc) from exc
    try:
        # Validate both CIDRs before the (read-only) capture walk is ever used.
        troubleshoot.routing.parse_prefix(source_cidr, "source_cidr")
        troubleshoot.routing.parse_prefix(destination_cidr, "destination_cidr")
    except routing.UnsupportedInput as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # The computation works on the frozen capture only, so snapshot
    # corrections arriving now affect later queries, never this report.
    return troubleshoot.analyze(captured, source_cidr, destination_cidr)
