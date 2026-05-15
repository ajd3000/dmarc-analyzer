"""FastAPI app: local static UI + DMARC aggregate analysis API."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from dmarc_analyzer.parse import (
    MAX_ARCHIVE_BYTES,
    MAX_TOTAL_RECORDS,
    flatten_feedbacks,
    parse_upload,
)
from dmarc_analyzer.ip_org import build_ip_org_map, is_public_ip
from dmarc_analyzer.rules import annotate_rows

# Cap JSON payload size for browser performance
MAX_ROWS_IN_RESPONSE = 15_000

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="DMARC aggregate scanner", version="0.1.0")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze(
    files: list[UploadFile] = File(default_factory=list),
    min_count: int = Form(1),
    resolve_ip_org: str = Form("true"),
) -> JSONResponse:
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    mc = max(1, min_count)
    do_ip_org = resolve_ip_org.strip().lower() in ("true", "1", "on", "yes")

    all_rows: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []
    truncated_flatten = False

    for upload in files:
        if not upload.filename:
            continue
        data = await _read_upload_limited(upload, MAX_ARCHIVE_BYTES)
        pr = parse_upload(upload.filename, data)
        parse_errors.extend(pr.errors)
        rows, trunc = flatten_feedbacks(pr.feedbacks, upload.filename)
        truncated_flatten = truncated_flatten or trunc
        all_rows.extend(rows)

    annotated = annotate_rows(all_rows, min_count=mc)

    reason_counts: dict[str, int] = {}
    for r in annotated:
        for reason in r.get("reasons") or []:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

    rows_out = annotated
    response_truncated = False
    if len(rows_out) > MAX_ROWS_IN_RESPONSE:
        rows_out = rows_out[:MAX_ROWS_IN_RESPONSE]
        response_truncated = True

    org_map: dict[str, str] = {}
    org_meta: dict[str, Any] = {"enabled": False}
    if do_ip_org and rows_out:
        seen_ip: set[str] = set()
        ips_ordered: list[str] = []
        for r in rows_out:
            ip = (r.get("source_ip") or "").strip()
            if ip and ip not in seen_ip:
                seen_ip.add(ip)
                ips_ordered.append(ip)
        org_map, org_meta = await asyncio.to_thread(build_ip_org_map, ips_ordered)
        org_meta["enabled"] = True
        if org_meta.get("capped"):
            for r in rows_out:
                sip = (r.get("source_ip") or "").strip()
                if (
                    sip
                    and is_public_ip(sip)
                    and sip not in org_map
                ):
                    org_map[sip] = "(RDAP lookup cap)"

    # Serialize auth_results for JSON
    serializable: list[dict[str, Any]] = []
    for r in rows_out:
        item = {k: v for k, v in r.items() if k != "auth_results"}
        item["auth_results"] = r.get("auth_results") or []
        sip = (item.get("source_ip") or "").strip()
        if do_ip_org:
            item["ip_org"] = org_map.get(sip, "—")
        else:
            item["ip_org"] = ""
        serializable.append(item)

    return JSONResponse(
        {
            "rows": serializable,
            "summary": {
                "files_received": len(files),
                "rows_in_response": len(serializable),
                "rows_total_parsed": len(annotated),
                "reason_counts": reason_counts,
                "truncated_at_parse_cap": truncated_flatten,
                "truncated_at_response_cap": response_truncated,
                "max_archive_bytes": MAX_ARCHIVE_BYTES,
                "max_total_records_parse": MAX_TOTAL_RECORDS,
                "max_rows_in_response": MAX_ROWS_IN_RESPONSE,
                "ip_org": org_meta,
            },
            "file_errors": parse_errors,
            "options": {
                "min_count": mc,
                "resolve_ip_org": do_ip_org,
            },
        }
    )


async def _read_upload_limited(upload: UploadFile, limit: int) -> bytes:
    buf = bytearray()
    while True:
        chunk = await upload.read(65536)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > limit:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds maximum size ({limit} bytes)",
            )
    return bytes(buf)


if STATIC_DIR.is_dir():
    app.mount(
        "/static",
        StaticFiles(directory=str(STATIC_DIR)),
        name="static",
    )


@app.get("/")
def index() -> FileResponse:
    index_path = STATIC_DIR / "index.html"
    if not index_path.is_file():
        raise HTTPException(status_code=500, detail="static/index.html missing")
    return FileResponse(index_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="DMARC aggregate scanner (local UI)")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default 127.0.0.1)",
    )
    parser.add_argument("--port", type=int, default=8765, help="TCP port")
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Dev auto-reload (do not use for packaged runs)",
    )
    args = parser.parse_args()

    import uvicorn

    uvicorn.run(
        "dmarc_analyzer.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
