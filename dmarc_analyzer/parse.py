"""Parse DMARC aggregate XML from bytes (plain, gzip, or ZIP archives)."""

from __future__ import annotations

import gzip
import io
import zipfile
from dataclasses import dataclass, field
from typing import Any

from defusedxml.ElementTree import fromstring as defused_fromstring

# Upload / expansion guards (override via env in server if needed)
MAX_ARCHIVE_BYTES = 25 * 1024 * 1024  # 25 MiB per uploaded file
MAX_DECOMPRESSED_XML = 50 * 1024 * 1024  # 50 MiB per XML payload after gzip
MAX_XML_PARSE_BYTES = 50 * 1024 * 1024
MAX_RECORDS_PER_FILE = 20_000
MAX_TOTAL_RECORDS = 100_000


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _text(el: Any) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _find_child(parent: Any, *names: str) -> Any:
    for child in list(parent):
        if _local(child.tag) in names:
            return child
    return None


def _read_gzip_limited(data: bytes, limit: int = MAX_DECOMPRESSED_XML) -> bytes:
    buf = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as gz:
        while True:
            chunk = gz.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > limit:
                raise ValueError(
                    f"Decompressed size exceeds limit ({limit} bytes)"
                )
    return bytes(buf)


def _parse_xml_bytes(xml_bytes: bytes, *, source_label: str) -> dict[str, Any]:
    if len(xml_bytes) > MAX_XML_PARSE_BYTES:
        raise ValueError("XML payload too large to parse")
    try:
        root = defused_fromstring(xml_bytes)
    except Exception as exc:  # noqa: BLE001 - surface parse errors
        raise ValueError(f"Invalid XML ({source_label}): {exc}") from exc
    if _local(root.tag) != "feedback":
        raise ValueError(f"Not a DMARC aggregate document (root={_local(root.tag)!r})")
    return _feedback_to_dict(root, source_label=source_label)


def _feedback_to_dict(root: Any, *, source_label: str) -> dict[str, Any]:
    meta_el = _find_child(root, "report_metadata")
    policy_el = _find_child(root, "policy_published")

    org_name = _text(_find_child(meta_el, "org_name")) if meta_el is not None else ""
    report_email = _text(_find_child(meta_el, "email")) if meta_el is not None else ""
    report_id = _text(_find_child(meta_el, "report_id")) if meta_el is not None else ""
    dr = _find_child(meta_el, "date_range") if meta_el is not None else None
    date_begin = _text(_find_child(dr, "begin")) if dr is not None else ""
    date_end = _text(_find_child(dr, "end")) if dr is not None else ""

    policy_domain = _text(_find_child(policy_el, "domain")) if policy_el is not None else ""
    adkim = _text(_find_child(policy_el, "adkim")) if policy_el is not None else ""
    aspf = _text(_find_child(policy_el, "aspf")) if policy_el is not None else ""
    p = _text(_find_child(policy_el, "p")) if policy_el is not None else ""
    sp = _text(_find_child(policy_el, "sp")) if policy_el is not None else ""
    pct = _text(_find_child(policy_el, "pct")) if policy_el is not None else ""

    records_out: list[dict[str, Any]] = []
    for rec in list(root):
        if _local(rec.tag) != "record":
            continue
        if len(records_out) >= MAX_RECORDS_PER_FILE:
            break
        row = _find_child(rec, "row")
        identifiers = _find_child(rec, "identifiers")
        auth_results = _find_child(rec, "auth_results")

        source_ip = ""
        count = "0"
        disposition = ""
        policy_dkim = ""
        policy_spf = ""
        if row is not None:
            source_ip = _text(_find_child(row, "source_ip"))
            count = _text(_find_child(row, "count")) or "0"
            pe = _find_child(row, "policy_evaluated")
            if pe is not None:
                disposition = _text(_find_child(pe, "disposition"))
                policy_dkim = _text(_find_child(pe, "dkim"))
                policy_spf = _text(_find_child(pe, "spf"))

        header_from = ""
        envelope_from = ""
        if identifiers is not None:
            header_from = _text(_find_child(identifiers, "header_from"))
            envelope_from = _text(_find_child(identifiers, "envelope_from"))

        auth_flat: list[dict[str, str]] = []
        if auth_results is not None:
            for child in list(auth_results):
                lt = _local(child.tag)
                if lt not in {"dkim", "spf"}:
                    continue
                dom = _text(_find_child(child, "domain"))
                sel = _text(_find_child(child, "selector"))
                res = _text(_find_child(child, "result"))
                auth_flat.append(
                    {
                        "type": lt,
                        "domain": dom,
                        "selector": sel,
                        "result": res,
                    }
                )

        records_out.append(
            {
                "source_ip": source_ip,
                "count": count,
                "disposition": disposition,
                "policy_dkim": policy_dkim,
                "policy_spf": policy_spf,
                "header_from": header_from,
                "envelope_from": envelope_from,
                "auth_results": auth_flat,
                "auth_summary": _format_auth_summary(auth_flat),
            }
        )

    return {
        "source_label": source_label,
        "org_name": org_name,
        "report_email": report_email,
        "report_id": report_id,
        "date_begin": date_begin,
        "date_end": date_end,
        "policy_domain": policy_domain,
        "adkim": adkim,
        "aspf": aspf,
        "p": p,
        "sp": sp,
        "pct": pct,
        "records": records_out,
    }


def _format_auth_summary(auth_flat: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for a in auth_flat:
        t = a.get("type", "")
        dom = a.get("domain", "")
        res = a.get("result", "")
        sel = a.get("selector", "")
        if sel:
            parts.append(f"{t.upper()} {dom} sel={sel}={res}")
        else:
            parts.append(f"{t.upper()} {dom}={res}")
    return "; ".join(parts) if parts else ""


@dataclass
class ParseResult:
    feedbacks: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    truncated_total: bool = False


def parse_upload(filename: str, data: bytes) -> ParseResult:
    """Parse one uploaded file (.zip, .xml, or .xml.gz)."""
    result = ParseResult()
    if len(data) > MAX_ARCHIVE_BYTES:
        result.errors.append(
            {
                "file": filename,
                "error": f"File exceeds max size ({MAX_ARCHIVE_BYTES} bytes)",
            }
        )
        return result

    lower = filename.lower()
    try:
        if lower.endswith(".zip"):
            _parse_zip(filename, data, result)
        elif lower.endswith(".xml.gz"):
            xml_bytes = _read_gzip_limited(data)
            fb = _parse_xml_bytes(xml_bytes, source_label=f"{filename}#xml")
            result.feedbacks.append(fb)
        elif lower.endswith(".xml"):
            fb = _parse_xml_bytes(data, source_label=f"{filename}#xml")
            result.feedbacks.append(fb)
        else:
            # Try ZIP magic; otherwise try as XML
            if data[:2] == b"PK":
                _parse_zip(filename, data, result)
            else:
                fb = _parse_xml_bytes(data, source_label=f"{filename}#xml")
                result.feedbacks.append(fb)
    except Exception as exc:  # noqa: BLE001
        result.errors.append({"file": filename, "error": str(exc)})
    return result


def _parse_zip(filename: str, data: bytes, result: ParseResult) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Bad ZIP: {exc}") from exc

    with zf:
        names = zf.namelist()
        parsed_any = False
        for name in names:
            if name.endswith("/"):
                continue
            nl = name.lower()
            if not (nl.endswith(".xml") or nl.endswith(".xml.gz")):
                continue
            try:
                raw = zf.read(name)
            except zipfile.BadZipFile as exc:
                result.errors.append({"file": f"{filename}!{name}", "error": str(exc)})
                continue
            if len(raw) > MAX_DECOMPRESSED_XML and not nl.endswith(".gz"):
                result.errors.append(
                    {
                        "file": f"{filename}!{name}",
                        "error": "ZIP member too large",
                    }
                )
                continue
            try:
                if nl.endswith(".xml.gz"):
                    xml_bytes = _read_gzip_limited(raw)
                else:
                    xml_bytes = raw[:MAX_DECOMPRESSED_XML]
                    if len(raw) > MAX_DECOMPRESSED_XML:
                        raise ValueError("XML member exceeds decompressed limit")
                fb = _parse_xml_bytes(
                    xml_bytes, source_label=f"{filename}!{name}"
                )
                result.feedbacks.append(fb)
                parsed_any = True
            except Exception as exc:  # noqa: BLE001
                result.errors.append(
                    {"file": f"{filename}!{name}", "error": str(exc)}
                )
        if not parsed_any and not result.errors:
            result.errors.append(
                {
                    "file": filename,
                    "error": "ZIP contained no .xml or .xml.gz members",
                }
            )


def flatten_feedbacks(
    feedbacks: list[dict[str, Any]],
    upload_filename: str,
) -> tuple[list[dict[str, Any]], bool]:
    """Attach upload + report metadata to each record for the UI."""
    rows: list[dict[str, Any]] = []
    truncated = False
    for fb in feedbacks:
        base = {k: v for k, v in fb.items() if k != "records"}
        base["upload_file"] = upload_filename
        for rec in fb.get("records", []):
            if len(rows) >= MAX_TOTAL_RECORDS:
                truncated = True
                return rows, truncated
            row = {**base, **rec}
            rows.append(row)
    return rows, truncated
