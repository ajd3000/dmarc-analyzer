"""Resolve source IP → organization-ish label via RDAP (ipwhois)."""

from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# Tunables: RDAP can be slow; many parallel queries hit RIR rate limits → empty "—" rows.
MAX_UNIQUE_IP_LOOKUPS = 300
RDAP_WORKERS = 4
RDAP_CHUNK = 24  # IPs per parallel batch (avoids hundreds of pending futures at once)
RDAP_PER_FUTURE_SEC = 120  # max wait for each lookup result once its future completes
RDAP_PER_IP_RETRIES = 3


def is_public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address((text or "").strip())
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved:
        return False
    if getattr(ip, "is_future_reserved", False):
        return False
    return True


def _format_rdap_line(d: dict[str, Any]) -> str:
    """Best-effort one-line label similar to common WHOIS 'Org + net handle' style."""
    parts: list[str] = []
    asn_desc = (d.get("asn_description") or "").strip()
    if asn_desc:
        parts.append(asn_desc)

    net = d.get("network")
    handle = ""
    name = ""
    if isinstance(net, dict):
        handle = (net.get("handle") or "").strip()
        name = (net.get("name") or "").strip()

    # RDAP sometimes omits asn_description; use network name (e.g. MSFT) as a fallback title.
    if not parts and name:
        parts.append(name)

    tail = ""
    if handle and handle not in asn_desc:
        tail = f"({handle})"
    elif name and name not in asn_desc and not parts:
        tail = f"({name})"

    if tail:
        if parts:
            return f"{parts[0]} {tail}".strip()
        return tail
    if parts:
        return parts[0]
    return "—"


def _lookup_one(ip: str) -> tuple[str, str]:
    from ipwhois import IPWhois

    for attempt in range(RDAP_PER_IP_RETRIES):
        try:
            d = IPWhois(ip).lookup_rdap(retry_count=2, depth=0)
            label = _format_rdap_line(d)
            if label != "—":
                return ip, label
        except Exception:
            pass
        if attempt < RDAP_PER_IP_RETRIES - 1:
            time.sleep(0.35 * (2**attempt))
    return ip, "—"


def build_ip_org_map(source_ips: list[str]) -> tuple[dict[str, str], dict[str, Any]]:
    """
    Deduplicate and RDAP-lookup public IPs in parallel.

    Returns (ip -> label, meta) where meta includes counts and cap info.
    """
    meta: dict[str, Any] = {
        "unique_public": 0,
        "looked_up": 0,
        "capped": False,
        "non_public_skipped": 0,
        "errors": False,
    }
    ordered: list[str] = []
    seen: set[str] = set()
    out: dict[str, str] = {}

    for raw in source_ips:
        ip = (raw or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        if not is_public_ip(ip):
            out[ip] = "(non-public)"
            meta["non_public_skipped"] += 1
            continue
        ordered.append(ip)

    meta["unique_public"] = len(ordered)
    if len(ordered) > MAX_UNIQUE_IP_LOOKUPS:
        meta["capped"] = True
        ordered = ordered[:MAX_UNIQUE_IP_LOOKUPS]

    if not ordered:
        return out, meta

    # Chunked parallel RDAP: `as_completed(..., timeout=T)` is **idle time since last
    # completion**, not a total budget — with 200+ IPs it wrongly raises TimeoutError
    # while most futures are still running. Process modest batches with no iterator
    # timeout instead.
    for i in range(0, len(ordered), RDAP_CHUNK):
        chunk = ordered[i : i + RDAP_CHUNK]
        with ThreadPoolExecutor(max_workers=min(RDAP_WORKERS, len(chunk))) as pool:
            fut_map = {pool.submit(_lookup_one, ip): ip for ip in chunk}
            for fut in as_completed(fut_map):
                ip_key = fut_map[fut]
                try:
                    ip, label = fut.result(timeout=RDAP_PER_FUTURE_SEC)
                    out[ip] = label
                except Exception:
                    meta["errors"] = True
                    out[ip_key] = "—"
        time.sleep(0.1)

    meta["looked_up"] = sum(1 for ip in ordered if ip in out)
    meta["max_lookups"] = MAX_UNIQUE_IP_LOOKUPS

    # Second pass: RDAP rate-limits parallel bursts; retry "—" sequentially.
    misses = [ip for ip in ordered if out.get(ip) == "—"]
    for ip in misses:
        ip2, label = _lookup_one(ip)
        out[ip2] = label

    for ip in ordered:
        if ip not in out:
            out[ip] = "— (timeout)"

    return out, meta
