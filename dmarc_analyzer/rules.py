"""Classify DMARC aggregate rows for quick triage."""

from __future__ import annotations

from typing import Any


def _lower(s: str | None) -> str:
    return (s or "").strip().lower()


def _count_int(row: dict[str, Any]) -> int:
    try:
        return int(str(row.get("count") or "0"))
    except ValueError:
        return 0


def tag_row(row: dict[str, Any], min_count: int = 1) -> list[str]:
    """Return all applicable reason codes (independent flags on one row)."""
    reasons: list[str] = []
    disp = _lower(row.get("disposition"))
    dkim = _lower(row.get("policy_dkim"))
    spf = _lower(row.get("policy_spf"))
    cnt = _count_int(row)
    mc = max(1, min_count)

    if disp and disp != "none":
        reasons.append("disposition_non_none")

    if dkim == "fail" and spf == "fail":
        reasons.append("dkim_spf_double_fail")

    if dkim == "fail" and spf != "fail" and cnt >= mc:
        reasons.append("dkim_fail_only")

    if spf == "fail" and dkim == "pass" and cnt >= mc:
        reasons.append("spf_alignment_fail")

    return reasons


def annotate_rows(rows: list[dict[str, Any]], min_count: int = 1) -> list[dict[str, Any]]:
    """Return shallow copies of rows with `reasons` and `severity` keys."""
    out: list[dict[str, Any]] = []
    for r in rows:
        reasons = tag_row(r, min_count)
        severity = _severity(reasons)
        out.append({**r, "reasons": reasons, "severity": severity})
    return out


def _severity(reasons: list[str]) -> str:
    if "disposition_non_none" in reasons or "dkim_spf_double_fail" in reasons:
        return "high"
    if "dkim_fail_only" in reasons:
        return "medium"
    if "spf_alignment_fail" in reasons:
        return "low"
    return "none"


def filter_by_reasons(
    rows: list[dict[str, Any]], active_codes: set[str]
) -> list[dict[str, Any]]:
    """Keep rows whose reasons intersect active_codes."""
    if not active_codes:
        return [r for r in rows if r.get("reasons")]
    return [
        r
        for r in rows
        if active_codes.intersection(set(r.get("reasons") or []))
    ]
