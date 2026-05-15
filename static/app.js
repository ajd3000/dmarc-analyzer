/**
 * DMARC scanner UI — fetch /api/analyze, filter rows client-side.
 */
(function () {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const clearBtn = document.getElementById("clearBtn");
  const downloadJsonBtn = document.getElementById("downloadJsonBtn");
  const minCount = document.getElementById("minCount");
  const resolveIpOrg = document.getElementById("resolveIpOrg");
  const fileList = document.getElementById("fileList");
  const summary = document.getElementById("summary");
  const errors = document.getElementById("errors");
  const resultsBody = document.getElementById("resultsBody");
  const rowCountLabel = document.getElementById("rowCountLabel");
  const showAllRows = document.getElementById("showAllRows");
  const resultsTable = document.getElementById("resultsTable");

  /** @type {File[]} */
  let stagedFiles = [];
  /** @type {object | null} */
  let lastResponse = null;
  let sortKey = "count";
  let sortDir = -1;

  function renderFileList() {
    fileList.innerHTML = "";
    stagedFiles.forEach((f) => {
      const li = document.createElement("li");
      li.textContent = `${f.name} (${(f.size / 1024).toFixed(1)} KiB)`;
      fileList.appendChild(li);
    });
  }

  function addFiles(fileListLike) {
    const arr = Array.from(fileListLike || []);
    stagedFiles = stagedFiles.concat(arr);
    renderFileList();
  }

  dropzone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    addFiles(fileInput.files);
    fileInput.value = "";
  });

  ["dragenter", "dragover"].forEach((ev) => {
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.add("drag");
    });
  });
  ["dragleave", "drop"].forEach((ev) => {
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag");
    });
  });
  dropzone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length) addFiles(dt.files);
  });

  clearBtn.addEventListener("click", () => {
    stagedFiles = [];
    renderFileList();
    lastResponse = null;
    downloadJsonBtn.disabled = true;
    resultsBody.innerHTML = "";
    rowCountLabel.textContent = "";
    summary.classList.add("hidden");
    errors.classList.add("hidden");
  });

  function activeReasonFilters() {
    const boxes = document.querySelectorAll(".reason-filter:checked");
    return new Set(Array.from(boxes).map((b) => /** @type {HTMLInputElement} */ (b).value));
  }

  function rowMatchesFilters(row) {
    if (showAllRows.checked) return true;
    const reasons = row.reasons || [];
    if (!reasons.length) return false;
    const active = activeReasonFilters();
    if (!active.size) return reasons.length > 0;
    return reasons.some((r) => active.has(r));
  }

  function severityClass(sev) {
    if (sev === "high") return "sev-high";
    if (sev === "medium") return "sev-medium";
    if (sev === "low") return "sev-low";
    return "sev-none";
  }

  /** Format `<date_range>` begin/end (Unix sec, UTC) for display. */
  function formatReportWindowUtc(beginStr, endStr) {
    const b = parseInt(String(beginStr || ""), 10);
    const e = parseInt(String(endStr || ""), 10);
    if (!Number.isFinite(b) || b < 0) return "—";
    const d0 = new Date(b * 1000);
    const isoDay = (d) => d.toISOString().slice(0, 10);
    if (!Number.isFinite(e) || e < b) return isoDay(d0);
    const d1 = new Date(e * 1000);
    const day0 = isoDay(d0);
    const day1 = isoDay(d1);
    if (day0 === day1) return day0;
    return `${day0} → ${day1}`;
  }

  function renderTable(rows) {
    const sorted = rows.slice().sort((a, b) => {
      let va = a[sortKey];
      let vb = b[sortKey];
      if (sortKey === "reasons") {
        va = (va || []).join(",");
        vb = (vb || []).join(",");
      }
      if (sortKey === "count" || sortKey === "date_begin") {
        va = parseInt(String(va || "0"), 10);
        vb = parseInt(String(vb || "0"), 10);
      }
      if (sortKey === "ip_org") {
        va = String(va || "");
        vb = String(vb || "");
      }
      if (va === vb) return 0;
      if (va === undefined || va === null) return 1;
      if (vb === undefined || vb === null) return -1;
      const c = va < vb ? -1 : 1;
      return c * sortDir;
    });

    resultsBody.innerHTML = "";
    sorted.forEach((row) => {
      const tr = document.createElement("tr");
      const reasons = (row.reasons || []).join(", ") || "—";
      const auth = row.auth_summary || "";
      const reportDate = formatReportWindowUtc(row.date_begin, row.date_end);
      tr.innerHTML = `
        <td class="date-cell" title="begin=${escapeHtml(String(row.date_begin ?? ""))} end=${escapeHtml(String(row.date_end ?? ""))}">${escapeHtml(reportDate)}</td>
        <td class="${severityClass(row.severity)}">${escapeHtml(row.severity || "")}</td>
        <td class="reason-tags">${escapeHtml(reasons)}</td>
        <td class="num">${escapeHtml(String(row.count ?? ""))}</td>
        <td>${escapeHtml(row.source_ip || "")}</td>
        <td class="org-cell" title="RDAP (registration data); same idea as WHOIS org line">${escapeHtml(row.ip_org || "—")}</td>
        <td>${escapeHtml(row.disposition || "")}</td>
        <td>${escapeHtml(row.policy_dkim || "")}</td>
        <td>${escapeHtml(row.policy_spf || "")}</td>
        <td>${escapeHtml(row.header_from || "")}</td>
        <td>${escapeHtml(row.org_name || "")}</td>
        <td>${escapeHtml(row.upload_file || "")}</td>
        <td class="auth-cell">${escapeHtml(auth)}</td>
      `;
      resultsBody.appendChild(tr);
    });
    rowCountLabel.textContent =
      rows.length === 0 ? "(no matching rows)" : `(${rows.length} row${rows.length === 1 ? "" : "s"})`;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderSummary(data) {
    const s = data.summary || {};
    const parts = [
      `Files: <strong>${s.files_received ?? 0}</strong>`,
      `Parsed rows: <strong>${s.rows_total_parsed ?? 0}</strong>`,
      `Shown in table: <strong>${s.rows_in_response ?? 0}</strong>`,
    ];
    if (s.truncated_at_parse_cap) {
      parts.push(
        `<span class="warn">Parse cap hit (${s.max_total_records_parse} rows max).</span>`
      );
    }
    if (s.truncated_at_response_cap) {
      parts.push(
        `<span class="warn">Response cap: only first ${s.max_rows_in_response} rows sent to browser.</span>`
      );
    }
    const io = s.ip_org;
    if (io && io.enabled) {
      const cap = io.capped
        ? ` <span class="warn">RDAP capped at ${io.max_lookups ?? "?"} unique IPs.</span>`
        : "";
      parts.push(
        `<br/>IP org (RDAP): <strong>${io.looked_up ?? 0}</strong> lookups, unique public <strong>${io.unique_public ?? 0}</strong>${cap}`
      );
    } else if (io && !io.enabled) {
      parts.push(`<br/>IP org: <em>disabled</em>`);
    }
    const rc = s.reason_counts || {};
    const rcStr = Object.keys(rc).length
      ? `<br/>Reason counts: <code>${escapeHtml(JSON.stringify(rc))}</code>`
      : "";
    summary.innerHTML = `<div>${parts.join(" · ")}${rcStr}</div>`;
    summary.classList.remove("hidden");
  }

  function renderErrors(list) {
    if (!list || !list.length) {
      errors.classList.add("hidden");
      errors.innerHTML = "";
      return;
    }
    errors.innerHTML = `<h3>File / parse issues</h3><pre>${escapeHtml(
      list.map((e) => `${e.file}: ${e.error}`).join("\n")
    )}</pre>`;
    errors.classList.remove("hidden");
  }

  document.querySelectorAll(".reason-filter, #showAllRows").forEach((el) => {
    el.addEventListener("change", () => {
      if (!lastResponse || !lastResponse.rows) return;
      const filtered = lastResponse.rows.filter(rowMatchesFilters);
      renderTable(filtered);
    });
  });

  resultsTable.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const k = th.getAttribute("data-sort");
      if (!k || !lastResponse) return;
      if (sortKey === k) sortDir *= -1;
      else {
        sortKey = k;
        sortDir = k === "count" || k === "date_begin" ? -1 : 1;
      }
      const filtered = lastResponse.rows.filter(rowMatchesFilters);
      renderTable(filtered);
    });
  });

  analyzeBtn.addEventListener("click", async () => {
    if (!stagedFiles.length) {
      alert("Choose one or more files first.");
      return;
    }
    analyzeBtn.disabled = true;
    summary.classList.add("hidden");
    errors.classList.add("hidden");
    try {
      const fd = new FormData();
      stagedFiles.forEach((f) => fd.append("files", f, f.name));
      fd.append("min_count", String(parseInt(minCount.value, 10) || 1));
      fd.append("resolve_ip_org", resolveIpOrg.checked ? "true" : "false");
      const res = await fetch("/api/analyze", { method: "POST", body: fd });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || res.statusText);
      }
      const data = await res.json();
      lastResponse = data;
      downloadJsonBtn.disabled = false;
      renderSummary(data);
      renderErrors(data.file_errors);
      const filtered = (data.rows || []).filter(rowMatchesFilters);
      renderTable(filtered);
    } catch (e) {
      console.error(e);
      alert(String(e.message || e));
    } finally {
      analyzeBtn.disabled = false;
    }
  });

  downloadJsonBtn.addEventListener("click", () => {
    if (!lastResponse) return;
    const blob = new Blob([JSON.stringify(lastResponse, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "dmarc-scan.json";
    a.click();
    URL.revokeObjectURL(a.href);
  });
})();
