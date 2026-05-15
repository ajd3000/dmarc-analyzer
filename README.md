# DMARC aggregate scanner

Small **local-only** tool: upload DMARC **aggregate** reports (ZIP with `.xml` / `.xml.gz`, or raw XML), see high-signal rows (disposition not `none`, DKIM+SPF double fail, optional DKIM-only / SPF-alignment noise). **Nothing is written to disk** except an optional JSON download from your browser.

## Requirements

- **Python 3.11+**
- Windows, macOS, or Linux

## Run (development)

From this directory (`dmarc-analyzer/`):

```bash
python -m pip install -r requirements.txt
python -m dmarc_analyzer
```

On **Windows**, if `python` is missing or opens the Microsoft Store stub, use the **Python launcher** instead (same commands, swap the prefix):

```powershell
py -3 -m pip install -r requirements.txt
py -3 -m dmarc_analyzer
```

Open **http://127.0.0.1:8765** in your browser.

Options:

```bash
python -m dmarc_analyzer --port 9000
python -m dmarc_analyzer --host 127.0.0.1 --port 8765
```

Windows (`py -3`):

```powershell
py -3 -m dmarc_analyzer --port 9000
py -3 -m dmarc_analyzer --host 127.0.0.1 --port 8765
```

Do **not** expose `--host 0.0.0.0` on untrusted networks; uploads are sensitive.

### Editable install (optional)

```bash
python -m pip install -e .
dmarc-analyzer --port 8765
```

Windows (`py -3`):

```powershell
py -3 -m pip install -e .
py -3 -m dmarc_analyzer --port 8765
```

## Limits (zip bombs / huge mailstreams)

Configurable in `dmarc_analyzer/parse.py` and `dmarc_analyzer/server.py`:

| Limit | Default |
|--------|---------|
| Max upload size per file | 25 MiB |
| Max decompressed XML per member | 50 MiB |
| Max records parsed per XML | 20,000 |
| Max total rows across all uploads in one request | 100,000 |
| Max rows returned to the browser JSON | 15,000 |

If you hit caps, split uploads or raise constants locally.

## PyInstaller (optional “single folder” app)

PyInstaller does **not** cross-compile: build on each OS you need.

1. Install deps + PyInstaller: `python -m pip install -r requirements.txt pyinstaller` (Windows: `py -3 -m pip install -r requirements.txt pyinstaller`)
2. From `dmarc-analyzer/`:

```bash
pyinstaller --name dmarc-analyzer ^
  --onedir ^
  --add-data "static;static" ^
  --collect-all uvicorn ^
  dmarc_analyzer/server.py
```

On macOS/Linux use `--add-data "static:static"`.

3. Run the generated executable; it still binds to **127.0.0.1** by default.

**Note:** `uvicorn.run("dmarc_analyzer.server:app", ...)` expects the `dmarc_analyzer` package on `PYTHONPATH`. For PyInstaller, prefer a small **launcher entry script** that imports `app` from `dmarc_analyzer.server` and calls `uvicorn.run(app, ...)` so the bundle includes your package cleanly. Adjust hidden imports if the console shows import errors.

## What it does / does not do

- **Does:** Aggregate reports (ZIP / `.xml.gz` / `.xml`), RFC-style `<feedback>` XML.
- **Does not:** Forensic failure reports (`message/rfc822` attachments), historical “new IP” baselines without saved state.

## UI behavior

- All rows are **tagged** with reason codes server-side.
- Checkboxes filter which reasons appear in the table; **“Show all rows”** disables reason filtering.
- **Download JSON** saves the last API response (in-memory in the page) to a file.

### IP org (RDAP) column

- Optional checkbox **Resolve IP org (RDAP)** (default: on). Uncheck for faster runs when you only care about auth columns.
- The **IP org** column is built from **RDAP** (registration data) via **`ipwhois`**, similar in spirit to a WHOIS “org + net handle” line — **not** a live `nslookup` PTR name.
- Requires **outbound internet** from the machine running the app (queries to RIR / RDAP services).
- **Dedupes** by `source_ip` per request. At most **300** unique **public** IPs are queried; extra unique IPs show **`(RDAP lookup cap)`**. Large reports may take **a few minutes** on first analyze. RDAP registries sometimes **rate-limit** bursts; the app uses **chunked parallel batches** (not a single giant `as_completed` timeout, which would abort mid-run), **per-IP retries**, and a **second sequential pass** for any IPs that still returned **"—"** after the first batch.
