# nessus-scope-extract

Two utilities for working with Nessus HTML reports:

- **`scope-extract.py`** — extract Service Detection `ip:port` pairs for recon piping.
- **`rpt-html-merge.py`** — merge multiple Nessus HTML reports into a single consolidated report.

---

## `scope-extract.py`

Parses every host where Nessus plugin **22964 (Service Detection)** fired and writes a clean, deduped, sorted `ip:port` list — ready to pipe into nmap, httpx, nuclei, or any other recon step.

Handles both Nessus HTML layouts:
- **Vulnerabilities by Host** (host header → per-finding port)
- **Vulnerabilities by Plugin** (host + port embedded in the finding's `<h2>`)

Stdlib only. No `pip install` required.

### Usage

```bash
# folder (recursive — walks all .html / .htm files)
python3 scope-extract.py -f ./reports -o output.txt

# single HTML file
python3 scope-extract.py -ff ./scan.html -o output.txt

# include protocol (e.g. 10.0.0.1:445/tcp)
python3 scope-extract.py -f ./reports -o output.txt --with-proto
```

Arguments:

| flag | description |
|---|---|
| `-f`, `--folder` | Folder of Nessus HTML reports (searched recursively). |
| `-ff`, `--file` | Single Nessus HTML report. |
| `-o`, `--output` | Output file (one `ip:port` per line). |
| `--with-proto` | Append `/tcp` or `/udp` to each entry. |

`-f` and `-ff` are mutually exclusive; one is required.

### Example

```
$ python3 scope-extract.py -f ./reports -o scope.txt
reports/network-01.html: 12 service-detection entries
reports/network-02.html: 20 service-detection entries
reports/server-01.html: 45 service-detection entries
wrote 77 unique ip:port pairs to scope.txt

$ head -5 scope.txt
10.0.104.100:21
10.0.104.100:139
10.0.104.100:443
10.0.104.100:445
10.0.104.100:3389
```

Feed it straight into the next step:

```bash
nmap -sV -iL scope.txt
httpx -l scope.txt -title -tech-detect
```

### Output format

- One entry per line: `ip:port` (or `ip:port/proto` with `--with-proto`).
- Sorted by IP octets, then port.
- Deduped across all input files.
- Per-file counts go to **stderr**; the `ip:port` list goes to the file specified by `-o`.

### Notes & limitations

- Findings with port `0` (informational / host-level metadata) are skipped — they aren't real services.
- Nessus summary-only HTML exports (a plugins table with no port column anywhere in the file) contain no port information to extract. The script will report `0 service-detection entries` for those. Re-export the report with per-finding detail (the standard "Vulnerabilities by Host" or "by Plugin" layouts).
- Tested against the default Nessus HTML report templates. Custom templates may need a regex tweak.

---

## `rpt-html-merge.py`

Merge a folder of Nessus HTML reports into one consolidated HTML report. Plugins are deduped by plugin ID; hosts under each plugin are deduped by host header; the TOC and Suggested Remediations table are rebuilt to match.

What it does:

- **Dedupes plugin sections by plugin ID.** When the same plugin appears across multiple reports, host entries are merged into a single section and the `(N)` header count is recalculated.
- **Dedupes host entries** within a plugin by host header text (first occurrence wins).
- **Sorts plugins** by severity (critical → info), then by host count descending, then by plugin ID.
- **Rebuilds the "Vulnerabilities by Plugin" TOC** with fresh anchors and severity-colored bullets.
- **Merges the Suggested Remediations table**, deduping rows by "Action to take".
- **Renumbers all `idN` anchors** across the merged document so toggles, `href="#idN"` links, and `toggleSection()` calls all stay consistent.
- Uses the first report as the layout template (header, footer, styles).

### Usage

```bash
python3 rpt-html-merge.py -ff ./reports -o merged.html
python3 rpt-html-merge.py -ff ./reports -o merged.html --title "Q2 Internal Scan — Merged"
```

Arguments:

| flag | description |
|---|---|
| `-ff`, `--folder` | Folder containing `.html` Nessus reports (non-recursive, `*.html` only). |
| `-o`, `--output` | Output merged HTML file. |
| `--title` | Title for the merged report (default: `Merged Nessus Report`). |

### Example

```
$ python3 rpt-html-merge.py -ff ./reports -o merged.html
[+] Merging 3 reports from reports
    - network-01.html
    - network-02.html
    - server-01.html
[+] Wrote merged.html
    Plugins: 142
    Total host-vulnerability rows: 1,084
    Remediation actions: 37
```

Open `merged.html` in a browser — collapsible plugin sections, severity colors, and the remediations table behave exactly like the original Nessus export.

### Notes & limitations

- Input files must be Nessus HTML exports using the standard template (the one with `toggleSection(...)` collapsibles and the `Suggested Remediations` table). Custom templates may not parse.
- Folder scan is non-recursive and matches `*.html` only (`.htm` is skipped).
- The first report is used as the document shell — its banner, CSS, and surrounding metadata become the template; only the title and date subtitle are rewritten.
- Severity ordering is driven by the header background color in the source HTML. Unrecognized colors sort last.

## Requirements

- **`scope-extract.py`** — Python 3.7+, stdlib only.
- **`rpt-html-merge.py`** — Python 3.7+, plus `beautifulsoup4` and `lxml`:

```bash
pip install beautifulsoup4 lxml
```
