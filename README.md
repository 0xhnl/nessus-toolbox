# nessus-scope-extract

Four utilities for working with Nessus reports:

- **`scope-extract.py`** — extract Service Detection `ip:port` pairs for recon piping.
- **`rpt-html-merge.py`** — merge multiple Nessus HTML reports into one consolidated report.
- **`auto-report.py`** — generate a styled `.docx` vulnerability report from a Nessus HTML report.
- **`csv-combine.py`** — combine Nessus CSV exports into a single deduped Excel workbook.

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

---

## `auto-report.py`

Generate a `.docx` vulnerability report from a single Nessus HTML report. Output mimics the in-house template under `doc-report/` — Montserrat Semi Bold headings, Lato body, Share Tech Mono code blocks. Findings are grouped into **Critical / High / Medium / Low Risk Findings**; Info is skipped.

For each finding the report emits:

- **Description** — synopsis sentence prepended to the plugin description.
- **Plugin Output** — first non-empty per-host output, rendered as a code block.
- **Affected Assets** — every host header from the source plugin, as code blocks.
- **Recommendation** — Nessus's Solution text, rewritten to start with "We recommend …" (imperative verb → gerund: `Upgrade` → `upgrading`, `Disable` → `disabling`, etc.).
- **Vulnerability Reference** — CVEs pulled from References / See Also, deduped and sorted by year then number.

Severity is taken from the plugin's **Risk Factor** field, falling back to the header background color (`#91243E` Critical, `#DD4B50` High, `#F18C43` Medium, `#F8C851` Low). Duplicate titles within the same severity bucket are dropped.

### Usage

```bash
python3 auto-report.py -f nessus-report.html -o output.docx

# override the styling template
python3 auto-report.py -f nessus-report.html -o output.docx \
    --template ./doc-report/custom-template.docx
```

Arguments:

| flag | description |
|---|---|
| `-f`, `--file` | Input Nessus HTML report. |
| `-o`, `--output` | Output `.docx` file. |
| `--template` | Template `.docx` used for fonts/styles (default: `doc-report/rpt.ysh-internal-assets-va-scan.20260610.docx`). |

### Example

```
$ python3 auto-report.py -f scan.html -o findings.docx
[+] Parsing scan.html
    Critical: 3 finding(s)
        High: 12 finding(s)
      Medium: 41 finding(s)
         Low: 7 finding(s)
       Total: 63 finding(s)
[+] Wrote findings.docx
```

### Notes & limitations

- The template `.docx` must define styles `Heading 1`–`Heading 4`, `Normal`, `List Paragraph`, and `k-code-block`, plus numbering `numId=10` (bullet list). The default template in `doc-report/` already does.
- Info-severity findings are skipped by design.
- One representative per-host plugin output is included per finding; if you need every host's raw output, parse from the source HTML directly.

---

## `csv-combine.py`

Combine multiple Nessus CSV exports into a single styled Excel workbook. Severity-tinted Risk cells, frozen header, auto-filter, an extra "Pentest Require" column (defaults to `No`, red bold) for triage tracking.

Modes:

- **default** — dedupe rows by `Host + Protocol + Port + Name`. CVEs from duplicate rows are merged and sorted.
- **`--no-dedupe`** — keep every row as-is.
- **`--depend-title`** — collapse rows sharing the same `Name`; `Host`, `Port`, and `Protocol` become comma-separated lists. Useful for a per-plugin overview.

Rows are sorted Critical → High → Medium → Low → Info, then by host, then port, then name.

### Usage

```bash
# default — dedupe by Host+Protocol+Port+Name
python3 csv-combine.py -ff ./reports -o findings.xlsx

# keep every raw row
python3 csv-combine.py -ff ./reports -o findings.xlsx --no-dedupe

# collapse to one row per plugin name
python3 csv-combine.py -ff ./reports -o findings.xlsx --depend-title
```

Arguments:

| flag | description |
|---|---|
| `-ff`, `--folder` | Folder containing `.csv` Nessus reports (searched recursively). |
| `-o`, `--output` | Output `.xlsx` file. |
| `--no-dedupe` | Keep every row (default is dedupe by Host+Protocol+Port+Name). |
| `--depend-title` | Collapse rows sharing the same Name; Host/Port/Protocol aggregated. |

`--no-dedupe` and `--depend-title` are mutually exclusive.

### Example

```
$ python3 csv-combine.py -ff ./reports -o findings.xlsx
[+] Reading 3 CSV file(s) from reports
    - network-01.csv: 412 row(s)
    - network-02.csv: 380 row(s)
    - server-01.csv: 297 row(s)
[+] Wrote findings.xlsx
    Total findings: 684
    Mode: default (deduped by Host+Protocol+Port+Name)
```

### Output columns

`CVE`, `Risk`, `Host`, `Protocol`, `Port`, `Name`, `Synopsis`, `Description`, `Solution`, `Risk Factor`, `Pentest Require`.

### Notes & limitations

- Column lookup is case- and whitespace-insensitive, but the source CSV must use Nessus's standard column names (`Host`, `Port`, `Risk`, etc.).
- Cell contents are capped at Excel's 32,767-character limit and suffixed `...[truncated]` if longer.
- `Risk Factor` falls back to a regex over the `Description` field when the column is missing.
- Rows with an empty `Host` are dropped.

---

## Requirements

- **`scope-extract.py`** — Python 3.7+, stdlib only.
- **`rpt-html-merge.py`** — Python 3.7+, plus `beautifulsoup4` and `lxml`.
- **`auto-report.py`** — Python 3.7+, plus `beautifulsoup4`, `lxml`, and `python-docx`.
- **`csv-combine.py`** — Python 3.7+, plus `openpyxl`.

```bash
pip install beautifulsoup4 lxml python-docx openpyxl
```

## License

MIT
