# nessus-scope-extract

Extract Service Detection `ip:port` pairs from Nessus HTML reports.

Parses every host where Nessus plugin **22964 (Service Detection)** fired and writes a clean, deduped, sorted `ip:port` list — ready to pipe into nmap, httpx, nuclei, or any other recon step.

Handles both Nessus HTML layouts:
- **Vulnerabilities by Host** (host header → per-finding port)
- **Vulnerabilities by Plugin** (host + port embedded in the finding's `<h2>`)

Stdlib only. No `pip install` required.

## Usage

```bash
# folder (recursive — walks all .html / .htm files)
python3 script.py -f ./reports -o output.txt

# single HTML file
python3 script.py -ff ./scan.html -o output.txt

# include protocol (e.g. 10.0.0.1:445/tcp)
python3 script.py -f ./reports -o output.txt --with-proto
```

Arguments:

| flag | description |
|---|---|
| `-f`, `--folder` | Folder of Nessus HTML reports (searched recursively). |
| `-ff`, `--file` | Single Nessus HTML report. |
| `-o`, `--output` | Output file (one `ip:port` per line). |
| `--with-proto` | Append `/tcp` or `/udp` to each entry. |

`-f` and `-ff` are mutually exclusive; one is required.

## Example

```
$ python3 script.py -f ./reports -o scope.txt
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

## Output format

- One entry per line: `ip:port` (or `ip:port/proto` with `--with-proto`).
- Sorted by IP octets, then port.
- Deduped across all input files.
- Per-file counts go to **stderr**; the `ip:port` list goes to the file specified by `-o`.

## Notes & limitations

- Findings with port `0` (informational / host-level metadata) are skipped — they aren't real services.
- Nessus summary-only HTML exports (a plugins table with no port column anywhere in the file) contain no port information to extract. The script will report `0 service-detection entries` for those. Re-export the report with per-finding detail (the standard "Vulnerabilities by Host" or "by Plugin" layouts).
- Tested against the default Nessus HTML report templates. Custom templates may need a regex tweak.

## Requirements

- Python 3.7+
- No third-party dependencies

