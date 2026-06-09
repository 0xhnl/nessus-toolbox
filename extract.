#!/usr/bin/env python3
"""Extract Service Detection <ip>:<port> pairs from Nessus HTML reports."""

import argparse
import re
import sys
from pathlib import Path

HOST_HEADER_RE = re.compile(
    r'<div[^>]*font-size:\s*22px[^>]*font-weight:\s*700[^>]*>([^<]+?)<div',
    re.IGNORECASE,
)
FINDING_HEADER_RE = re.compile(
    r'<div[^>]*font-weight:\s*700;\s*font-size:\s*14px[^>]*>\s*(\d+)(?:\s*\(\d+\))?\s*-\s*([^<]+?)<div',
    re.IGNORECASE,
)
# "by Host" format: <h2>tcp/22/ssh</h2> — port only, host comes from host header
H2_PORT_RE = re.compile(r'<h2>\s*(tcp|udp)\s*/\s*(\d+)', re.IGNORECASE)
# "by Plugin" format: <h2>172.16.10.49 (tcp/22/ssh)</h2> — host + port embedded
H2_HOST_PORT_RE = re.compile(
    r'<h2>\s*([^\s<()]+)\s*\(\s*(tcp|udp)\s*/\s*(\d+)',
    re.IGNORECASE,
)


def extract_pairs(html: str):
    pairs = set()
    hosts = list(HOST_HEADER_RE.finditer(html))
    findings = list(FINDING_HEADER_RE.finditer(html))
    if not hosts or not findings:
        return pairs

    host_starts = [h.start() for h in hosts]

    def host_for(pos: int):
        ip = None
        for h, start in zip(hosts, host_starts):
            if start <= pos:
                ip = h.group(1).strip()
            else:
                break
        return ip

    for i, fm in enumerate(findings):
        name = fm.group(2).strip()
        if "Service Detection" not in name:
            continue
        end = findings[i + 1].start() if i + 1 < len(findings) else len(html)
        section = html[fm.end():end]

        host_port_hits = list(H2_HOST_PORT_RE.finditer(section))
        if host_port_hits:
            for m in host_port_hits:
                ip = m.group(1).strip()
                proto = m.group(2).lower()
                port = m.group(3)
                if port == "0":
                    continue
                pairs.add((ip, int(port), proto))
        else:
            ip = host_for(fm.start())
            if not ip:
                continue
            for m in H2_PORT_RE.finditer(section):
                proto, port = m.group(1).lower(), m.group(2)
                if port == "0":
                    continue
                pairs.add((ip, int(port), proto))
    return pairs


def main():
    p = argparse.ArgumentParser(description="Extract Service Detection ip:port pairs from Nessus HTML reports.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-f", "--folder", help="Folder containing Nessus HTML reports (recursive)")
    src.add_argument("-ff", "--file", help="Single Nessus HTML report")
    p.add_argument("-o", "--output", required=True, help="Output file (one ip:port per line)")
    p.add_argument("--with-proto", action="store_true", help="Append /tcp or /udp to each entry")
    args = p.parse_args()

    if args.file:
        fp = Path(args.file)
        if not fp.is_file():
            print(f"error: not a file: {fp}", file=sys.stderr)
            sys.exit(1)
        html_files = [fp]
    else:
        folder = Path(args.folder)
        if not folder.is_dir():
            print(f"error: not a directory: {folder}", file=sys.stderr)
            sys.exit(1)
        html_files = sorted(folder.rglob("*.html")) + sorted(folder.rglob("*.htm"))
        if not html_files:
            print(f"error: no .html files under {folder}", file=sys.stderr)
            sys.exit(1)

    all_pairs = set()
    for fp in html_files:
        try:
            html = fp.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"warn: cannot read {fp}: {e}", file=sys.stderr)
            continue
        found = extract_pairs(html)
        all_pairs.update(found)
        print(f"{fp}: {len(found)} service-detection entries", file=sys.stderr)

    def sort_key(t):
        ip, port, proto = t
        octets = ip.split(".")
        if len(octets) == 4 and all(o.isdigit() for o in octets):
            return (0, tuple(int(o) for o in octets), port, proto)
        return (1, ip, port, proto)

    out_path = Path(args.output)
    with out_path.open("w", encoding="utf-8") as f:
        for ip, port, proto in sorted(all_pairs, key=sort_key):
            if args.with_proto:
                f.write(f"{ip}:{port}/{proto}\n")
            else:
                f.write(f"{ip}:{port}\n")

    print(f"wrote {len(all_pairs)} unique ip:port pairs to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
