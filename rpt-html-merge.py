#!/usr/bin/env python3
"""Merge multiple Nessus HTML reports into a single consolidated report.

Usage:
    python3 script.py -ff folder/ -o output.html
"""

import argparse
import os
import re
import sys
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from bs4 import BeautifulSoup, NavigableString, Tag

PLUGIN_HEADER_RE = re.compile(r"^\s*(\d+)\s*\((\d+)\)\s*-\s*(.+?)\s*$")
TOGGLE_RE = re.compile(r"toggleSection\('(id\d+-container)'\)")
SEVERITY_ORDER = {
    "#DD4B50": 0,  # critical (red)
    "#F18C43": 1,  # high (orange)
    "#F8C851": 2,  # medium (yellow)
    "#8b9a39": 3,  # low (green) - placeholder
    "#67ACE1": 4,  # info (blue)
}


def parse_header_text(div):
    """Return (plugin_id, count, title) from a plugin header div, or None."""
    # The header contains the title text plus a nested toggletext div with "+"/"-".
    # Strip the toggletext sibling for clean text.
    text_parts = []
    for child in div.children:
        if isinstance(child, NavigableString):
            text_parts.append(str(child))
        elif isinstance(child, Tag):
            cid = child.get("id", "")
            if cid.endswith("-toggletext"):
                continue
            text_parts.append(child.get_text())
    text = " ".join(text_parts).strip()
    m = PLUGIN_HEADER_RE.match(text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), m.group(3).strip()


def severity_key(header_div):
    """Return sort key for severity from header background color."""
    style = header_div.get("style", "") or ""
    m = re.search(r"background:\s*(#[0-9A-Fa-f]{6})", style)
    if not m:
        return 99
    return SEVERITY_ORDER.get(m.group(1).upper(), 99)


def severity_color(header_div):
    style = header_div.get("style", "") or ""
    m = re.search(r"background:\s*(#[0-9A-Fa-f]{6})", style)
    return m.group(1) if m else "#67ACE1"


def find_plugin_sections(soup):
    """Yield (header_div, container_div, plugin_id, count, title) for each plugin in soup."""
    for header in soup.find_all("div", onclick=TOGGLE_RE):
        parsed = parse_header_text(header)
        if not parsed:
            continue
        pid, count, title = parsed
        m = TOGGLE_RE.search(header.get("onclick", ""))
        if not m:
            continue
        container = soup.find("div", id=m.group(1))
        if container is None:
            continue
        yield header, container, pid, count, title


def extract_host_entries(container):
    """Return (pre_nodes, entries) where:
    - pre_nodes: nodes before first <h2> in the container (metadata: synopsis, refs, etc., including the "Plugin Output" header)
    - entries: list of (host_key, [nodes]) — one per host (h2 + following siblings until next h2 or end)
    """
    children = list(container.children)
    first_h2_idx = None
    for i, c in enumerate(children):
        if isinstance(c, Tag) and c.name == "h2":
            first_h2_idx = i
            break

    if first_h2_idx is None:
        return children, []

    pre = children[:first_h2_idx]
    entries = []
    cur_nodes = None
    cur_key = None
    for c in children[first_h2_idx:]:
        if isinstance(c, Tag) and c.name == "h2":
            if cur_nodes is not None:
                entries.append((cur_key, cur_nodes))
            cur_key = c.get_text(strip=True)
            cur_nodes = [c]
        else:
            if cur_nodes is not None:
                cur_nodes.append(c)
    if cur_nodes is not None:
        entries.append((cur_key, cur_nodes))

    return pre, entries


def find_remediation_table(soup):
    """Return the <div class='table-wrapper'> that wraps the Suggested Remediations table,
    or None. Identified by being the next table-wrapper after the 'Remediations' h6 and
    containing 'Action to take' in its table.
    """
    for h6 in soup.find_all("h6"):
        if h6.get_text(strip=True) == "Remediations":
            sib = h6
            while True:
                sib = sib.find_next("div", class_="table-wrapper")
                if sib is None:
                    return None
                tbl = sib.find("table")
                if tbl and "Action to take" in tbl.get_text(" ", strip=True):
                    return sib
            return None
    return None


def extract_remediation_rows(soup):
    """Return list of <tr class="plugin-row"> elements from the Suggested Remediations table."""
    wrapper = find_remediation_table(soup)
    if wrapper is None:
        return []
    tbl = wrapper.find("table")
    return tbl.find_all("tr", class_="plugin-row") if tbl else []


def main():
    p = argparse.ArgumentParser(description="Merge multiple Nessus HTML reports.")
    p.add_argument("-ff", "--folder", required=True, help="Folder containing .html Nessus reports")
    p.add_argument("-o", "--output", required=True, help="Output merged HTML file")
    p.add_argument("--title", default=None, help="Title for merged report (default: 'Merged Nessus Report')")
    args = p.parse_args()

    folder = Path(args.folder)
    if not folder.is_dir():
        sys.exit(f"Folder not found: {folder}")

    html_files = sorted(folder.rglob("*.html"))
    if not html_files:
        sys.exit(f"No .html files in {folder}")

    print(f"[+] Merging {len(html_files)} reports from {folder}", file=sys.stderr)
    for f in html_files:
        print(f"    - {f.name}", file=sys.stderr)

    # plugins[plugin_id] = {
    #   "header": Tag (copy of first header),
    #   "container": Tag (copy of first container, with host entries replaced),
    #   "pre_nodes": list (metadata nodes before first <h2>),
    #   "title": str,
    #   "host_entries": dict { host_key -> [nodes] },
    #   "host_order": [host_keys],
    #   "severity": int,
    #   "color": str,
    # }
    plugins = {}
    remediation_rows = []  # list of <tr> elements
    remediation_keys = set()
    remediation_template = None  # a deepcopy of a complete remediation table-wrapper div

    base_soup = None
    base_title = None
    base_date = None
    source_titles = []

    for idx, path in enumerate(html_files):
        with open(path, "rb") as f:
            soup = BeautifulSoup(f, "lxml")

        # Capture base info from first report
        if base_soup is None:
            base_soup = soup
            h3 = soup.find("h3")
            if h3:
                base_title = h3.get_text(strip=True)
            h4 = soup.find("h4")
            if h4:
                base_date = h4.get_text(strip=True)

        h3 = soup.find("h3")
        if h3:
            source_titles.append(h3.get_text(strip=True))
        else:
            source_titles.append(path.name)

        for header, container, pid, count, title in find_plugin_sections(soup):
            pre, entries = extract_host_entries(container)

            if pid not in plugins:
                plugins[pid] = {
                    "header": deepcopy(header),
                    "container": deepcopy(container),
                    "pre_nodes": [deepcopy(n) for n in pre],
                    "title": title,
                    "host_entries": {},
                    "host_order": [],
                    "severity": severity_key(header),
                    "color": severity_color(header),
                }

            for host_key, nodes in entries:
                if host_key in plugins[pid]["host_entries"]:
                    continue
                plugins[pid]["host_entries"][host_key] = [deepcopy(n) for n in nodes]
                plugins[pid]["host_order"].append(host_key)

        # Collect remediation rows and capture a wrapper template
        rem_wrapper = find_remediation_table(soup)
        if rem_wrapper is not None:
            if remediation_template is None:
                remediation_template = deepcopy(rem_wrapper)
            tbl = rem_wrapper.find("table")
            for tr in tbl.find_all("tr", class_="plugin-row"):
                cells = tr.find_all("td")
                action_text = cells[1].get_text(" ", strip=True) if len(cells) >= 2 else tr.get_text(" ", strip=True)
                if action_text in remediation_keys:
                    continue
                remediation_keys.add(action_text)
                remediation_rows.append(deepcopy(tr))

    # Now build the output document, using base_soup as the template
    out_soup = base_soup

    # Update title
    title_str = args.title or "Merged Nessus Report"
    if out_soup.title:
        out_soup.title.string = title_str
    h3 = out_soup.find("h3")
    if h3:
        h3.string = title_str
    h4 = out_soup.find("h4")
    if h4:
        h4.string = f"Merged from {len(html_files)} report(s) on {datetime.now().strftime('%a, %d %b %Y %H:%M:%S')}"

    # Sort plugins: severity asc (critical first), then host count desc, then pid asc
    sorted_pids = sorted(
        plugins.keys(),
        key=lambda pid: (plugins[pid]["severity"], -len(plugins[pid]["host_order"]), pid),
    )

    # Assign fresh sequential ids: id2..id(N+1) for plugin sections.
    # id1 is reserved for "Vulnerabilities by Plugin" h6 (already in template).
    # See-also/reference table ids inside each container also need uniqueness — we'll
    # offset them with a per-plugin prefix to avoid collisions.
    next_top_id = 2
    next_inner_id = 100_000  # high range to avoid collision with top ids

    finalized = []  # list of (new_header_id, new_header_div, new_container_div, plugin_info)

    for pid in sorted_pids:
        info = plugins[pid]
        new_id = f"id{next_top_id}"
        next_top_id += 1

        # Rebuild container: pre_nodes + all host entries in order
        new_container = deepcopy(info["container"])
        new_container.clear()
        # Update container's id attribute
        new_container["id"] = f"{new_id}-container"

        # Add pre_nodes (metadata)
        for n in info["pre_nodes"]:
            new_container.append(deepcopy(n))

        # Add host entries
        for host_key in info["host_order"]:
            for n in info["host_entries"][host_key]:
                new_container.append(deepcopy(n))

        # Rewrite header id and update count/text
        new_header = deepcopy(info["header"])
        new_header["id"] = new_id
        new_header["onclick"] = f"toggleSection('{new_id}-container')"

        # Update header text: "{pid} ({count}) - {title}"
        new_count = len(info["host_order"])
        new_text = f"{pid} ({new_count}) - {info['title']}"
        # Replace first text node, preserve nested toggletext div
        # Strategy: clear, add text, then re-add toggletext span
        toggletext = None
        for child in list(new_header.children):
            if isinstance(child, Tag) and child.get("id", "").endswith("-toggletext"):
                toggletext = deepcopy(child)
                toggletext["id"] = f"{new_id}-toggletext"
            child.extract()
        new_header.append(NavigableString(new_text))
        if toggletext is not None:
            new_header.append(toggletext)

        # Renumber inner ids in container (e.g., see-also tables with id="idM")
        inner_id_map = {}
        for el in new_container.find_all(id=re.compile(r"^id\d+$")):
            old = el["id"]
            if old not in inner_id_map:
                inner_id_map[old] = f"id{next_inner_id}"
                next_inner_id += 1
        # Apply mapping to container's element ids and href references
        for el in new_container.find_all(True):
            cid = el.get("id")
            if cid in inner_id_map:
                el["id"] = inner_id_map[cid]
            href = el.get("href")
            if href and href.startswith("#"):
                ref = href[1:]
                if ref in inner_id_map:
                    el["href"] = "#" + inner_id_map[ref]

        finalized.append((new_id, new_header, new_container, info, new_count, pid))

    # ---- Surgery on base_soup ----

    # 1) Remove existing plugin sections (everything between the h6#id1 "Vulnerabilities by Plugin"
    #    and the next h6 with id starting "id" that is NOT a plugin header, i.e., 'Compliance...').
    vuln_h6 = out_soup.find("h6", id="id1")
    if vuln_h6 is None:
        sys.exit("Could not locate 'Vulnerabilities by Plugin' h6#id1 in template.")

    # Find Compliance FAILED h6 (first h6 after id1 whose text starts with 'Compliance')
    compliance_h6 = None
    sib = vuln_h6.find_next_sibling()
    to_remove = []
    while sib is not None:
        if isinstance(sib, Tag) and sib.name == "h6" and sib.get_text(strip=True).startswith("Compliance"):
            compliance_h6 = sib
            break
        to_remove.append(sib)
        sib = sib.find_next_sibling()

    for node in to_remove:
        node.extract()

    # After removing plugin sections, renumber any remaining `idN` (except id1 which is
    # the 'Vulnerabilities by Plugin' h6 anchor) into a high range so the plugin ids we're
    # about to insert (id2..) don't collide with Compliance/Remediations h6 ids.
    template_id_map = {}
    next_template_id = 500_000
    for el in out_soup.find_all(id=re.compile(r"^id\d+(-container|-toggletext)?$")):
        cid = el["id"]
        m = re.match(r"^(id\d+)(-container|-toggletext)?$", cid)
        if not m:
            continue
        root = m.group(1)
        if root == "id1":
            continue
        if root not in template_id_map:
            template_id_map[root] = f"id{next_template_id}"
            next_template_id += 1
    # Apply mapping: ids + href references
    for el in out_soup.find_all(True):
        cid = el.get("id")
        if cid:
            m = re.match(r"^(id\d+)(-container|-toggletext)?$", cid)
            if m and m.group(1) in template_id_map:
                el["id"] = template_id_map[m.group(1)] + (m.group(2) or "")
        href = el.get("href")
        if href and href.startswith("#"):
            ref = href[1:]
            if ref in template_id_map:
                el["href"] = "#" + template_id_map[ref]
        oc = el.get("onclick")
        if oc:
            def _sub(match):
                root_full = match.group(1)
                root = root_full[:-len("-container")]
                return f"toggleSection('{template_id_map.get(root, root)}-container')"
            el["onclick"] = TOGGLE_RE.sub(_sub, oc)

    # Insert new plugin sections in order after vuln_h6
    insert_after = vuln_h6
    for new_id, new_header, new_container, info, new_count, pid in finalized:
        insert_after.insert_after(new_container)
        new_container.insert_before(new_header)
        insert_after = new_container

    # 2) Rebuild TOC under "Vulnerabilities by Plugin" link
    toc_link = out_soup.find("a", href="#id1")
    if toc_link is not None:
        parent_li = toc_link.find_parent("li")
        if parent_li is not None:
            inner_ul = parent_li.find("ul")
            if inner_ul is not None:
                inner_ul.clear()
                for new_id, new_header, new_container, info, new_count, pid in finalized:
                    li = out_soup.new_tag(
                        "li",
                        style=f"margin: 0 0 10px 0; color: {info['color']};",
                    )
                    a = out_soup.new_tag("a", href=f"#{new_id}")
                    a.string = f"{pid} ({new_count}) - {info['title']}"
                    li.append(a)
                    inner_ul.append(li)

    # 3) Update remediations table — find the existing wrapper or inject the template.
    remed_h6 = None
    for h6 in out_soup.find_all("h6"):
        if h6.get_text(strip=True) == "Remediations":
            remed_h6 = h6
            break

    if remed_h6 is not None and remediation_rows:
        existing_wrapper = find_remediation_table(out_soup)
        if existing_wrapper is None and remediation_template is not None:
            # Inject a fresh remediation block (summary div + table-wrapper) after the
            # Suggested Remediations div (which sits between remed_h6 and end).
            suggested_div = remed_h6.find_next(
                lambda t: isinstance(t, Tag) and t.name == "div"
                and t.get_text(strip=True).startswith("Suggested Remediations")
            )
            if suggested_div is not None:
                summary_div = out_soup.new_tag(
                    "div", style="line-height: 20px; padding: 0 0 20px 0;"
                )
                # Will be filled by the summary-update block below
                wrapper_clone = deepcopy(remediation_template)
                suggested_div.insert_after(wrapper_clone)
                wrapper_clone.insert_before(summary_div)
                existing_wrapper = wrapper_clone
                # Re-id the wrapper to avoid collision
                wrapper_clone["id"] = f"id{500_000 + 9999}"

        if existing_wrapper is not None:
            existing_table = existing_wrapper.find("table")
            tbody = existing_table.find("tbody") if existing_table else None
            if tbody is not None:
                for tr in tbody.find_all("tr", class_="plugin-row"):
                    tr.extract()
                for tr in remediation_rows:
                    tbody.append(tr)

            # Update the descriptive sentence directly above the wrapper.
            summary_div = existing_wrapper.find_previous(
                lambda t: isinstance(t, Tag) and t.name == "div"
                and (t.get_text(strip=True).startswith("Taking the following actions")
                     or t.get_text(strip=True) == "")
                and t is not existing_wrapper
            )
            if summary_div is not None:
                summary_div.clear()
                summary_div.append(NavigableString(
                    f"Merged remediation actions from {len(html_files)} report(s): {len(remediation_rows)} unique action(s)."
                ))
                clear = out_soup.new_tag("div", **{"class": "clear"})
                summary_div.append(clear)

    # 4) Write output
    out_path = Path(args.output)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(str(out_soup))

    print(f"[+] Wrote {out_path}", file=sys.stderr)
    print(f"    Plugins: {len(plugins)}", file=sys.stderr)
    total_hosts = sum(len(p['host_order']) for p in plugins.values())
    print(f"    Total host-vulnerability rows: {total_hosts}", file=sys.stderr)
    print(f"    Remediation actions: {len(remediation_rows)}", file=sys.stderr)


if __name__ == "__main__":
    main()
