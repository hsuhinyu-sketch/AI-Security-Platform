#!/usr/bin/env python3
"""Check documentation roles, inventory, JSON syntax and local file links."""

import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
INDEX = DOCS / "documentation-index.md"
START = "<!-- DOC-INDEX:START -->"
END = "<!-- DOC-INDEX:END -->"
ROLES = {
    "entrypoint", "handoff", "active-plan", "reference", "gate", "changelog",
    "implementation-record", "historical-plan", "historical-record",
    "vendor-reference", "index",
}
AUTHORITIES = {
    "entrypoint": DOCS / "README.md",
    "handoff": DOCS / "HANDOFF.md",
    "active-plan": DOCS / "architecture/componentization-plan.md",
    "gate": DOCS / "architecture/production-stability-risks.md",
    "index": INDEX,
}
ROLE = re.compile(r"<!-- doc-role: ([a-z-]+) -->")
LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+[\"'][^\n]*[\"'])?\s*\)")
REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>\n]+>|\S+)")
FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")


def local_links(content):
    """Yield inline/reference targets outside fenced code blocks."""
    fence = None
    for number, line in enumerate(content.splitlines(), 1):
        match = FENCE.match(line)
        if match:
            marker, tail = match.groups()
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence) and not tail.strip():
                fence = None
            continue
        if fence is not None:
            continue
        targets = [match.group(1) for match in LINK.finditer(line)]
        reference = REFERENCE.match(line)
        if reference:
            targets.append(reference.group(1))
        for target in targets:
            target = target.removeprefix("<").removesuffix(">")
            url = urlsplit(target)
            if not url.scheme and not url.netloc and url.path and not url.path.startswith("/"):
                yield number, unquote(url.path)


def inventory():
    entries, errors = [], []
    for path in sorted(DOCS.rglob("*")):
        if path.suffix not in {".md", ".json"} or not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            try:
                json.loads(content)
            except ValueError as error:
                errors.append(f"{path.relative_to(ROOT)}: invalid JSON: {error}")
            role, title = "evidence-snapshot", path.stem
        else:
            markers = ROLE.findall(content)
            if len(markers) != 1 or markers[0] not in ROLES:
                errors.append(f"{path.relative_to(ROOT)}: expected one valid doc-role marker")
            role = markers[0] if markers else "unknown"
            title = next((line[2:].strip() for line in content.splitlines() if line.startswith("# ")), path.stem)
        entries.append((path, title, role))
        archived = path.is_relative_to(DOCS / "archive")
        if role in {"historical-plan", "historical-record"} and not archived:
            errors.append(f"{path.relative_to(ROOT)}: historical documents belong in docs/archive/")
        if archived and role not in {"historical-plan", "historical-record", "implementation-record", "evidence-snapshot"}:
            errors.append(f"{path.relative_to(ROOT)}: current references/entrypoints must stay outside archive")
    for role, expected in AUTHORITIES.items():
        owners = [path for path, _, actual_role in entries if actual_role == role]
        if owners != [expected]:
            errors.append(f"{role}: expected sole owner {expected.relative_to(ROOT)}")
    return entries, errors


def index_block(entries):
    counts = Counter(role for _, _, role in entries)
    markdown = sum(path.suffix == ".md" for path, _, _ in entries)
    lines = [START, "", f"共 {markdown} 份 Markdown、{len(entries) - markdown} 份 JSON 证据。", ""]
    lines += [f"角色统计：{'；'.join(f'{role} {count}' for role, count in sorted(counts.items()))}。", ""]
    groups = {
        "现行文档与最近验收": [],
        "第三方参考": [],
        "历史归档（按需查证）": [],
    }
    for entry in entries:
        path = entry[0]
        group = "历史归档（按需查证）" if path.is_relative_to(DOCS / "archive") else (
            "第三方参考" if path.is_relative_to(DOCS / "third-party") else "现行文档与最近验收"
        )
        groups[group].append(entry)
    for group, items in groups.items():
        lines += [f"### {group}（{len(items)}）", ""]
        if group.startswith("历史归档"):
            lines += ["<details>", "<summary>展开旧方案、实施报告及验证证据</summary>", ""]
        lines += ["| 文件 | 类型 | 标题/证据名称 |", "| --- | --- | --- |"]
        for path, title, role in items:
            relative = path.relative_to(DOCS).as_posix()
            safe_title = title.replace("|", "\\|")
            lines.append(f"| [{relative}]({relative}) | {role} | {safe_title} |")
        lines += [""]
        if group.startswith("历史归档"):
            lines += ["</details>", ""]
    lines += ["", END]
    return "\n".join(lines)


def check_public():
    """Check only Git's prospective source docs, including a fresh clone without local records."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "docs"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    paths = sorted({ROOT / name for name in result.stdout.split("\0") if name})
    available = {path.resolve() for path in paths if path.is_file()}
    errors, links = [], 0
    for name in ("README.md", "architecture/README.md", "reference/configuration-guide.md", "release/README.md"):
        if (DOCS / name).resolve() not in available:
            errors.append(f"missing public documentation: docs/{name}")
    for path in paths:
        if not path.is_file():
            continue
        if path.suffix != ".md":
            errors.append(f"{path.relative_to(ROOT)}: public docs must be Markdown; keep evidence local")
            continue
        content = path.read_text(encoding="utf-8")
        markers = ROLE.findall(content)
        if len(markers) != 1 or markers[0] not in {"entrypoint", "reference", "vendor-reference", "changelog"}:
            errors.append(f"{path.relative_to(ROOT)}: expected a public documentation role")
        for number, target in local_links(content):
            links += 1
            destination = (path.parent / target).resolve()
            if not destination.exists():
                errors.append(f"{path.relative_to(ROOT)}:{number}: missing target {target}")
            elif destination.is_relative_to(DOCS) and destination not in available:
                errors.append(f"{path.relative_to(ROOT)}:{number}: target is local-only and will not be uploaded: {target}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"PASS: {len(available)} public documentation files; {links} local links; no private-document dependencies")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-index", action="store_true", help="Refresh the generated inventory only")
    parser.add_argument("--public", action="store_true", help="Check documents selected by Git, without local handoff/reports")
    args = parser.parse_args()
    if args.public or not (INDEX.is_file() and (DOCS / "HANDOFF.md").is_file()):
        if args.write_index:
            parser.error("--write-index requires the local documentation inventory")
        return check_public()
    entries, errors = inventory()
    content = INDEX.read_text(encoding="utf-8")
    if content.count(START) != 1 or content.count(END) != 1 or content.index(START) > content.index(END):
        errors.append("docs/documentation-index.md: expected one ordered inventory block")
    else:
        start, end = content.index(START), content.index(END) + len(END)
        expected = index_block(entries)
        if args.write_index and not errors:
            INDEX.write_text(content[:start] + expected + content[end:], encoding="utf-8")
        elif content[start:end] != expected:
            errors.append("documentation inventory is stale; run with --write-index")

    links = 0
    paths = [path for path, _, _ in entries if path.suffix == ".md"] + [ROOT / "AGENTS.md"]
    for path in paths:
        if not path.is_file():
            errors.append(f"missing handoff file: {path.relative_to(ROOT)}")
            continue
        for number, target in local_links(path.read_text(encoding="utf-8")):
            links += 1
            if not (path.parent / target).exists():
                errors.append(f"{path.relative_to(ROOT)}:{number}: missing target {target}")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8") if (ROOT / "AGENTS.md").is_file() else ""
    for target in ("docs/README.md", "docs/HANDOFF.md"):
        if target not in {target for _, target in local_links(agents)}:
            errors.append(f"AGENTS.md: missing entry link to {target}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"PASS: {len(entries)} documentation files inventoried; roles/JSON valid; {links} local file links checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
