#!/usr/bin/env python3
"""Render model.json as Markdown.

pytm 1.4.0's own `--report` templating (model.py --report <template.md>) breaks on
this Python/pytm combination: its `{value:repeat:template}` custom format spec relies
on a nested field (e.g. `{item.name}`) inside the format spec, but the standard
library's string.Formatter tries to resolve that nested field itself, against the
*outer* scope, before pytm's code ever sees it -- so it fails with `KeyError: 'item'`
on the simplest possible repeat template, not just this one. That is a pytm bug, not
something to work around inside model.py. This script reads pytm's `--json` output
instead (a stable, documented interface) and formats it directly, so the summary does
not depend on the broken piece.

Usage:
    python3 model.py --json model.json
    python3 summarize.py model.json > threat-model-summary.md
"""

import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <model.json>", file=sys.stderr)
        return 2

    with open(sys.argv[1]) as f:
        model = json.load(f)

    print(f"# {model['name']} threat model\n")
    print(model.get("description", "").strip() + "\n")

    print("## Elements\n")
    for e in model["elements"]:
        desc = f" -- {e['description']}" if e.get("description") else ""
        print(f"- **{e['name']}**{desc}")
    print()

    print("## Dataflows\n")
    print(
        "Each dataflow's note cites the Go source and, where one exists, the "
        "regression test backing its current control flags.\n"
    )
    for d in model["flows"]:
        print(f"### {d['name']}\n")
        print(f"- protocol: {d.get('protocol') or 'n/a'}")
        active = sorted(k for k, v in (d.get("controls") or {}).items() if v is True)
        print(f"- controls: {', '.join(active) if active else '(none set)'}")
        print()
        if d.get("note"):
            print(d["note"] + "\n")

    findings = model.get("findings", [])
    print(f"## Findings from pytm's built-in threat library ({len(findings)})\n")
    print(
        "pytm's bundled threat library is a generic, largely web-application-oriented "
        "catalog, not scoped to this architecture, so most matches below are not real "
        "findings for bladedr. Read this list with that in mind; the dataflow notes "
        "above (written against this codebase specifically) are the authoritative "
        "record of what was reviewed and fixed. A match is worth a second look only "
        "if its target is one of the dataflows this model defines and its description "
        "plausibly applies to an SSH-based agentless scanner rather than a web app.\n"
    )
    for finding in findings:
        print(
            f"- **[{finding.get('threat_id')}] {finding.get('description')}** "
            f"(target: {finding.get('target')}, severity: {finding.get('severity')})"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
