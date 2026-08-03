"""Regenerate 'build tracker.html' from fyp_build_tracker.jsx.

    python build_tracker_html.py           # rewrite the HTML from the JSX
    python build_tracker_html.py --check    # exit 1 if it is out of date

WHY
There were two copies of the board: the JSX, and a standalone HTML build with the
same app pasted inside a <script type="text/babel"> block. Two hand-edited copies of
the same seed data drift, and a tracker that disagrees with itself is worse than no
tracker — the first commit of the JSX was already stale against the repo it described.

So the JSX is the single source of truth and the HTML is generated, the same rule
already applied to graph.py versus its re-export shims (tracker p0-2).

WHAT THE HTML SHELL PROVIDES, and why the JSX cannot just be dropped in verbatim:
  - React, ReactDOM, Babel and Tailwind, inlined so the file works offline
  - a window.storage shim over localStorage, matching the async artifact API
  - inline SVG icons standing in for lucide-react
Everything above the SEED_DATA banner in the HTML is that shell and is preserved.
Only the app payload is replaced.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

SRC = pathlib.Path("fyp_build_tracker.jsx")
DST = pathlib.Path("build tracker.html")

#: Marks the first line of the app payload in BOTH files.
BANNER = "   SEED_DATA — hand-editable. Every task label is plain text only."
#: First line of the HTML tail that must survive regeneration.
TAIL_ANCHOR = 'const rootEl = document.getElementById("root");'

#: Deliberate differences between the module and the standalone page.
#: Keep this list short and explicit — every entry is a place the two can diverge.
TRANSFORMS = [
    # The page has no bundler, so the component is a plain declaration.
    ("export default function FypBuildTracker", "function FypBuildTracker"),
    # The page's Tailwind build drops the deprecated bg-opacity-* utilities.
    ("bg-neutral-950 bg-opacity-80", "bg-neutral-950/80"),
]


def payload_start(lines: list[str]) -> int:
    """Index of the '/* ====' line that opens the SEED_DATA banner comment."""
    for i, line in enumerate(lines):
        if line.rstrip() == BANNER.rstrip():
            if i == 0 or not lines[i - 1].startswith("/* ="):
                raise SystemExit(f"SEED_DATA banner at line {i + 1} is not opened by a /* === comment")
            return i - 1
    raise SystemExit(f"could not find the SEED_DATA banner line: {BANNER!r}")


def build() -> str:
    src_lines = SRC.read_text(encoding="utf-8").splitlines()
    dst_lines = DST.read_text(encoding="utf-8").splitlines()

    payload = "\n".join(src_lines[payload_start(src_lines):])
    for old, new in TRANSFORMS:
        if old not in payload:
            raise SystemExit(f"transform target vanished from the JSX: {old!r}")
        payload = payload.replace(old, new)

    head = dst_lines[:payload_start(dst_lines)]

    tail_at = next((i for i, l in enumerate(dst_lines) if l.strip() == TAIL_ANCHOR), None)
    if tail_at is None:
        raise SystemExit(f"could not find the HTML tail anchor: {TAIL_ANCHOR!r}")
    tail = dst_lines[tail_at:]

    return "\n".join(head) + "\n" + payload + "\n\n" + "\n".join(tail) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 if the HTML is out of date")
    args = ap.parse_args()

    if not SRC.exists() or not DST.exists():
        raise SystemExit(f"run from the project root; expected {SRC} and {DST}")

    generated = build()
    current = DST.read_text(encoding="utf-8")

    if generated == current:
        print(f"{DST} is up to date with {SRC}.")
        return

    if args.check:
        print(f"{DST} is STALE against {SRC}. Run: python {pathlib.Path(__file__).name}")
        sys.exit(1)

    # newline="" writes the "\n" in `generated` literally. Without it Python
    # translates to os.linesep, which on Windows rewrites all ~2300 lines to CRLF and
    # turns every regeneration into a whole-file diff.
    with DST.open("w", encoding="utf-8", newline="") as fh:
        fh.write(generated)
    print(f"Regenerated {DST} from {SRC}.")


if __name__ == "__main__":
    main()
