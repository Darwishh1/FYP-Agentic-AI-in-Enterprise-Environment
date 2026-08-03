"""The two build trackers must not drift apart.

'build tracker.html' embeds a copy of the fyp_build_tracker.jsx app. They were
hand-maintained in parallel, which is how the JSX ended up describing a repo state
that was already two commits old on the day it was committed. The HTML is now
generated from the JSX by build_tracker_html.py, and this test is what stops someone
editing the HTML directly and quietly re-forking them.

If this fails, do not edit the HTML. Edit the JSX, then run:
    python build_tracker_html.py
"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
JSX = ROOT / "fyp_build_tracker.jsx"
HTML = ROOT / "build tracker.html"
BUILDER = ROOT / "build_tracker_html.py"


def test_html_is_up_to_date_with_the_jsx():
    proc = subprocess.run(
        [sys.executable, str(BUILDER), "--check"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, (
        f"'build tracker.html' is stale against the JSX.\n"
        f"{proc.stdout}{proc.stderr}\n"
        f"Fix: edit fyp_build_tracker.jsx, then run `python build_tracker_html.py`."
    )


def test_generator_is_idempotent(tmp_path):
    """Running the build twice must not keep changing the file.

    Catches the line-ending bug this generator already had once: Python's default
    write translated '\\n' to CRLF, so every run rewrote all 2300 lines.
    """
    before = HTML.read_bytes()
    subprocess.run([sys.executable, str(BUILDER)], cwd=ROOT, capture_output=True, text=True, check=True)
    assert HTML.read_bytes() == before, "regeneration changed the file despite --check being clean"


def test_html_keeps_its_standalone_shell():
    """The generator must only replace the app payload.

    Everything that makes the HTML work offline lives above the SEED_DATA banner and
    has no equivalent in the JSX, so a generator that overwrote it would produce a
    blank page rather than an obvious error.
    """
    html = HTML.read_text(encoding="utf-8")
    for marker in (
        "<title>FYP Build Tracker",
        "localStorage.getItem",       # the window.storage shim
        "function mkIcon(",           # inline SVG icons replacing lucide-react
        'ReactDOM.createRoot(',       # mount
        '<div id="root">',
    ):
        assert marker in html, f"standalone shell lost: {marker!r}"


def test_html_has_no_bare_module_syntax():
    """A <script type='text/babel'> block is not a module — an import or a bare
    `export default` would fail at runtime with a blank page and a console error."""
    html = HTML.read_text(encoding="utf-8")
    assert "export default function FypBuildTracker" not in html
    assert 'from "lucide-react"' not in html
    assert 'import React' not in html


@pytest.mark.parametrize("marker", ["seedVersion", "mergeBoard", "mergeTasks", "pinned"])
def test_recent_app_logic_reached_the_html(marker):
    """Cheap canary that the payload really is the current JSX, not a stale copy."""
    assert marker in HTML.read_text(encoding="utf-8")


def test_seed_version_matches_between_the_two_files():
    import re

    def seed_version(path):
        m = re.search(r"seedVersion:\s*(\d+)", path.read_text(encoding="utf-8"))
        assert m, f"no seedVersion in {path.name}"
        return int(m.group(1))

    assert seed_version(JSX) == seed_version(HTML)
