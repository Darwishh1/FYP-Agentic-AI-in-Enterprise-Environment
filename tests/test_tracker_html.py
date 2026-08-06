"""'build tracker.html' is the build tracker. There is no source file above it.

Replaces test_tracker_sync.py, which guarded the JSX-to-HTML generator. The JSX and
the generator were deleted: two hand-maintained copies of the same board is what let
it drift four days out of date, and deleting one copy removes that whole class of
problem rather than testing around it.

What still needs guarding is the file's ability to open standalone. Everything above
the SEED_DATA banner — the inlined React, Babel and Tailwind, the localStorage shim,
the hand-rolled icons, the mount point — has no equivalent anywhere else in the repo.
Lose any of it and the page renders blank in a browser, with nothing failing loudly
here to say why. These tests are cheap; a blank tracker in front of a supervisor is
not.
"""
import re
from pathlib import Path

import pytest

HTML = Path(__file__).resolve().parent.parent / "build tracker.html"


@pytest.fixture(scope="module")
def html():
    return HTML.read_text(encoding="utf-8")


def test_the_tracker_exists():
    assert HTML.exists(), "build tracker.html is the board; nothing regenerates it"


@pytest.mark.parametrize("marker, why", [
    ('<div id="root">',            "React mount point"),
    ("ReactDOM.createRoot(",       "app is actually mounted"),
    ("localStorage.getItem",       "storage shim the board persists through"),
    ("localStorage.setItem",       "storage shim write path"),
    ("function mkIcon(",           "inline SVG icons replacing lucide-react"),
    ('<script type="text/babel">', "JSX is compiled in-page"),
    ("<title>",                    "browser tab identity"),
])
def test_standalone_shell_intact(html, marker, why):
    assert marker in html, f"offline shell broken — missing {why}: {marker!r}"


def test_no_external_requests(html):
    """It must work with no network. A CDN link would fail silently offline."""
    for pattern in ("https://cdn", "http://cdn", "src=\"http", "href=\"http"):
        assert pattern not in html, f"external reference found: {pattern!r}"


def test_no_module_syntax(html):
    """A <script type='text/babel'> block is not a module. An import or a bare
    `export default` fails at runtime as a blank page plus a console error."""
    assert "export default function" not in html
    assert 'from "lucide-react"' not in html
    assert "import React" not in html


def test_board_data_is_present_and_readable(html):
    """SEED_DATA must stay plain source. If a build step ever minifies it, the file
    stops being hand-editable and the reason for deleting the JSX evaporates."""
    assert "const SEED_DATA = {" in html
    for key in ("phases:", "counters:", "hygiene:", "seedVersion:"):
        assert key in html, f"SEED_DATA lost its {key} block"


def test_seed_version_is_an_integer(html):
    m = re.search(r"seedVersion:\s*(\d+)", html)
    assert m, "seedVersion missing — edits will not reach an already-saved board"
    assert int(m.group(1)) >= 1


def test_merge_on_hydrate_is_still_wired(html):
    """Without this a browser with a saved board silently ignores every seed edit,
    which is the single most confusing failure this file has.

    Matched on the definition and the call, not the bare name: a plain substring
    check still passed when mergeBoard was renamed to mergeBoardX.
    """
    for fn in ("mergeBoard", "mergeTasks"):
        assert re.search(rf"const {fn}\s*=", html), f"{fn} definition missing"
    assert re.search(r"\bmergeBoard\(SEED_DATA", html), "mergeBoard defined but never called"


def test_no_instructions_to_use_the_deleted_generator(html):
    """Stale instructions to run or edit a file that no longer exists are worse than
    none. Naming those files while explaining why they were removed is fine and is
    deliberately still allowed — an earlier version of this test banned the strings
    outright and failed on its own changelog.
    """
    for instruction in (
        "python build_tracker_html.py",
        "run build_tracker_html",
        "Edit this file, never",
        "generated from here",
    ):
        assert instruction not in html, f"stale instruction left behind: {instruction!r}"


def test_no_leftover_generator_files():
    root = HTML.parent
    for gone in ("fyp_build_tracker.jsx", "build_tracker_html.py", "tests/test_tracker_sync.py"):
        assert not (root / gone).exists(), f"{gone} was meant to be deleted"
