"""README contract: numbers, rule ids and install commands a visitor sees must
match what the package actually does."""

from __future__ import annotations

from pathlib import Path

from sshdguard.__about__ import __version__
from sshdguard.rules import REGISTRY

ROOT = Path(__file__).resolve().parent.parent


def test_readme_exists():
    assert (ROOT / "README.md").is_file()
    assert (ROOT / "README_CN.md").is_file()


def test_readme_rule_count_matches():
    for name in ("README.md", "README_CN.md"):
        body = (ROOT / name).read_text(encoding="utf-8")
        assert (
            f"{len(REGISTRY)} rules" in body or f"{len(REGISTRY)} 规则" in body or f"{len(REGISTRY)} 条规则" in body
        ), name


def test_readme_shows_highlight_rules():
    # The README highlights a representative subset; the full table lives in
    # docs/rules.md and is asserted separately.
    body = (ROOT / "README.md").read_text(encoding="utf-8")
    for rule_id in ("SHD001", "SHD018", "SHD019", "SHD050", "SHD072"):
        assert rule_id in body, rule_id


def test_readme_version_matches():
    body = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"pip install {__version__}" not in body  # never pin a version in install text
    assert __version__ in body  # badge carries the version


def test_readme_install_command_works_pre_pypi():
    # The package ships the git-clone + pip install . path first; both docs
    # must teach a command that works before PyPI registration.
    for name in ("README.md", "README_CN.md"):
        body = (ROOT / name).read_text(encoding="utf-8")
        assert "pip install ." in body, name


def test_readme_quickstart_is_three_steps():
    body = (ROOT / "README.md").read_text(encoding="utf-8")
    # the quickstart block must contain the three canonical invocations
    for command in ("sshdguard scan", "sshdguard demo", "sshdguard rules"):
        assert command in body, command


def test_rules_doc_exists_and_covers_table():
    doc = ROOT / "docs" / "rules.md"
    assert doc.is_file()
    body = doc.read_text(encoding="utf-8")
    for item in REGISTRY:
        assert item.id in body, f"{item.id} missing from docs/rules.md"


def test_rules_doc_counts_match():
    doc = ROOT / "docs" / "rules.md"
    body = doc.read_text(encoding="utf-8")
    assert f"{len(REGISTRY)} rules" in body
