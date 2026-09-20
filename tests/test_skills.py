"""The skills are documentation, but three things about them are checkable:
the frontmatter a harness needs, that no cross-reference points at a file
that no longer exists, and that the selector taxonomy in the pivoting skill
still matches the code it describes.

The last is the one that matters. A skill is read by an agent on every
invocation, and a stale taxonomy would have it arguing with a rule that has
already run in code.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SKILLS = sorted((REPO / "skills").glob("*/SKILL.md"))


def _frontmatter(path: pathlib.Path) -> dict[str, str]:
    text = path.read_text()
    assert text.startswith("---\n"), f"{path} has no frontmatter"
    block = text.split("---\n")[1]
    return dict(re.findall(r"^(\w+):\s*(.+)$", block, re.MULTILINE))


def test_there_are_skills_to_check():
    assert SKILLS, "no skills found - the glob or the layout changed"


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_every_skill_declares_a_name_matching_its_directory(path):
    assert _frontmatter(path)["name"] == path.parent.name


@pytest.mark.parametrize("path", SKILLS, ids=lambda p: p.parent.name)
def test_every_skill_describes_when_to_use_it(path):
    """The description is what a harness matches on; a vague one means the
    skill is either never loaded or always loaded."""
    description = _frontmatter(path)["description"]
    assert len(description) > 120, "too short to route on"
    assert description.lower().startswith("use when")


# --------------------------------------------------------------------------- #
# The split left no dangling pointers
# --------------------------------------------------------------------------- #

def _repo_text_files():
    for pattern in ("skills/*/SKILL.md", "docs/*.md", "scripts/*.py",
                    "setup.sh", "README.md"):
        yield from REPO.glob(pattern)


def test_nothing_still_points_at_the_retired_skill():
    """threat-cluster-tracking was split into cluster-bookkeeping,
    infrastructure-pivoting and docs/probe-vm.md.

    Path-shaped references only. Naming the old skill in prose is history -
    both this repo's setup.sh and its probe-VM doc do, to explain where
    something came from - while `skills/threat-cluster-tracking/` is a
    pointer at a directory that no longer exists.
    """
    offenders = []
    for path in _repo_text_files():
        for ref in re.findall(r"skills/threat-cluster-tracking[\w./-]*",
                              path.read_text()):
            if not (REPO / ref).exists():
                offenders.append(f"{path.relative_to(REPO)} -> {ref}")
    assert offenders == []


def test_every_referenced_skill_and_doc_exists():
    """`skills/x/` and `docs/y.md` in prose must resolve."""
    missing = []
    for path in _repo_text_files():
        for ref in re.findall(r"`(skills/[\w-]+/(?:SKILL\.md)?|docs/[\w.-]+\.md)`",
                              path.read_text()):
            if not (REPO / ref).exists():
                missing.append(f"{path.relative_to(REPO)} -> {ref}")
    assert missing == []


# --------------------------------------------------------------------------- #
# The generated taxonomy
# --------------------------------------------------------------------------- #

PIVOTING = REPO / "skills" / "infrastructure-pivoting" / "SKILL.md"


def test_the_taxonomy_block_is_in_sync_with_the_code():
    """Run scripts/render_selector_skill.py if this fails.

    whois.registrar moved structural -> behavioural and http.body_sha256
    grew a status condition while this skill was being written. A
    hand-maintained copy would already be wrong.
    """
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "render_selector_skill.py"),
         "--check"], capture_output=True, text=True, cwd=REPO)
    assert result.returncode == 0, result.stderr or result.stdout


def test_every_promoting_selector_type_is_documented():
    from cti.store.selectors import TYPES
    text = PIVOTING.read_text()
    for name, spec in TYPES.items():
        if spec.cls in ("identity", "structural"):
            assert f"`{name}`" in text, f"{name} can promote but is undocumented"


def test_the_generated_block_is_marked_as_generated():
    """So nobody edits it by hand and loses the edit on the next render."""
    text = PIVOTING.read_text()
    block = text[text.index("<!-- BEGIN GENERATED TAXONOMY -->"):]
    assert "Do not edit by hand" in block


def test_the_corroboration_rule_in_the_skill_matches_the_code():
    """The skill states the rule in prose; expand.py implements it. If the
    implementation's independence test changes, this prose is a lie."""
    import inspect

    from cti.store import expand
    source = inspect.getsource(expand)
    # independence is by TYPE, which is the part most likely to be softened
    assert 'independent = {t for t, _ in slot["structural"]}' in source
    text = PIVOTING.read_text()
    assert "different types" in text or "*different types*" in text
    assert "two sans off one certificate are one fact" in text.lower()


# --------------------------------------------------------------------------- #
# The split actually removed the duplication it was for
# --------------------------------------------------------------------------- #

def test_the_pivot_versus_probe_definition_lives_in_exactly_one_skill():
    """It was duplicated near-verbatim at two places in the 828-line skill.
    Two copies of a rule is one copy and one stale copy."""
    defining = [p.parent.name for p in SKILLS
                if "Pivoting vs. probing" in p.read_text()
                or "Pivot** —" in p.read_text()]
    assert defining == ["infrastructure-pivoting"], defining


def test_no_skill_carries_the_probe_vm_runbook():
    """285 of 828 lines were build steps and lab postmortems. An agent paid
    for them on every invocation; they are operator docs and belong in
    docs/probe-vm.md."""
    for path in SKILLS:
        text = path.read_text()
        assert "authorized_keys" not in text, f"{path.parent.name} has build steps"
        assert "administrators_authorized_keys" not in text


def test_the_runbook_survived_the_move():
    doc = (REPO / "docs" / "probe-vm.md").read_text()
    for marker in ("authorized_keys", "_is_probe_worthy",
                   "Automating the handoff"):
        assert marker in doc, marker


# --------------------------------------------------------------------------- #
# The mirrors
# --------------------------------------------------------------------------- #

def test_setup_rebuilds_the_mirrors_rather_than_adding_to_them():
    """Copying into an existing directory only ever ADDS, so a renamed or
    split skill left its old copy behind and every harness kept loading it.
    That is exactly what happened to threat-cluster-tracking: it was
    deleted from skills/ and still sat in .claude/skills/ and .pi/skills/,
    all 828 lines of it."""
    setup = (REPO / "setup.sh").read_text()
    block = setup[setup.index("# Claude Code reads Agent Skills"):
                  setup.index('echo "Installed cti + graph into')]
    assert 'rm -rf "$target"' in block, "mirrors are never pruned"
    assert block.index('rm -rf "$target"') < block.index('cp "$skill/SKILL.md"'), \
        "pruning must happen before copying, or it deletes what it just wrote"


@pytest.mark.parametrize("mirror", [".claude/skills", ".pi/skills"])
def test_a_mirror_holds_exactly_the_canonical_skills(mirror):
    """Skipped when the mirror has not been generated - it is gitignored,
    so a fresh clone has none until setup.sh runs."""
    target = REPO / mirror
    if not target.is_dir():
        pytest.skip(f"{mirror} not generated yet")
    assert sorted(p.name for p in target.iterdir() if p.is_dir()) == \
        sorted(p.parent.name for p in SKILLS)
