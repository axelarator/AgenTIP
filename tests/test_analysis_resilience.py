"""What the analysis stage does when the model is refused, and whether the
prompts still describe what the specialists are given.

The daily run shares the operator's subscription. On 2026-11-12 and
2026-11-13 every specialist was refused for a usage limit, the narrative
said "Nothing noteworthy", and the analysis was re-run by hand.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import duckdb
import pytest

from cti.store.schema import init_schema
from graph import sdk
from graph.nodes import analyze
from graph.nodes.rank import EVIDENCE_SHOWN, rank
from graph.sdk import TurnResult, load_prompt
from graph.state import FAMILY_ATTRIBUTES

# The message as the daily log recorded it.
REFUSED = ("ResultError: Claude Code returned an error result: You've hit your "
           "session limit · resets 7:30am (UTC) (exit code: 1)")
OUT_OF_TURNS = ("ResultError: Claude Code returned an error result: Reached "
                "maximum number of turns (6) (exit code: 1)")


def _utc(hour, minute=0, day=13):
    return datetime(2026, 11, day, hour, minute, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Reading the refusal
# --------------------------------------------------------------------------- #

def test_a_usage_limit_is_told_apart_from_other_failures():
    assert sdk.is_usage_limit(REFUSED)
    assert not sdk.is_usage_limit(OUT_OF_TURNS)
    assert not sdk.is_usage_limit("TimeoutError: no reply")
    assert not sdk.is_usage_limit(None)


@pytest.mark.parametrize("message, now, expected", [
    (REFUSED, _utc(6, 20), _utc(7, 30)),
    # Already past that time today: it means tomorrow.
    (REFUSED, _utc(8, 0), _utc(7, 30, day=14)),
    ("usage limit · resets 7pm (UTC)", _utc(6, 20), _utc(19, 0)),
    ("usage limit · resets 12:05am (UTC)", _utc(23, 50), _utc(0, 5, day=14)),
    ("usage limit · resets 12pm (UTC)", _utc(6, 20), _utc(12, 0)),
])
def test_the_reset_time_is_the_next_time_the_clock_reads_it(message, now, expected):
    assert sdk.limit_resets_at(message, now) == expected


@pytest.mark.parametrize("message", [
    "You've hit your session limit",
    "usage limit · resets 7:30am (Europe/Berlin)",
    "usage limit · resets 25:99am (UTC)",
])
def test_a_reset_time_that_cannot_be_read_is_not_guessed(message):
    assert sdk.limit_resets_at(message, _utc(6, 20)) is None


# --------------------------------------------------------------------------- #
# Waiting it out
# --------------------------------------------------------------------------- #

@pytest.fixture
def turns(monkeypatch):
    """Replace the model call with scripted replies and the sleep with a
    record of how long it was asked to wait."""
    script: list[TurnResult] = []
    slept: list[float] = []

    async def one_turn(**_kw):
        return script.pop(0)

    async def sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(sdk, "_one_turn", one_turn)
    monkeypatch.setattr(sdk.asyncio, "sleep", sleep)
    monkeypatch.delenv("CTI_LIMIT_WAIT_HOURS", raising=False)
    return script, slept


def _refused_resetting_in(minutes):
    at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    hour12 = at.hour % 12 or 12
    return TurnResult(text="", error=(
        f"ResultError: You've hit your session limit · resets "
        f"{hour12}:{at.minute:02d}{'am' if at.hour < 12 else 'pm'} (UTC)"))


async def test_a_refused_turn_waits_for_the_reset_and_answers(turns):
    script, slept = turns
    script += [_refused_resetting_in(45), TurnResult(text="[]")]

    result = await sdk.run_turn(system="s", prompt="p", allowed_tools=[])

    assert result.error is None and result.text == "[]"
    assert len(slept) == 1
    # Until the stated minute plus the margin, give or take the seconds
    # the message does not carry.
    margin = sdk.RESET_MARGIN.total_seconds()
    assert 44 * 60 + margin - 60 <= slept[0] <= 45 * 60 + margin


async def test_a_limit_that_lifts_too_late_is_not_waited_for(turns, monkeypatch):
    script, slept = turns
    monkeypatch.setenv("CTI_LIMIT_WAIT_HOURS", "1")
    script += [_refused_resetting_in(180), TurnResult(text="never reached")]

    result = await sdk.run_turn(system="s", prompt="p", allowed_tools=[])

    assert sdk.is_usage_limit(result.error)
    assert slept == []


async def test_waiting_can_be_turned_off(turns, monkeypatch):
    script, slept = turns
    monkeypatch.setenv("CTI_LIMIT_WAIT_HOURS", "0")
    script += [_refused_resetting_in(5), TurnResult(text="never reached")]

    result = await sdk.run_turn(system="s", prompt="p", allowed_tools=[])

    assert sdk.is_usage_limit(result.error) and slept == []


async def test_a_refusal_with_no_time_is_tried_again_after_a_fixed_wait(turns):
    script, slept = turns
    script += [TurnResult(text="", error="You've hit your usage limit"),
               TurnResult(text="[]")]

    result = await sdk.run_turn(system="s", prompt="p", allowed_tools=[])

    assert result.text == "[]"
    assert slept == [pytest.approx(sdk.BLIND_WAIT.total_seconds(), abs=5)]


async def test_any_other_failure_is_returned_at_once(turns):
    script, slept = turns
    script += [TurnResult(text="", error=OUT_OF_TURNS), TurnResult(text="unused")]

    result = await sdk.run_turn(system="s", prompt="p", allowed_tools=[])

    assert result.error == OUT_OF_TURNS and slept == []
    assert len(script) == 1


# --------------------------------------------------------------------------- #
# A day nothing was analysed is not a quiet day
# --------------------------------------------------------------------------- #

async def test_a_day_every_specialist_failed_is_not_written_up_as_quiet():
    state = {"day": "2026-11-13", "items": [], "findings": [],
             "errors": [f"cert_tls: {REFUSED}", f"hosting: {REFUSED}"]}

    narrative = (await analyze.narrate(state))["narrative"]

    assert "Nothing noteworthy" not in narrative
    assert "Not analysed" in narrative
    assert "cert_tls" in narrative and "hosting" in narrative
    assert "graph analyze --date 2026-11-13" in narrative


async def test_a_quiet_day_is_still_quiet():
    quiet = {"day": "2026-11-13", "items": [], "findings": [], "errors": []}
    noted = {**quiet, "errors": ["hosting: hit the 6-turn limit; answered "
                                 "without further lookups"]}
    for state in (quiet, noted):
        assert "Nothing noteworthy" in (await analyze.narrate(state))["narrative"]


def test_the_narrator_is_told_what_a_failed_specialist_means():
    prompt = load_prompt("narrate", with_common=False)
    assert "specialist_errors" in prompt
    for family in FAMILY_ATTRIBUTES:
        assert f"`{family}`" in prompt, f"narrate.md never explains {family}"


# --------------------------------------------------------------------------- #
# What a link item shows the specialist
# --------------------------------------------------------------------------- #

def _link(**kw):
    cert = [["tls.cert_sha256", f"{n:064x}"] for n in range(40)]
    row = {"seed": "192.0.2.10", "linked_to": "192.0.2.20", "actor": "A",
           "promoted": True, "score": 0.9731, "band": "strong",
           "reason": "1 identity fact(s) (certificate): tls.cert_sha256",
           "identity": cert,
           "structural": [["net.ip", "192.0.2.30"]],
           "corroborating": [["http.server", "nginx"], ["net.asn", "64500"]]}
    row.update(kw)
    return row


def _ranked_links(*rows):
    digest = {"day": "2026-11-13", "attribute_changes": [], "asn_pivots": [],
              "open_directories": [],
              "infrastructure_links": {"promoted": list(rows), "held_back_total": 7}}
    return rank({"digest_json": digest})["ranked"]["infrastructure"]


def test_a_link_item_carries_the_score_and_band_it_was_promoted_on():
    (item,) = _ranked_links(_link())
    assert item.new_value["score"] == 0.9731
    assert item.new_value["band"] == "strong"


def test_a_link_from_a_digest_without_scores_still_ranks():
    row = _link()
    del row["score"], row["band"]
    (item,) = _ranked_links(row)
    assert "score" not in item.new_value and "band" not in item.new_value


def test_forty_shared_certificates_do_not_hide_the_rest_of_the_evidence():
    """Listed in full, the identity values filled the slice a specialist
    reads and the structural and corroborating evidence was cut off."""
    (item,) = _ranked_links(_link())
    assert len(item.new_value["identity"]) == EVIDENCE_SHOWN
    assert item.new_value["identity_not_shown"] == 40 - EVIDENCE_SHOWN
    assert "structural_not_shown" not in item.new_value

    rendered = analyze._render_items([item])
    assert "chars total" not in rendered, "the item was still cut short"
    assert "192.0.2.30" in rendered and "http.server" in rendered


def test_the_link_prompt_describes_the_rule_that_now_promotes():
    prompt = load_prompt("infrastructure")
    assert "`strong`" in prompt
    for field in ("new_value.score", "new_value.band", "identity_not_shown"):
        assert field in prompt, f"infrastructure.md never explains {field}"


# --------------------------------------------------------------------------- #
# Prompts against the store
# --------------------------------------------------------------------------- #

_SQL = re.compile(r"`(SELECT\b[^`]+)`", re.IGNORECASE)


def test_every_query_a_prompt_suggests_runs_against_the_schema(tmp_path):
    """A prompt that names a column the store does not have costs a
    specialist one of its two lookups and an error for an answer."""
    con = duckdb.connect(str(tmp_path / "t.duckdb"))
    init_schema(con)
    found = 0
    for family in FAMILY_ATTRIBUTES:
        for sql in _SQL.findall(load_prompt(family)):
            found += 1
            con.execute(re.sub(r"\s+", " ", sql)).fetchall()
    assert found >= 2, "the prompts' example queries were not found"


def test_no_prompt_points_at_a_field_no_item_carries():
    # cert_tls.md told the specialist to lead with `revoked`; no certificate
    # row has ever carried it.
    assert "`revoked` is true" not in load_prompt("cert_tls")
    # opendir.md read as if analysis results arrived on the item.
    assert "never carries analysis results" in load_prompt("opendir")
