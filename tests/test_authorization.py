"""Milestone D tests: authorization, approval binding, simulation, verification.

Hard assertion of the whole suite: unauthorized sensitive actions NEVER execute.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from response import (
    ApprovalDenied,
    ApprovalExpired,
    ApprovalLedger,
    ApprovalMismatch,
    ApprovalReplayed,
    ApprovalNotFound,
    ResponseSimulator,
    StateStore,
    create_pending_action,
    decide,
    fingerprint,
    parse_decision,
    requires_approval,
    verify_state,
)
from schemas import ActionKind

INC = "INC-TEST01"
ACCT = "A104"
USER = "did:uni:session-abc"


@pytest.fixture()
def sim(tmp_path):
    return ResponseSimulator(StateStore(tmp_path / "state.json"))


@pytest.fixture()
def ledger():
    return ApprovalLedger()


def _fingerprint(action=ActionKind.CONTAIN_ACCOUNT):
    return fingerprint(INC, action, ACCT, USER)


def _approve(ledger, action=ActionKind.CONTAIN_ACCOUNT, user=USER):
    pending = create_pending_action(
        INC, action, ACCT, user, "test justification"
    )
    ledger.issue(pending)
    approval = ledger.validate(pending.action_id, "approve", user)
    return pending, approval


# ------------------------------------------------------- unauthorized (7)
def test_unauthorized_containment_never_executes(sim, ledger):
    policy = decide(
        ActionKind.CONTAIN_ACCOUNT, None,
        incident_id=INC, target_account=ACCT, requested_by=USER,
        expected_fingerprint=_fingerprint(),
    )
    assert policy.allowed is False
    assert "approval required" in policy.reason
    # state completely untouched
    state = sim.store.account(ACCT)
    assert state.contained is False
    assert state.flagged_for_investigation is False
    assert state.open_incidents == []


def test_unknown_action_not_allowlisted(sim, ledger):
    pending, approval = _approve(ledger)
    class FakeAction:
        value = "format_disk"
    from schemas import ActionKind as AK
    # simulate an action outside the enum by patching the decision input
    policy = decide(
        "run_shell_command", approval,  # type: ignore[arg-type]
        incident_id=INC, target_account=ACCT, requested_by=USER,
        expected_fingerprint=pending.fingerprint,
    )
    assert policy.allowed is False
    assert "not allowlisted" in policy.reason


# ---------------------------------------------------- valid approval (8)
def test_valid_approval_executes_and_verifies(sim, ledger):
    pending, approval = _approve(ledger)
    policy = decide(
        ActionKind.CONTAIN_ACCOUNT, approval,
        incident_id=INC, target_account=ACCT, requested_by=USER,
        expected_fingerprint=pending.fingerprint,
    )
    assert policy.allowed is True, policy.reason
    assert requires_approval(ActionKind.CONTAIN_ACCOUNT) is True

    result = sim.execute(
        ActionKind.CONTAIN_ACCOUNT, pending.action_id, ACCT, INC, "test containment"
    )
    assert result.status == "executed"

    check = verify_state(sim.store, ActionKind.CONTAIN_ACCOUNT,
                         pending.action_id, ACCT, INC)
    assert check.status == "verified", check.note
    assert check.actual_state is not None and check.actual_state["contained"] is True


def test_non_sensitive_action_allowed_without_approval(sim, ledger):
    policy = decide(
        ActionKind.CREATE_INCIDENT, None,
        incident_id=INC, target_account=ACCT, requested_by=USER,
        expected_fingerprint=fingerprint(INC, ActionKind.CREATE_INCIDENT, ACCT, USER),
    )
    assert policy.allowed is True
    assert policy.requires_approval is False


# ------------------------------------------- replay / mismatch (9)
def test_approval_replay_rejected(ledger):
    pending, approval = _approve(ledger)
    with pytest.raises(ApprovalReplayed):
        ledger.validate(pending.action_id, "approve", USER)
    with pytest.raises(ApprovalReplayed):
        ledger.validate(pending.action_id, "decline", USER)


def test_approval_mismatch_wrong_fingerprint(ledger):
    pending = create_pending_action(INC, ActionKind.CONTAIN_ACCOUNT, ACCT, USER, "j")
    ledger.issue(pending)
    wrong_fp = fingerprint("INC-OTHER", ActionKind.CONTAIN_ACCOUNT, ACCT, USER)
    with pytest.raises(ApprovalMismatch):
        ledger.validate(pending.action_id, "approve", USER,
                        expected_fingerprint=wrong_fp)


def test_approval_wrong_approver_rejected(ledger):
    pending = create_pending_action(INC, ActionKind.CONTAIN_ACCOUNT, ACCT, USER, "j")
    ledger.issue(pending)
    with pytest.raises(ApprovalMismatch):
        ledger.validate(pending.action_id, "approve", "did:uni:someone-else")


def test_approval_expired_rejected(ledger):
    pending = create_pending_action(
        INC, ActionKind.CONTAIN_ACCOUNT, ACCT, USER, "j", ttl_seconds=1
    )
    ledger.issue(pending)
    future = datetime.now(timezone.utc) + timedelta(seconds=5)
    with pytest.raises(ApprovalExpired):
        ledger.validate(pending.action_id, "approve", USER, now=future)


def test_unknown_token_rejected(ledger):
    with pytest.raises(ApprovalNotFound):
        ledger.validate("APR-DEADBEEF", "approve", USER)


def test_policy_denies_with_wrong_fingerprint_even_with_approval(ledger):
    pending, approval = _approve(ledger)
    policy = decide(
        ActionKind.CONTAIN_ACCOUNT, approval,
        incident_id=INC, target_account=ACCT, requested_by=USER,
        expected_fingerprint="0" * 64,
    )
    assert policy.allowed is False
    assert "fingerprint" in policy.reason


# -------------------------------------------------- user declines (10)
def test_user_declines_approval(sim, ledger):
    pending = create_pending_action(INC, ActionKind.CONTAIN_ACCOUNT, ACCT, USER, "j")
    ledger.issue(pending)
    with pytest.raises(ApprovalDenied):
        ledger.validate(pending.action_id, "decline", USER)
    # declining consumed the token
    with pytest.raises(ApprovalReplayed):
        ledger.validate(pending.action_id, "approve", USER)
    # no state change ever happened
    assert sim.store.account(ACCT).contained is False


def test_decline_blocked_by_policy(sim, ledger):
    pending = create_pending_action(INC, ActionKind.CONTAIN_ACCOUNT, ACCT, USER, "j")
    ledger.issue(pending)
    with pytest.raises(ApprovalDenied):
        ledger.validate(pending.action_id, "decline", USER)
    policy = decide(
        ActionKind.CONTAIN_ACCOUNT, None,
        incident_id=INC, target_account=ACCT, requested_by=USER,
        expected_fingerprint=pending.fingerprint,
        reason_for_denial="user declined approval",
    )
    assert policy.allowed is False
    assert "declined" in policy.reason
    assert sim.store.account(ACCT).contained is False


# --------------------------------- success claim but state unchanged (11)
def test_verification_detects_silent_failure():
    import tempfile
    from pathlib import Path

    honest = ResponseSimulator(StateStore(Path(tempfile.mkdtemp()) / "s.json"))
    liar_path = Path(tempfile.mkdtemp()) / "s2.json"
    liar = ResponseSimulator(StateStore(liar_path), faults={"contain_account": "silent_fail"})
    # account exists in state before the action (realistic precondition)
    liar.store.save_account(liar.store.account(ACCT))
    # liar claims success...
    result = liar.execute(ActionKind.CONTAIN_ACCOUNT, "APR-1", ACCT, INC, "x")
    assert result.status == "executed"
    # ...but independent verification catches the missing state change
    check = verify_state(liar.store, ActionKind.CONTAIN_ACCOUNT, "APR-1", ACCT, INC)
    assert check.status == "failed"
    assert "contained" in check.note
    # honest simulator verifies
    honest.execute(ActionKind.CONTAIN_ACCOUNT, "APR-2", ACCT, INC, "x")
    check2 = verify_state(honest.store, ActionKind.CONTAIN_ACCOUNT, "APR-2", ACCT, INC)
    assert check2.status == "verified"


def test_simulator_hard_failure_reports_failed(sim):
    faulty = ResponseSimulator(sim.store, faults={"flag_account": "raise"})
    from response import SimulatorError
    with pytest.raises(SimulatorError):
        faulty.execute(ActionKind.FLAG_ACCOUNT, "APR-3", ACCT, INC, "x")
    assert sim.store.account(ACCT).flagged_for_investigation is False


# ------------------------------------------------- decision parsing
def test_parse_decision_from_chat_text():
    assert parse_decision("APPROVE APR-1A2B3C4D5E6F") == ("approve", "APR-1A2B3C4D5E6F")
    assert parse_decision("decline") == ("decline", None)
    assert parse_decision("please APPROVE") == ("approve", None)
    assert parse_decision("investigate A104") is None
    assert parse_decision("") is None


# ------------------------------------------------- incident closed case
def test_policy_denies_when_incident_closed(ledger):
    pending, approval = _approve(ledger)
    policy = decide(
        ActionKind.CONTAIN_ACCOUNT, approval,
        incident_id=INC, target_account=ACCT, requested_by=USER,
        expected_fingerprint=pending.fingerprint,
        incident_open=False,
    )
    assert policy.allowed is False
    assert "no longer open" in policy.reason
