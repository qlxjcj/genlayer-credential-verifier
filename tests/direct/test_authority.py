"""Direct-mode tests for Credential Verifier authority/ownership logic.

Runs the real deployed contract source (credential_verifier.py) in an
in-memory VM. Covers the security properties requested by the steward:

  1. Holder binding: the caller MUST be the holder (sender == holder_address).
     A caller cannot submit an arbitrary holder address and become that key's
     owner.
  2. Ownership persistence: ownership is stored in its own `owners` map and
     survives UNVERIFIED. UNVERIFIED clears the public verified/flagged
     entries but never releases the key, so another account cannot re-claim.
  3. Index-state invariant: one holder:type key maps to exactly one public
     state; each verdict clears incompatible prior state.
  4. Only the owner may replace or clear their own public entry.

No network, no consensus: deterministic and instant.
Run: python -m pytest tests/direct/ -v   (from the project root)
"""

import json
import os
import pytest

# Absolute path to the contract under test (works from any cwd).
# __file__ = <project>/tests/direct/test_authority.py
# project root = three levels up.
CONTRACT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "credential_verifier.py",
)

VERIFIED_LLM = json.dumps({
    "result": "VERIFIED", "validity_score": 92, "confidence": 90,
    "findings": ["found in registry"],
})
UNVERIFIED_LLM = json.dumps({
    "result": "UNVERIFIED", "validity_score": 0, "confidence": 0,
    "findings": ["no match"],
})
SUSPICIOUS_LLM = json.dumps({
    "result": "SUSPICIOUS", "validity_score": 30, "confidence": 40,
    "findings": ["inconsistent"],
})


@pytest.fixture
def verifier(direct_vm, direct_deploy):
    c = direct_deploy(CONTRACT)
    return direct_vm, c


def submit(c, holder, ctype="PM1"):
    c.submit_credential("Alice", holder.as_hex, ctype, "Registry A", "[]")


def process(vm, c, llm_json, cid=1):
    vm.clear_mocks()
    vm.mock_llm(r".*Credential check.*", llm_json)
    c.process_verification(cid)


def owner_of(c, holder, ctype="PM1"):
    return c.get_owner(holder.as_hex, ctype)


# ---------- 1. Holder binding ----------

def test_non_holder_cannot_submit(direct_vm, verifier, direct_bob, direct_charlie):
    """A caller cannot submit for an arbitrary holder address."""
    vm, c = verifier
    vm.sender = direct_charlie
    with pytest.raises(Exception) as ei:
        c.submit_credential("Alice", direct_bob.as_hex, "PM1", "Registry A", "[]")
    assert "holder" in str(ei.value).lower()

    # the key stays unowned
    assert owner_of(c, direct_bob) == ""


def test_holder_can_submit_and_owns_key(direct_vm, verifier, direct_bob):
    """The real holder submits; ownership binds to the holder address."""
    vm, c = verifier
    vm.sender = direct_bob
    submit(c, direct_bob)
    assert owner_of(c, direct_bob).lower() == direct_bob.as_hex.lower()


# ---------- 2. Ownership persists independently of the verdict ----------

def test_ownership_survives_unverified(direct_vm, verifier, direct_bob):
    """UNVERIFIED clears public entries but ownership persists."""
    vm, c = verifier
    vm.sender = direct_bob
    submit(c, direct_bob)
    process(vm, c, VERIFIED_LLM)
    assert json.loads(c.is_verified(direct_bob.as_hex, "PM1"))["owner"]
    assert owner_of(c, direct_bob).lower() == direct_bob.as_hex.lower()

    # re-process the holder's next credential to UNVERIFIED
    submit(c, direct_bob)
    process(vm, c, UNVERIFIED_LLM, cid=2)
    assert c.is_verified(direct_bob.as_hex, "PM1") == "{}"
    assert c.is_flagged(direct_bob.as_hex, "PM1") == "{}"
    # ownership record STILL present
    assert owner_of(c, direct_bob).lower() == direct_bob.as_hex.lower()


def test_stranger_cannot_reclaim_after_unverified(direct_vm, verifier, direct_bob, direct_charlie):
    """Another account cannot re-claim the key after UNVERIFIED released it."""
    vm, c = verifier
    vm.sender = direct_bob
    submit(c, direct_bob)
    process(vm, c, UNVERIFIED_LLM)

    # stranger attempts to claim the freed key
    vm.sender = direct_charlie
    with pytest.raises(Exception):
        c.submit_credential("Mallory", direct_bob.as_hex, "PM1", "Registry A", "[]")
    assert owner_of(c, direct_bob).lower() == direct_bob.as_hex.lower()


# ---------- 3. Index-state invariant ----------

def test_index_single_consistent_state(direct_vm, verifier, direct_bob):
    """Repeated verdicts never leave a holder+type simultaneously verified+flagged."""
    vm, c = verifier
    vm.sender = direct_bob
    submit(c, direct_bob)
    process(vm, c, VERIFIED_LLM)
    assert c.is_verified(direct_bob.as_hex, "PM1") != "{}"
    assert c.is_flagged(direct_bob.as_hex, "PM1") == "{}"

    submit(c, direct_bob)
    process(vm, c, SUSPICIOUS_LLM, cid=2)
    assert c.is_verified(direct_bob.as_hex, "PM1") == "{}"
    assert c.is_flagged(direct_bob.as_hex, "PM1") != "{}"


# ---------- 4. Only the owner may replace or clear their own entry ----------

def test_stranger_cannot_clear_owner_entry(direct_vm, verifier, direct_bob, direct_charlie):
    """A stranger cannot submit for the owner's key (holder binding)."""
    vm, c = verifier
    vm.sender = direct_bob
    submit(c, direct_bob)
    process(vm, c, VERIFIED_LLM)

    vm.sender = direct_charlie
    with pytest.raises(Exception):
        c.submit_credential("Mallory", direct_bob.as_hex, "PM1", "Registry A", "[]")
    # owner's entry intact
    assert json.loads(c.is_verified(direct_bob.as_hex, "PM1"))["owner"].lower() == direct_bob.as_hex.lower()
