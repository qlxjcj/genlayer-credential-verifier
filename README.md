# Credential Verifier — Multi-Source Qualification Authenticity Verification

Decentralized credential authenticity verification on GenLayer. Users submit a credential claim (holder name, holder wallet address, type, claimed issuer) with multiple independent authoritative source URLs (registries, institutions, licensing bodies). GenLayer validators fetch all sources, verify credential existence, holder consistency, issuer legitimacy, and detect forged indicators. Consensus binds ALL consequential outputs via `prompt_comparative`: exact result label, validity_score, confidence, and findings set.

## How it works

1. **Submit** — A user submits a credential claim (holder name + holder wallet address) with independent source URLs.
2. **Verify** — Validators fetch each source, then LLM consensus (`gl.eq_principle.prompt_comparative`) binds the exact result (`VERIFIED` / `UNVERIFIED` / `SUSPICIOUS`), `validity_score`, `confidence`, and `findings`.
3. **Index** — Verified credentials are recorded in `verified`; suspicious ones in `flagged`.

## Consensus discipline

Every consequential output is inside the equivalence principle — the label alone is never enough:
- `result` (VERIFIED / UNVERIFIED / SUSPICIOUS)
- `validity_score` (0-100)
- `confidence` (0-100)
- `findings` (set)

## Index-state invariants

One `holder_address:credential_type` key maps to exactly ONE non-conflicting public state. Each new verdict **clears incompatible prior index state**:

| New verdict | verified index | flagged index |
|---|---|---|
| VERIFIED | written | removed |
| SUSPICIOUS | removed | written |
| UNVERIFIED | removed | removed |

A later verification can never leave a holder+type simultaneously verified and flagged.

## Authority & replacement policy

The public index is **bound to the holder's wallet address**:

- The index key is `holder_address:credential_type` (the holder's address, not just a name string).
- `submit_credential` requires the **caller to be the holder** (`sender == holder_address`). A caller cannot submit an arbitrary holder address and become that key's owner — only the holder themself can claim their pair.
- Ownership is stored in its **own `owners` map, persisted independently of the verdict**. `UNVERIFIED` clears the public `verified`/`flagged` entries but **never releases the key**, so another account cannot later re-claim the holder's pair.
- Only the holder may **update, overwrite, or clear** their key's public entry. Any other account attempting to act on the key is rejected (`Only the holder can submit their own credential`).
- `get_owner(holder_address, credential_type)` reads the persisted ownership record.

## Contract methods

### Writes
- `submit_credential(holder_name, holder_address, credential_type, issuer, source_urls_json)` — create a pending credential; the caller must be the holder. First submission binds `holders_address:credential_type` to that holder.
- `process_verification(credential_id)` — validators verify sources + LLM consensus + index update (holder-gated)

### Views
- `get_credential(credential_id)` — full record (JSON string)
- `is_verified(holder_address, credential_type)` / `is_flagged(holder_address, credential_type)` — public index lookups
- `get_owner(holder_address, credential_type)` — persisted ownership record (independent of verdict)
- `get_credential_count()`
- `get_stats()` — verified/unverified/suspicious/pending counts + index sizes
- `list_credentials()` — summarized list for the UI

## Correctness notes

- `submit_credential` is holder-bound: `sender == holder_address`, so no caller can claim another party's key.
- Ownership persists in `owners` across all verdicts, including `UNVERIFIED`.
- `UNVERIFIED` clears both public indexes — a dropped or failed verification leaves no stale public claim, but the holder's ownership of the pair remains.
- Sources are fetched with `gl.nondet.web.get`; missing/error sources degrade to `[FETCH_FAILED]` and the LLM weights what it actually received.

## Tests

- `tests/direct/test_authority.py` — direct-mode tests (genlayer-test 0.29.2) running the real contract source in-memory: holder binding, ownership persistence across UNVERIFIED, stranger re-claim rejection, index-state invariant, owner-gated writes. `python -m pytest tests/direct/ -v`
- `test_index.js` — deterministic mirror of the authority/ownership logic + live contract reads. `node test_index.js`

## Deployment

- Contract: `0x5257209605acd9BA1114CE9CcB02F6a4ee2F342C` (Bradbury)
- Explorer: https://explorer-bradbury.genlayer.com/address/0x5257209605acd9BA1114CE9CcB02F6a4ee2F342C
