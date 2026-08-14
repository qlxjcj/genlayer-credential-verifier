# Credential Verifier — Multi-Source Qualification Authenticity Verification

Decentralized credential authenticity verification on GenLayer. Users submit a credential claim (holder name, type, claimed issuer) with multiple independent authoritative source URLs (registries, institutions, licensing bodies). GenLayer validators fetch all sources, verify credential existence, holder consistency, issuer legitimacy, and detect forged indicators. Consensus binds ALL consequential outputs via `prompt_comparative`: exact result label, validity_score, confidence, and findings set.

## How it works

1. **Submit** — A user submits a credential claim with independent source URLs.
2. **Verify** — Validators fetch each source, then LLM consensus (`gl.eq_principle.prompt_comparative`) binds the exact result (`VERIFIED` / `UNVERIFIED` / `SUSPICIOUS`), `validity_score`, `confidence`, and `findings`.
3. **Index** — Verified credentials are recorded in `verified`; suspicious ones in `flagged`.

## Consensus discipline

Every consequential output is inside the equivalence principle — the label alone is never enough:
- `result` (VERIFIED / UNVERIFIED / SUSPICIOUS)
- `validity_score` (0-100)
- `confidence` (0-100)
- `findings` (set)

## Index-state invariants

One `holder:credential_type` key maps to exactly ONE non-conflicting public state. Each new verdict **clears incompatible prior index state**:

| New verdict | verified index | flagged index |
|---|---|---|
| VERIFIED | written | removed |
| SUSPICIOUS | removed | written |
| UNVERIFIED | removed | removed |

A later verification can never leave a holder+type simultaneously verified and flagged.

## Contract methods

### Writes
- `submit_credential(holder_name, credential_type, issuer, source_urls_json)` — create a pending credential
- `process_verification(credential_id)` — validators verify sources + LLM consensus + index update

### Views
- `get_credential(credential_id)` — full record (JSON string)
- `is_verified(holder_name, credential_type)` / `is_flagged(holder_name, credential_type)` — public index lookups
- `get_credential_count()`
- `get_stats()` — verified/unverified/suspicious/pending counts + index sizes
- `list_credentials()` — summarized list for the UI

## Correctness notes

- Only the submitter can process their own credential (party authorization).
- `UNVERIFIED` clears both indexes — a dropped or failed verification leaves no stale public claim.
- Sources are fetched with `gl.nondet.web.get`; missing/error sources degrade to `[FETCH_FAILED]` and the LLM weights what it actually received.

## Deployment

- Contract: `0x6BCE9be8026f09A054EBA79f97A20730Da6094b1` (Bradbury)
- Explorer: https://explorer-bradbury.genlayer.com/address/0x6BCE9be8026f09A054EBA79f97A20730Da6094b1
