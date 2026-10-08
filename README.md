# SALAH Governance — G0 foundation

This separate, owner-controlled repository is the governance root for future SALAH approvals. The SALAH application repository is candidate/evidence only. Owner control of this repository—not `trust-policy.json`, SALAH's `UPSTREAM.json`, or a verifier stored in SALAH—is the trust assumption. The owner has confirmed administrative access; branch protection and CI enforcement have **not** been verified or established by G0.

G0 contains only a versioned policy (`governance/trust-policy.json`), a schema-valid empty approval register (`governance/approvals.jsonl`), and a diagnostic bootstrap (`bootstrap/verify.mjs`). No amendment is admitted or active; V4 remains pending admission outside this register. There is no final V4 byte digest here.

Run `node bootstrap/verify.mjs` for a machine-readable diagnostic schema check and `node --test tests/bootstrap-trust.test.mjs` for focused adversarial tests. A successful G0 result always says `mode: DIAGNOSTIC`, `authoritative: false`, and `authority: NONE`. It is **not** approval of SALAH bytes, a release, or runtime authority. Missing, malformed, duplicate, stale, or contradictory records fail closed; revoked, expired, and rolled-back records have denied disposition. A candidate-controlled local diagnostic pass cannot confer authority, although G0 alone does not yet enforce independent execution against candidate-controlled verifier bytes.

The register starts with one canonical JSONL header and no decisions. Its version-1 schema can represent future amendment identity, owner, type, purpose, reason, exact paths, baseline/scope digests, architecture revision, state, register revision, decision/expiry timestamps, revocation/rollback references, and final-byte digest. G0 validates schema and legal transitions only; it rejects runtime-authority and final-byte assertions, and it does not issue approvals. Test fixtures are synthetic and never become register entries.

Pending gates:

- G1: independently pin and verify SALAH verifier bytes.
- G2: protect mandatory entrypoint and stage enforcement, including CI policy if approved.
- G3: execute finite owner-approved amendments.

Do not treat any of those gates as implemented. Do not stage or commit this G0 work until the owner directs it. No SALAH production or test file is modified by G0.
