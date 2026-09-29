# Changelog

## -02 author revision — 2026-09-28

- Added optional MIA-RT1 profile with separate assurance outcomes, pinned criteria,
  gateway audience and challenge, request digests, payment-recipient checks,
  expiry, replay and idempotency requirements.
- Added a separately signed Merchant Verification Appraisal and an informative
  mapping to Agent Manifest, cMCP and TRACE `condition-appraisal` references.
- Clarified the separation of merchant domain, authenticated agent and issuing
  workload identities, and kept consumer/agent-principal identities out of public MIAs.
- Tightened proof consistency and issuer trust; required complete RFC 8785 JCS;
  defined strict fetching, caching, revocation and time-boundary behavior.
- Fixed missing `alg` in proof construction, RFCXML section names, example
  timestamps, and overly broad novelty / post-quantum wording.
- Added six schemas, signed fictional fixtures, offline validation, and negative tests.

The document revision is -02; the core MIA wire version remains 1. The runtime
profile has its own identifier. Existing core documents are not runtime receipts.
Stricter validation may reject documents accepted by a permissive -01 verifier,
including mismatched proof paths or unchecked proof metadata.

GitHub publication is not IETF submission or AgenTrust acceptance.
