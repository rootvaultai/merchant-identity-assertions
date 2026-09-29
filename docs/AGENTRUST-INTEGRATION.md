# Proposed AgenTrust integration

MIA-RT1 is runtime-neutral. This document maps its role to AgenTrust's public
specifications; it does not announce a built-in AgenTrust capability.

## Identity mapping

| MIA / runtime concept | Mapping |
|---|---|
| Merchant domain | `MIA.subject` and ERT `sub` |
| Merchant assertion checked | Appraisal `subject.id` and `subject.digest` |
| Agent configuration | Agent Manifest `manifest_id` and `agent_id` |
| Agent associated with cMCP session | `gateway.agent_identity` in the documented envelope |
| Gateway workload issuing execution evidence | `trace.subject`; do not replace with merchant domain |
| Check criteria | Appraisal `condition.id` and `condition.digest` |
| Retained verification result | TRACE reference with `rel: condition-appraisal` |

## Before an action

1. Authenticate the agent and bind its approved manifest, policy, and tool catalog.
2. Derive the complete request context from the actual call. Generate a fresh
   request nonce and associate an opaque session handle with authenticated state.
3. Obtain a MIA-RT1 result from an independently trusted checker using approved
   criteria. The checker must actually obtain the evidence its result describes.
4. Validate the ERT and exact context. Feed verified attributes into policy through
   trusted adapter code. The model cannot declare itself merchant-verified.
5. Enforce policy, atomically consume the receipt, and dispatch only the bound
   request. Confine payment credentials so the agent cannot bypass this gate.
6. Retain the ERT, criteria, assertion, evidence, appraisal, and execution records
   under the deployment's access and retention policy.

Suggested attributes such as `merchant_identity_verified` and
`payment_context_matched` are **new adapter attributes**, not native cMCP fields.
The adapter must implement the runtime input mapping and Cedar schema/policy
changes, not merely add a prompt telling the agent to call a verification tool.

## After an action

`examples/trace-reference.json` is a reference fragment, not a complete TRACE
Trust Record. It points to `examples/merchant-appraisal.json` by its signed
canonical digest. The checker signs the appraisal with its `signature` member
absent; the reference digest covers the complete appraisal, signature included.

The existing JWT ERT retains JWS semantics. It is linked by its exact compact-token
digest inside the separately signed appraisal. The JSON appraisal matches the
documented shape required for the `condition-appraisal` relation.

A reference does not make its target hardware-attested, enforce an action, or
establish compliance. An unavailable target leaves that appraisal unconfirmed;
it does not invalidate a separately valid TRACE record. This repository does
not contain a TRACE verifier and does not claim to have tested that upstream rule.

## Compatibility record

| External component | Reviewed specification | Tested upstream runtime / commit |
|---|---|---|
| Agent Manifest | Public v0.2 documentation, reviewed 2026-09-28 | Not tested |
| cMCP | Public policy and session documentation, reviewed 2026-09-28 | Not tested |
| TRACE | Public v0.2 and reference-registry documentation, reviewed 2026-09-28 | Not tested |

Before claiming interoperability, pin upstream release tags or full commit IDs,
schema digests and verifier versions, implement the adapter, and execute an
end-to-end test across those exact revisions. A passing local fixture suite is
not upstream conformance. No external repository or API has been changed.

## First real integration acceptance cases

- An approved, current merchant result permits one authorized test payment call.
- Wrong issuer, wrong audience, changed merchant or recipient, changed amount,
  stale or revoked evidence, and a missing required check prevent dispatch.
- Concurrent replay and a retry after a process crash cannot issue a second payment.
- The retained appraisal and ERT agree with the request actually dispatched.
- A failed or unresolved merchant reference does not corrupt TRACE signature
  validation, while pre-action merchant policy still fails closed as configured.
- A software-only run makes no claim of hardware attestation.

These integration cases are goals for a live adapter. The committed test suite
covers only the explicitly documented offline subset.
