# Merchant Identity Assertions for Autonomous Commerce

An open specification for signed merchant identity claims, plus a proposed
integration profile for agent runtimes that check merchants before a transaction.

**Author:** Robb Anders · RegisteredBrands.AI  
**Draft:** `draft-anders-merchant-identity-assertions-02` · 28 September 2026  
**Status:** Author revision and experimental offline examples. This revision has
not been submitted to the IETF by this repository publication. There is no IETF
or AgenTrust endorsement and no claim of a production-certified integration.

## Read the draft

- [RFCXML source](spec/draft-anders-merchant-identity-assertions-02.xml)
- [Rendered text](spec/draft-anders-merchant-identity-assertions-02.txt)
- [Rendered HTML](spec/draft-anders-merchant-identity-assertions-02.html) — download
  and open locally for the formatted view
- [Changes in -02](CHANGELOG.md)
- [AgenTrust integration proposal](docs/AGENTRUST-INTEGRATION.md)
- [Security scope](SECURITY.md)

## What it does

MIA binds signed legal-entity claims to a merchant domain. A relying party can
check the assertion, the merchant's authorization of an issuer, and the identity
evidence its own policy requires. A signature alone does not prove the merchant's
claims are true, that it is reputable, or that it owns a payment destination.

The optional **MIA-RT1** profile adds:

- A verification result bound to the exact merchant assertion, approved criteria,
  gateway audience, request challenge, and transaction context.
- Separate outcomes for signature, domain, issuer authorization and trust,
  identity evidence, revocation, and payment-recipient binding.
- A pre-action gate with expiry, evidence freshness, replay and idempotency rules.
- A separately signed merchant-verification appraisal that a TRACE record can
  reference without upgrading the external evidence's assurance.

Core MIA version 1 and legacy ERTs remain available. A legacy ERT is insufficient
for MIA-RT1. The integration profile does not authorize or settle a payment.

## What is included

| Component | Status |
|---|---|
| -02 draft, text, and HTML | Authored and rendered with xml2rfc |
| Six JSON schemas | Structural constraints; semantic checks are also necessary |
| Signed MIA, delegation, ERT, and appraisal | Synthetic, reproducible public fixtures |
| Offline verifier and simulated pre-action gate | Example code with negative tests |
| TRACE `condition-appraisal` reference | Reference fragment; not a complete TRACE record |
| Live cMCP adapter / external identity checks / payment gateway | Not implemented here |
| Hardware attestation / upstream interoperability certification | Not demonstrated here |

## Run the examples

Use Python 3.11 or newer:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python tools/demo_verifier.py
python -m unittest discover -s tests -v
```

The example uses a fixed clock, fictional `.example` domains, and predictable
**public test signing keys**. It does not fetch real business records, contact
an agent runtime, or execute payments. It verifies actual fixture signatures
and digests, permits one simulated request, and rejects its replay. The tests
exercise altered signatures, wrong issuers/audiences, changed merchants,
recipients, amounts and sessions, stale evidence, failed checks, and appraisal
tampering. This is an illustration of the profile, not a full production SDK.

Rebuild the committed fixtures with `python tools/build_examples.py`.
Anyone can derive these fixture private keys from the public script; never
install the example keys in a live trust store.

## Build the Internet-Draft

```sh
python -m pip install -r requirements-docs.txt
xml2rfc --no-network --v3 --text --html --date 2026-09-28 \
  spec/draft-anders-merchant-identity-assertions-02.xml
```

The source embeds its bibliographic references so rendering requires no network.
The document date is intentionally pinned to the author revision date.

## Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md). Useful next work includes an independently
implemented verifier, real cMCP policy-context plumbing, authoritative identity
and recipient-evidence adapters, and testing against pinned upstream releases.

## Licensing and attribution

Original repository material is offered under [Apache-2.0](LICENSE), subject to
the third-party and IETF-notice boundaries in [LICENSING.md](LICENSING.md).
The RFCXML `trust200902` declaration and generated IETF notices are retained.
See [NOTICE](NOTICE). Project names do not imply affiliation or endorsement.

## Sources

- [Published IETF draft record](https://datatracker.ietf.org/doc/draft-anders-merchant-identity-assertions/)
- [Agent Manifest v0.2](https://manifest.agentrust-io.com/spec/agent-manifest-v0.2/)
- [cMCP](https://cmcp.agentrust-io.com/)
- [TRACE v0.2](https://trace.agentrust-io.com/spec/trace-v0.2/)
- [TRACE references registry](https://trace.agentrust-io.com/docs/references-registry/)

External project specifications were reviewed on 28 September 2026 and can
change. Publication of this repository does not update the IETF Datatracker.
