# Security scope

This is an experimental specification repository with an offline example. It is
not a production merchant-verification service, payment gateway, or certified
AgenTrust integration.

The example keys are public and predictable. Fictional issuer, identity-record,
revocation and payment-recipient findings are simulated. Successful fixture
verification proves that the fixture's signatures and local bindings check out;
it does not establish a real business's identity or a real account's ownership.

The code has no HTTP discovery, DNSSEC validation, SSRF defenses for live fetches,
IDNA2008 deployment implementation, authoritative business data adapter,
distributed replay store, durable payment idempotency, cMCP runtime plugin,
hardware attestation, or complete TRACE verifier. These are explicit remaining
implementation tasks, not capabilities supplied by the demo.

For suspected vulnerabilities, contact founder@registeredbrands.ai with a minimal
synthetic reproducer. Do not send credentials or customer/transaction data.
If the repository's private vulnerability reporting is enabled, that channel may
also be used. No response-time or remediation commitment is implied here.
