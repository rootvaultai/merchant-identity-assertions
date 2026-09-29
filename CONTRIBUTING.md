# Contributing

Issues and pull requests are welcome. State whether a proposal concerns the core
MIA protocol, the optional runtime profile, an example, or an external adapter.

For normative changes, explain the threat model and compatibility impact, update
the RFCXML, corresponding schemas and examples, and include a reproducible test
that distinguishes the old and new behavior. Preserve the distinction between
signature validity, issuer trust, identity evidence and authorization.

Run:

```sh
python tools/demo_verifier.py
python -m unittest discover -s tests -v
xml2rfc --no-network --v3 --text --html --date 2026-09-28 \
  spec/draft-anders-merchant-identity-assertions-02.xml
```

Do not add live keys, customer data, private merchant evidence, or payment details.
Use reserved example domains and clearly labeled public test keys.

Original contributions are submitted under the repository's Apache-2.0 terms;
existing third-party and IETF notices remain applicable. Contributions intended
for inclusion in an IETF submission are also subject to the applicable IETF
contribution and IPR policies. Do not assert someone else's rights or sign off
on their behalf. No upstream project is obliged to adopt this work.
