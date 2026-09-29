"""Apache-2.0. Rebuild synthetic examples. Every signing key is public test data."""
from datetime import datetime, timezone
from fixture_crypto import (ROOT, PROFILE, CHECKS, demo_key, public_jwk,
                            sign_mia, sign_ert, sign_appraisal, digest, token_digest, write)


def main():
    now = int(datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc).timestamp())
    merchant = demo_key('merchant')
    issuer = demo_key('issuer')
    checker = demo_key('verifier')
    keys = {'merchant.example': public_jwk(merchant, 'fixture-merchant-1'),
            'issuer.example': public_jwk(issuer, 'fixture-issuer-1'),
            'verifier.example': public_jwk(checker, 'fixture-verifier-1')}
    mia = sign_mia({
        'version': 1, 'subject': 'merchant.example',
        'legalName': 'Example Merchant LLC — TEST FIXTURE', 'entityType': 'llc',
        'jurisdiction': 'US', 'issuedAt': '2026-09-28T00:00:00Z',
        'expiresAt': '2026-12-27T00:00:00Z',
        'issuer': {'name': 'Example Issuer — TEST FIXTURE', 'domain': 'issuer.example',
                   'keyDirectory': 'https://issuer.example/.well-known/jwks.json'},
        'registrationId': 'TEST-REGISTRATION-0001',
        'evidenceUris': ['https://registry.example/test-record/0001'],
        'revocationUri': 'https://issuer.example/status/test-0001'
    }, issuer, 'https://issuer.example/.well-known/jwks.json', 'fixture-issuer-1')
    midd = sign_mia({'version': 1, 'type': 'MerchantIdentityDelegation',
        'subject': 'merchant.example', 'authorizedIssuer': 'issuer.example',
        'issuedAt': '2026-09-28T00:00:00Z', 'expiresAt': '2026-12-27T00:00:00Z'},
        merchant, 'https://merchant.example/.well-known/jwks.json', 'fixture-merchant-1')
    criteria = {'id': 'https://buyer.example/policies/merchant-identity/1', 'version': 1,
        'accepted_mia_issuers': ['issuer.example'], 'required_checks': list(CHECKS),
        'maximum_evidence_age_seconds': 120, 'require_payment_recipient_binding': True}
    context = {'version': 1, 'profile': PROFILE, 'merchant_domain': 'merchant.example',
        'operation': 'payment', 'tool_id': 'example.pay_invoice',
        'call_id': 'test-call-0001', 'session_binding': 'test-session-do-not-use-live',
        'request_nonce': 'JODaoPtibV_aEX41OP57_g',
        'parameters': {'recipient': {'scheme': 'example-provider-token', 'identifier': 'TEST-PAYEE-0001'},
                       'amount_minor': '25000', 'currency': 'USD', 'invoice_id': 'TEST-INVOICE-0001'}}
    payload = {'iss': 'verifier.example', 'sub': 'merchant.example',
        'aud': 'https://gateway.example/merchant-gate', 'iat': now, 'exp': now + 120,
        'jti': '7e2baf639f304547b090f0d3a7f9c269', 'mia_profile': PROFILE,
        'nonce': context['request_nonce'], 'mia_verified': True,
        'mia_subject': mia['subject'], 'mia_issued_at': mia['issuedAt'],
        'mia_issuer_domain': mia['issuer']['domain'], 'mia_digest': digest(mia),
        'criteria_id': criteria['id'], 'criteria_digest': digest(criteria),
        'request_digest': digest(context), 'checks': {k: 'pass' for k in CHECKS},
        'result': 'pass', 'reason_codes': [], 'evidence_checked_at': now - 10}
    token = sign_ert(payload, checker)
    appraisal = sign_appraisal({'version': 1, 'type': 'MerchantVerificationAppraisal-v1',
        'id': 'urn:uuid:80957119-0fd9-4b88-8a7d-d4a3425fc482',
        'condition': {'id': criteria['id'], 'digest': digest(criteria)},
        'subject': {'id': 'https://merchant.example/.well-known/merchant-identity.json', 'digest': digest(mia)},
        'issuer': 'verifier.example', 'issuer_key_id': 'fixture-verifier-1',
        'signature_algorithm': 'Ed25519', 'issued_at': now,
        'outcome_vocabulary': PROFILE + '#outcomes', 'outcome': 'pass',
        'checks': payload['checks'], 'request_digest': digest(context),
        'ert_digest': token_digest(token)}, checker)
    reference = {'rel': 'condition-appraisal', 'id': appraisal['id'],
        'resolver': 'https://verifier.example/appraisals', 'retention': 'P90D',
        'digest': digest(appraisal)}
    for name, value in [('merchant.mia.json', mia), ('merchant.midd.json', midd),
                         ('fixture-public-keys.json', keys), ('criteria.json', criteria),
                         ('request-context.json', context), ('ert-payload.json', payload),
                         ('merchant-appraisal.json', appraisal), ('trace-reference.json', reference)]:
        write(name, value)
    write('fixture-info.json', {'evaluation_time': now,
        'notice': 'SYNTHETIC TEST DATA. Predictable public signing keys. No real merchant checks or payment.',
        'audience': payload['aud'], 'source_checks': 'simulated; not independent business or bank verification',
        'trace_reference': 'fragment only, not a complete TRACE record'})
    (ROOT / 'examples' / 'ert.jwt').write_text(token + '\n')
    print('Generated signed synthetic MIA, MIDD, ERT, appraisal, and TRACE reference fragment.')


if __name__ == '__main__':
    main()
