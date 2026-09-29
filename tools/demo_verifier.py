"""Apache-2.0. Offline profile example. No network, payment, or cMCP implementation.

Business records, issuer authorization, and recipient ownership are synthetic
fixtures. The checker result must be trusted independently. This is not a
production verification service or a distributed idempotency implementation.
"""
from datetime import datetime
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from fixture_crypto import (ROOT, PROFILE, CHECKS, strict_json, canonical,
                            digest, token_digest, unb64, load)


def schema_check(name, value):
    schema = strict_json((ROOT / 'schemas' / (name + '.schema.json')).read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def instant(value):
    return int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())


def public_key(jwk):
    if jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519' or jwk.get('use') != 'sig' or 'd' in jwk:
        raise ValueError('invalid verification key')
    return Ed25519PublicKey.from_public_bytes(unb64(jwk['x']))


def verify_assertion(obj, jwk, expected_domain, now, delegation=False):
    schema_check('midd-v1' if delegation else 'mia-v1', obj)
    if obj['subject'] != expected_domain:
        raise ValueError('merchant domain mismatch')
    proof = obj['proof']
    directory, kid = proof['verificationMethod'].rsplit('#', 1)
    parsed = urlsplit(directory)
    expected_host = obj['subject'] if delegation else obj['issuer']['domain']
    if parsed.scheme != 'https' or parsed.hostname != expected_host or parsed.username or parsed.password or parsed.query or parsed.port not in (None, 443):
        raise ValueError('key directory origin mismatch')
    if not delegation and directory != obj['issuer']['keyDirectory']:
        raise ValueError('key directory mismatch')
    if kid != jwk['kid'] or proof['created'] != obj['issuedAt']:
        raise ValueError('proof consistency mismatch')
    if not instant(obj['issuedAt']) <= now < instant(obj['expiresAt']):
        raise ValueError('assertion outside validity interval')
    public_key(jwk).verify(unb64(proof['proofValue']), canonical({k: v for k, v in obj.items() if k != 'proof'}))


def verify_token(token, trusted_keys):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('not a compact JWS')
    header, payload = [strict_json(unb64(p)) for p in parts[:2]]
    if set(header) != {'alg', 'typ', 'kid'} or header['alg'] != 'EdDSA' or header['typ'] != 'mia-runtime-ert+jwt':
        raise ValueError('unsupported runtime ERT header')
    if not isinstance(payload, dict):
        raise ValueError('payload must be an object')
    jwk = trusted_keys.get((payload.get('iss'), header.get('kid')))
    if jwk is None:
        raise ValueError('untrusted verifier issuer/key pair')
    public_key(jwk).verify(unb64(parts[2]), (parts[0] + '.' + parts[1]).encode('ascii'))
    schema_check('ert-rt1-payload', payload)
    return payload


class FixtureGateway:
    """Single-process example gate; consumption simulates dispatch, never pays."""
    def __init__(self, keys, audience):
        self.keys = keys
        self.audience = audience
        self.consumed = set()

    def accept(self, token, mia, context, criteria, now):
        schema_check('mia-v1', mia)
        schema_check('request-context-rt1', context)
        schema_check('criteria-rt1', criteria)
        p = verify_token(token, self.keys)
        if p['aud'] != self.audience:
            raise ValueError('wrong audience')
        if p['sub'] != context['merchant_domain'] or p.get('mia_subject') != context['merchant_domain']:
            raise ValueError('merchant mismatch')
        if p['nonce'] != context['request_nonce'] or p['request_digest'] != digest(context):
            raise ValueError('request or challenge mismatch')
        if p['mia_digest'] != digest(mia) or p.get('mia_issuer_domain') != mia['issuer']['domain'] or p.get('mia_issued_at') != mia['issuedAt']:
            raise ValueError('assertion binding mismatch')
        if p['criteria_id'] != criteria['id'] or p['criteria_digest'] != digest(criteria):
            raise ValueError('criteria mismatch')
        if mia['issuer']['domain'] not in criteria['accepted_mia_issuers']:
            raise ValueError('merchant issuer not accepted')
        if not 0 < p['exp'] - p['iat'] <= 300 or p['iat'] > now + 30 or now >= p['exp']:
            raise ValueError('token expired or invalid lifetime')
        if not instant(mia['issuedAt']) <= now < instant(mia['expiresAt']) or p['exp'] > instant(mia['expiresAt']):
            raise ValueError('assertion expired or token outlives assertion')
        evidence_time = p['evidence_checked_at']
        if evidence_time is None or evidence_time > now + 30 or evidence_time > p['iat'] or now - evidence_time > criteria['maximum_evidence_age_seconds']:
            raise ValueError('evidence unavailable or stale')
        required = set(criteria['required_checks'])
        if not set(CHECKS[:6]).issubset(required):
            raise ValueError('required core check omitted')
        if context['operation'] == 'payment':
            if not criteria['require_payment_recipient_binding'] or 'payment_recipient_binding' not in required:
                raise ValueError('payment recipient check omitted')
        if not p['mia_verified'] or p['result'] != 'pass' or any(p['checks'][k] != 'pass' for k in required):
            raise ValueError('merchant verification did not pass')
        identity = (p['iss'], p['aud'], p['jti'])
        if identity in self.consumed:
            raise ValueError('replay rejected')
        self.consumed.add(identity)
        return {'decision': 'allow', 'mode': 'offline-simulation', 'call_id': context['call_id']}


def verify_appraisal(appraisal, reference, token, mia, criteria, context, trusted_keys):
    schema_check('merchant-verification-appraisal-v1', appraisal)
    if reference['rel'] != 'condition-appraisal' or reference['id'] != appraisal['id'] or reference['digest'] != digest(appraisal):
        raise ValueError('reference does not identify this signed appraisal')
    key = trusted_keys.get((appraisal['issuer'], appraisal['issuer_key_id']))
    if key is None:
        raise ValueError('untrusted appraisal key')
    public_key(key).verify(unb64(appraisal['signature']), canonical({k: v for k, v in appraisal.items() if k != 'signature'}))
    payload = verify_token(token, trusted_keys)
    if appraisal['subject']['digest'] != digest(mia) or appraisal['condition'] != {'id': criteria['id'], 'digest': digest(criteria)}:
        raise ValueError('appraisal subject or condition mismatch')
    if appraisal['request_digest'] != digest(context) or appraisal['ert_digest'] != token_digest(token):
        raise ValueError('appraisal request or token mismatch')
    if appraisal['issuer'] != payload['iss'] or appraisal['outcome'] != payload['result'] or appraisal['checks'] != payload['checks']:
        raise ValueError('appraisal and token disagree')
    return {'appraisal_signature_valid': True, 'external_evidence_attested': False}


def fixture_inputs():
    keys = load('fixture-public-keys.json')
    return (load('merchant.mia.json'), load('request-context.json'), load('criteria.json'),
            (ROOT / 'examples' / 'ert.jwt').read_text().strip(),
            {('verifier.example', keys['verifier.example']['kid']): keys['verifier.example']},
            load('fixture-info.json'))


def main():
    mia, context, criteria, token, keys, info = fixture_inputs()
    all_keys = load('fixture-public-keys.json')
    verify_assertion(mia, all_keys['issuer.example'], context['merchant_domain'], info['evaluation_time'])
    midd = load('merchant.midd.json')
    verify_assertion(midd, all_keys['merchant.example'], context['merchant_domain'], info['evaluation_time'], delegation=True)
    if midd['authorizedIssuer'] != mia['issuer']['domain']:
        raise ValueError('merchant delegation mismatch')
    gateway = FixtureGateway(keys, info['audience'])
    print(gateway.accept(token, mia, context, criteria, info['evaluation_time']))
    print(verify_appraisal(load('merchant-appraisal.json'), load('trace-reference.json'), token, mia, criteria, context, keys))
    try:
        gateway.accept(token, mia, context, criteria, info['evaluation_time'])
    except ValueError as err:
        print(str(err))
    print('Fixture checks complete. No real merchant, payment, hardware, or upstream runtime was contacted.')


if __name__ == '__main__':
    main()
