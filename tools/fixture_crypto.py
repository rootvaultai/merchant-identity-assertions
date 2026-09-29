"""Apache-2.0. Cryptographic helpers for public offline fixtures, not an SDK."""
import base64
import hashlib
import json
import re
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
PROFILE = 'https://registeredbrands.ai/profiles/mia-runtime/v1'
CHECKS = ('assertion_signature', 'merchant_domain', 'merchant_authorization',
          'issuer_trust', 'identity_evidence', 'revocation', 'payment_recipient_binding')


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    def bad_constant(value):
        raise ValueError('non-finite JSON value: ' + value)
    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)
    rfc8785.dumps(result)
    return result


def canonical(obj):
    return rfc8785.dumps(obj)


def digest(obj):
    return 'sha256:' + hashlib.sha256(canonical(obj)).hexdigest()


def token_digest(token):
    return 'sha256:' + hashlib.sha256(token.encode('ascii')).hexdigest()


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('noncanonical base64url')
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if b64(raw) != value:
        raise ValueError('noncanonical base64url')
    return raw


def demo_key(label):
    """PUBLIC predictable keys, deliberately unusable for production trust."""
    seed = hashlib.sha256(('MIA PUBLIC TEST KEY ONLY: ' + label).encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_jwk(key, kid):
    return {'kty': 'OKP', 'crv': 'Ed25519', 'use': 'sig', 'kid': kid,
            'x': b64(key.public_key().public_bytes_raw())}


def sign_mia(claims, key, directory, kid):
    return {**claims, 'proof': {'type': 'MerchantIdentityProof-v1', 'alg': 'Ed25519',
            'created': claims['issuedAt'], 'verificationMethod': directory + '#' + kid,
            'proofValue': b64(key.sign(canonical(claims)))}}


def sign_ert(payload, key, kid='fixture-verifier-1', header=None):
    header = header or {'alg': 'EdDSA', 'typ': 'mia-runtime-ert+jwt', 'kid': kid}
    preimage = b64(canonical(header)) + '.' + b64(canonical(payload))
    return preimage + '.' + b64(key.sign(preimage.encode('ascii')))


def sign_appraisal(unsigned, key):
    return {**unsigned, 'signature': b64(key.sign(canonical(unsigned)))}


def load(name):
    return strict_json((ROOT / 'examples' / name).read_text())


def write(name, obj):
    (ROOT / 'examples' / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n')
