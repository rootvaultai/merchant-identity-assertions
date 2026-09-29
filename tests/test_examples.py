"""Apache-2.0. Negative cases for the offline MIA-RT1 example gate."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from fixture_crypto import (load, demo_key, sign_ert, sign_appraisal, digest,
                            strict_json, canonical, b64, unb64)
from demo_verifier import (FixtureGateway, fixture_inputs, verify_appraisal,
                           verify_assertion, schema_check)


class ProfileFixtures(unittest.TestCase):
    def setUp(self):
        self.mia, self.context, self.criteria, self.token, self.keys, self.info = fixture_inputs()
        self.now = self.info['evaluation_time']
        self.gateway = FixtureGateway(self.keys, self.info['audience'])
        self.payload = load('ert-payload.json')

    def accept(self, token=None, **kwargs):
        values = dict(mia=self.mia, context=self.context, criteria=self.criteria, now=self.now)
        values.update(kwargs)
        return self.gateway.accept(token or self.token, **values)

    def signed_change(self, **kwargs):
        p = copy.deepcopy(self.payload)
        p.update(kwargs)
        return sign_ert(p, demo_key('verifier'))

    def test_valid_fixture_and_atomic_single_process_consumption(self):
        self.assertEqual(self.accept()['decision'], 'allow')
        with self.assertRaisesRegex(ValueError, 'replay'):
            self.accept()

    def test_wrong_audience(self):
        with self.assertRaisesRegex(ValueError, 'audience'):
            self.accept(self.signed_change(aud='https://other.example/gate'))

    def test_altered_signature(self):
        p = self.token.split('.')
        sig = bytearray(unb64(p[2])); sig[0] ^= 1
        with self.assertRaises(Exception):
            self.accept('.'.join(p[:2] + [b64(bytes(sig))]))

    def test_untrusted_signer(self):
        with self.assertRaisesRegex(ValueError, 'untrusted'):
            self.accept(sign_ert(self.payload, demo_key('attacker'), kid='unknown-key'))

    def test_forgery_with_trusted_key_id(self):
        with self.assertRaises(Exception):
            self.accept(sign_ert(self.payload, demo_key('attacker')))

    def test_merchant_substitution(self):
        c = copy.deepcopy(self.context); c['merchant_domain'] = 'attacker.example'
        with self.assertRaisesRegex(ValueError, 'merchant'):
            self.accept(context=c)

    def test_recipient_substitution(self):
        c = copy.deepcopy(self.context); c['parameters']['recipient']['identifier'] = 'OTHER-PAYEE'
        with self.assertRaisesRegex(ValueError, 'request'):
            self.accept(context=c)

    def test_amount_substitution(self):
        c = copy.deepcopy(self.context); c['parameters']['amount_minor'] = '2500000'
        with self.assertRaisesRegex(ValueError, 'request'):
            self.accept(context=c)

    def test_session_substitution(self):
        c = copy.deepcopy(self.context); c['session_binding'] = 'another-session'
        with self.assertRaisesRegex(ValueError, 'request'):
            self.accept(context=c)

    def test_wrong_challenge(self):
        with self.assertRaisesRegex(ValueError, 'challenge'):
            self.accept(self.signed_change(nonce='AzjLOFFSFclPXcpEhz03Vw'))

    def test_expiry_boundary(self):
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.accept(now=self.payload['exp'])

    def test_oversized_lifetime(self):
        with self.assertRaisesRegex(ValueError, 'lifetime'):
            self.accept(self.signed_change(exp=self.now + 301))

    def test_stale_evidence(self):
        with self.assertRaisesRegex(ValueError, 'stale'):
            self.accept(self.signed_change(evidence_checked_at=self.now - 121))

    def test_signed_revocation_blocks(self):
        checks = dict(self.payload['checks']); checks['revocation'] = 'fail'
        with self.assertRaisesRegex(ValueError, 'did not pass'):
            self.accept(self.signed_change(checks=checks, result='fail', reason_codes=['revoked']))

    def test_signed_indeterminate_blocks(self):
        checks = dict(self.payload['checks']); checks['identity_evidence'] = 'indeterminate'
        with self.assertRaisesRegex(ValueError, 'did not pass'):
            self.accept(self.signed_change(checks=checks, result='indeterminate', reason_codes=['evidence_unavailable']))

    def test_falsely_overall_pass_does_not_override_failed_check(self):
        checks = dict(self.payload['checks']); checks['payment_recipient_binding'] = 'fail'
        with self.assertRaisesRegex(ValueError, 'did not pass'):
            self.accept(self.signed_change(checks=checks))

    def test_changed_assertion(self):
        m = copy.deepcopy(self.mia); m['legalName'] = 'Different Merchant'
        with self.assertRaisesRegex(ValueError, 'assertion binding'):
            self.accept(mia=m)

    def test_downgraded_criteria(self):
        c = copy.deepcopy(self.criteria); c['require_payment_recipient_binding'] = False
        c['required_checks'].remove('payment_recipient_binding')
        token = self.signed_change(criteria_digest=digest(c))
        with self.assertRaisesRegex(ValueError, 'recipient check omitted'):
            self.accept(token, criteria=c)

    def test_missing_runtime_claim_rejected(self):
        p = dict(self.payload); del p['request_digest']
        with self.assertRaises(Exception):
            self.accept(sign_ert(p, demo_key('verifier')))

    def test_wrong_token_type(self):
        with self.assertRaisesRegex(ValueError, 'header'):
            self.accept(sign_ert(self.payload, demo_key('verifier'), header={'alg':'EdDSA','typ':'JWT','kid':'fixture-verifier-1'}))

    def test_injected_remote_key_header(self):
        with self.assertRaisesRegex(ValueError, 'header'):
            self.accept(sign_ert(self.payload, demo_key('verifier'), header={'alg':'EdDSA','typ':'mia-runtime-ert+jwt','kid':'fixture-verifier-1','jku':'https://attacker.example/keys'}))

    def test_rejection_does_not_consume_valid_receipt(self):
        with self.assertRaises(ValueError):
            self.accept(self.signed_change(aud='wrong'))
        self.assertEqual(self.accept()['decision'], 'allow')

    def test_core_signature_and_merchant_delegation(self):
        keys = load('fixture-public-keys.json')
        verify_assertion(self.mia, keys['issuer.example'], 'merchant.example', self.now)
        midd = load('merchant.midd.json')
        verify_assertion(midd, keys['merchant.example'], 'merchant.example', self.now, delegation=True)
        self.assertEqual(midd['authorizedIssuer'], self.mia['issuer']['domain'])

    def test_proof_timestamp_must_match(self):
        m = copy.deepcopy(self.mia); m['proof']['created'] = '2026-09-27T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'consistency'):
            verify_assertion(m, load('fixture-public-keys.json')['issuer.example'], 'merchant.example', self.now)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            strict_json('{"result":"fail","result":"pass"}')

    def test_jcs_uses_utf16_key_order(self):
        self.assertEqual(canonical({'\ue000':1,'\U0001f600':2}), '{"😀":2,"\ue000":1}'.encode())

    def test_valid_appraisal_and_reference(self):
        result = verify_appraisal(load('merchant-appraisal.json'), load('trace-reference.json'), self.token, self.mia, self.criteria, self.context, self.keys)
        self.assertTrue(result['appraisal_signature_valid'])
        self.assertFalse(result['external_evidence_attested'])

    def test_altered_appraisal_even_with_updated_pointer(self):
        a = load('merchant-appraisal.json'); a['outcome'] = 'fail'
        r = load('trace-reference.json'); r['digest'] = digest(a)
        with self.assertRaises(Exception):
            verify_appraisal(a, r, self.token, self.mia, self.criteria, self.context, self.keys)

    def test_appraisal_disagrees_with_token(self):
        a = load('merchant-appraisal.json'); a.pop('signature'); a['outcome'] = 'fail'
        a = sign_appraisal(a, demo_key('verifier'))
        r = load('trace-reference.json'); r['digest'] = digest(a)
        with self.assertRaisesRegex(ValueError, 'disagree'):
            verify_appraisal(a, r, self.token, self.mia, self.criteria, self.context, self.keys)

    def test_unresolved_reference_does_not_authorize_payment(self):
        # There is no complete TRACE verifier here. A reference alone cannot be
        # substituted for a runtime receipt, whether resolvable or otherwise.
        import json
        with self.assertRaises(ValueError):
            self.accept(json.dumps(load('trace-reference.json')))


if __name__ == '__main__':
    unittest.main()
