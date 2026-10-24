"""Access-control regressions on disposable SQLite and attachment storage."""
import hashlib
import hmac
import io
import json
import secrets
import subprocess
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import func, select

from investigator_auth import (
    COOKIE_NAME, SESSION_TTL, AuthConfig, InvestigatorAuth, get_auth_service, proof_message,
)
from models import Case, CaseAttachment, CaseHistoryEvent, CaseMessage, Investigator
from test_support import ORIGIN, WRITE_HEADERS, isolated_api, login, signed_case, signed_reply, encoded

ROOT = Path(__file__).resolve().parent


class InvestigatorAccessTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.context = isolated_api(clock=lambda: self.now)
        self.f = self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.client = self.f.reporter
        self.case_id = str(uuid.uuid4())
        self.token = encoded(secrets.token_bytes(32))
        self.f.case_token = self.token
        self.public_key = self.client.get('/api/v1/investigators/public-key').json()['publicKey']
        res = self.client.post('/api/v1/cases', json=self.case_payload())
        self.assertEqual(res.status_code, 201, res.text)

    def case_payload(self, **changes):
        return signed_case(self.f, caseId=changes.pop('caseId', self.case_id),
                           caseAccessTokenHash=changes.pop('caseAccessTokenHash', self.token), **changes)

    def reply(self, **changes):
        return signed_reply(self.f, self.case_id, **changes)

    @property
    def thread_url(self):
        return f'/api/v1/investigators/cases/{self.case_id}/messages'

    def snapshot(self):
        with self.f.sessions() as db:
            return (db.get(Case, self.case_id).status.value,
                    db.scalar(select(func.count()).select_from(CaseMessage)),
                    db.scalar(select(func.count()).select_from(CaseHistoryEvent)),
                    db.scalar(select(func.count()).select_from(CaseAttachment)))

    def sign_in(self):
        res = login(self.f)
        self.assertEqual(res.status_code, 200, res.text)
        return res

    def test_anonymous_reads_and_forged_cookie_rejected(self):
        for path in ('/api/v1/investigators/cases', '/api/v1/investigators/account',
                     '/api/v1/investigators/auth/session', self.thread_url):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)
        self.client.cookies.set(COOKIE_NAME, secrets.token_urlsafe(32), path='/api/v1')
        self.assertEqual(self.client.get('/api/v1/investigators/cases').status_code, 401)

    def test_anonymous_reply_cannot_change_status_messages_or_audit(self):
        before = self.snapshot()
        res = self.client.post(self.thread_url, json=self.reply(), headers=WRITE_HEADERS)
        self.assertEqual(res.status_code, 401)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(before[:2], ('OPEN', 0))

    def test_wrong_key_and_wrong_username_rejected(self):
        self.assertEqual(login(self.f, key=secrets.token_bytes(32)).status_code, 401)
        self.assertEqual(login(self.f, username='someone-else').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/investigators/cases').status_code, 401)

    def test_challenge_one_use_expiry_and_origin_binding(self):
        def challenge():
            data = self.client.post('/api/v1/investigators/auth/challenge', headers=WRITE_HEADERS,
                                    json={'username': self.f.username}).json()
            proof = hmac.new(self.f.key, proof_message(data['challengeId'], data['nonce'],
                              self.f.username, ORIGIN), hashlib.sha256).hexdigest()
            return {'username': self.f.username, 'challengeId': data['challengeId'], 'proof': proof}

        payload = challenge()
        self.assertEqual(self.client.post('/api/v1/investigators/auth/session', json=payload,
                                         headers=WRITE_HEADERS).status_code, 200)
        self.assertEqual(self.client.post('/api/v1/investigators/auth/session', json=payload,
                                         headers=WRITE_HEADERS).status_code, 401)
        payload = challenge()
        self.now += 61
        self.assertEqual(self.client.post('/api/v1/investigators/auth/session', json=payload,
                                         headers=WRITE_HEADERS).status_code, 401)
        payload = challenge()
        other_origin = {**WRITE_HEADERS, 'Origin': 'http://127.0.0.1:3000'}
        self.assertEqual(self.client.post('/api/v1/investigators/auth/session', json=payload,
                                         headers=other_origin).status_code, 401)
        payload = challenge()
        invalid = {**payload, 'proof': secrets.token_hex(32)}
        self.assertEqual(self.client.post('/api/v1/investigators/auth/session', json=invalid,
                                         headers=WRITE_HEADERS).status_code, 401)
        self.assertEqual(self.client.post('/api/v1/investigators/auth/session', json=payload,
                                         headers=WRITE_HEADERS).status_code, 401)

    def test_cookie_flags_no_token_json_and_logout_revocation(self):
        response = self.sign_in()
        cookie = response.headers['set-cookie'].lower()
        for expected in ('httponly', 'samesite=strict', 'path=/api/v1', 'max-age=3600'):
            self.assertIn(expected, cookie)
        self.assertNotIn('domain=', cookie)
        self.assertEqual(set(response.json()), {'username', 'expiresIn'})
        self.assertEqual(response.headers['cache-control'], 'no-store')
        old_cookie = self.client.cookies.get(COOKIE_NAME)
        res = self.client.delete('/api/v1/investigators/auth/session', headers=WRITE_HEADERS)
        self.assertEqual(res.status_code, 204)
        self.assertFalse(self.f.auth.is_authenticated(old_cookie))
        self.assertEqual(self.client.get('/api/v1/investigators/cases').status_code, 401)

    def test_session_expiry_and_rotation_revoke_old_token(self):
        self.sign_in()
        token = self.client.cookies.get(COOKIE_NAME)
        self.sign_in()
        self.assertFalse(self.f.auth.is_authenticated(token))
        self.now += SESSION_TTL
        self.assertEqual(self.client.get('/api/v1/investigators/cases').status_code, 401)

    def test_secure_cookie_option_and_cors_rejection(self):
        with patch.dict('os.environ', {'SEALED_COOKIE_SECURE': 'true'}):
            response = self.sign_in()
        self.assertIn('secure', response.headers['set-cookie'].lower())
        response = self.client.options('/api/v1/investigators/auth/session', headers={
            'Origin': 'https://untrusted.example', 'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'X-Sealed-Request,Content-Type',
        })
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('access-control-allow-origin', response.headers)

    def test_deleted_account_cannot_use_session_or_sign_in(self):
        self.sign_in()
        with self.f.sessions() as db:
            db.delete(db.scalar(select(Investigator)))
            db.commit()
        self.assertEqual(self.client.get('/api/v1/investigators/cases').status_code, 401)
        self.assertEqual(login(self.f).status_code, 401)

    def test_csrf_rejection_is_independent_of_valid_cookie(self):
        self.sign_in()
        before = self.snapshot()
        for headers in ({}, {'Origin': ORIGIN}, {'X-Sealed-Request': '1'},
                        {**WRITE_HEADERS, 'Origin': 'https://untrusted.example'},
                        {**WRITE_HEADERS, 'Origin': 'null'},
                        {**WRITE_HEADERS, 'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.client.post(self.thread_url, json=self.reply(),
                                                 headers=headers).status_code, 403)
                self.assertEqual(self.client.delete('/api/v1/investigators/auth/session',
                                                   headers=headers).status_code, 403)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.client.get('/api/v1/investigators/cases').status_code, 200)

    def test_login_requires_csrf_and_rejects_password_fields(self):
        for headers in ({}, {'Origin': ORIGIN}, {**WRITE_HEADERS, 'Origin': 'https://evil.example'}):
            self.assertEqual(self.client.post('/api/v1/investigators/auth/challenge', headers=headers,
                             json={'username': self.f.username}).status_code, 403)
        self.assertEqual(self.client.post('/api/v1/investigators/auth/challenge', headers=WRITE_HEADERS,
                         json={'username': self.f.username, 'password': 'not-accepted'}).status_code, 422)

    def test_login_throttle_cannot_be_bypassed_with_forwarded_header(self):
        for index in range(15):
            res = self.client.post('/api/v1/investigators/auth/challenge',
                headers={**WRITE_HEADERS, 'X-Forwarded-For': f'192.0.2.{index}'},
                json={'username': self.f.username})
            self.assertEqual(res.status_code, 200)
        res = self.client.post('/api/v1/investigators/auth/challenge',
            headers={**WRITE_HEADERS, 'X-Forwarded-For': '198.51.100.99'}, json={'username': self.f.username})
        self.assertEqual(res.status_code, 429)

    def test_authorized_reads_and_reply_but_not_other_account_or_reply_key(self):
        self.sign_in()
        self.assertEqual(self.client.get('/api/v1/investigators/cases').status_code, 200)
        self.assertEqual(self.client.get(self.thread_url).json(), [])
        self.assertEqual(self.client.get('/api/v1/investigators/account').status_code, 200)
        self.assertEqual(self.client.get('/api/v1/investigators/account?username=other').status_code, 403)
        before = self.snapshot()
        self.assertEqual(self.client.post(self.thread_url, headers=WRITE_HEADERS,
            json=self.reply(caseId=str(uuid.uuid4()))).status_code, 400)
        self.assertEqual(self.client.post(self.thread_url, headers=WRITE_HEADERS,
            json=self.reply(investigatorPublicKey='other-key')).status_code, 403)
        self.assertEqual(self.snapshot(), before)
        res = self.client.post(self.thread_url, headers=WRITE_HEADERS, json=self.reply())
        self.assertEqual(res.status_code, 201, res.text)
        self.assertEqual(self.snapshot()[:2], ('RESPONDED', 1))

    def test_public_reporter_workflows_remain_independent(self):
        self.assertEqual(self.client.get('/api/v1/investigators/public-key').status_code, 200)
        self.assertEqual(self.client.post('/api/v1/cases/lookup',
            json={'caseAccessTokenHash': self.token}).status_code, 200)
        self.assertEqual(self.client.post(f'/api/v1/cases/{self.case_id}/access',
            json={'caseAccessTokenHash': 'wrong'}).status_code, 422)
        reply = signed_reply(self.f, self.case_id, 'REPORTER')
        res = self.client.post('/api/v1/cases/messages', json=reply)
        self.assertEqual(res.status_code, 201, res.text)
        self.assertEqual(res.json()['sender'], 'REPORTER')
        self.assertEqual(self.snapshot()[:2], ('OPEN', 1))
        bad = {**reply, 'caseAccessTokenHash': 'wrong'}
        self.assertEqual(self.client.post(f'/api/v1/cases/{self.case_id}/messages', json=bad).status_code, 422)

    def test_case_attachment_authorization_and_no_reassignment(self):
        files = {'file': ('evidence.enc', b'ciphertext', 'application/octet-stream')}
        data = {'case_id': self.case_id}
        before = self.snapshot()
        self.assertEqual(self.client.post('/api/v1/cases/attachments', files=files, data=data).status_code, 401)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(self.f.storage.iterdir()), [])
        for token in ('wrong', ''):
            res = self.client.post('/api/v1/cases/attachments', files=files,
                                  data={**data, 'case_access_token_hash': token})
            self.assertIn(res.status_code, (401, 403, 422))
        other_token = encoded(secrets.token_bytes(32))
        other_case = self.client.post('/api/v1/cases', json=self.case_payload(
            caseId=str(uuid.uuid4()), caseAccessTokenHash=other_token))
        self.assertEqual(other_case.status_code, 201)
        self.assertEqual(self.client.post('/api/v1/cases/attachments', files=files,
            data={**data, 'case_access_token_hash': other_token}).status_code, 403)
        res = self.client.post('/api/v1/cases/attachments', files=files,
                              data={**data, 'case_access_token_hash': self.token})
        self.assertEqual(res.status_code, 201, res.text)
        attachment_id = res.json()['attachmentId']
        self.sign_in()
        self.assertEqual(self.client.post('/api/v1/cases/attachments', files=files,
                                         data=data).status_code, 403)
        self.assertEqual(self.client.post('/api/v1/cases/attachments', files=files,
            data={**data, 'case_access_token_hash': 'wrong'}, headers=WRITE_HEADERS).status_code, 422)
        self.assertEqual(self.client.post('/api/v1/cases/attachments', files=files,
                                         data=data, headers=WRITE_HEADERS).status_code, 201)
        new_id = str(uuid.uuid4())
        res = self.client.post('/api/v1/cases', json=self.case_payload(
            caseId=new_id, caseAccessTokenHash=encoded(secrets.token_bytes(32)), attachmentIds=[attachment_id]))
        self.assertEqual(res.status_code, 403)
        with self.f.sessions() as db:
            self.assertIsNone(db.get(Case, new_id))
            self.assertIsNone(db.get(CaseAttachment, attachment_id).case_id)  # staged until a signed reply commits
        # Anonymous staging + initial report attachment linking still works.
        staging_token = encoded(secrets.token_bytes(32))
        staged = self.client.post('/api/v1/cases/attachments', files=files, data={'staging_token': staging_token}).json()['attachmentId']
        res = self.client.post('/api/v1/cases', json=self.case_payload(
            caseId=new_id, caseAccessTokenHash=staging_token, attachmentIds=[staged]))
        self.assertEqual(res.status_code, 201, res.text)

    def test_missing_config_fails_closed_and_restart_loses_sessions(self):
        from main import app
        empty = InvestigatorAuth(None)
        app.dependency_overrides[get_auth_service] = lambda: empty
        self.assertEqual(self.client.post('/api/v1/investigators/auth/challenge', headers=WRITE_HEADERS,
            json={'username': self.f.username}).status_code, 503)
        self.assertEqual(self.client.get('/api/v1/investigators/cases').status_code, 401)
        token = self.f.auth.create_session()
        restarted = InvestigatorAuth(AuthConfig(self.f.username, self.f.key))
        self.assertFalse(restarted.is_authenticated(token))

    def test_real_frontend_crypto_authenticated_round_trip(self):
        def crypto_step(operation, **payload):
            process = subprocess.run(
                ['node', str(ROOT / 'node_modules/tsx/dist/cli.mjs'), str(ROOT / 'tests/frontend_crypto.ts')],
                input=json.dumps({'operation': operation, **payload}), text=True,
                capture_output=True, cwd=ROOT, timeout=45,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            return json.loads(process.stdout)

        fixture = crypto_step('create', username=self.f.username)
        self.f.frontend_fixture = fixture
        account = fixture['account']
        from models import InvestigatorIdentity
        with self.f.sessions() as db:
            for row in db.scalars(select(InvestigatorIdentity)):
                row.active = 0
            db.add(InvestigatorIdentity(signing_public_key=account['signingPublicKey'],
                public_key=account['publicKey'], investigator_id=db.scalar(select(Investigator)).id,
                identity_signature=account['identitySignature'], encrypted_bundle=json.dumps(account), active=1))
            db.commit()
        res = self.client.post('/api/v1/cases', json=fixture['case'])
        self.assertEqual(res.status_code, 201, res.text)
        case_id = res.json()['caseId']
        # Exercise the actual browser WebCrypto proof implementation too.
        challenge = self.client.post('/api/v1/investigators/auth/challenge', headers=WRITE_HEADERS,
                                     json={'username': self.f.username}).json()
        proof = crypto_step('proof', accessKey=self.f.key.hex(), username=self.f.username,
                            origin=ORIGIN, **challenge)['proof']
        res = self.client.post('/api/v1/investigators/auth/session', headers=WRITE_HEADERS,
            json={'username': self.f.username, 'challengeId': challenge['challengeId'], 'proof': proof})
        self.assertEqual(res.status_code, 200, res.text)
        account = self.client.get('/api/v1/investigators/identities').json()[0]
        cases = self.client.get('/api/v1/investigators/cases').json()
        case = next(item for item in cases if item['id'] == case_id)
        encrypted_reply = crypto_step('investigator', fixture=fixture, account=account, case=case)
        res = self.client.post(f'/api/v1/investigators/cases/{case_id}/messages',
                              headers=WRITE_HEADERS, json=encrypted_reply)
        self.assertEqual(res.status_code, 201, res.text)
        self.client.cookies.clear()
        track = self.client.post('/api/v1/cases/lookup', json={
            'caseAccessTokenHash': fixture['case']['caseAccessTokenHash']})
        self.assertEqual(track.status_code, 200, track.text)
        self.assertEqual(track.json()['status'], 'RESPONDED')
        followup = crypto_step('reporter', fixture=fixture, message=track.json()['messages'][0])
        self.assertEqual(self.client.post('/api/v1/cases/messages', json=followup).status_code, 201)
        self.sign_in()
        messages = self.client.get(f'/api/v1/investigators/cases/{case_id}/messages').json()
        result = crypto_step('read-followup', fixture=fixture, account=account, message=messages[-1])
        self.assertTrue(result['ok'])


class LocalProvisioningTests(unittest.TestCase):
    def test_provision_rotation_and_real_config_loader_preserve_encryption_record(self):
        from configure_investigator_access import main as configure
        from main import app
        with isolated_api() as fixture:
            attributes = ('public_key', 'encrypted_private_key', 'private_key_nonce', 'kdf_salt',
                          'kdf_ops_limit', 'kdf_mem_limit', 'kdf_algorithm')
            with fixture.sessions() as db:
                record = db.scalar(select(Investigator))
                original = tuple(getattr(record, name) for name in attributes)
            path = fixture.storage / 'access.json'
            args = ['configure_investigator_access.py', '--username', fixture.username]
            with patch.dict('os.environ', {'SEALED_AUTH_FILE': str(path)}), redirect_stdout(io.StringIO()):
                with patch('sys.argv', args):
                    configure()
                first = json.loads(path.read_text())
                self.assertEqual(len(bytes.fromhex(first['accessKey'])), 32)
                with patch('sys.argv', args), redirect_stdout(io.StringIO()), patch('sys.stderr', io.StringIO()):
                    with self.assertRaises(SystemExit):
                        configure()
                self.assertEqual(json.loads(path.read_text()), first)
                get_auth_service.cache_clear()
                try:
                    service = get_auth_service()
                    app.dependency_overrides[get_auth_service] = lambda: service
                    self.assertEqual(login(fixture, key=bytes.fromhex(first['accessKey'])).status_code, 200)
                    with patch('sys.argv', [*args, '--rotate']):
                        configure()
                    second = json.loads(path.read_text())
                    self.assertNotEqual(first['accessKey'], second['accessKey'])
                    # Rotation takes effect on restart/cache recreation, not magically in a live worker.
                    get_auth_service.cache_clear()
                    restarted = get_auth_service()
                    self.assertFalse(restarted.is_authenticated(fixture.client.cookies.get(COOKIE_NAME)))
                    app.dependency_overrides[get_auth_service] = lambda: restarted
                    self.assertEqual(login(fixture, key=bytes.fromhex(first['accessKey'])).status_code, 401)
                    self.assertEqual(login(fixture, key=bytes.fromhex(second['accessKey'])).status_code, 200)
                    with fixture.sessions() as db:
                        record = db.scalar(select(Investigator))
                        self.assertEqual(tuple(getattr(record, name) for name in attributes), original)
                finally:
                    get_auth_service.cache_clear()

    def test_invalid_access_file_disables_auth_without_breaking_public_submission(self):
        from main import app
        with isolated_api() as fixture:
            path = fixture.storage / 'invalid.json'
            path.write_text('{bad json')
            with patch.dict('os.environ', {'SEALED_AUTH_FILE': str(path)}):
                get_auth_service.cache_clear()
                try:
                    with self.assertLogs('investigator_auth', level='ERROR'):
                        service = get_auth_service()
                    app.dependency_overrides[get_auth_service] = lambda: service
                    self.assertEqual(fixture.client.get('/api/v1/investigators/cases').status_code, 401)
                    self.assertEqual(fixture.client.get('/api/v1/investigators/public-key').status_code, 200)
                    response = fixture.reporter.post('/api/v1/cases/attachments', files={
                        'file': ('evidence.enc', b'ciphertext', 'application/octet-stream')},
                        data={'staging_token': encoded(secrets.token_bytes(32))})
                    self.assertEqual(response.status_code, 201)
                finally:
                    get_auth_service.cache_clear()


if __name__ == '__main__':
    unittest.main()
