"""V2 protocol/security regressions. All storage and keys are disposable."""
import base64
import io
import json
import secrets
import subprocess
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine, func, inspect, select, text

from message_protocol import message_bytes, report_bytes
from migrate_v2 import migrate, require_schema
from models import Case, CaseHistoryEvent, CaseMessage, Investigator, InvestigatorIdentity
from test_support import WRITE_HEADERS, isolated_api, login

ROOT = Path(__file__).resolve().parent


def frontend(operation, **payload):
    result = subprocess.run(['node', str(ROOT / 'node_modules/tsx/dist/cli.mjs'),
                             str(ROOT / 'tests/frontend_crypto.ts')],
                            input=json.dumps(dict(operation=operation, **payload)), cwd=ROOT,
                            capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def install(fixture, packet):
    with fixture.sessions() as db:
        for identity in db.scalars(select(InvestigatorIdentity)):
            identity.active = 0
        db.add(InvestigatorIdentity(signing_public_key=packet['signingPublicKey'], public_key=packet['publicKey'],
            investigator_id=db.scalar(select(Investigator)).id, identity_signature=packet['identitySignature'],
            encrypted_bundle=json.dumps(packet), active=1))
        db.commit()


class MessageProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = frontend('create')
        cls.other_case = frontend('create-case', fixture=cls.fixture)
        cls.rotated = frontend('create')
        cls.reply = frontend('investigator', fixture=cls.fixture, account=cls.fixture['account'],
                             case=dict(cls.fixture['case'], id=cls.fixture['case']['caseId']))
        message = dict(cls.reply, id=cls.reply['messageId'], sender='INVESTIGATOR', senderType='INVESTIGATOR',
                       createdAt='2026-10-18T00:00:00Z')
        cls.followup = frontend('reporter', fixture=cls.fixture, message=message)

    def setUp(self):
        context = isolated_api()
        self.f = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.f.frontend_fixture = self.fixture
        self.client = self.f.reporter
        install(self.f, self.fixture['account'])
        result = self.client.post('/api/v1/cases', json=self.fixture['case'])
        self.assertEqual(result.status_code, 201, result.text)
        self.case_id = result.json()['caseId']
        self.url = f'/api/v1/investigators/cases/{self.case_id}/messages'

    def snapshot(self):
        with self.f.sessions() as db:
            return (db.get(Case, self.case_id).status.value,
                    db.scalar(select(func.count()).select_from(CaseMessage)),
                    db.scalar(select(func.count()).select_from(CaseHistoryEvent)))

    def authenticated(self):
        self.assertEqual(login(self.f).status_code, 200)

    def test_actual_frontend_attacks_and_cross_language_signing_bytes(self):
        result = frontend('security', fixture=self.fixture)
        self.assertTrue(result['ok'])
        self.assertGreaterEqual(result['checks'], 30)
        self.assertEqual(base64.b64decode(result['reportBytes']), report_bytes(self.fixture['case']['manifest']))
        message = result['message']
        self.assertEqual(base64.b64decode(result['messageBytes']), message_bytes(self.fixture['case']['manifest'],
            message['id'], message['sender'], message['nonce'], message['encryptedResponse']))

    def test_real_signed_round_trip_and_public_key(self):
        public = self.client.get('/api/v1/investigators/public-key').json()
        self.assertEqual(public['protocolVersion'], 2)
        self.assertEqual(public['signingPublicKey'], self.fixture['account']['signingPublicKey'])
        self.assertEqual(self.client.get('/api/v1/investigators/identities').status_code, 401)
        self.authenticated()
        result = self.client.post(self.url, json=self.reply, headers=WRITE_HEADERS)
        self.assertEqual(result.status_code, 201, result.text)
        self.client.cookies.clear()
        track = self.client.post('/api/v1/cases/lookup', json={'caseAccessTokenHash': self.fixture['case']['caseAccessTokenHash']})
        self.assertEqual(track.status_code, 200)
        self.assertEqual(track.json()['manifest'], self.fixture['case']['manifest'])
        self.assertFalse(track.json()['readOnly'])
        response = self.client.post('/api/v1/cases/messages', json=self.followup)
        self.assertEqual(response.status_code, 201, response.text)
        frontend('read-followup', fixture=self.fixture, account=self.fixture['account'], message=response.json())

    def test_signature_tampering_and_key_substitution_leave_state_unchanged(self):
        self.authenticated()
        original = self.snapshot()
        ciphertext = bytearray(base64.b64decode(self.reply['encryptedResponse']))
        ciphertext[20] ^= 1
        for change in (
            {'signature': base64.b64encode(secrets.token_bytes(64)).decode()},
            {'nonce': base64.b64encode(secrets.token_bytes(24)).decode()},
            {'encryptedResponse': base64.b64encode(ciphertext).decode()},
            {'investigatorPublicKey': self.rotated['account']['publicKey']},
            {'messageId': str(uuid.uuid4())}, {'protocolVersion': 1}, {'protocolVersion': 99},
        ):
            with self.subTest(change=list(change)):
                result = self.client.post(self.url, json=dict(self.reply, **change), headers=WRITE_HEADERS)
                self.assertIn(result.status_code, (400, 403, 409), result.text)
                self.assertEqual(self.snapshot(), original)

    def test_reflection_in_both_directions_rejected(self):
        self.authenticated()
        original = self.snapshot()
        reflected = dict(self.followup, encryptedResponse=self.followup['encryptedMessage'], caseId=self.case_id)
        self.assertEqual(self.client.post(self.url, json=reflected, headers=WRITE_HEADERS).status_code, 403)
        inverse = dict(self.reply, encryptedMessage=self.reply['encryptedResponse'],
                       caseAccessTokenHash=self.fixture['case']['caseAccessTokenHash'])
        self.assertEqual(self.client.post('/api/v1/cases/messages', json=inverse).status_code, 403)
        self.assertEqual(self.snapshot(), original)

    def test_cross_case_and_outer_report_context_substitution_rejected(self):
        result = self.client.post('/api/v1/cases', json=self.other_case['case'])
        self.assertEqual(result.status_code, 201, result.text)
        other_id = result.json()['caseId']
        self.authenticated()
        original = self.snapshot()
        reply = dict(self.reply, caseId=other_id)
        result = self.client.post(f'/api/v1/investigators/cases/{other_id}/messages', json=reply, headers=WRITE_HEADERS)
        self.assertEqual(result.status_code, 403)
        wrong = dict(self.followup, caseAccessTokenHash=self.other_case['case']['caseAccessTokenHash'])
        self.assertEqual(self.client.post('/api/v1/cases/messages', json=wrong).status_code, 403)
        self.assertEqual(self.snapshot(), original)
        for field, value in (('caseId', str(uuid.uuid4())),
                             ('reporterPublicKey', self.other_case['case']['reporterPublicKey']),
                             ('caseAccessTokenHash', self.other_case['case']['caseAccessTokenHash'])):
            result = self.client.post('/api/v1/cases', json=dict(self.fixture['case'], **{field: value}))
            self.assertIn(result.status_code, (403, 409), result.text)

    def test_replayed_posts_rejected_atomically_without_status_audit_changes(self):
        self.authenticated()
        self.assertEqual(self.client.post(self.url, json=self.reply, headers=WRITE_HEADERS).status_code, 201)
        before = self.snapshot()
        self.assertEqual(self.client.post(self.url, json=self.reply, headers=WRITE_HEADERS).status_code, 409)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.client.post('/api/v1/cases/messages', json=self.followup).status_code, 201)
        before = self.snapshot()
        self.assertEqual(self.client.post('/api/v1/cases/messages', json=self.followup).status_code, 409)
        self.assertEqual(self.snapshot(), before)

    def test_wrong_phrase_credential_and_anonymous_signed_reply_rejected(self):
        self.assertEqual(self.client.post(self.url, json=self.reply, headers=WRITE_HEADERS).status_code, 401)
        result = self.client.post('/api/v1/cases/lookup', json={
            'caseAccessTokenHash': self.other_case['case']['caseAccessTokenHash']})
        self.assertEqual(result.status_code, 404)
        wrong = dict(self.followup, caseAccessTokenHash=self.other_case['case']['caseAccessTokenHash'])
        self.assertEqual(self.client.post(f'/api/v1/cases/{self.case_id}/messages', json=wrong).status_code, 404)
        self.assertEqual(self.snapshot()[:2], ('OPEN', 0))

    def test_initial_signature_and_protocol_downgrades_do_not_create_cases(self):
        before = self.snapshot()
        for modification in (
            {'protocolVersion': 1}, {'protocolVersion': 99},
            {'manifest': {**self.fixture['case']['manifest'],
                          'reportSignature': base64.b64encode(secrets.token_bytes(64)).decode()}},
            {'manifest': {**self.fixture['case']['manifest'],
                          'investigatorSigningPublicKey': self.rotated['account']['signingPublicKey']}},
        ):
            response = self.client.post('/api/v1/cases', json={**self.fixture['case'], **modification})
            self.assertIn(response.status_code, (400, 403, 409))
            self.assertEqual(self.snapshot(), before)
        with self.f.sessions() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Case)), 1)

    def test_legacy_is_readable_explicitly_unverified_and_read_only(self):
        legacy_id = str(uuid.uuid4())
        token = base64.b64encode(secrets.token_bytes(32)).decode()
        with self.f.sessions() as db:
            db.add(Case(id=legacy_id, case_access_token_hash=token, reporter_public_key='legacy', encrypted_report='legacy'))
            db.add(CaseMessage(case_id=legacy_id, encrypted_response='legacy', nonce='legacy', investigator_public_key='legacy'))
            db.commit()
        result = self.client.post('/api/v1/cases/lookup', json={'caseAccessTokenHash': token})
        self.assertEqual(result.status_code, 410)  # No safe legacy reporter signing enrolment.
        self.authenticated()
        self.assertEqual(self.client.get(f'/api/v1/investigators/cases/{legacy_id}/messages').status_code, 200)
        self.assertEqual(self.client.post(f'/api/v1/investigators/cases/{legacy_id}/messages',
            json=dict(self.reply, caseId=legacy_id), headers=WRITE_HEADERS).status_code, 409)
        self.assertEqual(self.client.post('/api/v1/cases/messages', json=dict(self.followup, caseAccessTokenHash=token)).status_code, 410)
        self.assertEqual(self.client.post('/api/v1/cases/attachments', headers=WRITE_HEADERS,
            data={'case_id': legacy_id}, files={'file': ('evidence.enc', b'cipher', 'application/octet-stream')}).status_code, 409)
        with self.f.sessions() as db:
            self.assertEqual(db.get(Case, legacy_id).status.value, 'OPEN')
            self.assertEqual(len(db.get(Case, legacy_id).messages), 1)

    def test_local_import_rotation_archives_old_cases_without_changing_auth_or_legacy_keys(self):
        import import_investigator_identity as importer
        path = self.f.storage / 'new-identity.json'
        path.write_text(json.dumps(self.rotated['account']), encoding='utf8')
        with self.f.sessions() as db:
            old_encrypted = db.scalar(select(Investigator)).encrypted_private_key
        auth_config = self.f.auth.config
        with patch.object(importer, 'engine', self.f.sessions.kw['bind']), patch.object(importer, 'SessionLocal', self.f.sessions), \
             patch('sys.argv', ['import_investigator_identity.py', '--username', self.f.username, '--file', str(path)]), \
             redirect_stdout(io.StringIO()):
            importer.main()
            with patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
                importer.main()
        self.assertEqual(self.client.get('/api/v1/investigators/public-key').json()['signingPublicKey'], self.rotated['account']['signingPublicKey'])
        self.authenticated()
        self.assertEqual(self.client.post(self.url, json=self.reply, headers=WRITE_HEADERS).status_code, 409)
        track = self.client.post('/api/v1/cases/lookup', json={'caseAccessTokenHash': self.fixture['case']['caseAccessTokenHash']}).json()
        self.assertTrue(track['readOnly'])
        self.assertEqual(track['manifest'], self.fixture['case']['manifest'])
        with self.f.sessions() as db:
            self.assertEqual(db.scalar(select(Investigator)).encrypted_private_key, old_encrypted)
        self.assertEqual(self.f.auth.config, auth_config)


class ProtocolMigrationTests(unittest.TestCase):
    def test_explicit_idempotent_migration_preserves_unsigned_records_as_v1(self):
        engine = create_engine('sqlite://')
        self.addCleanup(engine.dispose)
        with engine.begin() as connection:
            connection.execute(text('CREATE TABLE cases (id TEXT PRIMARY KEY, encrypted_report TEXT)'))
            connection.execute(text('CREATE TABLE case_messages (id TEXT PRIMARY KEY, encrypted_response TEXT)'))
            connection.execute(text("INSERT INTO cases VALUES ('original', 'unchanged ciphertext')"))
            connection.execute(text("INSERT INTO case_messages VALUES ('message', 'unchanged reply')"))
        with self.assertRaises(RuntimeError):
            require_schema(engine)
        migrate(engine)
        migrate(engine)
        require_schema(engine)
        with engine.connect() as connection:
            self.assertEqual(tuple(connection.execute(text('SELECT id, encrypted_report, protocol_version, manifest_json FROM cases')).one()),
                             ('original', 'unchanged ciphertext', 1, None))
            self.assertEqual(tuple(connection.execute(text('SELECT id, encrypted_response, protocol_version, signature FROM case_messages')).one()),
                             ('message', 'unchanged reply', 1, None))
        self.assertIn('investigator_identities', inspect(engine).get_table_names())


if __name__ == '__main__':
    unittest.main()
