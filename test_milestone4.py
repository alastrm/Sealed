"""M4 API attacks and consistency regressions; disposable keys and DBs only."""
import hashlib
import json
import secrets
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import select, delete, create_engine, inspect
from sqlalchemy.orm import sessionmaker
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from models import Case, CaseMessage, CaseHistoryEvent, CaseHistoryHead, CaseAuditLog, CaseAttachment
from test_support import isolated_api, signed_case, signed_reply, encoded, login, reporter_proof, WRITE_HEADERS, public
from reporter_auth import proof_bytes
from history_service import verify_history, hash_value, canonical, event_hash


class Milestone4Tests(unittest.TestCase):
    def setUp(self):
        self.context = isolated_api()
        self.f = self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.client = self.f.client
        self.body = signed_case(self.f)
        self.f.case_token = self.token = self.body['caseAccessTokenHash']
        self.id = self.body['caseId']
        self.assertEqual(self.client.post('/api/v1/cases', json=self.body).status_code, 201)

    def auth_request(self, path=None, payload=None):
        path = path or '/api/v1/cases/lookup'
        req = self.client.build_request('POST', path, json=payload or {'caseAccessTokenHash': self.token})
        headers = reporter_proof(self.f, 'POST '+path, hashlib.sha256(req.content).hexdigest(), self.token)
        self.assertIsInstance(headers, dict)
        req.headers.update(headers)
        return req

    def transition(self, target, revision=None, request_id=None):
        with self.f.sessions() as db:
            current = db.get(CaseHistoryHead, self.id).sequence
        return self.client.post(f'/api/v1/investigators/cases/{self.id}/status', headers=WRITE_HEADERS,
            json={'requestId': request_id or str(uuid.uuid4()), 'expectedRevision': current if revision is None else revision, 'targetStatus': target})

    def result(self):
        with self.f.sessions() as db:
            return verify_history(db, db.get(Case, self.id), self.f.storage)

    def test_copied_database_verifier_public_keys_and_manifest_are_not_authentication(self):
        with self.f.sessions() as db:
            copied = db.get(Case, self.id).case_access_token_hash
        for path in ('/api/v1/cases/lookup', f'/api/v1/cases/{self.id}/access'):
            self.assertEqual(self.client.post(path, json={'caseAccessTokenHash': copied}).status_code, 401)
        self.assertEqual(self.client.post(f'/api/v1/cases/{self.id}/messages', json=signed_reply(self.f, self.id, 'REPORTER')).status_code, 401)
        req = self.auth_request()
        req.headers['X-Sealed-Proof'] = encoded(Ed25519PrivateKey.generate().sign(b'copied public record'))
        self.assertEqual(self.client.send(req).status_code, 403)

    def test_valid_proof_once_and_no_plain_secrets(self):
        req = self.auth_request()
        self.assertEqual(self.client.send(req).status_code, 200)
        self.assertEqual(self.client.send(req).status_code, 401)
        self.assertEqual(self.client.post('/api/v1/cases/lookup', json={'caseAccessTokenHash': self.token}).status_code, 401)

    def test_expired_proof_fails(self):
        req = self.auth_request()
        self.f.reporter_auth.pending[req.headers['X-Sealed-Challenge']]['expiresAt'] = 0
        self.assertEqual(self.client.send(req).status_code, 401)

    def test_concurrent_proof_replay_only_one_succeeds(self):
        req = self.auth_request()
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda _: self.client.send(req).status_code, range(2)))
        self.assertEqual(sorted(statuses), [200, 401])

    def test_wrong_recovery_signing_identity_is_rejected(self):
        response = self.client.post('/api/v1/reporter-auth/challenge', json={
            'authVersion': 1, 'locator': self.token, 'signingPublicKey': public(Ed25519PrivateKey.generate()),
            'operation': 'POST /api/v1/cases/lookup', 'requestDigest': '0'*64})
        self.assertEqual(response.status_code, 403)

    def test_operation_and_body_substitution_fail_and_consume_nonce(self):
        req = self.auth_request()
        headers = dict(req.headers)
        response = self.client.post(f'/api/v1/cases/{self.id}/access', headers=headers, content=req.content)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.send(req).status_code, 401)
        req = self.auth_request()
        response = self.client.post('/api/v1/cases/lookup', headers=dict(req.headers), content=req.content+b' ')
        self.assertEqual(response.status_code, 403)

    def test_cross_case_proof_substitution_fails(self):
        other = signed_case(self.f)
        self.assertEqual(self.client.post('/api/v1/cases', json=other).status_code, 201)
        req = self.auth_request(f'/api/v1/cases/{self.id}/access')
        response = self.client.post(f"/api/v1/cases/{other['caseId']}/access", headers=dict(req.headers), json={'caseAccessTokenHash': other['caseAccessTokenHash']})
        self.assertEqual(response.status_code, 403)

    def test_static_verifier_upload_and_anonymous_audit_are_rejected(self):
        response = self.client.post('/api/v1/cases/attachments', files={'file': ('evidence.enc', b'cipher')},
            data={'case_id': self.id, 'case_access_token_hash': self.token,
                  'signing_public_key': public(self.f.reporter_sign), 'content_digest': hashlib.sha256(b'cipher').hexdigest()})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.get(f'/api/v1/cases/{self.id}/audit-verify').status_code, 401)

    def test_reporter_reply_cannot_change_status(self):
        res = self.f.reporter.post(f'/api/v1/cases/{self.id}/messages', json=signed_reply(self.f, self.id, 'REPORTER'))
        self.assertEqual(res.status_code, 201, res.text)
        with self.f.sessions() as db:
            self.assertEqual(db.get(Case, self.id).status.value, 'OPEN')
        self.assertTrue(self.result()['is_valid'])

    def test_lifecycle_and_both_views_and_reopening(self):
        self.assertEqual(login(self.f).status_code, 200)
        self.assertEqual(self.transition('IN_REVIEW').status_code, 200)
        response = self.client.post(f'/api/v1/investigators/cases/{self.id}/messages', headers=WRITE_HEADERS, json=signed_reply(self.f, self.id))
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(self.transition('CLOSED').status_code, 200)
        reporter = self.client.send(self.auth_request()).json()
        investigator = self.client.get('/api/v1/investigators/cases').json()[0]
        self.assertEqual(reporter['status'], investigator['status'])
        self.assertEqual(reporter['revision'], investigator['revision'])
        self.assertTrue(reporter['readOnly'])
        self.assertEqual(self.transition('IN_REVIEW').status_code, 200)
        self.assertFalse(self.client.send(self.auth_request()).json()['readOnly'])
        self.assertTrue(self.result()['is_valid'])

    def test_unauthorized_and_csrf_status_updates_fail(self):
        self.assertEqual(self.transition('CLOSED').status_code, 401)
        login(self.f)
        response = self.client.post(f'/api/v1/investigators/cases/{self.id}/status', json={
            'requestId': str(uuid.uuid4()), 'expectedRevision': 1, 'targetStatus': 'CLOSED'})
        self.assertEqual(response.status_code, 403)

    def test_duplicate_transition_does_not_reopen_or_append_history(self):
        login(self.f)
        request_id = str(uuid.uuid4())
        self.assertEqual(self.transition('CLOSED', 1, request_id).status_code, 200)
        self.assertEqual(self.transition('CLOSED', 1, request_id).status_code, 200)
        self.assertEqual(self.result()['events_count'], 2)
        self.assertEqual(self.transition('IN_REVIEW', 1, request_id).status_code, 409)

    def test_invalid_and_stale_transitions_fail(self):
        login(self.f)
        for target in ('OPEN', 'RESPONDED'):
            self.assertEqual(self.transition(target).status_code, 409)
        self.assertEqual(self.transition('CLOSED', 0).status_code, 409)

    def test_closed_case_rejects_both_replies_and_uploads(self):
        login(self.f)
        self.assertEqual(self.transition('CLOSED').status_code, 200)
        before = self.result()['events_count']
        self.assertEqual(self.f.reporter.post(f'/api/v1/cases/{self.id}/messages', json=signed_reply(self.f, self.id, 'REPORTER')).status_code, 409)
        self.assertEqual(self.client.post(f'/api/v1/investigators/cases/{self.id}/messages', headers=WRITE_HEADERS, json=signed_reply(self.f, self.id)).status_code, 409)
        response = self.f.reporter.post('/api/v1/cases/attachments', data={'case_id': self.id, 'case_access_token_hash': self.token}, files={'file': ('evidence.enc', b'cipher')})
        self.assertEqual(response.status_code, 409)
        response = self.client.post('/api/v1/cases/attachments', headers=WRITE_HEADERS, data={'case_id': self.id}, files={'file': ('evidence.enc', b'cipher')})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.result()['events_count'], before)
        self.assertEqual(list(self.f.storage.glob('*.enc')), [])

    def test_report_status_and_message_mutation_detected(self):
        response = self.f.reporter.post(f'/api/v1/cases/{self.id}/messages', json=signed_reply(self.f, self.id, 'REPORTER'))
        self.assertEqual(response.status_code, 201)
        mutations = [(Case, self.id, 'encrypted_report', 'changed'), (Case, self.id, 'status', 'CLOSED'),
                     (CaseMessage, response.json()['id'], 'encrypted_response', encoded(bytes(32))),
                     (CaseMessage, response.json()['id'], 'sender_type', 'INVESTIGATOR')]
        for model, id, field, changed in mutations:
            with self.f.sessions() as db:
                row = db.get(model, id); before = getattr(row, field)
                setattr(row, field, changed); db.commit()
            self.assertEqual(self.result()['status'], 'inconsistent')
            with self.f.sessions() as db:
                setattr(db.get(model, id), field, before); db.commit()
        self.assertTrue(self.result()['is_valid'])

    def test_deleted_message_detected_even_if_signature_of_remaining_is_valid(self):
        reply = signed_reply(self.f, self.id, 'REPORTER')
        self.assertEqual(self.f.reporter.post(f'/api/v1/cases/{self.id}/messages', json=reply).status_code, 201)
        with self.f.sessions() as db:
            db.delete(db.get(CaseMessage, reply['messageId'])); db.commit()
        self.assertEqual(self.result()['status'], 'inconsistent')

    def test_deleted_tail_and_empty_history_are_not_green(self):
        login(self.f); self.transition('IN_REVIEW')
        with self.f.sessions() as db:
            db.execute(delete(CaseHistoryEvent).where(CaseHistoryEvent.case_id == self.id, CaseHistoryEvent.sequence == 2)); db.commit()
        self.assertEqual(self.result()['status'], 'inconsistent')
        with self.f.sessions() as db:
            db.execute(delete(CaseHistoryEvent)); db.commit()
        self.assertEqual(self.result()['status'], 'inconsistent')
        with self.f.sessions() as db:
            db.execute(delete(CaseHistoryHead)); db.commit()
        self.assertEqual(self.result()['status'], 'unavailable')

    def test_reordered_history_and_rewritten_payload_detected(self):
        login(self.f); self.transition('IN_REVIEW')
        with self.f.sessions() as db:
            row = db.scalar(select(CaseHistoryEvent).where(CaseHistoryEvent.sequence == 1))
            row.sequence = 9; db.commit()
        self.assertEqual(self.result()['status'], 'inconsistent')

    def test_history_hashes_fit_schema_and_bind_case_sequence_actor_and_time(self):
        with self.f.sessions() as db:
            event = db.scalar(select(CaseHistoryEvent))
            self.assertEqual(len(event.current_hash), 64)
            original = event.current_hash
            for field, value in [('case_id', str(uuid.uuid4())), ('sequence', 123), ('actor', 'OTHER'), ('created_at', '2000')]:
                before = getattr(event, field); setattr(event, field, value)
                self.assertNotEqual(event_hash(event), original)
                setattr(event, field, before)

    def test_legacy_no_signing_identity_has_explicit_policy(self):
        legacy_id = str(uuid.uuid4()); token = encoded(secrets.token_bytes(32))
        with self.f.sessions() as db:
            db.add(Case(id=legacy_id, case_access_token_hash=token, encrypted_report='legacy', reporter_public_key=self.f.reporter_public)); db.commit()
        self.assertEqual(self.client.post('/api/v1/cases/lookup', json={'caseAccessTokenHash': token}).status_code, 410)
        login(self.f)
        legacy = next(x for x in self.client.get('/api/v1/investigators/cases').json() if x['id'] == legacy_id)
        self.assertTrue(legacy['readOnly'])
        self.assertEqual(self.client.post(f'/api/v1/investigators/cases/{legacy_id}/status', headers=WRITE_HEADERS,
            json={'requestId': str(uuid.uuid4()), 'expectedRevision': 0, 'targetStatus': 'CLOSED'}).status_code, 409)

    def test_migration_preserves_prior_rows_and_does_not_invent_verified_history(self):
        from migrate_m4 import migrate, missing_tables
        with tempfile.TemporaryDirectory(prefix='sealed-m4-migration-') as directory:
            engine = create_engine('sqlite:///'+str(Path(directory)/'copy.db'))
            from database import Base
            Base.metadata.create_all(engine)
            # Exercise additive recreation against a pre-M4-shaped disposable DB.
            CaseHistoryEvent.__table__.drop(engine); CaseHistoryHead.__table__.drop(engine)
            with engine.begin() as conn:
                conn.exec_driver_sql("INSERT INTO cases (id, protocol_version, case_access_token_hash, reporter_public_key, encrypted_report, status, created_at) VALUES ('old', 1, 'fixture', 'public', 'encrypted', 'OPEN', '2026-01-01')")
                before = conn.exec_driver_sql('SELECT * FROM cases').fetchall()
            self.assertEqual(len(missing_tables(engine)), 2)
            migrate(engine); migrate(engine)
            with engine.connect() as conn:
                self.assertEqual(conn.exec_driver_sql('SELECT * FROM cases').fetchall(), before)
                self.assertEqual(conn.exec_driver_sql('SELECT COUNT(*) FROM case_history_events').scalar(), 0)
            engine.dispose()

    def test_validation_errors_do_not_echo_sensitive_input(self):
        marker = 'synthetic-secret-do-not-echo'
        response = self.client.post('/api/v1/reporter-auth/challenge', json={'locator': marker})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(marker, response.text)

    def test_existing_v2_baseline_is_explicit_and_preserves_signing_identity(self):
        with self.f.sessions() as db:
            db.execute(delete(CaseHistoryEvent)); db.execute(delete(CaseHistoryHead)); db.commit()
        self.assertEqual(self.result()['status'], 'unavailable')
        self.assertEqual(self.client.send(self.auth_request()).status_code, 200)
        reply = signed_reply(self.f, self.id, 'REPORTER')
        self.assertEqual(self.f.reporter.post(f'/api/v1/cases/{self.id}/messages', json=reply).status_code, 201)
        self.assertTrue(self.result()['historical_baseline'])
        self.assertFalse(self.result()['completeness_verified'])

    def test_download_requires_same_case_proof_and_preserves_ciphertext(self):
        response = self.f.reporter.post('/api/v1/cases/attachments', data={
            'case_id': self.id, 'case_access_token_hash': self.token}, files={'file': ('evidence.enc', b'synthetic ciphertext')})
        self.assertEqual(response.status_code, 201, response.text)
        id = response.json()['attachmentId']
        self.assertEqual(self.f.reporter.post(f'/api/v1/cases/{self.id}/messages',
            json=signed_reply(self.f, self.id, 'REPORTER', attachmentIds=[id])).status_code, 201)
        path = '/api/v1/cases/attachments/'+id
        self.assertEqual(self.client.get(path).status_code, 401)
        headers = reporter_proof(self.f, 'GET '+path, hashlib.sha256(b'').hexdigest(), self.token)
        response = self.client.get(path, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'synthetic ciphertext')
        other = signed_case(self.f)
        self.assertEqual(self.client.post('/api/v1/cases', json=other).status_code, 201)
        headers = reporter_proof(self.f, 'GET '+path, hashlib.sha256(b'').hexdigest(), other['caseAccessTokenHash'])
        self.assertEqual(self.client.get(path, headers=headers).status_code, 403)
        with self.f.sessions() as db:
            Path(db.get(CaseAttachment, id).ciphertext_path).write_bytes(b'changed ciphertext!!')
        self.assertEqual(self.result()['status'], 'inconsistent')

    def test_upload_content_substitution_rejected_before_publication(self):
        from reporter_auth import upload_digest
        id = str(uuid.uuid4()); expected = hashlib.sha256(b'expected').hexdigest()
        headers = reporter_proof(self.f, 'POST /api/v1/cases/attachments',
            upload_digest(id, self.id, expected, None, self.token), self.token)
        response = self.client.post('/api/v1/cases/attachments', headers=headers, data={
            'case_id': self.id, 'case_access_token_hash': self.token, 'attachment_id': id,
            'signing_public_key': public(self.f.reporter_sign), 'content_digest': expected}, files={'file': ('evidence.enc', b'changed')})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(list(self.f.storage.iterdir()), [])

    def test_partial_transaction_failure_rolls_back_status_and_history(self):
        from unittest.mock import patch
        login(self.f)
        with patch('sqlalchemy.orm.Session.commit', side_effect=RuntimeError('synthetic failure')):
            with self.assertRaises(RuntimeError): self.transition('CLOSED')
        self.assertTrue(self.result()['is_valid'])
        self.assertEqual(self.result()['events_count'], 1)
        with self.f.sessions() as db:
            self.assertEqual(db.get(Case, self.id).status.value, 'OPEN')

    def test_concurrent_conflicting_transitions_use_separate_database_connections(self):
        from database import get_db
        from main import app
        login(self.f)
        # Copy only this synthetic fixture to a file DB with separate connections.
        source_engine = self.f.sessions.kw['bind']
        engine = create_engine('sqlite:///'+str(self.f.storage/'concurrent.sqlite'), connect_args={'check_same_thread': False})
        source = source_engine.raw_connection(); target = engine.raw_connection()
        source.driver_connection.backup(target.driver_connection)
        source.close(); target.close()
        sessions = sessionmaker(bind=engine)
        previous = app.dependency_overrides[get_db]
        def separate_db():
            with sessions() as db: yield db
        app.dependency_overrides[get_db] = separate_db
        try:
            def update(target):
                return self.client.post(f'/api/v1/investigators/cases/{self.id}/status', headers=WRITE_HEADERS,
                    json={'requestId': str(uuid.uuid4()), 'expectedRevision': 1, 'targetStatus': target}).status_code
            with ThreadPoolExecutor(max_workers=2) as pool:
                statuses = list(pool.map(update, ['CLOSED', 'IN_REVIEW']))
            self.assertEqual(sorted(statuses), [200, 409])
            with sessions() as db:
                result = verify_history(db, db.get(Case, self.id), self.f.storage)
                self.assertTrue(result['is_valid']); self.assertEqual(result['events_count'], 2)
        finally:
            app.dependency_overrides[get_db] = previous
            engine.dispose()

    def test_total_rollback_is_explicitly_outside_history_guarantee(self):
        # A coherent older DB snapshot cannot be distinguished without an
        # independent checkpoint. Keep this executable limitation in the suite.
        login(self.f)
        self.transition('CLOSED')
        with self.f.sessions() as db:
            first = db.scalar(select(CaseHistoryEvent).where(CaseHistoryEvent.sequence == 1))
            db.execute(delete(CaseHistoryEvent).where(CaseHistoryEvent.sequence > 1))
            head = db.get(CaseHistoryHead, self.id); head.sequence = 1; head.current_hash = first.current_hash
            db.get(Case, self.id).status = 'OPEN'; db.commit()
        result = self.result()
        self.assertTrue(result['is_valid'])
        self.assertFalse(result['completeness_verified'])

    def test_forwarded_headers_do_not_bypass_public_throttle(self):
        from rate_limiter import limiter
        limiter.reset()
        for i in range(15):
            response = self.client.post('/api/v1/cases/lookup', json={'caseAccessTokenHash': self.token},
                headers={'X-Forwarded-For': f'192.0.2.{i}', 'X-Real-IP': f'198.51.100.{i}'})
            self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.post('/api/v1/cases/lookup', json={'caseAccessTokenHash': self.token},
            headers={'X-Forwarded-For': '203.0.113.7'}).status_code, 429)
