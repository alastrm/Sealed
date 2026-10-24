"""M3 regressions. All databases, identities, and files are disposable."""
import asyncio
import json
import secrets
import uuid
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch

from sqlalchemy import select, func, create_engine
from sqlalchemy.orm import sessionmaker
from starlette.datastructures import UploadFile

from database import Base, get_db
from main import app
from attachment_service import cleanup_staged, now, MAX_CIPHERTEXT_BYTES
from models import Case, CaseAttachment, CaseMessage, CaseHistoryEvent, AttachmentUpload, SubmissionReceipt, Investigator, InvestigatorIdentity
from test_support import isolated_api, signed_case, signed_reply, encoded, login, WRITE_HEADERS


class SubmissionReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.context = isolated_api()
        self.f = self.context.__enter__()
        self.client = self.f.reporter
        self.token = encoded(secrets.token_bytes(32))
        self.f.case_token = self.token

    def tearDown(self):
        self.context.__exit__(None, None, None)

    def upload(self, data=None, content=b'ciphertext', id=None):
        return self.client.post('/api/v1/cases/attachments', data={
            'attachment_id': id or str(uuid.uuid4()), 'staging_token': self.token, **(data or {}),
        }, files={'file': ('evidence.enc', content, 'application/octet-stream')})

    def create(self, **changes):
        payload = signed_case(self.f, caseAccessTokenHash=self.token, **changes)
        result = self.client.post('/api/v1/cases', json=payload)
        self.assertEqual(result.status_code, 201, result.text)
        return payload

    def counts(self):
        with self.f.sessions() as db:
            return [db.scalar(select(func.count()).select_from(model)) for model in
                    (Case, CaseMessage, CaseHistoryEvent, CaseAttachment, SubmissionReceipt)]

    def test_repeated_initial_post_has_one_case_one_receipt_one_genesis(self):
        payload = self.create()
        before = self.counts()
        for _ in range(3):
            result = self.client.post('/api/v1/cases', json=payload)
            self.assertEqual(result.status_code, 201)
        self.assertEqual(self.counts(), before)
        self.assertEqual(before[:3], [1, 0, 1])
        self.assertEqual(self.client.post('/api/v1/cases/lookup', json={'caseAccessTokenHash': self.token}).status_code, 200)

    def test_conflicting_body_cannot_reuse_case_or_change_attachments(self):
        payload = self.create()
        before = self.counts()
        for key, value in [('reporterPublicKey', encoded(bytes(32))), ('attachmentIds', [str(uuid.uuid4())]),
                           ('encryptedReport', encoded(bytes(60)))]:
            result = self.client.post('/api/v1/cases', json={**payload, key: value})
            self.assertEqual(result.status_code, 409)
        self.assertEqual(self.counts(), before)

    def test_new_case_cannot_reuse_existing_recovery_credentials(self):
        self.create()
        before = self.counts()
        result = self.client.post('/api/v1/cases', json=signed_case(self.f, caseAccessTokenHash=self.token))
        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.counts(), before)

    def test_wrong_case_and_role_cannot_finalize_an_upload(self):
        first = self.create()
        id = self.upload(data={'case_id': first['caseId'], 'case_access_token_hash': self.token}).json()['attachmentId']
        other_token = encoded(secrets.token_bytes(32))
        other = signed_case(self.f, caseAccessTokenHash=other_token)
        self.assertEqual(self.client.post('/api/v1/cases', json=other).status_code, 201)
        self.f.case_token = other_token
        reply = signed_reply(self.f, other['caseId'], 'REPORTER', attachmentIds=[id])
        before = self.counts()
        self.assertEqual(self.client.post('/api/v1/cases/'+other['caseId']+'/messages', json=reply).status_code, 403)
        self.assertEqual(self.counts(), before)

    def test_batch_limit_and_multi_claim_rollback(self):
        ids = [self.upload(content=b'x'*(MAX_CIPHERTEXT_BYTES)).json()['attachmentId'] for _ in range(4)]
        before = self.counts()
        self.assertEqual(self.client.post('/api/v1/cases', json=signed_case(self.f,
            caseAccessTokenHash=self.token, attachmentIds=ids)).status_code, 413)
        self.assertEqual(self.counts(), before)
        with self.f.sessions() as db:
            for id in ids:
                self.assertEqual(db.get(AttachmentUpload, id).state, 'staged')
                self.assertIsNone(db.get(CaseAttachment, id).case_id)

    def test_upload_retry_same_id_bytes_owner_is_idempotent_and_repairs_missing_file(self):
        id = str(uuid.uuid4())
        first = self.upload(id=id)
        second = self.upload(id=id)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.json(), first.json())
        with self.f.sessions() as db:
            path = db.get(CaseAttachment, id).ciphertext_path
        from pathlib import Path
        Path(path).unlink()  # Only a synthetic file in this fixture.
        self.assertEqual(self.upload(id=id).status_code, 201)
        self.assertEqual(Path(path).read_bytes(), b'ciphertext')
        self.assertEqual(self.upload(id=id, content=b'other').status_code, 409)
        self.assertEqual(self.upload(id=id, data={'staging_token': encoded(secrets.token_bytes(32))}).status_code, 409)
        self.assertEqual(len(list(self.f.storage.glob('*.enc'))), 1)

    def test_initial_claim_requires_owner_missing_duplicate_and_invalid_ids_fail_atomically(self):
        id = self.upload().json()['attachmentId']
        for ids in [[str(uuid.uuid4())], [id, id], ['not-a-uuid']]:
            before = self.counts()
            result = self.client.post('/api/v1/cases', json=signed_case(self.f, caseAccessTokenHash=self.token, attachmentIds=ids))
            self.assertIn(result.status_code, (400, 403))
            self.assertEqual(self.counts(), before)
        other = signed_case(self.f, attachmentIds=[id])
        self.assertEqual(self.client.post('/api/v1/cases', json=other).status_code, 403)
        self.create(attachmentIds=[id])
        from rate_limiter import limiter
        limiter.reset()
        self.assertEqual(self.client.post('/api/v1/cases', json=other).status_code, 403)

    def test_missing_or_truncated_ciphertext_rejects_entire_report(self):
        from pathlib import Path
        for corrupt in ('missing', 'truncated'):
            id = self.upload().json()['attachmentId']
            with self.f.sessions() as db:
                path = Path(db.get(CaseAttachment, id).ciphertext_path)
            if corrupt == 'missing': path.unlink()
            else: path.write_bytes(b'x')
            before = self.counts()
            result = self.client.post('/api/v1/cases', json=signed_case(self.f, caseAccessTokenHash=self.token, attachmentIds=[id]))
            self.assertEqual(result.status_code, 409)
            self.assertEqual(self.counts(), before)

    def test_ciphertext_limit_includes_exact_mac_overhead(self):
        for size, expected in [(0, 400), (5*1024*1024+16, 201), (MAX_CIPHERTEXT_BYTES, 201),
                               (MAX_CIPHERTEXT_BYTES+1, 413)]:
            result = self.upload(content=b'x'*size)
            self.assertEqual(result.status_code, expected, result.text)
        self.assertEqual(len(list(self.f.storage.glob('*.part'))), 0)

    def test_case_linked_upload_is_staged_and_finalized_with_signed_reply(self):
        payload = self.create()
        id = self.upload(data={'case_id': payload['caseId'], 'case_access_token_hash': self.token}).json()['attachmentId']
        with self.f.sessions() as db: self.assertIsNone(db.get(CaseAttachment, id).case_id)
        reply = signed_reply(self.f, payload['caseId'], 'REPORTER', attachmentIds=[id])
        result = self.client.post('/api/v1/cases/'+payload['caseId']+'/messages', json=reply)
        self.assertEqual(result.status_code, 201, result.text)
        with self.f.sessions() as db:
            self.assertEqual(db.get(CaseAttachment, id).case_id, payload['caseId'])
            self.assertEqual(db.get(AttachmentUpload, id).state, 'claimed')
        before = self.counts()
        self.assertEqual(self.client.post('/api/v1/cases/'+payload['caseId']+'/messages', json=reply).status_code, 409)
        self.assertEqual(self.counts(), before)

    def test_investigator_claims_only_own_staged_uploads(self):
        payload = self.create(); id = self.upload().json()['attachmentId']
        self.assertEqual(login(self.f).status_code, 200)
        reply = signed_reply(self.f, payload['caseId'], attachmentIds=[id])
        before = self.counts()
        self.assertEqual(self.client.post('/api/v1/investigators/cases/'+payload['caseId']+'/messages', headers=WRITE_HEADERS, json=reply).status_code, 403)
        self.assertEqual(self.counts(), before)
        upload = self.client.post('/api/v1/cases/attachments', headers=WRITE_HEADERS,
            data={'case_id': payload['caseId']}, files={'file': ('evidence.enc', b'ciphertext')})
        self.assertEqual(upload.status_code, 201)
        reply = signed_reply(self.f, payload['caseId'], attachmentIds=[upload.json()['attachmentId']])
        self.assertEqual(self.client.post('/api/v1/investigators/cases/'+payload['caseId']+'/messages', headers=WRITE_HEADERS, json=reply).status_code, 201)

    def test_expiration_cleanup_never_deletes_claimed_legacy_or_live_staged_files(self):
        expired = self.upload().json()['attachmentId']
        live = self.upload().json()['attachmentId']
        claimed = self.upload().json()['attachmentId']
        self.create(attachmentIds=[claimed])
        legacy_path = self.f.storage/'legacy.enc'; legacy_path.write_bytes(b'legacy')
        with self.f.sessions() as db:
            db.add(CaseAttachment(id=str(uuid.uuid4()), case_id=None, ciphertext_path=str(legacy_path), size_bytes=6))
            db.get(AttachmentUpload, expired).expires_at = now()-timedelta(days=2)
            db.get(AttachmentUpload, claimed).expires_at = now()-timedelta(days=2)
            db.commit()
            before = set(self.f.storage.glob('*.enc'))
            self.assertEqual(cleanup_staged(db, self.f.storage)['expired'], 1)
            self.assertEqual(set(self.f.storage.glob('*.enc')), before)
            result = cleanup_staged(db, self.f.storage, apply=True)
            self.assertEqual(result['removed'], 1)
            self.assertEqual(db.get(AttachmentUpload, expired).state, 'expired')
            self.assertTrue(legacy_path.exists())
            for id in (live, claimed): self.assertTrue((self.f.storage/f'v3-{id}.enc').exists())
        self.assertEqual(self.upload(id=expired).status_code, 410)

    def test_abandoned_part_and_untracked_new_ciphertext_are_quarantined_only(self):
        import os
        old = now().timestamp()-timedelta(days=2).total_seconds()
        for suffix in ('part', 'enc'):
            extra = '-0123456789abcdef' if suffix == 'part' else ''
            path = self.f.storage/f'v3-{uuid.uuid4()}{extra}.{suffix}'
            path.write_bytes(b'synthetic crash orphan'); os.utime(path, (old, old))
        unrelated = self.f.storage/'unmanaged.enc'; unrelated.write_bytes(b'preserve')
        lookalike = self.f.storage/'v3-user-file.enc'; lookalike.write_bytes(b'preserve too'); os.utime(lookalike, (old, old))
        with self.f.sessions() as db:
            self.assertEqual(cleanup_staged(db, self.f.storage, apply=True)['quarantined'], 2)
        self.assertEqual(len(list((self.f.storage/'quarantine').iterdir())), 2)
        self.assertTrue(unrelated.exists())
        self.assertTrue(lookalike.exists())

    def test_read_interruption_and_db_failure_remove_only_request_files(self):
        original = UploadFile.read
        calls = 0
        async def broken(file, size=-1):
            nonlocal calls
            calls += 1
            if calls == 2: raise RuntimeError('synthetic interrupted read')
            return await original(file, 3)
        with patch.object(UploadFile, 'read', broken):
            with self.assertRaises(RuntimeError): self.upload(content=b'long synthetic upload')
        self.assertEqual(list(self.f.storage.iterdir()), [])
        with patch('sqlalchemy.orm.Session.commit', side_effect=RuntimeError('synthetic failed commit')):
            with self.assertRaises(RuntimeError): self.upload()
        self.assertEqual(list(self.f.storage.iterdir()), [])

    def test_expired_staging_cannot_be_finalized_without_cleanup(self):
        id = self.upload().json()['attachmentId']
        with self.f.sessions() as db:
            db.get(AttachmentUpload, id).expires_at = now()-timedelta(days=1); db.commit()
        before = self.counts()
        result = self.client.post('/api/v1/cases', json=signed_case(self.f, caseAccessTokenHash=self.token, attachmentIds=[id]))
        self.assertEqual(result.status_code, 410)
        self.assertEqual(self.counts(), before)

    def test_simultaneous_identical_submissions_converge(self):
        # A file database gives requests separate SQLite connections, unlike the
        # fast single-connection fixtures used by most tests.
        engine = create_engine('sqlite:///'+str(self.f.storage/'concurrency.sqlite'), connect_args={'check_same_thread': False})
        sessions = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        with self.f.sessions() as source, sessions() as target:
            for model in (Investigator, InvestigatorIdentity):
                for row in source.scalars(select(model)):
                    target.add(model(**{col.name: getattr(row, col.name) for col in model.__table__.columns}))
            target.commit()
        previous = app.dependency_overrides[get_db]
        def separate_db():
            with sessions() as db: yield db
        app.dependency_overrides[get_db] = separate_db
        try:
            payload = signed_case(self.f)
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: self.client.post('/api/v1/cases', json=payload), range(2)))
            self.assertEqual([r.status_code for r in results], [201, 201])
            with sessions() as db:
                self.assertEqual(db.scalar(select(func.count()).select_from(Case)), 1)
                self.assertEqual(db.scalar(select(func.count()).select_from(CaseHistoryEvent)), 1)
        finally:
            app.dependency_overrides[get_db] = previous
            engine.dispose()


if __name__ == '__main__': unittest.main()
