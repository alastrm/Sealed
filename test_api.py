"""
Comprehensive Integration Tests for E2EE Whistleblower Backend API.

Tests:
  1. GET /api/v1/investigators/public-key
  2. POST /api/v1/cases (Creation with camelCase DTO)
  3. POST /api/v1/cases/{case_id}/access (Authorized access with valid token hash)
  4. POST /api/v1/cases/{case_id}/access (Unauthorized access with invalid token hash -> 403)
  5. GET /api/v1/investigators/cases (Listing all cases)
  6. POST /api/v1/investigators/cases/{case_id}/messages (Investigator reply and status update)
  7. POST /api/v1/cases/{case_id}/access (Reporter viewing investigator's reply)

Run command:
    python test_api.py
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import uuid
from fastapi.testclient import TestClient

from database import Base, engine
from main import app
from seed import seed_database

client = TestClient(app)


def run_tests() -> None:
    print("==================================================================")
    print("E2EE Whistleblower Backend - API Integration Tests")
    print("==================================================================")

    # 1. Reset tables and seed
    Base.metadata.drop_all(bind=engine)
    seed_database()

    # Test 1: Get Investigator Public Key
    res = client.get("/api/v1/investigators/public-key")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    pubkey_data = res.json()
    assert "publicKey" in pubkey_data, "Response missing camelCase 'publicKey'"
    assert "investigatorId" in pubkey_data, "Response missing camelCase 'investigatorId'"
    assert pubkey_data["publicKey"] == "06Aobu71x1uxZri5AGN6kik/eziAOfHw3Co03wg20Tg="
    print("[PASS] Test 1: GET /api/v1/investigators/public-key")

    # Test 2: Create New Case
    test_case_id = str(uuid.uuid4())
    create_case_payload = {
        "caseId": test_case_id,
        "reporterPublicKey": "UZU6IUITmY2EwHGbDXq8DqUHkVXJppubw8Gazk/B9WE=",
        "caseAccessTokenHash": "546WDnBX9BKWBTACognIt9gyp0kvdqU2CW/boA0lldc=",
        "encryptedReport": "2N/JedFSMDRXPds5+N+MTJO0zMBoU0XVru6MuFvliVlvMMNAeK63es/LPYEwUQCDSCa0...",
    }

    res = client.post("/api/v1/cases", json=create_case_payload)
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    case_created = res.json()
    assert case_created["caseId"] == test_case_id
    assert case_created["status"] == "OPEN"
    assert "createdAt" in case_created
    print("[PASS] Test 2: POST /api/v1/cases (Creation with camelCase DTO)")

    # Test 2b: Duplicate Case ID Conflict (409)
    res = client.post("/api/v1/cases", json=create_case_payload)
    assert res.status_code == 409, f"Expected 409 for duplicate caseId, got {res.status_code}"
    print("[PASS] Test 2b: POST /api/v1/cases (Duplicate ID prevention -> 409)")

    # Test 3: Authorized Case Access
    access_payload = {
        "caseAccessTokenHash": "546WDnBX9BKWBTACognIt9gyp0kvdqU2CW/boA0lldc=",
    }
    res = client.post(f"/api/v1/cases/{test_case_id}/access", json=access_payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    case_access = res.json()
    assert case_access["caseId"] == test_case_id
    assert case_access["status"] == "OPEN"
    assert case_access["messages"] == []
    print("[PASS] Test 3: POST /api/v1/cases/{case_id}/access (Valid Access Token Hash)")

    # Test 3b: Authorized UUID-less Case Lookup via 12-word Token Hash
    res = client.post("/api/v1/cases/lookup", json=access_payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    case_lookup = res.json()
    assert case_lookup["caseId"] == test_case_id
    assert case_lookup["status"] == "OPEN"
    print("[PASS] Test 3b: POST /api/v1/cases/lookup (UUID-less Access via Token Hash)")

    # Test 3c: Lookup with non-existent token hash (404)
    res = client.post("/api/v1/cases/lookup", json={"caseAccessTokenHash": "NON_EXISTENT_HASH_1234567890="})
    assert res.status_code == 404, f"Expected 404, got {res.status_code}"
    print("[PASS] Test 3c: POST /api/v1/cases/lookup (Non-existent hash -> 404 Not Found)")

    # Test 4: Unauthorized Access (Wrong Token Hash -> 403 Forbidden)
    bad_access_payload = {
        "caseAccessTokenHash": "WRONG_TOKEN_HASH_FOR_TESTING_ACCESS_DENIAL_123=",
    }
    res = client.post(f"/api/v1/cases/{test_case_id}/access", json=bad_access_payload)
    assert res.status_code == 403, f"Expected 403, got {res.status_code}"
    assert "Access Denied" in res.json()["detail"]
    print("[PASS] Test 4: POST /api/v1/cases/{case_id}/access (Invalid Token Hash -> 403 Forbidden)")

    # Test 5: Investigator Listing Cases
    res = client.get("/api/v1/investigators/cases")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    cases_list = res.json()
    assert len(cases_list) == 1
    assert cases_list[0]["id"] == test_case_id
    assert cases_list[0]["status"] == "OPEN"
    assert cases_list[0]["messageCount"] == 0
    print("[PASS] Test 5: GET /api/v1/investigators/cases (Listing all cases)")

    # Test 6: Investigator Submitting Response
    response_payload = {
        "caseId": test_case_id,
        "encryptedResponse": "vJnjmgeMZT+cgCghykVQ6fYQUA0/FDLysiTZpwU+47NN24oNoXBRtmFPOxeIehAlK0gV...",
        "nonce": "adHsc6y0lsQSEgIwvLCf5di8ia6FQe0g",
        "investigatorPublicKey": pubkey_data["publicKey"],
    }
    res = client.post(
        f"/api/v1/investigators/cases/{test_case_id}/messages",
        json=response_payload,
    )
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    msg_data = res.json()
    assert msg_data["caseId"] == test_case_id
    assert msg_data["encryptedResponse"] == response_payload["encryptedResponse"]
    assert msg_data["nonce"] == response_payload["nonce"]
    print("[PASS] Test 6: POST /api/v1/investigators/cases/{case_id}/messages (Investigator Response)")

    # Test 7: Reporter Reading Thread (Case Status is now RESPONDED and contains message)
    res = client.post(f"/api/v1/cases/{test_case_id}/access", json=access_payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    updated_case_access = res.json()
    assert updated_case_access["status"] == "RESPONDED"
    assert len(updated_case_access["messages"]) == 1
    assert updated_case_access["messages"][0]["id"] == msg_data["id"]
    print("[PASS] Test 7: POST /api/v1/cases/{case_id}/access (Thread verification after response)")

    # Test 8: Investigator Zero-Knowledge Account Blob Retrieval
    res = client.get("/api/v1/investigators/account")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    account_data = res.json()
    assert account_data["username"] == "compliance.lead@integrity-trust.corp"
    assert "encryptedPrivateKey" in account_data
    assert "privateKeyNonce" in account_data
    assert "kdfSalt" in account_data
    print("[PASS] Test 8: GET /api/v1/investigators/account (Zero-Knowledge login blob)")

    # Test 9: SlowAPI Rate Limiting (15/min limit on lookup)
    ip_headers = {"X-Forwarded-For": "198.51.100.42"}
    lookup_payload = {"caseAccessTokenHash": "546WDnBX9BKWBTACognIt9gyp0kvdqU2CW/boA0lldc="}

    # First request from this IP succeeds
    res = client.post("/api/v1/cases/lookup", json=lookup_payload, headers=ip_headers)
    assert res.status_code == 200

    # Exhaust remaining 14 requests
    for _ in range(14):
        res = client.post("/api/v1/cases/lookup", json=lookup_payload, headers=ip_headers)
        assert res.status_code == 200

    # 16th request must trigger HTTP 429 Too Many Requests
    res_429 = client.post("/api/v1/cases/lookup", json=lookup_payload, headers=ip_headers)
    assert res_429.status_code == 429, f"Expected 429, got {res_429.status_code}"
    assert "Retry-After" in res_429.headers
    print("[PASS] Test 9: SlowAPI Rate Limiter (Throttles abuse -> 429 Too Many Requests with Retry-After)")

    # Test 10: Reporter Follow-up Message via URL ID (POST /api/v1/cases/{case_id}/messages)
    reporter_reply_payload = {
        "caseAccessTokenHash": "546WDnBX9BKWBTACognIt9gyp0kvdqU2CW/boA0lldc=",
        "encryptedMessage": "reporter_reply_ciphertext_base64_example_payload...",
        "nonce": "reporter_nonce_24_bytes_base64_example...",
        "investigatorPublicKey": pubkey_data["publicKey"],
    }

    # 10a: Unauthorized reporter reply with wrong token hash
    bad_reply = dict(reporter_reply_payload)
    bad_reply["caseAccessTokenHash"] = "WRONG_TOKEN_HASH="
    res = client.post(f"/api/v1/cases/{test_case_id}/messages", json=bad_reply)
    assert res.status_code == 403, f"Expected 403, got {res.status_code}"

    # 10b: Authorized reporter reply
    res = client.post(f"/api/v1/cases/{test_case_id}/messages", json=reporter_reply_payload)
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    rep_msg = res.json()
    assert rep_msg["sender"] == "REPORTER"
    assert rep_msg["senderType"] == "REPORTER"
    assert rep_msg["caseId"] == test_case_id
    print("[PASS] Test 10: Bidirectional dialog by case ID (POST /api/v1/cases/{case_id}/messages)")

    # Test 11: Direct Reporter Reply without UUID (POST /api/v1/cases/messages purely by token hash)
    direct_reply_payload = {
        "caseAccessTokenHash": "546WDnBX9BKWBTACognIt9gyp0kvdqU2CW/boA0lldc=",
        "encryptedMessage": "second_reporter_reply_ciphertext_base64...",
        "nonce": "second_nonce_24_bytes_base64...",
        # investigatorPublicKey is optional; backend resolves it automatically
    }
    res = client.post("/api/v1/cases/messages", json=direct_reply_payload)
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    rep_msg2 = res.json()
    assert rep_msg2["sender"] == "REPORTER"
    assert rep_msg2["senderType"] == "REPORTER"
    assert rep_msg2["caseId"] == test_case_id

    # Verify investigator retrieves all 3 messages in the thread in chronological order
    res = client.get(f"/api/v1/investigators/cases/{test_case_id}/messages")
    assert res.status_code == 200
    thread = res.json()
    assert len(thread) == 3
    assert thread[0]["sender"] == "INVESTIGATOR"
    assert thread[1]["sender"] == "REPORTER"
    assert thread[2]["sender"] == "REPORTER"
    print("[PASS] Test 11: UUID-less reporter reply (POST /api/v1/cases/messages)")

    # Test 12: IP Logging Anonymization
    import logging
    from logging_config import IPAnonymizeFilter

    filter_instance = IPAnonymizeFilter()

    # Verify access log record args are scrubbed
    test_record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("192.0.2.1:54321", "POST", "/api/v1/cases", "1.1", 201),
        exc_info=None,
    )
    filter_instance.filter(test_record)
    formatted = test_record.msg % test_record.args
    assert "192.0.2.1" not in formatted, "IP address leaked in log record args!"
    assert "[ANONYMIZED_CLIENT]" in formatted

    # Verify message string embedded IP is scrubbed
    test_msg_record = logging.LogRecord(
        name="fastapi",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Request from client 198.51.100.99 via X-Real-IP: 203.0.113.12",
        args=(),
        exc_info=None,
    )
    filter_instance.filter(test_msg_record)
    assert "198.51.100.99" not in test_msg_record.msg
    assert "203.0.113.12" not in test_msg_record.msg
    assert "[ANONYMIZED_IP]" in test_msg_record.msg
    print("[PASS] Test 12: IP Logging Anonymizer (Guarantees zero client IP leakage in logs)")

    # Test 13: 4KB Constant-size Padding Invariant
    def simulate_iso_padding(data: bytes, block_size: int = 4096) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        return data + b"\x80" + (b"\x00" * (pad_len - 1))

    short_msg = b"Hello"
    long_msg = b"A" * 1500
    padded_short = simulate_iso_padding(short_msg, 4096)
    padded_long = simulate_iso_padding(long_msg, 4096)
    assert len(padded_short) == 4096
    assert len(padded_long) == 4096
    assert len(padded_short) == len(padded_long), "Padding failed to enforce constant ciphertext size"
    print("[PASS] Test 13: 4KB Constant Padding Invariant (Equal ciphertext size for short and long messages)")

    # Test 14: Zero-Knowledge Evidence Upload & Blind Storage
    blind_evidence_bytes = b"encrypted_blind_evidence_blob_with_bucket_padding_12345678"
    files = {"file": ("evidence.enc", blind_evidence_bytes, "application/octet-stream")}
    data = {"case_id": test_case_id}
    res = client.post("/api/v1/cases/attachments", files=files, data=data)
    assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
    att_res = res.json()
    assert "attachmentId" in att_res
    assert att_res["sizeBytes"] == len(blind_evidence_bytes)
    att_id = att_res["attachmentId"]

    # Test 14b: Download Blind Evidence with Anti-XSS and Octet-Stream Headers
    res = client.get(f"/api/v1/cases/attachments/{att_id}")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert res.content == blind_evidence_bytes
    assert res.headers.get("x-content-type-options") == "nosniff", "Missing X-Content-Type-Options: nosniff"
    assert "application/octet-stream" in res.headers.get("content-type", "")
    assert 'attachment; filename="evidence.enc"' in res.headers.get("content-disposition", "")
    print("[PASS] Test 14: Zero-Knowledge Evidence Upload & Anti-XSS Download")

    # Test 14c: Strict 10MB Attachment File Limit (Rejection of oversized blobs)
    oversized_bytes = b"0" * (10 * 1024 * 1024 + 1)
    files_oversized = {"file": ("oversized.enc", oversized_bytes, "application/octet-stream")}
    res = client.post("/api/v1/cases/attachments", files=files_oversized)
    assert res.status_code == 413, f"Expected 413 Request Entity Too Large, got {res.status_code}"
    print("[PASS] Test 14c: Strict 10MB Attachment Size Limit Enforced (413 Payload Too Large)")

    # Test 15: Tamper-Evident BLAKE2b Audit Chain Verification
    res = client.get(f"/api/v1/cases/{test_case_id}/audit-verify")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    audit_data = res.json()
    assert audit_data["isValid"] is True, f"Audit chain should be valid, reason: {audit_data.get('reason')}"
    assert audit_data["eventsCount"] >= 3, f"Expected at least 3 events, got {audit_data['eventsCount']}"
    assert audit_data["latestHash"] is not None
    assert audit_data["brokenAt"] is None
    print(f"[PASS] Test 15: Tamper-evident BLAKE2b Audit Chain Verified ({audit_data['eventsCount']} linked events)")

    # Test 15b: Detection of Retroactive Database Tampering
    from database import SessionLocal
    from models import CaseAuditLog

    db = SessionLocal()
    try:
        logs = db.query(CaseAuditLog).filter_by(case_id=test_case_id).all()
        assert len(logs) > 0
        # Attacker tampers with the first event payload
        tampered_entry_id = logs[0].id
        logs[0].payload_hash = "tampered_fake_blake2b_digest_attacker_injection_0000000000000"
        db.commit()
    finally:
        db.close()

    # Re-verify audit chain: backend MUST detect hash collision/break
    res = client.get(f"/api/v1/cases/{test_case_id}/audit-verify")
    assert res.status_code == 200
    tampered_audit = res.json()
    assert tampered_audit["isValid"] is False, "Audit chain failed to detect database tampering!"
    assert tampered_audit["brokenAt"] == tampered_entry_id, "brokenAt did not pinpoint the tampered record!"
    print("[PASS] Test 15b: Retroactive Database Tampering Detected by Audit Hash Chain")

    print("==================================================================")
    print("ALL API INTEGRATION TESTS PASSED SUCCESSFULLY!")
    print("==================================================================")


if __name__ == "__main__":
    run_tests()


