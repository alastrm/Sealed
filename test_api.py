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

    # Test 9: Sliding Window Rate Limiter
    import asyncio
    from rate_limiter import SlidingWindowRateLimiter

    test_limiter = SlidingWindowRateLimiter(times=3, seconds=60)

    class DummyClient:
        host = "192.168.1.100"

    class DummyRequest:
        headers = {}
        client = DummyClient()

    async def run_limiter_test():
        for _ in range(3):
            await test_limiter(DummyRequest())
        try:
            await test_limiter(DummyRequest())
            assert False, "Expected 429 Too Many Requests was not raised"
        except Exception as exc:
            assert hasattr(exc, "status_code") and exc.status_code == 429
            assert "Retry-After" in exc.headers

    asyncio.run(run_limiter_test())
    print("[PASS] Test 9: Sliding Window Rate Limiter (Throttles abuse -> 429 Too Many Requests)")

    # Test 10: Reporter Follow-up Message (Bidirectional Thread)
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
    assert rep_msg["caseId"] == test_case_id

    # 10c: Investigator fetches full thread
    res = client.get(f"/api/v1/investigators/cases/{test_case_id}/messages")
    assert res.status_code == 200
    thread = res.json()
    assert len(thread) == 2
    assert thread[0]["sender"] == "INVESTIGATOR"
    assert thread[1]["sender"] == "REPORTER"
    print("[PASS] Test 10: Bidirectional dialog (Reporter follow-up & investigator thread retrieval)")

    print("==================================================================")
    print("ALL API INTEGRATION TESTS PASSED SUCCESSFULLY!")
    print("==================================================================")


if __name__ == "__main__":
    run_tests()

