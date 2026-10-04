"""
Database Seeder for E2EE Whistleblower System.
Populates the database with the pre-generated test investigator matching poc.ts.

Run command:
    python seed.py
"""

import sys
from datetime import datetime, timezone
from sqlalchemy import select

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from database import Base, SessionLocal, engine
from models import Investigator

# Exact investigator record parameters from poc.ts validation run
TEST_INVESTIGATOR = {
    "id": "f25ac5f0-aa96-4297-9bd0-48f5c087a248",
    "username": "compliance.lead@integrity-trust.corp",
    "public_key": "06Aobu71x1uxZri5AGN6kik/eziAOfHw3Co03wg20Tg=",
    "encrypted_private_key": "XfdTeNpdXeSrYyVp8yD8NapvJWXIsN6PfWuEBNPqz/tDcmxFxEP3abWFljZiY9YR",
    "private_key_nonce": "czS9I0y4+g+uXKH3MjgUBR5kYn8a9XH1",
    "kdf_salt": "W1OkfcDfAnuCeIl1jaOTPg==",
    "kdf_ops_limit": 2,
    "kdf_mem_limit": 67108864,
    "kdf_algorithm": 2,
    "created_at": datetime(2026, 10, 4, 17, 58, 20, tzinfo=timezone.utc),
}

TEST_PASSWORD_HINT = "Correct-Horse-Battery-Staple-2026!#"


def seed_database() -> None:
    print("==================================================================")
    print("E2EE Whistleblower System - Database Seeder")
    print("==================================================================")

    # Ensure tables exist
    Base.metadata.create_all(bind=engine)
    print("[OK] Database schema verified.")

    db = SessionLocal()
    try:
        # Check if investigator already exists
        existing = db.execute(
            select(Investigator).where(
                Investigator.username == TEST_INVESTIGATOR["username"]
            )
        ).scalars().first()

        if existing:
            print(f"[OK] Investigator '{existing.username}' already exists in DB.")
            investigator = existing
        else:
            investigator = Investigator(**TEST_INVESTIGATOR)
            db.add(investigator)
            db.commit()
            db.refresh(investigator)
            print(f"[OK] Seeded test investigator '{investigator.username}'.")

        print("\n--- Investigator Details ---")
        print(f"ID:                   {investigator.id}")
        print(f"Username:             {investigator.username}")
        print(f"Public Key (Base64):  {investigator.public_key}")
        print(f"Password for login:   {TEST_PASSWORD_HINT}")
        print(f"KDF Salt (Base64):    {investigator.kdf_salt}")
        print(f"KDF Ops/Mem Limits:   ops={investigator.kdf_ops_limit}, mem={investigator.kdf_mem_limit} bytes")
        print("==================================================================")
        print("[OK] Seeding completed successfully.")

    except Exception as e:
        db.rollback()
        print(f"[ERROR] Error during seeding: {e}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
