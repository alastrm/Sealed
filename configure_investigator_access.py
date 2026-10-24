"""Provision/rotate a separate random login key for an existing local investigator."""

import argparse
import json
import os
import secrets

from sqlalchemy import select

from database import SessionLocal
from investigator_auth import auth_file_path
from models import Investigator


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument("--rotate", action="store_true", help="Replace existing login key; restart the backend to revoke sessions")
    args = parser.parse_args()
    if any(c in args.username for c in "\r\n") or not 1 <= len(args.username) <= 255:
        parser.error("Invalid username")
    with SessionLocal() as db:
        if db.execute(select(Investigator).where(Investigator.username == args.username)).scalars().first() is None:
            parser.error("No such investigator account. This tool does not create or alter encryption keys.")
    path = auth_file_path()
    if path.exists() and not args.rotate:
        parser.error("Access is already configured. Use --rotate intentionally, then restart the backend.")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump({"username": args.username, "accessKey": key}, target)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    print("Workspace access key (save privately; do not commit or share):")
    print(key)
    print("Restart the backend. This key is separate from the local decryption master password.")


if __name__ == "__main__":
    main()
