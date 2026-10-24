"""Local attachment maintenance. Defaults to a read-only preview; --apply opts in."""
import argparse
import json
from database import SessionLocal
from routers.cases import STORAGE_DIR
from attachment_service import cleanup_staged

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    with SessionLocal() as db:
        print(json.dumps(cleanup_staged(db, STORAGE_DIR, apply=args.apply)))
