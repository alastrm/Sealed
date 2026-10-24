"""Read-only source -> protected SQLite copy -> additive migration verification.

Explicit source argument; never imports database.py against the source or starts
the real application. No row values, identity material or credentials are printed.
"""
import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sqlalchemy import create_engine
from migrate_m4 import migrate, missing_tables


def row_fingerprints(connection):
    result = {}
    tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for name in tables:
        quoted = '"' + name.replace('"', '""') + '"'
        rows = connection.execute('SELECT * FROM ' + quoted).fetchall()
        hashes = sorted(hashlib.sha256(repr(row).encode()).hexdigest() for row in rows)
        result[name] = hashes
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    source_path = Path(args.source).resolve(strict=True)
    parent = ROOT/'storage/backups'
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='sealed-m4-schema-copy-', dir=parent))
    if os.name == 'nt':
        user = os.environ['USERDOMAIN'] + '\\' + os.environ['USERNAME']
        subprocess.run(['icacls', str(directory), '/inheritance:r', '/grant:r', user+':(OI)(CI)F',
                        '*S-1-5-18:(OI)(CI)F'], capture_output=True, check=True)
    else:
        directory.chmod(0o700)
    copy_path = directory/'copy.db'
    with sqlite3.connect(source_path.as_uri()+'?mode=ro', uri=True) as source, sqlite3.connect(copy_path) as target:
        source.backup(target)
    with sqlite3.connect(copy_path) as copied:
        before = row_fingerprints(copied)
    engine = create_engine('sqlite:///'+str(copy_path))
    missing = missing_tables(engine)
    migrate(engine)
    migrate(engine)
    engine.dispose()
    with sqlite3.connect(copy_path) as copied:
        after = row_fingerprints(copied)
        assert copied.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    assert all(after[name] == rows for name, rows in before.items())
    print(json.dumps({'copy': str(copy_path), 'sourceOpenedReadOnly': True, 'missingBefore': missing,
                      'priorTablesPreserved': len(before), 'priorRowsPreserved': sum(map(len, before.values())),
                      'idempotentMigration': True, 'sqliteIntegrity': 'ok'}))


if __name__ == '__main__':
    main()
