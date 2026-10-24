"""Add M4 history tables only. Explicit --database and --apply, never auto-migrate.

Existing rows (including legacy audit chains) are not rewritten. Existing v2
cases acquire an explicitly labeled baseline on their first successful write.
"""
import argparse
from sqlalchemy import create_engine, inspect
from models import CaseHistoryHead, CaseHistoryEvent

TABLES = [CaseHistoryHead.__table__, CaseHistoryEvent.__table__]


def missing_tables(engine):
    present = set(inspect(engine).get_table_names())
    return [table.name for table in TABLES if table.name not in present]


def migrate(engine):
    with engine.begin() as connection:
        for table in TABLES:
            table.create(connection, checkfirst=True)


def require_m4_schema(engine):
    if missing_tables(engine):
        raise RuntimeError('M4 requires an explicit additive migration. Back up the database and run migrate_m4.py against an approved target. See DEMO.md.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, help='Explicit SQLAlchemy database URL')
    parser.add_argument('--apply', action='store_true', help='Create only missing M4 tables on this approved target')
    args = parser.parse_args()
    engine = create_engine(args.database)
    print('Missing M4 tables:', ', '.join(missing_tables(engine)) or 'none')
    if args.apply:
        migrate(engine)
        print('Additive migration complete. Existing rows were not changed.')
