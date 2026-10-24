"""Add v2 columns/tables without reinterpreting, deleting, or rewriting legacy data.

Back up the local database first; run explicitly: python migrate_v2.py
"""
from sqlalchemy import inspect, text
from database import Base, engine
import models  # noqa: F401 — register all tables

ADDITIONS = {
    "cases": {"protocol_version": "INTEGER NOT NULL DEFAULT 1", "manifest_json": "TEXT"},
    "case_messages": {"protocol_version": "INTEGER NOT NULL DEFAULT 1", "signature": "TEXT"},
}


def migrate(target_engine):
    Base.metadata.create_all(target_engine)
    with target_engine.begin() as connection:
        for table, fields in ADDITIONS.items():
            existing = {column["name"] for column in inspect(connection).get_columns(table)}
            for name, sql_type in fields.items():
                if name not in existing:
                    connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {sql_type}'))


def require_schema(target_engine):
    for table, fields in ADDITIONS.items():
        existing = {column["name"] for column in inspect(target_engine).get_columns(table)}
        if not set(fields).issubset(existing):
            raise RuntimeError("Legacy schema detected. Back up the database and run python migrate_v2.py.")


if __name__ == "__main__":
    migrate(engine)
    print("V2 schema ready. Existing reports/messages remain version 1, unverified and read-only.")
