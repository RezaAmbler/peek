#!/usr/bin/env python3
"""
Apply SQL migrations to the database.

Usage:
    python migrations/apply_migrations.py [db_path]

This script applies pending SQL migrations to the database.
For SQLite, schema additions are idempotent — columns that already exist are skipped.
One-time data wipes are gated by sentinel files alongside the DB.
"""
import sqlite3
import sys
from pathlib import Path

# Default database path (relative to backend directory)
DEFAULT_DB_PATH = "./data/peek.db"


def get_existing_columns(cursor, table_name: str) -> set:
    """Get existing column names for a table."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    return {row[1] for row in cursor.fetchall()}


def table_exists(cursor, table_name: str) -> bool:
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    return cursor.fetchone() is not None


def add_column_if_not_exists(cursor, table: str, column: str, column_type: str, default=None):
    """Add a column to a table if it doesn't already exist."""
    if not table_exists(cursor, table):
        print(f"  Table '{table}' does not exist yet, skipping {table}.{column}")
        return False

    existing = get_existing_columns(cursor, table)
    if column in existing:
        print(f"  Column '{table}.{column}' already exists, skipping")
        return False

    default_clause = ""
    if default is not None:
        if isinstance(default, bool):
            default_clause = f" DEFAULT {1 if default else 0}"
        elif isinstance(default, int):
            default_clause = f" DEFAULT {default}"
        elif isinstance(default, str):
            default_clause = f" DEFAULT '{default}'"

    sql = f"ALTER TABLE {table} ADD COLUMN {column} {column_type}{default_clause}"
    print(f"  Adding column: {table}.{column}")
    cursor.execute(sql)
    return True


def apply_001_httpx_screenshots_vhost(cursor):
    """Migration 001: Add httpx screenshot and vhost discovery support."""
    print("\nApplying migration 001: httpx screenshots and vhost discovery")

    # scan_configs columns
    add_column_if_not_exists(cursor, "scan_configs", "httpx_screenshots", "BOOLEAN NOT NULL", default=False)
    add_column_if_not_exists(cursor, "scan_configs", "httpx_screenshot_timeout", "INTEGER NOT NULL", default=10)
    add_column_if_not_exists(cursor, "scan_configs", "httpx_vhost_discovery", "BOOLEAN NOT NULL", default=True)

    # httpx_results columns
    add_column_if_not_exists(cursor, "httpx_results", "screenshot_path", "VARCHAR", default=None)

    print("  Migration 001 complete")


# Order matters: child tables first, parent (scans) last.
# scan_comparisons has no ON DELETE CASCADE on its scans FK, so we hit it explicitly.
# Everything else either has CASCADE from scans or scan_targets, but we delete
# explicitly anyway because SQLite's PRAGMA foreign_keys is off by default in
# this codebase and we don't want to depend on it.
SCAN_DATA_TABLES_DELETE_ORDER = (
    "scan_comparisons",
    "vulnerabilities",
    "nse_findings",
    "ssh_audits",
    "sslscan_results",
    "testssl_results",
    "httpx_results",
    "discovered_endpoints",
    "tool_executions",
    "ports",
    "scan_targets",
    "scans",
)


def apply_002_compare_series(cursor, db_path: Path):
    """Migration 002: per-config series via config snapshot + hash.

    - Adds config_snapshot (TEXT/JSON) and config_hash (TEXT) to scans.
    - Wipes existing scan-side rows (one-time, gated by sentinel).
    """
    print("\nApplying migration 002: compare-series (snapshot+hash)")

    add_column_if_not_exists(cursor, "scans", "config_snapshot", "TEXT", default=None)
    add_column_if_not_exists(cursor, "scans", "config_hash", "TEXT", default=None)

    sentinel = db_path.parent / ".migration_002_wipe_applied"
    if sentinel.exists():
        print("  Data wipe already applied (sentinel present), skipping")
        return

    print("  Wiping existing scan data (one-time, per the design)")
    total_deleted = 0
    for table in SCAN_DATA_TABLES_DELETE_ORDER:
        if not table_exists(cursor, table):
            print(f"    {table}: table does not exist, skipping")
            continue
        cursor.execute(f"SELECT count(*) FROM {table}")
        before = cursor.fetchone()[0]
        cursor.execute(f"DELETE FROM {table}")
        print(f"    {table}: deleted {before} row(s)")
        total_deleted += before

    sentinel.write_text("applied\n", encoding="utf-8")
    print(f"  Migration 002 complete — {total_deleted} row(s) removed, sentinel written to {sentinel}")


def create_index_if_not_exists(cursor, index_name: str, table: str, column: str):
    """Create an index if it doesn't already exist (idempotent)."""
    if not table_exists(cursor, table):
        print(f"  Table '{table}' does not exist yet, skipping index {index_name}")
        return
    sql = f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({column})"
    print(f"  Ensuring index: {index_name} on {table}({column})")
    cursor.execute(sql)


def apply_003_soc_findings(cursor):
    """Migration 003: SOC-grade finding fingerprints.

    Adds vulnerabilities.fingerprint (stable sha256 hex, indexed) used by the
    fingerprint-keyed, de-noised scan comparison. See services/fingerprint.py.
    """
    print("\nApplying migration 003: SOC finding fingerprints")

    added = add_column_if_not_exists(cursor, "vulnerabilities", "fingerprint", "VARCHAR(64)", default=None)
    create_index_if_not_exists(cursor, "ix_vulnerabilities_fingerprint", "vulnerabilities", "fingerprint")

    # --- Risk enrichment columns (SOC hardening) ---
    # Structured CVE identity + threat-intel context + computed prioritization
    # score, populated post-scan from NVD/CVSS, FIRST/EPSS and CISA KEV feeds.
    # Each ADD COLUMN is guarded; columns that already exist are skipped.
    add_column_if_not_exists(cursor, "vulnerabilities", "cve_id", "VARCHAR", default=None)
    add_column_if_not_exists(cursor, "vulnerabilities", "cvss_score", "FLOAT", default=None)
    add_column_if_not_exists(cursor, "vulnerabilities", "cvss_vector", "VARCHAR", default=None)
    add_column_if_not_exists(cursor, "vulnerabilities", "epss_score", "FLOAT", default=None)
    add_column_if_not_exists(cursor, "vulnerabilities", "kev_flag", "BOOLEAN", default=False)
    add_column_if_not_exists(cursor, "vulnerabilities", "exploit_known", "BOOLEAN", default=False)
    add_column_if_not_exists(cursor, "vulnerabilities", "risk_score", "FLOAT", default=None)
    create_index_if_not_exists(cursor, "ix_vulnerabilities_cve_id", "vulnerabilities", "cve_id")
    create_index_if_not_exists(cursor, "ix_vulnerabilities_risk_score", "vulnerabilities", "risk_score")

    print("  Migration 003 complete" + ("" if added else " (fingerprint already present)"))


def apply_all(db_path: str) -> None:
    db_path_obj = Path(db_path)
    if not db_path_obj.exists():
        print(f"Database not found at {db_path}")
        print("Run the application first to create the initial database.")
        return

    print(f"Applying migrations to: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        apply_001_httpx_screenshots_vhost(cursor)
        apply_002_compare_series(cursor, db_path_obj)
        apply_003_soc_findings(cursor)

        conn.commit()
        print("\nAll migrations applied successfully!")
    except Exception as e:
        conn.rollback()
        print(f"\nMigration failed: {e}")
        raise
    finally:
        conn.close()


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB_PATH
    if not Path(db_path).exists():
        print(f"Database not found at {db_path}")
        print("Run the application first to create the initial database.")
        sys.exit(1)
    try:
        apply_all(db_path)
    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    main()
