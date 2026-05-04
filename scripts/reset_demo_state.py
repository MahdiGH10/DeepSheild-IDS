from __future__ import annotations

import sqlite3
from pathlib import Path


TABLES_TO_CLEAR = [
    'incident_events',
    'automation_runs',
    'traffic_events',
    'alerts',
]


def find_database() -> Path | None:
    root = Path(__file__).resolve().parents[1]
    candidates = [
        root / 'deepshield_backend' / 'deepshield.db',
        root / 'deepshield_backend' / 'instance' / 'deepshield.db',
        root / 'deepshield.db',
        root / 'instance' / 'deepshield.db',
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def main() -> int:
    db_path = find_database()
    if not db_path:
        print('[DeepShield] No SQLite DB found to reset.')
        return 1

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute('PRAGMA foreign_keys = OFF;')
        for table in TABLES_TO_CLEAR:
            try:
                cur.execute(f'DELETE FROM {table};')
            except sqlite3.OperationalError as exc:
                print(f'[DeepShield] Skipping {table}: {exc}')
        try:
            cur.execute("DELETE FROM sqlite_sequence WHERE name IN (?, ?, ?, ?);", TABLES_TO_CLEAR)
        except sqlite3.OperationalError:
            pass
        conn.commit()

        print(f'[DeepShield] Demo state reset in {db_path}')
        for table in TABLES_TO_CLEAR:
            try:
                count = cur.execute(f'SELECT COUNT(*) FROM {table};').fetchone()[0]
                print(f'  - {table}: {count} rows')
            except sqlite3.OperationalError:
                print(f'  - {table}: unavailable')
    finally:
        conn.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
