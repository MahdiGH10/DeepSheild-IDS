import sqlite3
from pathlib import Path

db = Path(__file__).resolve().parents[1] / 'deepshield.db'
print('DB path:', db)
if not db.exists():
    print('DB not found')
else:
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute('DELETE FROM traffic_events;')
    conn.commit()
    cur.execute('SELECT COUNT(*) FROM traffic_events')
    print('traffic_events rows after delete:', cur.fetchone()[0])
    cur.execute('SELECT COUNT(*) FROM alerts')
    print('alerts rows:', cur.fetchone()[0])
    conn.close()
