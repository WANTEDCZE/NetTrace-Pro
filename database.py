"""SQLite persistence and schema migrations for NetTrace Pro."""
import os, sqlite3
DB_PATH = os.path.join(os.path.expanduser("~"), ".nettrace_pro", "history.sqlite3")

def db_connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=15000")
    return db

def ensure_db():
    with db_connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS samples (id INTEGER PRIMARY KEY, target TEXT, timestamp TEXT, latency REAL, packet_loss INTEGER)")
        db.execute("CREATE TABLE IF NOT EXISTS hop_samples (id INTEGER PRIMARY KEY, target TEXT, timestamp TEXT, hop INTEGER, address TEXT, latency REAL)")
        db.execute("CREATE TABLE IF NOT EXISTS tcp_samples (id INTEGER PRIMARY KEY, target TEXT, port INTEGER, timestamp TEXT, connect_ms REAL, success INTEGER)")
        db.execute("CREATE TABLE IF NOT EXISTS comparison_samples (id INTEGER PRIMARY KEY, target TEXT, port INTEGER, timestamp TEXT, icmp_ms REAL, tcp_ms REAL)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_samples_target_time ON samples(target,timestamp)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_hops_target_time ON hop_samples(target,timestamp)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_tcp_target_time ON tcp_samples(target,port,timestamp)")
        db.execute("CREATE TABLE IF NOT EXISTS device_scans (id INTEGER PRIMARY KEY, scanned_at TEXT, subnet TEXT, ip TEXT, hostname TEXT, mac TEXT, latency_ms REAL, status TEXT)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_device_scans_time ON device_scans(scanned_at,subnet)")
