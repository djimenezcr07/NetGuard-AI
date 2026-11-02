import os,sqlite3
from pathlib import Path

SCHEMA="""
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS imports(id INTEGER PRIMARY KEY,name TEXT NOT NULL,created_at TEXT NOT NULL,accepted INTEGER NOT NULL,rejected INTEGER NOT NULL,source TEXT NOT NULL,columns_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,line INTEGER NOT NULL,timestamp TEXT NOT NULL,source_ip TEXT NOT NULL,destination_ip TEXT NOT NULL,source_port INTEGER,destination_port INTEGER NOT NULL,protocol TEXT NOT NULL,action TEXT NOT NULL,bytes INTEGER,fingerprint TEXT NOT NULL,UNIQUE(import_id,fingerprint));
CREATE INDEX IF NOT EXISTS ix_events_import_time ON events(import_id,timestamp);
CREATE TABLE IF NOT EXISTS rejected_rows(id INTEGER PRIMARY KEY,import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,line INTEGER NOT NULL,reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY,import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,created_at TEXT NOT NULL,params_json TEXT NOT NULL,steps_json TEXT NOT NULL,version TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY,run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,method TEXT NOT NULL,title TEXT NOT NULL,source_ip TEXT NOT NULL,destination_ip TEXT,start_time TEXT NOT NULL,end_time TEXT NOT NULL,metrics_json TEXT NOT NULL,details_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS finding_events(finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,PRIMARY KEY(finding_id,event_id));
PRAGMA user_version=1;
"""
def connect():
    path=Path(os.environ.get('NETGUARD_DB','data/netguard.db'));path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path,timeout=15);db.row_factory=sqlite3.Row;db.execute('PRAGMA foreign_keys=ON');return db

def initialize():
    with connect() as db:
        version=db.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0,1):raise RuntimeError('Versión de esquema no compatible.')
        db.executescript(SCHEMA)
