"""SQLite persistence for scan history and findings."""
from ._imports import *

class SecretPulseDB:
    """
    SQLite-backed persistence for findings, subdomains, scan history.
    Enables historical comparison, URL change tracking, and correlation.
    """

    DB_DIR = Path.home() / '.SecretPulse'
    DB_PATH = DB_DIR / 'SecretPulse.db'

    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(self.DB_PATH)
        self.DB_DIR.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self):
        """Create tables if they don't exist."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                urls_scanned INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                duration_seconds REAL,
                config TEXT
            );

            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                source TEXT DEFAULT 'unknown',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_alive INTEGER DEFAULT 0,
                ip_address TEXT,
                risk_score INTEGER DEFAULT 0,
                risk_factors TEXT,
                http_status INTEGER,
                server_header TEXT,
                technologies TEXT,
                UNIQUE(domain, subdomain)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                type TEXT NOT NULL,
                value_hash TEXT NOT NULL,
                value_preview TEXT,
                source TEXT,
                severity TEXT,
                confidence INTEGER,
                risk_score INTEGER,
                verified_live INTEGER DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                times_seen INTEGER DEFAULT 1,
                status TEXT DEFAULT 'active',
                raw_json TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS scan_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                status_code INTEGER,
                content_hash TEXT,
                last_scanned TEXT,
                changed_since_last INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                finding_id INTEGER NOT NULL,
                value_hash TEXT NOT NULL,
                UNIQUE(scan_id, finding_id),
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            );

            CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
            CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(value_hash);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
            CREATE INDEX IF NOT EXISTS idx_scan_urls_url ON scan_urls(url);
            CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scan_findings_hash ON scan_findings(value_hash);
        """)
        self.conn.execute(
            """INSERT OR IGNORE INTO scan_findings (scan_id, finding_id, value_hash)
               SELECT scan_id, id, value_hash FROM findings WHERE scan_id IS NOT NULL"""
        )
        self.conn.commit()

    def start_scan(self, target: str, config: dict = None) -> int:
        """Register a new scan, return scan_id."""
        cur = self.conn.execute(
            "INSERT INTO scans (target, started_at, config) VALUES (?, ?, ?)",
            (target, datetime.now(timezone.utc).isoformat(),
             json.dumps(config) if config else None)
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int, urls_scanned: int, findings_count: int, duration: float):
        """Mark scan complete."""
        self.conn.execute(
            """UPDATE scans SET finished_at=?, urls_scanned=?,
               findings_count=?, duration_seconds=? WHERE id=?""",
            (datetime.now(timezone.utc).isoformat(), urls_scanned,
             findings_count, round(duration, 2), scan_id)
        )
        self.conn.commit()

    def save_subdomain(self, domain: str, subdomain: str, source: str = 'ct',
                       is_alive: bool = False, ip_address: str = None,
                       risk_score: int = 0, risk_factors: list = None):
        """Upsert a subdomain record."""
        now = datetime.now(timezone.utc).isoformat()
        existing = self.conn.execute(
            "SELECT id FROM subdomains WHERE domain=? AND subdomain=?",
            (domain, subdomain)
        ).fetchone()
        if existing:
            self.conn.execute(
                """UPDATE subdomains SET last_seen=?, is_alive=?,
                   ip_address=COALESCE(?, ip_address),
                   risk_score=MAX(risk_score, ?),
                   risk_factors=COALESCE(?, risk_factors) WHERE id=?""",
                (now, int(is_alive), ip_address, risk_score,
                 json.dumps(risk_factors) if risk_factors else None, existing['id'])
            )
        else:
            self.conn.execute(
                """INSERT INTO subdomains
                   (domain, subdomain, source, first_seen, last_seen,
                    is_alive, ip_address, risk_score, risk_factors)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (domain, subdomain, source, now, now, int(is_alive),
                 ip_address, risk_score,
                 json.dumps(risk_factors) if risk_factors else None)
            )
        self.conn.commit()

    def save_finding(self, scan_id: int, finding: dict):
        """Upsert a finding and link it to the current scan."""
        value_hash = hashlib.sha256(
            f"{finding.get('type', '')}:{finding.get('value', '')}".encode()
        ).hexdigest()[:16]
        now = datetime.now(timezone.utc).isoformat()
        confidence = finding.get('confidence_score')
        if confidence is None:
            confidence = {'HIGH': 80, 'MEDIUM': 50, 'LOW': 20}.get(
                str(finding.get('confidence', '')).upper(), 0)
        verified_live = int(bool(finding.get('verified_live')))
        existing = self.conn.execute(
            "SELECT id, times_seen FROM findings WHERE value_hash=?",
            (value_hash,)
        ).fetchone()
        if existing:
            finding_id = existing['id']
            self.conn.execute(
                """UPDATE findings SET last_seen=?, times_seen=times_seen+1,
                   severity=?, confidence=?, verified_live=?,
                   risk_score=? WHERE id=?""",
                (now, finding.get('severity', '') or '',
                 confidence, verified_live,
                 finding.get('risk_score') or 0, finding_id)
            )
        else:
            cur = self.conn.execute(
                """INSERT INTO findings
                   (scan_id, type, value_hash, value_preview, source, severity,
                    confidence, risk_score, verified_live, first_seen, last_seen, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, finding.get('type', '') or '', value_hash,
                 (finding.get('value', '') or '')[:30] + '...', finding.get('source', '') or '',
                 finding.get('severity', '') or '', confidence,
                 finding.get('risk_score') or 0, verified_live,
                 now, now, json.dumps(finding, default=str))
            )
            finding_id = cur.lastrowid
        self.conn.execute(
            """INSERT OR IGNORE INTO scan_findings (scan_id, finding_id, value_hash)
               VALUES (?, ?, ?)""",
            (scan_id, finding_id, value_hash)
        )
        self.conn.commit()

    def get_subdomains(self, domain: str, alive_only: bool = False) -> List[dict]:
        """Get all known subdomains for a domain."""
        query = "SELECT * FROM subdomains WHERE domain=?"
        if alive_only:
            query += " AND is_alive=1"
        query += " ORDER BY risk_score DESC"
        return [dict(row) for row in self.conn.execute(query, (domain,)).fetchall()]

    def get_finding_history(self, value_hash: str) -> List[dict]:
        """Get all sightings of a specific finding."""
        return [dict(row) for row in self.conn.execute(
            "SELECT * FROM findings WHERE value_hash=? ORDER BY first_seen",
            (value_hash,)
        ).fetchall()]

    def get_scan_history(self, target: str = None, limit: int = 20) -> List[dict]:
        """Get recent scan history."""
        if target:
            rows = self.conn.execute(
                "SELECT * FROM scans WHERE target LIKE ? ORDER BY id DESC LIMIT ?",
                (f"%{target}%", limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def has_url_changed(self, url: str, content_hash: str) -> bool:
        """Check if URL content changed since the last recorded scan."""
        row = self.conn.execute(
            "SELECT content_hash FROM scan_urls WHERE url=? ORDER BY id DESC LIMIT 1",
            (url,)
        ).fetchone()
        if row and row['content_hash'] == content_hash:
            return False
        return True

    def save_url_state(self, scan_id: int, url: str, status_code: int, content_hash: str):
        """Record URL state for differential scanning."""
        self.conn.execute(
            """INSERT INTO scan_urls (scan_id, url, status_code, content_hash, last_scanned)
               VALUES (?, ?, ?, ?, ?)""",
            (scan_id, url, status_code, content_hash,
             datetime.now(timezone.utc).isoformat())
        )
        self.conn.commit()

    def get_stats(self) -> dict:
        """Get overall database statistics."""
        stats = {}
        stats['total_scans'] = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        stats['total_subdomains'] = self.conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0]
        stats['alive_subdomains'] = self.conn.execute(
            "SELECT COUNT(*) FROM subdomains WHERE is_alive=1").fetchone()[0]
        stats['total_findings'] = self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        stats['active_findings'] = self.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE status='active'").fetchone()[0]
        stats['unique_domains'] = self.conn.execute(
            "SELECT COUNT(DISTINCT domain) FROM subdomains").fetchone()[0]
        return stats

    def get_previous_scan_data(self, target: str) -> dict:
        """Get the previous scan's findings, subdomains, and URLs for diff comparison."""
        # Find the most recent completed scan for this target
        row = self.conn.execute(
            "SELECT id FROM scans WHERE target LIKE ? AND finished_at IS NOT NULL "
            "ORDER BY id DESC LIMIT 1",
            (f"%{target}%",)
        ).fetchone()
        if not row:
            return {}
        prev_scan_id = row['id']

        # Get previous findings
        prev_findings = [dict(r) for r in self.conn.execute(
            "SELECT f.type, f.value_hash, f.value_preview, f.source, f.severity, f.confidence "
            "FROM findings f JOIN scan_findings sf ON sf.finding_id=f.id "
            "WHERE sf.scan_id=?", (prev_scan_id,)
        ).fetchall()]

        # Get previous subdomains
        prev_subdomains = [dict(r) for r in self.conn.execute(
            "SELECT subdomain, is_alive, risk_score FROM subdomains WHERE domain LIKE ?",
            (f"%{target}%",)
        ).fetchall()]

        # Get previous scanned URLs
        prev_urls = [dict(r) for r in self.conn.execute(
            "SELECT url, content_hash FROM scan_urls WHERE scan_id=?", (prev_scan_id,)
        ).fetchall()]

        return {
            'scan_id': prev_scan_id,
            'findings': prev_findings,
            'subdomains': prev_subdomains,
            'urls': prev_urls,
            'finding_hashes': {f['value_hash'] for f in prev_findings},
            'url_hashes': {u['url']: u['content_hash'] for u in prev_urls},
            'subdomain_set': {s['subdomain'] for s in prev_subdomains},
        }

    def close(self):
        self.conn.close()
