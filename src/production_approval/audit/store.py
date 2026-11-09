"""SQLite transactions serialize claims and persist signed transition evidence."""
import hashlib
import hmac
import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from production_approval.authorization.identity import Denied


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Store:
    def __init__(self, path, key):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key = bytes.fromhex(key)
        with closing(self.connect()) as c:
            c.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL,
                    signature TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT, state_mac TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS decisions (
                    request_id TEXT NOT NULL, person TEXT NOT NULL, decision TEXT NOT NULL,
                    signature TEXT NOT NULL, PRIMARY KEY (request_id, person));
                CREATE TABLE IF NOT EXISTS claims (resource TEXT PRIMARY KEY, request_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL, hash TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS immutable_payload BEFORE UPDATE OF payload, digest, signature ON requests
                    BEGIN SELECT RAISE(ABORT, 'request payload is immutable'); END;
            ''')
        self.path.chmod(0o600)

    def connect(self):
        c = sqlite3.connect(self.path, timeout=20, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA synchronous=FULL")
        return c

    @contextmanager
    def transaction(self):
        c = self.connect()
        try:
            c.execute("BEGIN IMMEDIATE")
            self.verify_audit(c)
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    def mac(self, value):
        return hmac.new(self.key, canonical(value).encode(), hashlib.sha256).hexdigest()

    def event(self, c, event):
        previous = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        event_hash = self.mac({"previous": previous[0] if previous else "GENESIS", "event": event})
        c.execute("INSERT INTO audit(body,hash) VALUES (?,?)", (canonical(event), event_hash))

    def verify_audit(self, c):
        previous = "GENESIS"
        expected_sequence = 1
        for row in c.execute("SELECT * FROM audit ORDER BY seq"):
            try:
                event = json.loads(row["body"])
            except (TypeError, ValueError) as e:
                raise Denied("audit_integrity_failure") from e
            if row["seq"] != expected_sequence or not hmac.compare_digest(
                row["hash"], self.mac({"previous": previous, "event": event})):
                raise Denied("audit_integrity_failure")
            previous = row["hash"]
            expected_sequence += 1

    def row(self, c, request_id):
        row = c.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise Denied("unknown_request")
        try:
            p = json.loads(row["payload"])
            receipt = json.loads(row["receipt"]) if row["receipt"] else None
        except (TypeError, ValueError) as e:
            raise Denied("payload_or_receipt_integrity_failure") from e
        if digest(p) != row["digest"] or not hmac.compare_digest(row["signature"], self.mac(p)):
            raise Denied("payload_integrity_failure")
        if not hmac.compare_digest(row["state_mac"], self.mac([request_id, row["digest"], row["state"], receipt])):
            raise Denied("state_integrity_failure")
        return {"id": request_id, "payload": p, "payload_hash": row["digest"], "state": row["state"], "receipt": receipt}

    def create(self, c, payload):
        d = digest(payload)
        c.execute("INSERT INTO requests VALUES (?,?,?,?,?,?,?)", (
            payload["request_id"], canonical(payload), d, self.mac(payload), "REQUESTED", None,
            self.mac([payload["request_id"], d, "REQUESTED", None])))

    def state(self, c, row, state, actor, timestamp, receipt=None):
        old = row["state"]
        c.execute("UPDATE requests SET state=?,receipt=?,state_mac=? WHERE id=?", (
            state, canonical(receipt) if receipt is not None else None,
            self.mac([row["id"], row["payload_hash"], state, receipt]), row["id"]))
        row.update(state=state, receipt=receipt)
        self.event(c, {"type": "transition", "request_id": row["id"], "from": old, "to": state,
                       "actor": actor, "timestamp": timestamp, "payload_hash": row["payload_hash"]})

    def history(self):
        with self.transaction() as c:
            return [dict(seq=r["seq"], **json.loads(r["body"]), evidence_hash=r["hash"])
                    for r in c.execute("SELECT * FROM audit ORDER BY seq")]
