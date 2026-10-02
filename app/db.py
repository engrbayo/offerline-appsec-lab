"""Data access. SR-4: every query is parameterized; no SQL is built from strings.

The lab uses an in-memory SQLite database seeded with two bank tenants so the
cross-tenant tests have something to attack."""
import sqlite3

SCHEMA = """
CREATE TABLE accounts (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, card_last4 TEXT NOT NULL);
CREATE TABLE transactions (id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
    merchant TEXT NOT NULL, amount_cents INTEGER NOT NULL, posted_on TEXT NOT NULL);
CREATE TABLE offers (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, merchant TEXT NOT NULL, cashback_pct REAL NOT NULL);
CREATE TABLE webhooks (tenant_id TEXT PRIMARY KEY, url TEXT NOT NULL);
"""

SEED = [
    ("INSERT INTO accounts VALUES (?, ?, ?)", [
        ("acct_a_001", "bank-a", "4242"),
        ("acct_b_001", "bank-b", "1881"),
    ]),
    ("INSERT INTO transactions VALUES (?, ?, ?, ?, ?)", [
        ("txn_1", "acct_a_001", "Coffee Co", 450, "2026-09-28"),
        ("txn_2", "acct_a_001", "Grocer", 8312, "2026-09-29"),
        ("txn_3", "acct_b_001", "Airline", 41200, "2026-09-30"),
    ]),
    ("INSERT INTO offers VALUES (?, ?, ?, ?)", [
        ("off_1", "bank-a", "Coffee Co", 10.0),
        ("off_2", "bank-b", "Airline", 3.0),
    ]),
]


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    for sql, rows in SEED:
        conn.executemany(sql, rows)
    conn.commit()
    return conn


def get_account(conn: sqlite3.Connection, account_id: str) -> dict | None:
    row = conn.execute("SELECT id, tenant_id, card_last4 FROM accounts WHERE id = ?", (account_id,)).fetchone()
    return dict(row) if row else None


def list_transactions(conn: sqlite3.Connection, account_id: str, limit: int) -> list[dict]:
    rows = conn.execute(
        "SELECT id, merchant, amount_cents, posted_on FROM transactions WHERE account_id = ? ORDER BY posted_on DESC LIMIT ?",
        (account_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def list_offers(conn: sqlite3.Connection, tenant_id: str) -> list[dict]:
    rows = conn.execute("SELECT id, merchant, cashback_pct FROM offers WHERE tenant_id = ?", (tenant_id,)).fetchall()
    return [dict(r) for r in rows]


def set_webhook(conn: sqlite3.Connection, tenant_id: str, url: str) -> None:
    conn.execute(
        "INSERT INTO webhooks VALUES (?, ?) ON CONFLICT(tenant_id) DO UPDATE SET url = excluded.url", (tenant_id, url)
    )
    conn.commit()
