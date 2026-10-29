"""Read-only HTTP API plus periodic ingestion worker. Run one process/worker only."""
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

from census import init_db, run_pipeline, counts
try:
    import psycopg
except ImportError:
    psycopg = None
try:
    import stripe
except ImportError:  # Billing routes return a clear setup error until the dependency is installed.
    stripe = None

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("agent-census-service")

DB_PATH = os.getenv("DATABASE_PATH", "/var/data/census.sqlite3")
CONFIG_PATH = os.getenv("SOURCES_CONFIG", "/app/sources.json")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/var/data/public")
REFRESH_SECONDS = max(900, int(os.getenv("REFRESH_SECONDS", "21600")))
_lock = threading.Lock()
_state_lock = threading.Lock()
_state = {"last_run_started_at": None, "last_run_finished_at": None,
          "last_run_status": "starting", "last_run_error": None,
          "last_ingested_source_records": 0, "last_sources_succeeded": 0,
          "last_sources_failed": 0}
DATABASE_URL = os.getenv("DATABASE_URL")

def _pg_conn():
    if not DATABASE_URL or psycopg is None:
        return None
    return psycopg.connect(DATABASE_URL)

def _init_status_store():
    conn = _pg_conn()
    if conn is None:
        return
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS ingestion_status (
                        id INTEGER PRIMARY KEY,
                        last_run_started_at TEXT,
                        last_run_finished_at TEXT,
                        last_run_status TEXT,
                        last_run_error TEXT,
                        last_ingested_source_records INTEGER NOT NULL DEFAULT 0,
                        last_sources_succeeded INTEGER NOT NULL DEFAULT 0,
                        last_sources_failed INTEGER NOT NULL DEFAULT 0,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    INSERT INTO ingestion_status (id)
                    VALUES (1)
                    ON CONFLICT (id) DO NOTHING
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS agent_snapshot (
                        agent_id TEXT PRIMARY KEY,
                        display_name TEXT,
                        description TEXT,
                        protocol TEXT,
                        operator_verification TEXT,
                        record JSONB NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)

                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_agent_snapshot_display_name
                    ON agent_snapshot (display_name)
                """)

                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_agent_snapshot_protocol
                    ON agent_snapshot (protocol)
                """)
    finally:
        conn.close()
        
def _init_waitlist_store():
    conn = _pg_conn()
    if conn is None:
        return

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS waitlist_leads (
                        lead_id BIGSERIAL PRIMARY KEY,
                        email TEXT NOT NULL UNIQUE,
                        role TEXT NOT NULL DEFAULT '',
                        use_case TEXT NOT NULL DEFAULT '',
                        consent_at TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        source_ip_hash TEXT NOT NULL
                    )
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS waitlist_submissions (
                        source_ip_hash TEXT NOT NULL,
                        hour_bucket TEXT NOT NULL,
                        submissions INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (source_ip_hash, hour_bucket)
                    )
                """)
    finally:
        conn.close()

def _save_status_to_postgres():
    conn = _pg_conn()
    if conn is None:
        return
    try:
        with _state_lock:
            state = dict(_state)

        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE ingestion_status
                    SET last_run_started_at = %s,
                        last_run_finished_at = %s,
                        last_run_status = %s,
                        last_run_error = %s,
                        last_ingested_source_records = %s,
                        last_sources_succeeded = %s,
                        last_sources_failed = %s,
                        updated_at = NOW()
                    WHERE id = 1
                """, (
                    state.get("last_run_started_at"),
                    state.get("last_run_finished_at"),
                    state.get("last_run_status"),
                    state.get("last_run_error"),
                    int(state.get("last_ingested_source_records", 0)),
                    int(state.get("last_sources_succeeded", 0)),
                    int(state.get("last_sources_failed", 0)),
                ))
    finally:
        conn.close()

def _restore_status_from_postgres():
    conn = _pg_conn()
    if conn is None:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT last_run_started_at,
                       last_run_finished_at,
                       last_run_status,
                       last_run_error,
                       last_ingested_source_records,
                       last_sources_succeeded,
                       last_sources_failed
                FROM ingestion_status
                WHERE id = 1
            """)
            row = cur.fetchone()

        if row:
            with _state_lock:
                _state.update(
                    last_run_started_at=row[0],
                    last_run_finished_at=row[1],
                    last_run_status=row[2] or "starting",
                    last_run_error=row[3],
                    last_ingested_source_records=row[4] or 0,
                    last_sources_succeeded=row[5] or 0,
                    last_sources_failed=row[6] or 0,
                )
    finally:
        conn.close()


def _restore_last_run():
    report_path = Path(OUTPUT_DIR) / "run_report.json"

    if not report_path.exists():
        bundled_report = (
            Path(__file__).resolve().parent
            / "public"
            / "run_report.json"
        )
        if bundled_report.exists():
            report_path = bundled_report

    if not report_path.exists():
        return

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))

        succeeded = int(report.get("sources_succeeded", 0))
        failed = int(report.get("sources_failed", 0))

        if succeeded == 0:
            status = "failed"
        elif failed:
            status = "partial_failure"
        else:
            status = "succeeded"
        with _state_lock:
            _state.update(
                last_run_finished_at=report.get("generated_at"),
                last_run_status=status,
                last_run_error=None,
                last_ingested_source_records=int(
                    report.get("ingested_source_records", 0)
                ),
                last_sources_succeeded=succeeded,
                last_sources_failed=failed,
            )

        log.info("Restored previous ingestion report from disk")

    except Exception:
        log.exception("Could not restore previous ingestion report")
_init_status_store()
_init_waitlist_store()
_restore_status_from_postgres()
_restore_last_run()
def _db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS billing_subscriptions (
      stripe_subscription_id TEXT PRIMARY KEY,
      stripe_customer_id TEXT NOT NULL,
      customer_email TEXT,
      plan TEXT NOT NULL,
      status TEXT NOT NULL,
      current_period_end INTEGER,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS api_keys (
      key_hash TEXT PRIMARY KEY,
      stripe_subscription_id TEXT NOT NULL,
      plan TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_used_at TEXT,
      revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS billing_events (
      event_id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      received_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS api_usage (
      key_hash TEXT NOT NULL,
      period TEXT NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (key_hash, period)
    );
    CREATE TABLE IF NOT EXISTS waitlist_leads (
      lead_id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      role TEXT NOT NULL DEFAULT '',
      use_case TEXT NOT NULL DEFAULT '',
      consent_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      source_ip_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS waitlist_submissions (
      source_ip_hash TEXT NOT NULL,
      hour_bucket TEXT NOT NULL,
      submissions INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (source_ip_hash, hour_bucket)
    );
    """)
    conn.commit()
    return conn


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


def _stripe_ready():
    if stripe is None or not os.getenv("STRIPE_SECRET_KEY"):
        return False
    stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
    return True


def _json_body(environ, max_bytes=100_000):
    try:
        length = max(0, min(max_bytes, int(environ.get("CONTENT_LENGTH") or "0")))
        raw = environ["wsgi.input"].read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def _api_key_auth(environ, conn):
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if not auth.startswith("Bearer "):
        return None, "missing_api_key"
    raw_key = auth[7:].strip()
    if not raw_key or len(raw_key) > 200:
        return None, "invalid_api_key"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    row = conn.execute("""SELECT k.key_hash, k.plan, k.revoked, s.status, s.current_period_end
        FROM api_keys k JOIN billing_subscriptions s
        ON s.stripe_subscription_id = k.stripe_subscription_id WHERE k.key_hash=?""", (key_hash,)).fetchone()
    if not row or row["revoked"]:
        return None, "invalid_api_key"
    if row["status"] not in ("active", "trialing"):
        return None, "subscription_inactive"
    if row["current_period_end"] and int(row["current_period_end"]) <= int(time.time()):
        return None, "subscription_period_expired"
    return dict(row), None


def _quota(plan):
    return {"developer": 10_000, "business": 100_000, "enterprise": 1_000_000}.get(plan, 0)


def _record_usage(conn, key_hash):
    period = datetime.now(timezone.utc).strftime("%Y-%m")
    conn.execute("INSERT INTO api_usage(key_hash,period,request_count) VALUES(?,?,1) "
                 "ON CONFLICT(key_hash,period) DO UPDATE SET request_count=request_count+1", (key_hash, period))
    count = conn.execute("SELECT request_count FROM api_usage WHERE key_hash=? AND period=?", (key_hash, period)).fetchone()[0]
    conn.execute("UPDATE api_keys SET last_used_at=? WHERE key_hash=?", (_utcnow(), key_hash))
    conn.commit()
    return count, period


def run_once(force=False):
    if not _lock.acquire(blocking=False):
        return {"status": "already_running"}

    started = datetime.now(timezone.utc).isoformat()

    with _state_lock:
        _state.update(
            last_run_started_at=started,
            last_run_status="running",
            last_run_error=None,
        )

    try:
        report = run_pipeline(CONFIG_PATH, DB_PATH, OUTPUT_DIR)
        succeeded = int(report.get("sources_succeeded", 0))
        failed = int(report.get("sources_failed", 0))
        if succeeded == 0:
            run_status = "failed"
            run_error = "No configured sources completed successfully"
        elif failed:
            run_status = "partial_failure"
            run_error = "One or more configured sources failed"
        else:
            run_status = "succeeded"
            run_error = None
        with _state_lock:
            _state.update(last_run_finished_at=datetime.now(timezone.utc).isoformat(),
                          last_run_status=run_status, last_run_error=run_error,
                          last_ingested_source_records=report.get("ingested_source_records", 0),
                          last_sources_succeeded=succeeded, last_sources_failed=failed)
        _save_status_to_postgres()
        log.info("Ingestion completed: %s", report)
        return {**report, "run_status": run_status}
    except Exception as exc:
        log.exception("Ingestion run failed")
        with _state_lock:
            _state.update(last_run_finished_at=datetime.now(timezone.utc).isoformat(),
                          last_run_status="failed", last_run_error=str(exc)[:500])
        _save_status_to_postgres()
        return {"status": "failed", "error": str(exc)[:500]}
    finally:
        _lock.release()


def _worker():
    # Start a first sync after web server startup, then run periodically.
    while True:
        run_once()
        time.sleep(REFRESH_SECONDS)


def _start_worker():
    thread = threading.Thread(target=_worker, name="census-refresh", daemon=True)
    thread.start()


def _rows_with_sources(conn, rows):
    results = [dict(row) for row in rows]
    ids = [row.get("agent_id") for row in results if row.get("agent_id")]
    if not ids:
        return results
    placeholders = ",".join("?" for _ in ids)
    source_rows = conn.execute(
        f"SELECT agent_id, source_name, source_url FROM source_records WHERE agent_id IN ({placeholders}) ORDER BY source_name",
        ids).fetchall()
    by_agent = {}
    for source in source_rows:
        item = {"name": source["source_name"], "url": source["source_url"]}
        if item not in by_agent.setdefault(source["agent_id"], []):
            by_agent[source["agent_id"]].append(item)
    for row in results:
        row["sources"] = by_agent.get(row.get("agent_id"), [])
    return results


def _public_run_state():
    # Keep internal exception text out of unauthenticated health/count endpoints.
    with _state_lock:
        state = dict(_state)
    return {
        "last_run_started_at": state.get("last_run_started_at"),
        "last_run_finished_at": state.get("last_run_finished_at"),
        "last_run_status": state.get("last_run_status"),
        "last_ingested_source_records": state.get("last_ingested_source_records", 0),
        "sources_succeeded": state.get("last_sources_succeeded", 0),
        "sources_failed": state.get("last_sources_failed", 0),
        "has_error": bool(state.get("last_run_error")),
    }


def _response(start_response, status, payload):
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    start_response(status, [("Content-Type", "application/json; charset=utf-8"),
                            ("Content-Length", str(len(body))),
                            ("Cache-Control", "no-store"),
                            ("Pragma", "no-cache"),
                            ("X-Content-Type-Options", "nosniff"),
                            ("X-Frame-Options", "DENY"),
                            ("Referrer-Policy", "no-referrer")])
    return [body]


def _html(start_response, status, content, cache="no-store"):
    body = content.encode("utf-8")
    start_response(status, [("Content-Type", "text/html; charset=utf-8"),
                            ("Content-Length", str(len(body))),
                            ("Cache-Control", cache),
                            ("X-Content-Type-Options", "nosniff"),
                            ("X-Frame-Options", "DENY"),
                            ("Referrer-Policy", "no-referrer"),
                            ("Content-Security-Policy", "default-src 'self' https://js.stripe.com; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")])
    return [body]


def _site_page(name):
    path = Path(__file__).resolve().parent / "site" / name
    return path.read_text(encoding="utf-8")


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    query = parse_qs(environ.get("QUERY_STRING", ""))
    if path == "/":
        try:
            return _html(start_response, "200 OK", _site_page("index.html"), cache="public, max-age=60")
        except Exception:
            return _response(start_response, "503 Service Unavailable", {"error": "site_unavailable"})
    if path == "/pricing":
        try:
            return _html(start_response, "200 OK", _site_page("pricing.html"), cache="public, max-age=60")
        except Exception:
            return _response(start_response, "503 Service Unavailable", {"error": "pricing_page_unavailable"})
    if path == "/admin":
        try:
            return _html(
                start_response,
                "200 OK",
                _site_page("admin.html"),
                cache="no-store",
            )
        except Exception:
            return _response(
                start_response,
                "503 Service Unavailable",
                {"error": "admin_page_unavailable"},
            )
    if path == "/privacy":
        try:
            return _html(start_response, "200 OK", _site_page("privacy.html"), cache="public, max-age=300")
        except Exception:
            return _response(start_response, "503 Service Unavailable", {"error": "privacy_page_unavailable"})
    if path == "/terms":
        try:
            return _html(start_response, "200 OK", _site_page("terms.html"), cache="public, max-age=300")
        except Exception:
            return _response(start_response, "503 Service Unavailable", {"error": "terms_page_unavailable"})
    if path in ("/healthz", "/health"):
        # Liveness only: a source outage must not cause the host to restart a healthy web process.
        return _response(start_response, "200 OK", {
            "status": "ok", "service": "global-agent-census",
            "refresh_seconds": REFRESH_SECONDS,
            "last_run": _public_run_state(),
        })
    if path == "/readyz":
        # Readiness is separate from liveness and fails until one successful ingest completes.
        state = _public_run_state()
        finished = state.get("last_run_finished_at")
        fresh = False
        if finished and state.get("last_run_status") in ("succeeded", "partial_failure") and state.get("sources_succeeded", 0) > 0:
            try:
                completed = datetime.fromisoformat(finished)
                fresh = (datetime.now(timezone.utc) - completed).total_seconds() <= max(REFRESH_SECONDS * 2, 86400)
            except (TypeError, ValueError):
                fresh = False
        status = "200 OK" if fresh else "503 Service Unavailable"
        return _response(start_response, status, {
            "status": "ready" if fresh else "not_ready",
            "service": "global-agent-census",
            "last_run": state,
        })
    if path == "/api/sources":
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as source_file:
                cfg = json.load(source_file)
            return _response(start_response, "200 OK", {
                "coverage_note": "No authoritative list of every public directory exists. Enabled sources may be partial; read each source's coverage_status and scope.",
                "sources": [{k: v for k, v in src.items() if k not in ("headers",)} for src in cfg.get("sources", [])],
            })
        except Exception:
            log.exception("Source inventory endpoint failed")
            return _response(start_response, "503 Service Unavailable", {"error": "source_inventory_unavailable"})
    if path == "/api/waitlist" and environ.get("REQUEST_METHOD", "GET").upper() == "POST":
        body = _json_body(environ)
        email = str(body.get("email", "")).strip().lower()[:254]
        role = str(body.get("role", "")).strip()[:80]
        use_case = str(body.get("use_case", "")).strip()[:1000]
        consent = body.get("consent") is True
        if not consent or len(email) < 6 or "@" not in email or "." not in email.rsplit("@", 1)[-1]:
            return _response(start_response, "400 Bad Request", {"error": "valid_email_and_explicit_consent_required"})
        salt = os.getenv("WAITLIST_IP_SALT", "").strip()
        if len(salt) < 32:
            return _response(start_response, "503 Service Unavailable", {"error": "waitlist_not_configured"})
        remote = str(environ.get("REMOTE_ADDR", "unknown"))[:100]
        ip_hash = hashlib.sha256((salt + remote).encode()).hexdigest()
        hour_bucket = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
        pg_conn = _pg_conn()

        if pg_conn is not None:
            try:
                with pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO waitlist_submissions
                            (source_ip_hash, hour_bucket, submissions)
                        VALUES (%s, %s, 1)
                        ON CONFLICT (source_ip_hash, hour_bucket)
                        DO UPDATE SET submissions =
                            waitlist_submissions.submissions + 1
                        RETURNING submissions
                        """,
                        (ip_hash, hour_bucket),
                    )
        
                    used = cur.fetchone()[0]
        
                    if used > 5:
                        pg_conn.rollback()
                        return _response(
                            start_response,
                            "429 Too Many Requests",
                            {"error": "submission_rate_limit_exceeded"},
                        )
        
                    now = _utcnow()
        
                    cur.execute(
                        """
                        INSERT INTO waitlist_leads
                            (
                                email,
                                role,
                                use_case,
                                consent_at,
                                created_at,
                                source_ip_hash
                            )
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (email)
                        DO UPDATE SET
                            role = EXCLUDED.role,
                            use_case = EXCLUDED.use_case,
                            consent_at = EXCLUDED.consent_at
                        """,
                        (email, role, use_case, now, now, ip_hash),
                    )
        
                    pg_conn.commit()
        
                return _response(
                    start_response,
                    "201 Created",
                    {
                        "ok": True,
                        "message": "Thanks. Your early-access request has been recorded.",
                    },
                )
        
            finally:
                pg_conn.close()
        
        else:
            conn = _db()
        
            try:
                conn.execute(
                    """
                    INSERT INTO waitlist_submissions
                        (source_ip_hash, hour_bucket, submissions)
                    VALUES (?, ?, 1)
                    ON CONFLICT(source_ip_hash, hour_bucket)
                    DO UPDATE SET submissions = submissions + 1
                    """,
                    (ip_hash, hour_bucket),
                )
        
                used = conn.execute(
                    """
                    SELECT submissions
                    FROM waitlist_submissions
                    WHERE source_ip_hash = ?
                      AND hour_bucket = ?
                    """,
                    (ip_hash, hour_bucket),
                ).fetchone()[0]
        
                if used > 5:
                    conn.rollback()
                    return _response(
                        start_response,
                        "429 Too Many Requests",
                        {"error": "submission_rate_limit_exceeded"},
                    )
        
                now = _utcnow()
        
                conn.execute(
                    """
                    INSERT INTO waitlist_leads
                        (
                            email,
                            role,
                            use_case,
                            consent_at,
                            created_at,
                            source_ip_hash
                        )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(email)
                    DO UPDATE SET
                        role = excluded.role,
                        use_case = excluded.use_case,
                        consent_at = excluded.consent_at
                    """,
                    (email, role, use_case, now, now, ip_hash),
                )
        
                conn.commit()
        
                return _response(
                    start_response,
                    "201 Created",
                    {
                        "ok": True,
                        "message": "Thanks. Your early-access request has been recorded.",
                    },
                )
            finally:
                conn.close()
        pg_conn = _pg_conn()

        if pg_conn is not None:
            try:
                with pg_conn.cursor() as cur:
                    cur.execute("""
                        SELECT
                            lead_id,
                            email,
                            role,
                            use_case,
                            consent_at,
                            created_at
                        FROM waitlist_leads
                        ORDER BY created_at DESC
                        LIMIT 1000
                    """)

                    rows = cur.fetchall()

                    leads = [
                        {
                            "lead_id": row[0],
                            "email": row[1],
                            "role": row[2],
                            "use_case": row[3],
                            "consent_at": row[4],
                            "created_at": row[5],
                        }
                        for row in rows
                    ]

                return _response(
                    start_response,
                    "200 OK",
                    {
                        "count": len(leads),
                        "leads": leads,
                    },
                )

            finally:
                pg_conn.close()

        else:
            conn = _db()

            try:
                rows = conn.execute(
                    """
                    SELECT
                        lead_id,
                        email,
                        role,
                        use_case,
                        consent_at,
                        created_at
                    FROM waitlist_leads
                    ORDER BY created_at DESC
                    LIMIT 1000
                    """
                ).fetchall()

                return _response(
                    start_response,
                    "200 OK",
                    {
                        "count": len(rows),
                        "leads": [dict(row) for row in rows],
                    },
                )

            finally:
                conn.close()
        try:
            rows = conn.execute("SELECT lead_id,email,role,use_case,consent_at,created_at FROM waitlist_leads ORDER BY created_at DESC LIMIT 1000").fetchall()
            return _response(start_response, "200 OK", {"count": len(rows), "leads": [dict(row) for row in rows]})
        finally:
            conn.close()
    if path == "/api/pricing":
        return _response(start_response, "200 OK", {
            "currency": "USD", "billing": "monthly", "plans": [
                {"id": "free", "price": 0, "features": ["Public search", "Basic metadata", "Census counts"]},
                {"id": "developer", "price": 29, "features": ["10,000 API requests/month", "API key", "Bulk-ready JSON API"]},
                {"id": "business", "price": 99, "features": ["100,000 API requests/month", "Higher API quota", "Search and filters"]},
                {"id": "enterprise", "price": "custom", "features": ["Custom quotas (by agreement)", "Scheduled feeds (roadmap / custom scope)", "Team and SLA options by agreement"]}
            ], "note": "Prices are launch proposals and should be validated with customers. Paid plans require Stripe configuration."})
    if path == "/billing/checkout" and environ.get("REQUEST_METHOD", "GET").upper() == "POST":
        if not _stripe_ready():
            return _response(start_response, "503 Service Unavailable", {"error": "billing_not_configured", "required": ["STRIPE_SECRET_KEY", "STRIPE_PRICE_DEVELOPER", "STRIPE_PRICE_BUSINESS", "APP_BASE_URL"]})
        body = _json_body(environ)
        plan = str(body.get("plan", "")).lower()
        email = str(body.get("email", "")).strip()[:254]
        if plan not in ("developer", "business") or "@" not in email:
            return _response(start_response, "400 Bad Request", {"error": "choose_developer_or_business_and_supply_email"})
        price_id = os.getenv("STRIPE_PRICE_" + plan.upper())
        base_url = os.getenv("APP_BASE_URL", "").rstrip("/")
        if not price_id or not base_url.startswith("https://"):
            return _response(start_response, "503 Service Unavailable", {"error": "stripe_prices_or_https_app_base_url_missing"})
        try:
            session = stripe.checkout.Session.create(
                mode="subscription", customer_email=email,
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=base_url + "/billing/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=base_url + "/pricing",
                metadata={"plan": plan},
                subscription_data={"metadata": {"plan": plan}},
            )
            return _response(start_response, "200 OK", {"checkout_url": session.url})
        except Exception as exc:
            log.exception("Stripe checkout creation failed")
            return _response(start_response, "502 Bad Gateway", {"error": "checkout_creation_failed"})
    if path == "/billing/webhook" and environ.get("REQUEST_METHOD", "GET").upper() == "POST":
        if not _stripe_ready() or not os.getenv("STRIPE_WEBHOOK_SECRET"):
            return _response(start_response, "503 Service Unavailable", {"error": "stripe_webhook_not_configured"})
        try:
            length = max(0, min(1_000_000, int(environ.get("CONTENT_LENGTH") or "0")))
            raw = environ["wsgi.input"].read(length)
            event = stripe.Webhook.construct_event(raw, environ.get("HTTP_STRIPE_SIGNATURE", ""), os.environ["STRIPE_WEBHOOK_SECRET"])
        except Exception:
            return _response(start_response, "400 Bad Request", {"error": "invalid_webhook_signature_or_payload"})
        conn = _db()
        try:
            if conn.execute("SELECT 1 FROM billing_events WHERE event_id=?", (event["id"],)).fetchone():
                return _response(start_response, "200 OK", {"received": True, "duplicate": True})
            obj = event["data"]["object"]
            etype = event["type"]
            sub = None
            if etype == "checkout.session.completed" and obj.get("subscription"):
                sub = stripe.Subscription.retrieve(obj["subscription"])
                customer_id = obj.get("customer") or sub.get("customer")
                email = (obj.get("customer_details") or {}).get("email") or obj.get("customer_email")
                plan = (obj.get("metadata") or {}).get("plan") or (sub.get("metadata") or {}).get("plan") or "developer"
                conn.execute("""INSERT INTO billing_subscriptions VALUES(?,?,?,?,?,?,?)
                  ON CONFLICT(stripe_subscription_id) DO UPDATE SET stripe_customer_id=excluded.stripe_customer_id,
                  customer_email=excluded.customer_email, plan=excluded.plan, status=excluded.status,
                  current_period_end=excluded.current_period_end, updated_at=excluded.updated_at""",
                  (sub["id"], customer_id, email, plan, sub.get("status", "active"), sub.get("current_period_end"), _utcnow()))
            elif etype in ("customer.subscription.updated", "customer.subscription.deleted"):
                sub = obj
                customer_id = sub.get("customer")
                existing = conn.execute("SELECT customer_email,plan FROM billing_subscriptions WHERE stripe_subscription_id=?", (sub["id"],)).fetchone()
                email = existing["customer_email"] if existing else None
                plan = (sub.get("metadata") or {}).get("plan") or (existing["plan"] if existing else "developer")
                conn.execute("""INSERT INTO billing_subscriptions VALUES(?,?,?,?,?,?,?)
                  ON CONFLICT(stripe_subscription_id) DO UPDATE SET status=excluded.status,
                  current_period_end=excluded.current_period_end, updated_at=excluded.updated_at""",
                  (sub["id"], customer_id, email, plan, "canceled" if etype.endswith("deleted") else sub.get("status", "inactive"), sub.get("current_period_end"), _utcnow()))
            conn.execute("INSERT INTO billing_events VALUES(?,?,?)", (event["id"], etype, _utcnow()))
            conn.commit()
        finally:
            conn.close()
        return _response(start_response, "200 OK", {"received": True})
    if path == "/billing/success":
        try:
            return _html(start_response, "200 OK", _site_page("success.html"))
        except Exception:
            return _response(start_response, "503 Service Unavailable", {"error": "success_page_unavailable"})
    if path == "/billing/activate" and environ.get("REQUEST_METHOD", "GET").upper() == "POST":
        # POST avoids link-preview crawlers consuming the one-time API-key activation link.
        # The browser removes the session id from its address bar before making this request.
        body = _json_body(environ, max_bytes=4096)
        sid = str(body.get("session_id", "")).strip()
        if not sid or len(sid) > 200 or not _stripe_ready():
            return _response(start_response, "400 Bad Request", {"error": "missing_session_or_billing_not_configured"})
        try:
            session = stripe.checkout.Session.retrieve(sid, expand=["subscription"])
            sub = session.get("subscription")
            if session.get("status") != "complete" or not sub or sub.get("status") not in ("active", "trialing"):
                return _response(start_response, "402 Payment Required", {"error": "subscription_not_active_yet"})
            plan = (session.get("metadata") or {}).get("plan") or (sub.get("metadata") or {}).get("plan") or "developer"
            if plan not in ("developer", "business", "enterprise"):
                plan = "developer"
            customer_id = session.get("customer") or sub.get("customer")
            email = (session.get("customer_details") or {}).get("email") or session.get("customer_email")
            conn = _db()
            try:
                conn.execute("""INSERT INTO billing_subscriptions VALUES(?,?,?,?,?,?,?)
                  ON CONFLICT(stripe_subscription_id) DO UPDATE SET status=excluded.status,
                  current_period_end=excluded.current_period_end, updated_at=excluded.updated_at""",
                  (sub["id"], customer_id, email, plan, sub.get("status", "active"), sub.get("current_period_end"), _utcnow()))
                # Session ID is the one-time redemption marker. Store it in the event table to prevent key re-issuance.
                if conn.execute("SELECT 1 FROM billing_events WHERE event_id=?", ("activate:"+sid,)).fetchone():
                    return _response(start_response, "409 Conflict", {"error": "key_already_issued", "message": "Contact support to rotate your key."})
                raw_key = "gac_" + secrets.token_urlsafe(32)
                key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
                conn.execute("INSERT INTO api_keys(key_hash,stripe_subscription_id,plan,created_at) VALUES(?,?,?,?)", (key_hash, sub["id"], plan, _utcnow()))
                conn.execute("INSERT INTO billing_events VALUES(?,?,?)", ("activate:"+sid, "key.issued", _utcnow()))
                conn.commit()
            finally:
                conn.close()
            return _response(start_response, "200 OK", {"message": "Subscription active. Save this API key now; it will not be shown again.", "api_key": raw_key, "plan": plan, "monthly_request_limit": _quota(plan)})
        except Exception as exc:
            log.exception("Billing activation failed")
            return _response(start_response, "502 Bad Gateway", {"error": "activation_failed"})
    if path in ("/api/v1/counts", "/api/v1/agents", "/api/v1/usage"):
        try:
            conn = _db()
            try:
                auth, auth_error = _api_key_auth(environ, conn)
                if auth_error:
                    return _response(start_response, "401 Unauthorized", {"error": auth_error, "message": "Send Authorization: Bearer YOUR_API_KEY"})
                used, period = _record_usage(conn, auth["key_hash"])
                limit_for_plan = _quota(auth["plan"])
                if used > limit_for_plan:
                    return _response(start_response, "429 Too Many Requests", {"error": "monthly_quota_exceeded", "used": used, "limit": limit_for_plan, "period": period})
                if path == "/api/v1/usage":
                    return _response(start_response, "200 OK", {"plan": auth["plan"], "period": period, "used": used, "limit": limit_for_plan, "remaining": max(0, limit_for_plan-used)})
                if path == "/api/v1/counts":
                    return _response(start_response, "200 OK", {"plan": auth["plan"], "counts": counts(conn), "usage": {"period": period, "used": used, "limit": limit_for_plan}})
                limit = min(200, max(1, int(query.get("limit", ["50"])[0])))
                offset = max(0, int(query.get("offset", ["0"])[0]))
                search = query.get("q", [""])[0].strip()[:200]
                where, params = ("", [])
                if search:
                    where = "WHERE display_name LIKE ? OR description LIKE ? OR protocol LIKE ?"
                    like = "%" + search + "%"
                    params.extend([like, like, like])
                total = conn.execute("SELECT COUNT(*) FROM agents " + where, params).fetchone()[0]
                rows = conn.execute("SELECT agent_id,display_name,description,kind,canonical_identity,primary_endpoint,metadata_url,protocol,protocol_version,operator_name,operator_domain,operator_verification,metadata_valid,endpoint_reachable,endpoint_status,validation_notes,first_seen_at,last_seen_at,last_checked_at FROM agents " + where + " ORDER BY display_name COLLATE NOCASE LIMIT ? OFFSET ?", params+[limit,offset]).fetchall()
                return _response(start_response, "200 OK", {"plan": auth["plan"], "total": total, "limit": limit, "offset": offset, "results": _rows_with_sources(conn, rows), "usage": {"period": period, "used": used, "limit": limit_for_plan}})
            finally:
                conn.close()
        except Exception:
            log.exception("Authenticated API request failed")
            return _response(start_response, "400 Bad Request", {"error": "invalid_request_or_data_unavailable"})
    
    if path == "/api/counts":
    try:
        conn = _db()
        try:
                
            state = _public_run_state()
            snapshot_path = Path(OUTPUT_DIR) / "counts.json"

            if not snapshot_path.exists():
                    bundled_snapshot = (
                    Path(__file__).resolve().parent
                    / "public"
                    / "counts.json"
                    )
                    if bundled_snapshot.exists():
                        snapshot_path = bundled_snapshot

            if snapshot_path.exists():
                data = json.loads(
                    snapshot_path.read_text(encoding="utf-8")
                )
            else:
                data = counts(conn)

                data["service"] = state
                return _response(start_response, "200 OK", data)
            finally:
                conn.close()
        except Exception:
            log.exception("Census counts endpoint failed")
            return _response(
                start_response,
                "503 Service Unavailable",
                {"error": "census_counts_unavailable"},
            )

    if path == "/api/agents":
        try:
            limit = min(200, max(1, int(query.get("limit", ["50"])[0])))
            offset = max(0, int(query.get("offset", ["0"])[0]))
            search = query.get("q", [""])[0].strip()[:200]
            conn = _db()
            try:
                where = ""
                params = []
                if search:
                    where = "WHERE display_name LIKE ? OR description LIKE ? OR protocol LIKE ?"
                    like = "%" + search + "%"
                    params.extend([like, like, like])
                total = conn.execute("SELECT COUNT(*) FROM agents " + where, params).fetchone()[0]
                rows = conn.execute(
                    "SELECT agent_id, display_name, description, kind, canonical_identity, primary_endpoint, "
                    "metadata_url, protocol, protocol_version, operator_name, operator_domain, "
                    "operator_verification, metadata_valid, endpoint_reachable, endpoint_status, "
                    "validation_notes, first_seen_at, last_seen_at, last_checked_at "
                    "FROM agents " + where + " ORDER BY display_name COLLATE NOCASE LIMIT ? OFFSET ?",
                    params + [limit, offset]).fetchall()
                return _response(start_response, "200 OK", {
                    "total": total, "limit": limit, "offset": offset,
                    "results": _rows_with_sources(conn, rows)
                })
            finally:
                conn.close()
        except Exception:
            log.exception("Public agent search failed")
            return _response(start_response, "400 Bad Request", {"error": "invalid_query_or_data_unavailable"})
    return _response(start_response, "404 Not Found", {
        "error": "not_found", "routes": ["/", "/pricing", "/privacy", "/terms", "/healthz", "/readyz", "/api/pricing", "/api/waitlist (POST; GET requires WAITLIST_ADMIN_TOKEN)", "/billing/checkout (POST)", "/billing/webhook (POST)", "/billing/success?session_id=...", "/billing/activate (POST)", "/api/v1/counts", "/api/v1/agents", "/api/v1/usage", "/api/counts", "/api/sources", "/api/agents?q=search&limit=50&offset=0"]
    })


# Gunicorn imports this module once with one worker as configured in the deployment files.
_start_worker()
