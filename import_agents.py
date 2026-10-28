
import json
import os
import sqlite3
from pathlib import Path

from census import init_db

BASE_DIR = Path(__file__).resolve().parent
EXPORT_PATH = BASE_DIR / "public" / "agents.json"
DB_PATH = os.getenv(
    "DATABASE_PATH", "/var/data/census.sqlite3"
)

COLUMNS = [
    "agent_id",
    "display_name",
    "description",
    "kind",
    "canonical_identity",
    "primary_endpoint",
    "metadata_url",
    "protocol",
    "protocol_version",
    "operator_name",
    "operator_domain",
    "operator_verification",
    "operator_evidence",
    "metadata_valid",
    "endpoint_reachable",
    "endpoint_status",
    "validation_notes",
    "first_seen_at",
    "last_seen_at",
    "last_checked_at",
    "record_hash",
    "raw_json",
]


def import_agents():
    if not EXPORT_PATH.is_file():
        raise FileNotFoundError(EXPORT_PATH)

    Path(DB_PATH).parent.mkdir(
        parents=True, exist_ok=True
    )

    with EXPORT_PATH.open(encoding="utf-8") as f:
        records = json.load(f)

    if not isinstance(records, list) or not records:
        raise ValueError("Agent export is empty or invalid")

    conn = sqlite3.connect(DB_PATH, timeout=30)

    try:
        init_db(conn)

        placeholders = ", ".join(["?"] * len(COLUMNS))
        names = ", ".join(COLUMNS)

        
        sql = (
            f"INSERT INTO agents ({names}) "
            f"VALUES ({placeholders}) "
            "ON CONFLICT(agent_id) DO UPDATE SET "
            + ", ".join(
                f"{col}=excluded.{col}"
                for col in COLUMNS
                if col not in (
                    "agent_id",
                    "first_seen_at",
                )
            )
        )


        imported = 0

        with conn:
            for record in records:
                if not isinstance(record, dict):
                    continue

                if not record.get("agent_id"):
                    continue

                item = dict(record)

                item.setdefault(
                    "last_seen_at",
                    item.get("first_seen_at"),
                )
                item.setdefault("last_checked_at", None)
                item.setdefault("kind", "agent")
                item.setdefault(
                    "operator_verification", "unverified"
                )
                item.setdefault("metadata_valid", 0)
                item.setdefault("endpoint_reachable", 0)

                raw = item.get("raw_json")
                if raw is None:
    continue
                if not isinstance(raw, str):
                    item["raw_json"] = json.dumps(
                        raw, ensure_ascii=False
                    )

                values = [
                    item.get(column) for column in COLUMNS
                ]

                conn.execute(sql, values)
                imported += 1

        print(f"Imported {imported} agent records")

    finally:
        conn.close()


if __name__ == "__main__":
    import_agents()
