#!/usr/bin/env python3
"""
Global AI Agent Census pipeline.

Python 3.11+, standard library only.
- Ingests official MCP Registry pages and configurable JSON feeds.
- Normalizes records and deduplicates on source IDs, canonical identity, then endpoint.
- Validates public metadata and performs conservative HTTPS/HTTP reachability checks.
- Stores snapshots and change events in SQLite.
- Reports listed, metadata-valid/reachable, and independently verified operator counts.

Security: endpoint checks are limited to fetching declared public metadata URLs or
A2A Agent Cards. This tool does not invoke agent tasks, tools, RPC methods, or MCP tools.
Run only on infrastructure where outbound HTTP is permitted and follow each source's terms.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_VERSION = "0.2.0"
DEFAULT_DB = "census.sqlite3"
DEFAULT_CONFIG = "sources.json"
USER_AGENT = f"GlobalAgentCensus/{APP_VERSION} (+public-metadata-indexer)"
MAX_BODY_BYTES = 2_000_000
TIMEOUT_SECONDS = 20
MAX_PAGES = 10000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("agent-census")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def clean_text(value: Any, limit: int = 2000) -> str | None:
    if not isinstance(value, str):
        return None
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit] or None


def canonical_url(url: Any) -> str | None:
    if not isinstance(url, str):
        return None
    try:
        p = urllib.parse.urlsplit(url.strip())
        if p.scheme.lower() not in ("http", "https") or not p.hostname:
            return None
        host = p.hostname.lower().rstrip(".")
        port = p.port
        netloc = host
        if port and not ((p.scheme.lower() == "https" and port == 443) or
                         (p.scheme.lower() == "http" and port == 80)):
            netloc += f":{port}"
        path = p.path or "/"
        # Keep path and query because endpoint paths may distinguish agents.
        return urllib.parse.urlunsplit((p.scheme.lower(), netloc, path, p.query, ""))
    except (ValueError, AttributeError):
        return None


def request_bytes(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    url = canonical_url(url)
    if not url:
        raise ValueError("URL must be absolute HTTP(S)")
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.5"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                raise ValueError(f"Response exceeds {MAX_BODY_BYTES} bytes")
            return response.status, dict(response.headers.items()), body
    except urllib.error.HTTPError as e:
        # Preserve status/body for diagnostics, without treating HTTP errors as healthy.
        body = e.read(MAX_BODY_BYTES + 1)
        return e.code, dict(e.headers.items()), body[:MAX_BODY_BYTES]


def fetch_json(url: str, headers: dict[str, str] | None = None) -> tuple[int, Any, dict[str, str]]:
    status, response_headers, body = request_bytes(url, headers)
    if status < 200 or status >= 300:
        raise RuntimeError(f"HTTP {status} fetching {url}")
    content_type = response_headers.get("Content-Type", response_headers.get("content-type", ""))
    try:
        data = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Expected JSON from {url}; content-type={content_type!r}") from exc
    return status, data, response_headers


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS agents (
      agent_id TEXT PRIMARY KEY,
      display_name TEXT,
      description TEXT,
      kind TEXT NOT NULL DEFAULT 'agent',
      canonical_identity TEXT,
      primary_endpoint TEXT,
      metadata_url TEXT,
      protocol TEXT,
      protocol_version TEXT,
      operator_name TEXT,
      operator_domain TEXT,
      operator_verification TEXT NOT NULL DEFAULT 'unverified',
      operator_evidence TEXT,
      metadata_valid INTEGER NOT NULL DEFAULT 0,
      endpoint_reachable INTEGER NOT NULL DEFAULT 0,
      endpoint_status INTEGER,
      validation_notes TEXT,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      last_checked_at TEXT,
      record_hash TEXT NOT NULL,
      raw_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS source_records (
      source_name TEXT NOT NULL,
      source_record_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      source_url TEXT,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      PRIMARY KEY (source_name, source_record_id),
      FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
    );
    CREATE TABLE IF NOT EXISTS snapshots (
      snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      record_hash TEXT NOT NULL,
      record_json TEXT NOT NULL,
      FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
    );
    CREATE TABLE IF NOT EXISTS change_events (
      event_id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_id TEXT NOT NULL,
      changed_at TEXT NOT NULL,
      event_type TEXT NOT NULL,
      previous_hash TEXT,
      current_hash TEXT,
      details TEXT,
      FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
    );
    CREATE TABLE IF NOT EXISTS source_runs (
      run_id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_name TEXT NOT NULL,
      started_at TEXT NOT NULL,
      finished_at TEXT,
      status TEXT NOT NULL,
      records_seen INTEGER NOT NULL DEFAULT 0,
      error TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_agents_endpoint ON agents(primary_endpoint);
    CREATE INDEX IF NOT EXISTS idx_agents_identity ON agents(canonical_identity);
    CREATE INDEX IF NOT EXISTS idx_agents_last_checked ON agents(last_checked_at);
    CREATE INDEX IF NOT EXISTS idx_source_records_agent ON source_records(agent_id);
    """)


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)
    if not isinstance(config, dict) or not isinstance(config.get("sources", []), list):
        raise ValueError("Config must be an object with a 'sources' array")
    return config


def mcp_registry_records(source: dict[str, Any]) -> list[dict[str, Any]]:
    """Read all public latest-version records from the official MCP Registry."""
    base = source.get("base_url", "https://registry.modelcontextprotocol.io")
    page_size = int(source.get("page_size", 50))
    cursor = None
    records: list[dict[str, Any]] = []
    seen_cursors = set()
    for _ in range(MAX_PAGES):
        params = {"limit": str(page_size), "version": source.get("version", "latest")}
        if cursor:
            params["cursor"] = cursor
        url = base.rstrip("/") + "/v0.1/servers?" + urllib.parse.urlencode(params)
        last_error = None
        for attempt in range(3):
            try:
                _, payload, _ = fetch_json(url)
                last_error = None
                break
            except (TimeoutError, urllib.error.URLError, RuntimeError) as exc:
                last_error = exc
                log.warning(
                    "MCP Registry page fetch failed (attempt %d/3): %s",
                    attempt + 1,
                    exc,
                )
                if attempt < 2:
                    time.sleep(2 ** attempt)

        if last_error is not None:
            raise last_error
        if isinstance(payload, list):
            batch = payload
            next_cursor = None
        elif isinstance(payload, dict):
            batch = payload.get("servers", payload.get("data", []))
            metadata = payload.get("metadata") or {}
            next_cursor = (payload.get("nextCursor") or payload.get("next_cursor")
                           or payload.get("cursor") or metadata.get("nextCursor"))
        else:
            raise ValueError("Unexpected MCP registry response shape")
        if not isinstance(batch, list):
            raise ValueError("MCP registry response lacks a records array")
        for item in batch:
            if not isinstance(item, dict):
                continue
            server = item.get("server") if isinstance(item.get("server"), dict) else item
            meta = item.get("_meta") if isinstance(item.get("_meta"), dict) else {}
            name = server.get("name") or server.get("id")
            version = server.get("version") or meta.get("version")
            records.append({
                "source_record_id": f"{name or stable_hash(server)}@{version or 'unknown'}",
                "name": server.get("name") or name,
                "description": server.get("description"),
                "kind": "mcp_server",
                "protocol": "MCP",
                "protocol_version": version,
                "primary_endpoint": (
                    server.get("url") or server.get("remoteUrl") or
                    ((server.get("remotes") or [{}])[0].get("url")
                     if isinstance(server.get("remotes"), list) and server.get("remotes") else None)
                ),
                "metadata_url": None,
                "canonical_identity": f"mcp:{name}" if name else None,
                "operator_name": None,
                "operator_domain": None,
                # MCP namespace publication is a source-provided claim, not automatically
                # our independent verification of the real-world operator.
                "operator_verification": "source_claim",
                "operator_evidence": "Published in official MCP Registry; operator not independently verified by this census",
                "raw": item,
                "source_url": url,
            })
        if not next_cursor or next_cursor in seen_cursors:
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    else:
        raise RuntimeError("MCP registry pagination safety limit reached")
    return records



def _extract_items(payload: Any, keys: tuple[str, ...] = ("agents", "servers", "results", "items", "data")) -> list[dict[str, Any]]:
    """Extract common public-directory response shapes without assuming a schema."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
            if isinstance(value, dict):
                nested = _extract_items(value, keys)
                if nested:
                    return nested
    return []


def a2a_registry_records(source: dict[str, Any]) -> list[dict[str, Any]]:
    """Search the public A2A registry with a bounded set of discovery queries.

    The documented endpoint is search-oriented and doesn't document exhaustive pagination,
    so this adapter deliberately reports a discovery sample, not a complete registry dump.
    """
    base = source.get("base_url", "https://api.a2a-registry.org").rstrip("/")
    terms = source.get("query_terms", ["assistant", "research", "search", "finance", "weather", "coding", "data", "travel"])
    seen: dict[str, dict[str, Any]] = {}
    for term in terms[:40]:
        url = base + "/public/agents?" + urllib.parse.urlencode({"q": str(term)})
        _, payload, _ = fetch_json(url)
        items = _extract_items(payload, ("agents", "results", "items", "data"))
        for item in items:
            ident = item.get("id") or item.get("identifier") or item.get("package_name") or item.get("packageName")
            name = item.get("displayName") or item.get("name") or item.get("title") or ident
            if not ident and not name:
                continue
            key = str(ident or name).strip()
            endpoint = (item.get("url") or item.get("endpoint") or item.get("agentUrl") or
                        item.get("agent_url") or item.get("agentCardUrl") or item.get("manifest_url"))
            seen[key] = {
                "source_record_id": key, "name": name,
                "description": item.get("description") or item.get("summary"),
                "kind": "agent", "protocol": "A2A",
                "protocol_version": item.get("protocolVersion"),
                "primary_endpoint": endpoint,
                "metadata_url": item.get("agentCardUrl") or item.get("agent_card_url") or item.get("manifest_url"),
                "canonical_identity": "a2a:" + key.lower(),
                "operator_name": item.get("publisher") or item.get("organization"),
                "operator_domain": item.get("domain"),
                "operator_verification": "source_claim",
                "operator_evidence": "Listed by public A2A Registry; operator not independently verified by this census",
                "raw": item, "source_url": url,
            }
    return list(seen.values())


def github_markdown_directory_records(source: dict[str, Any]) -> list[dict[str, Any]]:
    """Index repository/project links in a public Awesome-style Markdown directory."""
    url = source["url"]
    status, headers, body = request_bytes(url, {"Accept": "text/plain, text/markdown, */*"})
    if status < 200 or status >= 300:
        raise RuntimeError(f"HTTP {status} fetching directory Markdown")
    text_body = body.decode("utf-8", "replace")
    # Only markdown links, avoid bare links and images; link labels become display names.
    pattern = re.compile(r"(?m)^\s*(?:[-*+]\s+|\d+[.)]\s+)?\[([^\]]{2,180})\]\((https?://[^)\s]+)\)(?:\s*[-–—:]\s*(.*))?\s*$")
    records = []
    seen_urls = set()
    for label, target, desc in pattern.findall(text_body):
        target = target.rstrip(".,;")
        parsed = urllib.parse.urlsplit(target)
        if parsed.hostname not in {"github.com", "www.github.com", "gitlab.com", "codeberg.org"}:
            continue
        target = canonical_url(target) or target
        if target in seen_urls:
            continue
        seen_urls.add(target)
        records.append({
            "source_record_id": target, "name": clean_text(label, 300),
            "description": clean_text(desc, 1000), "kind": source.get("kind", "mcp_project"),
            "protocol": source.get("protocol", "MCP"), "protocol_version": None,
            "primary_endpoint": None, "metadata_url": None,
            "canonical_identity": "project:" + target.lower(),
            "operator_name": None, "operator_domain": parsed.hostname,
            "operator_verification": "unverified", "operator_evidence": None,
            "raw": {"directory_url": url, "project_url": target, "label": label, "description": desc},
            "source_url": url,
        })
    return records


def glama_directory_records(source: dict[str, Any]) -> list[dict[str, Any]]:
    """Mirror Glama's MCP connector catalog with its required API key and cursor pagination."""
    token_env = source.get("token_env", "GLAMA_API_KEY")
    token = os.environ.get(token_env)
    if not token:
        raise RuntimeError(f"Source requires {token_env}; add it as a hosting secret before enabling this source")
    base = source.get("base_url", "https://glama.ai/api/mcp").rstrip("/")
    collection = source.get("collection", "connectors")
    cursor = None
    seen_cursors = set()
    records: dict[str, dict[str, Any]] = {}
    for _ in range(MAX_PAGES):
        params = {"first": str(min(100, int(source.get("page_size", 100))))}
        if cursor:
            params["after"] = cursor
        url = base + "/v1/" + collection + "?" + urllib.parse.urlencode(params)
        _, payload, _ = fetch_json(url, {"Authorization": "Bearer " + token})
        items = _extract_items(payload, ("connectors", "servers", "items", "results", "data"))
        for item in items:
            ident = item.get("id") or item.get("slug") or item.get("name") or item.get("url")
            name = item.get("name") or item.get("title") or item.get("slug") or ident
            if not ident or not name:
                continue
            record_url = item.get("url") or item.get("link")
            endpoint = item.get("endpoint") or item.get("mcpUrl") or item.get("remoteUrl")
            records[str(ident)] = {
                "source_record_id": str(ident), "name": name,
                "description": item.get("description"), "kind": "mcp_server", "protocol": "MCP",
                "protocol_version": None, "primary_endpoint": endpoint, "metadata_url": None,
                "canonical_identity": "glama:" + str(ident).lower(),
                "operator_name": item.get("publisher") or item.get("namespace"),
                "operator_domain": None, "operator_verification": "source_claim",
                "operator_evidence": "Listed in Glama directory; operator not independently verified by this census",
                "raw": item, "source_url": record_url or url,
                "directory_attribution": "MCP data from Glama",
            }
        page_info = payload.get("pageInfo", {}) if isinstance(payload, dict) else {}
        if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
            page_info = payload["data"].get("pageInfo", page_info)
        has_next = page_info.get("hasNextPage") if isinstance(page_info, dict) else False
        next_cursor = page_info.get("endCursor") if isinstance(page_info, dict) else None
        if not has_next or not next_cursor or next_cursor in seen_cursors:
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    else:
        raise RuntimeError("Glama pagination safety limit reached")
    return list(records.values())

def json_feed_records(source: dict[str, Any]) -> list[dict[str, Any]]:
    """Ingest a configured public JSON feed; map common directory schemas."""
    url = source["url"]
    _, payload, _ = fetch_json(url, source.get("headers"))
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        key = source.get("items_key", "items")
        items = payload.get(key)
        if items is None:
            for candidate in ("agents", "servers", "results", "data"):
                if isinstance(payload.get(candidate), list):
                    items = payload[candidate]
                    break
    else:
        items = None
    if not isinstance(items, list):
        raise ValueError(f"Feed {url} has no list; configure items_key for its schema")
    out = []
    mapping = source.get("field_map", {})
    def field(item, name, fallback=None):
        path = mapping.get(name, name)
        value = item
        for part in path.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return fallback
        return value if value is not None else fallback
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        name = field(item, "name") or field(item, "title")
        source_id = field(item, "source_record_id") or field(item, "id") or field(item, "slug") or stable_hash(item)
        endpoint = field(item, "primary_endpoint") or field(item, "endpoint") or field(item, "url")
        metadata_url = field(item, "metadata_url") or field(item, "agent_card_url")
        out.append({
            "source_record_id": str(source_id),
            "name": name,
            "description": field(item, "description"),
            "kind": source.get("kind", "agent"),
            "protocol": field(item, "protocol") or source.get("protocol"),
            "protocol_version": field(item, "protocol_version"),
            "primary_endpoint": endpoint,
            "metadata_url": metadata_url,
            "canonical_identity": field(item, "canonical_identity") or field(item, "id"),
            "operator_name": field(item, "operator_name"),
            "operator_domain": field(item, "operator_domain"),
            "operator_verification": "unverified",
            "operator_evidence": None,
            "raw": item,
            "source_url": url,
        })
    return out


def ingest_source(source: dict[str, Any]) -> list[dict[str, Any]]:
    kind = source.get("adapter")
    if kind == "mcp_registry":
        return mcp_registry_records(source)
    if kind == "json_feed":
        return json_feed_records(source)
    if kind == "a2a_registry_search":
        return a2a_registry_records(source)
    if kind == "github_markdown_directory":
        return github_markdown_directory_records(source)
    if kind == "glama_directory":
        return glama_directory_records(source)
    raise ValueError(f"Unsupported adapter {kind!r}; supported: mcp_registry, a2a_registry_search, github_markdown_directory, glama_directory, json_feed")


def normalized_identity(record: dict[str, Any]) -> str | None:
    identity = clean_text(record.get("canonical_identity"), 1000)
    if identity:
        return identity.lower()
    # Directory namespaces are often stable even when endpoint URLs rotate.
    if record.get("protocol") == "MCP" and record.get("source_record_id"):
        return "mcp:" + record["source_record_id"].split("@", 1)[0].lower()
    return None


def choose_agent_id(record: dict[str, Any]) -> str:
    # Stable IDs prefer canonical identities, then normalized endpoints, then source key.
    identity = normalized_identity(record)
    endpoint = canonical_url(record.get("primary_endpoint"))
    metadata_url = canonical_url(record.get("metadata_url"))
    basis = ("identity:" + identity if identity else
             "endpoint:" + endpoint if endpoint else
             "metadata:" + metadata_url if metadata_url else
             "source:" + record.get("_source_name", "unknown") + ":" + str(record["source_record_id"]))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]


def a2a_card_from_url(url: str) -> tuple[dict[str, Any] | None, int | None, str | None]:
    """Fetch a declared metadata URL or a standard A2A Agent Card location."""
    candidates = [canonical_url(url)]
    if not candidates[0]:
        return None, None, "No valid HTTP(S) URL"
    base = candidates[0].rstrip("/")
    candidates.append(base + "/.well-known/agent-card.json")
    last_status = None
    last_error = None
    for candidate in dict.fromkeys(candidates):
        try:
            status, data, _ = fetch_json(candidate)
            last_status = status
            if isinstance(data, dict) and ("name" in data or "supportedInterfaces" in data or "url" in data):
                return data, status, None
            last_error = "JSON response does not resemble an A2A Agent Card"
        except Exception as exc:
            last_error = str(exc)[:300]
    return None, last_status, last_error


def validate_record(record: dict[str, Any]) -> tuple[int, int, int | None, str, dict[str, Any]]:
    """Returns metadata_valid, endpoint_reachable, HTTP status, notes, enriched record."""
    enriched = dict(record)
    notes: list[str] = []
    card = None
    status = None
    metadata_url = canonical_url(record.get("metadata_url"))
    endpoint = canonical_url(record.get("primary_endpoint"))
    proto = str(record.get("protocol") or "").upper()

    # A2A: if endpoint/metadata URL is declared, fetch a card; never invoke task endpoints.
    if proto == "A2A" or record.get("kind") == "agent":
        target = metadata_url or endpoint
        if target:
            card, status, error = a2a_card_from_url(target)
            if error:
                notes.append("Agent Card check: " + error)
        else:
            notes.append("No public metadata URL or endpoint to validate")
    elif proto == "MCP" or record.get("kind") == "mcp_server":
        # MCP servers are not required to expose a generic JSON metadata endpoint. Check
        # only an explicitly declared HTTP endpoint with a conservative GET.
        if endpoint:
            try:
                status, headers, body = request_bytes(endpoint)
                if 200 <= status < 400:
                    return 1, 1, status, "Declared MCP endpoint returned HTTP response; protocol handshake not tested", enriched
                notes.append(f"Declared endpoint returned HTTP {status}")
            except Exception as exc:
                notes.append("Endpoint check: " + str(exc)[:250])
        else:
            notes.append("No public endpoint URL in source metadata")
        return 0, 0, status, "; ".join(notes), enriched
    else:
        target = metadata_url or endpoint
        if target:
            try:
                status, _, _ = request_bytes(target)
                if 200 <= status < 400:
                    return 1, 1, status, "HTTP endpoint reachable; protocol-specific validation not performed", enriched
                notes.append(f"Endpoint returned HTTP {status}")
            except Exception as exc:
                notes.append("Endpoint check: " + str(exc)[:250])
        else:
            notes.append("No public endpoint URL")
        return 0, 0, status, "; ".join(notes), enriched

    if card:
        name = clean_text(card.get("name"))
        desc = clean_text(card.get("description"))
        skills = card.get("skills", [])
        interfaces = card.get("supportedInterfaces", [])
        # Older A2A cards commonly use "url"; v1 uses supportedInterfaces[].url.
        card_endpoint = None
        if isinstance(interfaces, list) and interfaces and isinstance(interfaces[0], dict):
            card_endpoint = interfaces[0].get("url")
        card_endpoint = canonical_url(card_endpoint or card.get("url") or endpoint)
        required_ok = bool(name and (card_endpoint or endpoint) and isinstance(skills, list))
        if not name:
            notes.append("Agent Card missing name")
        if not isinstance(skills, list):
            notes.append("Agent Card skills field must be an array")
        if required_ok:
            enriched["name"] = name or enriched.get("name")
            enriched["description"] = desc or enriched.get("description")
            enriched["primary_endpoint"] = card_endpoint or endpoint
            enriched["metadata_url"] = metadata_url or (endpoint.rstrip("/") + "/.well-known/agent-card.json" if endpoint else None)
            enriched["protocol"] = "A2A"
            enriched["protocol_version"] = card.get("protocolVersion") or (
                interfaces[0].get("protocolVersion") if interfaces and isinstance(interfaces[0], dict) else None
            )
            enriched["raw"] = {"source_record": record.get("raw"), "validated_agent_card": card}
            return 1, 1, status, "A2A Agent Card fetched and required metadata checks passed", enriched
        return 0, 1, status, "; ".join(notes) or "Agent Card did not pass required-field checks", enriched

    return 0, 0, status, "; ".join(notes) or "Metadata could not be validated", enriched


def find_existing_id(conn: sqlite3.Connection, record: dict[str, Any], proposed_id: str) -> str:
    """Deduplicate by exact identity first, then endpoint, then metadata URL."""
    identity = normalized_identity(record)
    endpoint = canonical_url(record.get("primary_endpoint"))
    metadata_url = canonical_url(record.get("metadata_url"))
    for query, value in (
        ("SELECT agent_id FROM agents WHERE canonical_identity=? LIMIT 1", identity),
        ("SELECT agent_id FROM agents WHERE primary_endpoint=? LIMIT 1", endpoint),
        ("SELECT agent_id FROM agents WHERE metadata_url=? LIMIT 1", metadata_url),
    ):
        if value:
            row = conn.execute(query, (value,)).fetchone()
            if row:
                return row[0]
    return proposed_id


def save_record(conn: sqlite3.Connection, source_name: str, record: dict[str, Any]) -> str:
    observed = now_iso()
    record["_source_name"] = source_name
    proposed_id = choose_agent_id(record)
    agent_id = find_existing_id(conn, record, proposed_id)
    record["canonical_identity"] = normalized_identity(record)
    record["primary_endpoint"] = canonical_url(record.get("primary_endpoint"))
    record["metadata_url"] = canonical_url(record.get("metadata_url"))
    raw = record.get("raw", {})
    record_hash = stable_hash({
        "name": record.get("name"), "description": record.get("description"),
        "kind": record.get("kind"), "identity": record.get("canonical_identity"),
        "endpoint": record.get("primary_endpoint"), "metadata_url": record.get("metadata_url"),
        "protocol": record.get("protocol"), "protocol_version": record.get("protocol_version"),
        "operator_name": record.get("operator_name"), "operator_domain": record.get("operator_domain"),
        "raw": raw,
    })
    previous = conn.execute("SELECT record_hash, first_seen_at FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
    first_seen = previous[1] if previous else observed
    conn.execute("""
      INSERT INTO agents (
        agent_id, display_name, description, kind, canonical_identity, primary_endpoint,
        metadata_url, protocol, protocol_version, operator_name, operator_domain,
        operator_verification, operator_evidence, metadata_valid, endpoint_reachable,
        endpoint_status, validation_notes, first_seen_at, last_seen_at, last_checked_at,
        record_hash, raw_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, NULL, ?, ?, NULL, ?, ?)
      ON CONFLICT(agent_id) DO UPDATE SET
        display_name=COALESCE(excluded.display_name, agents.display_name),
        description=COALESCE(excluded.description, agents.description),
        kind=excluded.kind,
        canonical_identity=COALESCE(excluded.canonical_identity, agents.canonical_identity),
        primary_endpoint=COALESCE(excluded.primary_endpoint, agents.primary_endpoint),
        metadata_url=COALESCE(excluded.metadata_url, agents.metadata_url),
        protocol=COALESCE(excluded.protocol, agents.protocol),
        protocol_version=COALESCE(excluded.protocol_version, agents.protocol_version),
        operator_name=COALESCE(excluded.operator_name, agents.operator_name),
        operator_domain=COALESCE(excluded.operator_domain, agents.operator_domain),
        last_seen_at=excluded.last_seen_at,
        record_hash=excluded.record_hash,
        raw_json=excluded.raw_json
    """, (
        agent_id, clean_text(record.get("name")), clean_text(record.get("description")),
        record.get("kind", "agent"), record.get("canonical_identity"), record.get("primary_endpoint"),
        record.get("metadata_url"), clean_text(record.get("protocol"), 100),
        clean_text(record.get("protocol_version"), 100), clean_text(record.get("operator_name"), 500),
        clean_text(record.get("operator_domain"), 500), record.get("operator_verification", "unverified"),
        clean_text(record.get("operator_evidence"), 2000), first_seen, observed, record_hash,
        json.dumps(raw, ensure_ascii=False, sort_keys=True),
    ))
    if previous and previous[0] != record_hash:
        conn.execute(
            "INSERT INTO change_events(agent_id, changed_at, event_type, previous_hash, current_hash, details) VALUES(?,?,?,?,?,?)",
            (agent_id, observed, "metadata_changed", previous[0], record_hash,
             json.dumps({"source": source_name, "source_record_id": record.get("source_record_id")})),
        )
    conn.execute("INSERT INTO snapshots(agent_id, observed_at, record_hash, record_json) VALUES(?,?,?,?)",
                 (agent_id, observed, record_hash, json.dumps(record, ensure_ascii=False, sort_keys=True)))
    source_id = str(record.get("source_record_id") or stable_hash(raw))
    conn.execute("""
      INSERT INTO source_records(source_name, source_record_id, agent_id, source_url, first_seen_at, last_seen_at)
      VALUES(?,?,?,?,?,?)
      ON CONFLICT(source_name, source_record_id) DO UPDATE SET
        agent_id=excluded.agent_id, source_url=excluded.source_url, last_seen_at=excluded.last_seen_at
    """, (source_name, source_id, agent_id, record.get("source_url"), observed, observed))
    return agent_id


def validate_pending(conn: sqlite3.Connection, only_stale_hours: int = 24) -> int:
    cutoff = datetime.now(timezone.utc).timestamp() - only_stale_hours * 3600
    rows = conn.execute("""
      SELECT agent_id, display_name, description, kind, canonical_identity, primary_endpoint,
             metadata_url, protocol, protocol_version, operator_name, operator_domain,
             operator_verification, operator_evidence, raw_json, last_checked_at
      FROM agents
    """)
    checked = 0
    for row in rows:   
        if checked >= 500:
            break
        (agent_id, name, desc, kind, identity, endpoint, metadata_url, protocol, proto_ver,
         op_name, op_domain, op_ver, op_evidence, raw_json, last_checked) = row
        if last_checked:
            try:
                last_ts = datetime.fromisoformat(last_checked.replace("Z", "+00:00")).timestamp()
                if last_ts >= cutoff:
                    continue
            except ValueError:
                pass
        rec = {
            "name": name, "description": desc, "kind": kind, "canonical_identity": identity,
            "primary_endpoint": endpoint, "metadata_url": metadata_url, "protocol": protocol,
            "protocol_version": proto_ver, "operator_name": op_name, "operator_domain": op_domain,
            "operator_verification": op_ver, "operator_evidence": op_evidence,
            "raw": json.loads(raw_json),
        }
        valid, reachable, status, notes, enriched = validate_record(rec)
        checked_at = now_iso()
        conn.execute("""
          UPDATE agents SET metadata_valid=?, endpoint_reachable=?, endpoint_status=?,
          validation_notes=?, last_checked_at=?,
          display_name=COALESCE(?, display_name),
          description=COALESCE(?, description),
          primary_endpoint=COALESCE(?, primary_endpoint),
          metadata_url=COALESCE(?, metadata_url),
          protocol=COALESCE(?, protocol),
          protocol_version=COALESCE(?, protocol_version)
          WHERE agent_id=?
        """, (valid, reachable, status, notes, checked_at, enriched.get("name"),
              enriched.get("description"), canonical_url(enriched.get("primary_endpoint")),
              canonical_url(enriched.get("metadata_url")), enriched.get("protocol"),
              enriched.get("protocol_version"), agent_id))
        conn.execute("INSERT INTO change_events(agent_id, changed_at, event_type, details) VALUES(?,?,?,?)",
                     (agent_id, checked_at, "validation_check",
                      json.dumps({"metadata_valid": valid, "endpoint_reachable": reachable,
                                  "http_status": status, "notes": notes})))
        checked += 1
    conn.commit()
    return checked


def counts(conn: sqlite3.Connection) -> dict[str, Any]:
    total = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    valid_reachable = conn.execute(
        "SELECT COUNT(*) FROM agents WHERE metadata_valid=1 AND endpoint_reachable=1"
    ).fetchone()[0]
    # Deliberately only count explicitly adjudicated independent evidence; source claims
    # and successful HTTP checks do not qualify.
    verified_operators = conn.execute("""
      SELECT COUNT(DISTINCT COALESCE(operator_domain, operator_name, canonical_identity))
      FROM agents
      WHERE operator_verification='independently_verified'
        AND (operator_domain IS NOT NULL OR operator_name IS NOT NULL)
    """).fetchone()[0]
    sources = conn.execute("SELECT COUNT(DISTINCT source_name) FROM source_records").fetchone()[0]
    checked = conn.execute("SELECT MAX(last_checked_at) FROM agents").fetchone()[0]
    return {
        "generated_at": now_iso(),
        "listed_unique_records": total,
        "validated_reachable_records": valid_reachable,
        "independently_verified_operators": verified_operators,
        "distinct_sources_contributing": sources,
        "most_recent_endpoint_check": checked,
        "definitions": {
            "listed_unique_records": "Deduplicated entities retained from ingested public sources, including unvalidated entries.",
            "validated_reachable_records": "Metadata passed adapter checks and its declared endpoint/Agent Card was reachable on last check; this does not prove safe behavior or full protocol functionality.",
            "independently_verified_operators": "Distinct operator identities explicitly marked independently_verified with recorded evidence; source self-claims and endpoint reachability do not count.",
        },
        "caveat": "This is a source-bounded census, not a claim to enumerate every AI agent on the internet."
    }


def export_records(conn: sqlite3.Connection, output_dir: str) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    columns = [x[1] for x in conn.execute("PRAGMA table_info(agents)").fetchall()]
    select_sql = "SELECT * FROM agents"

    # Stream JSON one record at a time to avoid loading the full census into RAM.
    with (out / "agents.json").open("w", encoding="utf-8") as f:
        f.write("[\n")
        first = True

        for row in conn.execute(select_sql):
            record = dict(zip(columns, row))

            try:
                record["raw_json"] = json.loads(record["raw_json"])
            except Exception:
                pass

            if not first:
                f.write(",\n")

            json.dump(
                record,
                f,
                ensure_ascii=False,
                sort_keys=True,
            )
            first = False

        f.write("\n]\n")

    (out / "counts.json").write_text(
        json.dumps(counts(conn), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    import csv

    with (out / "agents.csv").open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=columns,
            extrasaction="ignore",
        )
        writer.writeheader()

        for row in conn.execute(select_sql):
            record = dict(zip(columns, row))
            writer.writerow(record)


def run_pipeline(config_path: str, db_path: str, output_dir: str, force_check: bool = False) -> dict[str, Any]:
    config = load_config(config_path)
    conn = sqlite3.connect(db_path)
    init_db(conn)
    total_ingested = 0
    sources_attempted = 0
    sources_succeeded = 0
    sources_failed = 0
    for source in config.get("sources", []):
        if not source.get("enabled", True):
            continue
        name = source.get("name") or source.get("adapter", "unknown")
        sources_attempted += 1
        started = now_iso()
        cur = conn.execute("INSERT INTO source_runs(source_name, started_at, status) VALUES(?,?,?)",
                           (name, started, "running"))
        run_id = cur.lastrowid
        conn.commit()
        try:
            records = ingest_source(source)
            for rec in records:
                rec["_source_name"] = name
                save_record(conn, name, rec)
            conn.execute("UPDATE source_runs SET finished_at=?, status=?, records_seen=? WHERE run_id=?",
                         (now_iso(), "succeeded", len(records), run_id))
            conn.commit()
            sources_succeeded += 1
            total_ingested += len(records)
            log.info("%s: ingested %d records", name, len(records))
        except Exception as exc:
            log.exception("Source %s failed", name)
            conn.execute("UPDATE source_runs SET finished_at=?, status=?, error=? WHERE run_id=?",
                         (now_iso(), "failed", str(exc)[:2000], run_id))
            conn.commit()
            sources_failed += 1
    checked = validate_pending(conn, only_stale_hours=0 if force_check else int(config.get("recheck_after_hours", 24)))
    export_records(conn, output_dir)
    result = {"ingested_source_records": total_ingested, "validated_checks_run": checked,
              "sources_attempted": sources_attempted, "sources_succeeded": sources_succeeded,
              "sources_failed": sources_failed, **counts(conn)}
    (Path(output_dir) / "run_report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    conn.close()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest, deduplicate, validate, and snapshot public agent metadata.")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--out", default="public")
    parser.add_argument("--force-check", action="store_true", help="Recheck all endpoints regardless of last-checked time")
    parser.add_argument("--counts-only", action="store_true", help="Print counts from existing database")
    args = parser.parse_args()
    conn = sqlite3.connect(args.db)
    init_db(conn)
    if args.counts_only:
        print(json.dumps(counts(conn), indent=2))
        conn.close()
        return
    conn.close()
    result = run_pipeline(args.config, args.db, args.out, args.force_check)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
