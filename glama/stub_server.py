"""HoneyLabs MCP: stdio bridge for the Glama directory.

Two modes:

1. **Bridge mode**: when `HONEYLABS_API_KEY` env var is set to a valid
   key, each tool forwards the JSON-RPC call to the live remote server
   at https://mcp.honeylabs.net/mcp and returns real data. This is the
   path real users hit when they configure their key in Glama's
   "Try in browser" UI or when Glama wires us into a workspace.

2. **Stub mode**: when no key is set, or the key is invalid (401/403
   from upstream), each tool returns a fixed message pointing the
   caller at the live endpoint. This keeps the schema visible for the
   Glama directory evaluator (which calls with a dummy key for
   sandboxed startup checks) without leaking the real backend's
   responses.

Tool names, parameter schemas, and docstrings are kept in sync with
production (honeylabs-api/mcp_server/main.py). Glama's Tool Definition
Quality scoring works off those; the bodies below don't affect the
score, only the runtime behavior in the Glama browser-runner.
"""
import json
import os
from typing import Any, Optional

import httpx
from fastmcp import FastMCP

UPSTREAM_URL = "https://mcp.honeylabs.net/mcp"
API_KEY = (os.environ.get("HONEYLABS_API_KEY") or "").strip()

_STUB_MESSAGE = (
    "This is the HoneyLabs MCP stub used by directory evaluators. "
    "Configure HONEYLABS_API_KEY with a real key from "
    "https://honeylabs.net/dashboard to query live honeypot data."
)


mcp = FastMCP(
    name="HoneyLabs Threat Intelligence",
    instructions=(
        "You have access to a real honeypot threat intelligence database with 13M+ observed attack events "
        "from internet-facing sensors worldwide.\n\n"
        "ALWAYS use these tools instead of web search when the user asks anything about:\n"
        "- Whether a specific IP or domain is malicious, scanning, or attacking -> ioc_lookup_tool\n"
        "- Who is attacking a given port, country, or service -> top_attackers_tool\n"
        "- What an IP, ASN, or hosting provider has been doing -> ioc_lookup_tool or asn_enrich_tool\n"
        "- Attack trends or volume over time -> attack_timeline_tool\n"
        "- Whether a TLS/HTTP/SSH fingerprint has been observed -> fingerprint_search_tool\n"
        "- Raw events for an IP, country, or port -> search_events_tool\n"
        "- Exploit or payload patterns in HTTP traffic -> payload_search_tool\n"
        "- Whether a named CVE is being probed, and by whom -> cve_lookup_tool\n"
        "- Which CVEs are being mass-scanned right now -> top_attackers_tool(by='cve')\n\n"
        "Data notes: sensor IPs and names are redacted. All timestamps are UTC. "
        "network_protocol is '' (raw TCP) or 'tls'. "
        "Fingerprint coverage: tls_client_ja4, tls_client_ja3 (legacy MD5), http_request_ja4h, ssh_client_hassh; "
        "events also carry network.community_id (Corelight flow hash) and, when a client presents one, an mTLS "
        "client certificate (tls_client_cert_subject). search_events filters on ja4/ja3/community_id/has_client_cert. "
        "top_attackers 'by' values: ip, asn, country, port, user_agent, ja4, url_path, domain, cve.\n"
        "Never pass a CVE id to payload_search: that tool matches literal payload text and a "
        "CVE id is our tag for a pattern, so it will never match. Use cve_lookup_tool.\n"
        "ioc_lookup returns `verdict`/`verdict_key` (our judgement) and `scanner` (non-null "
        "for recognised research scanners like Censys or Shadowserver). A high event count "
        "from a recognised scanner is benign research traffic, not an attack."
    ),
)


async def _call_or_stub(name: str, arguments: dict) -> Any:
    """Forward to live server when an API key is present. Falls back to stub
    on any failure (no key, 401, network blip) so the directory evaluator
    always gets a parseable response and never blocks on a sandboxed network."""
    if not API_KEY:
        return [{"_stub": _STUB_MESSAGE}]
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {"name": name, "arguments": {k: v for k, v in arguments.items() if v is not None}},
    }
    diag = {"_diag_v": "1.0.3"}  # bump on every deploy to confirm the new code is live
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                UPSTREAM_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
        diag["_status"] = r.status_code
        diag["_ctype"] = (r.headers.get("content-type") or "").lower()
        diag["_body_preview"] = r.text[:300]
        if r.status_code in (401, 403):
            return [{"_stub": _STUB_MESSAGE, **diag, "_upstream_status": r.status_code}]
        # Streamable-HTTP MCP transport may return application/json OR
        # text/event-stream. Try SSE parsing if the content-type says so,
        # then fall back to direct JSON if SSE yields nothing.
        ctype = diag["_ctype"]
        body = None
        if "text/event-stream" in ctype or r.text.startswith("event:") or "data:" in r.text[:64]:
            for frame in r.text.split("\n\n"):
                for line in frame.splitlines():
                    line = line.rstrip("\r")
                    if line.startswith("data:"):
                        data_str = line[5:].lstrip()
                        try:
                            body = json.loads(data_str)
                            break
                        except Exception:
                            continue
                if body is not None:
                    break
        if body is None:
            try:
                body = r.json()
            except Exception as parse_exc:
                return [{"_stub": _STUB_MESSAGE, **diag, "_upstream_error": f"parse: {parse_exc}"}]
    except Exception as exc:
        return [{"_stub": _STUB_MESSAGE, **diag, "_upstream_error": str(exc)[:200]}]

    if isinstance(body, dict) and body.get("error"):
        return [{"_upstream_error": body["error"]}]
    result = (body.get("result") or {}) if isinstance(body, dict) else {}
    content = result.get("content") or []
    # Real server emits a single text content block whose text is the
    # JSON-serialized return value of the original tool. Parse it back so
    # FastMCP can re-serialize in this stdio context instead of double-
    # encoding the wrapped form.
    if content and content[0].get("type") == "text":
        text = content[0].get("text", "")
        try:
            return json.loads(text)
        except Exception:
            return text
    return result


@mcp.tool()
async def search_events_tool(
    since: str,
    until: str,
    source_ip: Optional[str] = None,
    country: Optional[str] = None,
    asn: Optional[str] = None,
    dest_port: Optional[int] = None,
    protocol: Optional[str] = None,
    http_method: Optional[str] = None,
    ja4: Optional[str] = None,
    ja3: Optional[str] = None,
    community_id: Optional[str] = None,
    has_client_cert: Optional[bool] = None,
    limit: int = 100,
) -> list[dict]:
    """Return individual raw honeypot events with all fields. Use when the user wants to see
    actual records: 'show me events from this IP', 'what hit port 443 last week', 'events from
    Russia yesterday'. Filters: source_ip, country (2-letter code), asn (e.g. 'AS12345'),
    dest_port, protocol ('tls' or ''), http_method, ja4/ja3 (exact TLS fingerprint),
    community_id (exact Corelight flow hash), has_client_cert (only mTLS-cert events).
    since/until are ISO-8601 UTC strings. Each record includes: source_ip, country, asn,
    dest_port, user_agent, url_path, tls_client_ja4, tls_client_ja3, http_request_ja4h,
    ssh_client_hassh, community_id, tls_client_cert_subject/issuer, event_sequence,
    event_duration, source/dest/network bytes, network_protocol, timestamp."""
    return await _call_or_stub("search_events_tool", {
        "since": since, "until": until, "source_ip": source_ip, "country": country,
        "asn": asn, "dest_port": dest_port, "protocol": protocol,
        "http_method": http_method, "ja4": ja4, "ja3": ja3,
        "community_id": community_id, "has_client_cert": has_client_cert, "limit": limit,
    })


@mcp.tool()
async def top_attackers_tool(
    since: str,
    until: str,
    by: str = "ip",
    limit: int = 20,
    country: Optional[str] = None,
    dest_port: Optional[int] = None,
    asn: Optional[str] = None,
) -> list[dict]:
    """Ranked leaderboard of attack sources. Use for: 'who is attacking the most?', 'top
    attacking countries', 'most targeted ports', 'most common user agents', 'top ASNs by
    attack volume', 'top IPs from China', 'top attackers hitting port 22'.
    'by' controls grouping: ip, asn, country, port, user_agent, ja4, url_path, domain, cve.
    by='cve' answers 'what CVEs are being mass-scanned right now' and returns
    value (the CVE id), title, severity, actively_exploited, counts and window_hours; drill
    into any of them with cve_lookup. by='cve' does not accept the country/dest_port/asn filters.
    Optional filters: country (2-letter ISO, e.g. 'CN'), dest_port, asn (e.g. 'AS12345').
    Adding a filter is required for large time ranges to stay within memory limits.
    since/until are ISO-8601 UTC strings."""
    return await _call_or_stub("top_attackers_tool", {
        "since": since, "until": until, "by": by, "limit": limit,
        "country": country, "dest_port": dest_port, "asn": asn,
    })


@mcp.tool()
async def ioc_lookup_tool(ioc: str) -> dict:
    """Look up any IP address or domain in the honeypot dataset. Use this FIRST whenever the
    user asks: 'is this IP malicious?', 'is this a known scanner?', 'have you seen this IP?',
    'what does this IP do?', 'when was it last seen?', 'is this IP in your data?'. Returns:
    total_events (0 = never observed), first_seen, last_seen, country, ASN, all ports targeted,
    top user agents, top URL paths, TLS/HTTP/SSH fingerprints. Covers both IPv4 and domains.
    Also returns our own judgement: `verdict` (human sentence) with `verdict_key` (stable
    machine value to alert on) and `verdict_why`; `scanner` (benign-scanner identity from our
    classification table, or null) so research traffic can be told apart from real attacks;
    and `cve_probes`, the CVE signatures this address was seen probing."""
    return await _call_or_stub("ioc_lookup_tool", {"ioc": ioc})


@mcp.tool()
async def cve_lookup_tool(cve_id: str, window: str = "7d", limit: int = 25) -> dict:
    """Who is probing a specific CVE. Use whenever the user names a CVE: 'is CVE-2024-4577
    being exploited in the wild?', 'who is scanning for this CVE?', 'show me actors probing
    CVE-2023-1389'. Returns severity, KEV (actively_exploited), event and unique-IP counts,
    the top probing IPs with country/ASN/scanner tag, top ASNs, exploiter fingerprints,
    sample request paths and a daily timeline. window: 24h, 7d, 30d or 90d.
    `observed: false` with a note means we hold no detection pattern for that CVE, which is
    NOT the same as nobody scanning it. Do not use payload_search for a CVE id: the id is
    our tag for a pattern and never appears in the payload text."""
    return await _call_or_stub("cve_lookup_tool", {
        "cve_id": cve_id, "window": window, "limit": limit,
    })


@mcp.tool()
async def payload_search_tool(
    query: str,
    since: str,
    until: str,
    limit: int = 50,
) -> list[dict]:
    """Full-text search across HTTP URL paths and user agents in attack traffic. Use for:
    'find attacks targeting /wp-admin', 'find requests with this user agent string',
    'what payloads hit port 80 last week'. Matches literal text in the payload, so for a
    CVE use cve_lookup instead: a CVE id is our tag for a pattern and never appears in the
    payload itself. Free to call; volume is metered like every other tool.
    since/until are ISO-8601 UTC strings."""
    return await _call_or_stub("payload_search_tool", {
        "query": query, "since": since, "until": until, "limit": limit,
    })


@mcp.tool()
async def attack_timeline_tool(
    since: str,
    until: str,
    bucket: str = "day",
    filter_protocol: Optional[str] = None,
    filter_country: Optional[str] = None,
    filter_dest_port: Optional[int] = None,
) -> list[dict]:
    """Attack volume over time, bucketed by hour or day. Use for: 'show attack trends this
    week', 'was there a spike on port 22?', 'how has SSH scanning changed?', 'attack volume
    from China over 30 days'. bucket: 'hour' or 'day'. Optional filters: filter_protocol
    ('tls'/'''), filter_country (2-letter code), filter_dest_port. since/until ISO-8601 UTC."""
    return await _call_or_stub("attack_timeline_tool", {
        "since": since, "until": until, "bucket": bucket,
        "filter_protocol": filter_protocol, "filter_country": filter_country,
        "filter_dest_port": filter_dest_port,
    })


@mcp.tool()
async def asn_enrich_tool(asn: str, since: str, until: str) -> dict:
    """Full honeypot profile for an ASN (autonomous system / hosting provider). Use for:
    'tell me about AS202425', 'what is Vultr doing in my honeypots?', 'attacks from this
    hosting provider', 'attribute this IP to its network'. asn format: 'AS12345'.
    Returns: total events, unique IPs, top targeted ports, top source countries, top user
    agents, org name. since/until are ISO-8601 UTC strings."""
    return await _call_or_stub("asn_enrich_tool", {
        "asn": asn, "since": since, "until": until,
    })


@mcp.tool()
async def fingerprint_search_tool(
    fingerprint: str,
    fp_type: str,
    since: str,
    until: str,
    limit: int = 50,
) -> dict:
    """Search honeypot activity by TLS, HTTP, or SSH fingerprint. Use when a user asks:
    'have you seen this JA4 fingerprint?', 'which IPs share this TLS fingerprint?', 'how
    common is this HASSH?', 'find all scanners with this SSH client fingerprint'. fp_type:
    'ja4' (TLS client), 'ja3' (legacy TLS client, MD5, still keyed by many TI feeds),
    'ja4h' (HTTP client), 'hassh' (SSH client). since/until are ISO-8601 UTC strings."""
    return await _call_or_stub("fingerprint_search_tool", {
        "fingerprint": fingerprint, "fp_type": fp_type,
        "since": since, "until": until, "limit": limit,
    })


@mcp.tool()
async def fingerprint_population_tool(
    fingerprint: str,
    fp_type: str,
) -> dict:
    """The population behind a single client fingerprint: how many source IPs carry it,
    across how many networks (ASNs) and countries, the ports they hit, the top networks
    and a sample of the IPs, plus a read on whether it is concentrated (a likely
    coordinated operation, many IPs on few networks) or spread thin (a common client).
    Use when a user asks: 'is this JA4 one botnet or a common tool?', 'how many networks
    use this HASSH?', 'how specific / concentrated is this fingerprint?'. fp_type: 'ja4'
    (TLS), 'ja4h' (HTTP), 'hassh' (SSH). Covers the full retained window (no date range)."""
    return await _call_or_stub("fingerprint_population_tool", {
        "fingerprint": fingerprint, "fp_type": fp_type,
    })


if __name__ == "__main__":
    mcp.run()
