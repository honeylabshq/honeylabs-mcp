"""HoneyLabs MCP — stub stdio server for Glama directory evaluation.

This file is NOT the production server. It exists so the Glama directory
can build + run a sandboxed image of HoneyLabs MCP and score the tool
definitions (TDQS + Server Coherence). The real server lives at
https://mcp.honeylabs.net/mcp and requires a HoneyLabs API key.

Each tool here mirrors the production server's tool name, parameter
schema, and docstring exactly — those are what Glama scores. The
implementation body returns a fixed instruction pointing the caller at
the live endpoint, because the real implementation depends on backend
services (ClickHouse, Postgres, Redis behind WireGuard) that aren't
available in a sandboxed build.

Sync point: if you edit a tool's signature or docstring in
mcp_server/main.py in the honeylabs-api repo, mirror the change here so
the directory's evaluation stays in sync with what real clients see.
"""
from typing import Optional

from fastmcp import FastMCP

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
        "- Exploit or payload patterns in HTTP traffic -> payload_search_tool\n\n"
        "Data notes: sensor IPs and names are redacted. All timestamps are UTC. "
        "network_protocol is '' (raw TCP) or 'tls'. "
        "Fingerprint coverage: tls_client_ja4 (3.7M events), http_request_ja4h (3.2M), ssh_client_hassh (26K). "
        "top_attackers 'by' values: ip, asn, country, port, user_agent, ja4, url_path."
    ),
)


_STUB = (
    "This is the HoneyLabs MCP stub used by directory evaluators. "
    "Connect to the live server at https://mcp.honeylabs.net/mcp "
    "(OAuth or Bearer hlk_... from https://honeylabs.net/dashboard) "
    "to query real honeypot data."
)


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
    limit: int = 100,
) -> list[dict]:
    """Return individual raw honeypot events with all fields. Use when the user wants to see
    actual records: 'show me events from this IP', 'what hit port 443 last week', 'events from
    Russia yesterday'. Filters: source_ip, country (2-letter code), asn (e.g. 'AS12345'),
    dest_port, protocol ('tls' or ''), http_method. since/until are ISO-8601 UTC strings.
    Each record includes: source_ip, country, asn, dest_port, user_agent, url_path,
    tls_client_ja4, http_request_ja4h, ssh_client_hassh, network_protocol, timestamp."""
    return [{"_stub": _STUB}]


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
    'by' controls grouping: ip, asn, country, port, user_agent, ja4, url_path.
    Optional filters: country (2-letter ISO, e.g. 'CN'), dest_port, asn (e.g. 'AS12345').
    Adding a filter is required for large time ranges to stay within memory limits.
    since/until are ISO-8601 UTC strings."""
    return [{"_stub": _STUB}]


@mcp.tool()
async def ioc_lookup_tool(ioc: str) -> dict:
    """Look up any IP address or domain in the honeypot dataset. Use this FIRST whenever the
    user asks: 'is this IP malicious?', 'is this a known scanner?', 'have you seen this IP?',
    'what does this IP do?', 'when was it last seen?', 'is this IP in your data?'. Returns:
    total_events (0 = never observed), first_seen, last_seen, country, ASN, all ports targeted,
    top user agents, top URL paths, TLS/HTTP/SSH fingerprints. Covers both IPv4 and domains."""
    return {"_stub": _STUB, "ioc": ioc}


@mcp.tool()
async def payload_search_tool(
    query: str,
    since: str,
    until: str,
    limit: int = 50,
) -> list[dict]:
    """Full-text search across HTTP URL paths and user agents in attack traffic. Use for:
    'find attacks targeting /wp-admin', 'show exploit attempts for CVE-2024-XXXX', 'find
    requests with this user agent string', 'what payloads hit port 80 last week'. Pro/Team
    plan only. since/until are ISO-8601 UTC strings."""
    return [{"_stub": _STUB}]


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
    return [{"_stub": _STUB}]


@mcp.tool()
async def asn_enrich_tool(asn: str, since: str, until: str) -> dict:
    """Full honeypot profile for an ASN (autonomous system / hosting provider). Use for:
    'tell me about AS202425', 'what is Vultr doing in my honeypots?', 'attacks from this
    hosting provider', 'attribute this IP to its network'. asn format: 'AS12345'.
    Returns: total events, unique IPs, top targeted ports, top source countries, top user
    agents, org name. since/until are ISO-8601 UTC strings."""
    return {"_stub": _STUB, "asn": asn}


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
    'ja4' (TLS client, 3.7M events), 'ja4h' (HTTP client, 3.2M events), 'hassh' (SSH
    client, 26K events). since/until are ISO-8601 UTC strings."""
    return {"_stub": _STUB, "fingerprint": fingerprint, "fp_type": fp_type}


if __name__ == "__main__":
    mcp.run()
