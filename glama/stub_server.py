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

Tool names, titles, annotations, parameter schemas and docstrings are
generated from production (honeylabs-api/mcp_server/main.py). Glama's Tool Definition
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
    "https://honeylabs.net/dashboard?src=mcp to query live honeypot data."
)


mcp = FastMCP(
    name="HoneyLabs Threat Intelligence",
    instructions=(
        'HoneyLabs is a database of what its own internet-facing honeypot sensors have observed: source addresses, networks, ports, request paths and payloads, TLS, HTTP and SSH client fingerprints, CVE probes, and the sessions interactive sensors held with clients. Prefer these tools over web search for questions about scanning and exploitation traffic, and quote the window a count covers.\n'
        '\n'
        'Which tool:\n'
        '- One IP, CIDR range, set of ranges or domain: ioc_lookup_tool. Start here.\n'
        '- What an address did inside sessions (commands, logins, exploits): interactive_sessions_tool, after ioc_lookup_tool.\n'
        "- One named CVE: cve_lookup_tool. CVEs being probed now: top_attackers_tool with by='cve'.\n"
        '- Rankings (top addresses, networks, countries, ports, user agents, JA4, paths, domains): top_attackers_tool.\n'
        '- One network or hosting provider: asn_enrich_tool.\n'
        '- Volume over time: attack_timeline_tool.\n'
        '- The raw events: search_events_tool.\n'
        '- Text that appeared in requests: payload_search_tool. Never a CVE id, product name or description of behaviour; those return nothing.\n'
        '- A client fingerprint: fingerprint_search_tool (events), fingerprint_population_tool (who carries it and whether it is one operation), fingerprint_similar_tool (Akin HTTP shapes a few headers away).\n'
        '- DNS questions, QUIC fingerprints and other UDP: udp_activity_tool. A JA4 starting with q is QUIC.\n'
        '- Logins tried, files handed over: interactive_credentials_tool, interactive_files_tool.\n'
        '\n'
        "Reading the answers: verdict_key is scanner, tor, malicious, scanning, probing or none, and verdict_why lists the signals that decided it; show the reasons with the label. A recognised research scanner (scanner is non-null) is benign research traffic, whatever its volume. total_events 0 means our sensors did not see it, which says nothing about the address elsewhere. UDP source addresses can be forged and never count against an address. Interactive-session records feed no verdict; cve_lookup_tool and by='cve' count them beside first-contact events and say how (first_contact_events, interactive_requests). Sensor addresses and names are redacted everywhere. Timestamps are UTC.\n"
        '\n'
        "Limits: since/until spans may not exceed the plan's query window. Each call costs one credit, and tools that return a list cost one credit per row. Plans and limits: https://honeylabs.net/pricing.json. Never loop over addresses in a range or over CVE ids: ioc_lookup_tool takes ranges and top_attackers_tool by='cve' lists CVEs in one call."
    ),
)

_READ_ONLY = {"readOnlyHint": True, "destructiveHint": False,
              "idempotentHint": True, "openWorldHint": False}


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


@mcp.tool(title='Search raw events', annotations=_READ_ONLY)
async def search_events_tool(
    since: str,
    until: str,
    source_ip: str | None = None,
    country: str | None = None,
    asn: str | None = None,
    dest_port: int | None = None,
    protocol: str | None = None,
    app_protocol: str | None = None,
    http_method: str | None = None,
    source_domain: str | None = None,
    request_header: str | None = None,
    ja4: str | None = None,
    ja3: str | None = None,
    akin: str | None = None,
    has_client_cert: bool | None = None,
    ip_version: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """Individual honeypot events with every field, newest first, filtered by source,
    network, port, protocol or fingerprint.

    Use when the user wants to see the records themselves: "show me the events from
    this IP", "what hit port 443 yesterday", "every request carrying this JA4",
    "all RDP traffic regardless of port". Do not use it to judge one address (use
    ioc_lookup_tool), to rank or count (use top_attackers_tool or
    attack_timeline_tool), to search request text (use payload_search_tool), or for
    a CVE (use cve_lookup_tool).

    Filters, all optional and combined with AND: source_ip, country (ISO 3166
    two-letter code), asn ('AS12345'), dest_port, protocol ('tls', or '' for raw
    TCP), app_protocol (detected layer-7 protocol such as 'ssh', 'rdp',
    'mssql-tds', 'rtsp', 'smbv1', 'bittorrent' or 'mining', whatever the port),
    http_method, request_header (substring of the masked request headers),
    source_domain (reverse DNS substring), ja4 or ja3 (exact TLS client
    fingerprint), akin (exact HTTP request fingerprint such as
    b11cun030_00040014_54d07b6d), has_client_cert (true for clients that presented
    an mTLS certificate), ip_version (4 or 6). limit is 1 to 500, default 100.

    since and until are ISO-8601 UTC timestamps; the span between them may not
    exceed the query window of the caller's plan (https://honeylabs.net/pricing.json).
    Each record carries source_ip, country, asn, dest_port, user_agent, url_path,
    http_request_headers, tls_client_ja4, tls_client_ja3, tls_client_hello_hex (the
    raw ClientHello), ssh_client_hassh, tls_client_cert_subject and issuer,
    event_sequence, event_duration, byte counts, network_protocol,
    application_protocol and timestamp. TCP events from first-contact sensors only."""
    return await _call_or_stub("search_events_tool", {"since": since, "until": until, "source_ip": source_ip, "country": country, "asn": asn, "dest_port": dest_port, "protocol": protocol, "app_protocol": app_protocol, "http_method": http_method, "source_domain": source_domain, "request_header": request_header, "ja4": ja4, "ja3": ja3, "akin": akin, "has_client_cert": has_client_cert, "ip_version": ip_version, "limit": limit})


@mcp.tool(title='Rank sources, ports or CVEs', annotations=_READ_ONLY)
async def top_attackers_tool(
    since: str,
    until: str,
    by: str = 'ip',
    limit: int = 20,
    country: str | None = None,
    dest_port: int | None = None,
    asn: str | None = None,
) -> list[dict]:
    """Ranked leaderboard over a time window: the top source addresses, networks,
    countries, destination ports, user agents, JA4 fingerprints, URL paths, reverse
    DNS domains or CVEs by event count.

    Use for "who is attacking the most", "top countries hitting port 22", "most
    targeted ports this week", "top networks by volume", and with by='cve' for
    "which CVEs are being scanned for right now". Do not use it for one known
    address (use ioc_lookup_tool), one known network (use asn_enrich_tool), one
    known CVE (use cve_lookup_tool), or a trend over time (use
    attack_timeline_tool).

    by: ip, asn, country, port, user_agent, ja4, url_path, domain or cve (default
    ip). limit is 1 to 100, default 20. Optional filters country (ISO code),
    dest_port and asn ('AS12345'); add one when the window is long, because an
    unfiltered ranking over many days can hit the query memory limit. by='cve'
    takes no filters and returns value (the CVE id), title, severity,
    actively_exploited (on the CISA KEV catalogue), kev_date_added and counts.
    since and until are ISO-8601 UTC, within the plan's query window."""
    return await _call_or_stub("top_attackers_tool", {"since": since, "until": until, "by": by, "limit": limit, "country": country, "dest_port": dest_port, "asn": asn})


@mcp.tool(title='Look up an address, range or domain', annotations=_READ_ONLY)
async def ioc_lookup_tool(
    ioc: str,
    days: int | None = None,
) -> dict:
    """Everything the sensors hold on one IP address, a CIDR range, several ranges at
    once, or a domain, with our verdict and the reasons for it. Start here for any
    question about a specific indicator.

    Use for "is this IP malicious", "is this a known scanner", "have you seen this
    address", "when was it last seen", "have any of this vendor's ranges touched
    you". Do not use it to rank many sources (use top_attackers_tool), to profile a
    whole ASN (use asn_enrich_tool), or to list raw events (use
    search_events_tool). For what an address did inside sessions with the
    interactive sensors, follow up with interactive_sessions_tool.

    Returns total_events (0 means never observed in the window), first_seen,
    last_seen, country, ASN, the 50 most-hit ports with ports_targeted_count, top
    user agents and URL paths, TLS/HTTP/SSH fingerprints, cve_probes (the CVE
    signatures it was seen probing), verdict (a sentence), verdict_key (a stable
    value to alert on: scanner, tor, malicious, scanning, probing or none),
    verdict_why (the signals behind it) and scanner (the identity of a recognised
    research scanner, else null). Report the verdict with its reasons. A high
    count from a recognised scanner is research traffic, not an attack. A single
    address may also carry udp_unverified: UDP traffic that claimed it as source,
    which can be forged and never counts against it.

    days limits the lookback. Leave it unset for a single address to read every
    retained event. A CIDR or domain defaults to 90 days because neither can use
    an index; pass days to change that. The response names the window it used in
    `window`; quote it with any count.

    Pass ranges as one string separated by commas, spaces or newlines
    ('103.66.28.0/22, 8.34.210.32/27'). Never expand a range into addresses and
    loop: one call answers it, and looping burns the daily credits. A range answer
    has query_type 'cidr' or 'cidr_set', per_range counts and top_source_ips."""
    return await _call_or_stub("ioc_lookup_tool", {"ioc": ioc, "days": days})


@mcp.tool(title='Who is probing a CVE', annotations=_READ_ONLY)
async def cve_lookup_tool(
    cve_id: str,
    window: str = '7d',
    limit: int = 25,
) -> dict:
    """Who is probing one named CVE, and how: counts, top probing addresses, networks,
    countries, fingerprints, sample request paths and a daily timeline.

    Use whenever the user names a CVE: "is CVE-2024-4577 being exploited in the
    wild", "who scans for CVE-2023-1389", "has anyone probed this before it was
    published". Do not pass a CVE id to payload_search_tool: the id is our label
    for a detection pattern and never appears in request text. For the list of
    CVEs being probed right now, use top_attackers_tool with by='cve'.

    Returns title, severity, actively_exploited and kev (the CISA KEV entry with
    date_added, or null), event and unique-address counts across both sensor
    types (first_contact_events and interactive_requests split them; an address
    both saw counts once), up to `limit` top probing addresses (1 to 25, default
    25) with country, ASN and scanner (name and kind of a recognised research or
    vendor scanner, else null), top networks and countries, exploiter
    fingerprints, sample paths, a daily timeline and `interactive` (what the
    interactive sensors recorded of the probes).

    window: 24h, 7d (default), 30d or 90d, and on plans with the full history also
    180d, 365d or all. observed: false with a note means we hold no detection
    pattern for that CVE, which is not evidence that nobody is scanning for it."""
    return await _call_or_stub("cve_lookup_tool", {"cve_id": cve_id, "window": window, "limit": limit})


@mcp.tool(title='Search request text', annotations=_READ_ONLY)
async def payload_search_tool(
    query: str,
    since: str,
    until: str,
    limit: int = 50,
) -> list[dict]:
    """Literal substring search, ignoring case, over captured request text: URL path,
    request body, request headers and event summary.

    Use for "find requests to /wp-admin", "which requests carried this user agent
    string", "who sent '../../etc/passwd' last week". It matches text that
    appeared in the request and nothing else, so these return nothing:
      - a CVE id ('CVE-2024-4577'). Use cve_lookup_tool; this tool rejects CVE ids.
      - a product or vendor name ('Cisco FMC'). Search the path the product
        exposes instead, such as '/ccmadmin'.
      - a description of behaviour ('SQL injection'). Search a marker that
        occurs in the traffic, such as 'UNION SELECT'.
    For a fingerprint use fingerprint_search_tool; for events from one source use
    search_events_tool.

    An empty list is a real answer: no captured request in the window contained
    the string. Widen since and until before concluding the activity does not
    exist. since and until are ISO-8601 UTC within the plan's query window. limit
    is 1 to 100, default 50."""
    return await _call_or_stub("payload_search_tool", {"query": query, "since": since, "until": until, "limit": limit})


@mcp.tool(title='Event volume over time', annotations=_READ_ONLY)
async def attack_timeline_tool(
    since: str,
    until: str,
    bucket: str = 'day',
    filter_protocol: str | None = None,
    filter_country: str | None = None,
    filter_dest_port: int | None = None,
) -> list[dict]:
    """Event counts over time, in hourly or daily buckets, optionally filtered by
    protocol, country or destination port.

    Use for "show the trend this week", "was there a spike on port 22", "how has
    SSH scanning changed over 30 days". Do not use it to find who caused a spike
    (follow up with top_attackers_tool on the same window and filter) or to see
    the events themselves (use search_events_tool).

    bucket: 'hour' or 'day' (default). filter_protocol: 'tls', or '' for raw TCP.
    filter_country: ISO two-letter code. filter_dest_port: a port number. since
    and until are ISO-8601 UTC within the plan's query window. Counts are raw
    totals from the first-contact sensors."""
    return await _call_or_stub("attack_timeline_tool", {"since": since, "until": until, "bucket": bucket, "filter_protocol": filter_protocol, "filter_country": filter_country, "filter_dest_port": filter_dest_port})


@mcp.tool(title='Profile a network (ASN)', annotations=_READ_ONLY)
async def asn_enrich_tool(
    asn: str,
    since: str,
    until: str,
) -> dict:
    """Profile of one autonomous system (a hosting provider, ISP or company network)
    over a time window: total events, unique addresses, top targeted ports, source
    countries, top user agents and the organisation name.

    Use for "tell me about AS202425", "what is this hosting provider doing", "is
    this network a source of scanning". To attribute one address to its network,
    ioc_lookup_tool already returns the ASN; call this one afterwards for the
    network's wider behaviour. To rank networks against each other, use
    top_attackers_tool with by='asn'.

    asn: 'AS12345' or '12345'. since and until are ISO-8601 UTC within the plan's
    query window."""
    return await _call_or_stub("asn_enrich_tool", {"asn": asn, "since": since, "until": until})


@mcp.tool(title='Find activity by fingerprint', annotations=_READ_ONLY)
async def fingerprint_search_tool(
    fingerprint: str,
    fp_type: str,
    since: str,
    until: str,
    limit: int = 50,
) -> dict:
    """Events and sources that carried one client fingerprint in a time window.

    Use for "have you seen this JA4", "which IPs share this TLS fingerprint",
    "find every scanner with this SSH client fingerprint". For how widespread a
    fingerprint is and whether it is one operation or a common client, use
    fingerprint_population_tool. For HTTP request shapes a few headers away from an
    Akin fingerprint, use fingerprint_similar_tool. A JA4 that starts with q comes
    from QUIC over UDP and is answered by udp_activity_tool.

    fp_type: 'ja4' (TLS client), 'ja3' (legacy TLS client hash, still keyed by
    many feeds), 'akin' (HTTP request shape, such as b11cun030_00040014_54d07b6d)
    or 'hassh' (SSH client). since and until are ISO-8601 UTC within the plan's
    query window. limit is 1 to 200, default 50."""
    return await _call_or_stub("fingerprint_search_tool", {"fingerprint": fingerprint, "fp_type": fp_type, "since": since, "until": until, "limit": limit})


@mcp.tool(title='Similar HTTP request shapes', annotations=_READ_ONLY)
async def fingerprint_similar_tool(
    fingerprint: str,
    max_distance: int = 2,
    limit: int = 8,
) -> dict:
    """HTTP request shapes within a few headers of one Akin fingerprint, with what
    those clients request and call themselves, and the family the fingerprint
    belongs to.

    Use when an unfamiliar request shape turns up in your own web server, WAF or
    proxy logs and you want to know whether it is a known tool or a variant of
    one: "what is close to this fingerprint", "is this the same scanner with one
    header added". Only Akin fingerprints work here, because a hashed fingerprint
    such as JA4 changes completely when one header is added. For the sources that
    carried the exact fingerprint, use fingerprint_search_tool.

    fingerprint: an Akin token such as b11cun030_00040014_54d07b6d. max_distance:
    1 to 4 headers, default 2. limit: 1 to 25 neighbours, default 8."""
    return await _call_or_stub("fingerprint_similar_tool", {"fingerprint": fingerprint, "max_distance": max_distance, "limit": limit})


@mcp.tool(title='Who carries a fingerprint', annotations=_READ_ONLY)
async def fingerprint_population_tool(
    fingerprint: str,
    fp_type: str,
) -> dict:
    """The population behind one client fingerprint over the full retained window:
    how many source addresses carry it, across how many networks and countries,
    the ports they hit, the top networks, a sample of addresses, and a read on its
    shape.

    Use for "is this JA4 one botnet or a common tool", "how many networks use this
    HASSH", "how concentrated is this fingerprint". The concentration field says
    concentrated (many addresses on few networks), dispersed (many networks in one
    short burst on one or two ports, a coordinated operation spread thinly on
    purpose), spread (a common client) or mixed; concentrated and dispersed both
    point to one operator. For the individual events, use
    fingerprint_search_tool with a time window.

    fp_type: 'ja4' (TLS; a QUIC JA4 starting with q is answered from UDP traffic,
    whose sources can be forged), 'akin' (HTTP request shape) or 'hassh' (SSH).
    No date range: it reads everything retained."""
    return await _call_or_stub("fingerprint_population_tool", {"fingerprint": fingerprint, "fp_type": fp_type})


@mcp.tool(title='UDP probes: DNS, QUIC and more', annotations=_READ_ONLY)
async def udp_activity_tool(
    query: str = '',
    window: str = '7d',
    samples: int = 10,
) -> dict:
    """UDP datagrams sent to the sensors: DNS questions, QUIC client fingerprints and
    other UDP probes, with the ports, networks and countries involved.

    Use for "who is sending DNS ANY queries", "is anyone querying version.bind",
    "have you seen this QUIC JA4", "which UDP ports are probed", "what hits
    5060/udp". Every other tool reads TCP only, so UDP questions belong here. A
    UDP source address can be forged: treat each address as claimed, never as
    evidence against it, and do not feed it to ioc_lookup_tool as proof.

    query uses the /udp search grammar: 'qtype:ANY', 'qname:version.bind',
    'proto:quic', 'port:5060 country:CN',
    'ja4:q13d0310h3_55b375c5d22e_cd85d2d88918' or 'quic:3f1a9c2b7d40'; leave it
    empty for the overview. window: 24h, 7d (default) or 30d, shortened to the
    plan's query window when that is shorter (window_notice then says so).
    samples: 0 to 25 example datagrams, default 10."""
    return await _call_or_stub("udp_activity_tool", {"query": query, "window": window, "samples": samples})


@mcp.tool(title='Logins tried on interactive sensors', annotations=_READ_ONLY)
async def interactive_credentials_tool(
    service: str = '',
    source: str = '',
    window: str = '7d',
    limit: int = 50,
) -> dict:
    """Plaintext logins captured by the interactive sensors (sensors that answer as a
    real service and hold the session): username, password, the service they were
    tried on, the outcome and the source address, newest first, plus the pairs
    tried most and a per-service breakdown.

    Use for "what passwords are attackers trying on SSH", "which credentials did
    this IP try", "what logins hit MySQL this week". For whether an address is
    hostile overall, use ioc_lookup_tool; for the rest of what it did in its
    sessions, use interactive_sessions_tool.

    service: a service name such as ssh-password, telnet-login, mysql-login,
    rdp-credssp or smb-ntlmssp, or empty for all. source: an address or CIDR, or
    empty for all. window: 24h, 7d (default) or 30d, capped at the plan's query
    window. limit: 1 to 200, default 50. These records feed no verdict, and
    ioc_lookup_tool does not include them."""
    return await _call_or_stub("interactive_credentials_tool", {"service": service, "source": source, "window": window, "limit": limit})


@mcp.tool(title='Files handed to interactive sensors', annotations=_READ_ONLY)
async def interactive_files_tool(
    sha256: str = '',
    source: str = '',
    window: str = '30d',
    limit: int = 50,
) -> dict:
    """Files clients handed to the interactive sensors: uploads, mail attachments,
    published messages and other artifacts, by SHA-256, with name, size, MIME
    type, the sessions that carried them and the VirusTotal verdict when one is
    known.

    Use for "have you seen this hash", "what files did this IP upload", "which
    malware samples reached the honeypots this month". For files referenced by
    URL in exploit payloads rather than delivered in a session, use
    payload_search_tool with the URL or path.

    sha256: one hash, or empty for every file in the window. source: an address
    or CIDR, or empty. window: 24h, 7d or 30d (default), capped at the plan's
    query window. limit: 1 to 200, default 50."""
    return await _call_or_stub("interactive_files_tool", {"sha256": sha256, "source": source, "window": window, "limit": limit})


@mcp.tool(title='Sessions held by one source', annotations=_READ_ONLY)
async def interactive_sessions_tool(
    source: str,
    window: str = '7d',
    limit: int = 50,
) -> dict:
    """Sessions one address or range held with the interactive sensors: when, which
    port and protocol, the service the sensor answered as, the session verdict
    (scan, credential or exploit), labels, turns, bytes, duration, CVE ids proven
    by the payload, path-only CVE candidates and the download URLs the client
    named, newest first, with verdict, service and port breakdowns.

    Use after ioc_lookup_tool when the question is what an address did inside a
    session: "what did this IP do on the honeypots", "did this range get past a
    login", "which exploits did it try". For the logins alone, use
    interactive_credentials_tool; for files it delivered, interactive_files_tool.

    source is required: an address or CIDR. window: 24h, 7d (default) or 30d,
    capped at the plan's query window. limit: 1 to 200, default 50."""
    return await _call_or_stub("interactive_sessions_tool", {"source": source, "window": window, "limit": limit})


if __name__ == "__main__":
    mcp.run()
