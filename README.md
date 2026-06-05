# HoneyLabs

**Honeypot threat intelligence as MCP tools.** Query 90 days of probe
data from our honeypot sensor network: IP reputation, scanner
classification, CVE probing trends, TLS/SSH fingerprints (JA4, JA3, JA4H,
HASSH), mTLS client certificates, Community ID flow hashes, and attack
timelines. Use it straight from Claude, Cursor, Gemini, Cline, or any
other Model Context Protocol client.

- 🌐 **Web:** https://honeylabs.net
- 🔌 **MCP endpoint:** https://mcp.honeylabs.net/mcp (streamable HTTP)
- 🧰 **Tool catalog & worked prompts:** https://honeylabs.net/mcp
- 📖 **Docs:** https://honeylabs.net/docs
- 🔑 **Access:** free with a key, within fair-use limits

---

## Install

### Claude Code

```bash
claude mcp add honeylabs \
  --transport http \
  https://mcp.honeylabs.net/mcp \
  --header "Authorization: Bearer <your-key>"
```

Get a key at https://honeylabs.net/dashboard (magic-link sign-in, no
password).

### Claude Desktop / Cursor

Add to your MCP config:

```json
{
  "mcpServers": {
    "honeylabs": {
      "url": "https://mcp.honeylabs.net/mcp",
      "headers": {
        "Authorization": "Bearer <your-key>"
      }
    }
  }
}
```

### Cline

Same JSON config as Claude Desktop / Cursor. Install via the MCP
Marketplace listing or paste the config block above into your settings.

### Gemini CLI

```bash
gemini /mcp add honeylabs https://mcp.honeylabs.net/mcp
gemini /mcp auth honeylabs    # OAuth flow, no static key
```

OAuth 2.1 with PKCE + DCR is supported at `/oauth/authorize`. Any MCP
client that speaks standard OAuth (Gemini, MCP Inspector, Smithery,
Cline's OAuth flow) works out of the box.

---

## Tools

| Tool | What it answers |
|---|---|
| `ioc_lookup` | Is this IP / domain known to be probing? When was it last seen? What ports / paths does it hit? |
| `top_attackers` | Ranked leaderboard of source IPs, ASNs, countries, ports, or user-agents over a time window. |
| `search_events` | Raw honeypot events matching filters (IP, ASN, country, dest_port, protocol, http_method, ja4/ja3, community_id, has_client_cert). |
| `attack_timeline` | Hourly / daily attack volume over a window, with protocol / country / port filters. |
| `asn_enrich` | Full profile for an ASN: total events, unique IPs, top ports, source countries, user-agents, org name. |
| `fingerprint_search` | Search by TLS JA4 / JA3 / HTTP JA4H / SSH HASSH fingerprint to find shared infrastructure. |
| `payload_search` | Full-text URL-path + user-agent search across attack traffic. Pro tier. |

Each row in a response counts as one credit. A free key gives 500
credits a day, with higher limits for heavier use. See
https://honeylabs.net/docs#plans for the breakdown.

---

## What the data is

HoneyLabs runs a fleet of honeypots that get probed by the public
internet all day. Every probe, meaning every connection, TLS
handshake, and HTTP request, is logged with the source IP, ASN,
geo, TLS/HTTP/SSH fingerprints, and full URL path. We retain the
last 90 days and expose it through this MCP server, a JSON API, a
public lookup web UI at `/lookup/<ip>`, and CSV / STIX exports.

This is our own ground-truth record of what is actively scanning the
internet right now, gathered first-hand rather than copied from a CVSS
database or a third-party reputation feed.

---

## Showcase prompts

Things to ask Claude / Cursor / Gemini once HoneyLabs is wired in:

- *"Is 80.82.77.202 a known scanner? When was it last seen and what
  does it probe?"*
- *"Pull every IP that hit port 445 with a non-Windows User-Agent in
  the last 24 hours."*
- *"Show CVE-2024-4577 probing volume per day for the last 7 days,
  broken down by ASN."*
- *"For the top 10 attackers on port 6379 right now, what TLS JA4
  fingerprints do they share?"*

More worked examples at https://honeylabs.net/mcp.

---

## Open source

The honeypot fleet itself ([Spip-Go](https://github.com/honeylabshq/Spip-Go))
and the enrichment pipeline ([Loom](https://github.com/honeylabshq/Loom))
are public. This repo (the MCP / API surface) is closed.

---

## Contact

- info@honeylabs.net
- https://www.linkedin.com/company/honeylabsnet/
