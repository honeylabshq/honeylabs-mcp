# HoneyLabs MCP is a *remote* server. The production endpoint lives at
# https://mcp.honeylabs.net/mcp and there's nothing to containerise on
# the client side.
#
# Some registries (Glama, etc.) still expect a Dockerfile in the repo
# so they can run introspection against the resulting container. This
# image is a thin stdio→HTTP shim: it boots, connects to the public
# endpoint via the standard MCP HTTP transport, and forwards
# introspection (`tools/list`, `prompts/list`, etc.) over stdio so the
# registry can score the server without needing the production
# bearer-token / OAuth flow.
#
# Anyone running a real workload should NOT use this image; install the
# server in their MCP client directly per the README's "Install" section.

FROM node:20-alpine

# mcp-remote is the canonical stdio adapter for hosted MCP servers.
# Maintained at https://github.com/modelcontextprotocol/mcp-remote
RUN npm install -g mcp-remote@latest

ENV HONEYLABS_MCP_URL=https://mcp.honeylabs.net/mcp

# Default to read-only introspection (no auth header) — the public
# `/mcp` endpoint advertises its tool list under MCP protocol-level
# inspection even when the bearer token is missing. For real tool
# calls, pass `--header "Authorization: Bearer <key>"` via the
# wrapping MCP client config.
ENTRYPOINT ["mcp-remote"]
CMD ["https://mcp.honeylabs.net/mcp"]
