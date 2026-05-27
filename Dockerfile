# HoneyLabs MCP — stub stdio server for Glama directory evaluation.
#
# Production lives at https://mcp.honeylabs.net/mcp (remote streamable-http,
# OAuth + Bearer auth). The Glama directory needs a Dockerfile-buildable
# artifact to run sandboxed for Tool Definition Quality + Server Coherence
# scoring; this image satisfies that by registering the same 7 tools with
# identical names, parameter schemas, and docstrings as production. The
# tool *implementations* return a stub message pointing the caller at the
# live endpoint, because the real implementations depend on backend
# services (ClickHouse, Postgres, Redis behind WireGuard) that aren't
# available in a sandboxed build.
#
# DO NOT use this image for real workloads — install the public MCP
# endpoint in your MCP client per the README "Install" section.

FROM python:3.12-slim

WORKDIR /app
COPY glama/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY glama/stub_server.py ./stub_server.py

ENTRYPOINT ["python", "stub_server.py"]
