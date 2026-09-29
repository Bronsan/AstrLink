---
name: astrlink-debug
description:
  Debug AstrLink local gateway requests using request records, sessions, and
  trajectory events. Use when an IDE or agent call through AstrLink fails,
  routes to the wrong model, is blocked by privacy policy, retries, or
  astrlink/auto classification looks wrong.
---

# AstrLink request-record debugging

AstrLink is the local API gateway. When a client request through `127.0.0.1`
misbehaves, inspect **request records** instead of guessing from the model error
text.

## Use the MCP tools first

The `astrlink` MCP server is a **local stdio** process (Cursor, Claude Code,
Codex, Grok Build, or any other host). It only reads; the one exception is
`request_raw_audit`, which files an approval request that the user decides in
the AstrLink desktop. Prefer it over curling Control API or reading SQLite.

It is **not** a remote OAuth server. Never call `mcp_auth`, never click
Authenticate / Sign in / login for `astrlink`. Hosts sometimes expose that stub
when the stdio handshake failed; authenticating cannot fix a local process.

1. `get_audit_settings` — see whether bodies are being captured.
2. `list_request_sessions` or `list_request_records` — filter with `status`,
   `protocol`, `service_id`, `from`, `to`. `search_requests` does the same with
   a required `q` that matches the record's short input preview.
3. `explain_request` — one call for a record, its retry attempts, and whether
   bodies were captured. Use `get_request_record` / `get_request_session` for
   the raw metadata and `events[]`.
4. `get_request_children` — inspect failed retries under a root record.
5. `get_request_audit` — the shareable bodies, only if the user already enabled
   capture for that request. See [Bodies](#bodies) for withheld parts.
6. `get_routing_settings` — model redirects, failover and retry settings,
   channel stickiness, and identity enforcement.
7. `list_services` / `get_service_status` — configured providers, their models
   and capabilities, subscription state, and a summary of recent requests and
   risk events. Credentials, proxy addresses, and URL paths are never returned;
   `base_origin` is only scheme, host, and port.
8. `get_privacy_policy` — privacy policy settings. Allowlist entries and custom
   regex rules are reported as counts and types, never their values.

If the only visible tool is `mcp_auth`, or the server is loading / error /
disconnected:

1. Ask the user to open the AstrLink desktop and wait until the gateway is
   Ready.
2. If the read-only tools still do not appear, ask them to open Settings → Agent
   tools, reinstall skill + MCP, then start a **new** agent session in that
   host.
3. If an authenticate / login dialog appears for `astrlink`, tell the user to
   Skip or dismiss it.

If the tools are listed but a call says the control session is unavailable, the
desktop gateway is not running. Ask the user to start it. Do not search sidecar
memory, process arguments, or `astrlink.db`.

## When to look

- Gateway 4xx/5xx, timeouts, or cancellations
- Wrong upstream model or service — check `model_redirect` on the record and
  `get_routing_settings` first; a redirect rule may have replaced the model
- `codex-auto-review` fails (for example `missing_protocol_capability`) — it is
  Codex's auto-review model, which third-party providers rarely list; Codex then
  denies the pending action. Suggest the featured redirect in Routing → Model
  redirects (OpenAI serves it with `gpt-5.6-luna`)
- Privacy policy `block` / `warn` / unexpected redaction
- Retry loops or a child attempt that failed after a root
- `astrlink/auto` picked an unexpected category or fallback

## How to read a record

Metadata is always present. Treat these fields as the source of truth:

- `status`: `pending` | `succeeded` | `failed` | `cancelled` | `blocked`
- `requested_model` (the model the client sent), `input_protocol`, `streaming`
- `model_redirect` `{from, to}`: a routing-settings redirect replaced
  `requested_model` with `to` for routing and in the upstream request; absent
  when no rule matched. Responses pass through unchanged, so they name the
  upstream model rather than `from`
- `recovery.upstream_model`: the model finally sent upstream
- `service_id`, `route_id`, `plan`
- `routing_decision` `{selected, skipped[]}`: why routing chose `service_id`.
  `selected` is `priority`, `session_binding`, `response_affinity`,
  `websocket_connection`, or `failover`; `skipped` lists the higher-priority
  providers excluded before any attempt, each with a `reason` such as
  `disabled`, `model_not_listed`, or `circuit_open`. Without `selected`, no
  provider could serve the call and `skipped` names every exclusion. Absent on
  older records, model discovery, and calls still choosing a provider
- `error` (transport failures include the unwrapped cause — host/URL/IP may be
  present; credentials are redacted; no bodies or header maps)
- `input_preview` (short, secrets stripped)
- `privacy_restore` (hit counts only)
- `events[]` trajectory — see
  [references/trajectory.md](references/trajectory.md)

You may quote the transport error on the record, including host or IP, so the
operator can see a disconnect, DNS failure, or refused connection. Do not repeat
credentials, `sk-` tokens, or Authorization material if a redaction marker was
missed. Do not invent an upstream origin that is not already on the record.

## Bodies

Request/response bodies are **off by default**. `get_request_audit` returns
`bodies_captured: false` unless the user enabled body audit in the AstrLink
desktop and acknowledged the risk. Do not try to turn capture on from the agent.
Ask the user to enable it in the app if the prompt/response text is required.

Captured bodies come in two levels:

- **Shareable** (`content_view: "shareable"`) — what `get_request_audit`
  returns: parts the privacy policy cleared or redacted, such as the request
  that was sent upstream with placeholders. `privacy_findings` lists what was
  found by kind and JSON path, never the values.
- **Raw** — the client's original request, restored responses, and parts that
  were never inspected. `get_request_audit` withholds them with a `reason` and
  `raw_available`.

Work from the shareable parts first. Ask for raw parts only when a withheld part
has `raw_available: true` and the shareable parts cannot answer the question:

1. Tell the user which request you want to read raw and why. Raw content enters
   your context and is sent to the model provider you use.
2. Call `request_raw_audit` with the `request_id` and that reason. It returns
   `approval_required`.
3. Ask the user to approve it in the AstrLink desktop. Approval needs the user's
   raw password (Touch ID on macOS). Only the user can approve; do not try to
   click, script, or otherwise complete the approval yourself.
4. When the user says they approved, call `request_raw_audit` again with the
   same `request_id`. An approval for "only this time" allows one read.

If a withheld part has `raw_available: false`, or `request_raw_audit` returns
`raw_access_disabled`, `raw_access_unavailable`, or `raw_access_denied`, do not
ask again unless the user asks you to; continue with the shareable parts.

## Access level

The `astrlink` MCP server connects through the local control socket (or, on
Windows, the session token in `~/.astrlink/control-session.json`). Both carry
**observer** access only: reads succeed, and every setting change, purge,
delete, or token reveal is refused with `forbidden`. Do not try to use the
socket or session token to change settings; ask the user to make the change in
the AstrLink desktop.

## What not to do

- Do not call `mcp_auth` or complete a host login flow for the local `astrlink`
  server.
- Do not call purge, delete, or change audit or routing settings.
- Do not disable the privacy policy to “make it work”.
- Do not put control tokens, access tokens, or upstream keys into chat, files,
  or MCP config.
- Do not read, copy, or open `astrlink.db*`, the AstrLink data directory, or
  `~/.astrlink/control-session.json`, and do not run `sqlite3` on them. Tell the
  user: "AstrLink's local database is not an agent interface; I will use the
  AstrLink MCP tools instead."
