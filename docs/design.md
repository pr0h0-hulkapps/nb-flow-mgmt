# Design: self-hosted NetBird traffic-event collection → Wazuh

## Problem

NetBird's **traffic-events logging** and **SIEM event-streaming** are advertised
as cloud-/Business-only. We want the same data — per-connection flow events
(start/end/blocked, src/dst IP, ports, byte counts) — on a self-hosted,
open-source NetBird, streamed into an existing Wazuh SIEM, without a commercial
license.

## How the feature is actually gated (from source)

- **Agents are not gated.** `client/internal/netflow` + `flow/client` (AGPL) hold
  the complete flow client. `engine.go` calls `handleFlowUpdate(wCfg.GetFlow())`
  and emits whenever the management server sends a `FlowConfig{Enabled,URL,…}`.
  No license/feature check exists on the agent side.
- **The management server never sends that config.** Two seams, both in the
  external module `github.com/netbirdio/management-integrations/integrations`,
  whose public build is a no-op stub:
  - `extra_settings.GetExtraSettings` returns empty → `FlowEnabled=false`.
  - `config.ExtendNetBirdConfig` returns the config untouched → no `Flow` field.
- **No receiver exists in OSS.** Only `flow/proto` (contract) and `flow/client`
  (sender) are open; the `FlowService` server and SIEM streamers live in the
  proprietary build.

So enabling = (a) replace that module so the seams do their job, and (b) supply a
receiver. Agents need no changes.

## Architecture

Two deployables we own, plus glue into the existing `wazuh-siem` stack:

1. **management-integrations fork** — installed by one `go.mod replace`. No
   NetBird source edits. `GetExtraSettings` reports `FlowEnabled` from env;
   `ExtendNetBirdConfig` injects `Flow{URL, token, interval, counters, dns}` and
   mints a per-peer HMAC bearer token.
2. **flow receiver** — gRPC `FlowService.Events` server → normalize → SQLite
   durable buffer → cursor-based poll API.
3. **SIEM glue** (in `wazuh-siem/`) — `netbird-traffic` poller drains the poll
   API and ships to Logstash; a `netbird-flow` lane normalizes to an ECS-ish
   envelope → `netbird-flow-*` with 30-day ISM. Mirrors the existing audit lane.

### Why these choices

- **Replace directive, not a fork.** Minimal, upgrade-stable surface; verified to
  compile against both v0.65.3 and current `main`. Agents stay stock.
- **Poll API + poller (not receiver→Logstash push).** Matches the user's existing
  `netbird-poller` pattern exactly ("poll like audit events"); the SQLite buffer
  doubles as the outage-survival store and the poll backing store (rowid = the
  monotonic cursor). The final SIEM hop is still Logstash HTTP + token.
- **HMAC bearer token.** The agent already sends `authorization: Bearer
  <sig>.<payload>`; we define `sig = base64url(HMAC-SHA256(secret, payload))`,
  `payload = base64url(json{peer,account,exp})`. Management mints, receiver
  verifies. Consistent with the stack's existing HMAC/token lanes.
- **Decoupled API in the receiver (Option A).** No coupling to NetBird's DB or to
  the `RegisterHandlers` API; robust to upgrades; one service owns flow data.

## Contracts

### gRPC handshake (receiver must honor)

1. Client opens `Events`, sends `FlowEvent{IsInitiator:true}`.
2. Client blocks on `stream.Header()` and requires ≥1 header → server sends one
   immediately.
3. Client streams events; server stores then replies `FlowEventAck{EventId}` so
   the agent stops retransmitting (at-least-once → idempotent store on `event_id`).
4. Auth: `authorization: Bearer <sig>.<payload>`, verified before any event.

### Normalized event (store + poll API JSON)

`id` (cursor), `event_id`, `flow_id`, `received_at`, `timestamp`, `public_key`,
`account`, `type` (start|end|drop), `direction`, `protocol`/`protocol_name`,
`source_ip`, `dest_ip`, `source_port`, `dest_port`, `icmp_type`/`icmp_code`,
`rx_packets`/`tx_packets`/`rx_bytes`/`tx_bytes`, `rule_id`,
`source_resource_id`, `dest_resource_id`.

### Poll API

`GET /api/events/network-traffic?after=<id>&limit=<n>` (Bearer
`NB_FLOW_API_TOKEN`) → `{"events":[…],"cursor":<maxId>}`. `/healthz` unauthenticated.

### Logstash mapping (`netbird-flow` lane)

`type→event.action`, drop→`event.outcome=failure`, `source/dest_ip→source/destination.ip`,
ports→`source/destination.port`, `protocol_name→network.transport`,
`direction→network.direction`; deterministic `_id = nbf-<event_id>`; raw under
`nbflow.*`. Index `netbird-flow-*`, ISM `audit_retention` (30 days).

## Failure handling

- Logstash/Wazuh down → events accumulate in SQLite; poller resumes by cursor and
  the pager drains the backlog. Deterministic `_id` makes re-sends idempotent.
- Store write fails → no ack → agent retransmits.
- Bad/expired token → stream rejected `Unauthenticated`.
- Flow misconfigured (no URL/secret) → `ExtendNetBirdConfig` is a no-op; agents
  stay silent. Safe default = exactly upstream behavior.

## Verification status

- receiver: unit (token/store/api) + gRPC handshake integration test (drives the
  real generated client) + live binary smoke — all pass; static `CGO_ENABLED=0`
  build OK.
- fork: builds standalone vs v0.65.3 **and** compiles into the real NetBird
  management binary via `replace` (vs `main`); golden token vector matches the
  receiver byte-for-byte.
- Logstash pipeline: `Configuration OK` against the stack's custom image.
- compose: `docker compose config` valid with the new services.

## Non-goals (v1)

- Dashboard toggle (flow is operator-controlled via `NB_FLOW_*` env).
- Per-account scoping (global on; `FlowGroups` hook present but unused).
- Folding audit ingestion into the receiver (audit stays on its own poller).
