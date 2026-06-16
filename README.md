# netbird-flow-mgmt

The **NetBird-server side** of self-hosted traffic-event collection: a drop-in
replacement for NetBird's `management-integrations` stub that **activates flow
collection on stock agents — without a commercial license**.

The SIEM side (flow receiver, traffic poller, Logstash lane, Wazuh indices) lives
in the `wazuh-siem` repo. This repo produces the patched **management server**
that tells agents to start streaming, and points them at that receiver.

## Why this works

NetBird agents already contain the full flow client (AGPL) and emit whenever the
management server sends them a `FlowConfig` — there is **no agent-side gate**. The
open-source management server never sends it because the
`github.com/netbirdio/management-integrations/integrations` module it imports is a
no-op stub. This fork replaces that stub via a single `go.mod replace`:

- `extra_settings.GetExtraSettings` → reports `FlowEnabled=true` (from env).
- `config.ExtendNetBirdConfig` → injects `Flow{URL, token, interval, …}` and
  mints a short-lived per-peer HMAC bearer token.

**No NetBird source is edited and agents are never patched.** On a NetBird
upgrade you bump `NETBIRD_VERSION` and rebuild; the seam is verified stable from
v0.65.3 through current `main`.

## Layout

```
management-integrations/   drop-in fork (module github.com/netbirdio/management-integrations/integrations)
  flowconfig.go            reads NB_FLOW_* env (once)
  extra_settings.go        GetExtraSettings -> FlowEnabled
  config/config.go         ExtendNetBirdConfig -> inject Flow + mint token
  flowtoken/               HMAC token scheme (golden-vector-matched to the receiver)
deploy/Dockerfile.management   builds a patched mgmt image via `replace`
docs/design.md             full design + how the gating works
```

## Build & deploy

Pin to **exactly** the NetBird version you run today:

```bash
docker build -f deploy/Dockerfile.management \
  --build-arg NETBIRD_VERSION=v0.65.3 \
  -t netbird-mgmt-flow:v0.65.3 .
```

Run it in place of the stock management image with:

```
NB_FLOW_URL=http://<receiver-mesh-ip-or-dns>:9999   # the wazuh-siem flow-receiver, reachable by agents
NB_FLOW_HMAC_SECRET=<openssl rand -hex 32>          # MUST match the receiver's NB_FLOW_HMAC_SECRET
NB_FLOW_INTERVAL=10s      # optional
NB_FLOW_COUNTERS=true     # optional: packet/byte counters
NB_FLOW_DNS=false         # optional: DNS event collection
```

If `NB_FLOW_URL` or `NB_FLOW_HMAC_SECRET` is unset, flow stays **off** and
behavior is exactly stock NetBird (safe default). `NB_FLOW_URL` must be reachable
by every agent — a NetBird mesh IP/DNS of the receiver host, or a public TLS
endpoint (use `https://` to encrypt the agent→receiver hop).

`NB_FLOW_HMAC_SECRET` is shared with the SIEM side: the management server mints
the token with it, and the `wazuh-siem` flow-receiver verifies the token with the
same value.

## Test

```bash
cd management-integrations && go test ./flowtoken/   # token golden vector (matches the receiver)
```

The golden-vector test pins the HMAC wire format; the receiver in `wazuh-siem`
asserts the same constants, so minting and verification cannot drift.
