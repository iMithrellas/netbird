# External flow collector (downstream PoC)

Management can direct stock NetBird clients in one account to send traffic events
to a standalone gRPC collector. Clients connect to the collector directly. Use an
HTTPS hostname and explicit port reachable from the peers, with a TLS certificate
they trust.

Generate a dedicated token-signing key. Management needs the private key; the
collector needs only the public key. These are separate from the collector's TLS keys.

```sh
openssl genpkey -algorithm Ed25519 -out flow-signing.pem
openssl pkey -in flow-signing.pem -pubout -out flow-verification.pem
```

Build Management from this checkout (`go build -o ./bin/netbird-management ./management`).
Set these environment variables on that process (or a combined server built from
the same checkout) and restart it. Use your account's `id` from `GET /api/accounts`.
For a container, mount the signing key read-only at the indicated path.

```sh
export NB_EXTERNAL_FLOW_ENABLED=true
export NB_EXTERNAL_FLOW_ACCOUNT_ID='replace-with-your-account-id'
export NB_EXTERNAL_FLOW_URL=https://flows.example.net:8443
export NB_EXTERNAL_FLOW_AUDIENCE=netbird-flows
export NB_EXTERNAL_FLOW_SIGNING_KEY_FILE=/run/secrets/flow-signing.pem
export NB_EXTERNAL_FLOW_INTERVAL=5s
```

Start the local collector with its TLS certificate and the verification key:

```sh
./flowcollector -listen :8443 -tls-cert server-chain.pem -tls-key server-key.pem \
  -issuer-public-key flow-verification.pem -audience netbird-flows -output stdout
```

The reporting interval is optional (default `1m`, range `1s` to less than `30m`).
Peers receive the settings on their next Management sync. Make a TCP connection
between two peers in the selected account and look for a JSON record on stdout
after a reporting interval. No Vector process is needed. Exit-node and DNS flow
collection and kernel packet accounting are off.

### Credentials

Management signs version `1` JSON claims `v`, `aud`, `exp` (Unix seconds),
`account_id`, `peer_id`, and `wg_pub_key` (standard padded base64). `tokenPayload`
is unpadded base64url of the JSON; `tokenSignature` is unpadded base64url of the
Ed25519 signature over that **encoded payload**. Stock clients send
`authorization: Bearer <tokenSignature>.<tokenPayload>` to `/flow.FlowService/Events`.
Credentials last an hour and are renewed every 30 minutes on the Management sync
stream, including on deployments without TURN or Relay.

### Disabling

Set `NB_EXTERNAL_FLOW_ENABLED=false`, keep the same `NB_EXTERNAL_FLOW_ACCOUNT_ID`,
and restart Management. This sends an explicit stop on the next sync. Leave this
setting in place while offline peers reconnect. Leaving `NB_EXTERNAL_FLOW_ENABLED`
**unset** preserves upstream behavior: no instruction is sent, so it cannot stop
an already running sender. Other accounts are unaffected by either setting.
