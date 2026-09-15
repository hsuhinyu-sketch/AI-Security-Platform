# Capability Broker

The Capability Broker is a shared security component between an AI Gateway and protected MCP
Tool/API backends. It separates short-lived, one-time authority from a particular gateway process,
so gateway replicas cannot accidentally accept each other's in-memory state as a security boundary.

## Trust boundary

The broker router is hosted behind an mTLS-aware listener or service mesh. After verifying the
client certificate, that host injects `BrokerPrincipal` into the Axum request extension:

- a gateway principal has `can_issue = true`;
- a protected Tool/API principal has `can_consume = true`;
- no principal, or a principal without the relevant permission, receives `403`.

`BrokerPrincipal` is not parsed from an HTTP header. This prevents a caller from declaring itself a
gateway or Tool backend. TLS termination, certificate-to-principal mapping, and the injection layer
are deployment concerns; the broker never offers an anonymous issue endpoint.

## HTTP contract

### Issue

`POST /v1/capabilities/issue`

```json
{
  "protocolVersion": "v1",
  "request": { "requestId": "req-7", "subject": {}, "action": {}, "resource": {} },
  "argumentsHash": "sha256-of-actual-tool-arguments",
  "ttlSeconds": 30
}
```

The broker enforces a positive TTL no greater than its configured maximum and stores an opaque UUID
token with the complete normalized request, argument hash, and expiry. It returns:

```json
{
  "token": "opaque-capability",
  "requestId": "req-7",
  "argumentsHash": "sha256-of-actual-tool-arguments",
  "expiresAt": "2026-09-15T00:00:30Z"
}
```

The Gateway verifies all response bindings before forwarding the token internally as
`x-ai-security-capability`. It also forwards the Base64url-encoded, gateway-normalized
`ActionRequest` as `x-ai-security-capability-context`. The original caller's values for both
headers are stripped before each HTTP Tool/API upstream request.

### Consume

`POST /v1/capabilities/consume`

```json
{
  "protocolVersion": "v1",
  "token": "opaque-capability",
  "request": { "requestId": "req-7", "subject": {}, "action": {}, "resource": {} },
  "argumentsHash": "sha256-of-actual-tool-arguments"
}
```

Consume removes the token before checking expiry, request equality, and parameter hash equality.
Therefore a successful use, an expired token, and a mismatched replay all leave no reusable token.
The protected backend should compare the returned action/resource binding against the operation it
will execute before performing its side effect.

## Tool/API consumption adapter

The optional `security-capability-broker` `client` feature supplies `HttpCapabilityConsumer` for a
protected backend. Configure a mutual-TLS consume endpoint:

```yaml
capabilityConsumer:
  consumeEndpoint: https://capability.security.internal/v1/capabilities/consume
  timeoutMillis: 250
  identityPemFile: /run/secrets/tool-api-identity.pem
  rootCaPemFile: /run/secrets/capability-root-ca.pem
```

Before an irreversible Tool/API action, the adapter reads the two internal headers, decodes the
normalized context, hashes the Tool parameters actually received, invokes `consume`, and validates
the returned request/hash/expiry binding. A missing header, invalid context, mTLS or broker failure,
or any mismatch is an error and the backend must not execute the side effect. The consumer must be
installed at the protected Tool/API boundary, never at the gateway: consuming at the gateway would
weaken the protection if a forwarded request were replayed downstream.

## Storage boundary

`CapabilityStore` defines `issue` and atomic `consume`. `InMemoryCapabilityStore` is usable for a
single-process PoC and tests only. A production adapter (for example, a relational database or a
transactional distributed cache) must provide:

- globally shared records across broker replicas;
- an atomic remove-and-return operation conditioned on the token;
- expiry cleanup that never revives a removed token;
- outage reporting as `Unavailable`, so callers fail closed.

The broker does not make a client-provided request context authoritative. The Gateway constructs
the normalized `ActionRequest` from verified identity and protocol state; the protected backend
derives the parameter hash from the Tool request it actually received.
