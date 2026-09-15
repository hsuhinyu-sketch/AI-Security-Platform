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
`x-ai-security-capability`; the original caller's header with that name is stripped.

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
