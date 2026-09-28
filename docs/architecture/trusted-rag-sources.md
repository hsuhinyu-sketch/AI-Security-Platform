# Trusted RAG sources and index integrity

Trusted imports use `POST /v1/rag/import` with a configured `sourceId` and a relative `path`. The caller cannot supply a URL, redirect target, source version, or source-origin field. The gateway authorizes the import before fetching, disables redirects and proxy use, limits response bytes, and records the SHA-256 digest of the fetched bytes. The source version recorded in ingestion metadata must equal that digest. The public `DocumentIngestRequest::new` constructor produces a submitted source; only the configured `TrustedHttpsSourceRegistry::import_request` path can create a trusted HTTPS request. Request fields are read-only outside `security-rag`.

A configuration can enable a trusted source as follows:

```yaml
rag:
  qdrant:
    endpoint: https://qdrant.example
    collection: knowledge
    quarantineCollection: knowledge-quarantine
    integrity:
      keyId: rag-index-2026-01
      keyEnvVar: RAG_INDEX_HMAC_KEY
  trustedSources:
    - id: internal-kb
      baseUrl: https://kb.example/internal/
      bearerTokenEnvVar: INTERNAL_KB_TOKEN
      # Optional for a source using a private CA certificate:
      # caCertPem: |
      #   -----BEGIN CERTIFICATE-----
      #   ...
      #   -----END CERTIFICATE-----
```

`caCertPem` adds a trusted CA certificate for that source only. The gateway still validates the HTTPS certificate and hostname, and never follows redirects or uses a proxy. A failed source fetch emits a denied ingestion audit event with a fixed reason and no document content, URL, or response details.

`RAG_INDEX_HMAC_KEY` must contain at least 32 random bytes encoded as hex. Keep it in the deployment secret store. Trusted-source configurations require Qdrant integrity signing. The gateway signs the complete chunk payload, including tenant, ACL, source digest, classification, and content. Retrieval rejects absent or invalid proofs and point IDs that differ from their signed chunk IDs.

## Index and key changes

When enabling integrity for an existing collection, reingest or reindex every point before serving retrieval from that collection. Legacy unsigned points intentionally fail verification. Keep a backup before changing the collection.

The current verifier accepts one active key ID. For key rotation, build a replacement collection using the new key, reingest or reindex the documents, switch the configured collection, and then retire the old key and collection. Do not roll old-key and new-key instances against the same collection because each instance will reject proofs made by the other key.

Changing a trusted source's bytes naturally produces a new SHA-256 version. Reimport the document to update its indexed content and provenance. A hash proves byte identity; it does not prove who published the bytes. Publisher signatures and freshness policy are separate future controls.
