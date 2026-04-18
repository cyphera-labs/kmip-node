# kmip-node

[![CI](https://github.com/cyphera-labs/kmip-node/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/kmip-node/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/kmip-node/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/kmip-node/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

KMIP client for Node.js — connect to any KMIP-compliant key management server.

Supports Thales CipherTrust, IBM SKLM, Entrust KeyControl, Fortanix, HashiCorp Vault Enterprise, and any KMIP 1.4 server.

```
npm install @cyphera/kmip
```

## Quick Start

```javascript
const { KmipClient } = require("@cyphera/kmip");

const client = new KmipClient({
  host: "kmip-server.corp.internal",
  clientCert: "/path/to/client.pem",
  clientKey: "/path/to/client-key.pem",
  caCert: "/path/to/ca.pem",
});

// Fetch a key by name (locate + get in one call)
const key = await client.fetchKey("my-encryption-key");
// key is a Buffer of raw key bytes (e.g., 32 bytes for AES-256)

// Or step by step:
const ids = await client.locate("my-key");
const result = await client.get(ids[0]);
console.log(result.keyMaterial); // Buffer

// Create a new AES-256 key on the server
const created = await client.create("new-key-name", "AES", 256);
console.log(created.uniqueIdentifier);

await client.close();
```

## Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Locate | `client.locate(name)` | Find keys by name, returns unique IDs |
| Get | `client.get(id)` | Fetch key material by unique ID |
| Create | `client.create(name, algo, length)` | Create a new symmetric key |
| Fetch | `client.fetchKey(name)` | Locate + Get in one call |

## Authentication

KMIP uses mutual TLS (mTLS). Provide:
- **Client certificate** — identifies your application to the KMS
- **Client private key** — proves ownership of the certificate
- **CA certificate** — validates the KMS server's certificate

```javascript
const client = new KmipClient({
  host: "kmip.corp.internal",
  port: 5696,                    // default KMIP port
  clientCert: "/etc/kmip/client.pem",
  clientKey: "/etc/kmip/client-key.pem",
  caCert: "/etc/kmip/ca.pem",
  timeout: 10000,                // connection timeout (ms)
});
```

## TTLV Codec

The low-level TTLV (Tag-Type-Length-Value) encoder/decoder is also exported for advanced use:

```javascript
const { encodeTTLV, decodeTTLV, encodeStructure, encodeTextString, Tag, Type } = require("@cyphera/kmip");

// Build custom KMIP messages
const msg = encodeStructure(Tag.RequestMessage, [ ... ]);

// Parse raw KMIP responses
const parsed = decodeTTLV(responseBuffer);
```

## Supported KMS Servers

| Server | KMIP Version | Tested |
|--------|-------------|--------|
| Thales CipherTrust Manager | 1.x, 2.0 | Planned |
| IBM SKLM | 1.x, 2.0 | Planned |
| Entrust KeyControl | 1.x, 2.0 | Planned |
| Fortanix DSM | 2.0 | Planned |
| HashiCorp Vault Enterprise | 1.4 | Planned |
| PyKMIP (test server) | 1.0-2.0 | CI |

## Zero Dependencies

This library uses only Node.js standard library (`tls`, `fs`, `Buffer`). No external dependencies.

## Status

Alpha. KMIP 1.4 operations: Locate, Get, Create.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
