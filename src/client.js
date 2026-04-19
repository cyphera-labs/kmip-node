"use strict";

const tls = require("tls");
const fs = require("fs");
const {
  buildLocateRequest, buildGetRequest, buildCreateRequest,
  buildActivateRequest, buildDestroyRequest, buildCreateKeyPairRequest,
  buildRegisterRequest, buildReKeyRequest, buildDeriveKeyRequest,
  buildCheckRequest, buildGetAttributesRequest, buildGetAttributeListRequest,
  buildAddAttributeRequest, buildModifyAttributeRequest, buildDeleteAttributeRequest,
  buildObtainLeaseRequest, buildRevokeRequest, buildArchiveRequest,
  buildRecoverRequest, buildQueryRequest, buildPollRequest,
  buildDiscoverVersionsRequest, buildEncryptRequest, buildDecryptRequest,
  buildSignRequest, buildSignatureVerifyRequest, buildMACRequest,
  parseResponse, parseLocatePayload, parseGetPayload, parseCreatePayload,
  parseCheckPayload, parseReKeyPayload, parseEncryptPayload, parseDecryptPayload,
  parseSignPayload, parseSignatureVerifyPayload, parseMACPayload,
  parseQueryPayload, parseDiscoverVersionsPayload, parseDeriveKeyPayload,
  parseCreateKeyPairPayload,
} = require("./operations");
const { Operation, Tag } = require("./tags");
const { findChild, findChildren } = require("./ttlv");

/**
 * KMIP client — connects to any KMIP 1.4 server via mTLS.
 *
 * Usage:
 *   const client = new KmipClient({
 *     host: "kmip-server.corp.internal",
 *     clientCert: "/path/to/client.pem",
 *     clientKey: "/path/to/client-key.pem",
 *     caCert: "/path/to/ca.pem",
 *   });
 *
 *   const key = await client.fetchKey("my-key-name");
 *   // key is a Buffer of raw key bytes
 *
 *   await client.close();
 */
class KmipClient {
  /**
   * @param {Object} options
   * @param {string} options.host — KMIP server hostname
   * @param {number} [options.port=5696] — KMIP server port
   * @param {string} options.clientCert — path to client certificate PEM (or PEM string)
   * @param {string} options.clientKey — path to client private key PEM (or PEM string)
   * @param {string} [options.caCert] — path to CA certificate PEM (or PEM string)
   * @param {number} [options.timeout=10000] — connection timeout in ms
   */
  constructor(options) {
    this.host = options.host;
    this.port = options.port || 5696;
    this.timeout = options.timeout || 10000;
    this._socket = null;

    // Load certs — accept file paths or PEM strings
    this._cert = loadPem(options.clientCert);
    this._key = loadPem(options.clientKey);
    this._ca = options.caCert ? loadPem(options.caCert) : undefined;
  }

  /**
   * Locate keys by name.
   * @param {string} name — key name to search for
   * @returns {Promise<string[]>} — array of unique identifiers
   */
  async locate(name) {
    const request = buildLocateRequest(name);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseLocatePayload(response.payload).uniqueIdentifiers;
  }

  /**
   * Get key material by unique ID.
   * @param {string} uniqueId
   * @returns {Promise<{ objectType: number, uniqueIdentifier: string, keyMaterial: Buffer }>}
   */
  async get(uniqueId) {
    const request = buildGetRequest(uniqueId);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseGetPayload(response.payload);
  }

  /**
   * Create a new symmetric key on the server.
   * @param {string} name — key name
   * @param {string} [algorithm="AES"] — algorithm name
   * @param {number} [length=256] — key length in bits
   * @returns {Promise<{ objectType: number, uniqueIdentifier: string }>}
   */
  async create(name, algorithm, length) {
    const { Algorithm: Algo } = require("./tags");
    const algoEnum = algorithm
      ? (Algo[algorithm] || Algo[algorithm.toUpperCase()] || Algo.AES)
      : Algo.AES;
    const request = buildCreateRequest(name, algoEnum, length || 256);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseCreatePayload(response.payload);
  }

  /**
   * Convenience: locate by name + get material in one call.
   * @param {string} name — key name
   * @returns {Promise<Buffer>} — raw key bytes
   */
  async fetchKey(name) {
    const ids = await this.locate(name);
    if (ids.length === 0) {
      throw new Error(`KMIP: no key found with name "${name}"`);
    }
    const result = await this.get(ids[0]);
    if (!result.keyMaterial) {
      throw new Error(`KMIP: key "${name}" (${ids[0]}) has no extractable material`);
    }
    return result.keyMaterial;
  }

  /**
   * Activate a key by unique ID.
   * @param {string} uniqueId
   * @returns {Promise<void>}
   */
  async activate(uniqueId) {
    const request = buildActivateRequest(uniqueId);
    const responseData = await this._send(request);
    parseResponse(responseData);
  }

  /**
   * Destroy a key by unique ID.
   * @param {string} uniqueId
   * @returns {Promise<void>}
   */
  async destroy(uniqueId) {
    const request = buildDestroyRequest(uniqueId);
    const responseData = await this._send(request);
    parseResponse(responseData);
  }

  /**
   * Create a new asymmetric key pair on the server.
   * @param {string} name — key pair name
   * @param {number} [algorithm] — algorithm enum
   * @param {number} [length] — key length in bits
   * @returns {Promise<{ privateKeyUID: string, publicKeyUID: string }>}
   */
  async createKeyPair(name, algorithm, length) {
    const { Algorithm: Algo } = require("./tags");
    const algoEnum = algorithm || Algo.RSA;
    const request = buildCreateKeyPairRequest(name, algoEnum, length || 2048);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseCreateKeyPairPayload(response.payload);
  }

  /**
   * Register existing key material on the server.
   * @param {number} objectType — object type enum
   * @param {Buffer} material — raw key bytes
   * @param {string} name — key name
   * @param {number} [algorithm] — algorithm enum
   * @param {number} [length] — key length in bits
   * @returns {Promise<{ objectType: number, uniqueIdentifier: string }>}
   */
  async register(objectType, material, name, algorithm, length) {
    const { Algorithm: Algo } = require("./tags");
    const algoEnum = algorithm || Algo.AES;
    const request = buildRegisterRequest(objectType, material, name, algoEnum, length || 256);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseCreatePayload(response.payload);
  }

  /**
   * Re-key an existing key on the server.
   * @param {string} uniqueId
   * @returns {Promise<{ uniqueIdentifier: string }>}
   */
  async reKey(uniqueId) {
    const request = buildReKeyRequest(uniqueId);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseReKeyPayload(response.payload);
  }

  /**
   * Derive a new key from an existing key.
   * @param {string} uniqueId — source key UID
   * @param {Buffer} derivationData — derivation data
   * @param {string} name — derived key name
   * @param {number} [length=256] — derived key length in bits
   * @returns {Promise<{ uniqueIdentifier: string }>}
   */
  async deriveKey(uniqueId, derivationData, name, length) {
    const request = buildDeriveKeyRequest(uniqueId, derivationData, name, length || 256);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseDeriveKeyPayload(response.payload);
  }

  /**
   * Check the status of a managed object.
   * @param {string} uniqueId
   * @returns {Promise<{ uniqueIdentifier: string }>}
   */
  async check(uniqueId) {
    const request = buildCheckRequest(uniqueId);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseCheckPayload(response.payload);
  }

  /**
   * Fetch all attributes of a managed object.
   * @param {string} uniqueId
   * @returns {Promise<{ objectType: number, uniqueIdentifier: string, keyMaterial: Buffer }>}
   */
  async getAttributes(uniqueId) {
    const request = buildGetAttributesRequest(uniqueId);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseGetPayload(response.payload);
  }

  /**
   * Fetch the list of attribute names for a managed object.
   * @param {string} uniqueId
   * @returns {Promise<string[]>}
   */
  async getAttributeList(uniqueId) {
    const request = buildGetAttributeListRequest(uniqueId);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    if (!response.payload) return [];
    const attrs = findChildren(response.payload, Tag.AttributeName);
    return attrs.map(a => a.value);
  }

  /**
   * Add an attribute to a managed object.
   * @param {string} uniqueId
   * @param {string} name — attribute name
   * @param {string} value — attribute value
   * @returns {Promise<void>}
   */
  async addAttribute(uniqueId, name, value) {
    const request = buildAddAttributeRequest(uniqueId, name, value);
    const responseData = await this._send(request);
    parseResponse(responseData);
  }

  /**
   * Modify an attribute of a managed object.
   * @param {string} uniqueId
   * @param {string} name — attribute name
   * @param {string} value — attribute value
   * @returns {Promise<void>}
   */
  async modifyAttribute(uniqueId, name, value) {
    const request = buildModifyAttributeRequest(uniqueId, name, value);
    const responseData = await this._send(request);
    parseResponse(responseData);
  }

  /**
   * Delete an attribute from a managed object.
   * @param {string} uniqueId
   * @param {string} name — attribute name
   * @returns {Promise<void>}
   */
  async deleteAttribute(uniqueId, name) {
    const request = buildDeleteAttributeRequest(uniqueId, name);
    const responseData = await this._send(request);
    parseResponse(responseData);
  }

  /**
   * Obtain a lease for a managed object.
   * @param {string} uniqueId
   * @returns {Promise<number>} — lease time in seconds
   */
  async obtainLease(uniqueId) {
    const request = buildObtainLeaseRequest(uniqueId);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    if (!response.payload) return 0;
    const lease = findChild(response.payload, Tag.LeaseTime);
    return lease ? lease.value : 0;
  }

  /**
   * Revoke a managed object with the given reason code.
   * @param {string} uniqueId
   * @param {number} reason — revocation reason code
   * @returns {Promise<void>}
   */
  async revoke(uniqueId, reason) {
    const request = buildRevokeRequest(uniqueId, reason);
    const responseData = await this._send(request);
    parseResponse(responseData);
  }

  /**
   * Archive a managed object.
   * @param {string} uniqueId
   * @returns {Promise<void>}
   */
  async archive(uniqueId) {
    const request = buildArchiveRequest(uniqueId);
    const responseData = await this._send(request);
    parseResponse(responseData);
  }

  /**
   * Recover an archived managed object.
   * @param {string} uniqueId
   * @returns {Promise<void>}
   */
  async recover(uniqueId) {
    const request = buildRecoverRequest(uniqueId);
    const responseData = await this._send(request);
    parseResponse(responseData);
  }

  /**
   * Query the server for supported operations and object types.
   * @returns {Promise<{ operations: number[], objectTypes: number[] }>}
   */
  async query() {
    const request = buildQueryRequest();
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseQueryPayload(response.payload);
  }

  /**
   * Poll the server.
   * @returns {Promise<void>}
   */
  async poll() {
    const request = buildPollRequest();
    const responseData = await this._send(request);
    parseResponse(responseData);
  }

  /**
   * Discover the KMIP versions supported by the server.
   * @returns {Promise<{ versions: Array<{ major: number, minor: number }> }>}
   */
  async discoverVersions() {
    const request = buildDiscoverVersionsRequest();
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseDiscoverVersionsPayload(response.payload);
  }

  /**
   * Encrypt data using a managed key.
   * @param {string} uniqueId
   * @param {Buffer} data
   * @returns {Promise<{ data: Buffer, nonce: Buffer }>}
   */
  async encrypt(uniqueId, data) {
    const request = buildEncryptRequest(uniqueId, data);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseEncryptPayload(response.payload);
  }

  /**
   * Decrypt data using a managed key.
   * @param {string} uniqueId
   * @param {Buffer} data
   * @param {Buffer} [nonce]
   * @returns {Promise<{ data: Buffer }>}
   */
  async decrypt(uniqueId, data, nonce) {
    const request = buildDecryptRequest(uniqueId, data, nonce);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseDecryptPayload(response.payload);
  }

  /**
   * Sign data using a managed key.
   * @param {string} uniqueId
   * @param {Buffer} data
   * @returns {Promise<{ signatureData: Buffer }>}
   */
  async sign(uniqueId, data) {
    const request = buildSignRequest(uniqueId, data);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseSignPayload(response.payload);
  }

  /**
   * Verify a signature using a managed key.
   * @param {string} uniqueId
   * @param {Buffer} data
   * @param {Buffer} signature
   * @returns {Promise<{ valid: boolean }>}
   */
  async signatureVerify(uniqueId, data, signature) {
    const request = buildSignatureVerifyRequest(uniqueId, data, signature);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseSignatureVerifyPayload(response.payload);
  }

  /**
   * Compute a MAC using a managed key.
   * @param {string} uniqueId
   * @param {Buffer} data
   * @returns {Promise<{ macData: Buffer }>}
   */
  async mac(uniqueId, data) {
    const request = buildMACRequest(uniqueId, data);
    const responseData = await this._send(request);
    const response = parseResponse(responseData);
    return parseMACPayload(response.payload);
  }

  /**
   * Close the TLS connection.
   */
  async close() {
    if (this._socket) {
      this._socket.destroy();
      this._socket = null;
    }
  }

  /**
   * Send a KMIP request and receive the response.
   * @private
   */
  async _send(request) {
    const socket = await this._connect();

    return new Promise((resolve, reject) => {
      const chunks = [];
      let expectedLength = null;

      const onData = (data) => {
        chunks.push(data);
        const buf = Buffer.concat(chunks);

        // TTLV header: first 8 bytes contain the total length
        if (expectedLength === null && buf.length >= 8) {
          const valueLength = buf.readUInt32BE(4);
          expectedLength = 8 + valueLength;
        }

        if (expectedLength !== null && buf.length >= expectedLength) {
          socket.removeListener("data", onData);
          resolve(buf.subarray(0, expectedLength));
        }
      };

      socket.on("data", onData);
      socket.once("error", reject);
      socket.write(request);
    });
  }

  /**
   * Establish or reuse the mTLS connection.
   * @private
   */
  async _connect() {
    if (this._socket && !this._socket.destroyed) {
      return this._socket;
    }

    return new Promise((resolve, reject) => {
      const options = {
        host: this.host,
        port: this.port,
        cert: this._cert,
        key: this._key,
        ca: this._ca,
        rejectUnauthorized: !!this._ca,
        timeout: this.timeout,
      };

      const socket = tls.connect(options, () => {
        this._socket = socket;
        resolve(socket);
      });

      socket.once("error", (err) => {
        reject(new Error(`KMIP connection failed: ${err.message}`));
      });

      socket.once("timeout", () => {
        socket.destroy();
        reject(new Error(`KMIP connection timed out after ${this.timeout}ms`));
      });
    });
  }
}

/**
 * Load a PEM — if it looks like a file path, read it; otherwise treat as PEM string.
 */
function loadPem(pathOrPem) {
  if (!pathOrPem) return undefined;
  if (pathOrPem.includes("-----BEGIN")) return pathOrPem;
  return fs.readFileSync(pathOrPem, "utf8");
}

module.exports = { KmipClient };
