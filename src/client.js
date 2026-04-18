"use strict";

const tls = require("tls");
const fs = require("fs");
const {
  buildLocateRequest, buildGetRequest, buildCreateRequest,
  parseResponse, parseLocatePayload, parseGetPayload, parseCreatePayload,
} = require("./operations");
const { Operation } = require("./tags");

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
