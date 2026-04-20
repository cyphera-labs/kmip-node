"use strict";

const {
  encodeStructure, encodeInteger, encodeEnum, encodeTextString, encodeByteString,
  encodeBoolean, decodeTTLV, findChild, findChildren, Type,
} = require("./ttlv");

const { Tag, Operation, ObjectType, ResultStatus, Algorithm, NameType, KeyFormatType, UsageMask } = require("./tags");

// Protocol version: KMIP 1.4
const PROTOCOL_MAJOR = 1;
const PROTOCOL_MINOR = 4;

/**
 * Build the request header (included in every request).
 */
function buildRequestHeader(batchCount = 1) {
  return encodeStructure(Tag.RequestHeader, [
    encodeStructure(Tag.ProtocolVersion, [
      encodeInteger(Tag.ProtocolVersionMajor, PROTOCOL_MAJOR),
      encodeInteger(Tag.ProtocolVersionMinor, PROTOCOL_MINOR),
    ]),
    encodeInteger(Tag.BatchCount, batchCount),
  ]);
}

/**
 * Build a Locate request — find keys by name.
 */
function buildLocateRequest(name) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeStructure(Tag.Attribute, [
      encodeTextString(Tag.AttributeName, "Name"),
      encodeStructure(Tag.AttributeValue, [
        encodeTextString(Tag.NameValue, name),
        encodeEnum(Tag.NameType, NameType.UninterpretedTextString),
      ]),
    ]),
  ]);

  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.Locate),
    payload,
  ]);

  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a Get request — fetch key material by unique ID.
 */
function buildGetRequest(uniqueId) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
  ]);

  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.Get),
    payload,
  ]);

  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a Create request — create a new symmetric key.
 */
function buildCreateRequest(name, algorithm = Algorithm.AES, length = 256) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeEnum(Tag.ObjectType, ObjectType.SymmetricKey),
    encodeStructure(Tag.TemplateAttribute, [
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Cryptographic Algorithm"),
        encodeEnum(Tag.AttributeValue, algorithm),
      ]),
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Cryptographic Length"),
        encodeInteger(Tag.AttributeValue, length),
      ]),
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Cryptographic Usage Mask"),
        encodeInteger(Tag.AttributeValue, UsageMask.Encrypt | UsageMask.Decrypt),
      ]),
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Name"),
        encodeStructure(Tag.AttributeValue, [
          encodeTextString(Tag.NameValue, name),
          encodeEnum(Tag.NameType, NameType.UninterpretedTextString),
        ]),
      ]),
    ]),
  ]);

  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.Create),
    payload,
  ]);

  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Parse a KMIP response message.
 * @param {Buffer} data — raw TTLV response bytes
 * @returns {{ operation, resultStatus, resultReason?, resultMessage?, payload }}
 */
function parseResponse(data) {
  const msg = decodeTTLV(data);
  if (msg.tag !== Tag.ResponseMessage) {
    throw new Error(`Expected ResponseMessage (0x42007B), got 0x${msg.tag.toString(16)}`);
  }

  const batchItem = findChild(msg, Tag.BatchItem);
  if (!batchItem) throw new Error("No BatchItem in response");

  const operationItem = findChild(batchItem, Tag.Operation);
  const statusItem = findChild(batchItem, Tag.ResultStatus);
  const reasonItem = findChild(batchItem, Tag.ResultReason);
  const messageItem = findChild(batchItem, Tag.ResultMessage);
  const payloadItem = findChild(batchItem, Tag.ResponsePayload);

  // ResultStatus missing = treat as failure (not silent success)
  if (!statusItem) {
    throw new Error("KMIP: response missing ResultStatus field");
  }

  const result = {
    operation: operationItem ? operationItem.value : null,
    resultStatus: statusItem.value,
    resultReason: reasonItem ? reasonItem.value : null,
    // M3: Sanitize server-controlled resultMessage to prevent log injection
    resultMessage: messageItem
      ? String(messageItem.value || "").slice(0, 256).replace(/[\r\n]/g, " ")
      : null,
    payload: payloadItem,
  };

  if (result.resultStatus !== ResultStatus.Success) {
    const msg = result.resultMessage || `KMIP operation failed (status=${result.resultStatus})`;
    const err = new Error(msg);
    err.resultStatus = result.resultStatus;
    err.resultReason = result.resultReason;
    throw err;
  }

  return result;
}

/**
 * Parse a Locate response payload.
 * @returns {{ uniqueIdentifiers: string[] }}
 */
function parseLocatePayload(payload) {
  const ids = findChildren(payload, Tag.UniqueIdentifier);
  return {
    uniqueIdentifiers: ids.map(id => id.value),
  };
}

/**
 * Parse a Get response payload.
 * @returns {{ objectType, uniqueIdentifier, keyMaterial: Buffer }}
 */
function parseGetPayload(payload) {
  const uid = findChild(payload, Tag.UniqueIdentifier);
  const objType = findChild(payload, Tag.ObjectType);

  // Navigate: SymmetricKey → KeyBlock → KeyValue → KeyMaterial
  const symKey = findChild(payload, Tag.SymmetricKey);
  let keyMaterial = null;

  if (symKey) {
    const keyBlock = findChild(symKey, Tag.KeyBlock);
    if (keyBlock) {
      const keyValue = findChild(keyBlock, Tag.KeyValue);
      if (keyValue) {
        const material = findChild(keyValue, Tag.KeyMaterial);
        if (material) keyMaterial = material.value;
      }
    }
  }

  return {
    objectType: objType ? objType.value : null,
    uniqueIdentifier: uid ? uid.value : null,
    keyMaterial,
  };
}

/**
 * Parse a Create response payload.
 * @returns {{ objectType, uniqueIdentifier }}
 */
function parseCreatePayload(payload) {
  const uid = findChild(payload, Tag.UniqueIdentifier);
  const objType = findChild(payload, Tag.ObjectType);
  return {
    objectType: objType ? objType.value : null,
    uniqueIdentifier: uid ? uid.value : null,
  };
}

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

/**
 * Build a request with just a UID in the payload.
 */
function buildUIDOnlyRequest(operation, uniqueId) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, operation),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a request with an empty payload.
 */
function buildEmptyPayloadRequest(operation) {
  const payload = encodeStructure(Tag.RequestPayload, []);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, operation),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

// ---------------------------------------------------------------------------
// Additional request builders
// ---------------------------------------------------------------------------

/**
 * Build an Activate request.
 */
function buildActivateRequest(uniqueId) {
  return buildUIDOnlyRequest(Operation.Activate, uniqueId);
}

/**
 * Build a Destroy request.
 */
function buildDestroyRequest(uniqueId) {
  return buildUIDOnlyRequest(Operation.Destroy, uniqueId);
}

/**
 * Build a CreateKeyPair request.
 */
function buildCreateKeyPairRequest(name, algorithm = Algorithm.RSA, length = 2048) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeStructure(Tag.TemplateAttribute, [
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Cryptographic Algorithm"),
        encodeEnum(Tag.AttributeValue, algorithm),
      ]),
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Cryptographic Length"),
        encodeInteger(Tag.AttributeValue, length),
      ]),
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Cryptographic Usage Mask"),
        encodeInteger(Tag.AttributeValue, UsageMask.Sign | UsageMask.Verify),
      ]),
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Name"),
        encodeStructure(Tag.AttributeValue, [
          encodeTextString(Tag.NameValue, name),
          encodeEnum(Tag.NameType, NameType.UninterpretedTextString),
        ]),
      ]),
    ]),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.CreateKeyPair),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a Register request for a symmetric key.
 */
function buildRegisterRequest(objectType, material, name, algorithm = Algorithm.AES, length = 256) {
  const payloadChildren = [
    encodeEnum(Tag.ObjectType, objectType),
    encodeStructure(Tag.SymmetricKey, [
      encodeStructure(Tag.KeyBlock, [
        encodeEnum(Tag.KeyFormatType, KeyFormatType.Raw),
        encodeStructure(Tag.KeyValue, [
          encodeByteString(Tag.KeyMaterial, material),
        ]),
        encodeEnum(Tag.CryptographicAlgorithm, algorithm),
        encodeInteger(Tag.CryptographicLength, length),
      ]),
    ]),
  ];
  if (name) {
    payloadChildren.push(
      encodeStructure(Tag.TemplateAttribute, [
        encodeStructure(Tag.Attribute, [
          encodeTextString(Tag.AttributeName, "Name"),
          encodeStructure(Tag.AttributeValue, [
            encodeTextString(Tag.NameValue, name),
            encodeEnum(Tag.NameType, NameType.UninterpretedTextString),
          ]),
        ]),
      ])
    );
  }
  const payload = encodeStructure(Tag.RequestPayload, payloadChildren);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.Register),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a ReKey request.
 */
function buildReKeyRequest(uniqueId) {
  return buildUIDOnlyRequest(Operation.ReKey, uniqueId);
}

/**
 * Build a DeriveKey request.
 */
function buildDeriveKeyRequest(uniqueId, derivationData, name, length = 256, derivationMethod = 1) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeStructure(Tag.DerivationParameters, [
      // M6: Include DerivationMethod per KMIP 1.4 §6.32 (default 1 = PBKDF2)
      encodeEnum(Tag.DerivationMethod, derivationMethod),
      encodeByteString(Tag.DerivationData, derivationData),
    ]),
    encodeStructure(Tag.TemplateAttribute, [
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Cryptographic Length"),
        encodeInteger(Tag.AttributeValue, length),
      ]),
      encodeStructure(Tag.Attribute, [
        encodeTextString(Tag.AttributeName, "Name"),
        encodeStructure(Tag.AttributeValue, [
          encodeTextString(Tag.NameValue, name),
          encodeEnum(Tag.NameType, NameType.UninterpretedTextString),
        ]),
      ]),
    ]),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.DeriveKey),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a Check request.
 */
function buildCheckRequest(uniqueId) {
  return buildUIDOnlyRequest(Operation.Check, uniqueId);
}

/**
 * Build a GetAttributes request.
 */
function buildGetAttributesRequest(uniqueId) {
  return buildUIDOnlyRequest(Operation.GetAttributes, uniqueId);
}

/**
 * Build a GetAttributeList request.
 */
function buildGetAttributeListRequest(uniqueId) {
  return buildUIDOnlyRequest(Operation.GetAttributeList, uniqueId);
}

/**
 * Build an AddAttribute request.
 */
function buildAddAttributeRequest(uniqueId, attrName, attrValue) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeStructure(Tag.Attribute, [
      encodeTextString(Tag.AttributeName, attrName),
      encodeTextString(Tag.AttributeValue, attrValue),
    ]),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.AddAttribute),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a ModifyAttribute request.
 */
function buildModifyAttributeRequest(uniqueId, attrName, attrValue) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeStructure(Tag.Attribute, [
      encodeTextString(Tag.AttributeName, attrName),
      encodeTextString(Tag.AttributeValue, attrValue),
    ]),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.ModifyAttribute),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a DeleteAttribute request.
 */
function buildDeleteAttributeRequest(uniqueId, attrName) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeStructure(Tag.Attribute, [
      encodeTextString(Tag.AttributeName, attrName),
    ]),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.DeleteAttribute),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build an ObtainLease request.
 */
function buildObtainLeaseRequest(uniqueId) {
  return buildUIDOnlyRequest(Operation.ObtainLease, uniqueId);
}

/**
 * Build a Revoke request.
 */
function buildRevokeRequest(uniqueId, reason) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeStructure(Tag.RevocationReason, [
      encodeEnum(Tag.RevocationReasonCode, reason),
    ]),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.Revoke),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build an Archive request.
 */
function buildArchiveRequest(uniqueId) {
  return buildUIDOnlyRequest(Operation.Archive, uniqueId);
}

/**
 * Build a Recover request.
 */
function buildRecoverRequest(uniqueId) {
  return buildUIDOnlyRequest(Operation.Recover, uniqueId);
}

/**
 * Build a Query request.
 */
function buildQueryRequest() {
  return buildEmptyPayloadRequest(Operation.Query);
}

/**
 * Build a Poll request.
 */
function buildPollRequest() {
  return buildEmptyPayloadRequest(Operation.Poll);
}

/**
 * Build a DiscoverVersions request.
 */
function buildDiscoverVersionsRequest() {
  return buildEmptyPayloadRequest(Operation.DiscoverVersions);
}

/**
 * Build an Encrypt request.
 */
function buildEncryptRequest(uniqueId, data) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeByteString(Tag.Data, data),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.Encrypt),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a Decrypt request.
 */
function buildDecryptRequest(uniqueId, data, nonce) {
  const payloadChildren = [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeByteString(Tag.Data, data),
  ];
  if (nonce && nonce.length > 0) {
    payloadChildren.push(encodeByteString(Tag.IVCounterNonce, nonce));
  }
  const payload = encodeStructure(Tag.RequestPayload, payloadChildren);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.Decrypt),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a Sign request.
 */
function buildSignRequest(uniqueId, data) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeByteString(Tag.Data, data),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.Sign),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a SignatureVerify request.
 */
function buildSignatureVerifyRequest(uniqueId, data, signature) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeByteString(Tag.Data, data),
    encodeByteString(Tag.SignatureData, signature),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.SignatureVerify),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

/**
 * Build a MAC request.
 */
function buildMACRequest(uniqueId, data) {
  const payload = encodeStructure(Tag.RequestPayload, [
    encodeTextString(Tag.UniqueIdentifier, uniqueId),
    encodeByteString(Tag.Data, data),
  ]);
  const batchItem = encodeStructure(Tag.BatchItem, [
    encodeEnum(Tag.Operation, Operation.MAC),
    payload,
  ]);
  return encodeStructure(Tag.RequestMessage, [
    buildRequestHeader(),
    batchItem,
  ]);
}

// ---------------------------------------------------------------------------
// Additional response parsers
// ---------------------------------------------------------------------------

/**
 * Parse a Check response payload.
 * @returns {{ uniqueIdentifier }}
 */
function parseCheckPayload(payload) {
  if (!payload) return { uniqueIdentifier: null };
  const uid = findChild(payload, Tag.UniqueIdentifier);
  return {
    uniqueIdentifier: uid ? uid.value : null,
  };
}

/**
 * Parse a ReKey response payload.
 * @returns {{ uniqueIdentifier }}
 */
function parseReKeyPayload(payload) {
  if (!payload) return { uniqueIdentifier: null };
  const uid = findChild(payload, Tag.UniqueIdentifier);
  return {
    uniqueIdentifier: uid ? uid.value : null,
  };
}

/**
 * Parse an Encrypt response payload.
 * @returns {{ data: Buffer|null, nonce: Buffer|null }}
 */
function parseEncryptPayload(payload) {
  if (!payload) return { data: null, nonce: null };
  const dataItem = findChild(payload, Tag.Data);
  const nonceItem = findChild(payload, Tag.IVCounterNonce);
  return {
    data: dataItem ? dataItem.value : null,
    nonce: nonceItem ? nonceItem.value : null,
  };
}

/**
 * Parse a Decrypt response payload.
 * @returns {{ data: Buffer|null }}
 */
function parseDecryptPayload(payload) {
  if (!payload) return { data: null };
  const dataItem = findChild(payload, Tag.Data);
  return {
    data: dataItem ? dataItem.value : null,
  };
}

/**
 * Parse a Sign response payload.
 * @returns {{ signatureData: Buffer|null }}
 */
function parseSignPayload(payload) {
  if (!payload) return { signatureData: null };
  const sig = findChild(payload, Tag.SignatureData);
  return {
    signatureData: sig ? sig.value : null,
  };
}

/**
 * Parse a SignatureVerify response payload.
 * @returns {{ valid: boolean }}
 */
function parseSignatureVerifyPayload(payload) {
  if (!payload) return { valid: false };
  const indicator = findChild(payload, Tag.ValidityIndicator);
  return {
    // 0 = Valid, non-zero = Invalid
    valid: indicator ? indicator.value === 0 : false,
  };
}

/**
 * Parse a MAC response payload.
 * @returns {{ macData: Buffer|null }}
 */
function parseMACPayload(payload) {
  if (!payload) return { macData: null };
  const macItem = findChild(payload, Tag.MACData);
  return {
    macData: macItem ? macItem.value : null,
  };
}

/**
 * Parse a Query response payload.
 * @returns {{ operations: number[], objectTypes: number[] }}
 */
function parseQueryPayload(payload) {
  if (!payload) return { operations: [], objectTypes: [] };
  const ops = findChildren(payload, Tag.Operation);
  const objTypes = findChildren(payload, Tag.ObjectType);
  return {
    operations: ops.map(op => op.value),
    objectTypes: objTypes.map(ot => ot.value),
  };
}

/**
 * Parse a DiscoverVersions response payload.
 * @returns {{ versions: Array<{ major: number, minor: number }> }}
 */
function parseDiscoverVersionsPayload(payload) {
  if (!payload) return { versions: [] };
  const versions = findChildren(payload, Tag.ProtocolVersion);
  return {
    versions: versions.map(v => {
      const major = findChild(v, Tag.ProtocolVersionMajor);
      const minor = findChild(v, Tag.ProtocolVersionMinor);
      return {
        major: major ? major.value : 0,
        minor: minor ? minor.value : 0,
      };
    }),
  };
}

/**
 * Parse a DeriveKey response payload.
 * @returns {{ uniqueIdentifier }}
 */
function parseDeriveKeyPayload(payload) {
  if (!payload) return { uniqueIdentifier: null };
  const uid = findChild(payload, Tag.UniqueIdentifier);
  return {
    uniqueIdentifier: uid ? uid.value : null,
  };
}

/**
 * Parse a CreateKeyPair response payload.
 * @returns {{ privateKeyUID, publicKeyUID }}
 */
function parseCreateKeyPairPayload(payload) {
  if (!payload) return { privateKeyUID: null, publicKeyUID: null };
  const privUID = findChild(payload, Tag.PrivateKeyUniqueIdentifier);
  const pubUID = findChild(payload, Tag.PublicKeyUniqueIdentifier);
  return {
    privateKeyUID: privUID ? privUID.value : null,
    publicKeyUID: pubUID ? pubUID.value : null,
  };
}

module.exports = {
  buildLocateRequest,
  buildGetRequest,
  buildCreateRequest,
  buildActivateRequest,
  buildDestroyRequest,
  buildCreateKeyPairRequest,
  buildRegisterRequest,
  buildReKeyRequest,
  buildDeriveKeyRequest,
  buildCheckRequest,
  buildGetAttributesRequest,
  buildGetAttributeListRequest,
  buildAddAttributeRequest,
  buildModifyAttributeRequest,
  buildDeleteAttributeRequest,
  buildObtainLeaseRequest,
  buildRevokeRequest,
  buildArchiveRequest,
  buildRecoverRequest,
  buildQueryRequest,
  buildPollRequest,
  buildDiscoverVersionsRequest,
  buildEncryptRequest,
  buildDecryptRequest,
  buildSignRequest,
  buildSignatureVerifyRequest,
  buildMACRequest,
  parseResponse,
  parseLocatePayload,
  parseGetPayload,
  parseCreatePayload,
  parseCheckPayload,
  parseReKeyPayload,
  parseEncryptPayload,
  parseDecryptPayload,
  parseSignPayload,
  parseSignatureVerifyPayload,
  parseMACPayload,
  parseQueryPayload,
  parseDiscoverVersionsPayload,
  parseDeriveKeyPayload,
  parseCreateKeyPairPayload,
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
};
