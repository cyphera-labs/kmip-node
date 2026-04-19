"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
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
  PROTOCOL_MAJOR, PROTOCOL_MINOR,
} = require("./operations");
const {
  Type, decodeTTLV, findChild, findChildren,
  encodeStructure, encodeEnum, encodeInteger, encodeTextString, encodeByteString,
} = require("./ttlv");
const { Tag, Operation, ObjectType, ResultStatus, Algorithm, UsageMask, KeyFormatType } = require("./tags");

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

describe("Operations — request building", () => {
  it("buildLocateRequest produces valid TTLV structure", () => {
    const request = buildLocateRequest("test-key");
    const decoded = decodeTTLV(request);
    assert.equal(decoded.tag, Tag.RequestMessage);
    assert.equal(decoded.type, Type.Structure);
  });

  it("buildLocateRequest contains protocol version 1.4", () => {
    const decoded = decodeTTLV(buildLocateRequest("k"));
    const header = findChild(decoded, Tag.RequestHeader);
    assert.notEqual(header, null);
    const version = findChild(header, Tag.ProtocolVersion);
    assert.notEqual(version, null);
    const major = findChild(version, Tag.ProtocolVersionMajor);
    const minor = findChild(version, Tag.ProtocolVersionMinor);
    assert.equal(major.value, PROTOCOL_MAJOR);
    assert.equal(minor.value, PROTOCOL_MINOR);
  });

  it("buildLocateRequest has batch count 1", () => {
    const decoded = decodeTTLV(buildLocateRequest("k"));
    const header = findChild(decoded, Tag.RequestHeader);
    const count = findChild(header, Tag.BatchCount);
    assert.equal(count.value, 1);
  });

  it("buildLocateRequest has Locate operation", () => {
    const decoded = decodeTTLV(buildLocateRequest("k"));
    const batch = findChild(decoded, Tag.BatchItem);
    const op = findChild(batch, Tag.Operation);
    assert.equal(op.value, Operation.Locate);
  });

  it("buildLocateRequest contains name attribute with correct value", () => {
    const decoded = decodeTTLV(buildLocateRequest("my-key"));
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = findChild(batch, Tag.RequestPayload);
    const attr = findChild(payload, Tag.Attribute);
    const attrName = findChild(attr, Tag.AttributeName);
    assert.equal(attrName.value, "Name");
    const attrValue = findChild(attr, Tag.AttributeValue);
    const nameValue = findChild(attrValue, Tag.NameValue);
    assert.equal(nameValue.value, "my-key");
  });

  it("buildGetRequest produces valid TTLV structure", () => {
    const request = buildGetRequest("unique-id-123");
    const decoded = decodeTTLV(request);
    assert.equal(decoded.tag, Tag.RequestMessage);
  });

  it("buildGetRequest has Get operation", () => {
    const decoded = decodeTTLV(buildGetRequest("uid"));
    const batch = findChild(decoded, Tag.BatchItem);
    const op = findChild(batch, Tag.Operation);
    assert.equal(op.value, Operation.Get);
  });

  it("buildGetRequest contains unique identifier", () => {
    const decoded = decodeTTLV(buildGetRequest("uid-456"));
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = findChild(batch, Tag.RequestPayload);
    const uid = findChild(payload, Tag.UniqueIdentifier);
    assert.equal(uid.value, "uid-456");
  });

  it("buildCreateRequest produces valid TTLV structure", () => {
    const request = buildCreateRequest("new-key");
    const decoded = decodeTTLV(request);
    assert.equal(decoded.tag, Tag.RequestMessage);
  });

  it("buildCreateRequest has Create operation", () => {
    const decoded = decodeTTLV(buildCreateRequest("k"));
    const batch = findChild(decoded, Tag.BatchItem);
    const op = findChild(batch, Tag.Operation);
    assert.equal(op.value, Operation.Create);
  });

  it("buildCreateRequest uses SymmetricKey object type", () => {
    const decoded = decodeTTLV(buildCreateRequest("k"));
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = findChild(batch, Tag.RequestPayload);
    const objType = findChild(payload, Tag.ObjectType);
    assert.equal(objType.value, ObjectType.SymmetricKey);
  });

  it("buildCreateRequest defaults to AES algorithm", () => {
    const decoded = decodeTTLV(buildCreateRequest("k"));
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = findChild(batch, Tag.RequestPayload);
    const tmpl = findChild(payload, Tag.TemplateAttribute);
    const attrs = findChildren(tmpl, Tag.Attribute);
    // First attribute should be Cryptographic Algorithm
    const algoAttr = attrs.find(a => {
      const name = findChild(a, Tag.AttributeName);
      return name && name.value === "Cryptographic Algorithm";
    });
    assert.notEqual(algoAttr, null);
    const algoValue = findChild(algoAttr, Tag.AttributeValue);
    assert.equal(algoValue.value, Algorithm.AES);
  });

  it("buildCreateRequest defaults to 256-bit length", () => {
    const decoded = decodeTTLV(buildCreateRequest("k"));
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = findChild(batch, Tag.RequestPayload);
    const tmpl = findChild(payload, Tag.TemplateAttribute);
    const attrs = findChildren(tmpl, Tag.Attribute);
    const lenAttr = attrs.find(a => {
      const name = findChild(a, Tag.AttributeName);
      return name && name.value === "Cryptographic Length";
    });
    assert.notEqual(lenAttr, null);
    const lenValue = findChild(lenAttr, Tag.AttributeValue);
    assert.equal(lenValue.value, 256);
  });

  it("buildCreateRequest includes encrypt+decrypt usage mask", () => {
    const decoded = decodeTTLV(buildCreateRequest("k"));
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = findChild(batch, Tag.RequestPayload);
    const tmpl = findChild(payload, Tag.TemplateAttribute);
    const attrs = findChildren(tmpl, Tag.Attribute);
    const usageAttr = attrs.find(a => {
      const name = findChild(a, Tag.AttributeName);
      return name && name.value === "Cryptographic Usage Mask";
    });
    assert.notEqual(usageAttr, null);
    const usageValue = findChild(usageAttr, Tag.AttributeValue);
    assert.equal(usageValue.value, UsageMask.Encrypt | UsageMask.Decrypt);
  });

  it("buildCreateRequest includes key name in template", () => {
    const decoded = decodeTTLV(buildCreateRequest("prod-key"));
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = findChild(batch, Tag.RequestPayload);
    const tmpl = findChild(payload, Tag.TemplateAttribute);
    const attrs = findChildren(tmpl, Tag.Attribute);
    const nameAttr = attrs.find(a => {
      const name = findChild(a, Tag.AttributeName);
      return name && name.value === "Name";
    });
    assert.notEqual(nameAttr, null);
    const nameStruct = findChild(nameAttr, Tag.AttributeValue);
    const nameValue = findChild(nameStruct, Tag.NameValue);
    assert.equal(nameValue.value, "prod-key");
  });

  it("buildCreateRequest accepts custom algorithm and length", () => {
    const decoded = decodeTTLV(buildCreateRequest("k", Algorithm.TripleDES, 192));
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = findChild(batch, Tag.RequestPayload);
    const tmpl = findChild(payload, Tag.TemplateAttribute);
    const attrs = findChildren(tmpl, Tag.Attribute);
    const algoAttr = attrs.find(a => {
      const name = findChild(a, Tag.AttributeName);
      return name && name.value === "Cryptographic Algorithm";
    });
    const algoValue = findChild(algoAttr, Tag.AttributeValue);
    assert.equal(algoValue.value, Algorithm.TripleDES);
    const lenAttr = attrs.find(a => {
      const name = findChild(a, Tag.AttributeName);
      return name && name.value === "Cryptographic Length";
    });
    const lenValue = findChild(lenAttr, Tag.AttributeValue);
    assert.equal(lenValue.value, 192);
  });
});

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

describe("Operations — response parsing", () => {
  function buildMockResponse(operation, status, payloadChildren = []) {
    const batchChildren = [
      encodeEnum(Tag.Operation, operation),
      encodeEnum(Tag.ResultStatus, status),
    ];
    if (payloadChildren.length > 0) {
      batchChildren.push(encodeStructure(Tag.ResponsePayload, payloadChildren));
    }
    return encodeStructure(Tag.ResponseMessage, [
      encodeStructure(Tag.ResponseHeader, [
        encodeStructure(Tag.ProtocolVersion, [
          encodeInteger(Tag.ProtocolVersionMajor, 1),
          encodeInteger(Tag.ProtocolVersionMinor, 4),
        ]),
        encodeInteger(Tag.BatchCount, 1),
      ]),
      encodeStructure(Tag.BatchItem, batchChildren),
    ]);
  }

  it("parseResponse extracts operation and status on success", () => {
    const response = buildMockResponse(Operation.Locate, ResultStatus.Success, [
      encodeTextString(Tag.UniqueIdentifier, "id-1"),
    ]);
    const result = parseResponse(response);
    assert.equal(result.operation, Operation.Locate);
    assert.equal(result.resultStatus, ResultStatus.Success);
  });

  it("parseResponse throws on operation failure", () => {
    const batchChildren = [
      encodeEnum(Tag.Operation, Operation.Get),
      encodeEnum(Tag.ResultStatus, ResultStatus.OperationFailed),
      encodeTextString(Tag.ResultMessage, "Item Not Found"),
    ];
    const response = encodeStructure(Tag.ResponseMessage, [
      encodeStructure(Tag.ResponseHeader, [
        encodeStructure(Tag.ProtocolVersion, [
          encodeInteger(Tag.ProtocolVersionMajor, 1),
          encodeInteger(Tag.ProtocolVersionMinor, 4),
        ]),
        encodeInteger(Tag.BatchCount, 1),
      ]),
      encodeStructure(Tag.BatchItem, batchChildren),
    ]);
    assert.throws(
      () => parseResponse(response),
      /Item Not Found/
    );
  });

  it("parseResponse throws on non-ResponseMessage tag", () => {
    const badMsg = encodeStructure(Tag.RequestMessage, []);
    assert.throws(
      () => parseResponse(badMsg),
      /Expected ResponseMessage/
    );
  });

  it("parseLocatePayload extracts unique identifiers", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeTextString(Tag.UniqueIdentifier, "uid-1"),
      encodeTextString(Tag.UniqueIdentifier, "uid-2"),
      encodeTextString(Tag.UniqueIdentifier, "uid-3"),
    ]));
    const result = parseLocatePayload(payload);
    assert.deepEqual(result.uniqueIdentifiers, ["uid-1", "uid-2", "uid-3"]);
  });

  it("parseLocatePayload handles empty result", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, []));
    const result = parseLocatePayload(payload);
    assert.deepEqual(result.uniqueIdentifiers, []);
  });

  it("parseLocatePayload handles single result", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeTextString(Tag.UniqueIdentifier, "only-one"),
    ]));
    const result = parseLocatePayload(payload);
    assert.deepEqual(result.uniqueIdentifiers, ["only-one"]);
  });

  it("parseGetPayload extracts key material from nested structure", () => {
    const keyBytes = Buffer.from("0123456789abcdef0123456789abcdef", "hex");
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeTextString(Tag.UniqueIdentifier, "uid-99"),
      encodeEnum(Tag.ObjectType, ObjectType.SymmetricKey),
      encodeStructure(Tag.SymmetricKey, [
        encodeStructure(Tag.KeyBlock, [
          encodeEnum(Tag.KeyFormatType, 0x01), // Raw
          encodeStructure(Tag.KeyValue, [
            encodeByteString(Tag.KeyMaterial, keyBytes),
          ]),
        ]),
      ]),
    ]));
    const result = parseGetPayload(payload);
    assert.equal(result.uniqueIdentifier, "uid-99");
    assert.equal(result.objectType, ObjectType.SymmetricKey);
    assert.deepEqual(result.keyMaterial, keyBytes);
  });

  it("parseGetPayload returns null key material when no SymmetricKey", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeTextString(Tag.UniqueIdentifier, "uid-50"),
      encodeEnum(Tag.ObjectType, ObjectType.Certificate),
    ]));
    const result = parseGetPayload(payload);
    assert.equal(result.uniqueIdentifier, "uid-50");
    assert.equal(result.keyMaterial, null);
  });

  it("parseCreatePayload extracts object type and unique ID", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeEnum(Tag.ObjectType, ObjectType.SymmetricKey),
      encodeTextString(Tag.UniqueIdentifier, "new-uid-7"),
    ]));
    const result = parseCreatePayload(payload);
    assert.equal(result.objectType, ObjectType.SymmetricKey);
    assert.equal(result.uniqueIdentifier, "new-uid-7");
  });
});

// ---------------------------------------------------------------------------
// Round-trip: build → encode → decode → verify
// ---------------------------------------------------------------------------

describe("Operations — round-trip verification", () => {
  it("Locate request round-trips through TTLV encoding", () => {
    const request = buildLocateRequest("round-trip-key");
    const decoded = decodeTTLV(request);
    const reEncoded = buildLocateRequest("round-trip-key");
    assert.deepEqual(request, reEncoded);
  });

  it("Get request round-trips through TTLV encoding", () => {
    const request = buildGetRequest("uid-abc");
    const decoded = decodeTTLV(request);
    assert.equal(decoded.tag, Tag.RequestMessage);
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = findChild(batch, Tag.RequestPayload);
    const uid = findChild(payload, Tag.UniqueIdentifier);
    assert.equal(uid.value, "uid-abc");
  });

  it("Create request round-trips through TTLV encoding", () => {
    const request = buildCreateRequest("rt-key", Algorithm.AES, 128);
    const decoded = decodeTTLV(request);
    assert.equal(decoded.tag, Tag.RequestMessage);
    const batch = findChild(decoded, Tag.BatchItem);
    const op = findChild(batch, Tag.Operation);
    assert.equal(op.value, Operation.Create);
  });
});

// ---------------------------------------------------------------------------
// New request builders
// ---------------------------------------------------------------------------

describe("Operations — new request builders", () => {
  function verifyRequestStructure(request, expectedOp) {
    const decoded = decodeTTLV(request);
    assert.equal(decoded.tag, Tag.RequestMessage);
    const batch = findChild(decoded, Tag.BatchItem);
    assert.notEqual(batch, null);
    const op = findChild(batch, Tag.Operation);
    assert.equal(op.value, expectedOp);
    return { decoded, batch };
  }

  function getPayload(batch) {
    return findChild(batch, Tag.RequestPayload);
  }

  it("buildActivateRequest has Activate operation and UID", () => {
    const request = buildActivateRequest("uid-1");
    const { batch } = verifyRequestStructure(request, Operation.Activate);
    const payload = getPayload(batch);
    const uid = findChild(payload, Tag.UniqueIdentifier);
    assert.equal(uid.value, "uid-1");
  });

  it("buildDestroyRequest has Destroy operation and UID", () => {
    const request = buildDestroyRequest("uid-2");
    const { batch } = verifyRequestStructure(request, Operation.Destroy);
    const payload = getPayload(batch);
    const uid = findChild(payload, Tag.UniqueIdentifier);
    assert.equal(uid.value, "uid-2");
  });

  it("buildCreateKeyPairRequest has CreateKeyPair operation", () => {
    const request = buildCreateKeyPairRequest("kp-name", Algorithm.RSA, 2048);
    const { batch } = verifyRequestStructure(request, Operation.CreateKeyPair);
    const payload = getPayload(batch);
    const tmpl = findChild(payload, Tag.TemplateAttribute);
    assert.notEqual(tmpl, null);
    const attrs = findChildren(tmpl, Tag.Attribute);
    const algoAttr = attrs.find(a => {
      const n = findChild(a, Tag.AttributeName);
      return n && n.value === "Cryptographic Algorithm";
    });
    assert.notEqual(algoAttr, null);
    const algoVal = findChild(algoAttr, Tag.AttributeValue);
    assert.equal(algoVal.value, Algorithm.RSA);
  });

  it("buildRegisterRequest has Register operation with key material", () => {
    const material = Buffer.from("deadbeef", "hex");
    const request = buildRegisterRequest(ObjectType.SymmetricKey, material, "reg-key", Algorithm.AES, 256);
    const { batch } = verifyRequestStructure(request, Operation.Register);
    const payload = getPayload(batch);
    const objType = findChild(payload, Tag.ObjectType);
    assert.equal(objType.value, ObjectType.SymmetricKey);
    const symKey = findChild(payload, Tag.SymmetricKey);
    assert.notEqual(symKey, null);
    const keyBlock = findChild(symKey, Tag.KeyBlock);
    assert.notEqual(keyBlock, null);
    const keyValue = findChild(keyBlock, Tag.KeyValue);
    const keyMat = findChild(keyValue, Tag.KeyMaterial);
    assert.deepEqual(keyMat.value, material);
  });

  it("buildRegisterRequest omits TemplateAttribute when name is empty", () => {
    const material = Buffer.from("cafe", "hex");
    const request = buildRegisterRequest(ObjectType.SymmetricKey, material, "", Algorithm.AES, 128);
    const { batch } = verifyRequestStructure(request, Operation.Register);
    const payload = getPayload(batch);
    const tmpl = findChild(payload, Tag.TemplateAttribute);
    assert.equal(tmpl, null);
  });

  it("buildReKeyRequest has ReKey operation and UID", () => {
    const request = buildReKeyRequest("uid-rk");
    const { batch } = verifyRequestStructure(request, Operation.ReKey);
    const payload = getPayload(batch);
    const uid = findChild(payload, Tag.UniqueIdentifier);
    assert.equal(uid.value, "uid-rk");
  });

  it("buildDeriveKeyRequest has DeriveKey operation with derivation params", () => {
    const derData = Buffer.from("aabb", "hex");
    const request = buildDeriveKeyRequest("uid-dk", derData, "derived-key", 128);
    const { batch } = verifyRequestStructure(request, Operation.DeriveKey);
    const payload = getPayload(batch);
    const uid = findChild(payload, Tag.UniqueIdentifier);
    assert.equal(uid.value, "uid-dk");
    const params = findChild(payload, Tag.DerivationParameters);
    assert.notEqual(params, null);
    const dd = findChild(params, Tag.DerivationData);
    assert.deepEqual(dd.value, derData);
  });

  it("buildCheckRequest has Check operation and UID", () => {
    const request = buildCheckRequest("uid-chk");
    const { batch } = verifyRequestStructure(request, Operation.Check);
    const payload = getPayload(batch);
    const uid = findChild(payload, Tag.UniqueIdentifier);
    assert.equal(uid.value, "uid-chk");
  });

  it("buildGetAttributesRequest has GetAttributes operation", () => {
    const request = buildGetAttributesRequest("uid-ga");
    verifyRequestStructure(request, Operation.GetAttributes);
  });

  it("buildGetAttributeListRequest has GetAttributeList operation", () => {
    const request = buildGetAttributeListRequest("uid-gal");
    verifyRequestStructure(request, Operation.GetAttributeList);
  });

  it("buildAddAttributeRequest has AddAttribute operation with attr", () => {
    const request = buildAddAttributeRequest("uid-aa", "Contact", "admin@example.com");
    const { batch } = verifyRequestStructure(request, Operation.AddAttribute);
    const payload = getPayload(batch);
    const uid = findChild(payload, Tag.UniqueIdentifier);
    assert.equal(uid.value, "uid-aa");
    const attr = findChild(payload, Tag.Attribute);
    const attrName = findChild(attr, Tag.AttributeName);
    assert.equal(attrName.value, "Contact");
    const attrValue = findChild(attr, Tag.AttributeValue);
    assert.equal(attrValue.value, "admin@example.com");
  });

  it("buildModifyAttributeRequest has ModifyAttribute operation", () => {
    const request = buildModifyAttributeRequest("uid-ma", "Contact", "new@example.com");
    const { batch } = verifyRequestStructure(request, Operation.ModifyAttribute);
    const payload = getPayload(batch);
    const attr = findChild(payload, Tag.Attribute);
    const attrValue = findChild(attr, Tag.AttributeValue);
    assert.equal(attrValue.value, "new@example.com");
  });

  it("buildDeleteAttributeRequest has DeleteAttribute operation", () => {
    const request = buildDeleteAttributeRequest("uid-da", "Contact");
    const { batch } = verifyRequestStructure(request, Operation.DeleteAttribute);
    const payload = getPayload(batch);
    const attr = findChild(payload, Tag.Attribute);
    const attrName = findChild(attr, Tag.AttributeName);
    assert.equal(attrName.value, "Contact");
  });

  it("buildObtainLeaseRequest has ObtainLease operation", () => {
    const request = buildObtainLeaseRequest("uid-ol");
    verifyRequestStructure(request, Operation.ObtainLease);
  });

  it("buildRevokeRequest has Revoke operation with reason", () => {
    const request = buildRevokeRequest("uid-rev", 1);
    const { batch } = verifyRequestStructure(request, Operation.Revoke);
    const payload = getPayload(batch);
    const revReason = findChild(payload, Tag.RevocationReason);
    assert.notEqual(revReason, null);
    const reasonCode = findChild(revReason, Tag.RevocationReasonCode);
    assert.equal(reasonCode.value, 1);
  });

  it("buildArchiveRequest has Archive operation", () => {
    const request = buildArchiveRequest("uid-arc");
    verifyRequestStructure(request, Operation.Archive);
  });

  it("buildRecoverRequest has Recover operation", () => {
    const request = buildRecoverRequest("uid-rec");
    verifyRequestStructure(request, Operation.Recover);
  });

  it("buildQueryRequest has Query operation with empty payload", () => {
    const request = buildQueryRequest();
    verifyRequestStructure(request, Operation.Query);
  });

  it("buildPollRequest has Poll operation with empty payload", () => {
    const request = buildPollRequest();
    verifyRequestStructure(request, Operation.Poll);
  });

  it("buildDiscoverVersionsRequest has DiscoverVersions operation", () => {
    const request = buildDiscoverVersionsRequest();
    verifyRequestStructure(request, Operation.DiscoverVersions);
  });

  it("buildEncryptRequest has Encrypt operation with data", () => {
    const data = Buffer.from("plaintext", "utf8");
    const request = buildEncryptRequest("uid-enc", data);
    const { batch } = verifyRequestStructure(request, Operation.Encrypt);
    const payload = getPayload(batch);
    const d = findChild(payload, Tag.Data);
    assert.deepEqual(d.value, data);
  });

  it("buildDecryptRequest has Decrypt operation with data", () => {
    const data = Buffer.from("ciphertext", "utf8");
    const request = buildDecryptRequest("uid-dec", data);
    const { batch } = verifyRequestStructure(request, Operation.Decrypt);
    const payload = getPayload(batch);
    const d = findChild(payload, Tag.Data);
    assert.deepEqual(d.value, data);
  });

  it("buildDecryptRequest includes nonce when provided", () => {
    const data = Buffer.from("ct", "utf8");
    const nonce = Buffer.from("aabbccdd", "hex");
    const request = buildDecryptRequest("uid-dec2", data, nonce);
    const decoded = decodeTTLV(request);
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = getPayload(batch);
    const iv = findChild(payload, Tag.IVCounterNonce);
    assert.deepEqual(iv.value, nonce);
  });

  it("buildDecryptRequest omits nonce when null", () => {
    const data = Buffer.from("ct", "utf8");
    const request = buildDecryptRequest("uid-dec3", data, null);
    const decoded = decodeTTLV(request);
    const batch = findChild(decoded, Tag.BatchItem);
    const payload = getPayload(batch);
    const iv = findChild(payload, Tag.IVCounterNonce);
    assert.equal(iv, null);
  });

  it("buildSignRequest has Sign operation with data", () => {
    const data = Buffer.from("message", "utf8");
    const request = buildSignRequest("uid-sign", data);
    const { batch } = verifyRequestStructure(request, Operation.Sign);
    const payload = getPayload(batch);
    const d = findChild(payload, Tag.Data);
    assert.deepEqual(d.value, data);
  });

  it("buildSignatureVerifyRequest has SignatureVerify operation with data and signature", () => {
    const data = Buffer.from("msg", "utf8");
    const sig = Buffer.from("sigbytes", "utf8");
    const request = buildSignatureVerifyRequest("uid-sv", data, sig);
    const { batch } = verifyRequestStructure(request, Operation.SignatureVerify);
    const payload = getPayload(batch);
    const d = findChild(payload, Tag.Data);
    assert.deepEqual(d.value, data);
    const s = findChild(payload, Tag.SignatureData);
    assert.deepEqual(s.value, sig);
  });

  it("buildMACRequest has MAC operation with data", () => {
    const data = Buffer.from("macme", "utf8");
    const request = buildMACRequest("uid-mac", data);
    const { batch } = verifyRequestStructure(request, Operation.MAC);
    const payload = getPayload(batch);
    const d = findChild(payload, Tag.Data);
    assert.deepEqual(d.value, data);
  });
});

// ---------------------------------------------------------------------------
// New response parsers
// ---------------------------------------------------------------------------

describe("Operations — new response parsers", () => {
  it("parseCheckPayload extracts uniqueIdentifier", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeTextString(Tag.UniqueIdentifier, "chk-uid"),
    ]));
    const result = parseCheckPayload(payload);
    assert.equal(result.uniqueIdentifier, "chk-uid");
  });

  it("parseCheckPayload handles null payload", () => {
    const result = parseCheckPayload(null);
    assert.equal(result.uniqueIdentifier, null);
  });

  it("parseReKeyPayload extracts uniqueIdentifier", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeTextString(Tag.UniqueIdentifier, "rk-uid"),
    ]));
    const result = parseReKeyPayload(payload);
    assert.equal(result.uniqueIdentifier, "rk-uid");
  });

  it("parseReKeyPayload handles null payload", () => {
    const result = parseReKeyPayload(null);
    assert.equal(result.uniqueIdentifier, null);
  });

  it("parseEncryptPayload extracts data and nonce", () => {
    const ct = Buffer.from("ciphertext", "utf8");
    const nonce = Buffer.from("aabbccdd", "hex");
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeByteString(Tag.Data, ct),
      encodeByteString(Tag.IVCounterNonce, nonce),
    ]));
    const result = parseEncryptPayload(payload);
    assert.deepEqual(result.data, ct);
    assert.deepEqual(result.nonce, nonce);
  });

  it("parseEncryptPayload handles null payload", () => {
    const result = parseEncryptPayload(null);
    assert.equal(result.data, null);
    assert.equal(result.nonce, null);
  });

  it("parseEncryptPayload handles payload without nonce", () => {
    const ct = Buffer.from("ct", "utf8");
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeByteString(Tag.Data, ct),
    ]));
    const result = parseEncryptPayload(payload);
    assert.deepEqual(result.data, ct);
    assert.equal(result.nonce, null);
  });

  it("parseDecryptPayload extracts data", () => {
    const pt = Buffer.from("plaintext", "utf8");
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeByteString(Tag.Data, pt),
    ]));
    const result = parseDecryptPayload(payload);
    assert.deepEqual(result.data, pt);
  });

  it("parseDecryptPayload handles null payload", () => {
    const result = parseDecryptPayload(null);
    assert.equal(result.data, null);
  });

  it("parseSignPayload extracts signatureData", () => {
    const sig = Buffer.from("sigbytes", "utf8");
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeByteString(Tag.SignatureData, sig),
    ]));
    const result = parseSignPayload(payload);
    assert.deepEqual(result.signatureData, sig);
  });

  it("parseSignPayload handles null payload", () => {
    const result = parseSignPayload(null);
    assert.equal(result.signatureData, null);
  });

  it("parseSignatureVerifyPayload returns valid=true for indicator 0", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeEnum(Tag.ValidityIndicator, 0),
    ]));
    const result = parseSignatureVerifyPayload(payload);
    assert.equal(result.valid, true);
  });

  it("parseSignatureVerifyPayload returns valid=false for indicator 1", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeEnum(Tag.ValidityIndicator, 1),
    ]));
    const result = parseSignatureVerifyPayload(payload);
    assert.equal(result.valid, false);
  });

  it("parseSignatureVerifyPayload handles null payload", () => {
    const result = parseSignatureVerifyPayload(null);
    assert.equal(result.valid, false);
  });

  it("parseMACPayload extracts macData", () => {
    const mac = Buffer.from("macvalue", "utf8");
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeByteString(Tag.MACData, mac),
    ]));
    const result = parseMACPayload(payload);
    assert.deepEqual(result.macData, mac);
  });

  it("parseMACPayload handles null payload", () => {
    const result = parseMACPayload(null);
    assert.equal(result.macData, null);
  });

  it("parseQueryPayload extracts operations and object types", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeEnum(Tag.Operation, Operation.Create),
      encodeEnum(Tag.Operation, Operation.Get),
      encodeEnum(Tag.ObjectType, ObjectType.SymmetricKey),
    ]));
    const result = parseQueryPayload(payload);
    assert.deepEqual(result.operations, [Operation.Create, Operation.Get]);
    assert.deepEqual(result.objectTypes, [ObjectType.SymmetricKey]);
  });

  it("parseQueryPayload handles null payload", () => {
    const result = parseQueryPayload(null);
    assert.deepEqual(result.operations, []);
    assert.deepEqual(result.objectTypes, []);
  });

  it("parseQueryPayload handles empty payload", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, []));
    const result = parseQueryPayload(payload);
    assert.deepEqual(result.operations, []);
    assert.deepEqual(result.objectTypes, []);
  });

  it("parseDiscoverVersionsPayload extracts versions", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeStructure(Tag.ProtocolVersion, [
        encodeInteger(Tag.ProtocolVersionMajor, 1),
        encodeInteger(Tag.ProtocolVersionMinor, 4),
      ]),
      encodeStructure(Tag.ProtocolVersion, [
        encodeInteger(Tag.ProtocolVersionMajor, 1),
        encodeInteger(Tag.ProtocolVersionMinor, 3),
      ]),
    ]));
    const result = parseDiscoverVersionsPayload(payload);
    assert.equal(result.versions.length, 2);
    assert.deepEqual(result.versions[0], { major: 1, minor: 4 });
    assert.deepEqual(result.versions[1], { major: 1, minor: 3 });
  });

  it("parseDiscoverVersionsPayload handles null payload", () => {
    const result = parseDiscoverVersionsPayload(null);
    assert.deepEqual(result.versions, []);
  });

  it("parseDeriveKeyPayload extracts uniqueIdentifier", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeTextString(Tag.UniqueIdentifier, "dk-uid"),
    ]));
    const result = parseDeriveKeyPayload(payload);
    assert.equal(result.uniqueIdentifier, "dk-uid");
  });

  it("parseDeriveKeyPayload handles null payload", () => {
    const result = parseDeriveKeyPayload(null);
    assert.equal(result.uniqueIdentifier, null);
  });

  it("parseCreateKeyPairPayload extracts private and public UIDs", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeTextString(Tag.PrivateKeyUniqueIdentifier, "priv-uid"),
      encodeTextString(Tag.PublicKeyUniqueIdentifier, "pub-uid"),
    ]));
    const result = parseCreateKeyPairPayload(payload);
    assert.equal(result.privateKeyUID, "priv-uid");
    assert.equal(result.publicKeyUID, "pub-uid");
  });

  it("parseCreateKeyPairPayload handles null payload", () => {
    const result = parseCreateKeyPairPayload(null);
    assert.equal(result.privateKeyUID, null);
    assert.equal(result.publicKeyUID, null);
  });

  it("parseCreateKeyPairPayload handles partial payload (only private)", () => {
    const payload = decodeTTLV(encodeStructure(Tag.ResponsePayload, [
      encodeTextString(Tag.PrivateKeyUniqueIdentifier, "priv-only"),
    ]));
    const result = parseCreateKeyPairPayload(payload);
    assert.equal(result.privateKeyUID, "priv-only");
    assert.equal(result.publicKeyUID, null);
  });
});
