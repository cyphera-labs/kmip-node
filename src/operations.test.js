"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  buildLocateRequest, buildGetRequest, buildCreateRequest,
  parseResponse, parseLocatePayload, parseGetPayload, parseCreatePayload,
  PROTOCOL_MAJOR, PROTOCOL_MINOR,
} = require("./operations");
const {
  Type, decodeTTLV, findChild, findChildren,
  encodeStructure, encodeEnum, encodeInteger, encodeTextString, encodeByteString,
} = require("./ttlv");
const { Tag, Operation, ObjectType, ResultStatus, Algorithm, UsageMask } = require("./tags");

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
