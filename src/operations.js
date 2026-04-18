"use strict";

const {
  encodeStructure, encodeInteger, encodeEnum, encodeTextString, encodeByteString,
  decodeTTLV, findChild, findChildren, Type,
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

  const result = {
    operation: operationItem ? operationItem.value : null,
    resultStatus: statusItem ? statusItem.value : null,
    resultReason: reasonItem ? reasonItem.value : null,
    resultMessage: messageItem ? messageItem.value : null,
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

module.exports = {
  buildLocateRequest,
  buildGetRequest,
  buildCreateRequest,
  parseResponse,
  parseLocatePayload,
  parseGetPayload,
  parseCreatePayload,
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
};
