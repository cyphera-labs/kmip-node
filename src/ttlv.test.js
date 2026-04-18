"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { Type, encodeTTLV, encodeStructure, encodeInteger, encodeEnum, encodeTextString, encodeByteString, encodeBoolean, decodeTTLV, findChild } = require("./ttlv");

describe("TTLV Codec", () => {
  it("encodes and decodes an integer", () => {
    const encoded = encodeInteger(0x42006A, 1);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.tag, 0x42006A);
    assert.equal(decoded.type, Type.Integer);
    assert.equal(decoded.value, 1);
  });

  it("encodes and decodes an enumeration", () => {
    const encoded = encodeEnum(0x42005C, 0x0000000A);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.tag, 0x42005C);
    assert.equal(decoded.type, Type.Enumeration);
    assert.equal(decoded.value, 0x0000000A);
  });

  it("encodes and decodes a text string", () => {
    const encoded = encodeTextString(0x420055, "my-key");
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.tag, 0x420055);
    assert.equal(decoded.type, Type.TextString);
    assert.equal(decoded.value, "my-key");
  });

  it("encodes and decodes a byte string", () => {
    const key = Buffer.from("aabbccdd", "hex");
    const encoded = encodeByteString(0x420043, key);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.tag, 0x420043);
    assert.equal(decoded.type, Type.ByteString);
    assert.deepEqual(decoded.value, key);
  });

  it("encodes and decodes a boolean", () => {
    const encoded = encodeBoolean(0x420008, true);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.type, Type.Boolean);
    assert.equal(decoded.value, true);
  });

  it("encodes and decodes a structure with children", () => {
    const encoded = encodeStructure(0x420069, [
      encodeInteger(0x42006A, 1),
      encodeInteger(0x42006B, 4),
    ]);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.tag, 0x420069);
    assert.equal(decoded.type, Type.Structure);
    assert.equal(decoded.value.length, 2);
    assert.equal(decoded.value[0].value, 1);
    assert.equal(decoded.value[1].value, 4);
  });

  it("findChild locates a child by tag", () => {
    const encoded = encodeStructure(0x420069, [
      encodeInteger(0x42006A, 1),
      encodeInteger(0x42006B, 4),
    ]);
    const decoded = decodeTTLV(encoded);
    const child = findChild(decoded, 0x42006B);
    assert.notEqual(child, null);
    assert.equal(child.value, 4);
  });

  it("pads text strings to 8-byte alignment", () => {
    // "hello" = 5 bytes → padded to 8 bytes → total TTLV = 16 bytes
    const encoded = encodeTextString(0x420055, "hello");
    assert.equal(encoded.length, 16); // 8 header + 8 padded value
  });

  it("handles empty text string", () => {
    const encoded = encodeTextString(0x420055, "");
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, "");
  });

  it("round-trips nested structures", () => {
    const encoded = encodeStructure(0x420078, [
      encodeStructure(0x420077, [
        encodeStructure(0x420069, [
          encodeInteger(0x42006A, 1),
          encodeInteger(0x42006B, 4),
        ]),
        encodeInteger(0x42000D, 1),
      ]),
    ]);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.tag, 0x420078);
    const header = findChild(decoded, 0x420077);
    assert.notEqual(header, null);
    const version = findChild(header, 0x420069);
    assert.notEqual(version, null);
    const major = findChild(version, 0x42006A);
    assert.equal(major.value, 1);
  });
});
