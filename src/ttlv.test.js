"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  Type, encodeTTLV, encodeStructure, encodeInteger, encodeLongInteger,
  encodeEnum, encodeTextString, encodeByteString, encodeBoolean,
  encodeDateTime, decodeTTLV, findChild, findChildren,
} = require("./ttlv");

// ---------------------------------------------------------------------------
// Primitive encode / decode round-trips
// ---------------------------------------------------------------------------

describe("TTLV Codec — primitives", () => {
  it("encodes and decodes an integer", () => {
    const encoded = encodeInteger(0x42006A, 1);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.tag, 0x42006A);
    assert.equal(decoded.type, Type.Integer);
    assert.equal(decoded.value, 1);
  });

  it("encodes and decodes a negative integer", () => {
    const encoded = encodeInteger(0x42006A, -42);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, -42);
  });

  it("encodes and decodes max 32-bit integer", () => {
    const encoded = encodeInteger(0x42006A, 0x7FFFFFFF);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, 0x7FFFFFFF);
  });

  it("encodes and decodes min 32-bit integer", () => {
    const encoded = encodeInteger(0x42006A, -0x80000000);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, -0x80000000);
  });

  it("encodes and decodes zero integer", () => {
    const encoded = encodeInteger(0x42006A, 0);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, 0);
  });

  it("encodes and decodes an enumeration", () => {
    const encoded = encodeEnum(0x42005C, 0x0000000A);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.tag, 0x42005C);
    assert.equal(decoded.type, Type.Enumeration);
    assert.equal(decoded.value, 0x0000000A);
  });

  it("encodes and decodes a long integer", () => {
    const encoded = encodeLongInteger(0x42006A, 1234567890123n);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.tag, 0x42006A);
    assert.equal(decoded.type, Type.LongInteger);
    assert.equal(decoded.value, 1234567890123n);
  });

  it("encodes and decodes a negative long integer", () => {
    const encoded = encodeLongInteger(0x42006A, -9999999999n);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, -9999999999n);
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

  it("encodes and decodes a boolean true", () => {
    const encoded = encodeBoolean(0x420008, true);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.type, Type.Boolean);
    assert.equal(decoded.value, true);
  });

  it("encodes and decodes a boolean false", () => {
    const encoded = encodeBoolean(0x420008, false);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.type, Type.Boolean);
    assert.equal(decoded.value, false);
  });

  it("encodes and decodes a date-time", () => {
    const date = new Date("2026-04-18T12:00:00Z");
    const encoded = encodeDateTime(0x420008, date);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.type, Type.DateTime);
    assert.equal(decoded.value.getTime(), date.getTime());
  });

  it("encodes and decodes epoch zero date-time", () => {
    const date = new Date(0);
    const encoded = encodeDateTime(0x420008, date);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value.getTime(), 0);
  });
});

// ---------------------------------------------------------------------------
// Padding and alignment
// ---------------------------------------------------------------------------

describe("TTLV Codec — padding", () => {
  it("integer occupies 8 bytes total value (4 value + 4 padding)", () => {
    const encoded = encodeInteger(0x42006A, 1);
    // 8 header + 8 padded value = 16 bytes
    assert.equal(encoded.length, 16);
    // Length field should say 4
    assert.equal(encoded.readUInt32BE(4), 4);
  });

  it("enum occupies 8 bytes total value (4 value + 4 padding)", () => {
    const encoded = encodeEnum(0x42005C, 1);
    assert.equal(encoded.length, 16);
    assert.equal(encoded.readUInt32BE(4), 4);
  });

  it("boolean uses exactly 8 bytes (no padding needed)", () => {
    const encoded = encodeBoolean(0x420008, true);
    assert.equal(encoded.length, 16); // 8 header + 8 value
    assert.equal(encoded.readUInt32BE(4), 8);
  });

  it("long integer uses exactly 8 bytes (no padding needed)", () => {
    const encoded = encodeLongInteger(0x42006A, 42n);
    assert.equal(encoded.length, 16);
    assert.equal(encoded.readUInt32BE(4), 8);
  });

  it("pads text strings to 8-byte alignment", () => {
    // "hello" = 5 bytes → padded to 8 bytes
    const encoded = encodeTextString(0x420055, "hello");
    assert.equal(encoded.length, 16); // 8 header + 8 padded value
  });

  it("text string exactly 8 bytes needs no padding", () => {
    const encoded = encodeTextString(0x420055, "12345678");
    assert.equal(encoded.length, 16); // 8 header + 8 value
  });

  it("text string 9 bytes pads to 16", () => {
    const encoded = encodeTextString(0x420055, "123456789");
    assert.equal(encoded.length, 24); // 8 header + 16 padded
  });

  it("handles empty text string (0 bytes, no padding)", () => {
    const encoded = encodeTextString(0x420055, "");
    assert.equal(encoded.length, 8); // header only
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, "");
  });

  it("byte string with exact 8-byte alignment needs no padding", () => {
    const data = Buffer.alloc(16, 0xAB);
    const encoded = encodeByteString(0x420043, data);
    assert.equal(encoded.length, 24); // 8 header + 16 value
  });

  it("byte string with 1 extra byte pads to next 8", () => {
    const data = Buffer.alloc(17, 0xAB);
    const encoded = encodeByteString(0x420043, data);
    assert.equal(encoded.length, 32); // 8 header + 24 padded
  });

  it("empty byte string", () => {
    const encoded = encodeByteString(0x420043, Buffer.alloc(0));
    assert.equal(encoded.length, 8);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value.length, 0);
  });

  it("32-byte key material round-trips correctly (AES-256)", () => {
    const key = Buffer.from(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "hex"
    );
    const encoded = encodeByteString(0x420043, key);
    assert.equal(encoded.length, 40); // 8 header + 32 value (exact alignment)
    const decoded = decodeTTLV(encoded);
    assert.deepEqual(decoded.value, key);
  });
});

// ---------------------------------------------------------------------------
// Structures and tree navigation
// ---------------------------------------------------------------------------

describe("TTLV Codec — structures", () => {
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

  it("empty structure with no children", () => {
    const encoded = encodeStructure(0x420069, []);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.type, Type.Structure);
    assert.equal(decoded.value.length, 0);
  });

  it("structure with mixed types", () => {
    const encoded = encodeStructure(0x420069, [
      encodeInteger(0x42006A, 42),
      encodeTextString(0x420055, "hello"),
      encodeBoolean(0x420008, true),
      encodeByteString(0x420043, Buffer.from("cafe", "hex")),
      encodeEnum(0x42005C, 0x0A),
    ]);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value.length, 5);
    assert.equal(decoded.value[0].value, 42);
    assert.equal(decoded.value[1].value, "hello");
    assert.equal(decoded.value[2].value, true);
    assert.deepEqual(decoded.value[3].value, Buffer.from("cafe", "hex"));
    assert.equal(decoded.value[4].value, 0x0A);
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

  it("findChild returns null for missing tag", () => {
    const encoded = encodeStructure(0x420069, [
      encodeInteger(0x42006A, 1),
    ]);
    const decoded = decodeTTLV(encoded);
    assert.equal(findChild(decoded, 0x42FFFF), null);
  });

  it("findChild returns null for non-structure", () => {
    const encoded = encodeInteger(0x42006A, 1);
    const decoded = decodeTTLV(encoded);
    assert.equal(findChild(decoded, 0x42006A), null);
  });

  it("findChildren returns all matching children", () => {
    const encoded = encodeStructure(0x420069, [
      encodeTextString(0x420094, "id-1"),
      encodeTextString(0x420094, "id-2"),
      encodeTextString(0x420094, "id-3"),
      encodeInteger(0x42006A, 99),
    ]);
    const decoded = decodeTTLV(encoded);
    const ids = findChildren(decoded, 0x420094);
    assert.equal(ids.length, 3);
    assert.equal(ids[0].value, "id-1");
    assert.equal(ids[1].value, "id-2");
    assert.equal(ids[2].value, "id-3");
  });

  it("findChildren returns empty array for non-structure", () => {
    const encoded = encodeInteger(0x42006A, 1);
    const decoded = decodeTTLV(encoded);
    assert.deepEqual(findChildren(decoded, 0x42006A), []);
  });

  it("round-trips deeply nested structures", () => {
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
    const minor = findChild(version, 0x42006B);
    assert.equal(minor.value, 4);
  });

  it("structure containing structure containing structure (3 levels)", () => {
    const encoded = encodeStructure(0x420001, [
      encodeStructure(0x420002, [
        encodeStructure(0x420003, [
          encodeTextString(0x420055, "deep"),
        ]),
      ]),
    ]);
    const decoded = decodeTTLV(encoded);
    const lvl1 = findChild(decoded, 0x420002);
    const lvl2 = findChild(lvl1, 0x420003);
    const leaf = findChild(lvl2, 0x420055);
    assert.equal(leaf.value, "deep");
  });
});

// ---------------------------------------------------------------------------
// TTLV header bytes — wire format verification
// ---------------------------------------------------------------------------

describe("TTLV Codec — wire format", () => {
  it("tag is encoded as 3 bytes big-endian", () => {
    const encoded = encodeInteger(0x420069, 0);
    assert.equal(encoded[0], 0x42);
    assert.equal(encoded[1], 0x00);
    assert.equal(encoded[2], 0x69);
  });

  it("type byte is correct for each type", () => {
    assert.equal(encodeInteger(0x420001, 0)[3], Type.Integer);
    assert.equal(encodeLongInteger(0x420001, 0n)[3], Type.LongInteger);
    assert.equal(encodeEnum(0x420001, 0)[3], Type.Enumeration);
    assert.equal(encodeBoolean(0x420001, true)[3], Type.Boolean);
    assert.equal(encodeTextString(0x420001, "x")[3], Type.TextString);
    assert.equal(encodeByteString(0x420001, Buffer.from([1]))[3], Type.ByteString);
    assert.equal(encodeStructure(0x420001, [])[3], Type.Structure);
    assert.equal(encodeDateTime(0x420001, new Date())[3], Type.DateTime);
  });

  it("length field is 4 bytes big-endian at offset 4", () => {
    const encoded = encodeTextString(0x420055, "AB"); // 2 bytes
    assert.equal(encoded.readUInt32BE(4), 2);
  });

  it("padding bytes are zero-filled", () => {
    const encoded = encodeTextString(0x420055, "AB"); // 2 bytes → padded to 8
    // Bytes 10-15 (value at offset 8, length 2, padding at 10-15)
    for (let i = 10; i < 16; i++) {
      assert.equal(encoded[i], 0, `padding byte at ${i} should be 0`);
    }
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe("TTLV Codec — error handling", () => {
  it("throws on buffer too short for header", () => {
    assert.throws(
      () => decodeTTLV(Buffer.alloc(4)),
      /too short/
    );
  });

  it("throws on empty buffer", () => {
    assert.throws(
      () => decodeTTLV(Buffer.alloc(0)),
      /too short/
    );
  });
});

// ---------------------------------------------------------------------------
// Unicode and special strings
// ---------------------------------------------------------------------------

describe("TTLV Codec — unicode strings", () => {
  it("handles UTF-8 multi-byte characters", () => {
    const encoded = encodeTextString(0x420055, "café");
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, "café");
  });

  it("handles emoji", () => {
    const encoded = encodeTextString(0x420055, "key-🔑");
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, "key-🔑");
  });

  it("handles long text string crossing multiple 8-byte boundaries", () => {
    const longStr = "a]".repeat(100); // 200 bytes
    const encoded = encodeTextString(0x420055, longStr);
    const decoded = decodeTTLV(encoded);
    assert.equal(decoded.value, longStr);
  });
});
