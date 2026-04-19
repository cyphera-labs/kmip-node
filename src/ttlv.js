"use strict";

/**
 * TTLV (Tag-Type-Length-Value) encoder/decoder for KMIP.
 * Implements the OASIS KMIP 1.4 binary encoding.
 *
 * Each TTLV item:
 *   Tag:    3 bytes (identifies the field)
 *   Type:   1 byte  (data type)
 *   Length: 4 bytes  (value length in bytes)
 *   Value:  variable (padded to 8-byte alignment)
 */

// KMIP data types
const Type = {
  Structure:   0x01,
  Integer:     0x02,
  LongInteger: 0x03,
  BigInteger:  0x04,
  Enumeration: 0x05,
  Boolean:     0x06,
  TextString:  0x07,
  ByteString:  0x08,
  DateTime:    0x09,
  Interval:    0x0A,
};

/**
 * Encode a TTLV item to a Buffer.
 * @param {number} tag - 3-byte tag value (e.g., 0x420069)
 * @param {number} type - 1-byte type value
 * @param {Buffer} value - raw value bytes
 * @returns {Buffer}
 */
function encodeTTLV(tag, type, value) {
  const valueLen = value.length;
  const padded = Math.ceil(valueLen / 8) * 8;
  const buf = Buffer.alloc(8 + padded);

  // Tag: 3 bytes big-endian
  buf[0] = (tag >> 16) & 0xFF;
  buf[1] = (tag >> 8) & 0xFF;
  buf[2] = tag & 0xFF;

  // Type: 1 byte
  buf[3] = type;

  // Length: 4 bytes big-endian
  buf.writeUInt32BE(valueLen, 4);

  // Value + padding
  value.copy(buf, 8);

  return buf;
}

/**
 * Encode a Structure (type 0x01) containing child TTLV items.
 */
function encodeStructure(tag, children) {
  const inner = Buffer.concat(children);
  return encodeTTLV(tag, Type.Structure, inner);
}

/**
 * Encode a 32-bit integer.
 */
function encodeInteger(tag, value) {
  const buf = Buffer.alloc(4);
  buf.writeInt32BE(value, 0);
  return encodeTTLV(tag, Type.Integer, buf);
}

/**
 * Encode a 64-bit long integer.
 */
function encodeLongInteger(tag, value) {
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(value), 0);
  return encodeTTLV(tag, Type.LongInteger, buf);
}

/**
 * Encode an enumeration (32-bit).
 */
function encodeEnum(tag, value) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(value, 0);
  return encodeTTLV(tag, Type.Enumeration, buf);
}

/**
 * Encode a boolean.
 */
function encodeBoolean(tag, value) {
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(value ? 1n : 0n, 0);
  return encodeTTLV(tag, Type.Boolean, buf);
}

/**
 * Encode a text string (UTF-8).
 */
function encodeTextString(tag, value) {
  return encodeTTLV(tag, Type.TextString, Buffer.from(value, "utf8"));
}

/**
 * Encode a byte string (raw bytes).
 */
function encodeByteString(tag, value) {
  return encodeTTLV(tag, Type.ByteString, Buffer.isBuffer(value) ? value : Buffer.from(value));
}

/**
 * Encode a DateTime (64-bit POSIX time).
 */
function encodeDateTime(tag, date) {
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(Math.floor(date.getTime() / 1000)), 0);
  return encodeTTLV(tag, Type.DateTime, buf);
}

/** Maximum nesting depth for TTLV structures. */
const MAX_DECODE_DEPTH = 32;

/**
 * Decode a TTLV buffer into a parsed tree.
 * @param {Buffer} buf
 * @param {number} [offset=0]
 * @param {number} [depth=0] - current recursion depth (internal)
 * @returns {{ tag: number, type: number, value: any, length: number, totalLength: number }}
 */
function decodeTTLV(buf, offset = 0, depth = 0) {
  if (depth > MAX_DECODE_DEPTH) {
    throw new Error("TTLV: maximum nesting depth exceeded");
  }
  if (buf.length - offset < 8) throw new Error("TTLV buffer too short for header");

  const tag = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2];
  const type = buf[offset + 3];
  const length = buf.readUInt32BE(offset + 4);
  const padded = Math.ceil(length / 8) * 8;
  const totalLength = 8 + padded;

  const valueStart = offset + 8;

  // Bounds check: ensure declared length fits within buffer.
  if (valueStart + padded > buf.length) {
    throw new Error(`TTLV: declared length ${length} exceeds buffer (have ${buf.length - valueStart} bytes)`);
  }

  let value;
  switch (type) {
    case Type.Structure: {
      const children = [];
      let pos = valueStart;
      const end = valueStart + length;
      while (pos < end) {
        const child = decodeTTLV(buf, pos, depth + 1);
        children.push(child);
        pos += child.totalLength;
      }
      value = children;
      break;
    }
    case Type.Integer:
      value = buf.readInt32BE(valueStart);
      break;
    case Type.LongInteger:
      value = buf.readBigInt64BE(valueStart);
      break;
    case Type.Enumeration:
      value = buf.readUInt32BE(valueStart);
      break;
    case Type.Boolean:
      value = buf.readBigInt64BE(valueStart) !== 0n;
      break;
    case Type.TextString:
      value = buf.toString("utf8", valueStart, valueStart + length);
      break;
    case Type.ByteString:
      value = buf.subarray(valueStart, valueStart + length);
      break;
    case Type.DateTime:
      value = new Date(Number(buf.readBigInt64BE(valueStart)) * 1000);
      break;
    case Type.BigInteger:
      value = buf.subarray(valueStart, valueStart + length);
      break;
    case Type.Interval:
      value = buf.readUInt32BE(valueStart);
      break;
    default:
      value = buf.subarray(valueStart, valueStart + length);
  }

  return { tag, type, value, length, totalLength };
}

/**
 * Find a child item by tag within a decoded structure.
 */
function findChild(decoded, tag) {
  if (!Array.isArray(decoded.value)) return null;
  return decoded.value.find(c => c.tag === tag) || null;
}

/**
 * Find all children by tag within a decoded structure.
 */
function findChildren(decoded, tag) {
  if (!Array.isArray(decoded.value)) return [];
  return decoded.value.filter(c => c.tag === tag);
}

module.exports = {
  Type,
  encodeTTLV,
  encodeStructure,
  encodeInteger,
  encodeLongInteger,
  encodeEnum,
  encodeBoolean,
  encodeTextString,
  encodeByteString,
  encodeDateTime,
  decodeTTLV,
  findChild,
  findChildren,
};
