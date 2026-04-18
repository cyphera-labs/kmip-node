"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { Tag, Operation, ObjectType, ResultStatus, KeyFormatType, Algorithm, NameType, UsageMask } = require("./tags");

// ---------------------------------------------------------------------------
// ObjectType values — KMIP 1.4 Section 9.1.3.2.3
// ---------------------------------------------------------------------------

describe("Tags — ObjectType (KMIP 1.4 spec)", () => {
  it("Certificate = 0x00000001", () => assert.equal(ObjectType.Certificate, 0x00000001));
  it("SymmetricKey = 0x00000002", () => assert.equal(ObjectType.SymmetricKey, 0x00000002));
  it("PublicKey = 0x00000003", () => assert.equal(ObjectType.PublicKey, 0x00000003));
  it("PrivateKey = 0x00000004", () => assert.equal(ObjectType.PrivateKey, 0x00000004));
  it("SplitKey = 0x00000005", () => assert.equal(ObjectType.SplitKey, 0x00000005));
  it("Template = 0x00000006", () => assert.equal(ObjectType.Template, 0x00000006));
  it("SecretData = 0x00000007", () => assert.equal(ObjectType.SecretData, 0x00000007));
  it("OpaqueData = 0x00000008", () => assert.equal(ObjectType.OpaqueData, 0x00000008));

  it("has no duplicate values", () => {
    const values = Object.values(ObjectType);
    assert.equal(new Set(values).size, values.length);
  });
});

// ---------------------------------------------------------------------------
// Operation values — KMIP 1.4 Section 9.1.3.2.2
// ---------------------------------------------------------------------------

describe("Tags — Operations (KMIP 1.4 spec)", () => {
  it("Create = 0x00000001", () => assert.equal(Operation.Create, 0x00000001));
  it("Locate = 0x00000008", () => assert.equal(Operation.Locate, 0x00000008));
  it("Get = 0x0000000A", () => assert.equal(Operation.Get, 0x0000000A));
  it("Activate = 0x00000012", () => assert.equal(Operation.Activate, 0x00000012));
  it("Destroy = 0x00000014", () => assert.equal(Operation.Destroy, 0x00000014));
  it("Check = 0x0000001C", () => assert.equal(Operation.Check, 0x0000001C));

  it("has no duplicate values", () => {
    const values = Object.values(Operation);
    assert.equal(new Set(values).size, values.length);
  });
});

// ---------------------------------------------------------------------------
// ResultStatus
// ---------------------------------------------------------------------------

describe("Tags — ResultStatus", () => {
  it("Success = 0x00000000", () => assert.equal(ResultStatus.Success, 0x00000000));
  it("OperationFailed = 0x00000001", () => assert.equal(ResultStatus.OperationFailed, 0x00000001));
  it("OperationPending = 0x00000002", () => assert.equal(ResultStatus.OperationPending, 0x00000002));
  it("OperationUndone = 0x00000003", () => assert.equal(ResultStatus.OperationUndone, 0x00000003));

  it("has no duplicate values", () => {
    const values = Object.values(ResultStatus);
    assert.equal(new Set(values).size, values.length);
  });
});

// ---------------------------------------------------------------------------
// Algorithm values — KMIP 1.4 Section 9.1.3.2.13
// ---------------------------------------------------------------------------

describe("Tags — Algorithms (KMIP 1.4 spec)", () => {
  it("DES = 0x00000001", () => assert.equal(Algorithm.DES, 0x00000001));
  it("TripleDES = 0x00000002", () => assert.equal(Algorithm.TripleDES, 0x00000002));
  it("AES = 0x00000003", () => assert.equal(Algorithm.AES, 0x00000003));
  it("RSA = 0x00000004", () => assert.equal(Algorithm.RSA, 0x00000004));
  it("DSA = 0x00000005", () => assert.equal(Algorithm.DSA, 0x00000005));
  it("ECDSA = 0x00000006", () => assert.equal(Algorithm.ECDSA, 0x00000006));
  it("HMACSHA1 = 0x00000007", () => assert.equal(Algorithm.HMACSHA1, 0x00000007));
  it("HMACSHA256 = 0x00000008", () => assert.equal(Algorithm.HMACSHA256, 0x00000008));
  it("HMACSHA384 = 0x00000009", () => assert.equal(Algorithm.HMACSHA384, 0x00000009));
  it("HMACSHA512 = 0x0000000A", () => assert.equal(Algorithm.HMACSHA512, 0x0000000A));

  it("has no duplicate values", () => {
    const values = Object.values(Algorithm);
    assert.equal(new Set(values).size, values.length);
  });
});

// ---------------------------------------------------------------------------
// KeyFormatType values
// ---------------------------------------------------------------------------

describe("Tags — KeyFormatType", () => {
  it("Raw = 0x00000001", () => assert.equal(KeyFormatType.Raw, 0x00000001));
  it("Opaque = 0x00000002", () => assert.equal(KeyFormatType.Opaque, 0x00000002));
  it("PKCS1 = 0x00000003", () => assert.equal(KeyFormatType.PKCS1, 0x00000003));
  it("PKCS8 = 0x00000004", () => assert.equal(KeyFormatType.PKCS8, 0x00000004));
  it("X509 = 0x00000005", () => assert.equal(KeyFormatType.X509, 0x00000005));
  it("ECPrivateKey = 0x00000006", () => assert.equal(KeyFormatType.ECPrivateKey, 0x00000006));
  it("TransparentSymmetric = 0x00000007", () => assert.equal(KeyFormatType.TransparentSymmetric, 0x00000007));

  it("has no duplicate values", () => {
    const values = Object.values(KeyFormatType);
    assert.equal(new Set(values).size, values.length);
  });
});

// ---------------------------------------------------------------------------
// NameType values
// ---------------------------------------------------------------------------

describe("Tags — NameType", () => {
  it("UninterpretedTextString = 0x00000001", () => assert.equal(NameType.UninterpretedTextString, 0x00000001));
  it("URI = 0x00000002", () => assert.equal(NameType.URI, 0x00000002));
});

// ---------------------------------------------------------------------------
// UsageMask — bitmask values
// ---------------------------------------------------------------------------

describe("Tags — UsageMask (bitmask)", () => {
  it("Sign = 0x00000001", () => assert.equal(UsageMask.Sign, 0x00000001));
  it("Verify = 0x00000002", () => assert.equal(UsageMask.Verify, 0x00000002));
  it("Encrypt = 0x00000004", () => assert.equal(UsageMask.Encrypt, 0x00000004));
  it("Decrypt = 0x00000008", () => assert.equal(UsageMask.Decrypt, 0x00000008));
  it("WrapKey = 0x00000010", () => assert.equal(UsageMask.WrapKey, 0x00000010));
  it("UnwrapKey = 0x00000020", () => assert.equal(UsageMask.UnwrapKey, 0x00000020));
  it("Export = 0x00000040", () => assert.equal(UsageMask.Export, 0x00000040));
  it("DeriveKey = 0x00000100", () => assert.equal(UsageMask.DeriveKey, 0x00000100));
  it("KeyAgreement = 0x00000800", () => assert.equal(UsageMask.KeyAgreement, 0x00000800));

  it("Encrypt | Decrypt combines correctly", () => {
    assert.equal(UsageMask.Encrypt | UsageMask.Decrypt, 0x0000000C);
  });

  it("all values are distinct powers of 2 (no overlapping bits)", () => {
    const values = Object.values(UsageMask);
    let combined = 0;
    for (const v of values) {
      assert.equal(combined & v, 0, `value 0x${v.toString(16)} overlaps with previous values`);
      combined |= v;
    }
  });
});

// ---------------------------------------------------------------------------
// Tag values — all should be in the 0x42XXXX range
// ---------------------------------------------------------------------------

describe("Tags — tag values in KMIP range", () => {
  it("all Tag values are in 0x42XXXX range", () => {
    for (const [name, value] of Object.entries(Tag)) {
      assert.ok(
        value >= 0x420000 && value <= 0x42FFFF,
        `Tag.${name} = 0x${value.toString(16)} is outside 0x42XXXX range`
      );
    }
  });

  it("has no duplicate tag values", () => {
    const values = Object.values(Tag);
    assert.equal(new Set(values).size, values.length);
  });
});
