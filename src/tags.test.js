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
  it("CreateKeyPair = 0x00000002", () => assert.equal(Operation.CreateKeyPair, 0x00000002));
  it("Register = 0x00000003", () => assert.equal(Operation.Register, 0x00000003));
  it("ReKey = 0x00000004", () => assert.equal(Operation.ReKey, 0x00000004));
  it("DeriveKey = 0x00000005", () => assert.equal(Operation.DeriveKey, 0x00000005));
  it("Locate = 0x00000008", () => assert.equal(Operation.Locate, 0x00000008));
  it("Check = 0x00000009", () => assert.equal(Operation.Check, 0x00000009));
  it("Get = 0x0000000A", () => assert.equal(Operation.Get, 0x0000000A));
  it("GetAttributes = 0x0000000B", () => assert.equal(Operation.GetAttributes, 0x0000000B));
  it("GetAttributeList = 0x0000000C", () => assert.equal(Operation.GetAttributeList, 0x0000000C));
  it("AddAttribute = 0x0000000D", () => assert.equal(Operation.AddAttribute, 0x0000000D));
  it("ModifyAttribute = 0x0000000E", () => assert.equal(Operation.ModifyAttribute, 0x0000000E));
  it("DeleteAttribute = 0x0000000F", () => assert.equal(Operation.DeleteAttribute, 0x0000000F));
  it("ObtainLease = 0x00000010", () => assert.equal(Operation.ObtainLease, 0x00000010));
  it("Activate = 0x00000012", () => assert.equal(Operation.Activate, 0x00000012));
  it("Revoke = 0x00000013", () => assert.equal(Operation.Revoke, 0x00000013));
  it("Destroy = 0x00000014", () => assert.equal(Operation.Destroy, 0x00000014));
  it("Archive = 0x00000015", () => assert.equal(Operation.Archive, 0x00000015));
  it("Recover = 0x00000016", () => assert.equal(Operation.Recover, 0x00000016));
  it("Query = 0x00000018", () => assert.equal(Operation.Query, 0x00000018));
  it("Poll = 0x0000001A", () => assert.equal(Operation.Poll, 0x0000001A));
  it("DiscoverVersions = 0x0000001E", () => assert.equal(Operation.DiscoverVersions, 0x0000001E));
  it("Encrypt = 0x0000001F", () => assert.equal(Operation.Encrypt, 0x0000001F));
  it("Decrypt = 0x00000020", () => assert.equal(Operation.Decrypt, 0x00000020));
  it("Sign = 0x00000021", () => assert.equal(Operation.Sign, 0x00000021));
  it("SignatureVerify = 0x00000022", () => assert.equal(Operation.SignatureVerify, 0x00000022));
  it("MAC = 0x00000023", () => assert.equal(Operation.MAC, 0x00000023));

  it("has 27 operations", () => {
    assert.equal(Object.keys(Operation).length, 27);
  });

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
  it("HMACSHA224 = 0x00000008", () => assert.equal(Algorithm.HMACSHA224, 0x00000008));
  it("HMACSHA256 = 0x00000009", () => assert.equal(Algorithm.HMACSHA256, 0x00000009));
  it("HMACSHA384 = 0x0000000A", () => assert.equal(Algorithm.HMACSHA384, 0x0000000A));
  it("HMACSHA512 = 0x0000000B", () => assert.equal(Algorithm.HMACSHA512, 0x0000000B));
  it("HMACMD5 = 0x0000000C", () => assert.equal(Algorithm.HMACMD5, 0x0000000C));

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
  it("MACGenerate = 0x00000080", () => assert.equal(UsageMask.MACGenerate, 0x00000080));
  it("MACVerify = 0x00000100", () => assert.equal(UsageMask.MACVerify, 0x00000100));
  it("DeriveKey = 0x00000200", () => assert.equal(UsageMask.DeriveKey, 0x00000200));
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

// ---------------------------------------------------------------------------
// New tag constants — key pair, certificate, crypto ops, revocation, etc.
// ---------------------------------------------------------------------------

describe("Tags — new tag constants", () => {
  it("PrivateKeyUniqueIdentifier = 0x420066", () => assert.equal(Tag.PrivateKeyUniqueIdentifier, 0x420066));
  it("PublicKeyUniqueIdentifier = 0x42006F", () => assert.equal(Tag.PublicKeyUniqueIdentifier, 0x42006F));
  it("PublicKey = 0x42004E", () => assert.equal(Tag.PublicKey, 0x42004E));
  it("PrivateKey = 0x42004D", () => assert.equal(Tag.PrivateKey, 0x42004D));
  it("Certificate = 0x420021", () => assert.equal(Tag.Certificate, 0x420021));
  it("CertificateType = 0x42001D", () => assert.equal(Tag.CertificateType, 0x42001D));
  it("CertificateValue = 0x42001E", () => assert.equal(Tag.CertificateValue, 0x42001E));
  it("Data = 0x420033", () => assert.equal(Tag.Data, 0x420033));
  it("IVCounterNonce = 0x420047", () => assert.equal(Tag.IVCounterNonce, 0x420047));
  it("SignatureData = 0x42004F", () => assert.equal(Tag.SignatureData, 0x42004F));
  it("MACData = 0x420051", () => assert.equal(Tag.MACData, 0x420051));
  it("ValidityIndicator = 0x420098", () => assert.equal(Tag.ValidityIndicator, 0x420098));
  it("RevocationReason = 0x420082", () => assert.equal(Tag.RevocationReason, 0x420082));
  it("RevocationReasonCode = 0x420083", () => assert.equal(Tag.RevocationReasonCode, 0x420083));
  it("QueryFunction = 0x420074", () => assert.equal(Tag.QueryFunction, 0x420074));
  it("State = 0x42008D", () => assert.equal(Tag.State, 0x42008D));
  it("DerivationMethod = 0x420031", () => assert.equal(Tag.DerivationMethod, 0x420031));
  it("DerivationParameters = 0x420032", () => assert.equal(Tag.DerivationParameters, 0x420032));
  it("DerivationData = 0x420030", () => assert.equal(Tag.DerivationData, 0x420030));
  it("LeaseTime = 0x420049", () => assert.equal(Tag.LeaseTime, 0x420049));
});
