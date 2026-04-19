"use strict";

/**
 * KMIP 1.4 tag, type, and enum constants.
 * Only the subset needed for Locate, Get, Create operations.
 *
 * Reference: OASIS KMIP Specification v1.4
 * https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html
 */

const Tag = {
  // Message structure
  RequestMessage:        0x420078,
  ResponseMessage:       0x42007B,
  RequestHeader:         0x420077,
  ResponseHeader:        0x42007A,
  ProtocolVersion:       0x420069,
  ProtocolVersionMajor:  0x42006A,
  ProtocolVersionMinor:  0x42006B,
  BatchCount:            0x42000D,
  BatchItem:             0x42000F,
  Operation:             0x42005C,
  RequestPayload:        0x420079,
  ResponsePayload:       0x42007C,
  ResultStatus:          0x42007F,
  ResultReason:          0x420080,
  ResultMessage:         0x420081,

  // Object identification
  UniqueIdentifier:      0x420094,
  ObjectType:            0x420057,

  // Naming
  Name:                  0x420053,
  NameValue:             0x420055,
  NameType:              0x420054,

  // Attributes (KMIP 1.x style)
  Attribute:             0x420008,
  AttributeName:         0x42000A,
  AttributeValue:        0x42000B,

  // Key structure
  SymmetricKey:          0x42008F,
  KeyBlock:              0x420040,
  KeyFormatType:         0x420042,
  KeyValue:              0x420045,
  KeyMaterial:           0x420043,

  // Crypto attributes
  CryptographicAlgorithm:  0x420028,
  CryptographicLength:     0x42002A,
  CryptographicUsageMask:  0x42002C,

  // Template
  TemplateAttribute:     0x420091,

  // Key pair
  PrivateKeyUniqueIdentifier: 0x420066,
  PublicKeyUniqueIdentifier:  0x42006F,
  PublicKey:                  0x42004E,
  PrivateKey:                 0x42004D,

  // Certificate
  Certificate:      0x420021,
  CertificateType:  0x42001D,
  CertificateValue: 0x42001E,

  // Crypto operations
  Data:              0x420033,
  IVCounterNonce:    0x420047,
  SignatureData:     0x42004F,
  MACData:           0x420051,
  ValidityIndicator: 0x420098,

  // Revocation
  RevocationReason:     0x420082,
  RevocationReasonCode: 0x420083,

  // Query
  QueryFunction: 0x420074,

  // State
  State: 0x42008D,

  // Derivation
  DerivationMethod:     0x420031,
  DerivationParameters: 0x420032,
  DerivationData:       0x420030,

  // Lease
  LeaseTime: 0x420049,
};

const Operation = {
  Create:           0x00000001,
  CreateKeyPair:    0x00000002,
  Register:         0x00000003,
  ReKey:            0x00000004,
  DeriveKey:        0x00000005,
  Locate:           0x00000008,
  Check:            0x00000009,
  Get:              0x0000000A,
  GetAttributes:    0x0000000B,
  GetAttributeList: 0x0000000C,
  AddAttribute:     0x0000000D,
  ModifyAttribute:  0x0000000E,
  DeleteAttribute:  0x0000000F,
  ObtainLease:      0x00000010,
  Activate:         0x00000012,
  Revoke:           0x00000013,
  Destroy:          0x00000014,
  Archive:          0x00000015,
  Recover:          0x00000016,
  Query:            0x00000018,
  Poll:             0x0000001A,
  DiscoverVersions: 0x0000001E,
  Encrypt:          0x0000001F,
  Decrypt:          0x00000020,
  Sign:             0x00000021,
  SignatureVerify:  0x00000022,
  MAC:              0x00000023,
};

const ObjectType = {
  Certificate:  0x00000001,
  SymmetricKey: 0x00000002,
  PublicKey:    0x00000003,
  PrivateKey:   0x00000004,
  SplitKey:     0x00000005,
  Template:     0x00000006,
  SecretData:   0x00000007,
  OpaqueData:   0x00000008,
};

const ResultStatus = {
  Success:          0x00000000,
  OperationFailed:  0x00000001,
  OperationPending: 0x00000002,
  OperationUndone:  0x00000003,
};

const KeyFormatType = {
  Raw:                 0x00000001,
  Opaque:              0x00000002,
  PKCS1:               0x00000003,
  PKCS8:               0x00000004,
  X509:                0x00000005,
  ECPrivateKey:        0x00000006,
  TransparentSymmetric: 0x00000007,
};

const Algorithm = {
  DES:        0x00000001,
  TripleDES:  0x00000002,
  AES:        0x00000003,
  RSA:        0x00000004,
  DSA:        0x00000005,
  ECDSA:      0x00000006,
  HMACSHA1:   0x00000007,
  HMACSHA256: 0x00000008,
  HMACSHA384: 0x00000009,
  HMACSHA512: 0x0000000A,
};

const NameType = {
  UninterpretedTextString: 0x00000001,
  URI:                     0x00000002,
};

// Cryptographic usage mask (bitmask)
const UsageMask = {
  Sign:       0x00000001,
  Verify:     0x00000002,
  Encrypt:    0x00000004,
  Decrypt:    0x00000008,
  WrapKey:    0x00000010,
  UnwrapKey:  0x00000020,
  Export:     0x00000040,
  DeriveKey:  0x00000100,
  KeyAgreement: 0x00000800,
};

module.exports = {
  Tag,
  Operation,
  ObjectType,
  ResultStatus,
  KeyFormatType,
  Algorithm,
  NameType,
  UsageMask,
};
