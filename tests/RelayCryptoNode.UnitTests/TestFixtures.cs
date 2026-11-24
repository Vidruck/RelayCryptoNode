using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.UnitTests;

internal static class TestFixtures
{
    public static readonly string ValidSha256A = new('a', 64);
    public static readonly string ValidSha256B = new('b', 64);
    public static readonly string ValidSha256Upper = new('A', 64);

    public static NodeIdentity CreateNodeIdentity(string nodeId = "NODO01") =>
        new(nodeId, "http://192.168.1.10:5000", ValidSha256A);

    public static CryptoParameters CreateCryptoParameters() =>
        new(
            ivOrNonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            authTag: [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160],
            encryptedSessionKey: [42, 43, 44, 45]);

    public static CryptoEnvelope CreateEnvelope(
        Guid? packetId = null,
        CipherAlgorithmType cipher = CipherAlgorithmType.Aes256Gcm) =>
        new(
            packetId: packetId ?? Guid.NewGuid(),
            sourceNode: CreateNodeIdentity(),
            timestampUtc: DateTimeOffset.UtcNow,
            cipherAlgorithm: cipher,
            keyExchangeAlgorithm: KeyExchangeAlgorithmType.RsaOaepSha256,
            signatureAlgorithm: SignatureAlgorithmType.RsaPssSha256,
            parameters: CreateCryptoParameters(),
            ciphertextBytes: [0x10, 0x20, 0x30, 0x40],
            encryptedSha256: IntegrityDigest.Sha256(ValidSha256B),
            senderCertificatePem: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE-----",
            manifestSignature: [0xAA, 0xBB, 0xCC, 0xDD],
            originalPayloadSha256: IntegrityDigest.Sha256(ValidSha256A),
            originalFileName: "evidencia.pdf",
            originalExtension: ".pdf",
            originalSizeBytes: 1024);

    public static PayloadItem CreatePayloadItem(string fileName = "mensaje.txt", byte[]? bytes = null)
    {
        var content = bytes ?? [1, 2, 3, 4, 5];
        return new PayloadItem(
            fileName: fileName,
            extension: Path.GetExtension(fileName),
            mimeType: "application/octet-stream",
            sizeBytes: content.LongLength,
            rawBytes: content,
            sha256Hash: IntegrityDigest.Sha256(ValidSha256A));
    }
}
