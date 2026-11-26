using System.Text;
using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.ValueObjects;
using RelayCryptoNode.Infrastructure.Certificates;
using RelayCryptoNode.Infrastructure.Packaging;
using Xunit;

namespace RelayCryptoNode.UnitTests;

public sealed class ZipPackageSerializerTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "rcn-unit", Guid.NewGuid().ToString("N"));
    private readonly ZipPackageSerializer _serializer = new();

    [Fact]
    public async Task Envelope_ShouldRoundTripThroughZipWithSameCanonicalBytes()
    {
        var certificates = new LocalCertificateService(_folder, "NODO06");
        var envelope = CreateEnvelope(certificates);

        var zip = await _serializer.SerializeEnvelopeAsync(envelope);
        var reader = new ZipPackageSerializer();
        var restored = await reader.DeserializeEnvelopeAsync(zip);

        Assert.Equal(envelope.PacketId, restored.PacketId);
        Assert.Equal(envelope.CipherAlgorithm, restored.CipherAlgorithm);
        Assert.Equal(envelope.CiphertextBytes, restored.CiphertextBytes);
        Assert.Equal(envelope.Parameters.EncryptedSessionKey, restored.Parameters.EncryptedSessionKey);
        Assert.Equal(envelope.OriginalPayloadSha256, restored.OriginalPayloadSha256);
        Assert.Equal(_serializer.GetCanonicalManifestBytes(envelope), reader.GetCanonicalManifestBytes(restored));
        Assert.True(certificates.VerifySignature(
            reader.GetCanonicalManifestBytes(restored),
            restored.ManifestSignature,
            restored.SenderCertificatePem,
            SignatureAlgorithmType.RsaPssSha256));
    }

    [Fact]
    public async Task NonZipBytes_ShouldBeMalformed()
    {
        var ex = await Assert.ThrowsAsync<DomainException>(() => _serializer.DeserializeEnvelopeAsync(Encoding.UTF8.GetBytes("no es zip")));
        Assert.Equal("PACKAGE_MALFORMED", ex.ErrorCode);
    }

    [Fact]
    public void FileName_ShouldFollowContractConvention()
    {
        var certificates = new LocalCertificateService(_folder, "NODO06");
        var envelope = CreateEnvelope(certificates);

        var name = _serializer.BuildStandardPackageFileName(envelope);

        Assert.Matches(@"^NODO06_AESGCM_\d{8}_\d{6}_[0-9a-f]{8}\.zip$", name);
    }

    [Fact]
    public void MultiItemBundle_ShouldRoundTripItemsAndDeclaredHashes()
    {
        var first = new byte[] { 1, 2, 3 };
        var second = Encoding.UTF8.GetBytes("segundo");
        var items = new List<PayloadItem>
        {
            new("a.bin", ".bin", "application/octet-stream", first.Length, first, Sha(first)),
            new("b.txt", ".txt", "text/plain", second.Length, second, Sha(second))
        };
        var bundle = new PayloadBundle(Guid.NewGuid(), PayloadKind.MultiPartBundle, items, Sha(first), DateTimeOffset.UtcNow);

        var bytes = _serializer.SerializePayloadBundle(bundle);
        var restored = _serializer.DeserializePayloadBundle(bytes, "lote_2_archivos.zip");

        Assert.Equal(2, restored.Items.Count);
        Assert.Equal(first, restored.Items[0].RawBytes);
        Assert.Equal(Sha(second), restored.Items[1].Sha256Hash);
    }

    [Fact]
    public void SingleItemBundle_ShouldTravelAsRawBytes()
    {
        var content = Encoding.UTF8.GetBytes("solo un archivo");
        var item = new PayloadItem("nota.txt", ".txt", "text/plain", content.Length, content, Sha(content));
        var bundle = new PayloadBundle(Guid.NewGuid(), PayloadKind.PlainText, [item], Sha(content), DateTimeOffset.UtcNow);

        Assert.Equal(content, _serializer.SerializePayloadBundle(bundle));
        Assert.Equal("nota.txt", _serializer.DeserializePayloadBundle(content, "nota.txt").Items.Single().FileName);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_folder, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private CryptoEnvelope CreateEnvelope(LocalCertificateService certificates)
    {
        var pem = certificates.GetLocalCertificatePem();
        var ciphertext = Encoding.UTF8.GetBytes("cifrado de prueba");
        CryptoEnvelope Build(byte[] signature) => new(
            Guid.NewGuid(),
            new NodeIdentity("NODO06", "http://192.168.1.6:5000", certificates.ComputeThumbprintSha256(pem)),
            new DateTimeOffset(2026, 11, 25, 20, 0, 0, TimeSpan.Zero),
            CipherAlgorithmType.Aes256Gcm,
            KeyExchangeAlgorithmType.RsaOaepSha256,
            SignatureAlgorithmType.RsaPssSha256,
            new CryptoParameters(new byte[12], new byte[16], [9, 9, 9], null, new Dictionary<string, string> { ["hopCount"] = "1" }),
            ciphertext,
            Sha(ciphertext),
            pem,
            signature,
            IntegrityDigest.Sha256(new string('c', 64)),
            "nota.txt",
            ".txt",
            10);

        var unsigned = Build([0]);
        return Build(certificates.SignData(_serializer.GetCanonicalManifestBytes(unsigned), SignatureAlgorithmType.RsaPssSha256));
    }

    private static IntegrityDigest Sha(byte[] data) =>
        IntegrityDigest.Sha256(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)));
}
