using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using RelayCryptoNode.Infrastructure.Certificates;
using RelayCryptoNode.Infrastructure.ProtocolV2;
using RelayCryptoNode.Infrastructure.ProtocolV2.Providers;
using Xunit;

namespace RelayCryptoNode.UnitTests;

/// <summary>
/// Pruebas del Estándar de Comunicación v2.0: formato, paquete firmado, sobre CC-ENV-1 y algoritmos del EQ06.
/// </summary>
public sealed class ProtocolV2Tests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "rcn-v2", Guid.NewGuid().ToString("N"));

    [Fact]
    public void Format_ShouldFollowNamingRules()
    {
        Assert.Equal("EQ06", V2Format.NodeIdFor(6));
        Assert.Equal(5006, V2Format.HttpPortFor(6));
        var canonical = V2Format.CanonicalParameters(new Dictionary<string, string> { ["b"] = "2", ["a"] = "1" });
        Assert.Equal("a=1\nb=2", canonical);
        Assert.Equal(21, V2Catalog.All.Count);
        Assert.Equal("EQ06", V2Catalog.ByCode("EUCLIDESAFFINE")!.OwnerNode);
    }

    [Fact]
    public void Package_ShouldBuildAndValidate()
    {
        var identity = Identity(6);
        var package = BuildAffine(identity);

        var validated = V2PackageCodec.Validate(package.ZipBytes);

        Assert.Equal("EQ06", validated.SourceNode);
        Assert.Equal("EUCLIDESAFFINE", validated.AlgorithmCode);
        Assert.Equal(identity.Thumbprint, V2PackageCodec.ValidateCertificate(validated.CertificatePem, "EQ06"));
    }

    [Fact]
    public void Package_ShouldRejectTamperedData()
    {
        var package = BuildAffine(Identity(6));
        var entries = Entries(package.ZipBytes);
        entries["datos.enc"][0] ^= 0xFF;

        var error = Assert.Throws<V2ProtocolException>(() => V2PackageCodec.Validate(V2PackageCodec.WriteZip(entries)));
        Assert.Equal("E-HASH", error.Code);
    }

    [Fact]
    public void Package_ShouldRejectTamperedSignature()
    {
        var package = BuildAffine(Identity(6));
        var entries = Entries(package.ZipBytes);
        var manifest = JsonNode.Parse(entries["manifest.json"])!.AsObject();
        manifest["operation"] = "inverse";
        entries["manifest.json"] = Encoding.UTF8.GetBytes(manifest.ToJsonString());

        var error = Assert.Throws<V2ProtocolException>(() => V2PackageCodec.Validate(V2PackageCodec.WriteZip(entries)));
        Assert.Equal("E-SIGNATURE", error.Code);
    }

    [Fact]
    public void Package_ShouldRejectExtraFiles()
    {
        var package = BuildAffine(Identity(6));
        var entries = Entries(package.ZipBytes);
        entries["extra.txt"] = [1, 2, 3];

        var error = Assert.Throws<V2ProtocolException>(() => V2PackageCodec.Validate(V2PackageCodec.WriteZip(entries)));
        Assert.Equal("E-ZIP-STRUCTURE", error.Code);
    }

    [Fact]
    public void Package_ShouldRouteByVersion()
    {
        var package = BuildAffine(Identity(6));
        Assert.True(V2PackageCodec.LooksLikeV2(package.ZipBytes));

        var entries = Entries(package.ZipBytes);
        var manifest = JsonNode.Parse(entries["manifest.json"])!.AsObject();
        manifest.Remove("version");
        entries["manifest.json"] = Encoding.UTF8.GetBytes(manifest.ToJsonString());
        Assert.False(V2PackageCodec.LooksLikeV2(V2PackageCodec.WriteZip(entries)));
    }

    [Fact]
    public void Rewrap_ShouldKeepContentWithNewSignature()
    {
        var original = BuildAffine(Identity(6));
        var forwarder = Identity(7);

        var rewrapped = V2PackageCodec.Rewrap(original, forwarder);
        var validated = V2PackageCodec.Validate(rewrapped.ZipBytes);

        Assert.Equal("EQ07", validated.SourceNode);
        Assert.Equal("EQ06", validated.ProducerNode);
        Assert.False(validated.PacketId == original.PacketId);
        Assert.Equal(Convert.ToHexString(original.Data), Convert.ToHexString(validated.Data));
    }

    [Fact]
    public void Envelope_ShouldOpenOnlyForRecipient()
    {
        var recipient = Identity(7);
        var other = Identity(8);
        var secret = Encoding.UTF8.GetBytes("{\"a\":\"5\",\"b\":\"8\"}");

        var (envelope, ciphertext) = CcEnvelope.Seal(secret, recipient.NodeId, recipient.CertificatePem, "req-1");
        var opened = CcEnvelope.Open(envelope, ciphertext, recipient.NodeId, recipient.Thumbprint, recipient.PrivateKeyPem, "req-1");
        Assert.Equal(Encoding.UTF8.GetString(secret), Encoding.UTF8.GetString(opened));

        var wrongNode = Assert.Throws<V2ProtocolException>(() =>
            CcEnvelope.Open(envelope, ciphertext, other.NodeId, other.Thumbprint, other.PrivateKeyPem, "req-1"));
        Assert.Equal("E-ENV-RECIPIENT", wrongNode.Code);

        var wrongAad = Assert.Throws<V2ProtocolException>(() =>
            CcEnvelope.Open(envelope, ciphertext, recipient.NodeId, recipient.Thumbprint, recipient.PrivateKeyPem, "req-2"));
        Assert.Equal("E-ENV-DECRYPT", wrongAad.Code);
    }

    [Fact]
    public void Affine_ShouldRoundTripBothModuli()
    {
        var provider = new AffineV2Provider();
        var text = Encoding.UTF8.GetBytes("Hola Mundo, prueba 2026!");

        foreach (var modulus in new[] { "256", "26" })
        {
            var options = new Dictionary<string, string> { ["modulus"] = modulus };
            var secrets = new Dictionary<string, string> { ["a"] = "5", ["b"] = "8" };
            var output = provider.Forward(new V2ForwardInput(text, null, "text", "m.txt", options, secrets));
            Assert.False(output.Data.AsSpan().SequenceEqual(text));

            var back = provider.Inverse(output.Data, output.PublicParameters, secrets);
            Assert.Equal(Encoding.UTF8.GetString(text), Encoding.UTF8.GetString(back.Original));
        }
    }

    [Fact]
    public void Affine_ShouldRejectNonInvertibleKey()
    {
        var provider = new AffineV2Provider();
        var secrets = new Dictionary<string, string> { ["a"] = "8", ["b"] = "1" };
        var error = Assert.Throws<V2ProtocolException>(() =>
            provider.Forward(new V2ForwardInput([1, 2, 3], null, "text", "m.txt", new Dictionary<string, string>(), secrets)));
        Assert.Equal("E-PARAMS", error.Code);
        Assert.Equal(205L, AffineV2Provider.ModInverse(5, 256));
    }

    [Fact]
    public void Lsb_ShouldHideAndRecoverWithPassword()
    {
        var provider = new LsbV2Provider();
        var message = Encoding.UTF8.GetBytes("Mensaje oculto del EQ06");
        var cover = LsbV2Provider.DefaultCoverFor(message.Length + 64);
        var secrets = new Dictionary<string, string> { ["password"] = "virologia" };

        var output = provider.Forward(new V2ForwardInput(message, cover, "text", "m.txt", new Dictionary<string, string>(), secrets));
        Assert.Equal("true", output.PublicParameters["passwordProtected"]);

        var back = provider.Inverse(output.Data, output.PublicParameters, secrets);
        Assert.Equal(Encoding.UTF8.GetString(message), Encoding.UTF8.GetString(back.Original));
    }

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    private V2Identity Identity(int team)
    {
        var certificates = new LocalCertificateService(Path.Combine(_folder, $"eq{team}"), V2Format.NodeIdFor(team), "prueba");
        return new V2Identity(team, certificates);
    }

    private static V2Package BuildAffine(V2Identity identity)
    {
        var provider = new AffineV2Provider();
        var payload = Encoding.UTF8.GetBytes("Prueba v2.0");
        var output = provider.Forward(new V2ForwardInput(
            payload, null, "text", "mensaje.txt",
            new Dictionary<string, string> { ["modulus"] = "256" },
            new Dictionary<string, string> { ["a"] = "5", ["b"] = "8" }));

        return V2PackageCodec.Build(new V2PackageSpec
        {
            Algorithm = V2Catalog.ByCode("EUCLIDESAFFINE")!,
            Operation = "forward",
            PayloadMode = "text",
            OriginalFileName = "mensaje.txt",
            OriginalSizeBytes = payload.Length,
            ContentType = "text/plain",
            Data = output.Data,
            PublicParameters = output.PublicParameters
        }, identity);
    }

    private static Dictionary<string, byte[]> Entries(byte[] zipBytes)
    {
        using var zip = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);
        return zip.Entries.ToDictionary(e => e.FullName, e =>
        {
            using var stream = e.Open();
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            return buffer.ToArray();
        });
    }
}
