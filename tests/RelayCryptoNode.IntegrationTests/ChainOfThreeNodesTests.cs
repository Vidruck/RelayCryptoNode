using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using RelayCryptoNode.Application.Abstractions;
using RelayCryptoNode.Application.Services;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Ports.Inbound;
using Xunit;

namespace RelayCryptoNode.IntegrationTests;

/// <summary>
/// Cadena completa Initial → Intermediate → Final con los servicios reales en memoria.
/// </summary>
public sealed class ChainOfThreeNodesTests
{
    [Theory]
    [InlineData("AESGCM", "LORENZSZ40", KeyExchangeAlgorithmType.RsaOaepSha256)]
    [InlineData("CAESAR", "CHACHA20", KeyExchangeAlgorithmType.RsaOaepSha256)]
    [InlineData("LSBSTEGO", "LAGRANGESHAMIR", KeyExchangeAlgorithmType.PreSharedKey)]
    [InlineData("MILLERRABIN", "DFTSPECTRAL", KeyExchangeAlgorithmType.PreSharedKey)]
    public async Task InitialIntermediateFinal_ShouldDeliverBitExactFiles(string initialAlgorithm, string relayAlgorithm, KeyExchangeAlgorithmType keyExchange)
    {
        var network = new InMemoryNetwork();
        using var final = new NodeHarness("NODO06", NodeRole.Final, network);
        using var middle = new NodeHarness("NODO02", NodeRole.Intermediate, network, final.Endpoint, relayAlgorithm);
        using var initial = new NodeHarness("NODO01", NodeRole.Initial, network, middle.Endpoint);
        middle.State.Update(middle.State.Current with { KeyExchange = keyExchange });

        var image = RandomNumberGenerator.GetBytes(64 * 1024);
        var note = Encoding.UTF8.GetBytes("Evidencia de la práctica: cadena de 3 nodos ñ");
        var bundle = initial.Bundles.Create([
            new PayloadFileInput("foto.png", "image/png", image),
            new PayloadFileInput("nota.txt", "text/plain", note)
        ]);

        var emitted = await initial.Emit.ExecuteAsync(new EmitInitialPackageCommand(
            bundle,
            initial.IdentityFor(middle),
            EnvelopeCryptoService.ResolveCipherFromCode(initialAlgorithm),
            keyExchange,
            SignatureAlgorithmType.RsaPssSha256));
        Assert.True(emitted.Delivered, emitted.RemoteStatusMessage);

        var atMiddle = Assert.Single(await middle.Inbox.GetRequestsAsync(RequestStatus.Pending));
        Assert.True(atMiddle.SignatureValid);
        var relay = await middle.Processing.AcceptAndProcessAsync(atMiddle.RequestId);
        Assert.True(relay.Success, relay.Message);
        Assert.Equal(RequestStatus.Relayed, (await middle.Inbox.GetRequiredAsync(atMiddle.RequestId)).Status);

        var atFinal = Assert.Single(await final.Inbox.GetRequestsAsync(RequestStatus.Pending));
        Assert.Equal(EnvelopeCryptoService.ResolveCipherFromCode(relayAlgorithm), atFinal.Envelope.CipherAlgorithm);
        var audit = await final.Processing.AcceptAndProcessAsync(atFinal.RequestId);

        Assert.True(audit.Success, audit.Message);
        Assert.NotNull(audit.Audit);
        Assert.True(audit.Audit!.AuditReport.IsBitExactMatch);
        Assert.Equal(0, audit.Audit.AuditReport.ByteLossCount);
        Assert.Equal(bundle.BundleSha256Hash, audit.Audit.AuditReport.ComputedSha256);
        Assert.Equal(image, audit.Audit.RecoveredBundle.Items.Single(i => i.FileName == "foto.png").RawBytes);
        Assert.Equal(note, audit.Audit.RecoveredBundle.Items.Single(i => i.FileName == "nota.txt").RawBytes);
    }

    [Fact]
    public async Task TamperedCiphertext_ShouldBeRefusedWith422()
    {
        var network = new InMemoryNetwork();
        using var final = new NodeHarness("NODO06", NodeRole.Final, network);
        using var initial = new NodeHarness("NODO01", NodeRole.Initial, network, final.Endpoint);
        var bundle = initial.Bundles.FromText("hola");
        var envelope = initial.Crypto.Seal(
            initial.Serializer.SerializePayloadBundle(bundle),
            PayloadBundleFactory.DescribeOriginal(bundle, 4),
            CipherAlgorithmType.Aes256Gcm,
            KeyExchangeAlgorithmType.RsaOaepSha256,
            SignatureAlgorithmType.RsaPssSha256,
            final.Certificates.GetLocalCertificatePem());
        var zip = await initial.Serializer.SerializeEnvelopeAsync(envelope);

        var tampered = Rewrite(zip, "datos.enc", data => { data[0] ^= 0xFF; return data; });
        var result = await final.Reception.ReceiveAsync(tampered);

        Assert.Equal(ReceptionOutcome.Unprocessable, result.Outcome);
    }

    [Fact]
    public async Task PackageFromNodo04Format_ShouldBeAcceptedAndDecryptedWithSharedAesKey()
    {
        var network = new InMemoryNetwork();
        using var final = new NodeHarness("NODO06", NodeRole.Final, network);

        // Se arma un paquete igual al que produce el NODO04: manifiesto plano, AES-GCM nonce|tag|cifrado
        // con clave SHA-256("clave-aes-256-segura") y firma sobre "sha|HUELLA|timestamp".
        var plaintext = Encoding.UTF8.GetBytes("Mensaje del NODO-04");
        var key = SHA256.HashData(Encoding.UTF8.GetBytes("clave-aes-256-segura"));
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[plaintext.Length];
        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(nonce, plaintext, cipher, tag);
        }

        byte[] data = [.. nonce, .. tag, .. cipher];
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=NODO-04, O=CentroCiberseguridad", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        var thumb = Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256));
        var sha = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        var timestamp = DateTime.UtcNow.ToString("O");
        var signature = rsa.SignData(Encoding.UTF8.GetBytes($"{sha}|{thumb}|{timestamp}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var manifest = new JsonObject
        {
            ["version"] = "1.0",
            ["packetId"] = Guid.NewGuid().ToString(),
            ["sourceNode"] = "NODO-04",
            ["sourceIp"] = "192.168.1.4",
            ["timestampUtc"] = timestamp,
            ["algorithm"] = "AES-256-GCM",
            ["algorithmCode"] = "AESGCM",
            ["payloadMode"] = "file",
            ["originalFileName"] = "secreto.txt",
            ["originalExtension"] = ".txt",
            ["originalSizeBytes"] = plaintext.Length,
            ["encryptedSha256"] = sha,
            ["publicParameters"] = new JsonObject(),
            ["certificateThumbprintSha256"] = thumb,
            ["signatureAlgorithm"] = "RSA-PSS-SHA256",
            ["manifestSignatureBase64"] = Convert.ToBase64String(signature)
        };

        var zip = BuildZip(new()
        {
            ["datos.enc"] = data,
            ["certificado.pem"] = Encoding.UTF8.GetBytes(cert.ExportCertificatePem()),
            ["manifest.json"] = Encoding.UTF8.GetBytes(manifest.ToJsonString())
        });

        var received = await final.Reception.ReceiveAsync(zip);
        Assert.Equal(ReceptionOutcome.Registered, received.Outcome);
        Assert.True(received.Request!.SignatureValid);

        var processed = await final.Processing.AcceptAndProcessAsync(received.Request.RequestId);
        Assert.Equal(plaintext, processed.Audit!.RecoveredBundle.Items.Single().RawBytes);
    }

    [Fact]
    public async Task SharedKeyMode_ShouldProduceDatosEncReadableByNodo04Layout()
    {
        var network = new InMemoryNetwork();
        using var final = new NodeHarness("NODO06", NodeRole.Final, network);
        using var initial = new NodeHarness("NODO01", NodeRole.Initial, network, final.Endpoint);
        var bundle = initial.Bundles.FromText("hola nodo 4");

        var result = await initial.Emit.ExecuteAsync(new EmitInitialPackageCommand(
            bundle,
            initial.IdentityFor(final),
            CipherAlgorithmType.Aes256Gcm,
            KeyExchangeAlgorithmType.PreSharedKey,
            SignatureAlgorithmType.RsaPssSha256,
            ExtraMetadata: new Dictionary<string, string> { [LegacyFormat.MetadataKey] = LegacyFormat.SharedKeyValue }));
        Assert.True(result.Delivered, result.RemoteStatusMessage);

        var data = result.Envelope.CiphertextBytes;
        var key = SHA256.HashData(Encoding.UTF8.GetBytes("clave-aes-256-segura"));
        var plaintext = new byte[data.Length - 28];
        using (var aes = new AesGcm(key, 16))
        {
            aes.Decrypt(data.AsSpan(0, 12), data.AsSpan(28), data.AsSpan(12, 16), plaintext);
        }

        Assert.Equal("hola nodo 4", Encoding.UTF8.GetString(plaintext));
    }

    private static byte[] Rewrite(byte[] zip, string entryName, Func<byte[], byte[]> change)
    {
        var entries = new Dictionary<string, byte[]>();
        using (var archive = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read))
        {
            foreach (var entry in archive.Entries)
            {
                using var stream = entry.Open();
                using var buffer = new MemoryStream();
                stream.CopyTo(buffer);
                entries[entry.FullName] = entry.FullName == entryName ? change(buffer.ToArray()) : buffer.ToArray();
            }
        }

        return BuildZip(entries);
    }

    private static byte[] BuildZip(Dictionary<string, byte[]> entries)
    {
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var pair in entries)
            {
                using var stream = archive.CreateEntry(pair.Key).Open();
                stream.Write(pair.Value);
            }
        }

        return buffer.ToArray();
    }
}
