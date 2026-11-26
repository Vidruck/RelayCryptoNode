using System.Globalization;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RelayCryptoNode.Domain.Catalog;
using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Infrastructure.Packaging;

/// <summary>
/// Arma y lee el paquete <c>.zip</c> de 3 archivos (<c>datos.enc</c>, <c>certificado.pem</c>, <c>manifest.json</c>).
/// <para>
/// Escribe el manifiesto "plano" que usa el grupo (el mismo del NODO04) y guarda los datos propios de
/// RelayCryptoNode (nonce, etiqueta, clave envuelta, huella original) en <c>publicParameters</c>.
/// Lee tanto ese formato como el anidado descrito en <c>contrato-intercambio-zip-http.md</c>.
/// </para>
/// <para>
/// La firma <c>manifestSignatureBase64</c> es RSA-PSS-SHA256 sobre el texto UTF-8
/// <c>encryptedSha256|HUELLA_CERTIFICADO_SHA256_MAYUSCULAS|timestampUtc</c>.
/// </para>
/// </summary>
public sealed class ZipPackageSerializer : IPackageSerializerPort
{
    /// <summary>Nombre del archivo cifrado dentro del .zip.</summary>
    public const string DataEntry = "datos.enc";

    /// <summary>Nombre del certificado dentro del .zip.</summary>
    public const string CertificateEntry = "certificado.pem";

    /// <summary>Nombre del manifiesto dentro del .zip.</summary>
    public const string ManifestEntry = "manifest.json";

    private const string BundleMarkerEntry = "__relaycryptonode_bundle.json";
    private const string ParamPrefix = "rcn.";

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    // Bytes firmados tal como venían en el manifiesto original (las fechas de otros equipos no siempre
    // se pueden reconstruir igual desde DateTimeOffset).
    private readonly ConditionalWeakTable<CryptoEnvelope, byte[]> _signedBytes = new();
    private readonly ConditionalWeakTable<CryptoEnvelope, string> _rawTimestamps = new();

    /// <inheritdoc />
    public Task<byte[]> SerializeEnvelopeAsync(CryptoEnvelope envelope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var manifest = BuildManifest(envelope);
        manifest["manifestSignatureBase64"] = Convert.ToBase64String(envelope.ManifestSignature);

        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(zip, DataEntry, envelope.CiphertextBytes);
            WriteEntry(zip, CertificateEntry, Encoding.UTF8.GetBytes(envelope.SenderCertificatePem));
            WriteEntry(zip, ManifestEntry, Encoding.UTF8.GetBytes(manifest.ToJsonString(Indented)));
        }

        return Task.FromResult(buffer.ToArray());
    }

    /// <inheritdoc />
    public Task<CryptoEnvelope> DeserializeEnvelopeAsync(byte[] packageBytes, CancellationToken cancellationToken = default)
    {
        if (packageBytes is null || packageBytes.Length == 0)
        {
            throw Malformed("El paquete está vacío.");
        }

        byte[] data;
        string certificatePem;
        string manifestText;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(packageBytes, writable: false), ZipArchiveMode.Read);
            var dataEntry = FindEntry(zip, DataEntry);
            var certEntry = FindEntry(zip, CertificateEntry);
            var manifestEntry = FindEntry(zip, ManifestEntry);
            if (dataEntry is null || certEntry is null || manifestEntry is null)
            {
                throw Malformed("El ZIP debe contener datos.enc, certificado.pem y manifest.json en su raíz.");
            }

            data = ReadEntry(dataEntry);
            certificatePem = Encoding.UTF8.GetString(ReadEntry(certEntry)).Trim();
            manifestText = Encoding.UTF8.GetString(ReadEntry(manifestEntry)).TrimStart('﻿');
        }
        catch (InvalidDataException)
        {
            throw Malformed("El archivo enviado no es un ZIP válido.");
        }

        if (data.Length == 0)
        {
            throw Malformed("datos.enc está vacío.");
        }

        JsonObject manifest;
        try
        {
            manifest = JsonNode.Parse(manifestText) as JsonObject ?? throw Malformed("manifest.json no es un objeto JSON.");
        }
        catch (JsonException)
        {
            throw Malformed("Error de formato JSON en manifest.json.");
        }

        var envelope = manifest["sourceNode"] is JsonObject || manifest["cryptoParameters"] is JsonObject
            ? ReadNestedManifest(manifest, data, certificatePem)
            : ReadFlatManifest(manifest, data, certificatePem);

        return Task.FromResult(envelope);
    }

    /// <inheritdoc />
    public byte[] GetCanonicalManifestBytes(CryptoEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (_signedBytes.TryGetValue(envelope, out var stored))
        {
            return stored.ToArray();
        }

        var text = string.Join(
            '|',
            envelope.EncryptedSha256.HexHash,
            UpperThumbprint(envelope.SenderCertificatePem),
            TimestampText(envelope));
        return Encoding.UTF8.GetBytes(text);
    }

    /// <inheritdoc />
    public byte[] SerializePayloadBundle(PayloadBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        if (bundle.Items.Count == 1)
        {
            return bundle.Items[0].RawBytes;
        }

        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            var index = new JsonArray();
            foreach (var item in bundle.Items)
            {
                WriteEntry(zip, item.FileName, item.RawBytes);
                index.Add(new JsonObject
                {
                    ["fileName"] = item.FileName,
                    ["mimeType"] = item.MimeType,
                    ["sizeBytes"] = item.SizeBytes,
                    ["sha256"] = item.Sha256Hash.HexHash
                });
            }

            var marker = new JsonObject
            {
                ["bundleId"] = bundle.BundleId.ToString(),
                ["kind"] = bundle.Kind.ToString(),
                ["items"] = index
            };
            WriteEntry(zip, BundleMarkerEntry, Encoding.UTF8.GetBytes(marker.ToJsonString(Indented)));
        }

        return buffer.ToArray();
    }

    /// <inheritdoc />
    public PayloadBundle DeserializePayloadBundle(byte[] plaintextBytes, string originalFileName)
    {
        ArgumentNullException.ThrowIfNull(plaintextBytes);
        var bundleHash = Sha256(plaintextBytes);
        var multi = TryReadMultiItemBundle(plaintextBytes, bundleHash);
        if (multi is not null)
        {
            return multi;
        }

        var name = string.IsNullOrWhiteSpace(originalFileName) ? "archivo.bin" : Path.GetFileName(originalFileName.Trim());
        var extension = Path.GetExtension(name);
        var item = new PayloadItem(
            name,
            extension,
            GuessMime(extension),
            plaintextBytes.LongLength,
            plaintextBytes,
            bundleHash);
        return new PayloadBundle(Guid.NewGuid(), GuessKind(extension), [item], bundleHash, DateTimeOffset.UtcNow);
    }

    /// <inheritdoc />
    public string BuildStandardPackageFileName(CryptoEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var node = new string(envelope.SourceNode.NodeId.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        var code = OfficialAlgorithmCatalog.TryFromCipherAlgorithm(envelope.CipherAlgorithm, out var official)
            ? official.ToString()
            : envelope.CipherAlgorithm.ToString().ToUpperInvariant();
        var stamp = envelope.TimestampUtc.UtcDateTime.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        return $"{(node.Length == 0 ? "NODO" : node)}_{code}_{stamp}_{envelope.EncryptedSha256.ShortHex()}.zip";
    }

    private JsonObject BuildManifest(CryptoEnvelope envelope)
    {
        var descriptor = OfficialAlgorithmCatalog.TryFromCipherAlgorithm(envelope.CipherAlgorithm, out var code)
            ? OfficialAlgorithmCatalog.GetByCode(code)
            : null;

        var publicParameters = new JsonObject
        {
            [ParamPrefix + "protocol"] = "RelayCryptoNode/1.0",
            [ParamPrefix + "endpointAddress"] = envelope.SourceNode.EndpointAddress,
            [ParamPrefix + "keyExchangeAlgorithm"] = envelope.KeyExchangeAlgorithm.ToString(),
            [ParamPrefix + "originalSha256"] = envelope.OriginalPayloadSha256.HexHash,
            [ParamPrefix + "ivOrNonceBase64"] = Convert.ToBase64String(envelope.Parameters.IvOrNonce)
        };
        AddOptional(publicParameters, ParamPrefix + "authTagBase64", envelope.Parameters.AuthTag);
        AddOptional(publicParameters, ParamPrefix + "encryptedSessionKeyBase64", envelope.Parameters.EncryptedSessionKey);
        AddOptional(publicParameters, ParamPrefix + "saltBase64", envelope.Parameters.Salt);
        foreach (var pair in envelope.Parameters.ExtraMetadata.OrderBy(static p => p.Key, StringComparer.Ordinal))
        {
            publicParameters[pair.Key] = pair.Value;
        }

        return new JsonObject
        {
            ["version"] = "1.0",
            ["protocolVersion"] = "1.0",
            ["packetId"] = envelope.PacketId.ToString(),
            ["sourceNode"] = envelope.SourceNode.NodeId,
            ["sourceIp"] = HostOf(envelope.SourceNode.EndpointAddress),
            ["timestampUtc"] = TimestampText(envelope),
            ["algorithm"] = descriptor?.DisplayName ?? envelope.CipherAlgorithm.ToString(),
            ["algorithmCode"] = descriptor?.OfficialCode ?? envelope.CipherAlgorithm.ToString().ToUpperInvariant(),
            ["payloadMode"] = "file",
            ["originalFileName"] = envelope.OriginalFileName,
            ["originalExtension"] = envelope.OriginalExtension,
            ["originalSizeBytes"] = envelope.OriginalSizeBytes,
            ["encryptedSha256"] = envelope.EncryptedSha256.HexHash,
            ["publicParameters"] = publicParameters,
            ["certificateThumbprintSha256"] = UpperThumbprint(envelope.SenderCertificatePem),
            ["keyExchangeAlgorithm"] = envelope.KeyExchangeAlgorithm.ToString(),
            ["signatureAlgorithm"] = SignatureName(envelope.SignatureAlgorithm)
        };
    }

    private CryptoEnvelope ReadFlatManifest(JsonObject manifest, byte[] data, string certificatePem)
    {
        var cipher = ResolveCipher(Str(manifest, "algorithmCode"), Str(manifest, "algorithm"));
        var encryptedSha = Required(manifest, "encryptedSha256");
        var signatureText = Required(manifest, "manifestSignatureBase64");
        var timestampText = Str(manifest, "timestampUtc") ?? string.Empty;
        var parameters = manifest["publicParameters"] as JsonObject ?? new JsonObject();

        var extra = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in parameters)
        {
            if (!pair.Key.StartsWith(ParamPrefix, StringComparison.Ordinal) && pair.Value is JsonValue value)
            {
                extra[pair.Key] = value.ToString();
            }
        }

        var wrappedKey = Base64(parameters, ParamPrefix + "encryptedSessionKeyBase64");
        if (wrappedKey is null)
        {
            extra["keyMode"] = "SHARED-KEY";
        }

        var iv = Base64(parameters, ParamPrefix + "ivOrNonceBase64")
                 ?? HexOrNull(Str(parameters, "nonceHex"))
                 ?? (data.Length >= 12 ? data[..12] : [0]);

        var keyExchange = ParseKeyExchange(Str(parameters, ParamPrefix + "keyExchangeAlgorithm") ?? Str(manifest, "keyExchangeAlgorithm"), wrappedKey is null);
        var sourceNodeId = NormalizeNodeId(Str(manifest, "sourceNode"));
        var endpoint = Str(parameters, ParamPrefix + "endpointAddress")
                       ?? (Str(manifest, "sourceIp") is { Length: > 0 } ip ? $"http://{ip}:5000" : "http://desconocido");

        var originalName = Str(manifest, "originalFileName") ?? "archivo.bin";
        var originalSha = Str(parameters, ParamPrefix + "originalSha256");
        if (originalSha is null)
        {
            extra["originalSha256Unknown"] = "true";
        }

        var envelope = Create(
            ParseGuid(Str(manifest, "packetId")),
            new NodeIdentity(sourceNodeId, endpoint, LowerThumbprint(certificatePem)),
            ParseTimestamp(timestampText),
            cipher,
            keyExchange,
            ParseSignature(Str(manifest, "signatureAlgorithm")),
            new CryptoParameters(
                iv,
                Base64(parameters, ParamPrefix + "authTagBase64"),
                wrappedKey,
                Base64(parameters, ParamPrefix + "saltBase64"),
                extra),
            data,
            encryptedSha,
            certificatePem,
            DecodeSignature(signatureText),
            originalSha ?? new string('0', 64),
            originalName,
            Str(manifest, "originalExtension") ?? Path.GetExtension(originalName),
            Long(manifest, "originalSizeBytes"));

        _signedBytes.AddOrUpdate(envelope, Encoding.UTF8.GetBytes($"{encryptedSha}|{UpperThumbprint(certificatePem)}|{timestampText}"));
        _rawTimestamps.AddOrUpdate(envelope, timestampText);
        return envelope;
    }

    private CryptoEnvelope ReadNestedManifest(JsonObject manifest, byte[] data, string certificatePem)
    {
        var cipher = ResolveCipher(Str(manifest, "algorithmCode"), Str(manifest, "algorithm"));
        var source = manifest["sourceNode"] as JsonObject ?? new JsonObject();
        var crypto = manifest["cryptoParameters"] as JsonObject ?? new JsonObject();
        var original = manifest["originalPayload"] as JsonObject ?? new JsonObject();
        var signatureText = Required(manifest, "manifestSignatureBase64");

        var extra = new Dictionary<string, string>(StringComparer.Ordinal);
        if (crypto["extraMetadata"] is JsonObject metadata)
        {
            foreach (var pair in metadata)
            {
                if (pair.Value is JsonValue value)
                {
                    extra[pair.Key] = value.ToString();
                }
            }
        }

        var thumbprint = Str(source, "certificateThumbprintSha256") ?? LowerThumbprint(certificatePem);
        var originalName = Str(original, "fileName") ?? "archivo.bin";
        var envelope = Create(
            ParseGuid(Str(manifest, "packetId")),
            new NodeIdentity(NormalizeNodeId(Str(source, "nodeId")), Str(source, "endpointAddress") ?? "http://desconocido", thumbprint),
            ParseTimestamp(Str(manifest, "timestampUtc") ?? string.Empty),
            cipher,
            ParseKeyExchange(Str(manifest, "keyExchangeAlgorithm"), false),
            ParseSignature(Str(manifest, "signatureAlgorithm")),
            new CryptoParameters(
                Base64(crypto, "ivOrNonceBase64") ?? [0],
                Base64(crypto, "authTagBase64"),
                Base64(crypto, "encryptedSessionKeyBase64"),
                Base64(crypto, "saltBase64"),
                extra),
            data,
            Required(manifest, "encryptedSha256"),
            certificatePem,
            DecodeSignature(signatureText),
            Str(original, "sha256") ?? new string('0', 64),
            originalName,
            Str(original, "extension") ?? Path.GetExtension(originalName),
            Long(original, "sizeBytes"));

        // Contrato anidado: se firma el manifiesto compacto sin el campo de firma.
        var unsigned = (JsonObject)manifest.DeepClone();
        unsigned.Remove("manifestSignatureBase64");
        _signedBytes.AddOrUpdate(envelope, Encoding.UTF8.GetBytes(unsigned.ToJsonString()));
        return envelope;
    }

    private static CryptoEnvelope Create(
        Guid packetId,
        NodeIdentity source,
        DateTimeOffset timestamp,
        CipherAlgorithmType cipher,
        KeyExchangeAlgorithmType keyExchange,
        SignatureAlgorithmType signature,
        CryptoParameters parameters,
        byte[] data,
        string encryptedSha,
        string certificatePem,
        byte[] signatureBytes,
        string originalSha,
        string originalName,
        string originalExtension,
        long originalSize)
    {
        try
        {
            return new CryptoEnvelope(
                packetId,
                source,
                timestamp,
                cipher,
                keyExchange,
                signature,
                parameters,
                data,
                IntegrityDigest.Sha256(encryptedSha),
                certificatePem,
                signatureBytes,
                IntegrityDigest.Sha256(originalSha),
                originalName,
                originalExtension,
                Math.Max(0, originalSize));
        }
        catch (DomainException ex) when (ex is not UnsupportedAlgorithmException)
        {
            throw Malformed("manifest.json inválido o incompleto: " + ex.Message);
        }
    }

    private PayloadBundle? TryReadMultiItemBundle(byte[] bytes, IntegrityDigest bundleHash)
    {
        if (bytes.Length < 4 || bytes[0] != 0x50 || bytes[1] != 0x4B)
        {
            return null;
        }

        try
        {
            using var zip = new ZipArchive(new MemoryStream(bytes, writable: false), ZipArchiveMode.Read);
            var markerEntry = zip.GetEntry(BundleMarkerEntry);
            if (markerEntry is null)
            {
                return null;
            }

            var marker = JsonNode.Parse(Encoding.UTF8.GetString(ReadEntry(markerEntry))) as JsonObject;
            if (marker?["items"] is not JsonArray index)
            {
                return null;
            }

            var items = new List<PayloadItem>();
            foreach (var node in index.OfType<JsonObject>())
            {
                var name = Str(node, "fileName") ?? "archivo.bin";
                var entry = zip.GetEntry(name);
                if (entry is null)
                {
                    continue;
                }

                var raw = ReadEntry(entry);
                var declared = Str(node, "sha256");
                items.Add(new PayloadItem(
                    name,
                    Path.GetExtension(name),
                    Str(node, "mimeType") ?? GuessMime(Path.GetExtension(name)),
                    raw.LongLength,
                    raw,
                    declared is { Length: 64 } ? IntegrityDigest.Sha256(declared) : Sha256(raw)));
            }

            if (items.Count == 0)
            {
                return null;
            }

            var bundleId = Guid.TryParse(Str(marker, "bundleId"), out var parsedId) ? parsedId : Guid.NewGuid();
            return new PayloadBundle(bundleId, PayloadKind.MultiPartBundle, items, bundleHash, DateTimeOffset.UtcNow);
        }
        catch (InvalidDataException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private string TimestampText(CryptoEnvelope envelope) =>
        _rawTimestamps.TryGetValue(envelope, out var raw)
            ? raw
            : envelope.TimestampUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static CipherAlgorithmType ResolveCipher(string? algorithmCode, string? algorithm)
    {
        var identifier = !string.IsNullOrWhiteSpace(algorithmCode) ? algorithmCode : algorithm;
        if (string.IsNullOrWhiteSpace(identifier))
        {
            throw Malformed("manifest.json no indica algorithmCode ni algorithm.");
        }

        if (!OfficialAlgorithmCatalog.TryParse(algorithmCode, out var code)
            && !OfficialAlgorithmCatalog.TryParse(algorithm, out code))
        {
            throw new UnsupportedAlgorithmException(identifier);
        }

        var descriptor = OfficialAlgorithmCatalog.GetByCode(code);
        return descriptor.CipherAlgorithm
               ?? throw new UnsupportedAlgorithmException(
                   identifier,
                   $"'{descriptor.OfficialCode}' no es un algoritmo que cifre datos.enc.");
    }

    private static KeyExchangeAlgorithmType ParseKeyExchange(string? value, bool sharedKey)
    {
        if (!string.IsNullOrWhiteSpace(value) && Enum.TryParse<KeyExchangeAlgorithmType>(value, true, out var parsed))
        {
            return parsed;
        }

        var normalized = new string((value ?? string.Empty).Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        return normalized switch
        {
            "RSA" or "RSAOAEP" or "RSAOAEPSHA256" => KeyExchangeAlgorithmType.RsaOaepSha256,
            "ECDH" or "ECDHP256" or "ECC" => KeyExchangeAlgorithmType.EcdhP256,
            "DH" or "DIFFIEHELLMAN" => KeyExchangeAlgorithmType.DiffieHellman,
            _ => sharedKey ? KeyExchangeAlgorithmType.PreSharedKey : KeyExchangeAlgorithmType.RsaOaepSha256
        };
    }

    private static SignatureAlgorithmType ParseSignature(string? value)
    {
        var normalized = new string((value ?? string.Empty).Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        return normalized switch
        {
            "ECDSAP256" or "ECDSA" or "ECDSASHA256" => SignatureAlgorithmType.EcdsaP256,
            _ => SignatureAlgorithmType.RsaPssSha256
        };
    }

    private static string SignatureName(SignatureAlgorithmType signature) => signature switch
    {
        SignatureAlgorithmType.EcdsaP256 => "ECDSA-P256-SHA256",
        _ => "RSA-PSS-SHA256"
    };

    private static string NormalizeNodeId(string? nodeId)
    {
        var cleaned = new string((nodeId ?? string.Empty).Where(c => !char.IsWhiteSpace(c)).ToArray());
        return string.IsNullOrEmpty(cleaned) ? "DESCONOCIDO" : cleaned.ToUpperInvariant();
    }

    private static Guid ParseGuid(string? value) =>
        Guid.TryParse(value, out var guid) && guid != Guid.Empty
            ? guid
            : throw Malformed("manifest.json no trae un packetId válido.");

    private static DateTimeOffset ParseTimestamp(string value) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed
            : DateTimeOffset.UtcNow;

    private static byte[] DecodeSignature(string base64)
    {
        try
        {
            var bytes = Convert.FromBase64String(base64.Trim());
            return bytes.Length == 0 ? throw Malformed("manifestSignatureBase64 está vacío.") : bytes;
        }
        catch (FormatException)
        {
            throw Malformed("manifestSignatureBase64 no es Base64 válido.");
        }
    }

    private static string Required(JsonObject node, string name) =>
        Str(node, name) is { Length: > 0 } value
            ? value
            : throw Malformed($"manifest.json inválido o incompleto: falta '{name}'.");

    private static string? Str(JsonObject node, string name)
    {
        var value = Find(node, name);
        if (value is not JsonValue jsonValue)
        {
            return null;
        }

        var text = jsonValue.TryGetValue<string>(out var s) ? s : jsonValue.ToString();
        return string.IsNullOrWhiteSpace(text) ? null : text.Trim();
    }

    private static long Long(JsonObject node, string name)
    {
        var value = Find(node, name);
        if (value is JsonValue jsonValue)
        {
            if (jsonValue.TryGetValue<long>(out var number))
            {
                return number;
            }

            if (long.TryParse(jsonValue.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number))
            {
                return number;
            }
        }

        return 0;
    }

    private static JsonNode? Find(JsonObject node, string name)
    {
        if (node.TryGetPropertyValue(name, out var exact))
        {
            return exact;
        }

        foreach (var pair in node)
        {
            if (string.Equals(pair.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value;
            }
        }

        return null;
    }

    private static byte[]? Base64(JsonObject node, string name)
    {
        var text = Str(node, name);
        if (text is null)
        {
            return null;
        }

        try
        {
            var bytes = Convert.FromBase64String(text);
            return bytes.Length == 0 ? null : bytes;
        }
        catch (FormatException)
        {
            throw Malformed($"El campo '{name}' no es Base64 válido.");
        }
    }

    private static byte[]? HexOrNull(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex) || hex.Length % 2 != 0)
        {
            return null;
        }

        try
        {
            return Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static void AddOptional(JsonObject node, string name, byte[]? value)
    {
        if (value is { Length: > 0 })
        {
            node[name] = Convert.ToBase64String(value);
        }
    }

    private static string UpperThumbprint(string certificatePem)
    {
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(certificatePem);
            return Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256));
        }
        catch (CryptographicException)
        {
            throw new InvalidCertificateException("certificado.pem no se pudo leer.");
        }
    }

    private static string LowerThumbprint(string certificatePem) => UpperThumbprint(certificatePem).ToLowerInvariant();

    private static string HostOf(string endpoint) =>
        Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) ? uri.Host : endpoint;

    private static IntegrityDigest Sha256(byte[] data) => IntegrityDigest.Sha256(Convert.ToHexString(SHA256.HashData(data)));

    private static ZipArchiveEntry? FindEntry(ZipArchive zip, string name) =>
        zip.GetEntry(name)
        ?? zip.Entries.FirstOrDefault(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));

    private static byte[] ReadEntry(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static void WriteEntry(ZipArchive zip, string name, byte[] content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        using var stream = entry.Open();
        stream.Write(content);
    }

    private static string GuessMime(string extension) => extension.ToLowerInvariant() switch
    {
        ".txt" => "text/plain",
        ".pdf" => "application/pdf",
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".bmp" => "image/bmp",
        ".gif" => "image/gif",
        ".json" => "application/json",
        ".zip" => "application/zip",
        ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        _ => "application/octet-stream"
    };

    private static PayloadKind GuessKind(string extension) => extension.ToLowerInvariant() switch
    {
        ".txt" or ".md" or ".csv" or ".json" => PayloadKind.PlainText,
        ".png" or ".jpg" or ".jpeg" or ".bmp" or ".gif" or ".webp" => PayloadKind.Image,
        ".pdf" or ".doc" or ".docx" or ".xlsx" or ".pptx" or ".odt" => PayloadKind.Document,
        _ => PayloadKind.Binary
    };

    private static DomainException Malformed(string message) => new(message, "PACKAGE_MALFORMED");
}
