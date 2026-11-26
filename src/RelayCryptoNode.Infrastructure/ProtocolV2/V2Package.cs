using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RelayCryptoNode.Infrastructure.ProtocolV2;

/// <summary>
/// Datos para armar un paquete v2.0.
/// </summary>
public sealed class V2PackageSpec
{
    /// <summary><c>package</c> o <c>result</c>.</summary>
    public string PacketType { get; init; } = "package";

    /// <summary>packetId fijo (cuando el contenido depende de él, como el AAD del sobre de un result).</summary>
    public string? PacketId { get; init; }

    /// <summary>Petición que lo originó o <c>null</c>.</summary>
    public string? RequestId { get; init; }

    /// <summary>Quién ejecutó el algoritmo (por defecto el propio nodo).</summary>
    public string? ProducerNode { get; init; }

    /// <summary>Algoritmo.</summary>
    public required V2Algorithm Algorithm { get; init; }

    /// <summary>Nombre descriptivo de la variante (por defecto el de la tabla).</summary>
    public string? AlgorithmName { get; init; }

    /// <summary><c>forward</c> o <c>inverse</c>.</summary>
    public required string Operation { get; init; }

    /// <summary><c>text</c>, <c>file</c>, <c>image</c> o <c>multipart</c>.</summary>
    public required string PayloadMode { get; init; }

    /// <summary>Nombre del archivo original.</summary>
    public required string OriginalFileName { get; init; }

    /// <summary>Tamaño original.</summary>
    public required long OriginalSizeBytes { get; init; }

    /// <summary>Tipo MIME del original.</summary>
    public required string ContentType { get; init; }

    /// <summary>Bytes de <c>datos.enc</c> / <c>resultado.enc</c>.</summary>
    public required byte[] Data { get; init; }

    /// <summary>Parámetros públicos (solo cadenas, nunca secretos).</summary>
    public IReadOnlyDictionary<string, string> PublicParameters { get; init; } = new Dictionary<string, string>();

    /// <summary>Partes en modo multipart.</summary>
    public JsonArray? Parts { get; init; }

    /// <summary>Referencia a llave asimétrica.</summary>
    public JsonObject? KeyRef { get; init; }

    /// <summary>Veredicto de verificación (solo result).</summary>
    public JsonObject? Verification { get; init; }

    /// <summary>Sobre CC-ENV-1 sin texto cifrado (solo result).</summary>
    public JsonObject? ResultEnvelope { get; init; }
}

/// <summary>
/// Paquete v2.0 ya validado o recién armado.
/// </summary>
/// <param name="ZipBytes">Bytes del .zip.</param>
/// <param name="FileName">Nombre estándar.</param>
/// <param name="Manifest">Manifiesto.</param>
/// <param name="Data">Contenido de datos.enc / resultado.enc.</param>
/// <param name="CertificatePem">Certificado del emisor.</param>
public sealed record V2Package(byte[] ZipBytes, string FileName, JsonObject Manifest, byte[] Data, string CertificatePem)
{
    /// <summary>Campo de texto del manifiesto.</summary>
    public string Str(string name) => Manifest[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : string.Empty;

    /// <summary>Tipo de paquete.</summary>
    public string PacketType => Str("packetType");

    /// <summary>Id del paquete.</summary>
    public string PacketId => Str("packetId");

    /// <summary>Emisor.</summary>
    public string SourceNode => Str("sourceNode");

    /// <summary>Productor.</summary>
    public string ProducerNode => Str("producerNode");

    /// <summary>Código del algoritmo.</summary>
    public string AlgorithmCode => Str("algorithmCode");

    /// <summary>Operación.</summary>
    public string Operation => Str("operation");

    /// <summary>Parámetros públicos como diccionario.</summary>
    public Dictionary<string, string> PublicParameters =>
        (Manifest["publicParameters"] as JsonObject ?? new JsonObject())
        .Where(p => p.Value is JsonValue)
        .ToDictionary(p => p.Key, p => p.Value!.GetValue<string>(), StringComparer.Ordinal);
}

/// <summary>
/// Arma, firma y valida paquetes .zip v2.0 (secciones 9 y 13.1).
/// </summary>
public static class V2PackageCodec
{
    private const long MaxUncompressedBytes = 200L * 1024 * 1024;
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
    private static readonly string[] PackageEntries = ["datos.enc", "certificado.pem", "manifest.json"];
    private static readonly string[] ResultEntries = ["resultado.enc", "certificado.pem", "manifest.json"];

    private static readonly string[] RequiredFields =
    [
        "version", "packetType", "packetId", "requestId", "sourceNode", "sourceTeam", "sourceIp", "producerNode",
        "timestampUtc", "algorithmId", "algorithmCode", "algorithmName", "operation", "operationName", "payloadMode",
        "originalFileName", "originalExtension", "originalSizeBytes", "contentType", "encryptedSha256",
        "encryptedSizeBytes", "parts", "keyRef", "publicParameters", "publicParametersSha256",
        "certificateThumbprintSha256", "signatureAlgorithm", "manifestSignatureBase64"
    ];

    /// <summary>Arma y firma un paquete con la identidad del nodo.</summary>
    public static V2Package Build(V2PackageSpec spec, V2Identity identity)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(identity);
        foreach (var value in spec.PublicParameters)
        {
            if (value.Value is null)
            {
                throw new V2ProtocolException("E-PARAMS", $"El parámetro público '{value.Key}' no puede ser nulo.");
            }
        }

        var timestamp = V2Format.Timestamp(V2Format.NowSeconds());
        var packetId = spec.PacketId ?? V2Format.NewUuid();
        var producer = spec.ProducerNode ?? identity.NodeId;
        var encryptedSha = V2Format.Sha256Hex(spec.Data);
        var paramsSha = V2Format.ParametersSha256(spec.PublicParameters);
        var operationName = spec.Operation == "forward" ? spec.Algorithm.ForwardName : spec.Algorithm.InverseName;
        var signature = identity.SignText(V2Format.SignatureString(
            V2Format.Version, spec.PacketType, packetId, identity.NodeId, producer, spec.Algorithm.Code,
            spec.Operation, timestamp, encryptedSha, paramsSha, identity.Thumbprint));

        var parameters = new JsonObject();
        foreach (var pair in spec.PublicParameters.OrderBy(p => p.Key, StringComparer.Ordinal))
        {
            parameters[pair.Key] = pair.Value;
        }

        var manifest = new JsonObject
        {
            ["version"] = V2Format.Version,
            ["packetType"] = spec.PacketType,
            ["packetId"] = packetId,
            ["requestId"] = spec.RequestId,
            ["sourceNode"] = identity.NodeId,
            ["sourceTeam"] = identity.TeamNumber,
            ["sourceIp"] = $"{identity.Ip}:{identity.HttpPort}",
            ["producerNode"] = producer,
            ["timestampUtc"] = timestamp,
            ["algorithmId"] = spec.Algorithm.Id,
            ["algorithmCode"] = spec.Algorithm.Code,
            ["algorithmName"] = spec.AlgorithmName ?? spec.Algorithm.Name,
            ["operation"] = spec.Operation,
            ["operationName"] = operationName,
            ["payloadMode"] = spec.PayloadMode,
            ["originalFileName"] = spec.OriginalFileName,
            ["originalExtension"] = Path.GetExtension(spec.OriginalFileName),
            ["originalSizeBytes"] = spec.OriginalSizeBytes,
            ["contentType"] = spec.ContentType,
            ["encryptedSha256"] = encryptedSha,
            ["encryptedSizeBytes"] = spec.Data.LongLength,
            ["parts"] = spec.Parts?.DeepClone(),
            ["keyRef"] = spec.KeyRef?.DeepClone(),
            ["publicParameters"] = parameters,
            ["publicParametersSha256"] = paramsSha,
            ["verification"] = spec.Verification?.DeepClone(),
            ["resultEnvelope"] = spec.ResultEnvelope?.DeepClone(),
            ["certificateThumbprintSha256"] = identity.Thumbprint,
            ["signatureAlgorithm"] = "RSA-PSS-SHA256",
            ["manifestSignatureBase64"] = signature
        };

        var dataEntry = spec.PacketType == "result" ? "resultado.enc" : "datos.enc";
        var zip = WriteZip(new()
        {
            [dataEntry] = spec.Data,
            ["certificado.pem"] = Encoding.UTF8.GetBytes(identity.CertificatePem),
            ["manifest.json"] = Encoding.UTF8.GetBytes(manifest.ToJsonString(Indented))
        });
        return new V2Package(
            zip,
            V2Format.ZipName(spec.PacketType, identity.NodeId, spec.Algorithm.Code, timestamp, encryptedSha),
            manifest,
            spec.Data,
            identity.CertificatePem);
    }

    /// <summary>
    /// Reempaqueta un paquete de otro nodo para reenviarlo (9.6): conserva datos, parámetros, keyRef,
    /// productor y algoritmo; cambia packetId, fecha, emisor, certificado y firma.
    /// </summary>
    public static V2Package Rewrap(V2Package original, V2Identity identity)
    {
        var algorithm = V2Catalog.ByCode(original.AlgorithmCode)
                        ?? throw new V2ProtocolException("E-ALGORITHM", "Algoritmo desconocido.");
        var m = original.Manifest;
        return Build(new V2PackageSpec
        {
            PacketType = original.PacketType,
            RequestId = original.Str("requestId") is { Length: > 0 } r ? r : null,
            ProducerNode = original.ProducerNode,
            Algorithm = algorithm,
            AlgorithmName = original.Str("algorithmName"),
            Operation = original.Operation,
            PayloadMode = original.Str("payloadMode"),
            OriginalFileName = original.Str("originalFileName"),
            OriginalSizeBytes = m["originalSizeBytes"]?.GetValue<long>() ?? 0,
            ContentType = original.Str("contentType"),
            Data = original.Data,
            PublicParameters = original.PublicParameters,
            Parts = m["parts"] as JsonArray,
            KeyRef = m["keyRef"] as JsonObject,
            Verification = m["verification"] as JsonObject,
            ResultEnvelope = m["resultEnvelope"] as JsonObject
        }, identity);
    }

    /// <summary>Indica si un .zip trae un manifiesto v2.0 (para decidir entre v1 y v2).</summary>
    public static bool LooksLikeV2(byte[] zipBytes)
    {
        try
        {
            using var zip = new ZipArchive(new MemoryStream(zipBytes, writable: false), ZipArchiveMode.Read);
            var entry = zip.GetEntry("manifest.json");
            if (entry is null || entry.Length > 1024 * 1024)
            {
                return false;
            }

            using var stream = entry.Open();
            var node = JsonNode.Parse(stream) as JsonObject;
            if (node?["version"] is not JsonValue v || !v.TryGetValue<string>(out var version))
            {
                return false;
            }

            // Cualquier versión 2.x o superior va por el camino v2 (que rechaza con E-VERSION lo que no sea 2.0).
            var major = version.Split('.')[0];
            return int.TryParse(major, out var number) && number >= 2;
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Valida un paquete recibido en el orden de la sección 13.1 (pasos 1 a 13). El paso 14 (repetidos) y la huella fijada
    /// se revisan afuera, con el directorio y el registro de repetidos.
    /// </summary>
    public static V2Package Validate(byte[] zipBytes)
    {
        if (zipBytes.LongLength > V2Format.MaxBodyBytes)
        {
            throw new V2ProtocolException("E-SIZE", "El paquete supera 50 MB.");
        }

        Dictionary<string, byte[]> entries;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(zipBytes, writable: false), ZipArchiveMode.Read);
            var names = zip.Entries.Select(e => e.FullName).ToList();
            var expected = names.Contains("resultado.enc") ? ResultEntries : PackageEntries;
            if (names.Count != 3 || !expected.All(names.Contains))
            {
                throw new V2ProtocolException("E-ZIP-STRUCTURE", $"El zip debe traer exactamente {string.Join(", ", expected)} en la raíz.");
            }

            long total = 0;
            long compressed = 0;
            foreach (var entry in zip.Entries)
            {
                total += entry.Length;
                compressed += entry.CompressedLength;
            }

            if (total > MaxUncompressedBytes || (total > 1024 * 1024 && total / Math.Max(1, compressed) > 100))
            {
                throw new V2ProtocolException("E-ZIP-BOMB", "El zip descomprimido es demasiado grande o la compresión es excesiva.");
            }

            entries = zip.Entries.ToDictionary(e => e.FullName, e =>
            {
                using var stream = e.Open();
                using var buffer = new MemoryStream();
                stream.CopyTo(buffer);
                return buffer.ToArray();
            });
        }
        catch (InvalidDataException)
        {
            throw new V2ProtocolException("E-ZIP-INVALID", "El archivo no es un zip válido.");
        }

        JsonObject manifest;
        try
        {
            manifest = JsonNode.Parse(Encoding.UTF8.GetString(entries["manifest.json"]).TrimStart('﻿')) as JsonObject
                       ?? throw new V2ProtocolException("E-MANIFEST", "manifest.json no es un objeto JSON.");
        }
        catch (JsonException)
        {
            throw new V2ProtocolException("E-MANIFEST", "manifest.json no es JSON válido.");
        }

        ValidateManifestShape(manifest);

        var version = Text(manifest, "version");
        if (version != V2Format.Version)
        {
            throw new V2ProtocolException("E-VERSION", $"Versión '{version}' no soportada (se espera 2.0).");
        }

        var algorithmId = manifest["algorithmId"]!.GetValue<int>();
        var algorithm = V2Catalog.ByCode(Text(manifest, "algorithmCode"));
        if (algorithm is null || algorithm.Id != algorithmId)
        {
            throw new V2ProtocolException("E-ALGORITHM", "algorithmId y algorithmCode no coinciden con la tabla 4.1.");
        }

        var packetType = Text(manifest, "packetType");
        var data = entries[packetType == "result" ? "resultado.enc" : "datos.enc"];
        if (!string.Equals(V2Format.Sha256Hex(data), Text(manifest, "encryptedSha256"), StringComparison.Ordinal))
        {
            throw new V2ProtocolException("E-HASH", "El SHA-256 de datos.enc no coincide con encryptedSha256.");
        }

        ValidateParts(manifest, data);

        var parameters = (JsonObject)manifest["publicParameters"]!;
        var dict = parameters.ToDictionary(p => p.Key, p => p.Value!.GetValue<string>(), StringComparer.Ordinal);
        if (!string.Equals(V2Format.ParametersSha256(dict), Text(manifest, "publicParametersSha256"), StringComparison.Ordinal))
        {
            throw new V2ProtocolException("E-PARAMS-HASH", "publicParametersSha256 no coincide con el texto canónico de publicParameters.");
        }

        var certificatePem = Encoding.UTF8.GetString(entries["certificado.pem"]).Trim();
        var thumbprint = ValidateCertificate(certificatePem, Text(manifest, "sourceNode"));
        if (!string.Equals(thumbprint, Text(manifest, "certificateThumbprintSha256"), StringComparison.Ordinal))
        {
            throw new V2ProtocolException("E-CERT-THUMBPRINT", "La huella de certificado.pem no coincide con el manifiesto.");
        }

        var signed = V2Format.SignatureString(
            version, packetType, Text(manifest, "packetId"), Text(manifest, "sourceNode"), Text(manifest, "producerNode"),
            algorithm.Code, Text(manifest, "operation"), Text(manifest, "timestampUtc"), Text(manifest, "encryptedSha256"),
            Text(manifest, "publicParametersSha256"), Text(manifest, "certificateThumbprintSha256"));
        if (!VerifySignature(certificatePem, Encoding.UTF8.GetBytes(signed), Text(manifest, "manifestSignatureBase64")))
        {
            throw new V2ProtocolException("E-SIGNATURE", "La firma del manifiesto no es válida.");
        }

        V2Format.TryParseTimestamp(Text(manifest, "timestampUtc"), out var stamp);
        if ((DateTimeOffset.UtcNow - stamp).Duration() > V2Format.TimeWindow)
        {
            throw new V2ProtocolException("E-TIMESTAMP", "timestampUtc está fuera de la ventana de ±10 minutos.");
        }

        return new V2Package(
            zipBytes,
            V2Format.ZipName(packetType, Text(manifest, "sourceNode"), algorithm.Code, Text(manifest, "timestampUtc"), Text(manifest, "encryptedSha256")),
            manifest,
            data,
            certificatePem);
    }

    /// <summary>Valida un certificado de nodo (RSA-2048, CN, vigencia) y devuelve su huella.</summary>
    public static string ValidateCertificate(string certificatePem, string expectedNodeId)
    {
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(certificatePem);
            using var rsa = certificate.GetRSAPublicKey();
            if (rsa is null || rsa.KeySize != 2048)
            {
                throw new V2ProtocolException("E-CERT", "El certificado debe ser RSA-2048.");
            }

            var cn = certificate.GetNameInfo(X509NameType.SimpleName, false);
            if (!string.Equals(cn, expectedNodeId, StringComparison.Ordinal))
            {
                throw new V2ProtocolException("E-CERT", $"El CN del certificado ({cn}) no es {expectedNodeId}.");
            }

            var now = DateTime.UtcNow;
            if (certificate.NotBefore.ToUniversalTime() - V2Format.TimeWindow > now || certificate.NotAfter.ToUniversalTime() < now)
            {
                throw new V2ProtocolException("E-CERT", "El certificado no está vigente.");
            }

            return Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256));
        }
        catch (CryptographicException)
        {
            throw new V2ProtocolException("E-CERT", "certificado.pem no es un X.509 válido.");
        }
    }

    /// <summary>Verifica RSA-PSS-SHA256 con el certificado.</summary>
    public static bool VerifySignature(string certificatePem, byte[] data, string signatureBase64)
    {
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(certificatePem);
            using var rsa = certificate.GetRSAPublicKey();
            return rsa is not null
                   && rsa.VerifyData(data, Convert.FromBase64String(signatureBase64), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return false;
        }
    }

    /// <summary>Lee las partes de un datos.enc multipart (zip interno).</summary>
    public static List<(string Name, byte[] Content)> ReadInnerParts(byte[] data)
    {
        using var zip = new ZipArchive(new MemoryStream(data, writable: false), ZipArchiveMode.Read);
        if (zip.Entries.Count > 64)
        {
            throw new V2ProtocolException("E-ZIP-STRUCTURE", "El zip interno tiene más de 64 partes.");
        }

        return zip.Entries.Select(e =>
        {
            if (e.FullName.Contains('/') || e.FullName.Contains('\\') || e.FullName.Contains(".."))
            {
                throw new V2ProtocolException("E-ZIP-STRUCTURE", "El zip interno trae rutas no permitidas.");
            }

            using var stream = e.Open();
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            return (e.FullName, buffer.ToArray());
        }).ToList();
    }

    /// <summary>Escribe un zip plano.</summary>
    public static byte[] WriteZip(Dictionary<string, byte[]> entries)
    {
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var pair in entries)
            {
                using var stream = zip.CreateEntry(pair.Key, CompressionLevel.Optimal).Open();
                stream.Write(pair.Value);
            }
        }

        return buffer.ToArray();
    }

    private static void ValidateManifestShape(JsonObject m)
    {
        foreach (var field in RequiredFields)
        {
            if (!m.ContainsKey(field))
            {
                throw new V2ProtocolException("E-MANIFEST", $"Falta el campo obligatorio '{field}'.");
            }
        }

        void Require(bool ok, string message)
        {
            if (!ok)
            {
                throw new V2ProtocolException("E-MANIFEST", message);
            }
        }

        Require(Text(m, "packetType") is "package" or "result", "packetType debe ser package o result.");
        Require(V2Format.UuidPattern().IsMatch(Text(m, "packetId")), "packetId no es un UUID v4 en minúsculas.");
        Require(m["requestId"] is null || V2Format.UuidPattern().IsMatch(Text(m, "requestId")), "requestId debe ser UUID v4 o null.");
        Require(V2Format.NodeIdPattern().IsMatch(Text(m, "sourceNode")), "sourceNode debe ser EQNN.");
        Require(V2Format.NodeIdPattern().IsMatch(Text(m, "producerNode")), "producerNode debe ser EQNN.");
        Require(IsInt(m["sourceTeam"]) && V2Format.NodeIdFor(m["sourceTeam"]!.GetValue<int>()) == Text(m, "sourceNode"), "sourceTeam no corresponde a sourceNode.");
        Require(V2Format.TryParseTimestamp(Text(m, "timestampUtc"), out _), "timestampUtc debe ser yyyy-MM-ddTHH:mm:ssZ.");
        Require(IsInt(m["algorithmId"]) && m["algorithmId"]!.GetValue<int>() is >= 1 and <= 21, "algorithmId debe ir de 1 a 21.");
        Require(Text(m, "operation") is "forward" or "inverse", "operation debe ser forward o inverse.");
        Require(Text(m, "payloadMode") is "text" or "file" or "image" or "multipart", "payloadMode inválido.");
        Require(V2Format.ContentHashPattern().IsMatch(Text(m, "encryptedSha256")), "encryptedSha256 debe ser hex minúsculas.");
        Require(V2Format.ContentHashPattern().IsMatch(Text(m, "publicParametersSha256")), "publicParametersSha256 debe ser hex minúsculas.");
        Require(V2Format.ThumbprintPattern().IsMatch(Text(m, "certificateThumbprintSha256")), "certificateThumbprintSha256 debe ser hex MAYÚSCULAS.");
        Require(Text(m, "signatureAlgorithm") == "RSA-PSS-SHA256", "signatureAlgorithm debe ser RSA-PSS-SHA256.");
        Require(IsLong(m["originalSizeBytes"]) && IsLong(m["encryptedSizeBytes"]), "Los tamaños deben ser enteros.");
        Require(m["publicParameters"] is JsonObject p && p.All(x => x.Value is JsonValue v && v.TryGetValue<string>(out _)),
            "publicParameters debe ser un objeto plano con valores cadena.");
        Require(!string.IsNullOrEmpty(Text(m, "manifestSignatureBase64")), "Falta la firma.");
    }

    private static void ValidateParts(JsonObject manifest, byte[] data)
    {
        if (Text(manifest, "payloadMode") != "multipart")
        {
            return;
        }

        if (manifest["parts"] is not JsonArray declared)
        {
            throw new V2ProtocolException("E-MANIFEST", "payloadMode multipart requiere el arreglo parts.");
        }

        List<(string Name, byte[] Content)> parts;
        try
        {
            parts = ReadInnerParts(data);
        }
        catch (InvalidDataException)
        {
            throw new V2ProtocolException("E-ZIP-STRUCTURE", "datos.enc multipart no es un zip válido.");
        }

        foreach (var item in declared.OfType<JsonObject>())
        {
            var name = (string?)item["name"];
            var part = parts.FirstOrDefault(p => p.Name == name);
            if (part.Content is null || V2Format.Sha256Hex(part.Content) != (string?)item["sha256"])
            {
                throw new V2ProtocolException("E-HASH", $"La parte {name} no coincide con su SHA-256.");
            }
        }
    }

    private static string Text(JsonObject node, string name) =>
        node[name] is JsonValue value && value.TryGetValue<string>(out var text) ? text : string.Empty;

    private static bool IsInt(JsonNode? node) => node is JsonValue v && v.TryGetValue<int>(out _);

    private static bool IsLong(JsonNode? node) => node is JsonValue v && v.TryGetValue<long>(out _);
}
