using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace RelayCryptoNode.Infrastructure.ProtocolV2;

/// <summary>
/// Formatos, expresiones regulares y cadenas canónicas del estándar v2.0 (secciones 3, 8.4 y 8.5).
/// </summary>
public static partial class V2Format
{
    /// <summary>Versión del protocolo.</summary>
    public const string Version = "2.0";

    /// <summary>Puerto UDP común de anuncio.</summary>
    public const int BeaconPort = 5099;

    /// <summary>Tamaño máximo de cuerpo y paquete.</summary>
    public const long MaxBodyBytes = 50L * 1024 * 1024;

    /// <summary>Ventana de tiempo permitida.</summary>
    public static readonly TimeSpan TimeWindow = TimeSpan.FromMinutes(10);

    /// <summary>nodeId de un equipo (<c>EQ06</c>).</summary>
    public static string NodeIdFor(int team) => $"EQ{team:00}";

    /// <summary>Puerto HTTP de un equipo (5000 + número).</summary>
    public static int HttpPortFor(int team) => 5000 + team;

    /// <summary>Fecha UTC en el formato del estándar (<c>2026-11-25T15:47:00Z</c>).</summary>
    public static string Timestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>Instante actual truncado a segundos.</summary>
    public static DateTimeOffset NowSeconds()
    {
        var now = DateTimeOffset.UtcNow;
        return new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second, TimeSpan.Zero);
    }

    /// <summary>UUID v4 en minúsculas.</summary>
    public static string NewUuid() => Guid.NewGuid().ToString("D");

    /// <summary>SHA-256 en hex minúsculas.</summary>
    public static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    /// <summary>
    /// Saca el certificado de lo que regrese otro nodo en <c>/api/certificate</c>: PEM directo, JSON con cualquier
    /// nombre de campo (también anidado), saltos de línea escapados o solo el Base64 del DER. Regresa un PEM limpio.
    /// </summary>
    public static string? ExtractCertificatePem(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        var text = body.Trim();
        if (text.StartsWith('{') || text.StartsWith('[') || text.StartsWith('"'))
        {
            try
            {
                var found = FindCertificateText(JsonNode.Parse(text));
                if (found is not null)
                {
                    text = found;
                }
            }
            catch (System.Text.Json.JsonException)
            {
            }
        }

        text = text.Replace("\\r", string.Empty).Replace("\\n", "\n").Replace("\\/", "/");
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        var start = text.IndexOf(begin, StringComparison.Ordinal);
        string base64;
        if (start >= 0)
        {
            var stop = text.IndexOf(end, start, StringComparison.Ordinal);
            if (stop < 0)
            {
                return null;
            }

            base64 = text[(start + begin.Length)..stop];
        }
        else
        {
            base64 = text;
        }

        base64 = new string(base64.Where(c => !char.IsWhiteSpace(c)).ToArray());
        try
        {
            var der = Convert.FromBase64String(base64);
            using var certificate = new X509Certificate2(der);
            return certificate.ExportCertificatePem();
        }
        catch (FormatException)
        {
            return null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static string? FindCertificateText(JsonNode? node)
    {
        switch (node)
        {
            case JsonValue value when value.TryGetValue<string>(out var str):
                return str.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal) ? str : null;
            case JsonObject obj:
                foreach (var name in new[] { "certificatePem", "certificate", "pem", "certificado", "certificadoPem" })
                {
                    if (obj[name] is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 100)
                    {
                        return s;
                    }
                }

                foreach (var pair in obj)
                {
                    if (pair.Key.Contains("cert", StringComparison.OrdinalIgnoreCase)
                        && pair.Value is JsonValue cv && cv.TryGetValue<string>(out var cs) && cs.Length > 100)
                    {
                        return cs;
                    }
                }

                foreach (var pair in obj)
                {
                    var inner = FindCertificateText(pair.Value);
                    if (inner is not null)
                    {
                        return inner;
                    }
                }

                return null;
            case JsonArray array:
                foreach (var item in array)
                {
                    var inner = FindCertificateText(item);
                    if (inner is not null)
                    {
                        return inner;
                    }
                }

                return null;
            default:
                return null;
        }
    }

    /// <summary>SHA-256 del DER del certificado en hex MAYÚSCULAS.</summary>
    public static string Thumbprint(string certificatePem)
    {
        using var certificate = X509Certificate2.CreateFromPem(certificatePem);
        return Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256));
    }

    /// <summary>Texto canónico de <c>publicParameters</c> (8.5).</summary>
    public static string CanonicalParameters(IReadOnlyDictionary<string, string> parameters) =>
        string.Join('\n', parameters
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => $"{p.Key}={p.Value}"));

    /// <summary><c>publicParametersSha256</c> (8.5).</summary>
    public static string ParametersSha256(IReadOnlyDictionary<string, string> parameters) =>
        Sha256Hex(Encoding.UTF8.GetBytes(CanonicalParameters(parameters)));

    /// <summary>Cadena de firma del manifiesto (8.4).</summary>
    public static string SignatureString(
        string version,
        string packetType,
        string packetId,
        string sourceNode,
        string producerNode,
        string algorithmCode,
        string operation,
        string timestampUtc,
        string encryptedSha256,
        string publicParametersSha256,
        string certificateThumbprintSha256) =>
        string.Join('|', version, packetType, packetId, sourceNode, producerNode, algorithmCode, operation,
            timestampUtc, encryptedSha256, publicParametersSha256, certificateThumbprintSha256);

    /// <summary>Nombre estándar del zip (9.2).</summary>
    public static string ZipName(string packetType, string sourceNode, string algorithmCode, string timestampUtc, string encryptedSha256)
    {
        var stamp = DateTimeOffset.Parse(timestampUtc, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal)
            .UtcDateTime.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var name = $"{sourceNode}_{algorithmCode}_{stamp}_{encryptedSha256[..8].ToUpperInvariant()}.zip";
        return packetType == "result" ? "RES_" + name : name;
    }

    /// <summary>Patrón de nodeId.</summary>
    [GeneratedRegex("^EQ[0-9]{2}$")]
    public static partial Regex NodeIdPattern();

    /// <summary>Patrón de UUID v4 en minúsculas.</summary>
    [GeneratedRegex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    public static partial Regex UuidPattern();

    /// <summary>Patrón de fecha.</summary>
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")]
    public static partial Regex TimestampPattern();

    /// <summary>Patrón de huella (hex MAYÚSCULAS).</summary>
    [GeneratedRegex("^[0-9A-F]{64}$")]
    public static partial Regex ThumbprintPattern();

    /// <summary>Patrón de hash de contenido (hex minúsculas).</summary>
    [GeneratedRegex("^[0-9a-f]{64}$")]
    public static partial Regex ContentHashPattern();

    /// <summary>Patrón de keyId.</summary>
    [GeneratedRegex("^EQ[0-9]{2}-KEY-[0-9a-f-]{36}$")]
    public static partial Regex KeyIdPattern();

    /// <summary>Convierte un texto de fecha del estándar.</summary>
    public static bool TryParseTimestamp(string? text, out DateTimeOffset value)
    {
        value = default;
        return text is not null
               && TimestampPattern().IsMatch(text)
               && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out value);
    }
}
