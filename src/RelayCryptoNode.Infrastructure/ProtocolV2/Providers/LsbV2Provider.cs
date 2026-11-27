using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Infrastructure.Algorithms.Steganography;

namespace RelayCryptoNode.Infrastructure.ProtocolV2.Providers;

/// <summary>
/// 11 LSBSTEGO: oculta el archivo en el bit menos significativo de cada canal de una imagen PNG (RGB/RGBA, 8 bits) o BMP.
/// <list type="bullet">
/// <item><c>forward</c> requiere la parte <c>cover</c>; datos.enc = imagen resultante (mismo formato que la portadora).</item>
/// <item>Secreto opcional <c>password</c>: antes de ocultar, el archivo se cifra con AES-256-GCM,
/// clave = SHA-256(UTF-8(password)), formato nonce(12) ‖ etiqueta(16) ‖ cifrado.</item>
/// <item>Bits: cabecera de 8 bytes ("RCNS" + longitud big-endian) y luego los datos, del bit más significativo al menos,
/// recorriendo los bytes de píxel en orden (BMP: tal como están en el archivo; PNG: filas sin filtro, de arriba hacia abajo).</item>
/// </list>
/// </summary>
public sealed class LsbV2Provider : IV2AlgorithmProvider
{
    private readonly LsbStegoModule _module = new();

    /// <inheritdoc />
    public V2Algorithm Algorithm { get; } = V2Catalog.ByCode("LSBSTEGO")!;

    /// <inheritdoc />
    public JsonObject Profile() => new()
    {
        ["algorithmId"] = Algorithm.Id,
        ["algorithmCode"] = Algorithm.Code,
        ["variants"] = new JsonArray("LSB-1BIT-PNG", "LSB-1BIT-BMP"),
        ["operations"] = new JsonObject
        {
            ["forward"] = new JsonObject { ["name"] = "ocultar", ["inputs"] = new JsonArray("payload", "cover") },
            ["inverse"] = new JsonObject { ["name"] = "extraer", ["inputs"] = new JsonArray("package") }
        },
        ["secretParameters"] = new JsonArray(
            new JsonObject { ["name"] = "password", ["type"] = "text", ["optional"] = true, ["requiredFor"] = new JsonArray() }),
        ["options"] = new JsonArray(),
        ["publicParameters"] = new JsonArray("imageFormat", "bitsPerChannel", "channels", "payloadLengthBytes", "passwordProtected", "header"),
        ["payloadModes"] = new JsonArray("text", "file", "image"),
        ["maxPayloadBytes"] = V2Format.MaxBodyBytes,
        ["notes"] = "Portadora PNG de 8 bits (RGB o RGBA) o BMP de 24 bits. Capacidad: (bytes de píxel / 8) - 8 bytes."
    };

    /// <inheritdoc />
    public V2ForwardOutput Forward(V2ForwardInput input)
    {
        if (input.Cover is null || input.Cover.Length == 0)
        {
            throw new V2ProtocolException("E-PARAMS", "LSBSTEGO requiere la imagen portadora (parte cover) en PNG o BMP.");
        }

        var format = DetectFormat(input.Cover);
        var protectedPayload = input.Secrets.TryGetValue("password", out var password) && !string.IsNullOrEmpty(password);
        var payload = protectedPayload ? Encrypt(input.Payload, password!) : input.Payload;
        byte[] image;
        try
        {
            image = _module.EmbedPayload(input.Cover, payload);
        }
        catch (DomainException ex)
        {
            throw new V2ProtocolException("E-PARAMS", ex.Message);
        }

        return new V2ForwardOutput(
            image,
            new Dictionary<string, string>
            {
                ["bitsPerChannel"] = "1",
                ["channels"] = "RGB",
                ["header"] = "LSBC-BE32",
                ["imageFormat"] = format,
                ["passwordProtected"] = protectedPayload ? "true" : "false",
                ["payloadLengthBytes"] = payload.Length.ToString(CultureInfo.InvariantCulture)
            },
            "image",
            $"LSB 1 bit {format}");
    }

    /// <inheritdoc />
    public V2InverseOutput Inverse(byte[] data, IReadOnlyDictionary<string, string> publicParameters, IReadOnlyDictionary<string, string> secrets)
    {
        byte[] payload;
        try
        {
            payload = _module.ExtractPayload(data);
        }
        catch (DomainException ex)
        {
            throw new V2ProtocolException("E-PARAMS", "No se encontró un mensaje oculto: " + ex.Message);
        }

        if (publicParameters.TryGetValue("passwordProtected", out var flag) && flag == "true")
        {
            if (!secrets.TryGetValue("password", out var password) || string.IsNullOrEmpty(password))
            {
                throw new V2ProtocolException("E-PARAMS", "Este mensaje está protegido: falta el secreto password.");
            }

            payload = Decrypt(payload, password);
        }

        return new V2InverseOutput(payload);
    }

    private static string DetectFormat(byte[] image)
    {
        if (image.Length > 8 && image[0] == 0x89 && image[1] == (byte)'P' && image[2] == (byte)'N' && image[3] == (byte)'G')
        {
            return "PNG";
        }

        if (image.Length > 54 && image[0] == (byte)'B' && image[1] == (byte)'M')
        {
            return "BMP";
        }

        throw new V2ProtocolException("E-PARAMS", "La portadora debe ser PNG o BMP.");
    }


    private static byte[] Encrypt(byte[] payload, string password)
    {
        var key = SHA256.HashData(Encoding.UTF8.GetBytes(password));
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[payload.Length];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, payload, cipher, tag);
        return [.. nonce, .. tag, .. cipher];
    }

    private static byte[] Decrypt(byte[] data, string password)
    {
        if (data.Length < 28)
        {
            throw new V2ProtocolException("E-PARAMS", "El mensaje oculto está incompleto.");
        }

        try
        {
            var key = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            var plain = new byte[data.Length - 28];
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(data.AsSpan(0, 12), data.AsSpan(28), data.AsSpan(12, 16), plain);
            return plain;
        }
        catch (CryptographicException)
        {
            throw new V2ProtocolException("E-PARAMS", "La contraseña de la imagen es incorrecta.");
        }
    }

    /// <summary>Crea una imagen PNG lisa del tamaño justo para una carga (portadora por defecto).</summary>
    public static byte[] DefaultCoverFor(int payloadBytes)
    {
        var needed = (payloadBytes + 8 + 28) * 8;
        var side = Math.Max(64, (int)Math.Ceiling(Math.Sqrt(needed / 3.0)) + 4);
        return LsbStegoModule.CreateBlankPngRgb(side, side);
    }
}
