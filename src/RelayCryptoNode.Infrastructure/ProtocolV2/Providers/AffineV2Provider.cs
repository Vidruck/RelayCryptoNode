using System.Globalization;
using System.Text.Json.Nodes;

namespace RelayCryptoNode.Infrastructure.ProtocolV2.Providers;

/// <summary>
/// 12 EUCLIDESAFFINE: cifrado afín E(x) = (a·x + b) mod m, con a⁻¹ calculado por Euclides extendido.
/// <list type="bullet">
/// <item>Secretos: <c>a</c> y <c>b</c> (enteros en texto), con mcd(a, m) = 1.</item>
/// <item>Público: <c>modulus</c> = <c>256</c> (cada byte del archivo) o <c>26</c> (solo letras A–Z / a–z, conserva
/// mayúsculas/minúsculas; el resto de los bytes no cambia).</item>
/// </list>
/// </summary>
public sealed class AffineV2Provider : IV2AlgorithmProvider
{
    /// <inheritdoc />
    public V2Algorithm Algorithm { get; } = V2Catalog.ByCode("EUCLIDESAFFINE")!;

    /// <inheritdoc />
    public JsonObject Profile() => new()
    {
        ["algorithmId"] = Algorithm.Id,
        ["algorithmCode"] = Algorithm.Code,
        ["variants"] = new JsonArray("AFFINE-MOD256", "AFFINE-MOD26"),
        ["operations"] = new JsonObject
        {
            ["forward"] = new JsonObject { ["name"] = "cifrar", ["inputs"] = new JsonArray("payload") },
            ["inverse"] = new JsonObject { ["name"] = "descifrar", ["inputs"] = new JsonArray("package") }
        },
        ["secretParameters"] = new JsonArray(
            new JsonObject { ["name"] = "a", ["type"] = "integer", ["description"] = "Coprimo con el módulo (con 256: impar)", ["requiredFor"] = new JsonArray("forward", "inverse") },
            new JsonObject { ["name"] = "b", ["type"] = "integer", ["description"] = "Desplazamiento", ["requiredFor"] = new JsonArray("forward", "inverse") }),
        ["options"] = new JsonArray(
            new JsonObject { ["name"] = "modulus", ["type"] = "enum", ["values"] = new JsonArray("256", "26"), ["default"] = "256" }),
        ["publicParameters"] = new JsonArray("modulus"),
        ["payloadModes"] = new JsonArray("text", "file", "image"),
        ["maxPayloadBytes"] = V2Format.MaxBodyBytes,
        ["notes"] = "Con modulus=26 solo se transforman letras ASCII A-Z/a-z; con 256 se transforma cada byte."
    };

    /// <inheritdoc />
    public V2ForwardOutput Forward(V2ForwardInput input)
    {
        var modulus = ReadModulus(input.Options.TryGetValue("modulus", out var m) ? m : "256");
        var (a, b) = ReadKey(input.Secrets, modulus);
        return new V2ForwardOutput(
            Transform(input.Payload, modulus, x => Mod((a * x) + b, modulus)),
            new Dictionary<string, string> { ["modulus"] = modulus.ToString(CultureInfo.InvariantCulture) },
            input.PayloadMode,
            $"Afín mod {modulus}");
    }

    /// <inheritdoc />
    public V2InverseOutput Inverse(byte[] data, IReadOnlyDictionary<string, string> publicParameters, IReadOnlyDictionary<string, string> secrets)
    {
        var modulus = ReadModulus(publicParameters.TryGetValue("modulus", out var m) ? m : "256");
        var (a, b) = ReadKey(secrets, modulus);
        var aInverse = ModInverse(a, modulus);
        return new V2InverseOutput(Transform(data, modulus, y => Mod(aInverse * (y - b), modulus)));
    }

    /// <summary>Euclides extendido: devuelve (mcd, x, y) con a·x + b·y = mcd.</summary>
    public static (long Gcd, long X, long Y) ExtendedGcd(long a, long b)
    {
        long oldR = a, r = b, oldS = 1, s = 0, oldT = 0, t = 1;
        while (r != 0)
        {
            var q = oldR / r;
            (oldR, r) = (r, oldR - (q * r));
            (oldS, s) = (s, oldS - (q * s));
            (oldT, t) = (t, oldT - (q * t));
        }

        return (oldR, oldS, oldT);
    }

    /// <summary>Inverso modular por Euclides extendido.</summary>
    public static long ModInverse(long a, long modulus)
    {
        var (gcd, x, _) = ExtendedGcd(Mod(a, modulus), modulus);
        if (gcd != 1)
        {
            throw new V2ProtocolException("E-PARAMS", $"a={a} no es coprimo con {modulus} (mcd={gcd}); no tiene inverso.");
        }

        return Mod(x, modulus);
    }

    private static byte[] Transform(byte[] input, int modulus, Func<long, long> f)
    {
        var output = new byte[input.Length];
        for (var i = 0; i < input.Length; i++)
        {
            var value = input[i];
            if (modulus == 256)
            {
                output[i] = (byte)f(value);
            }
            else if (value is >= (byte)'A' and <= (byte)'Z')
            {
                output[i] = (byte)('A' + f(value - 'A'));
            }
            else if (value is >= (byte)'a' and <= (byte)'z')
            {
                output[i] = (byte)('a' + f(value - 'a'));
            }
            else
            {
                output[i] = value;
            }
        }

        return output;
    }

    private static int ReadModulus(string text) => text switch
    {
        "256" => 256,
        "26" => 26,
        _ => throw new V2ProtocolException("E-PARAMS", "modulus debe ser 26 o 256.")
    };

    private static (long A, long B) ReadKey(IReadOnlyDictionary<string, string> secrets, int modulus)
    {
        if (!secrets.TryGetValue("a", out var aText) || !long.TryParse(aText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var a)
            || !secrets.TryGetValue("b", out var bText) || !long.TryParse(bText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var b))
        {
            throw new V2ProtocolException("E-PARAMS", "EUCLIDESAFFINE requiere los secretos a y b (enteros).");
        }

        _ = ModInverse(a, modulus);
        return (Mod(a, modulus), Mod(b, modulus));
    }

    private static long Mod(long value, long modulus) => ((value % modulus) + modulus) % modulus;
}
