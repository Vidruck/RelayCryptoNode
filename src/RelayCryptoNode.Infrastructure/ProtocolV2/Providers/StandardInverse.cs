using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace RelayCryptoNode.Infrastructure.ProtocolV2.Providers;

/// <summary>
/// Modo v4: descifra en este nodo paquetes de OTROS equipos siguiendo la tabla 4.2 del estándar,
/// cuando el usuario tiene la clave (o el algoritmo no la necesita). Así no hace falta que el dueño
/// esté conectado. Algoritmos con llave guardada por el dueño (RSA, ECC, DH, MILLERRABIN, PQC…) siguen
/// necesitando al dueño.
/// </summary>
public static class StandardInverse
{
    /// <summary>Algoritmos que se pueden invertir en local con el formato del estándar.</summary>
    public static readonly IReadOnlyDictionary<string, string?> Supported = new Dictionary<string, string?>(StringComparer.Ordinal)
    {
        ["AESGCM"] = "key",
        ["DES"] = "key",
        ["TRIPLEDES"] = "key",
        ["CHACHA20"] = "key",
        ["CAESAR"] = "shift",
        ["VIGENERE"] = "key",
        ["HMACSHA256"] = "key",
        ["HASHSHA"] = null
    };

    /// <summary>¿Se puede hacer local con lo que escribió el usuario?</summary>
    public static bool CanRun(string code, IReadOnlyDictionary<string, string> secrets) =>
        Supported.TryGetValue(code, out var needed)
        && (needed is null || !string.IsNullOrWhiteSpace(secrets.GetValueOrDefault(needed)));

    /// <summary>Ejecuta el inverse con el formato del estándar.</summary>
    public static V2InverseOutput Run(string code, byte[] data, IReadOnlyDictionary<string, string> p, IReadOnlyDictionary<string, string> secrets, string packetId)
    {
        try
        {
            return code switch
            {
                "AESGCM" => new V2InverseOutput(Gcm(data, p, Key(secrets, "key", 16, 32), packetId, chacha: false)),
                "CHACHA20" => new V2InverseOutput(Gcm(data, p, Key(secrets, "key", 32), packetId, chacha: true)),
                "DES" => new V2InverseOutput(Cbc(DES.Create(), data, p, Key(secrets, "key", 8))),
                "TRIPLEDES" => new V2InverseOutput(Cbc(TripleDES.Create(), data, p, Key(secrets, "key", 24, 16))),
                "CAESAR" => new V2InverseOutput(Caesar(data, p, secrets)),
                "VIGENERE" => new V2InverseOutput(Vigenere(data, p, secrets)),
                "HASHSHA" => HashCheck(data, p),
                "HMACSHA256" => HmacCheck(data, p, Key(secrets, "key", 0)),
                _ => throw new V2ProtocolException("E-ALGORITHM", $"{code} no se puede invertir en local; lo invierte su dueño.")
            };
        }
        catch (CryptographicException)
        {
            throw new V2ProtocolException("E-PARAMS", "No se pudo descifrar en local: la clave no corresponde a ese paquete.");
        }
        catch (FormatException)
        {
            throw new V2ProtocolException("E-PARAMS", "Algún valor en Base64 no es válido (clave, iv, nonce o tag).");
        }
    }

    /// <summary>Clave en Base64 (como pide el estándar); si no es Base64 válido o no mide lo esperado, se usan sus bytes UTF-8.</summary>
    private static byte[] Key(IReadOnlyDictionary<string, string> secrets, string name, params int[] sizes)
    {
        var text = secrets.GetValueOrDefault(name)?.Trim() ?? string.Empty;
        if (text.Length == 0)
        {
            throw new V2ProtocolException("E-PARAMS", $"Falta el secreto {name}.");
        }

        byte[]? decoded = null;
        try
        {
            decoded = Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
        }

        var accepts = (byte[] k) => sizes.Length == 0 || sizes.Contains(0) || sizes.Contains(k.Length);
        if (decoded is not null && accepts(decoded))
        {
            return decoded;
        }

        var raw = Encoding.UTF8.GetBytes(text);
        if (accepts(raw))
        {
            return raw;
        }

        throw new V2ProtocolException("E-PARAMS", $"La clave debe medir {string.Join(" o ", sizes)} bytes (en Base64).");
    }

    private static string Param(IReadOnlyDictionary<string, string> p, params string[] names) =>
        names.Select(p.GetValueOrDefault).FirstOrDefault(v => !string.IsNullOrEmpty(v))
        ?? throw new V2ProtocolException("E-PARAMS", $"Falta {names[0]} en publicParameters.");

    private static byte[] Gcm(byte[] data, IReadOnlyDictionary<string, string> p, byte[] key, string packetId, bool chacha)
    {
        var nonce = Convert.FromBase64String(Param(p, "nonceBase64", "nonce", "ivBase64", "iv"));
        var tagText = p.GetValueOrDefault("tagBase64") ?? p.GetValueOrDefault("tag");
        byte[] tag, cipher;
        if (!string.IsNullOrEmpty(tagText))
        {
            tag = Convert.FromBase64String(tagText);
            cipher = data;
        }
        else
        {
            tag = data[^16..];
            cipher = data[..^16];
        }

        var aads = new[] { p.GetValueOrDefault(AesGcmV3Provider.PacketIdHint) ?? packetId, packetId, string.Empty }.Distinct();
        var plain = new byte[cipher.Length];
        foreach (var aad in aads)
        {
            try
            {
                if (chacha)
                {
                    using var c = new ChaCha20Poly1305(key);
                    c.Decrypt(nonce, cipher, tag, plain, Encoding.UTF8.GetBytes(aad));
                }
                else
                {
                    using var g = new AesGcm(key, tag.Length);
                    g.Decrypt(nonce, cipher, tag, plain, Encoding.UTF8.GetBytes(aad));
                }

                return plain;
            }
            catch (CryptographicException)
            {
            }
        }

        throw new CryptographicException();
    }

    private static byte[] Cbc(SymmetricAlgorithm algorithm, byte[] data, IReadOnlyDictionary<string, string> p, byte[] key)
    {
        using (algorithm)
        {
            algorithm.Key = key;
            var iv = Convert.FromBase64String(Param(p, "ivBase64", "iv"));
            var padding = (p.GetValueOrDefault("padding") ?? "PKCS7").ToUpperInvariant() switch
            {
                "NONE" => PaddingMode.None,
                "ZEROS" => PaddingMode.Zeros,
                _ => PaddingMode.PKCS7
            };
            return (p.GetValueOrDefault("mode") ?? "CBC").ToUpperInvariant() == "ECB"
                ? algorithm.DecryptEcb(data, padding)
                : algorithm.DecryptCbc(data, iv, padding);
        }
    }

    private static bool ByteAlphabet(IReadOnlyDictionary<string, string> p) =>
        string.Equals(p.GetValueOrDefault("alphabet"), "BYTE", StringComparison.OrdinalIgnoreCase);

    private static byte[] Caesar(byte[] data, IReadOnlyDictionary<string, string> p, IReadOnlyDictionary<string, string> secrets)
    {
        if (!int.TryParse(secrets.GetValueOrDefault("shift")?.Trim(), out var shift))
        {
            throw new V2ProtocolException("E-PARAMS", "shift debe ser un número entero.");
        }

        return ByteAlphabet(p)
            ? data.Select(b => (byte)(((b - shift) % 256 + 256) % 256)).ToArray()
            : Encoding.UTF8.GetBytes(new string(Encoding.UTF8.GetString(data).Select(c => ShiftLetter(c, -shift)).ToArray()));
    }

    private static byte[] Vigenere(byte[] data, IReadOnlyDictionary<string, string> p, IReadOnlyDictionary<string, string> secrets)
    {
        var key = secrets.GetValueOrDefault("key") ?? string.Empty;
        if (ByteAlphabet(p))
        {
            var k = Encoding.UTF8.GetBytes(key);
            return data.Select((b, i) => (byte)((b - k[i % k.Length] + 256) % 256)).ToArray();
        }

        var letters = key.Where(char.IsLetter).Select(c => char.ToUpperInvariant(c) - 'A').ToArray();
        if (letters.Length == 0)
        {
            throw new V2ProtocolException("E-PARAMS", "La clave de Vigenère debe tener letras A-Z.");
        }

        var text = Encoding.UTF8.GetString(data);
        var sb = new StringBuilder(text.Length);
        var j = 0;
        foreach (var c in text)
        {
            if (c is >= 'A' and <= 'Z' or >= 'a' and <= 'z')
            {
                sb.Append(ShiftLetter(c, -letters[j++ % letters.Length]));
            }
            else
            {
                sb.Append(c);
            }
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static char ShiftLetter(char c, int shift)
    {
        if (c is >= 'A' and <= 'Z')
        {
            return (char)('A' + (((c - 'A' + shift) % 26) + 26) % 26);
        }

        return c is >= 'a' and <= 'z' ? (char)('a' + (((c - 'a' + shift) % 26) + 26) % 26) : c;
    }

    private static V2InverseOutput HashCheck(byte[] data, IReadOnlyDictionary<string, string> p)
    {
        var algorithm = (p.GetValueOrDefault("hashAlgorithm") ?? "SHA-256").ToUpperInvariant();
        var digest = algorithm switch
        {
            "SHA-512" => SHA512.HashData(data),
            "SHA3-256" => SHA3_256.IsSupported ? SHA3_256.HashData(data) : throw new V2ProtocolException("E-ALGORITHM", "SHA3-256 no está disponible en esta máquina."),
            _ => SHA256.HashData(data)
        };
        return Verdict(data, Convert.ToHexString(digest), Param(p, "digestHex"), algorithm);
    }

    private static V2InverseOutput HmacCheck(byte[] data, IReadOnlyDictionary<string, string> p, byte[] key)
    {
        var algorithm = (p.GetValueOrDefault("macAlgorithm") ?? "HMAC-SHA256").ToUpperInvariant();
        var mac = algorithm == "HMAC-SHA512" ? HMACSHA512.HashData(key, data) : HMACSHA256.HashData(key, data);
        return Verdict(data, Convert.ToHexString(mac), Param(p, "macHex"), algorithm);
    }

    private static V2InverseOutput Verdict(byte[] data, string computed, string expected, string algorithm)
    {
        var valid = string.Equals(computed, expected.Trim(), StringComparison.OrdinalIgnoreCase);
        return new V2InverseOutput(data, new JsonObject
        {
            ["valid"] = valid,
            ["detail"] = valid ? $"{algorithm}: coincide." : $"{algorithm}: NO coincide (calculado {computed[..16]}…)."
        });
    }
}
