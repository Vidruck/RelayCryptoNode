using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms;
using RelayCryptoNode.Infrastructure.Algorithms.Asymmetric;

namespace RelayCryptoNode.Infrastructure.ProtocolV2.Providers;

/// <summary>
/// Modo v3 (extensión del EQ06): el nodo cifra y descifra localmente los 21 algoritmos de la tabla 4.1.
/// Los paquetes que genera siguen siendo v2.0 válidos (misma firma y manifiesto); solo cambia quién ejecuta.
/// </summary>
public static class V3LocalProviders
{
    /// <summary>Arma los 19 proveedores que no tiene el EQ06 por estándar (11 y 12 ya existen).</summary>
    public static IReadOnlyList<IV2AlgorithmProvider> Create(V2Identity identity, string dataDirectory)
    {
        var folder = Path.Combine(dataDirectory, "v3");
        Directory.CreateDirectory(folder);
        var vault = new V3KeyVault(Path.Combine(folder, "llaves.json"));
        var registry = new AlgorithmModuleRegistry();
        var list = new List<IV2AlgorithmProvider>();
        // AESGCM según la tabla 4.2 del estándar: clave secreta de 16/32 bytes, AAD = packetId y keyRef como EQ01.
        list.Add(new AesGcmV3Provider(V2Catalog.ByCode("AESGCM")!, identity.NodeId, vault,
            new SymmetricV3Provider(V2Catalog.ByCode("AESGCM")!, registry.ResolveCipherStrategy("AESGCM"), vault)));
        foreach (var code in new[]
                 {
                     "DES", "TRIPLEDES", "CHACHA20", "CAESAR", "VIGENERE", "XORASM", "MILLERRABIN",
                     "FISHERYATES", "QUANTUMPQC", "DFTSPECTRAL", "LAGRANGESHAMIR", "LORENZSZ40"
                 })
        {
            list.Add(new SymmetricV3Provider(V2Catalog.ByCode(code)!, registry.ResolveCipherStrategy(code), vault));
        }

        list.Add(new HybridV3Provider(V2Catalog.ByCode("RSA")!, HybridV3Provider.Kind.Rsa, identity, folder));
        list.Add(new HybridV3Provider(V2Catalog.ByCode("ECC")!, HybridV3Provider.Kind.Ecc, identity, folder));
        list.Add(new HybridV3Provider(V2Catalog.ByCode("DIFFIEHELLMAN")!, HybridV3Provider.Kind.DiffieHellman, identity, folder));
        list.Add(new IntegrityV3Provider(V2Catalog.ByCode("HASHSHA")!, IntegrityV3Provider.Kind.Hash, identity, vault));
        list.Add(new IntegrityV3Provider(V2Catalog.ByCode("HMACSHA256")!, IntegrityV3Provider.Kind.Hmac, identity, vault));
        list.Add(new IntegrityV3Provider(V2Catalog.ByCode("DIGITALSIG")!, IntegrityV3Provider.Kind.Signature, identity, vault));
        return list;
    }

    internal static JsonObject BasicProfile(V2Algorithm algorithm, JsonArray secrets, JsonArray options, string notes) => new()
    {
        ["algorithmId"] = algorithm.Id,
        ["algorithmCode"] = algorithm.Code,
        ["variants"] = new JsonArray("V3-LOCAL"),
        ["operations"] = new JsonObject
        {
            ["forward"] = new JsonObject { ["name"] = algorithm.ForwardName, ["inputs"] = new JsonArray("payload") },
            ["inverse"] = new JsonObject { ["name"] = algorithm.InverseName, ["inputs"] = new JsonArray("package") }
        },
        ["secretParameters"] = secrets,
        ["options"] = options,
        ["payloadModes"] = new JsonArray("text", "file", "image"),
        ["maxPayloadBytes"] = V2Format.MaxBodyBytes,
        ["notes"] = notes
    };

    internal static JsonObject Secret(string name, string type, string description, bool optional = true) => new()
    {
        ["name"] = name,
        ["type"] = type,
        ["description"] = description,
        ["optional"] = optional,
        ["requiredFor"] = new JsonArray("forward", "inverse")
    };

    /// <summary>Texto canónico de los secretos (llave=valor ordenado) para derivar la clave.</summary>
    internal static string CanonicalSecrets(IReadOnlyDictionary<string, string> secrets) =>
        string.Join("\n", secrets.Where(p => !string.IsNullOrEmpty(p.Value)).OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => p.Key + "=" + p.Value));
}

/// <summary>
/// Guarda los secretos usados en cada forward v3 (por keyId) para poder invertir sin volver a escribirlos.
/// </summary>
public sealed class V3KeyVault
{
    private readonly string _path;
    private readonly object _gate = new();

    /// <summary>Crea el almacén en el archivo indicado.</summary>
    public V3KeyVault(string path) => _path = path;

    /// <summary>Guarda los secretos y regresa el keyId.</summary>
    public string Save(IReadOnlyDictionary<string, string> secrets)
    {
        var id = "v3-" + Guid.NewGuid().ToString("N")[..16];
        lock (_gate)
        {
            var all = Read();
            all[id] = secrets.ToDictionary(p => p.Key, p => p.Value);
            File.WriteAllText(_path, JsonSerializer.Serialize(all));
        }

        return id;
    }

    /// <summary>Guarda los secretos con un keyId ya elegido (formato del estándar: EQ06-KEY-&lt;uuid&gt;).</summary>
    public void SaveAs(string keyId, IReadOnlyDictionary<string, string> secrets)
    {
        lock (_gate)
        {
            var all = Read();
            all[keyId] = secrets.ToDictionary(p => p.Key, p => p.Value);
            File.WriteAllText(_path, JsonSerializer.Serialize(all));
        }
    }

    /// <summary>Busca los secretos de un keyId.</summary>
    public IReadOnlyDictionary<string, string>? Find(string? keyId)
    {
        if (string.IsNullOrEmpty(keyId))
        {
            return null;
        }

        lock (_gate)
        {
            return Read().TryGetValue(keyId, out var found) ? found : null;
        }
    }

    private Dictionary<string, Dictionary<string, string>> Read()
    {
        if (!File.Exists(_path))
        {
            return new Dictionary<string, Dictionary<string, string>>();
        }

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(File.ReadAllText(_path))
                   ?? new Dictionary<string, Dictionary<string, string>>();
        }
        catch (JsonException)
        {
            return new Dictionary<string, Dictionary<string, string>>();
        }
    }
}

/// <summary>Los 13 algoritmos de carga útil del repo (simétricos, clásicos, matemáticos y simulados).</summary>
internal sealed class SymmetricV3Provider : IV2AlgorithmProvider
{
    private readonly ISymmetricCipherStrategy _strategy;
    private readonly V3KeyVault _vault;

    public SymmetricV3Provider(V2Algorithm algorithm, ISymmetricCipherStrategy strategy, V3KeyVault vault)
    {
        Algorithm = algorithm;
        _strategy = strategy;
        _vault = vault;
    }

    public V2Algorithm Algorithm { get; }

    public JsonObject Profile() => V3LocalProviders.BasicProfile(
        Algorithm,
        new JsonArray(V3LocalProviders.Secret("key", "text", "Clave o frase (si la dejas vacía se genera una y se guarda en el nodo)")),
        new JsonArray(),
        "Modo v3: se ejecuta en el EQ06 con el módulo del repositorio.");

    public V2ForwardOutput Forward(V2ForwardInput input)
    {
        var secrets = new Dictionary<string, string>(input.Secrets.Where(p => !string.IsNullOrEmpty(p.Value)));
        if (secrets.Count == 0)
        {
            secrets["key"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        }

        var key = Key(secrets);
        var encrypted = _strategy.Encrypt(input.Payload, key);
        var parameters = new Dictionary<string, string>
        {
            ["mode"] = "v3-local",
            ["ivBase64"] = Convert.ToBase64String(encrypted.IvOrNonce ?? []),
            ["tagBase64"] = Convert.ToBase64String(encrypted.AuthTag ?? []),
            ["keyId"] = _vault.Save(secrets)
        };
        foreach (var pair in input.Options.Where(p => !string.IsNullOrEmpty(p.Value)))
        {
            parameters["opt." + pair.Key] = pair.Value;
        }

        return new V2ForwardOutput(encrypted.Ciphertext, parameters, input.PayloadMode, Algorithm.Name);
    }

    public V2InverseOutput Inverse(byte[] data, IReadOnlyDictionary<string, string> publicParameters, IReadOnlyDictionary<string, string> secrets)
    {
        var used = secrets.Any(p => !string.IsNullOrEmpty(p.Value))
            ? secrets
            : _vault.Find(publicParameters.GetValueOrDefault("keyId"))
              ?? throw new V2ProtocolException("E-PARAMS", "Escribe la clave: este nodo no tiene guardada la de ese paquete.");
        var iv = Convert.FromBase64String(publicParameters.GetValueOrDefault("ivBase64") ?? string.Empty);
        var tag = Convert.FromBase64String(publicParameters.GetValueOrDefault("tagBase64") ?? string.Empty);
        try
        {
            return new V2InverseOutput(_strategy.Decrypt(data, Key(used), iv, tag.Length == 0 ? null : tag));
        }
        catch (CryptographicException ex)
        {
            throw new V2ProtocolException("E-PARAMS", $"No se pudo descifrar ({ex.Message}). ¿La clave es la correcta?");
        }
    }

    private static byte[] Key(IReadOnlyDictionary<string, string> secrets) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(V3LocalProviders.CanonicalSecrets(secrets)));
}

/// <summary>RSA, ECC y Diffie-Hellman como cifrado híbrido con AES-256-GCM y las llaves del nodo.</summary>
internal sealed class HybridV3Provider : IV2AlgorithmProvider
{
    public enum Kind
    {
        Rsa,
        Ecc,
        DiffieHellman
    }

    private readonly Kind _kind;
    private readonly V2Identity _identity;
    private readonly string _folder;

    public HybridV3Provider(V2Algorithm algorithm, Kind kind, V2Identity identity, string folder)
    {
        Algorithm = algorithm;
        _kind = kind;
        _identity = identity;
        _folder = folder;
    }

    public V2Algorithm Algorithm { get; }

    public JsonObject Profile() => V3LocalProviders.BasicProfile(Algorithm, new JsonArray(), new JsonArray(),
        "Modo v3: híbrido AES-256-GCM; la llave de sesión se protege con la llave del EQ06.");

    public V2ForwardOutput Forward(V2ForwardInput input)
    {
        var sessionKey = RandomNumberGenerator.GetBytes(32);
        var parameters = new Dictionary<string, string> { ["mode"] = "v3-local", ["dataCipher"] = "AES-256-GCM" };
        switch (_kind)
        {
            case Kind.Rsa:
                using (var rsa = RSA.Create())
                {
                    rsa.ImportFromPem(PublicKeyPem());
                    parameters["wrappedKeyBase64"] = Convert.ToBase64String(rsa.Encrypt(sessionKey, RSAEncryptionPadding.OaepSHA256));
                    parameters["keyWrap"] = "RSA-OAEP-SHA256";
                }

                break;
            case Kind.Ecc:
                using (var local = EccKey())
                using (var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
                {
                    var shared = ephemeral.DeriveKeyFromHash(local.PublicKey, HashAlgorithmName.SHA256);
                    parameters["ephemeralPublicKeyBase64"] = Convert.ToBase64String(ephemeral.ExportSubjectPublicKeyInfo());
                    parameters["keyWrap"] = "ECDH-P256-SHA256";
                    sessionKey = shared;
                }

                break;
            default:
                var (_, pub) = DhKey();
                var ephemeralPair = DiffieHellmanModule.GenerateKeyPair();
                sessionKey = SHA256.HashData(DiffieHellmanModule.DeriveSharedKey(ephemeralPair.PrivateExponent, pub));
                parameters["ephemeralPublicKeyBase64"] = Convert.ToBase64String(ephemeralPair.PublicKeyBytes);
                parameters["keyWrap"] = "DH-MODP2048-SHA256";
                break;
        }

        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[input.Payload.Length];
        using (var aes = new AesGcm(sessionKey, 16))
        {
            aes.Encrypt(nonce, input.Payload, cipher, tag);
        }

        parameters["nonceBase64"] = Convert.ToBase64String(nonce);
        parameters["tagBase64"] = Convert.ToBase64String(tag);
        return new V2ForwardOutput(cipher, parameters, input.PayloadMode, Algorithm.Name);
    }

    public V2InverseOutput Inverse(byte[] data, IReadOnlyDictionary<string, string> publicParameters, IReadOnlyDictionary<string, string> secrets)
    {
        byte[] sessionKey;
        try
        {
            switch (_kind)
            {
                case Kind.Rsa:
                    using (var rsa = RSA.Create())
                    {
                        rsa.ImportFromPem(_identity.PrivateKeyPem);
                        sessionKey = rsa.Decrypt(Convert.FromBase64String(publicParameters["wrappedKeyBase64"]), RSAEncryptionPadding.OaepSHA256);
                    }

                    break;
                case Kind.Ecc:
                    using (var local = EccKey())
                    using (var ephemeral = ECDiffieHellman.Create())
                    {
                        ephemeral.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicParameters["ephemeralPublicKeyBase64"]), out _);
                        sessionKey = local.DeriveKeyFromHash(ephemeral.PublicKey, HashAlgorithmName.SHA256);
                    }

                    break;
                default:
                    var (priv, _) = DhKey();
                    sessionKey = SHA256.HashData(DiffieHellmanModule.DeriveSharedKey(priv, Convert.FromBase64String(publicParameters["ephemeralPublicKeyBase64"])));
                    break;
            }

            var plain = new byte[data.Length];
            using var aes = new AesGcm(sessionKey, 16);
            aes.Decrypt(Convert.FromBase64String(publicParameters["nonceBase64"]), data, Convert.FromBase64String(publicParameters["tagBase64"]), plain);
            return new V2InverseOutput(plain);
        }
        catch (Exception ex) when (ex is CryptographicException or KeyNotFoundException or FormatException)
        {
            throw new V2ProtocolException("E-PARAMS", $"No se pudo descifrar: el paquete no se generó con las llaves de este nodo ({ex.Message}).");
        }
    }

    private string PublicKeyPem()
    {
        using var certificate = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(_identity.CertificatePem);
        using var key = certificate.GetRSAPublicKey()!;
        return key.ExportSubjectPublicKeyInfoPem();
    }

    private ECDiffieHellman EccKey()
    {
        var path = Path.Combine(_folder, "ecc-p256.pem");
        var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(path))
        {
            key.ImportFromPem(File.ReadAllText(path));
        }
        else
        {
            File.WriteAllText(path, key.ExportPkcs8PrivateKeyPem());
        }

        return key;
    }

    private (BigInteger Private, byte[] Public) DhKey()
    {
        var path = Path.Combine(_folder, "dh-modp2048.json");
        if (File.Exists(path))
        {
            var saved = JsonNode.Parse(File.ReadAllText(path))!;
            return (BigInteger.Parse(saved["private"]!.GetValue<string>()), Convert.FromBase64String(saved["public"]!.GetValue<string>()));
        }

        var pair = DiffieHellmanModule.GenerateKeyPair();
        File.WriteAllText(path, new JsonObject
        {
            ["private"] = pair.PrivateExponent.ToString(),
            ["public"] = Convert.ToBase64String(pair.PublicKeyBytes)
        }.ToJsonString());
        return (pair.PrivateExponent, pair.PublicKeyBytes);
    }
}

/// <summary>Hash, HMAC y firma digital: el forward agrega la prueba y el inverse la verifica.</summary>
internal sealed class IntegrityV3Provider : IV2AlgorithmProvider
{
    public enum Kind
    {
        Hash,
        Hmac,
        Signature
    }

    private readonly Kind _kind;
    private readonly V2Identity _identity;
    private readonly V3KeyVault _vault;

    public IntegrityV3Provider(V2Algorithm algorithm, Kind kind, V2Identity identity, V3KeyVault vault)
    {
        Algorithm = algorithm;
        _kind = kind;
        _identity = identity;
        _vault = vault;
    }

    public V2Algorithm Algorithm { get; }

    public JsonObject Profile() => V3LocalProviders.BasicProfile(
        Algorithm,
        _kind == Kind.Hmac ? new JsonArray(V3LocalProviders.Secret("key", "text", "Clave del HMAC (vacía = se genera)")) : new JsonArray(),
        _kind == Kind.Hash
            ? new JsonArray(new JsonObject { ["name"] = "hashAlgorithm", ["type"] = "enum", ["values"] = new JsonArray("SHA-256", "SHA-512", "SHA-384"), ["default"] = "SHA-256" })
            : new JsonArray(),
        "Modo v3: datos.enc lleva el archivo original y publicParameters la prueba; el inverse la verifica.");

    public V2ForwardOutput Forward(V2ForwardInput input)
    {
        var parameters = new Dictionary<string, string> { ["mode"] = "v3-local" };
        switch (_kind)
        {
            case Kind.Hash:
                var name = input.Options.GetValueOrDefault("hashAlgorithm") ?? "SHA-256";
                parameters["hashAlgorithm"] = name;
                parameters["digestHex"] = Convert.ToHexString(Digest(name, input.Payload)).ToLowerInvariant();
                break;
            case Kind.Hmac:
                var secrets = new Dictionary<string, string>(input.Secrets.Where(p => !string.IsNullOrEmpty(p.Value)));
                if (secrets.Count == 0)
                {
                    secrets["key"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                }

                parameters["macAlgorithm"] = "HMAC-SHA256";
                parameters["macHex"] = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(V3LocalProviders.CanonicalSecrets(secrets)), input.Payload)).ToLowerInvariant();
                parameters["keyId"] = _vault.Save(secrets);
                break;
            default:
                using (var rsa = RSA.Create())
                {
                    rsa.ImportFromPem(_identity.PrivateKeyPem);
                    parameters["signatureAlgorithm"] = "RSA-PSS-SHA256";
                    parameters["signatureBase64"] = Convert.ToBase64String(rsa.SignData(input.Payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
                    parameters["signerThumbprintSha256"] = _identity.Thumbprint;
                }

                break;
        }

        return new V2ForwardOutput(input.Payload, parameters, input.PayloadMode, Algorithm.Name);
    }

    public V2InverseOutput Inverse(byte[] data, IReadOnlyDictionary<string, string> publicParameters, IReadOnlyDictionary<string, string> secrets)
    {
        bool valid;
        switch (_kind)
        {
            case Kind.Hash:
                var name = publicParameters.GetValueOrDefault("hashAlgorithm") ?? "SHA-256";
                valid = string.Equals(Convert.ToHexString(Digest(name, data)), publicParameters.GetValueOrDefault("digestHex"), StringComparison.OrdinalIgnoreCase);
                break;
            case Kind.Hmac:
                var used = secrets.Any(p => !string.IsNullOrEmpty(p.Value))
                    ? secrets
                    : _vault.Find(publicParameters.GetValueOrDefault("keyId"))
                      ?? throw new V2ProtocolException("E-PARAMS", "Escribe la clave del HMAC.");
                var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(V3LocalProviders.CanonicalSecrets(used)), data);
                valid = string.Equals(Convert.ToHexString(mac), publicParameters.GetValueOrDefault("macHex"), StringComparison.OrdinalIgnoreCase);
                break;
            default:
                using (var certificate = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(_identity.CertificatePem))
                using (var rsa = certificate.GetRSAPublicKey()!)
                {
                    valid = rsa.VerifyData(data, Convert.FromBase64String(publicParameters.GetValueOrDefault("signatureBase64") ?? string.Empty),
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                }

                break;
        }

        return new V2InverseOutput(data, new JsonObject { ["valid"] = valid, ["method"] = Algorithm.InverseName });
    }

    private static byte[] Digest(string name, byte[] data) => name.ToUpperInvariant() switch
    {
        "SHA-512" => SHA512.HashData(data),
        "SHA-384" => SHA384.HashData(data),
        _ => SHA256.HashData(data)
    };
}

/// <summary>
/// AESGCM apegado al estándar v2.0 (tabla 4.2 y sección 12, igual que el EQ01):
/// la clave (16 o 32 bytes en Base64) es secreta y nunca va en el manifiesto; publicParameters lleva
/// keySizeBits, nonceBase64 (12 B), tagBase64 (16 B) y keyId; AAD = packetId en UTF-8; keyRef = { keyId, ownerNode }.
/// El nodo guarda la clave con su keyId para poder invertir sin volver a escribirla.
/// </summary>
internal sealed class AesGcmV3Provider : IV2AlgorithmProvider
{
    /// <summary>Clave interna con el packetId real del paquete que se invierte (no viaja).</summary>
    internal const string PacketIdHint = "__packetId";

    private readonly string _nodeId;
    private readonly V3KeyVault _vault;
    private readonly IV2AlgorithmProvider _legacy;

    public AesGcmV3Provider(V2Algorithm algorithm, string nodeId, V3KeyVault vault, IV2AlgorithmProvider legacy)
    {
        Algorithm = algorithm;
        _nodeId = nodeId;
        _vault = vault;
        _legacy = legacy;
    }

    public V2Algorithm Algorithm { get; }

    public JsonObject Profile()
    {
        var key = V3LocalProviders.Secret("key", "base64",
            "Clave secreta AES en Base64 (16 o 32 bytes). Vacía = se genera y se queda guardada en el nodo; nunca va en el manifiesto");
        key["minBytes"] = 16;
        key["maxBytes"] = 32;
        return V3LocalProviders.BasicProfile(
            Algorithm,
            new JsonArray(key),
            new JsonArray(new JsonObject
            {
                ["name"] = "keySizeBits",
                ["type"] = "enum",
                ["values"] = new JsonArray("256", "128"),
                ["default"] = "256"
            }),
            "AES-GCM según la tabla 4.2: publicParameters = keySizeBits, nonceBase64, tagBase64 y keyId; AAD = packetId.");
    }

    public V2ForwardOutput Forward(V2ForwardInput input)
    {
        var bits = input.Options.GetValueOrDefault("keySizeBits") is { Length: > 0 } b ? b : "256";
        if (bits is not ("128" or "256"))
        {
            throw new V2ProtocolException("E-PARAMS", "keySizeBits debe ser 128 o 256.");
        }

        byte[] key;
        if (input.Secrets.GetValueOrDefault("key") is { Length: > 0 } typed)
        {
            key = DecodeKey(typed);
            bits = (key.Length * 8).ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        else
        {
            key = RandomNumberGenerator.GetBytes(bits == "128" ? 16 : 32);
        }

        var packetId = V2Format.NewUuid();
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[input.Payload.Length];
        try
        {
            using (var aes = new AesGcm(key, 16))
            {
                aes.Encrypt(nonce, input.Payload, ciphertext, tag, Encoding.UTF8.GetBytes(packetId));
            }

            var keyId = $"{_nodeId}-KEY-{V2Format.NewUuid()}";
            _vault.SaveAs(keyId, new Dictionary<string, string>
            {
                ["key"] = Convert.ToBase64String(key),
                ["packetId"] = packetId
            });
            var parameters = new Dictionary<string, string>
            {
                ["keySizeBits"] = bits,
                ["nonceBase64"] = Convert.ToBase64String(nonce),
                ["tagBase64"] = Convert.ToBase64String(tag),
                ["keyId"] = keyId
            };
            var keyRef = new JsonObject { ["keyId"] = keyId, ["ownerNode"] = _nodeId };
            return new V2ForwardOutput(ciphertext, parameters, input.PayloadMode, Algorithm.Name, packetId, keyRef);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public V2InverseOutput Inverse(byte[] data, IReadOnlyDictionary<string, string> publicParameters, IReadOnlyDictionary<string, string> secrets)
    {
        // Paquetes v3 viejos (ivBase64 + clave derivada): se siguen abriendo como antes.
        if (publicParameters.ContainsKey("ivBase64") && publicParameters.GetValueOrDefault("mode") == "v3-local")
        {
            return _legacy.Inverse(data, publicParameters, secrets);
        }

        var stored = _vault.Find(publicParameters.GetValueOrDefault("keyId"));
        var keyText = secrets.GetValueOrDefault("key") is { Length: > 0 } typed ? typed : stored?.GetValueOrDefault("key");
        if (string.IsNullOrEmpty(keyText))
        {
            throw new V2ProtocolException("E-KEY-NOT-FOUND", "Este nodo no tiene la clave de ese paquete: escríbela en el campo key (Base64 de 16 o 32 bytes).");
        }

        var key = DecodeKey(keyText);
        try
        {
            var nonce = Convert.FromBase64String(Param(publicParameters, "nonceBase64", "nonce", "ivBase64", "iv"));
            var tag = Convert.FromBase64String(Param(publicParameters, "tagBase64", "tag"));
            var aads = new[] { stored?.GetValueOrDefault("packetId"), publicParameters.GetValueOrDefault(PacketIdHint), string.Empty }
                .Where(a => a is not null).Distinct().ToList();
            using var aes = new AesGcm(key, tag.Length);
            var plaintext = new byte[data.Length];
            foreach (var aad in aads)
            {
                try
                {
                    aes.Decrypt(nonce, data, tag, plaintext, Encoding.UTF8.GetBytes(aad!));
                    return new V2InverseOutput(plaintext);
                }
                catch (CryptographicException)
                {
                }
            }

            throw new V2ProtocolException("E-PARAMS", "No se pudo descifrar: la clave no corresponde a ese paquete.");
        }
        catch (FormatException)
        {
            throw new V2ProtocolException("E-PARAMS", "nonceBase64 o tagBase64 no son Base64 válido.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static string Param(IReadOnlyDictionary<string, string> p, params string[] names) =>
        names.Select(p.GetValueOrDefault).FirstOrDefault(v => !string.IsNullOrEmpty(v))
        ?? throw new V2ProtocolException("E-PARAMS", $"Falta {names[0]} en publicParameters.");

    private static byte[] DecodeKey(string text)
    {
        byte[] key;
        try
        {
            key = Convert.FromBase64String(text.Trim());
        }
        catch (FormatException)
        {
            throw new V2ProtocolException("E-PARAMS", "La clave debe ir en Base64 (16 o 32 bytes).");
        }

        if (key.Length is not (16 or 32))
        {
            throw new V2ProtocolException("E-PARAMS", $"La clave mide {key.Length} bytes; el estándar pide 16 o 32.");
        }

        return key;
    }
}
