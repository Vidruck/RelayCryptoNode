using System.Collections.ObjectModel;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Domain.Catalog;

/// <summary>
/// Registro canónico central de los 21 algoritmos oficiales soportados por RelayCryptoNode.
/// </summary>
public static class OfficialAlgorithmCatalog
{
    private static readonly IReadOnlyList<AlgorithmDescriptor> Descriptors =
        new ReadOnlyCollection<AlgorithmDescriptor>(
        [
            new(OfficialAlgorithmCode.AESGCM, "AESGCM", "AES-256-GCM", AlgorithmCategory.SymmetricCipher,
                cipherAlgorithm: CipherAlgorithmType.Aes256Gcm,
                acceptedAliases: ["AES-256-GCM", "AES256GCM", "Aes256Gcm"]),
            new(OfficialAlgorithmCode.DES, "DES", "DES 56-bit", AlgorithmCategory.SymmetricCipher,
                cipherAlgorithm: CipherAlgorithmType.Des,
                acceptedAliases: ["DES56", "DES-CBC", "Des"]),
            new(OfficialAlgorithmCode.TRIPLEDES, "TRIPLEDES", "Triple DES / 3DES", AlgorithmCategory.SymmetricCipher,
                cipherAlgorithm: CipherAlgorithmType.TripleDes,
                acceptedAliases: ["3DES", "TRIPLE-DES", "TDEA", "TripleDes"]),
            new(OfficialAlgorithmCode.CHACHA20, "CHACHA20", "ChaCha20-Poly1305", AlgorithmCategory.SymmetricCipher,
                cipherAlgorithm: CipherAlgorithmType.ChaCha20Poly1305,
                acceptedAliases: ["CHACHA20-POLY1305", "CHACHA20POLY1305", "ChaCha20Poly1305"]),
            new(OfficialAlgorithmCode.RSA, "RSA", "RSA-OAEP / RSA-PSS", AlgorithmCategory.AsymmetricKeyExchange,
                keyExchangeAlgorithm: KeyExchangeAlgorithmType.RsaOaepSha256,
                signatureAlgorithm: SignatureAlgorithmType.RsaPssSha256,
                acceptedAliases: ["RSA-OAEP", "RSA-OAEP-SHA256", "RsaOaepSha256"]),
            new(OfficialAlgorithmCode.ECC, "ECC", "ECDH / ECDSA", AlgorithmCategory.AsymmetricKeyExchange,
                keyExchangeAlgorithm: KeyExchangeAlgorithmType.EcdhP256,
                signatureAlgorithm: SignatureAlgorithmType.EcdsaP256,
                acceptedAliases: ["ECDH", "ECDSA", "ECDH-P256", "ECDSA-P256", "EcdhP256", "EcdsaP256"]),
            new(OfficialAlgorithmCode.DIFFIEHELLMAN, "DIFFIEHELLMAN", "Diffie-Hellman", AlgorithmCategory.AsymmetricKeyExchange,
                keyExchangeAlgorithm: KeyExchangeAlgorithmType.DiffieHellman,
                acceptedAliases: ["DH", "DIFFIE-HELLMAN", "DiffieHellman"]),
            new(OfficialAlgorithmCode.CAESAR, "CAESAR", "Cifrado César", AlgorithmCategory.ClassicalAndTransposition,
                cipherAlgorithm: CipherAlgorithmType.Caesar,
                acceptedAliases: ["CESAR", "CIFRADO-CESAR", "Caesar"]),
            new(OfficialAlgorithmCode.VIGENERE, "VIGENERE", "Cifrado Vigenère", AlgorithmCategory.ClassicalAndTransposition,
                cipherAlgorithm: CipherAlgorithmType.Vigenere,
                acceptedAliases: ["VIGENÈRE", "CIFRADO-VIGENERE", "Vigenere"]),
            new(OfficialAlgorithmCode.XORASM, "XORASM", "XOR en Registro", AlgorithmCategory.ClassicalAndTransposition,
                cipherAlgorithm: CipherAlgorithmType.XorAsm,
                acceptedAliases: ["XOR-ASM", "XOR-REGISTRO", "XorAsm"]),
            new(OfficialAlgorithmCode.LSBSTEGO, "LSBSTEGO", "Esteganografía LSB en PNG/BMP", AlgorithmCategory.Steganography,
                cipherAlgorithm: CipherAlgorithmType.LsbStego,
                acceptedAliases: ["LSB-STEGO", "STEGO-LSB", "LsbStego"]),
            new(OfficialAlgorithmCode.EUCLIDESAFFINE, "EUCLIDESAFFINE", "Euclides Extendido / Afín", AlgorithmCategory.ModularMath,
                cipherAlgorithm: CipherAlgorithmType.EuclidesAffine,
                acceptedAliases: ["EUCLIDES-AFIN", "AFFINE", "EuclidesAffine"]),
            new(OfficialAlgorithmCode.MILLERRABIN, "MILLERRABIN", "Miller-Rabin Modular", AlgorithmCategory.ModularMath,
                cipherAlgorithm: CipherAlgorithmType.MillerRabin,
                acceptedAliases: ["MILLER-RABIN", "MillerRabin"]),
            new(OfficialAlgorithmCode.FISHERYATES, "FISHERYATES", "Permutación Fisher-Yates", AlgorithmCategory.ClassicalAndTransposition,
                cipherAlgorithm: CipherAlgorithmType.FisherYates,
                acceptedAliases: ["FISHER-YATES", "FisherYates"]),
            new(OfficialAlgorithmCode.HASHSHA, "HASHSHA", "SHA-256 / SHA-512", AlgorithmCategory.HashingAndMac,
                hashAlgorithm: HashAlgorithmType.Sha256,
                acceptedAliases: ["SHA256", "SHA-256", "SHA512", "SHA-512", "HashSha"]),
            new(OfficialAlgorithmCode.HMACSHA256, "HMACSHA256", "HMAC-SHA256", AlgorithmCategory.HashingAndMac,
                hashAlgorithm: HashAlgorithmType.HmacSha256,
                acceptedAliases: ["HMAC-SHA256", "HmacSha256"]),
            new(OfficialAlgorithmCode.DIGITALSIG, "DIGITALSIG", "Firma Digital RSA-PSS", AlgorithmCategory.DigitalSignature,
                signatureAlgorithm: SignatureAlgorithmType.RsaPssSha256,
                acceptedAliases: ["RSA-PSS", "RSA-PSS-SHA256", "RsaPssSha256", "DigitalSig"]),
            new(OfficialAlgorithmCode.QUANTUMPQC, "QUANTUMPQC", "Simulación QKD BB84 / LWE", AlgorithmCategory.PostQuantumSimulation,
                cipherAlgorithm: CipherAlgorithmType.QuantumPqc,
                keyExchangeAlgorithm: KeyExchangeAlgorithmType.QuantumPqcBb84Lwe,
                acceptedAliases: ["BB84", "LWE", "QKD-BB84", "QuantumPqc"]),
            new(OfficialAlgorithmCode.DFTSPECTRAL, "DFTSPECTRAL", "Transformada Discreta de Fourier", AlgorithmCategory.SpectralTransform,
                cipherAlgorithm: CipherAlgorithmType.DftSpectral,
                acceptedAliases: ["DFT", "DFT-SPECTRAL", "DftSpectral"]),
            new(OfficialAlgorithmCode.LAGRANGESHAMIR, "LAGRANGESHAMIR", "Umbral Shamir GF(256)", AlgorithmCategory.SecretSharing,
                cipherAlgorithm: CipherAlgorithmType.LagrangeShamir,
                acceptedAliases: ["SHAMIR", "LAGRANGE-SHAMIR", "SHAMIR-GF256", "LagrangeShamir"]),
            new(OfficialAlgorithmCode.LORENZSZ40, "LORENZSZ40", "Cifrado Lorenz SZ40/42", AlgorithmCategory.ClassicalAndTransposition,
                cipherAlgorithm: CipherAlgorithmType.LorenzSz40,
                acceptedAliases: ["LORENZ", "LORENZ-SZ40", "LORENZ-SZ42", "LorenzSz40"])
        ]);

    private static readonly Dictionary<OfficialAlgorithmCode, AlgorithmDescriptor> ByCode =
        Descriptors.ToDictionary(static d => d.Code);

    private static readonly Dictionary<string, OfficialAlgorithmCode> LookupByIdentifier = BuildLookup();

    private static readonly Dictionary<CipherAlgorithmType, OfficialAlgorithmCode> ByCipherAlgorithm =
        Descriptors
            .Where(static d => d.CipherAlgorithm.HasValue)
            .ToDictionary(static d => d.CipherAlgorithm!.Value, static d => d.Code);

    /// <summary>
    /// Obtiene todos los descriptores oficiales del catálogo en orden canónico (21 módulos).
    /// </summary>
    /// <returns>Colección de solo lectura con los 21 algoritmos oficiales.</returns>
    public static IReadOnlyList<AlgorithmDescriptor> GetAll() => Descriptors;

    /// <summary>
    /// Obtiene el descriptor completo correspondiente a un <see cref="OfficialAlgorithmCode"/>.
    /// </summary>
    /// <param name="code">Código oficial del algoritmo.</param>
    /// <returns>Descriptor oficial encontrado.</returns>
    /// <exception cref="UnsupportedAlgorithmException">Se lanza si el código no está registrado.</exception>
    public static AlgorithmDescriptor GetByCode(OfficialAlgorithmCode code)
    {
        if (ByCode.TryGetValue(code, out var descriptor))
        {
            return descriptor;
        }

        throw new UnsupportedAlgorithmException(code.ToString());
    }

    /// <summary>
    /// Intenta resolver un código oficial o alias (tolerante a mayúsculas, guiones y espacios) hacia su <see cref="OfficialAlgorithmCode"/>.
    /// </summary>
    /// <param name="codeOrAlias">Cadena de algoritmo proveniente de manifiesto o configuración.</param>
    /// <param name="code">Código oficial resuelto si la búsqueda tuvo éxito.</param>
    /// <returns><c>true</c> si existe coincidencia en el catálogo oficial; de lo contrario, <c>false</c>.</returns>
    public static bool TryParse(string? codeOrAlias, out OfficialAlgorithmCode code)
    {
        if (string.IsNullOrWhiteSpace(codeOrAlias))
        {
            code = default;
            return false;
        }

        var normalized = NormalizeToken(codeOrAlias);
        return LookupByIdentifier.TryGetValue(normalized, out code);
    }

    /// <summary>
    /// Resuelve un código o alias de algoritmo o lanza <see cref="UnsupportedAlgorithmException"/> si no pertenece al catálogo oficial.
    /// </summary>
    /// <param name="codeOrAlias">Cadena de identificador o alias.</param>
    /// <returns>Código oficial resuelto.</returns>
    /// <exception cref="UnsupportedAlgorithmException">Se lanza si el identificador es nulo o no está registrado.</exception>
    public static OfficialAlgorithmCode ParseOrThrow(string? codeOrAlias)
    {
        if (TryParse(codeOrAlias, out var code))
        {
            return code;
        }

        throw new UnsupportedAlgorithmException(codeOrAlias ?? "<null>");
    }

    /// <summary>
    /// Obtiene el código oficial asociado a un <see cref="CipherAlgorithmType"/>, si existe.
    /// </summary>
    /// <param name="cipherAlgorithm">Tipo de cifrado en el dominio.</param>
    /// <param name="code">Código oficial correspondiente.</param>
    /// <returns><c>true</c> si tiene equivalencia directa en el catálogo oficial.</returns>
    public static bool TryFromCipherAlgorithm(CipherAlgorithmType cipherAlgorithm, out OfficialAlgorithmCode code) =>
        ByCipherAlgorithm.TryGetValue(cipherAlgorithm, out code);

    private static Dictionary<string, OfficialAlgorithmCode> BuildLookup()
    {
        var map = new Dictionary<string, OfficialAlgorithmCode>(StringComparer.Ordinal);
        foreach (var descriptor in Descriptors)
        {
            map[NormalizeToken(descriptor.OfficialCode)] = descriptor.Code;
            map[NormalizeToken(descriptor.DisplayName)] = descriptor.Code;

            foreach (var alias in descriptor.AcceptedAliases)
            {
                map[NormalizeToken(alias)] = descriptor.Code;
            }
        }

        return map;
    }

    private static string NormalizeToken(string token)
    {
        Span<char> buffer = stackalloc char[token.Length];
        var index = 0;

        foreach (var ch in token)
        {
            if (char.IsLetterOrDigit(ch))
            {
                buffer[index++] = char.ToUpperInvariant(ch);
            }
        }

        return new string(buffer[..index]);
    }
}
