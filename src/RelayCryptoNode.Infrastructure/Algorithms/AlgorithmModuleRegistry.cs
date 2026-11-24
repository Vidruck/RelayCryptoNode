using System.Collections.ObjectModel;
using RelayCryptoNode.Domain.Catalog;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Asymmetric;
using RelayCryptoNode.Infrastructure.Algorithms.Classical;
using RelayCryptoNode.Infrastructure.Algorithms.Integrity;
using RelayCryptoNode.Infrastructure.Algorithms.ModularMath;
using RelayCryptoNode.Infrastructure.Algorithms.PostQuantum;
using RelayCryptoNode.Infrastructure.Algorithms.SecretSharing;
using RelayCryptoNode.Infrastructure.Algorithms.Signature;
using RelayCryptoNode.Infrastructure.Algorithms.Spectral;
using RelayCryptoNode.Infrastructure.Algorithms.Steganography;
using RelayCryptoNode.Infrastructure.Algorithms.Symmetric;
using RelayCryptoNode.Infrastructure.Algorithms.Transposition;

namespace RelayCryptoNode.Infrastructure.Algorithms;

/// <summary>
/// Registro central de infraestructura que expone los 21 módulos criptográficos oficiales por código o estrategia de dominio.
/// </summary>
public sealed class AlgorithmModuleRegistry
{
    private readonly IReadOnlyDictionary<OfficialAlgorithmCode, ISymmetricCipherStrategy> _symmetricByCode;
    private readonly IReadOnlyDictionary<CipherAlgorithmType, ISymmetricCipherStrategy> _symmetricByCipher;
    private readonly IReadOnlyDictionary<OfficialAlgorithmCode, IAsymmetricKeyWrapperPort> _keyWrappersByCode;
    private readonly IReadOnlyDictionary<OfficialAlgorithmCode, IHashingServicePort> _hashersByCode;

    /// <summary>
    /// Módulo de esteganografía LSB (<c>LSBSTEGO</c>).
    /// </summary>
    public LsbStegoModule Steganography { get; }

    /// <summary>
    /// Módulo Euclides Extendido / Afín (<c>EUCLIDESAFFINE</c>).
    /// </summary>
    public EuclidesAffineModule EuclidesAffine { get; }

    /// <summary>
    /// Módulo Miller-Rabin Modular (<c>MILLERRABIN</c>).
    /// </summary>
    public MillerRabinModule MillerRabin { get; }

    /// <summary>
    /// Módulo de permutación Fisher-Yates (<c>FISHERYATES</c>).
    /// </summary>
    public FisherYatesModule FisherYates { get; }

    /// <summary>
    /// Módulo de firma digital RSA-PSS (<c>DIGITALSIG</c>).
    /// </summary>
    public DigitalSignatureRsaPssModule DigitalSignature { get; }

    /// <summary>
    /// Módulo cuántico QKD BB84 / LWE (<c>QUANTUMPQC</c>).
    /// </summary>
    public QuantumPqcModule QuantumPqc { get; }

    /// <summary>
    /// Módulo espectral DFT (<c>DFTSPECTRAL</c>).
    /// </summary>
    public DftSpectralModule DftSpectral { get; }

    /// <summary>
    /// Módulo Shamir GF(256) / Lagrange (<c>LAGRANGESHAMIR</c>).
    /// </summary>
    public LagrangeShamirModule LagrangeShamir { get; }

    /// <summary>
    /// Módulo Lorenz SZ40/42 (<c>LORENZSZ40</c>).
    /// </summary>
    public LorenzSz40Module LorenzSz40 { get; }

    /// <summary>
    /// Módulo XOR en registro (<c>XORASM</c>).
    /// </summary>
    public XorAsmModule XorAsm { get; }

    /// <summary>
    /// Inicializa el registro instanciando los 21 módulos oficiales dedicados.
    /// </summary>
    public AlgorithmModuleRegistry(
        string? rsaPrivateKeyPem = null,
        string? eccPrivateKeyPem = null,
        DiffieHellmanKeyPair? dhKeyPair = null)
    {
        var aesGcm = new AesGcmModule();
        var des = new DesModule();
        var tripleDes = new TripleDesModule();
        var chaCha20 = new ChaCha20Poly1305Module();
        var rsa = new RsaModule(rsaPrivateKeyPem);
        var ecc = new EccModule(eccPrivateKeyPem);
        var dh = new DiffieHellmanModule(dhKeyPair);
        var caesar = new CaesarModule();
        var vigenere = new VigenereModule();
        XorAsm = new XorAsmModule();
        Steganography = new LsbStegoModule();
        EuclidesAffine = new EuclidesAffineModule();
        MillerRabin = new MillerRabinModule();
        FisherYates = new FisherYatesModule();
        var hashSha = new HashShaModule();
        var hmacSha256 = new HmacSha256Module();
        DigitalSignature = new DigitalSignatureRsaPssModule();
        QuantumPqc = new QuantumPqcModule();
        DftSpectral = new DftSpectralModule();
        LagrangeShamir = new LagrangeShamirModule();
        LorenzSz40 = new LorenzSz40Module();

        var symDict = new Dictionary<OfficialAlgorithmCode, ISymmetricCipherStrategy>
        {
            [OfficialAlgorithmCode.AESGCM] = aesGcm,
            [OfficialAlgorithmCode.DES] = des,
            [OfficialAlgorithmCode.TRIPLEDES] = tripleDes,
            [OfficialAlgorithmCode.CHACHA20] = chaCha20,
            [OfficialAlgorithmCode.CAESAR] = caesar,
            [OfficialAlgorithmCode.VIGENERE] = vigenere,
            [OfficialAlgorithmCode.XORASM] = XorAsm,
            [OfficialAlgorithmCode.LSBSTEGO] = Steganography,
            [OfficialAlgorithmCode.EUCLIDESAFFINE] = EuclidesAffine,
            [OfficialAlgorithmCode.MILLERRABIN] = MillerRabin,
            [OfficialAlgorithmCode.FISHERYATES] = FisherYates,
            [OfficialAlgorithmCode.QUANTUMPQC] = QuantumPqc,
            [OfficialAlgorithmCode.DFTSPECTRAL] = DftSpectral,
            [OfficialAlgorithmCode.LAGRANGESHAMIR] = LagrangeShamir,
            [OfficialAlgorithmCode.LORENZSZ40] = LorenzSz40
        };

        _symmetricByCode = new ReadOnlyDictionary<OfficialAlgorithmCode, ISymmetricCipherStrategy>(symDict);
        _symmetricByCipher = new ReadOnlyDictionary<CipherAlgorithmType, ISymmetricCipherStrategy>(
            symDict.Values.ToDictionary(static s => s.Algorithm));

        _keyWrappersByCode = new ReadOnlyDictionary<OfficialAlgorithmCode, IAsymmetricKeyWrapperPort>(
            new Dictionary<OfficialAlgorithmCode, IAsymmetricKeyWrapperPort>
            {
                [OfficialAlgorithmCode.RSA] = rsa,
                [OfficialAlgorithmCode.ECC] = ecc,
                [OfficialAlgorithmCode.DIFFIEHELLMAN] = dh
            });

        _hashersByCode = new ReadOnlyDictionary<OfficialAlgorithmCode, IHashingServicePort>(
            new Dictionary<OfficialAlgorithmCode, IHashingServicePort>
            {
                [OfficialAlgorithmCode.HASHSHA] = hashSha,
                [OfficialAlgorithmCode.HMACSHA256] = hmacSha256
            });
    }

    /// <summary>
    /// Obtiene todos los descriptores oficiales del catálogo (21 módulos).
    /// </summary>
    public IReadOnlyList<Domain.ValueObjects.AlgorithmDescriptor> GetCatalog() => OfficialAlgorithmCatalog.GetAll();

    /// <summary>
    /// Resuelve la estrategia simétrica para un <see cref="CipherAlgorithmType"/>.
    /// </summary>
    public ISymmetricCipherStrategy ResolveCipherStrategy(CipherAlgorithmType algorithm)
    {
        if (_symmetricByCipher.TryGetValue(algorithm, out var strategy))
        {
            return strategy;
        }

        throw new UnsupportedAlgorithmException(algorithm.ToString());
    }

    /// <summary>
    /// Resuelve la estrategia simétrica a partir del código o alias oficial.
    /// </summary>
    public ISymmetricCipherStrategy ResolveCipherStrategy(string officialCodeOrAlias)
    {
        var code = OfficialAlgorithmCatalog.ParseOrThrow(officialCodeOrAlias);
        if (_symmetricByCode.TryGetValue(code, out var strategy))
        {
            return strategy;
        }

        throw new UnsupportedAlgorithmException(officialCodeOrAlias, $"El módulo '{code}' no opera como cifrador simétrico de carga útil.");
    }

    /// <summary>
    /// Resuelve un adaptador de intercambio/envoltura de clave por su código oficial.
    /// </summary>
    public IAsymmetricKeyWrapperPort ResolveKeyWrapper(OfficialAlgorithmCode code)
    {
        if (_keyWrappersByCode.TryGetValue(code, out var wrapper))
        {
            return wrapper;
        }

        throw new UnsupportedAlgorithmException(code.ToString());
    }

    /// <summary>
    /// Resuelve un servicio de integridad/MAC por su código oficial (<c>HASHSHA</c> o <c>HMACSHA256</c>).
    /// </summary>
    public IHashingServicePort ResolveHashingService(OfficialAlgorithmCode code)
    {
        if (_hashersByCode.TryGetValue(code, out var hasher))
        {
            return hasher;
        }

        throw new UnsupportedAlgorithmException(code.ToString());
    }

    /// <summary>
    /// Verifica si un código oficial cuenta con un módulo activo registrado en Infraestructura.
    /// </summary>
    public bool IsModuleImplemented(OfficialAlgorithmCode code) =>
        _symmetricByCode.ContainsKey(code)
        || _keyWrappersByCode.ContainsKey(code)
        || _hashersByCode.ContainsKey(code)
        || code == OfficialAlgorithmCode.DIGITALSIG;
}
