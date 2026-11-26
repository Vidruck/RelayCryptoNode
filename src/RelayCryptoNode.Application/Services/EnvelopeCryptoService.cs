using System.Security.Cryptography;
using RelayCryptoNode.Application.Abstractions;
using RelayCryptoNode.Application.Configuration;
using RelayCryptoNode.Domain.Catalog;
using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Application.Services;

/// <summary>
/// Cierra (cifra, envuelve la clave y firma) y abre (desenvuelve y descifra) sobres criptográficos en memoria.
/// </summary>
public sealed class EnvelopeCryptoService
{
    private const int SessionKeySizeBytes = 32;

    private readonly IReadOnlyList<ISymmetricCipherStrategy> _strategies;
    private readonly IReadOnlyList<IAsymmetricKeyWrapperPort> _keyWrappers;
    private readonly ICertificateServicePort _certificates;
    private readonly IHashingServicePort _hashing;
    private readonly IPackageSerializerPort _serializer;
    private readonly NodeRuntimeState _state;
    private readonly ILegacyPayloadCodec? _legacyCodec;

    /// <summary>
    /// Crea el servicio con los módulos de cifrado y envoltura registrados.
    /// </summary>
    public EnvelopeCryptoService(
        IEnumerable<ISymmetricCipherStrategy> strategies,
        IEnumerable<IAsymmetricKeyWrapperPort> keyWrappers,
        ICertificateServicePort certificates,
        IHashingServicePort hashing,
        IPackageSerializerPort serializer,
        NodeRuntimeState state,
        ILegacyPayloadCodec? legacyCodec = null)
    {
        _legacyCodec = legacyCodec;
        _strategies = strategies.ToList();
        _keyWrappers = keyWrappers.ToList();
        _certificates = certificates;
        _hashing = hashing;
        _serializer = serializer;
        _state = state;
    }

    /// <summary>
    /// Cifra la carga útil con una clave de sesión aleatoria, la envuelve para el destino y firma el manifiesto.
    /// </summary>
    public CryptoEnvelope Seal(
        byte[] plaintext,
        OriginalPayloadInfo original,
        CipherAlgorithmType cipherAlgorithm,
        KeyExchangeAlgorithmType keyExchangeAlgorithm,
        SignatureAlgorithmType signatureAlgorithm,
        string? recipientCertificatePem,
        IReadOnlyDictionary<string, string>? extraMetadata = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(original);

        var sharedKeyMode = extraMetadata is not null
                            && extraMetadata.TryGetValue(LegacyFormat.MetadataKey, out var mode)
                            && mode == LegacyFormat.SharedKeyValue;
        var sessionKey = RandomNumberGenerator.GetBytes(SessionKeySizeBytes);
        try
        {
            var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
            byte[] ciphertext;
            CryptoParameters parameters;
            if (sharedKeyMode)
            {
                if (_legacyCodec is null || !_legacyCodec.Supports(cipherAlgorithm))
                {
                    throw new UnsupportedAlgorithmException(
                        cipherAlgorithm.ToString(),
                        $"El modo de clave compartida (compatible con otros equipos) no está disponible para {cipherAlgorithm}.");
                }

                ciphertext = _legacyCodec.Encrypt(plaintext, cipherAlgorithm);
                Merge(metadata, extraMetadata);
                parameters = new CryptoParameters(ciphertext.Length >= 12 ? ciphertext[..12] : [0], extraMetadata: metadata);
            }
            else
            {
                var strategy = ResolveStrategy(cipherAlgorithm);
                var wrapper = ResolveWrapper(keyExchangeAlgorithm);
                var wrap = wrapper.WrapSessionKey(sessionKey, recipientCertificatePem ?? string.Empty);
                var encrypted = strategy.Encrypt(plaintext, sessionKey);
                ciphertext = encrypted.Ciphertext;

                Merge(metadata, encrypted.ExtraMetadata);
                Merge(metadata, wrap.ExtraMetadata);
                Merge(metadata, extraMetadata);

                parameters = new CryptoParameters(
                    encrypted.IvOrNonce,
                    encrypted.AuthTag,
                    wrap.WrappedKey,
                    wrap.Salt,
                    metadata);
            }

            var localPem = _certificates.GetLocalCertificatePem();
            var snapshot = _state.Current;
            var source = new NodeIdentity(
                snapshot.NodeId,
                snapshot.PublicEndpoint,
                _certificates.ComputeThumbprintSha256(localPem));

            var packetId = Guid.NewGuid();
            var timestamp = TruncateToSeconds(DateTimeOffset.UtcNow);
            var encryptedSha = _hashing.ComputeHash(ciphertext);

            CryptoEnvelope Build(byte[] signature) => new(
                packetId,
                source,
                timestamp,
                cipherAlgorithm,
                keyExchangeAlgorithm,
                signatureAlgorithm,
                parameters,
                ciphertext,
                encryptedSha,
                localPem,
                signature,
                original.Sha256,
                original.FileName,
                original.Extension,
                original.SizeBytes);

            var unsigned = Build([0]);
            var canonical = _serializer.GetCanonicalManifestBytes(unsigned);
            var signature = _certificates.SignData(canonical, signatureAlgorithm);
            return Build(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
        }
    }

    /// <summary>
    /// Desenvuelve la clave de sesión con la clave privada local (o la clave precompartida) y descifra en RAM.
    /// </summary>
    public byte[] Open(CryptoEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var wrapped = envelope.Parameters.EncryptedSessionKey;
        if (wrapped is null || wrapped.Length == 0)
        {
            if (_legacyCodec is not null && _legacyCodec.Supports(envelope.CipherAlgorithm))
            {
                return _legacyCodec.Decrypt(envelope.CiphertextBytes, envelope.CipherAlgorithm);
            }

            throw new DecryptionFailedException(
                $"El paquete viene en formato de clave compartida de otro equipo y este nodo no sabe descifrar {envelope.CipherAlgorithm} en ese formato (solo AES-GCM).",
                envelope.CipherAlgorithm,
                envelope.PacketId);
        }

        var wrapper = ResolveWrapper(envelope.KeyExchangeAlgorithm);
        var strategy = ResolveStrategy(envelope.CipherAlgorithm);
        var sessionKey = wrapper.UnwrapSessionKey(wrapped, envelope.Parameters.Salt, envelope.Parameters.ExtraMetadata);
        try
        {
            return strategy.Decrypt(
                envelope.CiphertextBytes,
                sessionKey,
                envelope.Parameters.IvOrNonce,
                envelope.Parameters.AuthTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
        }
    }

    /// <summary>
    /// Verifica la firma del manifiesto con el certificado que viene dentro del paquete.
    /// </summary>
    public bool VerifyManifestSignature(CryptoEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        try
        {
            var canonical = _serializer.GetCanonicalManifestBytes(envelope);
            return _certificates.VerifySignature(
                canonical,
                envelope.ManifestSignature,
                envelope.SenderCertificatePem,
                envelope.SignatureAlgorithm);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (DomainException)
        {
            return false;
        }
    }

    /// <summary>
    /// Indica si el nodo puede cifrar o descifrar con el algoritmo indicado.
    /// </summary>
    public bool SupportsCipher(CipherAlgorithmType algorithm) => _strategies.Any(s => s.CanHandle(algorithm));

    /// <summary>
    /// Indica si el algoritmo se puede usar en el modo de clave compartida con otros equipos.
    /// </summary>
    public bool SupportsSharedKeyMode(CipherAlgorithmType algorithm) => _legacyCodec?.Supports(algorithm) == true;

    /// <summary>
    /// Indica si el nodo puede envolver o desenvolver claves con el mecanismo indicado.
    /// </summary>
    public bool SupportsKeyExchange(KeyExchangeAlgorithmType algorithm) => _keyWrappers.Any(w => w.CanHandle(algorithm));

    /// <summary>
    /// Convierte un código oficial (o alias) en el tipo de cifrado de carga útil.
    /// </summary>
    public static CipherAlgorithmType ResolveCipherFromCode(string codeOrAlias)
    {
        var descriptor = OfficialAlgorithmCatalog.GetByCode(OfficialAlgorithmCatalog.ParseOrThrow(codeOrAlias));
        return descriptor.CipherAlgorithm
               ?? throw new UnsupportedAlgorithmException(
                   codeOrAlias,
                   $"El algoritmo '{descriptor.OfficialCode}' no cifra carga útil.");
    }

    private ISymmetricCipherStrategy ResolveStrategy(CipherAlgorithmType algorithm) =>
        _strategies.FirstOrDefault(s => s.CanHandle(algorithm))
        ?? throw new UnsupportedAlgorithmException(algorithm.ToString());

    private IAsymmetricKeyWrapperPort ResolveWrapper(KeyExchangeAlgorithmType algorithm) =>
        _keyWrappers.FirstOrDefault(w => w.CanHandle(algorithm))
        ?? throw new UnsupportedAlgorithmException(
            algorithm.ToString(),
            $"Este nodo no maneja el intercambio de clave '{algorithm}'.");

    private static void Merge(Dictionary<string, string> target, IReadOnlyDictionary<string, string>? source)
    {
        if (source is null)
        {
            return;
        }

        foreach (var pair in source)
        {
            target[pair.Key] = pair.Value;
        }
    }

    private static DateTimeOffset TruncateToSeconds(DateTimeOffset value) =>
        new(value.Year, value.Month, value.Day, value.Hour, value.Minute, value.Second, TimeSpan.Zero);
}
