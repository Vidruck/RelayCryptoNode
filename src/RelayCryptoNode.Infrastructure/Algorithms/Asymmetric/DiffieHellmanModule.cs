using System.Numerics;
using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Infrastructure.Algorithms.Asymmetric;

/// <summary>
/// Par de claves efímero o estático de Diffie-Hellman clásico sobre grupo MODP 2048-bit (RFC 3526 Grupo 14).
/// </summary>
/// <param name="PrivateExponent">Exponente privado secreto.</param>
/// <param name="PublicKeyBytes">Valor público <c>g^x mod p</c> en big-endian sin signo.</param>
public sealed record DiffieHellmanKeyPair(BigInteger PrivateExponent, byte[] PublicKeyBytes);

/// <summary>
/// Módulo oficial <c>DIFFIEHELLMAN</c> (#7): intercambio clásico Diffie-Hellman RFC 3526 MODP-2048 con derivación SHA-256.
/// </summary>
public sealed class DiffieHellmanModule : IAsymmetricKeyWrapperPort
{
    // RFC 3526 Group 14 (2048-bit MODP prime)
    private static readonly BigInteger PrimeP = BigInteger.Parse(
        "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        System.Globalization.NumberStyles.AllowHexSpecifier);

    private static readonly BigInteger GeneratorG = new(2);

    private readonly DiffieHellmanKeyPair? _localKeyPair;

    /// <summary>
    /// Inicializa el módulo Diffie-Hellman opcionalmente con un par de claves local para des-envolver claves de sesión.
    /// </summary>
    /// <param name="localKeyPair">Par de claves Diffie-Hellman local.</param>
    public DiffieHellmanModule(DiffieHellmanKeyPair? localKeyPair = null)
    {
        _localKeyPair = localKeyPair;
    }

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.DIFFIEHELLMAN;

    /// <inheritdoc />
    public KeyExchangeAlgorithmType Algorithm => KeyExchangeAlgorithmType.DiffieHellman;

    /// <inheritdoc />
    public bool CanHandle(KeyExchangeAlgorithmType algorithm) => algorithm == KeyExchangeAlgorithmType.DiffieHellman;

    /// <summary>
    /// Genera un par de claves Diffie-Hellman MODP-2048.
    /// </summary>
    public static DiffieHellmanKeyPair GenerateKeyPair()
    {
        var privateBytes = RandomNumberGenerator.GetBytes(32);
        var x = new BigInteger(privateBytes, isUnsigned: true, isBigEndian: true);
        if (x < 2)
        {
            x += 2;
        }

        var publicY = BigInteger.ModPow(GeneratorG, x, PrimeP);
        return new DiffieHellmanKeyPair(x, publicY.ToByteArray(isUnsigned: true, isBigEndian: true));
    }

    /// <summary>
    /// Deriva una clave compartida SHA-256 de 32 bytes combinando el exponente privado local con la clave pública del par remoto.
    /// </summary>
    public static byte[] DeriveSharedKey(BigInteger localPrivateExponent, byte[] peerPublicKeyBytes)
    {
        ArgumentNullException.ThrowIfNull(peerPublicKeyBytes);
        var peerY = new BigInteger(peerPublicKeyBytes, isUnsigned: true, isBigEndian: true);
        if (peerY <= 1 || peerY >= PrimeP - 1)
        {
            throw new DomainException("La clave pública Diffie-Hellman recibida está fuera del subgrupo válido.", "DH_INVALID_PUBLIC_KEY");
        }

        var sharedSecret = BigInteger.ModPow(peerY, localPrivateExponent, PrimeP);
        return SHA256.HashData(sharedSecret.ToByteArray(isUnsigned: true, isBigEndian: true));
    }

    /// <summary>
    /// Envuelve una clave de sesión mediante acuerdo Diffie-Hellman usando la clave pública remota codificada en Base64 en <paramref name="recipientCertificatePem"/>.
    /// </summary>
    public KeyWrapResult WrapSessionKey(byte[] sessionKey, string recipientCertificatePem)
    {
        ArgumentNullException.ThrowIfNull(sessionKey);
        if (string.IsNullOrWhiteSpace(recipientCertificatePem))
        {
            throw new InvalidCertificateException("Se requiere la clave pública Diffie-Hellman del receptor en Base64.");
        }

        byte[] peerPublicBytes;
        try
        {
            peerPublicBytes = Convert.FromBase64String(recipientCertificatePem.Trim());
        }
        catch (FormatException)
        {
            throw new InvalidCertificateException("Formato Base64 inválido para clave pública Diffie-Hellman.");
        }

        var ephemeral = GenerateKeyPair();
        var wrapKey = DeriveSharedKey(ephemeral.PrivateExponent, peerPublicBytes);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[sessionKey.Length];

        using (var aes = new AesGcm(wrapKey, 16))
        {
            aes.Encrypt(nonce, sessionKey, ciphertext, tag);
        }

        var packedWrapped = new byte[12 + 16 + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, packedWrapped, 0, 12);
        Buffer.BlockCopy(tag, 0, packedWrapped, 12, 16);
        Buffer.BlockCopy(ciphertext, 0, packedWrapped, 28, ciphertext.Length);

        return new KeyWrapResult(packedWrapped, ephemeral.PublicKeyBytes);
    }

    /// <inheritdoc />
    public byte[] UnwrapSessionKey(
        byte[] wrappedKey,
        byte[]? salt = null,
        IReadOnlyDictionary<string, string>? extraMetadata = null)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);
        if (_localKeyPair is null || salt is null || salt.Length == 0 || wrappedKey.Length < 29)
        {
            throw new DecryptionFailedException("Faltan claves locales o públicas efímeras para desenvolver Diffie-Hellman.");
        }

        var wrapKey = DeriveSharedKey(_localKeyPair.PrivateExponent, salt);
        var nonce = wrappedKey[..12];
        var tag = wrappedKey[12..28];
        var ciphertext = wrappedKey[28..];
        var sessionKey = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(wrapKey, 16);
            aes.Decrypt(nonce, ciphertext, tag, sessionKey);
            return sessionKey;
        }
        catch (CryptographicException ex)
        {
            throw new DecryptionFailedException("Falló el desenvolvimiento Diffie-Hellman.", innerException: ex);
        }
    }
}
