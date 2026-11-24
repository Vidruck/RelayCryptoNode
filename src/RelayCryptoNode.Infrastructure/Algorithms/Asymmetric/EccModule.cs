using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Infrastructure.Algorithms.Asymmetric;

/// <summary>
/// Módulo oficial <c>ECC</c> (#6): acuerdo de claves ECDH P-256 con HKDF-SHA256 y firmas digitales ECDSA P-256.
/// </summary>
public sealed class EccModule : IAsymmetricKeyWrapperPort
{
    private readonly string? _localPrivateKeyPem;

    /// <summary>
    /// Inicializa el módulo ECC con la clave privada EC P-256 local en PEM cuando actúa como receptor.
    /// </summary>
    /// <param name="localPrivateKeyPem">Clave privada EC en PEM.</param>
    public EccModule(string? localPrivateKeyPem = null)
    {
        _localPrivateKeyPem = localPrivateKeyPem;
    }

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.ECC;

    /// <inheritdoc />
    public KeyExchangeAlgorithmType Algorithm => KeyExchangeAlgorithmType.EcdhP256;

    /// <inheritdoc />
    public bool CanHandle(KeyExchangeAlgorithmType algorithm) => algorithm == KeyExchangeAlgorithmType.EcdhP256;

    /// <inheritdoc />
    public KeyWrapResult WrapSessionKey(byte[] sessionKey, string recipientCertificatePem)
    {
        ArgumentNullException.ThrowIfNull(sessionKey);
        if (string.IsNullOrWhiteSpace(recipientCertificatePem))
        {
            throw new InvalidCertificateException("El certificado o clave pública EC PEM es obligatorio.");
        }

        using var recipientPublic = LoadPublicEcdh(recipientCertificatePem);
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        var sharedSecret = ephemeral.DeriveRawSecretAgreement(recipientPublic.PublicKey);
        var wrapKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, info: "ECC-ECDH-WRAP"u8.ToArray());

        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[sessionKey.Length];
        using (var aes = new AesGcm(wrapKey, 16))
        {
            aes.Encrypt(nonce, sessionKey, ciphertext, tag);
        }

        var ephemeralSpki = ephemeral.PublicKey.ExportSubjectPublicKeyInfo();
        var packedWrapped = new byte[12 + 16 + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, packedWrapped, 0, 12);
        Buffer.BlockCopy(tag, 0, packedWrapped, 12, 16);
        Buffer.BlockCopy(ciphertext, 0, packedWrapped, 28, ciphertext.Length);

        return new KeyWrapResult(packedWrapped, ephemeralSpki);
    }

    /// <inheritdoc />
    public byte[] UnwrapSessionKey(
        byte[] wrappedKey,
        byte[]? salt = null,
        IReadOnlyDictionary<string, string>? extraMetadata = null)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);
        if (string.IsNullOrWhiteSpace(_localPrivateKeyPem))
        {
            throw new DecryptionFailedException("No hay clave privada ECC configurada para ECDH.");
        }

        if (salt is null || salt.Length == 0 || wrappedKey.Length < 29)
        {
            throw new DecryptionFailedException("Faltan parámetros efímeros ECDH válidos para desenvolver la clave.");
        }

        try
        {
            using var localEcdh = ECDiffieHellman.Create();
            localEcdh.ImportFromPem(_localPrivateKeyPem);

            using var ephemeralPublic = ECDiffieHellman.Create();
            ephemeralPublic.ImportSubjectPublicKeyInfo(salt, out _);

            var sharedSecret = localEcdh.DeriveRawSecretAgreement(ephemeralPublic.PublicKey);
            var wrapKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, info: "ECC-ECDH-WRAP"u8.ToArray());

            var nonce = wrappedKey[..12];
            var tag = wrappedKey[12..28];
            var ciphertext = wrappedKey[28..];
            var sessionKey = new byte[ciphertext.Length];

            using var aes = new AesGcm(wrapKey, 16);
            aes.Decrypt(nonce, ciphertext, tag, sessionKey);
            return sessionKey;
        }
        catch (CryptographicException ex)
        {
            throw new DecryptionFailedException("Falló el acuerdo o desenvolvimiento ECDH P-256.", innerException: ex);
        }
    }

    /// <summary>
    /// Firma datos con ECDSA sobre curva NIST P-256 y SHA-256.
    /// </summary>
    public static byte[] SignEcdsaP256(byte[] data, string privateKeyPem)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(privateKeyPem);
        return ecdsa.SignData(data, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Verifica una firma ECDSA P-256 con certificado X.509 PEM o clave pública PEM.
    /// </summary>
    public static bool VerifyEcdsaP256(byte[] data, byte[] signature, string certificateOrPublicKeyPem)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);

        if (certificateOrPublicKeyPem.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
        {
            using var cert = X509Certificate2.CreateFromPem(certificateOrPublicKeyPem);
            using var ecdsa = cert.GetECDsaPublicKey()
                              ?? throw new InvalidCertificateException("El certificado X.509 no contiene clave pública ECDSA.");
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }

        using var pub = ECDsa.Create();
        pub.ImportFromPem(certificateOrPublicKeyPem);
        return pub.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    private static ECDiffieHellman LoadPublicEcdh(string pem)
    {
        if (pem.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
        {
            using var cert = X509Certificate2.CreateFromPem(pem);
            using var ecdsa = cert.GetECDsaPublicKey()
                              ?? throw new InvalidCertificateException("El certificado X.509 no contiene clave pública ECC.");
            var spki = ecdsa.ExportSubjectPublicKeyInfo();
            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportSubjectPublicKeyInfo(spki, out _);
            return ecdh;
        }

        var direct = ECDiffieHellman.Create();
        direct.ImportFromPem(pem);
        return direct;
    }
}
