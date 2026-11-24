using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Infrastructure.Algorithms.Asymmetric;

/// <summary>
/// Módulo oficial <c>RSA</c> (#5): envoltura de clave de sesión RSA-OAEP-SHA256 y soporte de firma RSA-PSS-SHA256.
/// </summary>
public sealed class RsaModule : IAsymmetricKeyWrapperPort
{
    private readonly string? _localPrivateKeyPem;

    /// <summary>
    /// Inicializa el módulo RSA opcionalmente con la clave privada PEM local para desencapsular claves.
    /// </summary>
    /// <param name="localPrivateKeyPem">Clave privada RSA en formato PEM (PKCS#8 o PKCS#1).</param>
    public RsaModule(string? localPrivateKeyPem = null)
    {
        _localPrivateKeyPem = localPrivateKeyPem;
    }

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.RSA;

    /// <inheritdoc />
    public KeyExchangeAlgorithmType Algorithm => KeyExchangeAlgorithmType.RsaOaepSha256;

    /// <inheritdoc />
    public bool CanHandle(KeyExchangeAlgorithmType algorithm) => algorithm == KeyExchangeAlgorithmType.RsaOaepSha256;

    /// <inheritdoc />
    public KeyWrapResult WrapSessionKey(byte[] sessionKey, string recipientCertificatePem)
    {
        ArgumentNullException.ThrowIfNull(sessionKey);
        if (string.IsNullOrWhiteSpace(recipientCertificatePem))
        {
            throw new InvalidCertificateException("El certificado PEM destino es obligatorio para envolver con RSA-OAEP.");
        }

        using var rsa = LoadPublicRsa(recipientCertificatePem);
        var wrapped = rsa.Encrypt(sessionKey, RSAEncryptionPadding.OaepSHA256);
        return new KeyWrapResult(wrapped);
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
            throw new DecryptionFailedException("No hay clave privada RSA configurada para desenvolver la clave de sesión.");
        }

        try
        {
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportFromPem(_localPrivateKeyPem);
            return rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException ex)
        {
            throw new DecryptionFailedException("Falló el desenvolvimiento RSA-OAEP-SHA256.", innerException: ex);
        }
    }

    /// <summary>
    /// Firma datos arbitrarios usando RSA-PSS con SHA-256.
    /// </summary>
    /// <param name="data">Datos a firmar.</param>
    /// <param name="privateKeyPem">Clave privada RSA en PEM.</param>
    /// <returns>Firma digital resultante.</returns>
    public static byte[] SignPssSha256(byte[] data, string privateKeyPem)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    /// <summary>
    /// Verifica una firma RSA-PSS SHA-256 usando un certificado X.509 o clave pública RSA en PEM.
    /// </summary>
    /// <param name="data">Datos originales.</param>
    /// <param name="signature">Firma digital.</param>
    /// <param name="certificateOrPublicKeyPem">Certificado X.509 PEM o clave pública PEM.</param>
    /// <returns><c>true</c> si la firma es válida.</returns>
    public static bool VerifyPssSha256(byte[] data, byte[] signature, string certificateOrPublicKeyPem)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        using var rsa = LoadPublicRsa(certificateOrPublicKeyPem);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    private static System.Security.Cryptography.RSA LoadPublicRsa(string pem)
    {
        if (pem.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
        {
            using var cert = X509Certificate2.CreateFromPem(pem);
            return cert.GetRSAPublicKey()
                   ?? throw new InvalidCertificateException("El certificado X.509 no contiene una clave pública RSA.");
        }

        var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }
}
