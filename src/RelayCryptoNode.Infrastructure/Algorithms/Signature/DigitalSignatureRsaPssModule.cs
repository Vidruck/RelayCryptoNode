using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Infrastructure.Algorithms.Asymmetric;

namespace RelayCryptoNode.Infrastructure.Algorithms.Signature;

/// <summary>
/// Módulo oficial <c>DIGITALSIG</c> (#17): generación y verificación dedicada de firmas digitales RSA-PSS con SHA-256.
/// </summary>
public sealed class DigitalSignatureRsaPssModule
{
    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.DIGITALSIG;

    /// <summary>
    /// Algoritmo de firma implementado por el módulo.
    /// </summary>
    public SignatureAlgorithmType Algorithm => SignatureAlgorithmType.RsaPssSha256;

    /// <summary>
    /// Firma el bloque de datos mediante RSA-PSS SHA-256 usando la clave privada RSA en formato PEM.
    /// </summary>
    /// <param name="data">Datos canónicos a firmar.</param>
    /// <param name="privateKeyPem">Clave privada RSA en formato PEM.</param>
    /// <returns>Firma digital resultante.</returns>
    public byte[] Sign(byte[] data, string privateKeyPem)
    {
        if (string.IsNullOrWhiteSpace(privateKeyPem))
        {
            throw new InvalidCertificateException("La clave privada RSA PEM es obligatoria para firmar.");
        }

        return RsaModule.SignPssSha256(data, privateKeyPem);
    }

    /// <summary>
    /// Verifica la firma digital RSA-PSS SHA-256 contra un certificado X.509 PEM o una clave pública RSA PEM.
    /// </summary>
    /// <param name="data">Datos firmados originalmente.</param>
    /// <param name="signature">Firma digital recibida.</param>
    /// <param name="certificateOrPublicKeyPem">Certificado X.509 PEM o clave pública PEM.</param>
    /// <returns><c>true</c> si la firma es válida.</returns>
    public bool Verify(byte[] data, byte[] signature, string certificateOrPublicKeyPem)
    {
        if (string.IsNullOrWhiteSpace(certificateOrPublicKeyPem))
        {
            throw new InvalidCertificateException("El certificado o clave pública PEM es obligatorio para verificar.");
        }

        return RsaModule.VerifyPssSha256(data, signature, certificateOrPublicKeyPem);
    }

    /// <summary>
    /// Calcula la huella digital SHA-256 de un certificado X.509 en formato PEM.
    /// </summary>
    public static string ComputeCertificateThumbprintSha256(string certificatePem)
    {
        using var cert = X509Certificate2.CreateFromPem(certificatePem);
        var digest = SHA256.HashData(cert.RawData);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }
}
