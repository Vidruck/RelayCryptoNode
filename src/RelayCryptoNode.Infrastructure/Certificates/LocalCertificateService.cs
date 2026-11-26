using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Infrastructure.Certificates;

/// <summary>
/// Certificado X.509 autofirmado del nodo (RSA 2048). Se genera la primera vez y se guarda como PEM
/// en la carpeta de datos; la clave privada nunca sale del nodo.
/// </summary>
public sealed class LocalCertificateService : ICertificateServicePort
{
    private static readonly TimeSpan AllowedClockSkew = TimeSpan.FromMinutes(10);

    private readonly string _certificatePem;
    private readonly string _privateKeyPem;

    /// <summary>
    /// Carga el certificado del nodo o lo genera si no existe.
    /// </summary>
    /// <param name="certificatesDirectory">Carpeta donde se guardan <c>&lt;NODO&gt;-cert.pem</c> y <c>&lt;NODO&gt;-key.pem</c>.</param>
    /// <param name="nodeId">Identificador del nodo; se usa como CN del certificado.</param>
    public LocalCertificateService(string certificatesDirectory, string nodeId)
    {
        if (string.IsNullOrWhiteSpace(nodeId))
        {
            throw new DomainException("Se requiere el identificador del nodo para su certificado.", "NODE_ID_EMPTY");
        }

        Directory.CreateDirectory(certificatesDirectory);
        var id = nodeId.Trim().ToUpperInvariant();
        var certPath = Path.Combine(certificatesDirectory, $"{id}-cert.pem");
        var keyPath = Path.Combine(certificatesDirectory, $"{id}-key.pem");

        if (File.Exists(certPath) && File.Exists(keyPath))
        {
            _certificatePem = File.ReadAllText(certPath);
            _privateKeyPem = File.ReadAllText(keyPath);
            using var existing = X509Certificate2.CreateFromPem(_certificatePem);
            if (existing.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(1))
            {
                return;
            }
        }

        (_certificatePem, _privateKeyPem) = Generate(id);
        File.WriteAllText(certPath, _certificatePem);
        File.WriteAllText(keyPath, _privateKeyPem);
    }

    /// <summary>
    /// Clave privada RSA del nodo en PEM (solo para el módulo RSA que desenvuelve claves de sesión).
    /// </summary>
    public string GetLocalPrivateKeyPem() => _privateKeyPem;

    /// <inheritdoc />
    public string GetLocalCertificatePem() => _certificatePem;

    /// <inheritdoc />
    public Task<CertificateValidationResult> ValidateCertificateAsync(
        string certificatePem,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(certificatePem) || !certificatePem.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
        {
            return Task.FromResult(new CertificateValidationResult(false, string.Empty, string.Empty, "certificado.pem vacío o sin bloque BEGIN CERTIFICATE."));
        }

        try
        {
            using var certificate = X509Certificate2.CreateFromPem(certificatePem);
            var thumbprint = Thumbprint(certificate);
            var now = DateTime.UtcNow;
            if (certificate.NotBefore.ToUniversalTime() - AllowedClockSkew > now)
            {
                return Task.FromResult(new CertificateValidationResult(false, thumbprint, certificate.Subject, "El certificado todavía no es válido (revise la hora de los equipos)."));
            }

            if (certificate.NotAfter.ToUniversalTime() + AllowedClockSkew < now)
            {
                return Task.FromResult(new CertificateValidationResult(false, thumbprint, certificate.Subject, "El certificado ya venció."));
            }

            using var rsa = certificate.GetRSAPublicKey();
            using var ecdsa = rsa is null ? certificate.GetECDsaPublicKey() : null;
            if (rsa is null && ecdsa is null)
            {
                return Task.FromResult(new CertificateValidationResult(false, thumbprint, certificate.Subject, "El certificado no trae clave pública RSA ni ECDSA."));
            }

            return Task.FromResult(new CertificateValidationResult(true, thumbprint, certificate.Subject));
        }
        catch (CryptographicException ex)
        {
            return Task.FromResult(new CertificateValidationResult(false, string.Empty, string.Empty, $"No se pudo leer el certificado: {ex.Message}"));
        }
    }

    /// <inheritdoc />
    public string ComputeThumbprintSha256(string certificatePem)
    {
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(certificatePem);
            return Thumbprint(certificate);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidCertificateException($"no se pudo leer el PEM ({ex.Message})");
        }
    }

    /// <inheritdoc />
    public byte[] SignData(byte[] data, SignatureAlgorithmType signatureAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (signatureAlgorithm != SignatureAlgorithmType.RsaPssSha256)
        {
            throw new UnsupportedAlgorithmException(
                signatureAlgorithm.ToString(),
                "El certificado de este nodo es RSA: solo firma con RSA-PSS-SHA256.");
        }

        using var rsa = RSA.Create();
        rsa.ImportFromPem(_privateKeyPem);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    /// <inheritdoc />
    public bool VerifySignature(
        byte[] data,
        byte[] signature,
        string senderCertificatePem,
        SignatureAlgorithmType signatureAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        using var certificate = X509Certificate2.CreateFromPem(senderCertificatePem);
        switch (signatureAlgorithm)
        {
            case SignatureAlgorithmType.RsaPssSha256:
            {
                using var rsa = certificate.GetRSAPublicKey();
                return rsa is not null
                       && rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            }

            case SignatureAlgorithmType.EcdsaP256:
            {
                using var ecdsa = certificate.GetECDsaPublicKey();
                return ecdsa is not null
                       && (ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256)
                           || ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
            }

            default:
                return false;
        }
    }

    private static string Thumbprint(X509Certificate2 certificate) =>
        certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();

    private static (string CertificatePem, string PrivateKeyPem) Generate(string nodeId)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={nodeId}, OU=Virologia y Criptografia, O=RelayCryptoNode",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        using var certificate = request.CreateSelfSigned(notBefore, notBefore.AddYears(2));
        return (certificate.ExportCertificatePem(), rsa.ExportPkcs8PrivateKeyPem());
    }
}
