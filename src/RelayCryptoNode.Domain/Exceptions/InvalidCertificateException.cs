namespace RelayCryptoNode.Domain.Exceptions;

/// <summary>
/// Se lanza cuando un certificado X.509 o su firma asociada resulta inválido, expirado o no confiable.
/// </summary>
public sealed class InvalidCertificateException : DomainException
{
    /// <summary>
    /// Huella digital SHA-256 del certificado rechazado, si pudo extraerse.
    /// </summary>
    public string? Thumbprint { get; }

    /// <summary>
    /// Motivo específico de invalidez del certificado.
    /// </summary>
    public string Reason { get; }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="InvalidCertificateException"/>.
    /// </summary>
    /// <param name="reason">Motivo técnico del rechazo del certificado.</param>
    /// <param name="thumbprint">Huella SHA-256 opcional del certificado.</param>
    public InvalidCertificateException(string reason, string? thumbprint = null)
        : base($"Certificado X.509 inválido: {reason}", "CRYPTO_INVALID_CERTIFICATE")
    {
        Reason = reason;
        Thumbprint = thumbprint;
    }
}
