using RelayCryptoNode.Domain.Enums;

namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Resultado estructurado de validar un certificado X.509 recibido en un paquete.
/// </summary>
/// <param name="IsValid">Indica si el certificado es estructural y criptográficamente válido y vigente.</param>
/// <param name="ThumbprintSha256">Huella digital SHA-256 del certificado (64 hex en minúsculas).</param>
/// <param name="SubjectName">Nombre del sujeto del certificado X.509.</param>
/// <param name="DiagnosticMessage">Descripción del resultado o motivo del rechazo.</param>
public sealed record CertificateValidationResult(
    bool IsValid,
    string ThumbprintSha256,
    string SubjectName,
    string? DiagnosticMessage = null);

/// <summary>
/// Puerto de salida para operaciones sobre certificados X.509, cálculo de huella y firmas digitales.
/// </summary>
public interface ICertificateServicePort
{
    /// <summary>
    /// Valida un certificado X.509 en formato PEM (formato, vigencia temporal y cadena de confianza configurada).
    /// </summary>
    /// <param name="certificatePem">Certificado en formato PEM.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Resultado detallado de la validación.</returns>
    Task<CertificateValidationResult> ValidateCertificateAsync(
        string certificatePem,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Calcula la huella digital SHA-256 de un certificado X.509 en formato PEM.
    /// </summary>
    /// <param name="certificatePem">Certificado en formato PEM.</param>
    /// <returns>Cadena hexadecimal de 64 caracteres en minúsculas.</returns>
    string ComputeThumbprintSha256(string certificatePem);

    /// <summary>
    /// Obtiene el certificado X.509 público local del nodo en formato PEM.
    /// </summary>
    /// <returns>Contenido PEM del certificado público local.</returns>
    string GetLocalCertificatePem();

    /// <summary>
    /// Firma digitalmente los bytes del manifiesto utilizando la clave privada local del nodo.
    /// </summary>
    /// <param name="data">Datos canónicos a firmar.</param>
    /// <param name="signatureAlgorithm">Algoritmo de firma seleccionado.</param>
    /// <returns>Firma digital resultante.</returns>
    byte[] SignData(byte[] data, SignatureAlgorithmType signatureAlgorithm);

    /// <summary>
    /// Verifica la firma digital de un manifiesto contra el certificado X.509 PEM del emisor.
    /// </summary>
    /// <param name="data">Datos originales firmados.</param>
    /// <param name="signature">Firma digital a comprobar.</param>
    /// <param name="senderCertificatePem">Certificado PEM del nodo emisor.</param>
    /// <param name="signatureAlgorithm">Algoritmo de firma declarado.</param>
    /// <returns><c>true</c> si la firma es auténtica; de lo contrario, <c>false</c>.</returns>
    bool VerifySignature(
        byte[] data,
        byte[] signature,
        string senderCertificatePem,
        SignatureAlgorithmType signatureAlgorithm);
}
