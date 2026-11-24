namespace RelayCryptoNode.Domain.Exceptions;

/// <summary>
/// Se lanza cuando el resumen criptográfico calculado difiere del resumen esperado para un paquete o carga útil.
/// </summary>
public sealed class IntegrityMismatchException : DomainException
{
    /// <summary>
    /// Resumen hexadecimal esperado.
    /// </summary>
    public string ExpectedHash { get; }

    /// <summary>
    /// Resumen hexadecimal calculado realmente.
    /// </summary>
    public string ActualHash { get; }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="IntegrityMismatchException"/>.
    /// </summary>
    /// <param name="expectedHash">Resumen hexadecimal esperado.</param>
    /// <param name="actualHash">Resumen hexadecimal observado.</param>
    /// <param name="message">Mensaje descriptivo opcional.</param>
    public IntegrityMismatchException(string expectedHash, string actualHash, string? message = null)
        : base(
            message ?? $"Discrepancia de integridad detectada. Esperado: '{expectedHash}', calculado: '{actualHash}'.",
            "CRYPTO_INTEGRITY_MISMATCH")
    {
        ExpectedHash = expectedHash;
        ActualHash = actualHash;
    }
}
