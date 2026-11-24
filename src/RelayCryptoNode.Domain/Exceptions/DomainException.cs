namespace RelayCryptoNode.Domain.Exceptions;

/// <summary>
/// Excepción base para todas las violaciones de invariantes y reglas de negocio del dominio <c>RelayCryptoNode.Domain</c>.
/// </summary>
public class DomainException : Exception
{
    /// <summary>
    /// Código estructurado de error de dominio para trazabilidad operativa.
    /// </summary>
    public string? ErrorCode { get; }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="DomainException"/> con un mensaje descriptivo.
    /// </summary>
    /// <param name="message">Descripción clara de la invariante o regla incumplida.</param>
    /// <param name="errorCode">Código opcional de error de dominio.</param>
    public DomainException(string message, string? errorCode = null)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="DomainException"/> con una excepción interna.
    /// </summary>
    /// <param name="message">Descripción clara de la invariante o regla incumplida.</param>
    /// <param name="innerException">Excepción original causante del fallo.</param>
    /// <param name="errorCode">Código opcional de error de dominio.</param>
    public DomainException(string message, Exception innerException, string? errorCode = null)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }
}
