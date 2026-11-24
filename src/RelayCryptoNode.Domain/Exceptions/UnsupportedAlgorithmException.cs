namespace RelayCryptoNode.Domain.Exceptions;

/// <summary>
/// Se lanza cuando un paquete o solicitud declara un identificador de algoritmo no registrado en el catálogo oficial del nodo.
/// </summary>
public sealed class UnsupportedAlgorithmException : DomainException
{
    /// <summary>
    /// Identificador del algoritmo que originó el rechazo.
    /// </summary>
    public string AlgorithmIdentifier { get; }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="UnsupportedAlgorithmException"/>.
    /// </summary>
    /// <param name="algorithmIdentifier">Nombre o código del algoritmo no registrado.</param>
    /// <param name="message">Mensaje descriptivo opcional.</param>
    public UnsupportedAlgorithmException(string algorithmIdentifier, string? message = null)
        : base(
            message ?? $"El algoritmo '{algorithmIdentifier}' no se encuentra registrado en el catálogo oficial del nodo.",
            "CRYPTO_UNSUPPORTED_ALGORITHM")
    {
        AlgorithmIdentifier = algorithmIdentifier;
    }
}
