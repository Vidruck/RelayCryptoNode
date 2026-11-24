using RelayCryptoNode.Domain.Enums;

namespace RelayCryptoNode.Domain.Exceptions;

/// <summary>
/// Se lanza cuando falla el descifrado autenticado o el desenvolvimiento de la clave de sesión de un paquete.
/// </summary>
public sealed class DecryptionFailedException : DomainException
{
    /// <summary>
    /// Algoritmo simétrico involucrado en el intento de descifrado, si se conoce.
    /// </summary>
    public CipherAlgorithmType? Algorithm { get; }

    /// <summary>
    /// Identificador del paquete cuyo descifrado falló, si aplica.
    /// </summary>
    public Guid? PacketId { get; }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="DecryptionFailedException"/>.
    /// </summary>
    /// <param name="message">Detalle del fallo de descifrado.</param>
    /// <param name="algorithm">Algoritmo simétrico utilizado.</param>
    /// <param name="packetId">Identificador único del paquete afectado.</param>
    /// <param name="innerException">Excepción subyacente opcional.</param>
    public DecryptionFailedException(
        string message,
        CipherAlgorithmType? algorithm = null,
        Guid? packetId = null,
        Exception? innerException = null)
        : base(message, innerException!, "CRYPTO_DECRYPTION_FAILED")
    {
        Algorithm = algorithm;
        PacketId = packetId;
    }
}
