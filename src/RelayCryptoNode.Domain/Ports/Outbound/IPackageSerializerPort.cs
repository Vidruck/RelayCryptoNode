using RelayCryptoNode.Domain.Entities;

namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Puerto de salida para serializar y deserializar sobres criptográficos y lotes de carga útil hacia formatos de transporte.
/// </summary>
public interface IPackageSerializerPort
{
    /// <summary>
    /// Empaqueta un <see cref="CryptoEnvelope"/> en un arreglo de bytes listo para transporte (por ejemplo ZIP de 3 archivos).
    /// </summary>
    /// <param name="envelope">Sobre criptográfico a serializar.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Bytes del paquete serializado.</returns>
    Task<byte[]> SerializeEnvelopeAsync(
        CryptoEnvelope envelope,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Desempaqueta los bytes recibidos reconstruyendo el <see cref="CryptoEnvelope"/> de dominio.
    /// </summary>
    /// <param name="packageBytes">Bytes del paquete recibido.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Sobre criptográfico reconstruido.</returns>
    Task<CryptoEnvelope> DeserializeEnvelopeAsync(
        byte[] packageBytes,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Serializa un <see cref="PayloadBundle"/> en un flujo binario antes de ser cifrado.
    /// </summary>
    /// <param name="bundle">Lote de carga útil original.</param>
    /// <returns>Representación binaria determinista del lote.</returns>
    byte[] SerializePayloadBundle(PayloadBundle bundle);

    /// <summary>
    /// Reconstruye un <see cref="PayloadBundle"/> a partir de los bytes descifrados en memoria.
    /// </summary>
    /// <param name="plaintextBytes">Bytes en claro recuperados.</param>
    /// <returns>Lote de carga útil reconstruido.</returns>
    PayloadBundle DeserializePayloadBundle(byte[] plaintextBytes);

    /// <summary>
    /// Genera el nombre de archivo estandarizado para el paquete según el contrato de interoperabilidad.
    /// </summary>
    /// <param name="envelope">Sobre criptográfico emitido.</param>
    /// <returns>Nombre de archivo normalizado del paquete.</returns>
    string BuildStandardPackageFileName(CryptoEnvelope envelope);
}
