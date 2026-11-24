using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Resultado de transmitir un paquete serializado hacia otro nodo de la red local.
/// </summary>
/// <param name="Success">Indica si el nodo destino aceptó la transmisión.</param>
/// <param name="StatusCode">Código de estado del protocolo de transporte (por ejemplo 202, 400, 422).</param>
/// <param name="ResponseMessage">Mensaje o cuerpo resumido devuelto por el receptor.</param>
public sealed record TransportDeliveryResult(
    bool Success,
    int StatusCode,
    string? ResponseMessage = null);

/// <summary>
/// Puerto de salida para enviar paquetes empaquetados a otro nodo por su dirección de red.
/// </summary>
public interface INodeTransportSenderPort
{
    /// <summary>
    /// Envía el paquete serializado al endpoint del nodo destino.
    /// </summary>
    /// <param name="destinationNode">Identidad y endpoint del nodo receptor.</param>
    /// <param name="packageBytes">Contenido binario del paquete empaquetado.</param>
    /// <param name="packageFileName">Nombre estandarizado del archivo de paquete.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Resultado de la transmisión remota.</returns>
    Task<TransportDeliveryResult> SendPackageAsync(
        NodeIdentity destinationNode,
        byte[] packageBytes,
        string packageFileName,
        CancellationToken cancellationToken = default);
}
