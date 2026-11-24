namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Evento emitido en tiempo real hacia el panel de control del nodo.
/// </summary>
/// <param name="EventType">Nombre estructurado del evento (por ejemplo <c>RequestReceived</c>, <c>PackageRelayed</c>, <c>AuditCompleted</c>).</param>
/// <param name="Message">Descripción legible para el operador.</param>
/// <param name="TimestampUtc">Marca temporal UTC del evento.</param>
/// <param name="RelatedEntityId">Identificador opcional de paquete, solicitud o auditoría asociada.</param>
public sealed record NodeEventNotification(
    string EventType,
    string Message,
    DateTimeOffset TimestampUtc,
    Guid? RelatedEntityId = null);

/// <summary>
/// Puerto de salida para notificar eventos operativos en vivo al panel web de control.
/// </summary>
public interface IRealtimeNotifierPort
{
    /// <summary>
    /// Publica una notificación en tiempo real a los clientes suscritos del panel del nodo.
    /// </summary>
    /// <param name="notification">Evento estructurado a difundir.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    Task NotifyAsync(
        NodeEventNotification notification,
        CancellationToken cancellationToken = default);
}
