using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;

namespace RelayCryptoNode.Domain.Ports.Inbound;

/// <summary>
/// Puerto de entrada para registrar, consultar, aprobar o rechazar solicitudes entrantes en la bandeja del nodo.
/// </summary>
public interface IManageIncomingRequestsUseCase
{
    /// <summary>
    /// Registra un paquete entrante recién desempaquetado y prevalidado en estado <see cref="RequestStatus.Pending"/>.
    /// </summary>
    /// <param name="envelope">Sobre criptográfico recibido.</param>
    /// <param name="signatureValid">Resultado de la validación X.509 y de firma del manifiesto.</param>
    /// <param name="integrityValid">Resultado de la verificación de integridad del cifrado.</param>
    /// <param name="validationNotes">Notas diagnósticas de prevalidación.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Solicitud persistida en la bandeja.</returns>
    Task<IncomingRequest> RegisterIncomingAsync(
        CryptoEnvelope envelope,
        bool signatureValid,
        bool integrityValid,
        string? validationNotes = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Obtiene todas las solicitudes registradas, filtradas opcionalmente por estado.
    /// </summary>
    /// <param name="statusFilter">Filtro opcional de estado.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Lista de solo lectura de solicitudes.</returns>
    Task<IReadOnlyList<IncomingRequest>> GetRequestsAsync(
        RequestStatus? statusFilter = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Obtiene una solicitud específica por su identificador.
    /// </summary>
    /// <param name="requestId">Identificador de la solicitud.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Solicitud encontrada o <c>null</c> si no existe.</returns>
    Task<IncomingRequest?> GetByIdAsync(
        Guid requestId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Aprueba una solicitud válida en estado <see cref="RequestStatus.Pending"/>.
    /// </summary>
    /// <param name="requestId">Identificador de la solicitud a aceptar.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Solicitud actualizada en estado <see cref="RequestStatus.Accepted"/>.</returns>
    Task<IncomingRequest> AcceptRequestAsync(
        Guid requestId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Rechaza una solicitud en estado <see cref="RequestStatus.Pending"/> registrando el motivo.
    /// </summary>
    /// <param name="requestId">Identificador de la solicitud a rechazar.</param>
    /// <param name="reason">Motivo obligatorio del rechazo.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Solicitud actualizada en estado <see cref="RequestStatus.Rejected"/>.</returns>
    Task<IncomingRequest> RejectRequestAsync(
        Guid requestId,
        string reason,
        CancellationToken cancellationToken = default);
}
