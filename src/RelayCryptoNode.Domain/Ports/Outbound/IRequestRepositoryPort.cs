using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;

namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Puerto de salida para persistir y consultar las solicitudes entrantes en la bandeja del nodo.
/// </summary>
public interface IRequestRepositoryPort
{
    /// <summary>
    /// Almacena una nueva solicitud entrante.
    /// </summary>
    /// <param name="request">Solicitud a persistir.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    Task AddAsync(IncomingRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Actualiza el estado y metadatos de una solicitud existente.
    /// </summary>
    /// <param name="request">Solicitud con los cambios aplicados.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    Task UpdateAsync(IncomingRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Busca una solicitud por su identificador único.
    /// </summary>
    /// <param name="requestId">Identificador de la solicitud.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Solicitud encontrada o <c>null</c> si no existe.</returns>
    Task<IncomingRequest?> GetByIdAsync(Guid requestId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lista todas las solicitudes registradas, con filtro opcional por estado.
    /// </summary>
    /// <param name="statusFilter">Estado opcional a filtrar.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Colección de solo lectura ordenada de solicitudes.</returns>
    Task<IReadOnlyList<IncomingRequest>> ListAsync(
        RequestStatus? statusFilter = null,
        CancellationToken cancellationToken = default);
}
