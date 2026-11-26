using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Inbound;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Application.UseCases;

/// <summary>
/// Bandeja de solicitudes entrantes: registrar, listar, aceptar y rechazar.
/// </summary>
public sealed class ManageIncomingRequestsUseCase : IManageIncomingRequestsUseCase
{
    private readonly IRequestRepositoryPort _repository;
    private readonly IRealtimeNotifierPort _notifier;

    /// <summary>
    /// Crea el caso de uso de la bandeja.
    /// </summary>
    public ManageIncomingRequestsUseCase(IRequestRepositoryPort repository, IRealtimeNotifierPort notifier)
    {
        _repository = repository;
        _notifier = notifier;
    }

    /// <inheritdoc />
    public async Task<IncomingRequest> RegisterIncomingAsync(
        CryptoEnvelope envelope,
        bool signatureValid,
        bool integrityValid,
        string? validationNotes = null,
        CancellationToken cancellationToken = default)
    {
        var request = new IncomingRequest(
            Guid.NewGuid(),
            envelope,
            DateTimeOffset.UtcNow,
            signatureValid,
            integrityValid,
            validationNotes);

        await _repository.AddAsync(request, cancellationToken).ConfigureAwait(false);
        var validity = signatureValid && integrityValid ? "válido" : "con firma o integridad inválida";
        await NotifyAsync(
            "request.received",
            $"Llegó un paquete de {envelope.SourceNode.NodeId} cifrado con {envelope.CipherAlgorithm} ({validity}).",
            request.RequestId,
            cancellationToken).ConfigureAwait(false);
        return request;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<IncomingRequest>> GetRequestsAsync(
        RequestStatus? statusFilter = null,
        CancellationToken cancellationToken = default) =>
        _repository.ListAsync(statusFilter, cancellationToken);

    /// <inheritdoc />
    public Task<IncomingRequest?> GetByIdAsync(Guid requestId, CancellationToken cancellationToken = default) =>
        _repository.GetByIdAsync(requestId, cancellationToken);

    /// <inheritdoc />
    public async Task<IncomingRequest> AcceptRequestAsync(Guid requestId, CancellationToken cancellationToken = default)
    {
        var request = await GetRequiredAsync(requestId, cancellationToken).ConfigureAwait(false);
        request.Accept();
        await _repository.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
        await NotifyAsync("request.accepted", $"Solicitud {Short(requestId)} aceptada.", requestId, cancellationToken)
            .ConfigureAwait(false);
        return request;
    }

    /// <inheritdoc />
    public async Task<IncomingRequest> RejectRequestAsync(
        Guid requestId,
        string reason,
        CancellationToken cancellationToken = default)
    {
        var request = await GetRequiredAsync(requestId, cancellationToken).ConfigureAwait(false);
        request.Reject(reason);
        await _repository.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
        await NotifyAsync("request.rejected", $"Solicitud {Short(requestId)} rechazada: {request.RejectionReason}", requestId, cancellationToken)
            .ConfigureAwait(false);
        return request;
    }

    /// <summary>
    /// Obtiene la solicitud o lanza <c>REQUEST_NOT_FOUND</c>.
    /// </summary>
    public async Task<IncomingRequest> GetRequiredAsync(Guid requestId, CancellationToken cancellationToken = default) =>
        await _repository.GetByIdAsync(requestId, cancellationToken).ConfigureAwait(false)
        ?? throw new DomainException($"No existe la solicitud {requestId}.", RequestErrorCodes.NotFound);

    private Task NotifyAsync(string type, string message, Guid id, CancellationToken cancellationToken) =>
        _notifier.NotifyAsync(new NodeEventNotification(type, message, DateTimeOffset.UtcNow, id), cancellationToken);

    private static string Short(Guid id) => id.ToString("N")[..8];
}

/// <summary>
/// Códigos de error de la bandeja que el WebHost traduce a códigos HTTP.
/// </summary>
public static class RequestErrorCodes
{
    /// <summary>La solicitud no existe.</summary>
    public const string NotFound = "REQUEST_NOT_FOUND";

    /// <summary>El paquete no tiene la estructura del contrato.</summary>
    public const string MalformedPackage = "PACKAGE_MALFORMED";
}
