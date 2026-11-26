using RelayCryptoNode.Application.Abstractions;
using RelayCryptoNode.Application.Configuration;
using RelayCryptoNode.Application.UseCases;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Inbound;

namespace RelayCryptoNode.Application.Services;

/// <summary>
/// Resultado de procesar una solicitud aceptada según el rol del nodo.
/// </summary>
/// <param name="RequestId">Solicitud procesada.</param>
/// <param name="Action">"relay" o "audit".</param>
/// <param name="Success">Si el relevo se entregó o la auditoría salió limpia.</param>
/// <param name="Message">Resumen legible.</param>
/// <param name="Relay">Detalle del relevo, si aplica.</param>
/// <param name="Audit">Detalle de la auditoría, si aplica.</param>
public sealed record RequestProcessingResult(
    Guid RequestId,
    string Action,
    bool Success,
    string Message,
    RelayAndReEncryptResult? Relay = null,
    ReceiveAndAuditFinalResult? Audit = null);

/// <summary>
/// Acepta una solicitud y la procesa según el rol actual: Intermediate reenvía; Initial o Final auditan.
/// </summary>
public sealed class RequestProcessingService
{
    private readonly NodeRuntimeState _state;
    private readonly ManageIncomingRequestsUseCase _inbox;
    private readonly IRelayAndReEncryptUseCase _relay;
    private readonly IReceiveAndAuditFinalUseCase _audit;
    private readonly RemoteNodeResolver _resolver;

    /// <summary>
    /// Crea el orquestador de solicitudes aceptadas.
    /// </summary>
    public RequestProcessingService(
        NodeRuntimeState state,
        ManageIncomingRequestsUseCase inbox,
        IRelayAndReEncryptUseCase relay,
        IReceiveAndAuditFinalUseCase audit,
        RemoteNodeResolver resolver)
    {
        _state = state;
        _inbox = inbox;
        _relay = relay;
        _audit = audit;
        _resolver = resolver;
    }

    /// <summary>
    /// Acepta la solicitud y ejecuta la acción del rol.
    /// </summary>
    public async Task<RequestProcessingResult> AcceptAndProcessAsync(Guid requestId, CancellationToken cancellationToken = default)
    {
        var snapshot = _state.Current;
        if (snapshot.Role == NodeRole.Intermediate && string.IsNullOrWhiteSpace(snapshot.NextNodeEndpoint))
        {
            throw new DomainException(
                "El nodo está en rol Intermediate pero no tiene configurado el siguiente nodo.",
                "NEXT_NODE_NOT_CONFIGURED");
        }

        await _inbox.AcceptRequestAsync(requestId, cancellationToken).ConfigureAwait(false);
        return await ProcessAcceptedAsync(requestId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Procesa una solicitud que ya está aceptada.
    /// </summary>
    public async Task<RequestProcessingResult> ProcessAcceptedAsync(Guid requestId, CancellationToken cancellationToken = default)
    {
        var snapshot = _state.Current;
        if (snapshot.Role == NodeRole.Intermediate)
        {
            var next = await _resolver.ResolveAsync(
                    snapshot.NextNodeEndpoint!,
                    snapshot.SharedKeyFormat ? KeyExchangeAlgorithmType.PreSharedKey : snapshot.KeyExchange,
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var relay = await _relay.ExecuteAsync(
                new RelayAndReEncryptCommand(
                    requestId,
                    next.Identity,
                    EnvelopeCryptoService.ResolveCipherFromCode(snapshot.OutgoingAlgorithmCode),
                    snapshot.SharedKeyFormat ? KeyExchangeAlgorithmType.PreSharedKey : snapshot.KeyExchange,
                    SignatureAlgorithmType.RsaPssSha256,
                    next.CertificatePem,
                    snapshot.SharedKeyFormat
                        ? new Dictionary<string, string> { [LegacyFormat.MetadataKey] = LegacyFormat.SharedKeyValue }
                        : null),
                cancellationToken).ConfigureAwait(false);

            return new RequestProcessingResult(
                requestId,
                "relay",
                relay.Delivered,
                relay.Delivered
                    ? $"Reenviado como {relay.OutgoingPackageFileName} a {next.Identity.EndpointAddress}."
                    : "No se pudo entregar al siguiente nodo.",
                Relay: relay);
        }

        var audit = await _audit.ExecuteAsync(new ReceiveAndAuditFinalCommand(requestId), cancellationToken).ConfigureAwait(false);
        var request = await _inbox.GetRequiredAsync(requestId, cancellationToken).ConfigureAwait(false);
        var originalKnown = !request.Envelope.Parameters.ExtraMetadata.ContainsKey("originalSha256Unknown");
        return new RequestProcessingResult(
            requestId,
            "audit",
            audit.AuditReport.IsBitExactMatch,
            !originalKnown
                ? "Descifrado correcto. El emisor no mandó la huella del original, así que no hay contra qué comparar bit a bit."
                : audit.AuditReport.IsBitExactMatch
                ? "Auditoría limpia: el contenido llegó idéntico al original."
                : $"Auditoría con diferencias: {audit.AuditReport.ByteLossCount} bytes de diferencia.",
            Audit: audit);
    }
}
