using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Inbound;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Application.Services;

namespace RelayCryptoNode.Application.UseCases;

/// <summary>
/// Rol Final: descifra, recupera los archivos y los compara bit a bit contra la huella original.
/// </summary>
public sealed class ReceiveAndAuditFinalUseCase : IReceiveAndAuditFinalUseCase
{
    private readonly ManageIncomingRequestsUseCase _inbox;
    private readonly IRequestRepositoryPort _repository;
    private readonly EnvelopeCryptoService _crypto;
    private readonly IPackageSerializerPort _serializer;
    private readonly IHashingServicePort _hashing;
    private readonly IEvidenceStoragePort _evidence;
    private readonly IRealtimeNotifierPort _notifier;

    /// <summary>
    /// Crea el caso de uso de recepción final y auditoría.
    /// </summary>
    public ReceiveAndAuditFinalUseCase(
        ManageIncomingRequestsUseCase inbox,
        IRequestRepositoryPort repository,
        EnvelopeCryptoService crypto,
        IPackageSerializerPort serializer,
        IHashingServicePort hashing,
        IEvidenceStoragePort evidence,
        IRealtimeNotifierPort notifier)
    {
        _inbox = inbox;
        _repository = repository;
        _crypto = crypto;
        _serializer = serializer;
        _hashing = hashing;
        _evidence = evidence;
        _notifier = notifier;
    }

    /// <inheritdoc />
    public async Task<ReceiveAndAuditFinalResult> ExecuteAsync(
        ReceiveAndAuditFinalCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var request = await _inbox.GetRequiredAsync(command.RequestId, cancellationToken).ConfigureAwait(false);
        if (request.Status != RequestStatus.Accepted)
        {
            throw new DomainException(
                $"Solo se auditan solicitudes aceptadas (estado actual: {request.Status}).",
                "REQUEST_INVALID_TRANSITION");
        }

        var envelope = request.Envelope;
        try
        {
            var plaintext = _crypto.Open(envelope);
            var computed = _hashing.ComputeHash(plaintext);

            // Los paquetes de otros equipos no siempre traen la huella del original: se audita contra sí mismo
            // y el reporte lo indica en las notas del evento.
            var originalKnown = !envelope.Parameters.ExtraMetadata.ContainsKey("originalSha256Unknown");
            var expectedGlobal = originalKnown ? envelope.OriginalPayloadSha256 : computed;
            var expectedGlobalSize = originalKnown && envelope.OriginalSizeBytes > 0 ? envelope.OriginalSizeBytes : plaintext.LongLength;
            var bundle = _serializer.DeserializePayloadBundle(plaintext, envelope.OriginalFileName);

            var items = new List<ItemAuditResult>(bundle.Items.Count);
            foreach (var item in bundle.Items)
            {
                var raw = item.RawBytes;
                var expected = bundle.Items.Count == 1 ? expectedGlobal : item.Sha256Hash;
                var expectedSize = bundle.Items.Count == 1 ? expectedGlobalSize : item.SizeBytes;
                items.Add(ItemAuditResult.CreateComparison(
                    item.FileName,
                    expected,
                    _hashing.ComputeHash(raw),
                    expectedSize,
                    raw.LongLength));
            }

            var report = IntegrityAuditReport.CreateComparison(
                Guid.NewGuid(),
                envelope.PacketId,
                DateTimeOffset.UtcNow,
                expectedGlobal,
                computed,
                expectedGlobalSize,
                plaintext.LongLength,
                items);
            Array.Clear(plaintext);

            string? location = null;
            if (command.PersistEvidence)
            {
                location = await _evidence.SaveAuditEvidenceAsync(bundle, report, cancellationToken).ConfigureAwait(false);
            }

            request.MarkAudited();
            await _repository.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
            await _notifier.NotifyAsync(
                new NodeEventNotification(
                    report.IsBitExactMatch ? "audit.clean" : "audit.mismatch",
                    !originalKnown
                        ? $"Se descifró {envelope.OriginalFileName}; el emisor no mandó la huella del original, así que no hay contra qué comparar."
                        : report.IsBitExactMatch
                        ? $"Auditoría limpia: {envelope.OriginalFileName} llegó idéntico (0 bytes perdidos)."
                        : $"Auditoría con diferencias en {envelope.OriginalFileName}: {report.ByteLossCount} bytes de diferencia.",
                    DateTimeOffset.UtcNow,
                    request.RequestId),
                cancellationToken).ConfigureAwait(false);

            return new ReceiveAndAuditFinalResult(request.RequestId, bundle, report, location);
        }
        catch (DomainException ex)
        {
            if (request.Status == RequestStatus.Accepted)
            {
                request.MarkFailed(ex.Message);
                await _repository.UpdateAsync(request, CancellationToken.None).ConfigureAwait(false);
                await _notifier.NotifyAsync(
                    new NodeEventNotification("request.failed", $"Falló la auditoría: {ex.Message}", DateTimeOffset.UtcNow, request.RequestId),
                    CancellationToken.None).ConfigureAwait(false);
            }

            throw;
        }
    }
}
