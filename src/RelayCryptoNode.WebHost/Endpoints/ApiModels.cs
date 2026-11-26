using RelayCryptoNode.Domain.Catalog;
using RelayCryptoNode.Domain.Entities;

namespace RelayCryptoNode.WebHost.Endpoints;

/// <summary>
/// Conversión de entidades de dominio a JSON para el panel y otros nodos.
/// </summary>
internal static class ApiModels
{
    public static object Request(IncomingRequest request)
    {
        var envelope = request.Envelope;
        var code = OfficialAlgorithmCatalog.TryFromCipherAlgorithm(envelope.CipherAlgorithm, out var official)
            ? official.ToString()
            : envelope.CipherAlgorithm.ToString();
        var metadata = envelope.Parameters.ExtraMetadata;
        return new
        {
            requestId = request.RequestId,
            status = request.Status.ToString(),
            statusLabel = StatusLabel(request.Status),
            receivedUtc = request.ReceivedUtc,
            processedUtc = request.ProcessedUtc,
            signatureValid = request.SignatureValid,
            integrityValid = request.IntegrityValid,
            validationNotes = request.ValidationNotes,
            rejectionReason = request.RejectionReason,
            packetId = envelope.PacketId,
            sourceNode = envelope.SourceNode.NodeId,
            sourceEndpoint = envelope.SourceNode.EndpointAddress,
            algorithmCode = code,
            keyExchange = envelope.KeyExchangeAlgorithm.ToString(),
            sharedKeyFormat = envelope.Parameters.EncryptedSessionKey is null,
            originalFileName = envelope.OriginalFileName,
            originalSizeBytes = envelope.OriginalSizeBytes,
            encryptedSizeBytes = envelope.CiphertextBytes.LongLength,
            encryptedSha256 = envelope.EncryptedSha256.HexHash,
            originalSha256 = envelope.OriginalPayloadSha256.HexHash,
            hopCount = metadata.TryGetValue("hopCount", out var hop) ? hop : null,
            originNode = metadata.TryGetValue("originNode", out var origin) ? origin : envelope.SourceNode.NodeId
        };
    }

    public static object Audit(IntegrityAuditReport report) => new
    {
        auditId = report.AuditId,
        packetId = report.PacketId,
        auditedUtc = report.AuditedUtc,
        isBitExactMatch = report.IsBitExactMatch,
        expectedSha256 = report.ExpectedOriginalSha256.HexHash,
        computedSha256 = report.ComputedSha256.HexHash,
        expectedSizeBytes = report.ExpectedSizeBytes,
        actualSizeBytes = report.ActualSizeBytes,
        byteLossCount = report.ByteLossCount,
        items = report.ItemAuditResults.Select(i => new
        {
            fileName = i.FileName,
            expectedSha256 = i.ExpectedSha256.HexHash,
            computedSha256 = i.ComputedSha256.HexHash,
            expectedSizeBytes = i.ExpectedSizeBytes,
            actualSizeBytes = i.ActualSizeBytes,
            isBitExactMatch = i.IsBitExactMatch,
            byteLossCount = i.ByteLossCount
        })
    };

    private static string StatusLabel(Domain.Enums.RequestStatus status) => status switch
    {
        Domain.Enums.RequestStatus.Pending => "Pendiente",
        Domain.Enums.RequestStatus.Accepted => "Aceptada",
        Domain.Enums.RequestStatus.Rejected => "Rechazada",
        Domain.Enums.RequestStatus.Relayed => "Reenviada",
        Domain.Enums.RequestStatus.Audited => "Auditada",
        Domain.Enums.RequestStatus.Failed => "Fallida",
        _ => status.ToString()
    };
}
