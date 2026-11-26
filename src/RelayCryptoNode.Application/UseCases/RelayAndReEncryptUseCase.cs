using System.Globalization;
using RelayCryptoNode.Application.Services;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Inbound;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Application.UseCases;

/// <summary>
/// Rol Intermediate: descifra solo en RAM, vuelve a cifrar con el algoritmo de salida y reenvía.
/// </summary>
public sealed class RelayAndReEncryptUseCase : IRelayAndReEncryptUseCase
{
    private readonly ManageIncomingRequestsUseCase _inbox;
    private readonly IRequestRepositoryPort _repository;
    private readonly EnvelopeCryptoService _crypto;
    private readonly IPackageSerializerPort _serializer;
    private readonly INodeTransportSenderPort _transport;
    private readonly RemoteNodeResolver _resolver;
    private readonly IRealtimeNotifierPort _notifier;

    /// <summary>
    /// Crea el caso de uso de relevo.
    /// </summary>
    public RelayAndReEncryptUseCase(
        ManageIncomingRequestsUseCase inbox,
        IRequestRepositoryPort repository,
        EnvelopeCryptoService crypto,
        IPackageSerializerPort serializer,
        INodeTransportSenderPort transport,
        RemoteNodeResolver resolver,
        IRealtimeNotifierPort notifier)
    {
        _inbox = inbox;
        _repository = repository;
        _crypto = crypto;
        _serializer = serializer;
        _transport = transport;
        _resolver = resolver;
        _notifier = notifier;
    }

    /// <inheritdoc />
    public async Task<RelayAndReEncryptResult> ExecuteAsync(
        RelayAndReEncryptCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var request = await _inbox.GetRequiredAsync(command.RequestId, cancellationToken).ConfigureAwait(false);
        if (request.Status != RequestStatus.Accepted)
        {
            throw new DomainException(
                $"Solo se reenvían solicitudes aceptadas (estado actual: {request.Status}).",
                "REQUEST_INVALID_TRANSITION");
        }

        var incoming = request.Envelope;
        byte[]? plaintext = null;
        try
        {
            plaintext = _crypto.Open(incoming);

            var recipientPem = command.NextNodeCertificatePem;
            if (string.IsNullOrWhiteSpace(recipientPem) && command.TargetKeyExchangeAlgorithm == KeyExchangeAlgorithmType.RsaOaepSha256)
            {
                var resolved = await _resolver.ResolveAsync(
                    command.NextNode.EndpointAddress,
                    command.TargetKeyExchangeAlgorithm,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                recipientPem = resolved.CertificatePem;
            }

            var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var key in new[] { "payloadFormat", "payloadItems" })
            {
                if (incoming.Parameters.ExtraMetadata.TryGetValue(key, out var value))
                {
                    metadata[key] = value;
                }
            }

            var hop = incoming.Parameters.ExtraMetadata.TryGetValue("hopCount", out var hopText)
                      && int.TryParse(hopText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedHop)
                ? parsedHop
                : 1;
            metadata["hopCount"] = (hop + 1).ToString(CultureInfo.InvariantCulture);
            metadata["originNode"] = incoming.Parameters.ExtraMetadata.TryGetValue("originNode", out var origin)
                ? origin
                : incoming.SourceNode.NodeId;
            metadata["previousNode"] = incoming.SourceNode.NodeId;
            metadata["previousAlgorithm"] = incoming.CipherAlgorithm.ToString();
            if (command.ExtraMetadata is not null)
            {
                foreach (var pair in command.ExtraMetadata)
                {
                    metadata[pair.Key] = pair.Value;
                }
            }

            var outgoing = _crypto.Seal(
                plaintext,
                new OriginalPayloadInfo(
                    incoming.OriginalPayloadSha256,
                    incoming.OriginalFileName,
                    incoming.OriginalExtension,
                    incoming.OriginalSizeBytes),
                command.TargetCipherAlgorithm,
                command.TargetKeyExchangeAlgorithm,
                command.TargetSignatureAlgorithm,
                recipientPem,
                metadata);

            var packageBytes = await _serializer.SerializeEnvelopeAsync(outgoing, cancellationToken).ConfigureAwait(false);
            var fileName = _serializer.BuildStandardPackageFileName(outgoing);
            var delivery = await _transport.SendPackageAsync(command.NextNode, packageBytes, fileName, cancellationToken)
                .ConfigureAwait(false);

            if (delivery.Success)
            {
                request.MarkRelayed();
            }
            else
            {
                request.MarkFailed($"El siguiente nodo no recibió el paquete: {delivery.ResponseMessage}");
            }

            await _repository.UpdateAsync(request, cancellationToken).ConfigureAwait(false);
            await _notifier.NotifyAsync(
                new NodeEventNotification(
                    delivery.Success ? "request.relayed" : "request.failed",
                    delivery.Success
                        ? $"Relevo: {incoming.CipherAlgorithm} → {command.TargetCipherAlgorithm}, enviado {fileName} a {command.NextNode.EndpointAddress}."
                        : $"Falló el relevo hacia {command.NextNode.EndpointAddress}: {delivery.ResponseMessage}",
                    DateTimeOffset.UtcNow,
                    request.RequestId),
                cancellationToken).ConfigureAwait(false);

            return new RelayAndReEncryptResult(
                request.RequestId,
                incoming.CipherAlgorithm,
                outgoing,
                fileName,
                delivery.Success);
        }
        catch (Exception ex) when (ex is DomainException or HttpRequestException or TaskCanceledException)
        {
            if (request.Status == RequestStatus.Accepted)
            {
                request.MarkFailed(ex.Message);
                await _repository.UpdateAsync(request, CancellationToken.None).ConfigureAwait(false);
                await _notifier.NotifyAsync(
                    new NodeEventNotification("request.failed", $"Falló el relevo: {ex.Message}", DateTimeOffset.UtcNow, request.RequestId),
                    CancellationToken.None).ConfigureAwait(false);
            }

            throw;
        }
        finally
        {
            if (plaintext is not null)
            {
                Array.Clear(plaintext);
            }
        }
    }
}
