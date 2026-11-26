using RelayCryptoNode.Application.Services;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Ports.Inbound;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Application.UseCases;

/// <summary>
/// Rol Initial: serializa el lote, cifra, firma, arma el .zip y lo manda al siguiente nodo.
/// </summary>
public sealed class EmitInitialPackageUseCase : IEmitInitialPackageUseCase
{
    private readonly EnvelopeCryptoService _crypto;
    private readonly IPackageSerializerPort _serializer;
    private readonly INodeTransportSenderPort _transport;
    private readonly RemoteNodeResolver _resolver;
    private readonly IRealtimeNotifierPort _notifier;

    /// <summary>
    /// Crea el caso de uso de emisión inicial.
    /// </summary>
    public EmitInitialPackageUseCase(
        EnvelopeCryptoService crypto,
        IPackageSerializerPort serializer,
        INodeTransportSenderPort transport,
        RemoteNodeResolver resolver,
        IRealtimeNotifierPort notifier)
    {
        _crypto = crypto;
        _serializer = serializer;
        _transport = transport;
        _resolver = resolver;
        _notifier = notifier;
    }

    /// <inheritdoc />
    public async Task<EmitInitialPackageResult> ExecuteAsync(
        EmitInitialPackageCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var recipientPem = command.DestinationCertificatePem;
        if (string.IsNullOrWhiteSpace(recipientPem) && command.KeyExchangeAlgorithm == KeyExchangeAlgorithmType.RsaOaepSha256)
        {
            var resolved = await _resolver.ResolveAsync(
                command.DestinationNode.EndpointAddress,
                command.KeyExchangeAlgorithm,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            recipientPem = resolved.CertificatePem;
        }

        var plaintext = _serializer.SerializePayloadBundle(command.Bundle);
        try
        {
            var original = PayloadBundleFactory.DescribeOriginal(command.Bundle, plaintext.LongLength);
            var metadata = new Dictionary<string, string>
            {
                ["payloadFormat"] = command.Bundle.Items.Count > 1 ? "RCN-BUNDLE-ZIP" : "RAW",
                ["payloadItems"] = command.Bundle.Items.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["hopCount"] = "1"
            };
            if (command.ExtraMetadata is not null)
            {
                foreach (var pair in command.ExtraMetadata)
                {
                    metadata[pair.Key] = pair.Value;
                }
            }

            var envelope = _crypto.Seal(
                plaintext,
                original,
                command.CipherAlgorithm,
                command.KeyExchangeAlgorithm,
                command.SignatureAlgorithm,
                recipientPem,
                metadata);

            var packageBytes = await _serializer.SerializeEnvelopeAsync(envelope, cancellationToken).ConfigureAwait(false);
            var fileName = _serializer.BuildStandardPackageFileName(envelope);
            var delivery = await _transport.SendPackageAsync(
                command.DestinationNode,
                packageBytes,
                fileName,
                cancellationToken).ConfigureAwait(false);

            await _notifier.NotifyAsync(
                new NodeEventNotification(
                    delivery.Success ? "package.sent" : "package.send_failed",
                    delivery.Success
                        ? $"Se envió {fileName} a {command.DestinationNode.EndpointAddress} (HTTP {delivery.StatusCode})."
                        : $"No se pudo entregar {fileName} a {command.DestinationNode.EndpointAddress}: {delivery.ResponseMessage}",
                    DateTimeOffset.UtcNow,
                    envelope.PacketId),
                cancellationToken).ConfigureAwait(false);

            return new EmitInitialPackageResult(envelope, fileName, delivery.Success, delivery.ResponseMessage);
        }
        finally
        {
            Array.Clear(plaintext);
        }
    }
}
