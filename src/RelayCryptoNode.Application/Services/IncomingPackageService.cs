using RelayCryptoNode.Application.UseCases;
using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Application.Services;

/// <summary>
/// Resultado de recibir un paquete por <c>POST /api/requests/receive</c>.
/// </summary>
public enum ReceptionOutcome
{
    /// <summary>Paquete válido y registrado en la bandeja (HTTP 202).</summary>
    Registered = 1,

    /// <summary>El .zip o el manifiesto no cumplen la estructura del contrato (HTTP 400).</summary>
    Malformed = 2,

    /// <summary>Algoritmo fuera del catálogo, certificado inválido o hash cifrado distinto (HTTP 422).</summary>
    Unprocessable = 3
}

/// <summary>
/// Detalle del resultado de recepción.
/// </summary>
/// <param name="Outcome">Clasificación del resultado.</param>
/// <param name="Message">Mensaje legible para el emisor.</param>
/// <param name="Request">Solicitud registrada, si aplica.</param>
public sealed record PackageReceptionResult(ReceptionOutcome Outcome, string Message, IncomingRequest? Request = null);

/// <summary>
/// Valida un paquete entrante (estructura, algoritmo, certificado, hash cifrado y firma) y lo registra en la bandeja.
/// </summary>
public sealed class IncomingPackageService
{
    private readonly IPackageSerializerPort _serializer;
    private readonly ICertificateServicePort _certificates;
    private readonly IHashingServicePort _hashing;
    private readonly EnvelopeCryptoService _crypto;
    private readonly ManageIncomingRequestsUseCase _inbox;
    private readonly IRealtimeNotifierPort _notifier;

    /// <summary>
    /// Crea el servicio de recepción.
    /// </summary>
    public IncomingPackageService(
        IPackageSerializerPort serializer,
        ICertificateServicePort certificates,
        IHashingServicePort hashing,
        EnvelopeCryptoService crypto,
        ManageIncomingRequestsUseCase inbox,
        IRealtimeNotifierPort notifier)
    {
        _serializer = serializer;
        _certificates = certificates;
        _hashing = hashing;
        _crypto = crypto;
        _inbox = inbox;
        _notifier = notifier;
    }

    /// <summary>
    /// Procesa los bytes del .zip recibido.
    /// </summary>
    public async Task<PackageReceptionResult> ReceiveAsync(byte[] packageBytes, CancellationToken cancellationToken = default)
    {
        if (packageBytes is null || packageBytes.Length == 0)
        {
            return await RefuseAsync(ReceptionOutcome.Malformed, "No se recibió ningún archivo .zip en el campo 'package'.", cancellationToken)
                .ConfigureAwait(false);
        }

        CryptoEnvelope envelope;
        try
        {
            envelope = await _serializer.DeserializeEnvelopeAsync(packageBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (UnsupportedAlgorithmException ex)
        {
            return await RefuseAsync(ReceptionOutcome.Unprocessable, ex.Message, cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidCertificateException ex)
        {
            return await RefuseAsync(ReceptionOutcome.Unprocessable, ex.Message, cancellationToken).ConfigureAwait(false);
        }
        catch (DomainException ex)
        {
            return await RefuseAsync(ReceptionOutcome.Malformed, ex.Message, cancellationToken).ConfigureAwait(false);
        }

        if (!_crypto.SupportsCipher(envelope.CipherAlgorithm))
        {
            return await RefuseAsync(
                ReceptionOutcome.Unprocessable,
                $"Este nodo no tiene módulo para descifrar {envelope.CipherAlgorithm}.",
                cancellationToken).ConfigureAwait(false);
        }

        var certificate = await _certificates.ValidateCertificateAsync(envelope.SenderCertificatePem, cancellationToken)
            .ConfigureAwait(false);
        if (!certificate.IsValid)
        {
            return await RefuseAsync(
                ReceptionOutcome.Unprocessable,
                $"Certificado del emisor inválido: {certificate.DiagnosticMessage}",
                cancellationToken).ConfigureAwait(false);
        }

        var computedEncrypted = _hashing.ComputeHash(envelope.CiphertextBytes);
        if (!string.Equals(computedEncrypted.HexHash, envelope.EncryptedSha256.HexHash, StringComparison.Ordinal))
        {
            return await RefuseAsync(
                ReceptionOutcome.Unprocessable,
                $"El SHA-256 de datos.enc no coincide con encryptedSha256 (esperado {envelope.EncryptedSha256.ShortHex()}, calculado {computedEncrypted.ShortHex()}).",
                cancellationToken).ConfigureAwait(false);
        }

        if (!_crypto.VerifyManifestSignature(envelope))
        {
            return await RefuseAsync(
                ReceptionOutcome.Unprocessable,
                "Firma digital inválida frente a certificado.pem.",
                cancellationToken).ConfigureAwait(false);
        }

        var notes = new List<string>
        {
            "Firma del manifiesto verificada.",
            "Certificado vigente: " + certificate.SubjectName + ".",
            "SHA-256 de datos.enc verificado."
        };
        if (!string.Equals(certificate.ThumbprintSha256, envelope.SourceNode.CertificateThumbprintSha256, StringComparison.OrdinalIgnoreCase))
        {
            notes.Add("Aviso: la huella declarada no coincide con certificado.pem.");
        }

        if (envelope.Parameters.EncryptedSessionKey is null)
        {
            notes.Add("Formato de clave compartida (otro equipo).");
        }

        var request = await _inbox.RegisterIncomingAsync(
            envelope,
            true,
            true,
            string.Join(" ", notes),
            cancellationToken).ConfigureAwait(false);

        return new PackageReceptionResult(ReceptionOutcome.Registered, "Paquete recibido y encolado en la bandeja.", request);
    }

    private async Task<PackageReceptionResult> RefuseAsync(ReceptionOutcome outcome, string message, CancellationToken cancellationToken)
    {
        await _notifier.NotifyAsync(
            new NodeEventNotification("package.refused", $"Paquete rechazado al recibirlo: {message}", DateTimeOffset.UtcNow),
            cancellationToken).ConfigureAwait(false);
        return new PackageReceptionResult(outcome, message);
    }
}
