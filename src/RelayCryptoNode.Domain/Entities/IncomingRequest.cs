using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;

namespace RelayCryptoNode.Domain.Entities;

/// <summary>
/// Entidad de dominio con máquina de estados explícita para gestionar solicitudes de paquetes entrantes.
/// </summary>
public sealed class IncomingRequest
{
    /// <summary>
    /// Identificador único de la solicitud en la bandeja del nodo.
    /// </summary>
    public Guid RequestId { get; }

    /// <summary>
    /// Sobre criptográfico recibido asociado a esta solicitud.
    /// </summary>
    public CryptoEnvelope Envelope { get; }

    /// <summary>
    /// Estado actual dentro del ciclo de vida de la solicitud.
    /// </summary>
    public RequestStatus Status { get; private set; }

    /// <summary>
    /// Fecha y hora UTC en que el nodo recibió la solicitud.
    /// </summary>
    public DateTimeOffset ReceivedUtc { get; }

    /// <summary>
    /// Indica si la firma X.509 y del manifiesto superó la verificación criptográfica.
    /// </summary>
    public bool SignatureValid { get; }

    /// <summary>
    /// Indica si la integridad del paquete cifrado recibido coincide con su SHA-256 declarado.
    /// </summary>
    public bool IntegrityValid { get; }

    /// <summary>
    /// Notas diagnósticas recopiladas durante la validación inicial de recepción.
    /// </summary>
    public string ValidationNotes { get; private set; }

    /// <summary>
    /// Motivo registrado cuando la solicitud fue rechazada o marcada como fallida.
    /// </summary>
    public string? RejectionReason { get; private set; }

    /// <summary>
    /// Marca temporal UTC de la última transición de estado ejecutada.
    /// </summary>
    public DateTimeOffset? ProcessedUtc { get; private set; }

    /// <summary>
    /// Inicializa una nueva solicitud entrante en estado <see cref="RequestStatus.Pending"/>.
    /// </summary>
    /// <param name="requestId">Identificador único de la solicitud.</param>
    /// <param name="envelope">Sobre criptográfico recibido.</param>
    /// <param name="receivedUtc">Marca temporal UTC de recepción.</param>
    /// <param name="signatureValid">Resultado de la validación de firma y certificado.</param>
    /// <param name="integrityValid">Resultado de la validación de integridad del cifrado.</param>
    /// <param name="validationNotes">Observaciones de validación.</param>
    /// <exception cref="DomainException">Se lanza si los argumentos obligatorios son inválidos.</exception>
    public IncomingRequest(
        Guid requestId,
        CryptoEnvelope envelope,
        DateTimeOffset receivedUtc,
        bool signatureValid,
        bool integrityValid,
        string? validationNotes = null)
    {
        if (requestId == Guid.Empty)
        {
            throw new DomainException("El RequestId no puede ser Guid.Empty.", "REQUEST_ID_EMPTY");
        }

        if (envelope is null)
        {
            throw new DomainException("El CryptoEnvelope de la solicitud no puede ser nulo.", "REQUEST_ENVELOPE_NULL");
        }

        RequestId = requestId;
        Envelope = envelope;
        Status = RequestStatus.Pending;
        ReceivedUtc = receivedUtc;
        SignatureValid = signatureValid;
        IntegrityValid = integrityValid;
        ValidationNotes = string.IsNullOrWhiteSpace(validationNotes)
            ? string.Empty
            : validationNotes.Trim();
    }

    /// <summary>
    /// Aprueba la solicitud para su procesamiento posterior si permanece en <see cref="RequestStatus.Pending"/>
    /// y tanto la firma como la integridad son válidas.
    /// </summary>
    /// <exception cref="DomainException">
    /// Se lanza si el estado actual no es <see cref="RequestStatus.Pending"/> o si la firma o la integridad son inválidas.
    /// </exception>
    public void Accept()
    {
        if (Status != RequestStatus.Pending)
        {
            throw new DomainException(
                $"No se puede aceptar la solicitud en estado '{Status}'. Solo se permiten transiciones desde Pending.",
                "REQUEST_INVALID_TRANSITION");
        }

        if (!SignatureValid)
        {
            throw new DomainException(
                "No se puede aceptar una solicitud cuya firma digital o certificado X.509 es inválido.",
                "REQUEST_INVALID_SIGNATURE");
        }

        if (!IntegrityValid)
        {
            throw new DomainException(
                "No se puede aceptar una solicitud cuya integridad criptográfica ha fallado.",
                "REQUEST_INVALID_INTEGRITY");
        }

        Status = RequestStatus.Accepted;
        ProcessedUtc = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Rechaza la solicitud desde el estado <see cref="RequestStatus.Pending"/> registrando un motivo obligatorio.
    /// </summary>
    /// <param name="reason">Justificación clara del rechazo.</param>
    /// <exception cref="DomainException">
    /// Se lanza si el estado actual no es <see cref="RequestStatus.Pending"/> o el motivo está vacío.
    /// </exception>
    public void Reject(string reason)
    {
        if (Status != RequestStatus.Pending)
        {
            throw new DomainException(
                $"No se puede rechazar la solicitud en estado '{Status}'. Solo se permiten transiciones desde Pending.",
                "REQUEST_INVALID_TRANSITION");
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainException(
                "Se requiere un motivo explícito para rechazar una solicitud.",
                "REQUEST_REJECTION_REASON_EMPTY");
        }

        Status = RequestStatus.Rejected;
        RejectionReason = reason.Trim();
        ProcessedUtc = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Marca una solicitud aceptada como re-encriptada y retransmitida al siguiente nodo.
    /// </summary>
    /// <exception cref="DomainException">Se lanza si la solicitud no está en estado <see cref="RequestStatus.Accepted"/>.</exception>
    public void MarkRelayed()
    {
        if (Status != RequestStatus.Accepted)
        {
            throw new DomainException(
                $"Solo una solicitud en estado Accepted puede pasar a Relayed (estado actual: '{Status}').",
                "REQUEST_INVALID_TRANSITION");
        }

        Status = RequestStatus.Relayed;
        ProcessedUtc = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Marca una solicitud aceptada como auditada en el nodo final.
    /// </summary>
    /// <exception cref="DomainException">Se lanza si la solicitud no está en estado <see cref="RequestStatus.Accepted"/>.</exception>
    public void MarkAudited()
    {
        if (Status != RequestStatus.Accepted)
        {
            throw new DomainException(
                $"Solo una solicitud en estado Accepted puede pasar a Audited (estado actual: '{Status}').",
                "REQUEST_INVALID_TRANSITION");
        }

        Status = RequestStatus.Audited;
        ProcessedUtc = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Marca una solicitud en curso (<see cref="RequestStatus.Pending"/> o <see cref="RequestStatus.Accepted"/>) como fallida.
    /// </summary>
    /// <param name="reason">Motivo técnico del fallo.</param>
    /// <exception cref="DomainException">Se lanza si el estado actual es terminal o el motivo está vacío.</exception>
    public void MarkFailed(string reason)
    {
        if (Status is not (RequestStatus.Pending or RequestStatus.Accepted))
        {
            throw new DomainException(
                $"No se puede marcar como Failed una solicitud en estado '{Status}'.",
                "REQUEST_INVALID_TRANSITION");
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new DomainException(
                "Se requiere indicar el motivo del fallo.",
                "REQUEST_FAILURE_REASON_EMPTY");
        }

        Status = RequestStatus.Failed;
        RejectionReason = reason.Trim();
        ProcessedUtc = DateTimeOffset.UtcNow;
    }
}
