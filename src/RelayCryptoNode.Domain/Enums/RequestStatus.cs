namespace RelayCryptoNode.Domain.Enums;

/// <summary>
/// Estados posibles en el ciclo de vida de una solicitud entrante en la bandeja del nodo.
/// </summary>
public enum RequestStatus
{
    /// <summary>
    /// Solicitud recién recibida, pendiente de aprobación operativa o procesamiento.
    /// </summary>
    Pending = 1,

    /// <summary>
    /// Solicitud validada y aceptada para descifrado, relevo o auditoría.
    /// </summary>
    Accepted = 2,

    /// <summary>
    /// Solicitud rechazada por el operador o por política de validación.
    /// </summary>
    Rejected = 3,

    /// <summary>
    /// Paquete re-encriptado y retransmitido exitosamente al siguiente nodo de la cadena.
    /// </summary>
    Relayed = 4,

    /// <summary>
    /// Paquete descifrado y auditado bit a bit en el nodo final.
    /// </summary>
    Audited = 5,

    /// <summary>
    /// Procesamiento fallido tras un error criptográfico, de integridad o de transporte.
    /// </summary>
    Failed = 6
}
