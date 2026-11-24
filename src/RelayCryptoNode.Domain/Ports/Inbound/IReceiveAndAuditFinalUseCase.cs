using RelayCryptoNode.Domain.Entities;

namespace RelayCryptoNode.Domain.Ports.Inbound;

/// <summary>
/// Comando de entrada para descifrar y auditar un paquete en el rol <see cref="Enums.NodeRole.Final"/>.
/// </summary>
/// <param name="RequestId">Identificador de la solicitud entrante aceptada.</param>
/// <param name="PersistEvidence">Indica si los archivos recuperados y el reporte deben persistirse como evidencia.</param>
public sealed record ReceiveAndAuditFinalCommand(
    Guid RequestId,
    bool PersistEvidence = true);

/// <summary>
/// Resultado del descifrado y auditoría bit a bit ejecutados por el nodo final.
/// </summary>
/// <param name="RequestId">Identificador de la solicitud auditada.</param>
/// <param name="RecoveredBundle">Lote de archivos o mensajes recuperado tras el descifrado.</param>
/// <param name="AuditReport">Reporte detallado de comparación bit a bit contra el testigo original.</param>
/// <param name="EvidenceStorageLocation">Ruta o identificador lógico donde se resguardó la evidencia, si aplica.</param>
public sealed record ReceiveAndAuditFinalResult(
    Guid RequestId,
    PayloadBundle RecoveredBundle,
    IntegrityAuditReport AuditReport,
    string? EvidenceStorageLocation = null);

/// <summary>
/// Puerto de entrada para el caso de uso del rol <see cref="Enums.NodeRole.Final"/>.
/// </summary>
public interface IReceiveAndAuditFinalUseCase
{
    /// <summary>
    /// Descifra el paquete recibido y compara bit a bit tamaño, cantidad de ítems y hashes SHA-256 contra el testigo original.
    /// </summary>
    /// <param name="command">Parámetros de auditoría final.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Lote recuperado y reporte completo de auditoría.</returns>
    Task<ReceiveAndAuditFinalResult> ExecuteAsync(
        ReceiveAndAuditFinalCommand command,
        CancellationToken cancellationToken = default);
}
