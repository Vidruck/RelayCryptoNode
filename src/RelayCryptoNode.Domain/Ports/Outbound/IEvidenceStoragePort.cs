using RelayCryptoNode.Domain.Entities;

namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Puerto de salida para almacenar archivos recuperados y reportes de auditoría de pérdidas en el nodo final.
/// </summary>
public interface IEvidenceStoragePort
{
    /// <summary>
    /// Persiste los archivos recuperados de un <see cref="PayloadBundle"/> junto con su <see cref="IntegrityAuditReport"/>.
    /// </summary>
    /// <param name="bundle">Lote de archivos recuperados.</param>
    /// <param name="report">Reporte de auditoría bit a bit asociado.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Ruta o identificador lógico donde quedó resguardada la evidencia.</returns>
    Task<string> SaveAuditEvidenceAsync(
        PayloadBundle bundle,
        IntegrityAuditReport report,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Recupera un reporte de auditoría previamente almacenado a partir del identificador del paquete.
    /// </summary>
    /// <param name="packetId">Identificador del paquete auditado.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Reporte encontrado o <c>null</c> si no existe.</returns>
    Task<IntegrityAuditReport?> GetAuditReportByPacketIdAsync(
        Guid packetId,
        CancellationToken cancellationToken = default);
}
