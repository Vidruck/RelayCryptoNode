using System.Text.Json;
using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Infrastructure.Persistence;

/// <summary>
/// Guarda los archivos recuperados y el reporte de auditoría en <c>evidencia/&lt;packetId&gt;/</c>.
/// </summary>
public sealed class FileSystemEvidenceStorage : IEvidenceStoragePort
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _root;

    /// <summary>
    /// Crea el almacenamiento de evidencias en la carpeta indicada.
    /// </summary>
    public FileSystemEvidenceStorage(string rootDirectory)
    {
        _root = rootDirectory;
        Directory.CreateDirectory(_root);
    }

    /// <inheritdoc />
    public async Task<string> SaveAuditEvidenceAsync(
        PayloadBundle bundle,
        IntegrityAuditReport report,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        ArgumentNullException.ThrowIfNull(report);

        var folder = Path.Combine(_root, report.PacketId.ToString("N"));
        var files = Path.Combine(folder, "archivos");
        Directory.CreateDirectory(files);
        foreach (var item in bundle.Items)
        {
            var safeName = Path.GetFileName(item.FileName);
            await File.WriteAllBytesAsync(Path.Combine(files, safeName), item.RawBytes, cancellationToken).ConfigureAwait(false);
        }

        var dto = new StoredAudit(
            report.AuditId,
            report.PacketId,
            report.AuditedUtc,
            report.IsBitExactMatch,
            report.ExpectedOriginalSha256.HexHash,
            report.ComputedSha256.HexHash,
            report.ExpectedSizeBytes,
            report.ActualSizeBytes,
            report.ByteLossCount,
            report.ItemAuditResults.Select(i => new StoredItem(
                i.FileName,
                i.ExpectedSha256.HexHash,
                i.ComputedSha256.HexHash,
                i.ExpectedSizeBytes,
                i.ActualSizeBytes,
                i.IsBitExactMatch,
                i.ByteLossCount)).ToList());
        await File.WriteAllTextAsync(
            Path.Combine(folder, "auditoria.json"),
            JsonSerializer.Serialize(dto, JsonOptions),
            cancellationToken).ConfigureAwait(false);
        return folder;
    }

    /// <inheritdoc />
    public async Task<IntegrityAuditReport?> GetAuditReportByPacketIdAsync(Guid packetId, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(_root, packetId.ToString("N"), "auditoria.json");
        if (!File.Exists(path))
        {
            return null;
        }

        var dto = JsonSerializer.Deserialize<StoredAudit>(await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false));
        if (dto is null)
        {
            return null;
        }

        var items = dto.Items.Select(i => ItemAuditResult.CreateComparison(
            i.FileName,
            IntegrityDigest.Sha256(i.ExpectedSha256),
            IntegrityDigest.Sha256(i.ComputedSha256),
            i.ExpectedSizeBytes,
            i.ActualSizeBytes)).ToList();
        return IntegrityAuditReport.CreateComparison(
            dto.AuditId,
            dto.PacketId,
            dto.AuditedUtc,
            IntegrityDigest.Sha256(dto.ExpectedSha256),
            IntegrityDigest.Sha256(dto.ComputedSha256),
            dto.ExpectedSizeBytes,
            dto.ActualSizeBytes,
            items);
    }

    /// <summary>
    /// Ruta del archivo recuperado de un paquete, o <c>null</c> si no existe.
    /// </summary>
    public string? RecoveredFilePath(Guid packetId, string fileName)
    {
        var safeName = Path.GetFileName(fileName);
        var path = Path.Combine(_root, packetId.ToString("N"), "archivos", safeName);
        return File.Exists(path) ? path : null;
    }

    private sealed record StoredAudit(
        Guid AuditId,
        Guid PacketId,
        DateTimeOffset AuditedUtc,
        bool IsBitExactMatch,
        string ExpectedSha256,
        string ComputedSha256,
        long ExpectedSizeBytes,
        long ActualSizeBytes,
        long ByteLossCount,
        List<StoredItem> Items);

    private sealed record StoredItem(
        string FileName,
        string ExpectedSha256,
        string ComputedSha256,
        long ExpectedSizeBytes,
        long ActualSizeBytes,
        bool IsBitExactMatch,
        long ByteLossCount);
}
