using System.Collections.ObjectModel;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Domain.Entities;

/// <summary>
/// Resultado individual de auditoría bit a bit para cada archivo recuperado en el nodo final.
/// </summary>
public sealed record ItemAuditResult
{
    /// <summary>
    /// Nombre del archivo auditado.
    /// </summary>
    public string FileName { get; }

    /// <summary>
    /// Resumen SHA-256 esperado del archivo original.
    /// </summary>
    public IntegrityDigest ExpectedSha256 { get; }

    /// <summary>
    /// Resumen SHA-256 calculado tras el descifrado en el nodo final.
    /// </summary>
    public IntegrityDigest ComputedSha256 { get; }

    /// <summary>
    /// Tamaño esperado en bytes del archivo original.
    /// </summary>
    public long ExpectedSizeBytes { get; }

    /// <summary>
    /// Tamaño real en bytes del archivo recuperado.
    /// </summary>
    public long ActualSizeBytes { get; }

    /// <summary>
    /// Indica si el archivo recuperado es idéntico bit a bit al original.
    /// </summary>
    public bool IsBitExactMatch { get; }

    /// <summary>
    /// Diferencia absoluta en bytes entre el tamaño esperado y el recuperado.
    /// </summary>
    public long ByteLossCount { get; }

    private ItemAuditResult(
        string fileName,
        IntegrityDigest expectedSha256,
        IntegrityDigest computedSha256,
        long expectedSizeBytes,
        long actualSizeBytes,
        bool isBitExactMatch,
        long byteLossCount)
    {
        FileName = fileName;
        ExpectedSha256 = expectedSha256;
        ComputedSha256 = computedSha256;
        ExpectedSizeBytes = expectedSizeBytes;
        ActualSizeBytes = actualSizeBytes;
        IsBitExactMatch = isBitExactMatch;
        ByteLossCount = byteLossCount;
    }

    /// <summary>
    /// Crea un <see cref="ItemAuditResult"/> calculando automáticamente la coincidencia bit a bit y la diferencia de bytes.
    /// </summary>
    /// <param name="fileName">Nombre del archivo.</param>
    /// <param name="expectedSha256">Hash SHA-256 original.</param>
    /// <param name="computedSha256">Hash SHA-256 calculado.</param>
    /// <param name="expectedSizeBytes">Tamaño esperado en bytes.</param>
    /// <param name="actualSizeBytes">Tamaño real en bytes.</param>
    /// <returns>Instancia auditada de <see cref="ItemAuditResult"/>.</returns>
    /// <exception cref="DomainException">Se lanza si los argumentos son nulos o los tamaños son negativos.</exception>
    public static ItemAuditResult CreateComparison(
        string fileName,
        IntegrityDigest expectedSha256,
        IntegrityDigest computedSha256,
        long expectedSizeBytes,
        long actualSizeBytes)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new DomainException("El nombre del archivo auditado no puede estar vacío.", "AUDIT_ITEM_FILENAME_EMPTY");
        }

        if (expectedSha256 is null || computedSha256 is null)
        {
            throw new DomainException("Los digests esperado y calculado son obligatorios.", "AUDIT_ITEM_DIGEST_NULL");
        }

        if (expectedSizeBytes < 0 || actualSizeBytes < 0)
        {
            throw new DomainException("Los tamaños de auditoría no pueden ser negativos.", "AUDIT_ITEM_SIZE_NEGATIVE");
        }

        var byteLossCount = Math.Abs(expectedSizeBytes - actualSizeBytes);
        var hashesEqual = string.Equals(expectedSha256.HexHash, computedSha256.HexHash, StringComparison.Ordinal);
        var isExact = hashesEqual && byteLossCount == 0;

        return new ItemAuditResult(
            fileName.Trim(),
            expectedSha256,
            computedSha256,
            expectedSizeBytes,
            actualSizeBytes,
            isExact,
            byteLossCount);
    }
}

/// <summary>
/// Reporte global de auditoría bit a bit generado por el nodo en rol <see cref="Enums.NodeRole.Final"/>.
/// </summary>
public sealed record IntegrityAuditReport
{
    /// <summary>
    /// Identificador único del reporte de auditoría.
    /// </summary>
    public Guid AuditId { get; }

    /// <summary>
    /// Identificador del paquete auditado.
    /// </summary>
    public Guid PacketId { get; }

    /// <summary>
    /// Fecha y hora UTC en que se ejecutó la auditoría.
    /// </summary>
    public DateTimeOffset AuditedUtc { get; }

    /// <summary>
    /// Indica si no existió ninguna pérdida ni alteración bit a bit tanto a nivel global como en todos los ítems.
    /// </summary>
    public bool IsBitExactMatch { get; }

    /// <summary>
    /// Hash SHA-256 testigo original emitido por el nodo inicial.
    /// </summary>
    public IntegrityDigest ExpectedOriginalSha256 { get; }

    /// <summary>
    /// Hash SHA-256 calculado tras el descifrado final.
    /// </summary>
    public IntegrityDigest ComputedSha256 { get; }

    /// <summary>
    /// Tamaño original esperado en bytes del paquete completo.
    /// </summary>
    public long ExpectedSizeBytes { get; }

    /// <summary>
    /// Tamaño real recuperado en bytes del paquete completo.
    /// </summary>
    public long ActualSizeBytes { get; }

    /// <summary>
    /// Diferencia absoluta en bytes entre el tamaño original esperado y el recuperado.
    /// </summary>
    public long ByteLossCount { get; }

    /// <summary>
    /// Resultados detallados por cada archivo o ítem incluido en el paquete.
    /// </summary>
    public IReadOnlyList<ItemAuditResult> ItemAuditResults { get; }

    private IntegrityAuditReport(
        Guid auditId,
        Guid packetId,
        DateTimeOffset auditedUtc,
        bool isBitExactMatch,
        IntegrityDigest expectedOriginalSha256,
        IntegrityDigest computedSha256,
        long expectedSizeBytes,
        long actualSizeBytes,
        long byteLossCount,
        IReadOnlyList<ItemAuditResult> itemAuditResults)
    {
        AuditId = auditId;
        PacketId = packetId;
        AuditedUtc = auditedUtc;
        IsBitExactMatch = isBitExactMatch;
        ExpectedOriginalSha256 = expectedOriginalSha256;
        ComputedSha256 = computedSha256;
        ExpectedSizeBytes = expectedSizeBytes;
        ActualSizeBytes = actualSizeBytes;
        ByteLossCount = byteLossCount;
        ItemAuditResults = itemAuditResults;
    }

    /// <summary>
    /// Método fábrica estático que compara el paquete recuperado contra el testigo original y determina pérdidas bit a bit.
    /// </summary>
    /// <param name="auditId">Identificador único de auditoría.</param>
    /// <param name="packetId">Identificador del paquete auditado.</param>
    /// <param name="auditedUtc">Marca temporal UTC de auditoría.</param>
    /// <param name="expectedOriginalSha256">Hash SHA-256 testigo original.</param>
    /// <param name="computedSha256">Hash SHA-256 calculado sobre la carga recuperada.</param>
    /// <param name="expectedSizeBytes">Tamaño original esperado en bytes.</param>
    /// <param name="actualSizeBytes">Tamaño real recuperado en bytes.</param>
    /// <param name="itemAuditResults">Resultados opcionales por archivo individual.</param>
    /// <returns>Reporte consolidado de auditoría <see cref="IntegrityAuditReport"/>.</returns>
    /// <exception cref="DomainException">Se lanza si los identificadores son vacíos o los tamaños son negativos.</exception>
    public static IntegrityAuditReport CreateComparison(
        Guid auditId,
        Guid packetId,
        DateTimeOffset auditedUtc,
        IntegrityDigest expectedOriginalSha256,
        IntegrityDigest computedSha256,
        long expectedSizeBytes,
        long actualSizeBytes,
        IReadOnlyList<ItemAuditResult>? itemAuditResults = null)
    {
        if (auditId == Guid.Empty)
        {
            throw new DomainException("El AuditId no puede ser Guid.Empty.", "AUDIT_ID_EMPTY");
        }

        if (packetId == Guid.Empty)
        {
            throw new DomainException("El PacketId no puede ser Guid.Empty.", "AUDIT_PACKET_ID_EMPTY");
        }

        if (expectedOriginalSha256 is null || computedSha256 is null)
        {
            throw new DomainException("Los digests esperado y calculado son obligatorios para auditar.", "AUDIT_DIGEST_NULL");
        }

        if (expectedSizeBytes < 0 || actualSizeBytes < 0)
        {
            throw new DomainException("Los tamaños de auditoría no pueden ser negativos.", "AUDIT_SIZE_NEGATIVE");
        }

        var copiedItems = new List<ItemAuditResult>();
        if (itemAuditResults is not null)
        {
            foreach (var item in itemAuditResults)
            {
                if (item is null)
                {
                    throw new DomainException("La lista de resultados de ítems no puede contener nulos.", "AUDIT_NULL_ITEM");
                }

                copiedItems.Add(item);
            }
        }

        var byteLossCount = Math.Abs(expectedSizeBytes - actualSizeBytes);
        var globalHashMatch = string.Equals(
            expectedOriginalSha256.HexHash,
            computedSha256.HexHash,
            StringComparison.Ordinal);
        var allItemsMatch = copiedItems.All(static item => item.IsBitExactMatch);
        var isBitExactMatch = globalHashMatch && byteLossCount == 0 && allItemsMatch;

        return new IntegrityAuditReport(
            auditId,
            packetId,
            auditedUtc,
            isBitExactMatch,
            expectedOriginalSha256,
            computedSha256,
            expectedSizeBytes,
            actualSizeBytes,
            byteLossCount,
            new ReadOnlyCollection<ItemAuditResult>(copiedItems));
    }
}
