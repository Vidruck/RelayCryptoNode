using System.Collections.ObjectModel;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Domain.Entities;

/// <summary>
/// Entidad inmutable que agrupa uno o más elementos de carga útil originales antes del cifrado o tras su recuperación.
/// </summary>
public sealed record PayloadBundle
{
    /// <summary>
    /// Identificador único del lote de carga útil.
    /// </summary>
    public Guid BundleId { get; }

    /// <summary>
    /// Clasificación semántica de la carga útil transportada.
    /// </summary>
    public PayloadKind Kind { get; }

    /// <summary>
    /// Colección de solo lectura con al menos un <see cref="PayloadItem"/>.
    /// </summary>
    public IReadOnlyList<PayloadItem> Items { get; }

    /// <summary>
    /// Huella digital SHA-256 global del lote completo.
    /// </summary>
    public IntegrityDigest BundleSha256Hash { get; }

    /// <summary>
    /// Marca de tiempo UTC de creación del lote.
    /// </summary>
    public DateTimeOffset CreatedUtc { get; }

    /// <summary>
    /// Suma total en bytes de todos los elementos contenidos en el lote.
    /// </summary>
    public long TotalSizeBytes { get; }

    /// <summary>
    /// Inicializa un <see cref="PayloadBundle"/> garantizando al menos un elemento válido y huella SHA-256 de 64 hex.
    /// </summary>
    /// <param name="bundleId">Identificador único del lote.</param>
    /// <param name="kind">Tipo de carga útil.</param>
    /// <param name="items">Lista no vacía de elementos <see cref="PayloadItem"/>.</param>
    /// <param name="bundleSha256Hash">Hash SHA-256 testigo global del lote.</param>
    /// <param name="createdUtc">Fecha y hora UTC de creación.</param>
    /// <exception cref="DomainException">Se lanza si el lote está vacío o contiene datos inválidos.</exception>
    public PayloadBundle(
        Guid bundleId,
        PayloadKind kind,
        IReadOnlyList<PayloadItem> items,
        IntegrityDigest bundleSha256Hash,
        DateTimeOffset createdUtc)
    {
        if (bundleId == Guid.Empty)
        {
            throw new DomainException("El BundleId no puede ser Guid.Empty.", "PAYLOAD_BUNDLE_ID_EMPTY");
        }

        if (items is null || items.Count == 0)
        {
            throw new DomainException(
                "Un PayloadBundle debe contener al menos un PayloadItem.",
                "PAYLOAD_BUNDLE_EMPTY");
        }

        var copiedItems = new List<PayloadItem>(items.Count);
        long totalSize = 0;

        foreach (var item in items)
        {
            if (item is null)
            {
                throw new DomainException("Un PayloadBundle no puede contener elementos nulos.", "PAYLOAD_BUNDLE_NULL_ITEM");
            }

            copiedItems.Add(item);
            totalSize += item.SizeBytes;
        }

        if (bundleSha256Hash is null || bundleSha256Hash.HexHash.Length != 64)
        {
            throw new DomainException(
                "El PayloadBundle requiere un BundleSha256Hash SHA-256 válido de 64 caracteres hexadecimales.",
                "PAYLOAD_BUNDLE_SHA256_INVALID");
        }

        BundleId = bundleId;
        Kind = kind;
        Items = new ReadOnlyCollection<PayloadItem>(copiedItems);
        BundleSha256Hash = bundleSha256Hash;
        CreatedUtc = createdUtc;
        TotalSizeBytes = totalSize;
    }
}
