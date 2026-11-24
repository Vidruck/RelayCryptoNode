using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Domain.Entities;

/// <summary>
/// Entidad inmutable que representa un archivo o elemento individual dentro de un <see cref="PayloadBundle"/>.
/// </summary>
public sealed record PayloadItem
{
    private readonly byte[] _rawBytes;

    /// <summary>
    /// Nombre del archivo con extensión o identificador de ítem.
    /// </summary>
    public string FileName { get; }

    /// <summary>
    /// Extensión del archivo (incluyendo el punto inicial si existe, por ejemplo <c>.png</c>).
    /// </summary>
    public string Extension { get; }

    /// <summary>
    /// Tipo MIME del contenido (por ejemplo <c>image/png</c> o <c>application/octet-stream</c>).
    /// </summary>
    public string MimeType { get; }

    /// <summary>
    /// Tamaño exacto en bytes del contenido sin cifrar.
    /// </summary>
    public long SizeBytes { get; }

    /// <summary>
    /// Copia defensiva de los bytes en claro del elemento.
    /// </summary>
    public byte[] RawBytes => _rawBytes.ToArray();

    /// <summary>
    /// Huella digital SHA-256 exacta del contenido <see cref="RawBytes"/>.
    /// </summary>
    public IntegrityDigest Sha256Hash { get; }

    /// <summary>
    /// Inicializa un <see cref="PayloadItem"/> validando que el tamaño coincida con el arreglo de bytes y el resumen sea SHA-256.
    /// </summary>
    /// <param name="fileName">Nombre del archivo.</param>
    /// <param name="extension">Extensión del archivo.</param>
    /// <param name="mimeType">Tipo MIME del archivo.</param>
    /// <param name="sizeBytes">Tamaño declarado en bytes.</param>
    /// <param name="rawBytes">Contenido binario sin cifrar.</param>
    /// <param name="sha256Hash">Resumen SHA-256 de 64 caracteres hexadecimales.</param>
    /// <exception cref="DomainException">Se lanza si alguna invariante de contenido o tamaño falla.</exception>
    public PayloadItem(
        string fileName,
        string extension,
        string mimeType,
        long sizeBytes,
        byte[] rawBytes,
        IntegrityDigest sha256Hash)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new DomainException("El nombre de archivo del PayloadItem no puede estar vacío.", "PAYLOAD_ITEM_FILENAME_EMPTY");
        }

        if (extension is null)
        {
            throw new DomainException("La extensión del PayloadItem no puede ser nula.", "PAYLOAD_ITEM_EXTENSION_NULL");
        }

        if (string.IsNullOrWhiteSpace(mimeType))
        {
            throw new DomainException("El tipo MIME del PayloadItem no puede estar vacío.", "PAYLOAD_ITEM_MIME_EMPTY");
        }

        if (rawBytes is null)
        {
            throw new DomainException("Los bytes en claro del PayloadItem no pueden ser nulos.", "PAYLOAD_ITEM_BYTES_NULL");
        }

        if (sizeBytes < 0 || sizeBytes != rawBytes.LongLength)
        {
            throw new DomainException(
                $"El tamaño declarado ({sizeBytes} bytes) no coincide con la longitud real de los bytes ({rawBytes.LongLength} bytes).",
                "PAYLOAD_ITEM_SIZE_MISMATCH");
        }

        if (sha256Hash is null || sha256Hash.HexHash.Length != 64)
        {
            throw new DomainException(
                "Cada PayloadItem requiere un IntegrityDigest SHA-256 válido de 64 caracteres hexadecimales.",
                "PAYLOAD_ITEM_SHA256_INVALID");
        }

        FileName = fileName.Trim();
        Extension = extension.Trim();
        MimeType = mimeType.Trim();
        SizeBytes = sizeBytes;
        _rawBytes = rawBytes.ToArray();
        Sha256Hash = sha256Hash;
    }
}
