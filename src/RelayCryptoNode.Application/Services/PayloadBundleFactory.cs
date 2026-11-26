using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Application.Services;

/// <summary>
/// Archivo de entrada para armar un lote (lo que el operador sube desde el panel).
/// </summary>
/// <param name="FileName">Nombre original del archivo.</param>
/// <param name="MimeType">Tipo MIME declarado (opcional).</param>
/// <param name="Content">Bytes del archivo.</param>
public sealed record PayloadFileInput(string FileName, string? MimeType, byte[] Content);

/// <summary>
/// Datos del archivo original que viajan en <c>originalPayload</c> del manifiesto.
/// </summary>
/// <param name="Sha256">Huella testigo SHA-256 de la carga útil en claro.</param>
/// <param name="FileName">Nombre del archivo (o del lote).</param>
/// <param name="Extension">Extensión con punto.</param>
/// <param name="SizeBytes">Tamaño en bytes de la carga útil en claro.</param>
public sealed record OriginalPayloadInfo(IntegrityDigest Sha256, string FileName, string Extension, long SizeBytes);

/// <summary>
/// Arma <see cref="PayloadBundle"/> con sus huellas SHA-256 a partir de archivos o texto.
/// </summary>
public sealed class PayloadBundleFactory
{
    private static readonly IntegrityDigest Placeholder = IntegrityDigest.Sha256(new string('0', 64));

    private readonly IPackageSerializerPort _serializer;
    private readonly IHashingServicePort _hashing;

    /// <summary>
    /// Crea la fábrica de lotes.
    /// </summary>
    public PayloadBundleFactory(IPackageSerializerPort serializer, IHashingServicePort hashing)
    {
        _serializer = serializer;
        _hashing = hashing;
    }

    /// <summary>
    /// Arma un lote con uno o varios archivos. La huella del lote es el SHA-256 de su forma serializada.
    /// </summary>
    public PayloadBundle Create(IReadOnlyList<PayloadFileInput> files)
    {
        if (files is null || files.Count == 0)
        {
            throw new DomainException("Debe enviar al menos un archivo o un texto.", "PAYLOAD_INPUT_EMPTY");
        }

        var items = new List<PayloadItem>(files.Count);
        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            var name = UniqueName(SafeFileName(file.FileName), usedNames);
            var extension = Path.GetExtension(name);
            var mime = string.IsNullOrWhiteSpace(file.MimeType) ? GuessMimeType(extension) : file.MimeType.Trim();
            items.Add(new PayloadItem(
                name,
                extension,
                mime,
                file.Content.LongLength,
                file.Content,
                _hashing.ComputeHash(file.Content)));
        }

        var kind = items.Count > 1 ? PayloadKind.MultiPartBundle : GuessKind(items[0]);
        var bundleId = Guid.NewGuid();
        var createdUtc = DateTimeOffset.UtcNow;

        var draft = new PayloadBundle(bundleId, kind, items, Placeholder, createdUtc);
        var serialized = _serializer.SerializePayloadBundle(draft);
        return new PayloadBundle(bundleId, kind, items, _hashing.ComputeHash(serialized), createdUtc);
    }

    /// <summary>
    /// Arma un lote con un mensaje de texto plano (UTF-8).
    /// </summary>
    public PayloadBundle FromText(string text, string? fileName = null)
    {
        if (string.IsNullOrEmpty(text))
        {
            throw new DomainException("El mensaje de texto está vacío.", "PAYLOAD_TEXT_EMPTY");
        }

        var name = string.IsNullOrWhiteSpace(fileName) ? "mensaje.txt" : fileName;
        return Create([new PayloadFileInput(name, "text/plain; charset=utf-8", System.Text.Encoding.UTF8.GetBytes(text))]);
    }

    /// <summary>
    /// Describe la carga útil original tal como se declara en el manifiesto.
    /// </summary>
    public static OriginalPayloadInfo DescribeOriginal(PayloadBundle bundle, long serializedSize)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        if (bundle.Items.Count == 1)
        {
            var item = bundle.Items[0];
            return new OriginalPayloadInfo(bundle.BundleSha256Hash, item.FileName, item.Extension, serializedSize);
        }

        return new OriginalPayloadInfo(
            bundle.BundleSha256Hash,
            $"lote_{bundle.Items.Count}_archivos.zip",
            ".zip",
            serializedSize);
    }

    /// <summary>
    /// Deduce el tipo MIME a partir de la extensión.
    /// </summary>
    public static string GuessMimeType(string? extension) => (extension ?? string.Empty).ToLowerInvariant() switch
    {
        ".txt" => "text/plain",
        ".pdf" => "application/pdf",
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".bmp" => "image/bmp",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".doc" => "application/msword",
        ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".json" => "application/json",
        ".zip" => "application/zip",
        ".mp3" => "audio/mpeg",
        ".mp4" => "video/mp4",
        _ => "application/octet-stream"
    };

    private static PayloadKind GuessKind(PayloadItem item)
    {
        if (item.MimeType.StartsWith("text/", StringComparison.OrdinalIgnoreCase))
        {
            return PayloadKind.PlainText;
        }

        if (item.MimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
        {
            return PayloadKind.Image;
        }

        return item.Extension.ToLowerInvariant() is ".pdf" or ".doc" or ".docx" or ".xlsx" or ".pptx" or ".odt"
            ? PayloadKind.Document
            : PayloadKind.Binary;
    }

    private static string SafeFileName(string? fileName)
    {
        var name = Path.GetFileName((fileName ?? string.Empty).Replace('\\', '/'));
        foreach (var invalid in Path.GetInvalidFileNameChars().Concat(['/', '\\', ':', '*', '?', '"', '<', '>', '|']))
        {
            name = name.Replace(invalid, '_');
        }

        return string.IsNullOrWhiteSpace(name) ? "archivo.bin" : name.Trim();
    }

    private static string UniqueName(string name, HashSet<string> usedNames)
    {
        var candidate = name;
        var counter = 2;
        while (!usedNames.Add(candidate))
        {
            candidate = $"{Path.GetFileNameWithoutExtension(name)}_{counter++}{Path.GetExtension(name)}";
        }

        return candidate;
    }
}
