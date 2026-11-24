namespace RelayCryptoNode.Domain.Enums;

/// <summary>
/// Clasificación semántica del contenido transportado dentro de un <see cref="Entities.PayloadBundle"/>.
/// </summary>
public enum PayloadKind
{
    /// <summary>
    /// Mensaje de texto plano codificado en UTF-8.
    /// </summary>
    PlainText = 1,

    /// <summary>
    /// Documento estructurado u ofimático (PDF, DOCX, JSON, XML, entre otros).
    /// </summary>
    Document = 2,

    /// <summary>
    /// Archivo de imagen digital (PNG, JPEG, WebP, TIFF, entre otros).
    /// </summary>
    Image = 3,

    /// <summary>
    /// Carga binaria arbitraria o ejecutable/archivo genérico.
    /// </summary>
    Binary = 4,

    /// <summary>
    /// Conjunto heterogéneo compuesto por múltiples archivos o recursos multimedia.
    /// </summary>
    MultiPartBundle = 5
}
