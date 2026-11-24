namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Puerto de salida para ocultar y recuperar carga útil mediante esteganografía LSB en imágenes BMP y PNG.
/// </summary>
public interface ISteganographyPort
{
    /// <summary>
    /// Incrusta una carga útil binaria en los bits menos significativos (LSB) de una imagen portadora BMP o PNG.
    /// </summary>
    /// <param name="carrierImageBytes">Bytes de la imagen portadora en formato BMP o PNG sin compresión con pérdida.</param>
    /// <param name="payload">Bytes de carga útil a ocultar.</param>
    /// <returns>Imagen resultante con la carga útil incrustada manteniendo compatibilidad visual.</returns>
    byte[] EmbedPayload(byte[] carrierImageBytes, byte[] payload);

    /// <summary>
    /// Extrae la carga útil binaria previamente incrustada en una imagen esteganográfica BMP o PNG.
    /// </summary>
    /// <param name="stegoImageBytes">Bytes de la imagen BMP o PNG que contiene el mensaje oculto.</param>
    /// <returns>Bytes recuperados exactamente bit a bit.</returns>
    byte[] ExtractPayload(byte[] stegoImageBytes);
}
