namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Puerto de salida para codificación y decodificación reversible en el dominio frecuencial mediante Transformada Discreta de Fourier (DFT).
/// </summary>
public interface ISpectralTransformPort
{
    /// <summary>
    /// Transforma bloques de bytes al dominio espectral mediante DFT y aplica modulación de fase derivada de clave/nonce.
    /// </summary>
    /// <param name="plaintext">Bytes originales.</param>
    /// <param name="key">Clave secreta de modulación espectral.</param>
    /// <param name="nonce">Nonce de sesión.</param>
    /// <returns>Representación binaria del espectro modulado.</returns>
    byte[] EncodeSpectral(byte[] plaintext, byte[] key, byte[] nonce);

    /// <summary>
    /// Revierte la modulación de fase y aplica la DFT inversa recuperando exactamente los bytes originales.
    /// </summary>
    /// <param name="spectralCiphertext">Bytes en dominio espectral.</param>
    /// <param name="key">Misma clave secreta utilizada al codificar.</param>
    /// <param name="nonce">Mismo nonce utilizado al codificar.</param>
    /// <returns>Bytes originales recuperados sin pérdida.</returns>
    byte[] DecodeSpectral(byte[] spectralCiphertext, byte[] key, byte[] nonce);
}
