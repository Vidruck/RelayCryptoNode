namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Puerto de salida para cifrados de flujo simétricos involutivos basados en registros XOR o rotores históricos (por ejemplo <c>XORASM</c> y <c>LORENZSZ40</c>).
/// </summary>
public interface IStreamRotorCipherPort
{
    /// <summary>
    /// Aplica el flujo de clave pseudoaleatorio o de rotores mediante XOR sobre los datos de entrada.
    /// </summary>
    /// <param name="input">Bytes de entrada (en claro o cifrados).</param>
    /// <param name="key">Clave secreta para inicializar registros o posición inicial de ruedas.</param>
    /// <param name="nonce">Nonce de sesión.</param>
    /// <returns>Bytes transformados de la misma longitud que <paramref name="input"/>.</returns>
    byte[] TransformStream(byte[] input, byte[] key, byte[] nonce);
}
