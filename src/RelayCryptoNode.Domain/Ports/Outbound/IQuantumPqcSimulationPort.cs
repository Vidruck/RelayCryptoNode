namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Resultado de una simulación del protocolo de distribución cuántica de claves BB84.
/// </summary>
/// <param name="SharedKey">Clave simétrica destilada tras el cribado de bases.</param>
/// <param name="SiftedBitCount">Cantidad de bits útiles conservados tras coincidencia de bases.</param>
/// <param name="EstimatedQber">Tasa estimada de error cuántico de bit (QBER) en el rango <c>[0.0, 1.0]</c>.</param>
/// <param name="EavesdroppingDetected">Indica si el QBER supera el umbral indicando posible intercepción (Eve).</param>
public sealed record Bb84SimulationResult(
    byte[] SharedKey,
    int SiftedBitCount,
    double EstimatedQber,
    bool EavesdroppingDetected);

/// <summary>
/// Puerto de salida para simulación cuántica QKD BB84 y cifrado basado en retículos LWE.
/// </summary>
public interface IQuantumPqcSimulationPort
{
    /// <summary>
    /// Ejecuta una simulación completa del protocolo BB84 (emisión de qubits, bases aleatorias, cribado y detección QBER).
    /// </summary>
    /// <param name="bitCount">Número inicial de fotones/qubits transmitidos.</param>
    /// <param name="simulateEavesdropper">Activa un interceptor Eve de medición-reenvío sobre el canal cuántico.</param>
    /// <returns>Resultado con clave compartida, bits cribados y diagnóstico de intercepción.</returns>
    Bb84SimulationResult SimulateBb84KeyExchange(int bitCount = 512, bool simulateEavesdropper = false);

    /// <summary>
    /// Cifra un mensaje en claro mediante un esquema simétrico basado en problemas Learning With Errors (LWE) sobre anillo modular.
    /// </summary>
    /// <param name="plaintext">Bytes en claro.</param>
    /// <param name="key">Clave secreta.</param>
    /// <param name="nonce">Nonce de sesión.</param>
    /// <returns>Texto cifrado LWE.</returns>
    byte[] EncryptLwe(byte[] plaintext, byte[] key, byte[] nonce);

    /// <summary>
    /// Descifra un mensaje protegido con LWE recuperando los bytes originales sin pérdida.
    /// </summary>
    /// <param name="ciphertext">Bytes cifrados LWE.</param>
    /// <param name="key">Clave secreta.</param>
    /// <param name="nonce">Nonce de sesión.</param>
    /// <returns>Bytes originales en claro.</returns>
    byte[] DecryptLwe(byte[] ciphertext, byte[] key, byte[] nonce);
}
