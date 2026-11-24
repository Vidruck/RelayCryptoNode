using RelayCryptoNode.Domain.Enums;

namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Resultado de una operación de cifrado simétrico autenticado.
/// </summary>
/// <param name="Ciphertext">Bytes cifrados resultantes.</param>
/// <param name="IvOrNonce">Vector de inicialización o nonce generado.</param>
/// <param name="AuthTag">Etiqueta de autenticación AEAD o HMAC.</param>
/// <param name="ExtraMetadata">Metadatos adicionales opcionales propios del algoritmo.</param>
public sealed record SymmetricEncryptionResult(
    byte[] Ciphertext,
    byte[] IvOrNonce,
    byte[] AuthTag,
    IReadOnlyDictionary<string, string>? ExtraMetadata = null);

/// <summary>
/// Puerto de salida (patrón Estrategia) para algoritmos de cifrado simétrico vigentes.
/// </summary>
public interface ISymmetricCipherStrategy
{
    /// <summary>
    /// Algoritmo simétrico principal implementado por esta estrategia.
    /// </summary>
    CipherAlgorithmType Algorithm { get; }

    /// <summary>
    /// Determina si esta estrategia soporta el algoritmo solicitado.
    /// </summary>
    /// <param name="algorithm">Algoritmo a evaluar.</param>
    /// <returns><c>true</c> si la estrategia puede cifrar y descifrar con dicho algoritmo.</returns>
    bool CanHandle(CipherAlgorithmType algorithm);

    /// <summary>
    /// Cifra el texto en claro utilizando la clave simétrica proporcionada y datos asociados opcionales.
    /// </summary>
    /// <param name="plaintext">Bytes originales en claro.</param>
    /// <param name="key">Clave simétrica de sesión.</param>
    /// <param name="associatedData">Datos autenticados adicionales (AAD) opcionales.</param>
    /// <returns>Resultado con texto cifrado, IV/nonce y etiqueta de autenticación.</returns>
    SymmetricEncryptionResult Encrypt(
        byte[] plaintext,
        byte[] key,
        byte[]? associatedData = null);

    /// <summary>
    /// Descifra y autentica el texto cifrado verificando la etiqueta de autenticación.
    /// </summary>
    /// <param name="ciphertext">Bytes cifrados.</param>
    /// <param name="key">Clave simétrica de sesión.</param>
    /// <param name="ivOrNonce">Vector de inicialización o nonce utilizado en el cifrado.</param>
    /// <param name="authTag">Etiqueta de autenticación AEAD o HMAC.</param>
    /// <param name="associatedData">Datos autenticados adicionales (AAD) opcionales.</param>
    /// <returns>Bytes originales en claro.</returns>
    byte[] Decrypt(
        byte[] ciphertext,
        byte[] key,
        byte[] ivOrNonce,
        byte[]? authTag,
        byte[]? associatedData = null);
}
