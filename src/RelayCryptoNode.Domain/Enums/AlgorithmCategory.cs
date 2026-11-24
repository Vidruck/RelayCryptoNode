namespace RelayCryptoNode.Domain.Enums;

/// <summary>
/// Clasificación funcional de cada módulo del catálogo oficial de algoritmos.
/// </summary>
public enum AlgorithmCategory
{
    /// <summary>
    /// Cifrado simétrico por bloques o flujo (AEAD o autenticado).
    /// </summary>
    SymmetricCipher = 1,

    /// <summary>
    /// Envoltura o acuerdo asimétrico de claves.
    /// </summary>
    AsymmetricKeyExchange = 2,

    /// <summary>
    /// Firma digital y verificación con certificados/claves públicas.
    /// </summary>
    DigitalSignature = 3,

    /// <summary>
    /// Funciones de resumen criptográfico y códigos MAC.
    /// </summary>
    HashingAndMac = 4,

    /// <summary>
    /// Cifrados clásicos, de registro XOR y rotores históricos.
    /// </summary>
    ClassicalAndTransposition = 5,

    /// <summary>
    /// Ocultación de carga útil mediante esteganografía en imágenes.
    /// </summary>
    Steganography = 6,

    /// <summary>
    /// Aritmética modular, primalidad y cifrado afín.
    /// </summary>
    ModularMath = 7,

    /// <summary>
    /// Simulación cuántica BB84 y esquemas de retículos LWE.
    /// </summary>
    PostQuantumSimulation = 8,

    /// <summary>
    /// Transformación en el dominio frecuencial (DFT).
    /// </summary>
    SpectralTransform = 9,

    /// <summary>
    /// Esquemas de compartición de secretos por umbral.
    /// </summary>
    SecretSharing = 10
}
