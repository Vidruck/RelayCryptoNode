namespace RelayCryptoNode.Domain.Enums;

/// <summary>
/// Mecanismos de envoltura, acuerdo o encapsulación de clave de sesión soportados por el nodo.
/// </summary>
public enum KeyExchangeAlgorithmType
{
    /// <summary>
    /// Envoltura asimétrica RSA-OAEP utilizando SHA-256 como función de resumen y MGF1.
    /// </summary>
    RsaOaepSha256 = 1,

    /// <summary>
    /// Acuerdo efímero de claves ECDH sobre curva NIST P-256 (secp256r1) con derivación HKDF-SHA256.
    /// </summary>
    EcdhP256 = 2,

    /// <summary>
    /// Mecanismo poscuántico de encapsulación de claves ML-KEM-768 (NIST FIPS 203 / Kyber-768).
    /// </summary>
    MlKem768 = 3,

    /// <summary>
    /// Uso directo de clave simétrica precompartida (PSK) previamente distribuida por canal seguro.
    /// </summary>
    PreSharedKey = 4,

    /// <summary>
    /// Acuerdo ECDH sobre curva NIST P-384.
    /// </summary>
    EcdhP384 = 5,

    /// <summary>
    /// Acuerdo de claves Diffie-Hellman sobre Curve25519 según RFC 7748.
    /// </summary>
    X25519 = 6,

    /// <summary>
    /// Encapsulación poscuántica ML-KEM-1024 nivel de seguridad 5.
    /// </summary>
    MlKem1024 = 7,

    /// <summary>
    /// Esquema híbrido clásico-poscuántico X25519 + ML-KEM-768.
    /// </summary>
    HybridX25519MlKem768 = 8,

    /// <summary>
    /// Acuerdo clásico de claves Diffie-Hellman sobre grupo MODP entero.
    /// </summary>
    DiffieHellman = 9,

    /// <summary>
    /// Acuerdo de clave mediante simulación QKD BB84 y encapsulación LWE.
    /// </summary>
    QuantumPqcBb84Lwe = 10
}
