namespace RelayCryptoNode.Domain.Enums;

/// <summary>
/// Catálogo de algoritmos simétricos, clásicos, espectrales y especializados soportados por el nodo.
/// </summary>
public enum CipherAlgorithmType
{
    /// <summary>
    /// AES-256 en modo Galois/Counter Mode (AEAD estándar NIST SP 800-38D).
    /// </summary>
    Aes256Gcm = 1,

    /// <summary>
    /// AES-128 en modo Galois/Counter Mode (AEAD estándar NIST SP 800-38D).
    /// </summary>
    Aes128Gcm = 2,

    /// <summary>
    /// AES-256 en modo CBC autenticado mediante HMAC-SHA256 en esquema Encrypt-then-MAC.
    /// </summary>
    Aes256CbcHmac = 3,

    /// <summary>
    /// Cifrado de flujo AEAD ChaCha20-Poly1305 conforme a RFC 8439.
    /// </summary>
    ChaCha20Poly1305 = 4,

    /// <summary>
    /// AES-192 en modo Galois/Counter Mode (reservado para interoperabilidad extendida).
    /// </summary>
    Aes192Gcm = 5,

    /// <summary>
    /// XChaCha20-Poly1305 con nonce extendido de 192 bits.
    /// </summary>
    XChaCha20Poly1305 = 6,

    /// <summary>
    /// Camellia-256 en modo Galois/Counter Mode.
    /// </summary>
    Camellia256Gcm = 7,

    /// <summary>
    /// Ascon-128a AEAD ligero estandarizado por NIST SP 800-232.
    /// </summary>
    Ascon128a = 8,

    /// <summary>
    /// DES 56-bit clásico en modo CBC con autenticación HMAC-SHA256.
    /// </summary>
    Des = 9,

    /// <summary>
    /// Triple DES (3DES / TDEA) en modo CBC con autenticación HMAC-SHA256.
    /// </summary>
    TripleDes = 10,

    /// <summary>
    /// Cifrado César por desplazamiento modular de bytes.
    /// </summary>
    Caesar = 11,

    /// <summary>
    /// Cifrado Vigenère polialfabético sobre flujo de bytes.
    /// </summary>
    Vigenere = 12,

    /// <summary>
    /// Cifrado de flujo XOR en registro de 64 bits con rotación.
    /// </summary>
    XorAsm = 13,

    /// <summary>
    /// Esteganografía LSB en imágenes PNG/BMP.
    /// </summary>
    LsbStego = 14,

    /// <summary>
    /// Cifrado Afín basado en aritmética modular y algoritmo de Euclides Extendido.
    /// </summary>
    EuclidesAffine = 15,

    /// <summary>
    /// Cifrado modular con primos validados por Miller-Rabin.
    /// </summary>
    MillerRabin = 16,

    /// <summary>
    /// Cifrado por transposición mediante permutación determinista Fisher-Yates.
    /// </summary>
    FisherYates = 17,

    /// <summary>
    /// Cifrado basado en simulación QKD BB84 / LWE poscuántico.
    /// </summary>
    QuantumPqc = 18,

    /// <summary>
    /// Cifrado espectral reversible mediante Transformada Discreta de Fourier (DFT).
    /// </summary>
    DftSpectral = 19,

    /// <summary>
    /// Esquema de umbral de Shamir sobre GF(256) e interpolación de Lagrange.
    /// </summary>
    LagrangeShamir = 20,

    /// <summary>
    /// Máquina de rotores Lorenz SZ40/42 de 12 ruedas.
    /// </summary>
    LorenzSz40 = 21
}
