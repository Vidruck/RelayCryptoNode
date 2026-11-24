namespace RelayCryptoNode.Domain.Enums;

/// <summary>
/// Códigos oficiales estandarizados de los 21 módulos criptográficos y matemáticos soportados por RelayCryptoNode.
/// </summary>
public enum OfficialAlgorithmCode
{
    /// <summary>
    /// 1. AES-256-GCM (cifrado simétrico AEAD).
    /// </summary>
    AESGCM = 1,

    /// <summary>
    /// 2. DES 56-bit (cifrado por bloques clásico con clave efectiva de 56 bits).
    /// </summary>
    DES = 2,

    /// <summary>
    /// 3. Triple DES / 3DES (cifrado por bloques TDEA).
    /// </summary>
    TRIPLEDES = 3,

    /// <summary>
    /// 4. ChaCha20-Poly1305 (cifrado de flujo AEAD).
    /// </summary>
    CHACHA20 = 4,

    /// <summary>
    /// 5. RSA-OAEP / RSA-PSS (envoltura de clave y firma asimétrica).
    /// </summary>
    RSA = 5,

    /// <summary>
    /// 6. ECDH / ECDSA (curvas elípticas P-256 para acuerdo de clave y firma).
    /// </summary>
    ECC = 6,

    /// <summary>
    /// 7. Diffie-Hellman clásico sobre grupo MODP.
    /// </summary>
    DIFFIEHELLMAN = 7,

    /// <summary>
    /// 8. Cifrado César (sustitución por desplazamiento modular).
    /// </summary>
    CAESAR = 8,

    /// <summary>
    /// 9. Cifrado Vigenère (sustitución polialfabética modular).
    /// </summary>
    VIGENERE = 9,

    /// <summary>
    /// 10. XOR en Registro (cifrado de flujo por desplazamiento y rotación de registro de 64 bits).
    /// </summary>
    XORASM = 10,

    /// <summary>
    /// 11. Esteganografía LSB en imágenes PNG/BMP.
    /// </summary>
    LSBSTEGO = 11,

    /// <summary>
    /// 12. Euclides Extendido / Cifrado Afín modular.
    /// </summary>
    EUCLIDESAFFINE = 12,

    /// <summary>
    /// 13. Miller-Rabin Modular (primalidad probabilística y transformación exponencial modular).
    /// </summary>
    MILLERRABIN = 13,

    /// <summary>
    /// 14. Permutación Fisher-Yates (transposición determinista por semilla).
    /// </summary>
    FISHERYATES = 14,

    /// <summary>
    /// 15. SHA-256 / SHA-512 (resumen criptográfico de integridad).
    /// </summary>
    HASHSHA = 15,

    /// <summary>
    /// 16. HMAC-SHA256 (código de autenticación de mensajes con clave).
    /// </summary>
    HMACSHA256 = 16,

    /// <summary>
    /// 17. Firma Digital RSA-PSS dedicada.
    /// </summary>
    DIGITALSIG = 17,

    /// <summary>
    /// 18. Simulación QKD BB84 / cifrado LWE poscuántico.
    /// </summary>
    QUANTUMPQC = 18,

    /// <summary>
    /// 19. Transformada Discreta de Fourier (modulación espectral reversible).
    /// </summary>
    DFTSPECTRAL = 19,

    /// <summary>
    /// 20. Umbral Shamir sobre GF(256) con interpolación de Lagrange.
    /// </summary>
    LAGRANGESHAMIR = 20,

    /// <summary>
    /// 21. Cifrado de rotores Lorenz SZ40/42.
    /// </summary>
    LORENZSZ40 = 21
}
