namespace RelayCryptoNode.Domain.Enums;

/// <summary>
/// Funciones de resumen criptográfico y códigos de autenticación de mensajes vigentes.
/// </summary>
public enum HashAlgorithmType
{
    /// <summary>
    /// Función de resumen SHA-256 de la familia SHA-2 (salida de 256 bits / 64 caracteres hexadecimales).
    /// </summary>
    Sha256 = 1,

    /// <summary>
    /// Función de resumen SHA-512 de la familia SHA-2 (salida de 512 bits / 128 caracteres hexadecimales).
    /// </summary>
    Sha512 = 2,

    /// <summary>
    /// Función de resumen SHA3-256 basada en esponja Keccak según NIST FIPS 202.
    /// </summary>
    Sha3_256 = 3,

    /// <summary>
    /// Código de autenticación de mensajes con clave HMAC-SHA256.
    /// </summary>
    HmacSha256 = 4,

    /// <summary>
    /// Función de resumen SHA3-512 según NIST FIPS 202 (reservado para extensión futura).
    /// </summary>
    Sha3_512 = 5,

    /// <summary>
    /// Función de resumen BLAKE2b-256 según RFC 7693 (reservado para extensión futura).
    /// </summary>
    Blake2b256 = 6
}
