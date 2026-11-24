using RelayCryptoNode.Domain.Exceptions;

namespace RelayCryptoNode.Domain.ValueObjects;

/// <summary>
/// Value Object inmutable que representa un resumen criptográfico validado con su algoritmo y valor hexadecimal normalizado.
/// </summary>
public sealed record IntegrityDigest
{
    private const int Sha256HexLength = 64;
    private const int Sha512HexLength = 128;

    /// <summary>
    /// Nombre normalizado en mayúsculas del algoritmo de resumen (por ejemplo, <c>SHA-256</c>).
    /// </summary>
    public string AlgorithmName { get; }

    /// <summary>
    /// Valor del resumen en hexadecimal en minúsculas validado estrictamente.
    /// </summary>
    public string HexHash { get; }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="IntegrityDigest"/> validando formato y longitud del hash.
    /// </summary>
    /// <param name="algorithmName">Nombre del algoritmo de resumen.</param>
    /// <param name="hexHash">Cadena hexadecimal del resumen.</param>
    /// <exception cref="DomainException">Se lanza si el algoritmo o el resumen hexadecimal incumplen las invariantes.</exception>
    public IntegrityDigest(string algorithmName, string hexHash)
    {
        if (string.IsNullOrWhiteSpace(algorithmName))
        {
            throw new DomainException("El nombre del algoritmo de integridad no puede estar vacío.", "INTEGRITY_ALGORITHM_EMPTY");
        }

        if (string.IsNullOrWhiteSpace(hexHash))
        {
            throw new DomainException("El hash hexadecimal de integridad no puede estar vacío.", "INTEGRITY_HASH_EMPTY");
        }

        var normalizedAlgorithm = algorithmName.Trim().ToUpperInvariant();
        var normalizedHex = hexHash.Trim().ToLowerInvariant();

        if (!IsValidHexString(normalizedHex))
        {
            throw new DomainException(
                "El resumen de integridad contiene caracteres no hexadecimales.",
                "INTEGRITY_HASH_INVALID_HEX");
        }

        ValidateExpectedLength(normalizedAlgorithm, normalizedHex);

        AlgorithmName = normalizedAlgorithm;
        HexHash = normalizedHex;
    }

    /// <summary>
    /// Crea un <see cref="IntegrityDigest"/> utilizando el estándar <c>SHA-256</c> de 64 caracteres hexadecimales.
    /// </summary>
    /// <param name="hexHash">Hash SHA-256 de 64 caracteres hexadecimales.</param>
    /// <returns>Instancia validada de <see cref="IntegrityDigest"/>.</returns>
    public static IntegrityDigest Sha256(string hexHash) => new("SHA-256", hexHash);

    /// <summary>
    /// Obtiene el prefijo corto del hash (por defecto 8 caracteres) para nomenclatura de paquetes.
    /// </summary>
    /// <param name="length">Cantidad de caracteres iniciales a extraer.</param>
    /// <returns>Subcadena hexadecimal en minúsculas.</returns>
    /// <exception cref="DomainException">Se lanza si la longitud solicitada es inválida.</exception>
    public string ShortHex(int length = 8)
    {
        if (length <= 0 || length > HexHash.Length)
        {
            throw new DomainException(
                $"La longitud de prefijo debe estar entre 1 y {HexHash.Length}.",
                "INTEGRITY_SHORT_HEX_RANGE");
        }

        return HexHash[..length];
    }

    private static bool IsValidHexString(string value)
    {
        foreach (var c in value)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    private static void ValidateExpectedLength(string algorithm, string hex)
    {
        switch (algorithm)
        {
            case "SHA-256":
            case "SHA256":
            case "SHA3-256":
            case "SHA3_256":
            case "HMAC-SHA256":
            case "HMACSHA256":
            case "BLAKE2B-256":
            case "BLAKE2B256":
                if (hex.Length != Sha256HexLength)
                {
                    throw new DomainException(
                        $"Un hash {algorithm} debe tener exactamente {Sha256HexLength} caracteres hexadecimales (recibidos: {hex.Length}).",
                        "INTEGRITY_HASH_INVALID_LENGTH");
                }

                break;

            case "SHA-512":
            case "SHA512":
            case "SHA3-512":
            case "SHA3_512":
                if (hex.Length != Sha512HexLength)
                {
                    throw new DomainException(
                        $"Un hash {algorithm} debe tener exactamente {Sha512HexLength} caracteres hexadecimales (recibidos: {hex.Length}).",
                        "INTEGRITY_HASH_INVALID_LENGTH");
                }

                break;

            default:
                if (hex.Length < 32 || hex.Length % 2 != 0)
                {
                    throw new DomainException(
                        $"El hash para '{algorithm}' debe tener longitud par de al menos 32 caracteres hexadecimales.",
                        "INTEGRITY_HASH_INVALID_LENGTH");
                }

                break;
        }
    }
}
