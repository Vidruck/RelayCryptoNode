using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Puerto de salida para cálculo y verificación de resúmenes criptográficos e integridad con clave.
/// </summary>
public interface IHashingServicePort
{
    /// <summary>
    /// Calcula el resumen criptográfico de un arreglo de bytes usando el algoritmo especificado.
    /// </summary>
    /// <param name="data">Datos de entrada.</param>
    /// <param name="algorithm">Algoritmo de resumen (por defecto <see cref="HashAlgorithmType.Sha256"/>).</param>
    /// <param name="hmacKey">Clave secreta requerida únicamente para algoritmos HMAC.</param>
    /// <returns>Digest validado <see cref="IntegrityDigest"/>.</returns>
    IntegrityDigest ComputeHash(
        byte[] data,
        HashAlgorithmType algorithm = HashAlgorithmType.Sha256,
        byte[]? hmacKey = null);

    /// <summary>
    /// Calcula el resumen SHA-256 de un flujo binario sin cargar innecesariamente todo el contenido en RAM.
    /// </summary>
    /// <param name="stream">Flujo de lectura.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Digest SHA-256 de 64 caracteres hexadecimales.</returns>
    Task<IntegrityDigest> ComputeSha256Async(
        Stream stream,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifica si los datos producen exactamente el <see cref="IntegrityDigest"/> esperado.
    /// </summary>
    /// <param name="data">Datos a comprobar.</param>
    /// <param name="expectedDigest">Resumen esperado.</param>
    /// <param name="hmacKey">Clave HMAC opcional si el algoritmo es HMAC-SHA256.</param>
    /// <returns><c>true</c> si el resumen coincide bit a bit.</returns>
    bool VerifyHash(
        byte[] data,
        IntegrityDigest expectedDigest,
        byte[]? hmacKey = null);
}
