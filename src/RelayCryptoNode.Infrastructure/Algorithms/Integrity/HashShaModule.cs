using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Infrastructure.Algorithms.Integrity;

/// <summary>
/// Módulo oficial <c>HASHSHA</c> (#15): cálculo y verificación de resúmenes SHA-256 y SHA-512 (en memoria y streaming).
/// </summary>
public sealed class HashShaModule : IHashingServicePort
{
    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.HASHSHA;

    /// <inheritdoc />
    public IntegrityDigest ComputeHash(
        byte[] data,
        HashAlgorithmType algorithm = HashAlgorithmType.Sha256,
        byte[]? hmacKey = null)
    {
        ArgumentNullException.ThrowIfNull(data);

        return algorithm switch
        {
            HashAlgorithmType.Sha256 => new IntegrityDigest("SHA-256", Convert.ToHexString(SHA256.HashData(data))),
            HashAlgorithmType.Sha512 => new IntegrityDigest("SHA-512", Convert.ToHexString(SHA512.HashData(data))),
            HashAlgorithmType.Sha3_256 when SHA3_256.IsSupported =>
                new IntegrityDigest("SHA3-256", Convert.ToHexString(SHA3_256.HashData(data))),
            HashAlgorithmType.HmacSha256 => new HmacSha256Module().ComputeHash(data, HashAlgorithmType.HmacSha256, hmacKey),
            _ => throw new UnsupportedAlgorithmException(algorithm.ToString())
        };
    }

    /// <inheritdoc />
    public async Task<IntegrityDigest> ComputeSha256Async(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var hashBytes = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return IntegrityDigest.Sha256(Convert.ToHexString(hashBytes));
    }

    /// <inheritdoc />
    public bool VerifyHash(
        byte[] data,
        IntegrityDigest expectedDigest,
        byte[]? hmacKey = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(expectedDigest);

        var algorithm = expectedDigest.AlgorithmName switch
        {
            "SHA-256" or "SHA256" => HashAlgorithmType.Sha256,
            "SHA-512" or "SHA512" => HashAlgorithmType.Sha512,
            "SHA3-256" or "SHA3_256" => HashAlgorithmType.Sha3_256,
            "HMAC-SHA256" or "HMACSHA256" => HashAlgorithmType.HmacSha256,
            _ => throw new UnsupportedAlgorithmException(expectedDigest.AlgorithmName)
        };

        var computed = ComputeHash(data, algorithm, hmacKey);
        var expectedBytes = Convert.FromHexString(expectedDigest.HexHash);
        var actualBytes = Convert.FromHexString(computed.HexHash);
        return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }
}
