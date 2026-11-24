using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Infrastructure.Algorithms.Integrity;

/// <summary>
/// Módulo oficial <c>HMACSHA256</c> (#16): cálculo y verificación en tiempo constante de códigos HMAC-SHA256.
/// </summary>
public sealed class HmacSha256Module : IHashingServicePort
{
    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.HMACSHA256;

    /// <inheritdoc />
    public IntegrityDigest ComputeHash(
        byte[] data,
        HashAlgorithmType algorithm = HashAlgorithmType.HmacSha256,
        byte[]? hmacKey = null)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (algorithm != HashAlgorithmType.HmacSha256)
        {
            throw new UnsupportedAlgorithmException(algorithm.ToString());
        }

        if (hmacKey is null || hmacKey.Length == 0)
        {
            throw new DomainException("HMAC-SHA256 requiere una clave secreta no vacía.", "HMAC_KEY_EMPTY");
        }

        var mac = HMACSHA256.HashData(hmacKey, data);
        return new IntegrityDigest("HMAC-SHA256", Convert.ToHexString(mac));
    }

    /// <inheritdoc />
    public async Task<IntegrityDigest> ComputeSha256Async(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return IntegrityDigest.Sha256(Convert.ToHexString(hash));
    }

    /// <inheritdoc />
    public bool VerifyHash(
        byte[] data,
        IntegrityDigest expectedDigest,
        byte[]? hmacKey = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(expectedDigest);

        var computed = ComputeHash(data, HashAlgorithmType.HmacSha256, hmacKey);
        var expectedBytes = Convert.FromHexString(expectedDigest.HexHash);
        var actualBytes = Convert.FromHexString(computed.HexHash);
        return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }
}
