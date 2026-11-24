using System.Buffers.Binary;
using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.SecretSharing;

/// <summary>
/// Módulo oficial <c>LAGRANGESHAMIR</c> (#20): compartición de secretos por umbral Shamir sobre <c>GF(256)</c> con interpolación de Lagrange.
/// </summary>
public sealed class LagrangeShamirModule : ISymmetricCipherStrategy, ISecretSharingPort
{
    private const string DomainLabel = "LAGRANGESHAMIR";
    private const byte DefaultThreshold = 3;
    private const byte DefaultTotalShares = 5;

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.LAGRANGESHAMIR;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.LagrangeShamir;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.LagrangeShamir;

    /// <summary>
    /// Enmascara la carga útil con clave+nonce, genera <c>(3, 5)</c> fragmentos Shamir sobre <c>GF(256)</c> y empaqueta un subconjunto suficiente para su reconstrucción.
    /// </summary>
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var masked = ApplyStreamMask(plaintext, key, nonce);
        var shares = SplitSecret(masked, DefaultTotalShares, DefaultThreshold);

        // Empaqueta las k=3 primeras participaciones para transporte en el sobre único; SplitSecret/ReconstructSecret también se exponen directamente
        var packed = PackShares(shares.Take(DefaultThreshold).ToArray());
        var tag = CryptoModuleHelpers.ComputeTag(key, nonce, packed, associatedData, DomainLabel);
        return new SymmetricEncryptionResult(packed, nonce, tag);
    }

    /// <inheritdoc />
    public byte[] Decrypt(
        byte[] ciphertext,
        byte[] key,
        byte[] ivOrNonce,
        byte[]? authTag,
        byte[]? associatedData = null)
    {
        CryptoModuleHelpers.ValidateDecryptInputs(ciphertext, key, ivOrNonce, Algorithm);
        CryptoModuleHelpers.VerifyTagOrThrow(key, ivOrNonce, ciphertext, authTag, associatedData, DomainLabel, Algorithm);

        var shares = UnpackShares(ciphertext);
        var masked = ReconstructSecret(shares);
        return ApplyStreamMask(masked, key, ivOrNonce);
    }

    /// <inheritdoc />
    public IReadOnlyList<SecretShare> SplitSecret(byte[] secret, byte totalShares, byte threshold)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (totalShares == 0 || threshold == 0 || threshold > totalShares)
        {
            throw new DomainException(
                "Parámetros Shamir inválidos: se requiere 1 <= threshold <= totalShares <= 255.",
                "SHAMIR_INVALID_PARAMETERS");
        }

        var sharesData = new byte[totalShares][];
        for (var s = 0; s < totalShares; s++)
        {
            sharesData[s] = new byte[secret.Length];
        }

        var coefficients = new byte[threshold];
        for (var byteIdx = 0; byteIdx < secret.Length; byteIdx++)
        {
            coefficients[0] = secret[byteIdx];
            if (threshold > 1)
            {
                RandomNumberGenerator.Fill(coefficients.AsSpan(1));
            }

            for (var s = 0; s < totalShares; s++)
            {
                var x = (byte)(s + 1); // X in [1..totalShares]
                sharesData[s][byteIdx] = EvaluatePolynomial(coefficients, x);
            }
        }

        var result = new List<SecretShare>(totalShares);
        for (var s = 0; s < totalShares; s++)
        {
            result.Add(new SecretShare((byte)(s + 1), threshold, sharesData[s]));
        }

        return result.AsReadOnly();
    }

    /// <inheritdoc />
    public byte[] ReconstructSecret(IReadOnlyList<SecretShare> shares)
    {
        if (shares is null || shares.Count == 0)
        {
            throw new DomainException("Se requieren fragmentos para reconstruir el secreto Shamir.", "SHAMIR_NO_SHARES");
        }

        var threshold = shares[0].Threshold;
        if (threshold == 0 || shares.Count < threshold)
        {
            throw new DomainException(
                $"Fragmentos insuficientes: se requieren al menos {threshold} y se recibieron {shares.Count}.",
                "SHAMIR_INSUFFICIENT_SHARES");
        }

        var secretLength = shares[0].Data.Length;
        var seenX = new HashSet<byte>();
        var activeShares = shares.Take(threshold).ToArray();

        foreach (var share in activeShares)
        {
            if (share.ShareIndex == 0)
            {
                throw new DomainException("El índice X de un fragmento Shamir no puede ser 0.", "SHAMIR_INVALID_INDEX");
            }

            if (share.Data.Length != secretLength)
            {
                throw new DomainException("Todos los fragmentos Shamir deben tener la misma longitud.", "SHAMIR_LENGTH_MISMATCH");
            }

            if (!seenX.Add(share.ShareIndex))
            {
                throw new DomainException($"Índice de fragmento duplicado: {share.ShareIndex}.", "SHAMIR_DUPLICATE_INDEX");
            }
        }

        // Precalcular coeficientes de Lagrange l_i(0) sobre GF(256)
        var lagrangeBasisAtZero = new byte[threshold];
        for (var i = 0; i < threshold; i++)
        {
            byte numerator = 1;
            byte denominator = 1;
            var xi = activeShares[i].ShareIndex;

            for (var j = 0; j < threshold; j++)
            {
                if (i == j)
                {
                    continue;
                }

                var xj = activeShares[j].ShareIndex;
                // En GF(2^8), 0 - xj == xj y (xi - xj) == (xi ^ xj)
                numerator = GfMultiply(numerator, xj);
                denominator = GfMultiply(denominator, (byte)(xi ^ xj));
            }

            lagrangeBasisAtZero[i] = GfDivide(numerator, denominator);
        }

        var secret = new byte[secretLength];
        for (var byteIdx = 0; byteIdx < secretLength; byteIdx++)
        {
            byte acc = 0;
            for (var i = 0; i < threshold; i++)
            {
                acc ^= GfMultiply(activeShares[i].Data[byteIdx], lagrangeBasisAtZero[i]);
            }

            secret[byteIdx] = acc;
        }

        return secret;
    }

    private static byte EvaluatePolynomial(ReadOnlySpan<byte> coeffs, byte x)
    {
        byte y = 0;
        for (var i = coeffs.Length - 1; i >= 0; i--)
        {
            y = (byte)(GfMultiply(y, x) ^ coeffs[i]);
        }

        return y;
    }

    // Multiplicación en GF(2^8) con polinomio irreducible AES x^8 + x^4 + x^3 + x + 1 (0x11B)
    private static byte GfMultiply(byte a, byte b)
    {
        byte result = 0;
        var aa = a;
        var bb = b;

        for (var i = 0; i < 8; i++)
        {
            if ((bb & 1) != 0)
            {
                result ^= aa;
            }

            var highBit = (aa & 0x80) != 0;
            aa <<= 1;
            if (highBit)
            {
                aa ^= 0x1B;
            }

            bb >>= 1;
        }

        return result;
    }

    private static byte GfInverse(byte a)
    {
        if (a == 0)
        {
            throw new DivideByZeroException("El cero no tiene inverso en GF(256).");
        }

        // Pequeño teorema de Fermat en GF(256): a^(254) == a^(-1)
        byte result = 1;
        var baseVal = a;
        var exp = 254;

        while (exp > 0)
        {
            if ((exp & 1) != 0)
            {
                result = GfMultiply(result, baseVal);
            }

            baseVal = GfMultiply(baseVal, baseVal);
            exp >>= 1;
        }

        return result;
    }

    private static byte GfDivide(byte a, byte b) => GfMultiply(a, GfInverse(b));

    private static byte[] ApplyStreamMask(byte[] input, byte[] key, byte[] nonce)
    {
        var output = new byte[input.Length];
        var offset = 0;
        uint counter = 0;
        Span<byte> ctr = stackalloc byte[4];

        while (offset < input.Length)
        {
            BinaryPrimitives.WriteUInt32BigEndian(ctr, counter++);
            var block = CryptoModuleHelpers.DeriveFixedBytes(key, [.. nonce, .. ctr], $"{DomainLabel}:MASK", 32);
            var take = Math.Min(block.Length, input.Length - offset);
            for (var i = 0; i < take; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ block[i]);
            }

            offset += take;
        }

        return output;
    }

    private static byte[] PackShares(IReadOnlyList<SecretShare> shares)
    {
        var dataLen = shares[0].Data.Length;
        var output = new byte[6 + (shares.Count * (1 + dataLen))];
        output[0] = (byte)shares.Count;
        output[1] = shares[0].Threshold;
        BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(2, 4), dataLen);

        var pos = 6;
        foreach (var share in shares)
        {
            output[pos++] = share.ShareIndex;
            Buffer.BlockCopy(share.Data, 0, output, pos, dataLen);
            pos += dataLen;
        }

        return output;
    }

    private static IReadOnlyList<SecretShare> UnpackShares(byte[] packed)
    {
        if (packed.Length < 6)
        {
            throw new DecryptionFailedException("Paquete de fragmentos Shamir truncado.", CipherAlgorithmType.LagrangeShamir);
        }

        var count = packed[0];
        var threshold = packed[1];
        var dataLen = BinaryPrimitives.ReadInt32BigEndian(packed.AsSpan(2, 4));
        if (count == 0 || dataLen < 0 || packed.Length != 6 + (count * (1 + dataLen)))
        {
            throw new DecryptionFailedException("Estructura inválida de fragmentos Shamir.", CipherAlgorithmType.LagrangeShamir);
        }

        var shares = new List<SecretShare>(count);
        var pos = 6;
        for (var i = 0; i < count; i++)
        {
            var x = packed[pos++];
            var data = new byte[dataLen];
            Buffer.BlockCopy(packed, pos, data, 0, dataLen);
            pos += dataLen;
            shares.Add(new SecretShare(x, threshold, data));
        }

        return shares;
    }
}
