using System.Buffers.Binary;
using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Transposition;

/// <summary>
/// Módulo oficial <c>FISHERYATES</c> (#14): cifrado por transposición determinista mediante permutación Fisher-Yates sembrada por SHA-256.
/// </summary>
public sealed class FisherYatesModule : ISymmetricCipherStrategy, IPermutationCipherPort
{
    private const string DomainLabel = "FISHERYATES";

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.FISHERYATES;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.FisherYates;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.FisherYates;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var permuted = Permute(plaintext, key, nonce);
        var tag = CryptoModuleHelpers.ComputeTag(key, nonce, permuted, associatedData, DomainLabel);
        return new SymmetricEncryptionResult(permuted, nonce, tag);
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
        return InversePermute(ciphertext, key, ivOrNonce);
    }

    /// <inheritdoc />
    public byte[] Permute(byte[] data, byte[] key, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length <= 1)
        {
            return data.ToArray();
        }

        var swaps = BuildSwapTargets(data.Length, key, nonce);
        var output = data.ToArray();

        for (var i = data.Length - 1; i > 0; i--)
        {
            var j = swaps[i];
            (output[i], output[j]) = (output[j], output[i]);
        }

        return output;
    }

    /// <inheritdoc />
    public byte[] InversePermute(byte[] permutedData, byte[] key, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(permutedData);
        if (permutedData.Length <= 1)
        {
            return permutedData.ToArray();
        }

        var swaps = BuildSwapTargets(permutedData.Length, key, nonce);
        var output = permutedData.ToArray();

        for (var i = 1; i < permutedData.Length; i++)
        {
            var j = swaps[i];
            (output[i], output[j]) = (output[j], output[i]);
        }

        return output;
    }

    private static int[] BuildSwapTargets(int length, byte[] key, byte[] nonce)
    {
        var swaps = new int[length];
        var seed = CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:SEED", 32);

        Span<byte> counterBlock = stackalloc byte[36];
        seed.CopyTo(counterBlock);

        var buffer = Array.Empty<byte>();
        var bufferOffset = 32;
        uint blockCounter = 0;

        for (var i = length - 1; i > 0; i--)
        {
            if (bufferOffset + 4 > buffer.Length)
            {
                BinaryPrimitives.WriteUInt32BigEndian(counterBlock[32..36], blockCounter++);
                buffer = SHA256.HashData(counterBlock);
                bufferOffset = 0;
            }

            var rawRand = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(bufferOffset, 4));
            bufferOffset += 4;
            swaps[i] = (int)(rawRand % (uint)(i + 1));
        }

        return swaps;
    }
}
