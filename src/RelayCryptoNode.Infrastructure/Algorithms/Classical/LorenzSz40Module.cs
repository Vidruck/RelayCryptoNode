using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Classical;

/// <summary>
/// Módulo oficial <c>LORENZSZ40</c> (#21): máquina de cifrado de rotores Lorenz SZ40/42 de 12 ruedas (5 chi, 5 psi, 2 mu).
/// </summary>
public sealed class LorenzSz40Module : ISymmetricCipherStrategy, IStreamRotorCipherPort
{
    private const string DomainLabel = "LORENZSZ40";

    private static readonly int[] ChiLengths = [41, 31, 29, 26, 23];
    private static readonly int[] PsiLengths = [43, 47, 51, 53, 59];
    private static readonly int[] MuLengths = [61, 37];

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.LORENZSZ40;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.LorenzSz40;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.LorenzSz40;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = TransformStream(plaintext, key, nonce);
        var tag = CryptoModuleHelpers.ComputeTag(key, nonce, ciphertext, associatedData, DomainLabel);
        return new SymmetricEncryptionResult(ciphertext, nonce, tag);
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
        return TransformStream(ciphertext, key, ivOrNonce);
    }

    /// <inheritdoc />
    public byte[] TransformStream(byte[] input, byte[] key, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(input);
        var seed = CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:WHEELS", 64);

        var chiWheels = BuildWheels(ChiLengths, seed, 0);
        var psiWheels = BuildWheels(PsiLengths, seed, 16);
        var muWheels = BuildWheels(MuLengths, seed, 32);

        var chiPos = new int[5];
        var psiPos = new int[5];
        var muPos = new int[2];

        for (var i = 0; i < 5; i++)
        {
            chiPos[i] = seed[48 + i] % ChiLengths[i];
            psiPos[i] = seed[53 + i] % PsiLengths[i];
        }

        muPos[0] = seed[58] % MuLengths[0];
        muPos[1] = seed[59] % MuLengths[1];

        var output = new byte[input.Length];

        // Se generan 8 bits de flujo Lorenz (5 bits Vernam por par de impulsos + extensión de byte completo)
        for (var byteIdx = 0; byteIdx < input.Length; byteIdx++)
        {
            var low5 = Next5BitImpulse(chiWheels, psiWheels, muWheels, chiPos, psiPos, muPos);
            var high3 = Next5BitImpulse(chiWheels, psiWheels, muWheels, chiPos, psiPos, muPos) & 0x07;
            var keyByte = (byte)((high3 << 5) | low5);
            output[byteIdx] = (byte)(input[byteIdx] ^ keyByte);
        }

        return output;
    }

    private static int Next5BitImpulse(
        bool[][] chiWheels,
        bool[][] psiWheels,
        bool[][] muWheels,
        int[] chiPos,
        int[] psiPos,
        int[] muPos)
    {
        var impulse = 0;
        for (var bit = 0; bit < 5; bit++)
        {
            var chiBit = chiWheels[bit][chiPos[bit]];
            var psiBit = psiWheels[bit][psiPos[bit]];
            if (chiBit ^ psiBit)
            {
                impulse |= 1 << bit;
            }
        }

        // Las ruedas chi avanzan siempre en cada impulso
        for (var i = 0; i < 5; i++)
        {
            chiPos[i] = (chiPos[i] + 1) % ChiLengths[i];
        }

        // El avance irregular de psi depende de mu61 y mu37 (comportamiento auténtico SZ40/42)
        var mu61Bit = muWheels[0][muPos[0]];
        var mu37Bit = muWheels[1][muPos[1]];
        muPos[0] = (muPos[0] + 1) % MuLengths[0];
        if (mu61Bit)
        {
            muPos[1] = (muPos[1] + 1) % MuLengths[1];
        }

        if (mu37Bit)
        {
            for (var i = 0; i < 5; i++)
            {
                psiPos[i] = (psiPos[i] + 1) % PsiLengths[i];
            }
        }

        return impulse;
    }

    private static bool[][] BuildWheels(int[] lengths, byte[] seed, int seedOffset)
    {
        var wheels = new bool[lengths.Length][];
        for (var w = 0; w < lengths.Length; w++)
        {
            var len = lengths[w];
            var pins = new bool[len];
            var wheelSeed = SHA256.HashData([seed[(seedOffset + w) % seed.Length], (byte)w, (byte)len]);
            for (var p = 0; p < len; p++)
            {
                pins[p] = ((wheelSeed[p / 8] >> (p % 8)) & 1) == 1;
            }

            wheels[w] = pins;
        }

        return wheels;
    }
}
