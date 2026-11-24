using System.Buffers.Binary;
using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.PostQuantum;

/// <summary>
/// Módulo oficial <c>QUANTUMPQC</c> (#18): simulación de protocolo cuántico QKD BB84 con detección QBER y cifrado basado en retículos LWE sobre <c>Z_q</c>.
/// </summary>
public sealed class QuantumPqcModule : ISymmetricCipherStrategy, IQuantumPqcSimulationPort
{
    private const string DomainLabel = "QUANTUMPQC";
    private const int LweModulusQ = 256;
    private const int LweDimension = 4;

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.QUANTUMPQC;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.QuantumPqc;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.QuantumPqc;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = EncryptLwe(plaintext, key, nonce);
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
        return DecryptLwe(ciphertext, key, ivOrNonce);
    }

    /// <inheritdoc />
    public Bb84SimulationResult SimulateBb84KeyExchange(int bitCount = 512, bool simulateEavesdropper = false)
    {
        if (bitCount < 64)
        {
            throw new DomainException("La simulación BB84 requiere al menos 64 qubits.", "PQC_BB84_TOO_FEW_BITS");
        }

        var aliceBits = new bool[bitCount];
        var aliceBases = new bool[bitCount];
        var bobBases = new bool[bitCount];

        for (var i = 0; i < bitCount; i++)
        {
            aliceBits[i] = RandomNumberGenerator.GetInt32(2) == 1;
            aliceBases[i] = RandomNumberGenerator.GetInt32(2) == 1;
            bobBases[i] = RandomNumberGenerator.GetInt32(2) == 1;
        }

        var siftedAlice = new List<bool>(bitCount / 2);
        var siftedBob = new List<bool>(bitCount / 2);

        for (var i = 0; i < bitCount; i++)
        {
            bool transmittedBit;
            if (simulateEavesdropper)
            {
                // Eve mide en base aleatoria (rectilínea o diagonal) e introduce error ~50% cuando difiere de la base de Alice
                var eveBasis = RandomNumberGenerator.GetInt32(2) == 1;
                transmittedBit = eveBasis == aliceBases[i]
                    ? aliceBits[i]
                    : RandomNumberGenerator.GetInt32(2) == 1;
            }
            else
            {
                transmittedBit = aliceBits[i];
            }

            if (aliceBases[i] == bobBases[i])
            {
                siftedAlice.Add(aliceBits[i]);
                siftedBob.Add(transmittedBit);
            }
        }

        if (siftedAlice.Count == 0)
        {
            return new Bb84SimulationResult(Array.Empty<byte>(), 0, 1.0, true);
        }

        var mismatchCount = 0;
        for (var i = 0; i < siftedAlice.Count; i++)
        {
            if (siftedAlice[i] != siftedBob[i])
            {
                mismatchCount++;
            }
        }

        var qber = (double)mismatchCount / siftedAlice.Count;
        var eavesdropperDetected = qber > 0.11; // Umbral clásico Shor-Preskill

        var rawBytes = new byte[(siftedBob.Count + 7) / 8];
        for (var i = 0; i < siftedBob.Count; i++)
        {
            if (siftedBob[i])
            {
                rawBytes[i / 8] |= (byte)(1 << (i % 8));
            }
        }

        var distilledKey = SHA256.HashData(rawBytes);
        return new Bb84SimulationResult(distilledKey, siftedBob.Count, qber, eavesdropperDetected);
    }

    /// <summary>
    /// Cifra cada bit del mensaje mediante problema LWE binario sobre <c>Z_256^n</c>: <c>(a, &lt;a, s&gt; + e + floor(q/2)*m) mod 256</c>.
    /// </summary>
    public byte[] EncryptLwe(byte[] plaintext, byte[] key, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var secretS = DeriveSecretVector(key, nonce);
        var prngSeed = CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:LWE-A", 32);

        // Cada byte = 8 bits; cada bit produce (LweDimension + 1) bytes => (plaintext.Length * 8 * 5) bytes
        var stridePerBit = LweDimension + 1;
        var output = new byte[plaintext.Length * 8 * stridePerBit];
        Span<byte> ctrBlock = stackalloc byte[36];
        prngSeed.CopyTo(ctrBlock);

        var outPos = 0;
        uint sampleIndex = 0;

        foreach (var b in plaintext)
        {
            for (var bit = 0; bit < 8; bit++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(ctrBlock[32..36], sampleIndex++);
                var entropy = SHA256.HashData(ctrBlock);

                var dotProduct = 0;
                for (var j = 0; j < LweDimension; j++)
                {
                    var aj = entropy[j];
                    output[outPos++] = aj;
                    dotProduct += aj * secretS[j];
                }

                // Error LWE acotado en [-16, +15] para decodificación exacta sin pérdida frente a q/2 = 128
                var smallNoise = (entropy[LweDimension] & 0x1F) - 16;
                var messageBit = (b >> bit) & 1;
                var v = (dotProduct + smallNoise + (messageBit * (LweModulusQ / 2))) & 0xFF;
                output[outPos++] = (byte)v;
            }
        }

        return output;
    }

    /// <inheritdoc />
    public byte[] DecryptLwe(byte[] ciphertext, byte[] key, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        var stridePerBit = LweDimension + 1;
        var bytesPerPlainByte = 8 * stridePerBit;

        if (ciphertext.Length % bytesPerPlainByte != 0)
        {
            throw new DecryptionFailedException("Longitud de texto cifrado LWE inválida.", Algorithm);
        }

        var secretS = DeriveSecretVector(key, nonce);
        var plainLength = ciphertext.Length / bytesPerPlainByte;
        var plaintext = new byte[plainLength];
        var inPos = 0;

        for (var i = 0; i < plainLength; i++)
        {
            byte reconstructed = 0;
            for (var bit = 0; bit < 8; bit++)
            {
                var dotProduct = 0;
                for (var j = 0; j < LweDimension; j++)
                {
                    dotProduct += ciphertext[inPos++] * secretS[j];
                }

                var v = ciphertext[inPos++];
                var diff = (v - dotProduct) & 0xFF;

                // Distancia circular a q/2 (=128) vs 0
                var distToHalf = Math.Abs(diff - 128);
                var distToZero = Math.Min(diff, 256 - diff);
                if (distToHalf < distToZero)
                {
                    reconstructed |= (byte)(1 << bit);
                }
            }

            plaintext[i] = reconstructed;
        }

        return plaintext;
    }

    private static int[] DeriveSecretVector(byte[] key, byte[] nonce)
    {
        var raw = CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:LWE-S", LweDimension);
        var s = new int[LweDimension];
        for (var i = 0; i < LweDimension; i++)
        {
            s[i] = raw[i];
        }

        return s;
    }
}
