using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Spectral;

/// <summary>
/// Módulo oficial <c>DFTSPECTRAL</c> (#19): transformación reversible por bloques al dominio de frecuencias mediante Transformada Discreta de Fourier (DFT) y modulación de fase.
/// </summary>
public sealed class DftSpectralModule : ISymmetricCipherStrategy, ISpectralTransformPort
{
    private const string DomainLabel = "DFTSPECTRAL";
    private const int BlockSize = 16;

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.DFTSPECTRAL;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.DftSpectral;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.DftSpectral;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var spectralBytes = EncodeSpectral(plaintext, key, nonce);
        var tag = CryptoModuleHelpers.ComputeTag(key, nonce, spectralBytes, associatedData, DomainLabel);
        return new SymmetricEncryptionResult(spectralBytes, nonce, tag);
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
        return DecodeSpectral(ciphertext, key, ivOrNonce);
    }

    /// <inheritdoc />
    public byte[] EncodeSpectral(byte[] plaintext, byte[] key, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var phaseMultipliers = DeriveSpectralPhaseMask(key, nonce);

        var blockCount = plaintext.Length == 0 ? 0 : (plaintext.Length + BlockSize - 1) / BlockSize;
        var spectrumStride = BlockSize * 16; // 16 complejos * (8B Real + 8B Imag)
        var output = new byte[4 + (blockCount * spectrumStride)];
        BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(0, 4), plaintext.Length);

        var outPos = 4;
        var blockBuffer = new double[BlockSize];

        for (var b = 0; b < blockCount; b++)
        {
            Array.Clear(blockBuffer);
            var start = b * BlockSize;
            var len = Math.Min(BlockSize, plaintext.Length - start);
            for (var i = 0; i < len; i++)
            {
                blockBuffer[i] = plaintext[start + i];
            }

            var spectrum = ForwardDft(blockBuffer);
            for (var k = 0; k < BlockSize; k++)
            {
                var modulated = spectrum[k] * phaseMultipliers[k];
                BinaryPrimitives.WriteDoubleLittleEndian(output.AsSpan(outPos, 8), modulated.Real);
                BinaryPrimitives.WriteDoubleLittleEndian(output.AsSpan(outPos + 8, 8), modulated.Imaginary);
                outPos += 16;
            }
        }

        return output;
    }

    /// <inheritdoc />
    public byte[] DecodeSpectral(byte[] spectralCiphertext, byte[] key, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(spectralCiphertext);
        if (spectralCiphertext.Length < 4)
        {
            throw new DecryptionFailedException("Carga espectral DFT truncada.", Algorithm);
        }

        var originalLength = BinaryPrimitives.ReadInt32BigEndian(spectralCiphertext.AsSpan(0, 4));
        if (originalLength < 0)
        {
            throw new DecryptionFailedException("Longitud original inválida en espectro DFT.", Algorithm);
        }

        var blockCount = originalLength == 0 ? 0 : (originalLength + BlockSize - 1) / BlockSize;
        var expectedByteLength = 4 + (blockCount * BlockSize * 16);
        if (spectralCiphertext.Length != expectedByteLength)
        {
            throw new DecryptionFailedException("Tamaño de espectro DFT inconsistente.", Algorithm);
        }

        var phaseMultipliers = DeriveSpectralPhaseMask(key, nonce);
        var plaintext = new byte[originalLength];
        var inPos = 4;
        var spectrum = new Complex[BlockSize];

        for (var b = 0; b < blockCount; b++)
        {
            for (var k = 0; k < BlockSize; k++)
            {
                var re = BinaryPrimitives.ReadDoubleLittleEndian(spectralCiphertext.AsSpan(inPos, 8));
                var im = BinaryPrimitives.ReadDoubleLittleEndian(spectralCiphertext.AsSpan(inPos + 8, 8));
                inPos += 16;

                var modulated = new Complex(re, im);
                spectrum[k] = modulated * Complex.Conjugate(phaseMultipliers[k]);
            }

            var recoveredBlock = InverseDft(spectrum);
            var start = b * BlockSize;
            var len = Math.Min(BlockSize, originalLength - start);
            for (var i = 0; i < len; i++)
            {
                var rounded = (int)Math.Round(recoveredBlock[i], MidpointRounding.AwayFromZero);
                if (rounded is < 0 or > 255)
                {
                    throw new DecryptionFailedException("La reconstrucción DFT produjo valores fuera de rango de byte.", Algorithm);
                }

                plaintext[start + i] = (byte)rounded;
            }
        }

        return plaintext;
    }

    private static Complex[] ForwardDft(double[] samples)
    {
        var n = samples.Length;
        var result = new Complex[n];
        for (var k = 0; k < n; k++)
        {
            var sum = Complex.Zero;
            for (var t = 0; t < n; t++)
            {
                var angle = -2.0 * Math.PI * k * t / n;
                sum += samples[t] * new Complex(Math.Cos(angle), Math.Sin(angle));
            }

            result[k] = sum;
        }

        return result;
    }

    private static double[] InverseDft(Complex[] spectrum)
    {
        var n = spectrum.Length;
        var result = new double[n];
        for (var t = 0; t < n; t++)
        {
            var sum = Complex.Zero;
            for (var k = 0; k < n; k++)
            {
                var angle = 2.0 * Math.PI * k * t / n;
                sum += spectrum[k] * new Complex(Math.Cos(angle), Math.Sin(angle));
            }

            result[t] = sum.Real / n;
        }

        return result;
    }

    private static Complex[] DeriveSpectralPhaseMask(byte[] key, byte[] nonce)
    {
        var maskBytes = CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:PHASE", BlockSize * 2);
        var phases = new Complex[BlockSize];
        for (var k = 0; k < BlockSize; k++)
        {
            var rawAngle = BinaryPrimitives.ReadUInt16LittleEndian(maskBytes.AsSpan(k * 2, 2));
            var theta = (rawAngle / 65536.0) * 2.0 * Math.PI;
            phases[k] = new Complex(Math.Cos(theta), Math.Sin(theta));
        }

        return phases;
    }
}
