using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Classical;

/// <summary>
/// Módulo oficial <c>XORASM</c> (#10): cifrado de flujo mediante registro de 64 bits con rotación y mezcla XOR estilo ensamblador.
/// </summary>
public sealed class XorAsmModule : ISymmetricCipherStrategy, IStreamRotorCipherPort
{
    private const string DomainLabel = "XORASM";

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.XORASM;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.XorAsm;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.XorAsm;

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
        var stateMaterial = CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:REG64", 16);
        var regA = BinaryPrimitives.ReadUInt64LittleEndian(stateMaterial.AsSpan(0, 8));
        var regB = BinaryPrimitives.ReadUInt64LittleEndian(stateMaterial.AsSpan(8, 8));

        if (regA == 0)
        {
            regA = 0x9E3779B97F4A7C15UL;
        }

        if (regB == 0)
        {
            regB = 0xBF58476D1CE4E5B9UL;
        }

        var output = new byte[input.Length];
        for (var i = 0; i < input.Length; i++)
        {
            if ((i & 7) == 0)
            {
                // Operación de registro: ROL + XOR + desplazamiento xorshift64*
                regA ^= regA << 13;
                regA ^= regA >> 7;
                regA ^= regA << 17;
                regB = BitOperations.RotateLeft(regB + 0x9E3779B97F4A7C15UL, 19) ^ regA;
            }

            var mask = (byte)((regB >> ((i & 7) * 8)) & 0xFF);
            output[i] = (byte)(input[i] ^ mask);
        }

        return output;
    }
}
