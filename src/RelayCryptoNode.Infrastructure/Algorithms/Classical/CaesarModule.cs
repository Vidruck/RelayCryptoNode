using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Classical;

/// <summary>
/// Módulo oficial <c>CAESAR</c> (#8): cifrado César por desplazamiento modular invertible sobre bytes (<c>mod 256</c>) con autenticación HMAC-SHA256.
/// </summary>
public sealed class CaesarModule : ISymmetricCipherStrategy
{
    private const string DomainLabel = "CAESAR";

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.CAESAR;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.Caesar;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.Caesar;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var shift = DeriveShift(key, nonce);

        var ciphertext = new byte[plaintext.Length];
        for (var i = 0; i < plaintext.Length; i++)
        {
            ciphertext[i] = (byte)((plaintext[i] + shift) & 0xFF);
        }

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

        var shift = DeriveShift(key, ivOrNonce);
        var plaintext = new byte[ciphertext.Length];
        for (var i = 0; i < ciphertext.Length; i++)
        {
            plaintext[i] = (byte)((ciphertext[i] - shift) & 0xFF);
        }

        return plaintext;
    }

    private static int DeriveShift(byte[] key, byte[] nonce)
    {
        var derived = CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:SHIFT", 1);
        return derived[0] == 0 ? 13 : derived[0];
    }
}
