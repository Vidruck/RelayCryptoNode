using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Classical;

/// <summary>
/// Módulo oficial <c>VIGENERE</c> (#9): cifrado polialfabético Vigenère sobre flujo completo de bytes (<c>mod 256</c>) con autenticación HMAC-SHA256.
/// </summary>
public sealed class VigenereModule : ISymmetricCipherStrategy
{
    private const string DomainLabel = "VIGENERE";

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.VIGENERE;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.Vigenere;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.Vigenere;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var keyStream = DerivePolyKey(key, nonce);

        var ciphertext = new byte[plaintext.Length];
        for (var i = 0; i < plaintext.Length; i++)
        {
            ciphertext[i] = (byte)((plaintext[i] + keyStream[i % keyStream.Length]) & 0xFF);
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

        var keyStream = DerivePolyKey(key, ivOrNonce);
        var plaintext = new byte[ciphertext.Length];
        for (var i = 0; i < ciphertext.Length; i++)
        {
            plaintext[i] = (byte)((ciphertext[i] - keyStream[i % keyStream.Length]) & 0xFF);
        }

        return plaintext;
    }

    private static byte[] DerivePolyKey(byte[] key, byte[] nonce) =>
        CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:TABLE", 32);
}
