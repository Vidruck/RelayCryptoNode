using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Symmetric;

/// <summary>
/// Módulo oficial <c>AESGCM</c> (#1): cifrado simétrico autenticado AES-256-GCM.
/// </summary>
public sealed class AesGcmModule : ISymmetricCipherStrategy
{
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.AESGCM;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.Aes256Gcm;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.Aes256Gcm;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var normalizedKey = key.Length == KeySizeBytes
            ? key
            : CryptoModuleHelpers.DeriveFixedBytes(key, null, "AESGCM-KEY", KeySizeBytes);

        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];

        using var aes = new AesGcm(normalizedKey, TagSizeBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

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

        if (authTag is null || authTag.Length != TagSizeBytes)
        {
            throw new DecryptionFailedException("AES-256-GCM requiere una etiqueta AEAD de 16 bytes.", Algorithm);
        }

        if (ivOrNonce.Length != NonceSizeBytes)
        {
            throw new DecryptionFailedException("AES-256-GCM requiere un nonce de 12 bytes.", Algorithm);
        }

        var normalizedKey = key.Length == KeySizeBytes
            ? key
            : CryptoModuleHelpers.DeriveFixedBytes(key, null, "AESGCM-KEY", KeySizeBytes);

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(normalizedKey, TagSizeBytes);
            aes.Decrypt(ivOrNonce, ciphertext, authTag, plaintext, associatedData);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            throw new DecryptionFailedException("Falló la autenticación o el descifrado AES-256-GCM.", Algorithm, innerException: ex);
        }
    }
}
