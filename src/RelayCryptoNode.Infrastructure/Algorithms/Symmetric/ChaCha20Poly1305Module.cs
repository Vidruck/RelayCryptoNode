using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Symmetric;

/// <summary>
/// Módulo oficial <c>CHACHA20</c> (#4): cifrado de flujo AEAD ChaCha20-Poly1305.
/// </summary>
public sealed class ChaCha20Poly1305Module : ISymmetricCipherStrategy
{
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.CHACHA20;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.ChaCha20Poly1305;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.ChaCha20Poly1305;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var normalizedKey = key.Length == KeySizeBytes
            ? key
            : CryptoModuleHelpers.DeriveFixedBytes(key, null, "CHACHA20-KEY", KeySizeBytes);

        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];

        using var cipher = new ChaCha20Poly1305(normalizedKey);
        cipher.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

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
            throw new DecryptionFailedException("ChaCha20-Poly1305 requiere una etiqueta AEAD de 16 bytes.", Algorithm);
        }

        if (ivOrNonce.Length != NonceSizeBytes)
        {
            throw new DecryptionFailedException("ChaCha20-Poly1305 requiere un nonce de 12 bytes.", Algorithm);
        }

        var normalizedKey = key.Length == KeySizeBytes
            ? key
            : CryptoModuleHelpers.DeriveFixedBytes(key, null, "CHACHA20-KEY", KeySizeBytes);

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var cipher = new ChaCha20Poly1305(normalizedKey);
            cipher.Decrypt(ivOrNonce, ciphertext, authTag, plaintext, associatedData);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            throw new DecryptionFailedException("Falló la autenticación o el descifrado ChaCha20-Poly1305.", Algorithm, innerException: ex);
        }
    }
}
