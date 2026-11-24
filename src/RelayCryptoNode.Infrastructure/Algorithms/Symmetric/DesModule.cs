using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Symmetric;

/// <summary>
/// Módulo oficial <c>DES</c> (#2): cifrado por bloques DES 56-bit (CBC + PKCS7) con etiqueta HMAC-SHA256.
/// </summary>
public sealed class DesModule : ISymmetricCipherStrategy
{
    private const int KeySizeBytes = 8;
    private const int IvSizeBytes = 8;
    private const string DomainLabel = "DES56";

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.DES;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.Des;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.Des;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var desKey = key.Length == KeySizeBytes
            ? key
            : CryptoModuleHelpers.DeriveFixedBytes(key, null, $"{DomainLabel}:KEY", KeySizeBytes);
        var iv = RandomNumberGenerator.GetBytes(IvSizeBytes);

        using var des = System.Security.Cryptography.DES.Create();
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.PKCS7;
        des.Key = desKey;
        des.IV = iv;

        using var encryptor = des.CreateEncryptor();
        var ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        var tag = CryptoModuleHelpers.ComputeTag(key, iv, ciphertext, associatedData, DomainLabel);

        return new SymmetricEncryptionResult(ciphertext, iv, tag);
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

        if (ivOrNonce.Length != IvSizeBytes)
        {
            throw new DecryptionFailedException("DES requiere un IV de 8 bytes.", Algorithm);
        }

        var desKey = key.Length == KeySizeBytes
            ? key
            : CryptoModuleHelpers.DeriveFixedBytes(key, null, $"{DomainLabel}:KEY", KeySizeBytes);

        try
        {
            using var des = System.Security.Cryptography.DES.Create();
            des.Mode = CipherMode.CBC;
            des.Padding = PaddingMode.PKCS7;
            des.Key = desKey;
            des.IV = ivOrNonce;

            using var decryptor = des.CreateDecryptor();
            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }
        catch (CryptographicException ex)
        {
            throw new DecryptionFailedException("Falló el descifrado DES.", Algorithm, innerException: ex);
        }
    }
}
