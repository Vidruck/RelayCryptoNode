using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Symmetric;

/// <summary>
/// Módulo oficial <c>TRIPLEDES</c> (#3): cifrado por bloques Triple DES / 3DES (CBC + PKCS7) con autenticación HMAC-SHA256.
/// </summary>
public sealed class TripleDesModule : ISymmetricCipherStrategy
{
    private const int KeySizeBytes = 24;
    private const int IvSizeBytes = 8;
    private const string DomainLabel = "TRIPLEDES";

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.TRIPLEDES;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.TripleDes;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.TripleDes;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var tdesKey = key.Length == KeySizeBytes
            ? key
            : CryptoModuleHelpers.DeriveFixedBytes(key, null, $"{DomainLabel}:KEY", KeySizeBytes);
        var iv = RandomNumberGenerator.GetBytes(IvSizeBytes);

        using var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CBC;
        tdes.Padding = PaddingMode.PKCS7;
        tdes.Key = tdesKey;
        tdes.IV = iv;

        using var encryptor = tdes.CreateEncryptor();
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
            throw new DecryptionFailedException("Triple DES requiere un IV de 8 bytes.", Algorithm);
        }

        var tdesKey = key.Length == KeySizeBytes
            ? key
            : CryptoModuleHelpers.DeriveFixedBytes(key, null, $"{DomainLabel}:KEY", KeySizeBytes);

        try
        {
            using var tdes = TripleDES.Create();
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.PKCS7;
            tdes.Key = tdesKey;
            tdes.IV = ivOrNonce;

            using var decryptor = tdes.CreateDecryptor();
            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }
        catch (CryptographicException ex)
        {
            throw new DecryptionFailedException("Falló el descifrado Triple DES.", Algorithm, innerException: ex);
        }
    }
}
