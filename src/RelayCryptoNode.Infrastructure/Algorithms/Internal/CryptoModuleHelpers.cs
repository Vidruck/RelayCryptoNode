using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;

namespace RelayCryptoNode.Infrastructure.Algorithms.Internal;

internal static class CryptoModuleHelpers
{
    public static byte[] DeriveFixedBytes(byte[] key, byte[]? context, string domainLabel, int length)
    {
        if (key is null || key.Length == 0)
        {
            throw new DomainException("La clave criptográfica no puede ser nula ni vacía.", "CRYPTO_KEY_EMPTY");
        }

        var labelBytes = System.Text.Encoding.UTF8.GetBytes(domainLabel);
        var info = context is null || context.Length == 0
            ? labelBytes
            : [.. labelBytes, .. context];

        return HKDF.DeriveKey(HashAlgorithmName.SHA256, key, length, salt: null, info: info);
    }

    public static byte[] ComputeTag(
        byte[] key,
        byte[] ivOrNonce,
        byte[] ciphertext,
        byte[]? associatedData,
        string domainLabel)
    {
        var macKey = DeriveFixedBytes(key, ivOrNonce, $"{domainLabel}:MAC", 32);
        using var hmac = new HMACSHA256(macKey);
        using var ms = new MemoryStream();
        ms.Write(ivOrNonce);
        ms.Write(ciphertext);
        if (associatedData is { Length: > 0 })
        {
            ms.Write(associatedData);
        }

        return hmac.ComputeHash(ms.ToArray());
    }

    public static void VerifyTagOrThrow(
        byte[] key,
        byte[] ivOrNonce,
        byte[] ciphertext,
        byte[]? authTag,
        byte[]? associatedData,
        string domainLabel,
        CipherAlgorithmType algorithm)
    {
        if (authTag is null || authTag.Length != 32)
        {
            throw new DecryptionFailedException(
                "La etiqueta de autenticación HMAC-SHA256 está ausente o tiene longitud inválida.",
                algorithm);
        }

        var expectedTag = ComputeTag(key, ivOrNonce, ciphertext, associatedData, domainLabel);
        if (!CryptographicOperations.FixedTimeEquals(expectedTag, authTag))
        {
            throw new DecryptionFailedException(
                $"Falló la verificación de integridad del paquete para {algorithm}.",
                algorithm);
        }
    }

    public static void ValidateDecryptInputs(byte[] ciphertext, byte[] key, byte[] ivOrNonce, CipherAlgorithmType algorithm)
    {
        if (ciphertext is null)
        {
            throw new DecryptionFailedException("El texto cifrado no puede ser nulo.", algorithm);
        }

        if (key is null || key.Length == 0)
        {
            throw new DecryptionFailedException("La clave de descifrado no puede estar vacía.", algorithm);
        }

        if (ivOrNonce is null || ivOrNonce.Length == 0)
        {
            throw new DecryptionFailedException("El IV/Nonce es obligatorio para descifrar.", algorithm);
        }
    }
}
