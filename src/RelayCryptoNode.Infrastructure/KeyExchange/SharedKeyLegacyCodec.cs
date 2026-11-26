using System.Security.Cryptography;
using System.Text;
using RelayCryptoNode.Application.Abstractions;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;

namespace RelayCryptoNode.Infrastructure.KeyExchange;

/// <summary>
/// Formato de clave compartida compatible con el NODO04 para AES-256-GCM:
/// clave = SHA-256(UTF-8(clave de texto)) y <c>datos.enc</c> = nonce (12) | etiqueta (16) | cifrado.
/// </summary>
public sealed class SharedKeyLegacyCodec : ILegacyPayloadCodec
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly Func<string> _aesKeyProvider;

    /// <summary>
    /// Crea el códec con una función que devuelve la clave AES de texto acordada en el grupo.
    /// </summary>
    public SharedKeyLegacyCodec(Func<string> aesKeyProvider)
    {
        _aesKeyProvider = aesKeyProvider;
    }

    /// <inheritdoc />
    public bool Supports(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.Aes256Gcm;

    /// <inheritdoc />
    public byte[] Encrypt(byte[] plaintext, CipherAlgorithmType algorithm)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        EnsureSupported(algorithm);
        var key = DeriveKey();
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var tag = new byte[TagSize];
            var ciphertext = new byte[plaintext.Length];
            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            return [.. nonce, .. tag, .. ciphertext];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] ciphertext, CipherAlgorithmType algorithm)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        EnsureSupported(algorithm);
        if (ciphertext.Length < NonceSize + TagSize)
        {
            throw new DecryptionFailedException("Payload AES-GCM demasiado corto.", algorithm);
        }

        var key = DeriveKey();
        try
        {
            var plaintext = new byte[ciphertext.Length - NonceSize - TagSize];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(
                ciphertext.AsSpan(0, NonceSize),
                ciphertext.AsSpan(NonceSize + TagSize),
                ciphertext.AsSpan(NonceSize, TagSize),
                plaintext);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            throw new DecryptionFailedException(
                "No se pudo descifrar con la clave AES compartida (revise que sea la misma que usó el otro equipo).",
                algorithm,
                innerException: ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private byte[] DeriveKey() => SHA256.HashData(Encoding.UTF8.GetBytes(_aesKeyProvider()));

    private void EnsureSupported(CipherAlgorithmType algorithm)
    {
        if (!Supports(algorithm))
        {
            throw new UnsupportedAlgorithmException(algorithm.ToString(), "El modo de clave compartida solo está disponible para AES-GCM.");
        }
    }
}
