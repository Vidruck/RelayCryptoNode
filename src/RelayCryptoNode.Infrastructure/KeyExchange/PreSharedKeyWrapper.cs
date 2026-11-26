using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Infrastructure.KeyExchange;

/// <summary>
/// Envuelve la clave de sesión con una clave precompartida del grupo (PSK):
/// KEK = PBKDF2-SHA256(PSK, sal de 16 bytes, 100 000 iteraciones) y AES-256-GCM.
/// Sirve para enviar a nodos que no publican su certificado.
/// </summary>
public sealed class PreSharedKeyWrapper : IAsymmetricKeyWrapperPort
{
    private const int DefaultIterations = 100_000;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly Func<string?> _preSharedKeyProvider;

    /// <summary>
    /// Crea el envoltorio con una función que entrega la clave precompartida vigente.
    /// </summary>
    public PreSharedKeyWrapper(Func<string?> preSharedKeyProvider)
    {
        _preSharedKeyProvider = preSharedKeyProvider;
    }

    /// <inheritdoc />
    public KeyExchangeAlgorithmType Algorithm => KeyExchangeAlgorithmType.PreSharedKey;

    /// <inheritdoc />
    public bool CanHandle(KeyExchangeAlgorithmType algorithm) => algorithm == KeyExchangeAlgorithmType.PreSharedKey;

    /// <inheritdoc />
    public KeyWrapResult WrapSessionKey(byte[] sessionKey, string recipientCertificatePem)
    {
        ArgumentNullException.ThrowIfNull(sessionKey);
        var salt = RandomNumberGenerator.GetBytes(16);
        var kek = DeriveKek(salt, DefaultIterations);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var ciphertext = new byte[sessionKey.Length];
            var tag = new byte[TagSize];
            using (var aes = new AesGcm(kek, TagSize))
            {
                aes.Encrypt(nonce, sessionKey, ciphertext, tag);
            }

            var wrapped = new byte[NonceSize + ciphertext.Length + TagSize];
            nonce.CopyTo(wrapped, 0);
            ciphertext.CopyTo(wrapped, NonceSize);
            tag.CopyTo(wrapped, NonceSize + ciphertext.Length);

            return new KeyWrapResult(wrapped, salt, new Dictionary<string, string>
            {
                ["keyWrap"] = "PSK-PBKDF2-SHA256-AES256GCM",
                ["kdfIterations"] = DefaultIterations.ToString(CultureInfo.InvariantCulture)
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <inheritdoc />
    public byte[] UnwrapSessionKey(
        byte[] wrappedKey,
        byte[]? salt = null,
        IReadOnlyDictionary<string, string>? extraMetadata = null)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);
        if (salt is null || salt.Length == 0)
        {
            throw new DecryptionFailedException("La envoltura PSK requiere saltBase64 en el manifiesto.");
        }

        if (wrappedKey.Length <= NonceSize + TagSize)
        {
            throw new DecryptionFailedException("La clave de sesión envuelta con PSK tiene una longitud inválida.");
        }

        var iterations = DefaultIterations;
        if (extraMetadata is not null
            && extraMetadata.TryGetValue("kdfIterations", out var text)
            && int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            && parsed is >= 1_000 and <= 5_000_000)
        {
            iterations = parsed;
        }

        var kek = DeriveKek(salt, iterations);
        try
        {
            var nonce = wrappedKey.AsSpan(0, NonceSize);
            var ciphertext = wrappedKey.AsSpan(NonceSize, wrappedKey.Length - NonceSize - TagSize);
            var tag = wrappedKey.AsSpan(wrappedKey.Length - TagSize);
            var sessionKey = new byte[ciphertext.Length];
            using var aes = new AesGcm(kek, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, sessionKey);
            return sessionKey;
        }
        catch (CryptographicException ex)
        {
            throw new DecryptionFailedException(
                "No se pudo desenvolver la clave con la PSK (¿la clave precompartida es distinta entre nodos?).",
                innerException: ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private byte[] DeriveKek(byte[] salt, int iterations)
    {
        var psk = _preSharedKeyProvider();
        if (string.IsNullOrEmpty(psk))
        {
            throw new DomainException(
                "No hay clave precompartida (PSK) configurada en este nodo.",
                "PSK_NOT_CONFIGURED");
        }

        return Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(psk), salt, iterations, HashAlgorithmName.SHA256, 32);
    }
}
