using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace RelayCryptoNode.Infrastructure.ProtocolV2;

/// <summary>
/// Sobre híbrido CC-ENV-1 (8.3): AES-256-GCM con CEK aleatoria + RSA-OAEP-SHA256 (MGF1-SHA256) para la CEK.
/// </summary>
public static class CcEnvelope
{
    /// <summary>Nombre del sobre.</summary>
    public const string Name = "CC-ENV-1";

    /// <summary>
    /// Cifra <paramref name="content"/> para el destinatario. Devuelve el sobre (con <c>ciphertextBase64</c>) y el texto cifrado.
    /// </summary>
    public static (JsonObject Envelope, byte[] Ciphertext) Seal(byte[] content, string recipientNode, string recipientCertificatePem, string aad)
    {
        ArgumentNullException.ThrowIfNull(content);
        using var certificate = X509Certificate2.CreateFromPem(recipientCertificatePem);
        using var rsa = certificate.GetRSAPublicKey()
                        ?? throw new V2ProtocolException("E-CERT", "El certificado del destinatario no tiene llave RSA.");
        var cek = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[content.Length];
        try
        {
            using (var aes = new AesGcm(cek, 16))
            {
                aes.Encrypt(nonce, content, ciphertext, tag, Encoding.UTF8.GetBytes(aad));
            }

            var wrapped = rsa.Encrypt(cek, RSAEncryptionPadding.OaepSHA256);
            var envelope = new JsonObject
            {
                ["envelope"] = Name,
                ["recipientNode"] = recipientNode,
                ["recipientThumbprintSha256"] = Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
                ["wrappedKeyBase64"] = Convert.ToBase64String(wrapped),
                ["nonceBase64"] = Convert.ToBase64String(nonce),
                ["tagBase64"] = Convert.ToBase64String(tag),
                ["ciphertextBase64"] = Convert.ToBase64String(ciphertext)
            };
            return (envelope, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    /// <summary>
    /// Abre un sobre. Si <paramref name="ciphertext"/> es nulo se toma <c>ciphertextBase64</c> del sobre.
    /// Es tolerante con otros equipos: acepta nombres de campo distintos (wrappedKey/encryptedKey, nonce/iv,
    /// tag/authTag), tag pegado al final del texto cifrado, OAEP con SHA-256 o SHA-1 y varios AAD posibles.
    /// </summary>
    public static byte[] Open(JsonObject envelope, byte[]? ciphertext, string ownNodeId, string ownThumbprint, string privateKeyPem, string aad,
        params string?[] otherAads)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var name = Text(envelope, "envelope", "scheme", "format", "type", "alg", "algorithm", "version");
        var wrappedText = Text(envelope, "wrappedKeyBase64", "wrappedKey", "encryptedKeyBase64", "encryptedKey", "wrappedCekBase64", "wrappedCek",
            "encryptedCekBase64", "encryptedCek", "cekBase64", "cek", "ek", "keyBase64", "key");
        if (wrappedText is null && name is not null && !name.Contains("CC-ENV", StringComparison.OrdinalIgnoreCase))
        {
            throw new V2ProtocolException("E-ENV-DECRYPT", "El sobre no es CC-ENV-1.");
        }

        if (wrappedText is null)
        {
            throw new V2ProtocolException("E-ENV-DECRYPT", $"El sobre no trae la llave envuelta. Campos: {string.Join(", ", envelope.Select(p => p.Key))}.");
        }

        var recipient = Text(envelope, "recipientNode", "recipient", "to", "targetNode");
        var thumb = Text(envelope, "recipientThumbprintSha256", "recipientThumbprint", "thumbprint");
        if ((recipient is not null && !string.Equals(recipient, ownNodeId, StringComparison.OrdinalIgnoreCase))
            || (thumb is not null && !string.Equals(thumb, ownThumbprint, StringComparison.OrdinalIgnoreCase)))
        {
            throw new V2ProtocolException("E-ENV-RECIPIENT", "El sobre no está dirigido a este nodo.");
        }

        try
        {
            var wrapped = Bytes(wrappedText);
            var nonce = Bytes(Text(envelope, "nonceBase64", "nonce", "ivBase64", "iv") ?? string.Empty);
            var tagText = Text(envelope, "tagBase64", "tag", "authTagBase64", "authTag");
            var data = ciphertext ?? Bytes(Text(envelope, "ciphertextBase64", "ciphertext", "dataBase64", "data") ?? string.Empty);
            byte[] tag;
            if (tagText is not null)
            {
                tag = Bytes(tagText);
            }
            else
            {
                // Tag pegado al final del texto cifrado (como lo hacen Java, Python y WebCrypto).
                if (data.Length < 16)
                {
                    throw new FormatException();
                }

                tag = data[^16..];
                data = data[..^16];
            }

            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            byte[] cek;
            try
            {
                cek = rsa.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
            }
            catch (CryptographicException)
            {
                cek = rsa.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA1);
            }

            try
            {
                var candidates = new List<byte[]?> { Encoding.UTF8.GetBytes(aad) };
                var declared = Text(envelope, "aad", "aadBase64", "associatedData");
                if (declared is not null)
                {
                    candidates.Add(Encoding.UTF8.GetBytes(declared));
                }

                foreach (var other in otherAads)
                {
                    if (!string.IsNullOrEmpty(other))
                    {
                        candidates.Add(Encoding.UTF8.GetBytes(other));
                    }
                }

                candidates.Add(Array.Empty<byte>());
                candidates.Add(null);
                using var aes = new AesGcm(cek, tag.Length);
                var plaintext = new byte[data.Length];
                foreach (var candidate in candidates)
                {
                    try
                    {
                        aes.Decrypt(nonce, data, tag, plaintext, candidate);
                        return plaintext;
                    }
                    catch (CryptographicException)
                    {
                    }
                }

                throw new CryptographicException("Ningún AAD coincidió.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(cek);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            throw new V2ProtocolException("E-ENV-DECRYPT", "No se pudo abrir el sobre CC-ENV-1.");
        }
    }

    private static string? Text(JsonObject node, params string[] names)
    {
        foreach (var name in names)
        {
            foreach (var pair in node)
            {
                if (string.Equals(pair.Key, name, StringComparison.OrdinalIgnoreCase) && pair.Value is JsonValue value
                    && value.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text))
                {
                    return text;
                }
            }
        }

        return null;
    }

    /// <summary>Base64 (normal o URL) o hex.</summary>
    private static byte[] Bytes(string text)
    {
        var t = text.Trim();
        if (t.Length % 2 == 0 && t.All(Uri.IsHexDigit))
        {
            return Convert.FromHexString(t);
        }

        t = t.Replace('-', '+').Replace('_', '/');
        t = t.PadRight(t.Length + ((4 - (t.Length % 4)) % 4), '=');
        return Convert.FromBase64String(t);
    }

    /// <summary>Copia del sobre sin <c>ciphertextBase64</c> (para <c>resultEnvelope</c>).</summary>
    public static JsonObject WithoutCiphertext(JsonObject envelope)
    {
        var copy = (JsonObject)envelope.DeepClone();
        copy.Remove("ciphertextBase64");
        return copy;
    }
}
