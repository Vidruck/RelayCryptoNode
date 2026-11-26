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
    /// </summary>
    public static byte[] Open(JsonObject envelope, byte[]? ciphertext, string ownNodeId, string ownThumbprint, string privateKeyPem, string aad)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if ((string?)envelope["envelope"] != Name)
        {
            throw new V2ProtocolException("E-ENV-DECRYPT", "El sobre no es CC-ENV-1.");
        }

        if ((string?)envelope["recipientNode"] != ownNodeId
            || !string.Equals((string?)envelope["recipientThumbprintSha256"], ownThumbprint, StringComparison.Ordinal))
        {
            throw new V2ProtocolException("E-ENV-RECIPIENT", "El sobre no está dirigido a este nodo.");
        }

        try
        {
            var wrapped = Convert.FromBase64String((string?)envelope["wrappedKeyBase64"] ?? string.Empty);
            var nonce = Convert.FromBase64String((string?)envelope["nonceBase64"] ?? string.Empty);
            var tag = Convert.FromBase64String((string?)envelope["tagBase64"] ?? string.Empty);
            var data = ciphertext ?? Convert.FromBase64String((string?)envelope["ciphertextBase64"] ?? string.Empty);
            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            var cek = rsa.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
            try
            {
                var plaintext = new byte[data.Length];
                using var aes = new AesGcm(cek, 16);
                aes.Decrypt(nonce, data, tag, plaintext, Encoding.UTF8.GetBytes(aad));
                return plaintext;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(cek);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new V2ProtocolException("E-ENV-DECRYPT", "No se pudo abrir el sobre CC-ENV-1.");
        }
    }

    /// <summary>Copia del sobre sin <c>ciphertextBase64</c> (para <c>resultEnvelope</c>).</summary>
    public static JsonObject WithoutCiphertext(JsonObject envelope)
    {
        var copy = (JsonObject)envelope.DeepClone();
        copy.Remove("ciphertextBase64");
        return copy;
    }
}
