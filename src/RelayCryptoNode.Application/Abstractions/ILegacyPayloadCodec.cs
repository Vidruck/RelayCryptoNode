using RelayCryptoNode.Domain.Enums;

namespace RelayCryptoNode.Application.Abstractions;

/// <summary>
/// Códec para el formato "clave compartida" que usan otros equipos del grupo (por ejemplo el NODO04):
/// no hay clave de sesión envuelta; <c>datos.enc</c> se cifra directamente con la clave del algoritmo
/// acordada en clase.
/// </summary>
public interface ILegacyPayloadCodec
{
    /// <summary>
    /// Indica si el códec sabe cifrar y descifrar ese algoritmo en formato compartido.
    /// </summary>
    bool Supports(CipherAlgorithmType algorithm);

    /// <summary>
    /// Cifra con la clave compartida del algoritmo.
    /// </summary>
    byte[] Encrypt(byte[] plaintext, CipherAlgorithmType algorithm);

    /// <summary>
    /// Descifra con la clave compartida del algoritmo.
    /// </summary>
    byte[] Decrypt(byte[] ciphertext, CipherAlgorithmType algorithm);
}

/// <summary>
/// Claves de metadatos que marcan un sobre en formato compartido.
/// </summary>
public static class LegacyFormat
{
    /// <summary>Clave de metadatos que indica el formato de clave compartida.</summary>
    public const string MetadataKey = "keyMode";

    /// <summary>Valor para el formato de clave compartida (compatible con NODO04).</summary>
    public const string SharedKeyValue = "SHARED-KEY";
}
