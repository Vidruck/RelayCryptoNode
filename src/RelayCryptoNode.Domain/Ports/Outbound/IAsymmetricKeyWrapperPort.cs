using RelayCryptoNode.Domain.Enums;

namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Resultado de envolver o encapsular una clave simétrica de sesión para un destinatario.
/// </summary>
/// <param name="WrappedKey">Clave de sesión cifrada o texto cifrado KEM.</param>
/// <param name="Salt">Sal o material efímero adicional opcional (por ejemplo clave pública efímera ECDH).</param>
/// <param name="ExtraMetadata">Metadatos auxiliares de derivación o encapsulación.</param>
public sealed record KeyWrapResult(
    byte[] WrappedKey,
    byte[]? Salt = null,
    IReadOnlyDictionary<string, string>? ExtraMetadata = null);

/// <summary>
/// Puerto de salida para mecanismos de envoltura, acuerdo o encapsulación poscuántica de claves de sesión.
/// </summary>
public interface IAsymmetricKeyWrapperPort
{
    /// <summary>
    /// Algoritmo de intercambio o envoltura implementado por este adaptador.
    /// </summary>
    KeyExchangeAlgorithmType Algorithm { get; }

    /// <summary>
    /// Indica si este adaptador soporta el algoritmo de intercambio solicitado.
    /// </summary>
    /// <param name="algorithm">Algoritmo a evaluar.</param>
    /// <returns><c>true</c> si es compatible.</returns>
    bool CanHandle(KeyExchangeAlgorithmType algorithm);

    /// <summary>
    /// Envuelve o encapsula una clave simétrica de sesión usando la clave pública del certificado destino.
    /// </summary>
    /// <param name="sessionKey">Clave simétrica efímera en claro.</param>
    /// <param name="recipientCertificatePem">Certificado X.509 PEM del nodo receptor.</param>
    /// <returns>Clave envuelta y material auxiliar necesario para el receptor.</returns>
    KeyWrapResult WrapSessionKey(byte[] sessionKey, string recipientCertificatePem);

    /// <summary>
    /// Desenvuelve o desencapsula la clave simétrica de sesión usando la clave privada local del nodo.
    /// </summary>
    /// <param name="wrappedKey">Clave envuelta o cápsula recibida.</param>
    /// <param name="salt">Sal o material efímero opcional asociado.</param>
    /// <param name="extraMetadata">Metadatos opcionales del sobre criptográfico.</param>
    /// <returns>Clave simétrica de sesión en claro.</returns>
    byte[] UnwrapSessionKey(
        byte[] wrappedKey,
        byte[]? salt = null,
        IReadOnlyDictionary<string, string>? extraMetadata = null);
}
