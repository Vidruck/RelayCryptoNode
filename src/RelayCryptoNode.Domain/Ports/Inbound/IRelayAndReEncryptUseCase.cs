using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Domain.Ports.Inbound;

/// <summary>
/// Comando de entrada para desencriptar en RAM y re-encriptar un paquete en el rol <see cref="NodeRole.Intermediate"/>.
/// </summary>
/// <param name="RequestId">Identificador de la solicitud entrante previamente aceptada.</param>
/// <param name="NextNode">Identidad del siguiente nodo destino en la cadena.</param>
/// <param name="TargetCipherAlgorithm">Nuevo algoritmo simétrico configurado para la re-encriptación de salida.</param>
/// <param name="TargetKeyExchangeAlgorithm">Nuevo algoritmo de envoltura/acuerdo de clave de salida.</param>
/// <param name="TargetSignatureAlgorithm">Algoritmo de firma digital del nuevo manifiesto.</param>
public sealed record RelayAndReEncryptCommand(
    Guid RequestId,
    NodeIdentity NextNode,
    CipherAlgorithmType TargetCipherAlgorithm,
    KeyExchangeAlgorithmType TargetKeyExchangeAlgorithm,
    SignatureAlgorithmType TargetSignatureAlgorithm);

/// <summary>
/// Resultado del relevo polimórfico ejecutado por un nodo intermedio.
/// </summary>
/// <param name="RequestId">Identificador de la solicitud procesada.</param>
/// <param name="IncomingAlgorithm">Algoritmo simétrico autodetectado en el sobre entrante.</param>
/// <param name="OutgoingEnvelope">Nuevo sobre re-encriptado y firmado.</param>
/// <param name="OutgoingPackageFileName">Nombre estandarizado del nuevo paquete emitido.</param>
/// <param name="Delivered">Indica si el siguiente nodo confirmó la recepción.</param>
public sealed record RelayAndReEncryptResult(
    Guid RequestId,
    CipherAlgorithmType IncomingAlgorithm,
    CryptoEnvelope OutgoingEnvelope,
    string OutgoingPackageFileName,
    bool Delivered);

/// <summary>
/// Puerto de entrada para el caso de uso del rol <see cref="NodeRole.Intermediate"/>.
/// </summary>
public interface IRelayAndReEncryptUseCase
{
    /// <summary>
    /// Valida, autodetecta el algoritmo entrante, descifra en memoria RAM, re-encripta con el algoritmo configurado y reenvía.
    /// </summary>
    /// <param name="command">Parámetros del relevo y algoritmos de salida.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Resultado del relevo con el algoritmo detectado y el nuevo sobre emitido.</returns>
    Task<RelayAndReEncryptResult> ExecuteAsync(
        RelayAndReEncryptCommand command,
        CancellationToken cancellationToken = default);
}
