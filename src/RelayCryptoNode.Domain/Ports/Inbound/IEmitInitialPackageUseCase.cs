using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Domain.Ports.Inbound;

/// <summary>
/// Comando de entrada para emitir un paquete cifrado desde el rol <see cref="NodeRole.Initial"/>.
/// </summary>
/// <param name="Bundle">Lote original de archivos o mensajes a proteger.</param>
/// <param name="DestinationNode">Identidad del siguiente nodo receptor en la cadena.</param>
/// <param name="CipherAlgorithm">Algoritmo simétrico seleccionado para cifrar la carga útil.</param>
/// <param name="KeyExchangeAlgorithm">Mecanismo de envoltura o acuerdo de clave de sesión.</param>
/// <param name="SignatureAlgorithm">Algoritmo de firma digital del manifiesto.</param>
public sealed record EmitInitialPackageCommand(
    PayloadBundle Bundle,
    NodeIdentity DestinationNode,
    CipherAlgorithmType CipherAlgorithm,
    KeyExchangeAlgorithmType KeyExchangeAlgorithm,
    SignatureAlgorithmType SignatureAlgorithm);

/// <summary>
/// Resultado de la emisión inicial de un paquete cifrado y su entrega al siguiente nodo.
/// </summary>
/// <param name="Envelope">Sobre criptográfico generado y firmado.</param>
/// <param name="PackageFileName">Nombre estandarizado del paquete emitido.</param>
/// <param name="Delivered">Indica si el transporte confirmó recepción por parte del nodo destino.</param>
/// <param name="RemoteStatusMessage">Mensaje o código devuelto por el nodo receptor.</param>
public sealed record EmitInitialPackageResult(
    CryptoEnvelope Envelope,
    string PackageFileName,
    bool Delivered,
    string? RemoteStatusMessage = null);

/// <summary>
/// Puerto de entrada para el caso de uso del rol <see cref="NodeRole.Initial"/>.
/// </summary>
public interface IEmitInitialPackageUseCase
{
    /// <summary>
    /// Empaqueta el lote original, calcula su huella SHA-256 testigo, cifra, firma y transmite al siguiente nodo.
    /// </summary>
    /// <param name="command">Parámetros del paquete inicial y algoritmos de salida.</param>
    /// <param name="cancellationToken">Token de cancelación cooperativa.</param>
    /// <returns>Resultado detallado con el sobre emitido y estado de entrega.</returns>
    Task<EmitInitialPackageResult> ExecuteAsync(
        EmitInitialPackageCommand command,
        CancellationToken cancellationToken = default);
}
