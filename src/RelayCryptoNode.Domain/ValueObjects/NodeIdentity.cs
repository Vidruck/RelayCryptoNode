using RelayCryptoNode.Domain.Exceptions;

namespace RelayCryptoNode.Domain.ValueObjects;

/// <summary>
/// Value Object inmutable que identifica de forma única y verificable a un nodo dentro de la cadena LAN.
/// </summary>
public sealed record NodeIdentity
{
    /// <summary>
    /// Identificador único del nodo normalizado en mayúsculas y sin espacios (por ejemplo, <c>NODO01</c>).
    /// </summary>
    public string NodeId { get; }

    /// <summary>
    /// Dirección de red o endpoint base del nodo (por ejemplo, <c>http://192.168.1.10:5000</c>).
    /// </summary>
    public string EndpointAddress { get; }

    /// <summary>
    /// Huella digital SHA-256 (64 caracteres hexadecimales en minúsculas) del certificado X.509 del nodo.
    /// </summary>
    public string CertificateThumbprintSha256 { get; }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="NodeIdentity"/> validando todas sus invariantes.
    /// </summary>
    /// <param name="nodeId">Identificador lógico del nodo (sin espacios).</param>
    /// <param name="endpointAddress">Dirección de red del nodo.</param>
    /// <param name="certificateThumbprintSha256">Huella SHA-256 del certificado X.509 (64 hex).</param>
    /// <exception cref="DomainException">Se lanza cuando algún componente es inválido.</exception>
    public NodeIdentity(string nodeId, string endpointAddress, string certificateThumbprintSha256)
    {
        if (string.IsNullOrWhiteSpace(nodeId))
        {
            throw new DomainException("El NodeId no puede estar vacío ni ser nulo.", "NODE_ID_EMPTY");
        }

        if (nodeId.Any(char.IsWhiteSpace))
        {
            throw new DomainException(
                "El NodeId no puede contener espacios ni caracteres en blanco.",
                "NODE_ID_WHITESPACE");
        }

        if (string.IsNullOrWhiteSpace(endpointAddress))
        {
            throw new DomainException(
                "La dirección de endpoint del nodo no puede estar vacía.",
                "NODE_ENDPOINT_EMPTY");
        }

        var validatedThumbprint = IntegrityDigest.Sha256(certificateThumbprintSha256);

        NodeId = nodeId.ToUpperInvariant();
        EndpointAddress = endpointAddress.Trim();
        CertificateThumbprintSha256 = validatedThumbprint.HexHash;
    }
}
