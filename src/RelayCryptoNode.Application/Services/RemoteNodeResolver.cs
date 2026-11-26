using System.Security.Cryptography;
using System.Text;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Application.Services;

/// <summary>
/// Nodo remoto ya identificado, con su certificado si lo publica.
/// </summary>
/// <param name="Identity">Identidad del nodo remoto.</param>
/// <param name="CertificatePem">Certificado PEM del nodo o <c>null</c>.</param>
public sealed record ResolvedRemoteNode(NodeIdentity Identity, string? CertificatePem);

/// <summary>
/// Obtiene y valida el certificado de un nodo remoto para poder envolverle la clave de sesión.
/// </summary>
public sealed class RemoteNodeResolver
{
    private readonly INodeTransportSenderPort _transport;
    private readonly ICertificateServicePort _certificates;

    /// <summary>
    /// Crea el resolvedor de nodos remotos.
    /// </summary>
    public RemoteNodeResolver(INodeTransportSenderPort transport, ICertificateServicePort certificates)
    {
        _transport = transport;
        _certificates = certificates;
    }

    /// <summary>
    /// Pide el certificado al nodo remoto y arma su identidad. Con RSA el certificado es obligatorio;
    /// con clave precompartida se puede enviar a nodos que no lo publican.
    /// </summary>
    public async Task<ResolvedRemoteNode> ResolveAsync(
        string endpointAddress,
        KeyExchangeAlgorithmType keyExchange,
        string? knownCertificatePem = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(endpointAddress))
        {
            throw new DomainException("Falta la dirección del nodo destino (por ejemplo http://192.168.1.20:5000).", "DESTINATION_EMPTY");
        }

        var endpoint = NormalizeEndpoint(endpointAddress);
        string? pem = knownCertificatePem;
        if (string.IsNullOrWhiteSpace(pem))
        {
            try
            {
                pem = await _transport.FetchRemoteCertificatePemAsync(endpoint, cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException) when (keyExchange == KeyExchangeAlgorithmType.PreSharedKey)
            {
                // Con PSK basta con poder entregar el paquete; el certificado es opcional.
                pem = null;
            }
        }

        if (string.IsNullOrWhiteSpace(pem))
        {
            if (keyExchange != KeyExchangeAlgorithmType.PreSharedKey)
            {
                throw new InvalidCertificateException(
                    $"El nodo {endpoint} no publicó su certificado en /api/certificate. Use la clave precompartida (PSK) del grupo.");
            }

            var pseudoThumbprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(endpoint))).ToLowerInvariant();
            return new ResolvedRemoteNode(new NodeIdentity("REMOTO", endpoint, pseudoThumbprint), null);
        }

        var validation = await _certificates.ValidateCertificateAsync(pem, cancellationToken).ConfigureAwait(false);
        if (!validation.IsValid)
        {
            throw new InvalidCertificateException(validation.DiagnosticMessage ?? "certificado del destino inválido", validation.ThumbprintSha256);
        }

        var nodeId = ExtractCommonName(validation.SubjectName) ?? "REMOTO";
        return new ResolvedRemoteNode(new NodeIdentity(nodeId, endpoint, validation.ThumbprintSha256), pem);
    }

    /// <summary>
    /// Normaliza la dirección: agrega <c>http://</c> si falta y quita la diagonal final.
    /// </summary>
    public static string NormalizeEndpoint(string endpointAddress)
    {
        var endpoint = endpointAddress.Trim().TrimEnd('/');
        if (!endpoint.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            endpoint = "http://" + endpoint;
        }

        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        {
            throw new DomainException($"La dirección '{endpointAddress}' no es válida.", "DESTINATION_INVALID");
        }

        return uri.GetLeftPart(UriPartial.Authority);
    }

    private static string? ExtractCommonName(string subject)
    {
        foreach (var part in subject.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                var cn = new string(part[3..].Where(c => !char.IsWhiteSpace(c)).ToArray());
                return string.IsNullOrWhiteSpace(cn) ? null : cn.ToUpperInvariant();
            }
        }

        return null;
    }
}
