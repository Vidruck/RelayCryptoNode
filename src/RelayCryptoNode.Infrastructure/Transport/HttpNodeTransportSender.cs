using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Infrastructure.Transport;

/// <summary>
/// Envía paquetes por HTTP (<c>multipart/form-data</c>, campo <c>package</c>) a <c>/api/requests/receive</c>
/// y obtiene certificados de otros nodos con <c>GET /api/certificate</c>.
/// </summary>
public sealed class HttpNodeTransportSender : INodeTransportSenderPort
{
    private const int MaxMessageLength = 500;

    private readonly HttpClient _httpClient;

    /// <summary>
    /// Crea el transporte con el <see cref="HttpClient"/> indicado.
    /// </summary>
    public HttpNodeTransportSender(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    /// <inheritdoc />
    public async Task<TransportDeliveryResult> SendPackageAsync(
        NodeIdentity destinationNode,
        byte[] packageBytes,
        string packageFileName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destinationNode);
        ArgumentNullException.ThrowIfNull(packageBytes);

        var url = destinationNode.EndpointAddress.TrimEnd('/') + "/api/requests/receive";
        using var content = new MultipartFormDataContent();
        var file = new ByteArrayContent(packageBytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        content.Add(file, "package", packageFileName);

        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        var parts = packageFileName.Split('_');
        if (parts.Length > 0)
        {
            request.Headers.TryAddWithoutValidation("X-Source-Node", parts[0]);
        }

        try
        {
            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return new TransportDeliveryResult(
                response.IsSuccessStatusCode,
                (int)response.StatusCode,
                Describe(response.StatusCode, body));
        }
        catch (HttpRequestException ex)
        {
            return new TransportDeliveryResult(false, 0, $"No se pudo conectar con {url}: {ex.Message}");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new TransportDeliveryResult(false, 0, $"El nodo {url} no respondió a tiempo.");
        }
    }

    /// <inheritdoc />
    public async Task<string?> FetchRemoteCertificatePemAsync(string endpointAddress, CancellationToken cancellationToken = default)
    {
        var url = endpointAddress.TrimEnd('/') + "/api/certificate";
        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (body.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal) && !body.TrimStart().StartsWith('{'))
        {
            return body.Trim();
        }

        try
        {
            using var json = JsonDocument.Parse(body);
            foreach (var name in new[] { "certificatePem", "certificate", "pem" })
            {
                if (json.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
                {
                    return value.GetString();
                }
            }
        }
        catch (JsonException)
        {
            // La respuesta no era JSON: el nodo no publica certificado.
        }

        return null;
    }

    private static string Describe(HttpStatusCode status, string body)
    {
        var text = string.IsNullOrWhiteSpace(body) ? status.ToString() : body.Trim();
        return text.Length > MaxMessageLength ? text[..MaxMessageLength] + "…" : text;
    }
}
