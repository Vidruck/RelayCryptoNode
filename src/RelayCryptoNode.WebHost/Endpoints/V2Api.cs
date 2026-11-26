using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RelayCryptoNode.Application.Configuration;
using RelayCryptoNode.Application.Services;
using RelayCryptoNode.Infrastructure.ProtocolV2;
using RelayCryptoNode.WebHost.Hosting;

namespace RelayCryptoNode.WebHost.Endpoints;

/// <summary>
/// Endpoints del estándar v2.0 (sección 10) y del panel (/api/ui).
/// </summary>
public static class V2Api
{

    /// <summary>Registra los endpoints.</summary>
    public static void MapV2Api(this WebApplication app)
    {
        var api = app.MapGroup("/api");

        api.MapGet("/status", (V2NodeService node, NodeRuntimeState legacy) =>
        {
            var status = node.Status();
            // Campos extra para nodos v1 (se ignoran en v2.0).
            status["certificateThumbprint"] = node.Identity.Thumbprint;
            status["supportedProtocolVersions"] = new JsonArray("1.0", "2.0");
            status["role"] = legacy.Current.Role.ToString();
            status["endpoint"] = $"http://{node.Identity.Ip}:{node.Identity.HttpPort}";
            return Results.Text(status.ToJsonString(), "application/json");
        });

        api.MapGet("/certificate", (V2NodeService node) => Results.Text(node.Identity.CertificatePem, "application/x-pem-file"));

        api.MapGet("/algorithms", (V2NodeService node) => Results.Text(node.AlgorithmsProfile().ToJsonString(), "application/json"));

        api.MapPost("/requests/receive", ReceiveAsync);

        api.MapPost("/crypto/forward", (HttpRequest http, V2NodeService node, CancellationToken ct) => CryptoAsync("forward", http, node, ct));
        api.MapPost("/crypto/inverse", (HttpRequest http, V2NodeService node, CancellationToken ct) => CryptoAsync("inverse", http, node, ct));

        api.MapGet("/jobs/{jobId}", IResult (string jobId) =>
            throw new V2ProtocolException("E-JOB-NOT-FOUND", $"No hay trabajo {jobId}: este nodo responde todo de forma síncrona."));
        api.MapGet("/jobs/{jobId}/result", IResult (string jobId) =>
            throw new V2ProtocolException("E-JOB-NOT-FOUND", $"No hay trabajo {jobId}."));
        api.MapGet("/keys/{keyId}", IResult (string keyId) =>
            throw new V2ProtocolException("E-KEY-NOT-FOUND", $"{keyId} no existe: los algoritmos de este nodo no usan keyId."));

        MapUi(app.MapGroup("/api/ui"));
    }

    private static async Task<IResult> ReceiveAsync(
        HttpRequest http,
        V2NodeService node,
        IncomingPackageService legacyReception,
        NodeSettingsStore settings,
        NodeRuntimeState state,
        RequestProcessingService processing,
        ILoggerFactory loggers,
        CancellationToken ct)
    {
        if (http.ContentLength > V2Format.MaxBodyBytes + (1024 * 1024))
        {
            throw new V2ProtocolException("E-SIZE", "El cuerpo supera 50 MB.");
        }

        byte[] bytes;
        string? fileName = null;
        if (http.HasFormContentType)
        {
            var form = await http.ReadFormAsync(ct);
            var file = form.Files.GetFile("package") ?? form.Files.FirstOrDefault()
                       ?? throw new V2ProtocolException("E-REQUEST", "Se requiere multipart/form-data con el campo package.");
            fileName = file.FileName;
            bytes = await ReadAsync(file, ct);
        }
        else
        {
            using var buffer = new MemoryStream();
            await http.Body.CopyToAsync(buffer, ct);
            bytes = buffer.ToArray();
        }

        if (V2PackageCodec.LooksLikeV2(bytes))
        {
            var record = await node.ReceiveAsync(bytes, http.HttpContext.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? "?", ct);
            return Results.Json(new
            {
                packetId = record.PacketId,
                status = "Pendiente",
                receivedAtUtc = V2Format.Timestamp(record.CreatedUtc),
                requestId = record.Id,
                zipFileName = fileName ?? record.FileName,
                algorithmCode = record.AlgorithmCode,
                signatureValid = true
            }, statusCode: StatusCodes.Status202Accepted);
        }

        // Formato anterior (v1 / NODO04): se atiende con la bandeja y la cadena de 3 nodos.
        return await NodeApi.ReceiveRawAsync(bytes, fileName, legacyReception, settings, state, processing, loggers, ct);
    }

    private static async Task<IResult> CryptoAsync(string operation, HttpRequest http, V2NodeService node, CancellationToken ct)
    {
        if (!http.HasFormContentType)
        {
            throw new V2ProtocolException("E-UNSUPPORTED-MEDIA", "Se espera multipart/form-data.");
        }

        var form = await http.ReadFormAsync(ct);
        async Task<byte[]?> Part(string name)
        {
            var file = form.Files.GetFile(name);
            if (file is not null)
            {
                return await ReadAsync(file, ct);
            }

            return form.TryGetValue(name, out var text) && text.Count > 0 ? Encoding.UTF8.GetBytes(text.ToString()) : null;
        }

        var signature = await Part("requestSignature");
        var certificate = await Part("requesterCertificate");
        var parts = new V2CryptoRequestParts
        {
            Request = await Part("request"),
            RequestSignature = signature is null ? null : Encoding.UTF8.GetString(signature),
            RequesterCertificate = certificate is null ? null : Encoding.UTF8.GetString(certificate),
            Payload = await Part("payload"),
            Cover = await Part("cover"),
            Package = await Part("package")
        };
        var package = await node.ProvideAsync(operation, parts, ct);
        return Results.File(package.ZipBytes, "application/zip", package.FileName);
    }

    private static void MapUi(RouteGroupBuilder ui)
    {
        ui.MapGet("/overview", (V2NodeService node, NodeRuntimeState legacy, DiscoveryService discovery) =>
        {
            var directory = node.Directory.List();
            return Results.Ok(new
            {
                nodeId = node.Identity.NodeId,
                teamNumber = node.Identity.TeamNumber,
                ip = node.Identity.Ip,
                httpPort = node.Identity.HttpPort,
                thumbprint = node.Identity.Thumbprint,
                provided = node.Providers.Select(p => p.Algorithm.Code),
                mode = node.Mode,
                lastScanUtc = discovery.LastScan.At,
                lastScanFound = discovery.LastScan.Found,
                legacyRole = legacy.Current.Role.ToString(),
                catalog = V2Catalog.All.Select(a =>
                {
                    var own = node.LocalProvider(a.Code) is not null;
                    var owner = a.OwnerNode is null ? null : directory.FirstOrDefault(d => d.NodeId == a.OwnerNode);
                    var alternative = directory.Where(d => d.Algorithms.Contains(a.Code) && d.ProtocolVersion == V2Format.Version)
                        .OrderBy(d => d.TeamNumber).FirstOrDefault();
                    var provider = own ? null : owner ?? alternative;
                    string availability = own
                        ? "local"
                        : provider is null ? "sin-nodo"
                        : provider.ThumbprintChanged ? "huella-cambio"
                        : provider.PinnedThumbprintSha256 is null ? "sin-confirmar"
                        : provider.Status == "online" ? "disponible" : "fuera-de-linea";
                    return new
                    {
                        a.Id,
                        a.Code,
                        a.Name,
                        a.Category,
                        a.Team,
                        owner = a.OwnerNode,
                        a.ForwardName,
                        a.InverseName,
                        a.KeyType,
                        local = own,
                        provider = own ? node.Identity.NodeId : provider?.NodeId,
                        availability
                    };
                })
            });
        });

        ui.MapGet("/profiles/{nodeId}", async (string nodeId, V2NodeService node, IHttpClientFactory factory, CancellationToken ct) =>
        {
            if (nodeId == node.Identity.NodeId)
            {
                return Results.Text(node.AlgorithmsProfile().ToJsonString(), "application/json");
            }

            var entry = node.Directory.Get(nodeId) ?? throw new V2ProtocolException("E-REQUEST", $"{nodeId} no está en el directorio.");
            var client = factory.CreateClient("peers");
            var text = await client.GetStringAsync(entry.BaseUrl + "/api/algorithms", ct);
            return Results.Text(text, "application/json");
        });

        ui.MapGet("/directory", (V2NodeService node) => Results.Ok(node.Directory.List().Select(Entry)));

        ui.MapPost("/directory/manual", async (HttpRequest http, V2NodeService node, CancellationToken ct) =>
        {
            var body = await http.ReadFromJsonAsync<JsonElement>(ct);
            var ip = body.GetProperty("ip").GetString()?.Trim() ?? string.Empty;
            var port = body.TryGetProperty("port", out var p) && p.TryGetInt32(out var n) ? n : 5000;
            var entry = await node.ProbeAsync(ip, port, "manual", TimeSpan.FromSeconds(5), ct)
                        ?? throw new V2ProtocolException("E-REQUEST", $"No respondió ningún nodo en {ip}:{port} (/api/status).");
            return Results.Ok(Entry(entry));
        });

        ui.MapPost("/directory/scan", async (DiscoveryService discovery, CancellationToken ct) =>
        {
            var result = await discovery.ScanAsync(ct)
                         ?? throw new V2ProtocolException("E-BUSY", "Ya hay un escaneo en curso (se hace solo cada 30 s).");
            return Results.Ok(new { scanned = result.Scanned, found = result.Found.Select(Entry) });
        });

        ui.MapGet("/mode", (V2NodeService node) => Results.Ok(new { mode = node.Mode }));
        ui.MapPut("/mode", async (HttpRequest http, V2NodeService node) =>
        {
            var body = await System.Text.Json.JsonSerializer.DeserializeAsync<Dictionary<string, string>>(http.Body) ?? new();
            node.SetMode(body.GetValueOrDefault("mode") ?? string.Empty);
            return Results.Ok(new { mode = node.Mode });
        });

        ui.MapGet("/directory/{nodeId}/inspect", async (string nodeId, V2NodeService node, CancellationToken ct) =>
        {
            var (entry, thumbprint, subject) = await node.InspectAsync(nodeId, ct);
            return Results.Ok(new { node = Entry(entry), thumbprint, subject, changed = entry.PinnedThumbprintSha256 is not null && entry.PinnedThumbprintSha256 != thumbprint });
        });

        ui.MapPost("/directory/{nodeId}/pin", async (string nodeId, HttpRequest http, V2NodeService node, CancellationToken ct) =>
        {
            var body = await http.ReadFromJsonAsync<JsonElement>(ct);
            var thumbprint = body.GetProperty("thumbprint").GetString() ?? string.Empty;
            var (_, actual, _) = await node.InspectAsync(nodeId, ct);
            if (actual != thumbprint)
            {
                throw new V2ProtocolException("E-CERT-THUMBPRINT", "La huella cambió mientras la revisabas; vuelve a inspeccionar.");
            }

            return Results.Ok(Entry(node.Directory.Pin(nodeId, thumbprint)));
        });

        ui.MapDelete("/directory/{nodeId}", (string nodeId, V2NodeService node) =>
        {
            node.Directory.Remove(nodeId);
            return Results.NoContent();
        });

        ui.MapPost("/announce", (DiscoveryService discovery) =>
        {
            discovery.AnnounceNow();
            return Results.Ok(new { sent = true });
        });

        ui.MapPost("/forward", async (HttpRequest http, V2NodeService node, CancellationToken ct) =>
        {
            var form = await http.ReadFormAsync(ct);
            var code = form["algorithmCode"].ToString();
            byte[] payload;
            string fileName;
            string mode;
            var file = form.Files.GetFile("payload");
            if (file is not null)
            {
                payload = await ReadAsync(file, ct);
                fileName = Path.GetFileName(file.FileName);
                mode = file.ContentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) ? "image" : "file";
            }
            else
            {
                payload = Encoding.UTF8.GetBytes(form["text"].ToString());
                fileName = "mensaje.txt";
                mode = "text";
            }

            if (payload.Length == 0)
            {
                throw new V2ProtocolException("E-REQUEST", "Escribe un texto o elige un archivo.");
            }

            var coverFile = form.Files.GetFile("cover");
            var cover = coverFile is null ? null : await ReadAsync(coverFile, ct);
            if (cover is null && code == "LSBSTEGO" && form["autoCover"] == "true")
            {
                cover = Infrastructure.ProtocolV2.Providers.LsbV2Provider.DefaultCoverFor(payload.Length);
            }

            var provider = form["provider"].ToString();
            var result = await node.ForwardAsync(
                code,
                payload,
                fileName,
                mode,
                cover,
                Dict(form["options"]),
                Dict(form["secrets"]),
                string.IsNullOrWhiteSpace(provider) ? null : provider,
                ct);
            return Results.Ok(Operation(result));
        });

        ui.MapGet("/solicitudes", (V2NodeService node) => Results.Ok(node.Store.List("solicitud")));
        ui.MapPost("/solicitudes/{id}/accept", (string id, V2NodeService node) => Results.Ok(node.Accept(id)));
        ui.MapPost("/solicitudes/{id}/reject", (string id, V2NodeService node) => Results.Ok(node.Reject(id)));

        ui.MapGet("/consultas", (V2NodeService node) => Results.Ok(node.Store.List("consulta")));
        ui.MapGet("/packets/{id}/zip", (string id, V2NodeService node) =>
            Results.File(node.Store.ZipBytes(id), "application/zip", node.Store.Get(id).FileName));
        ui.MapGet("/packets/{id}/manifest", (string id, V2NodeService node) =>
            Results.Text(node.Store.Manifest(id).ToJsonString(new JsonSerializerOptions { WriteIndented = true }), "application/json"));
        ui.MapGet("/packets/{id}/recovered", (string id, V2NodeService node) =>
        {
            var path = node.Store.RecoveredPath(id) ?? throw new V2ProtocolException("E-REQUEST", "Ese registro no tiene archivo recuperado.");
            return Results.File(path, V2NodeService.Mime(path), node.Store.Get(id).RecoveredFileName);
        });
        ui.MapGet("/packets/{id}/data", (string id, V2NodeService node) =>
        {
            var package = node.Load(id, validate: false);
            var name = package.PacketType == "result" ? "resultado.enc" : "datos.enc";
            var mime = package.Str("payloadMode") == "image" && package.AlgorithmCode == "LSBSTEGO"
                ? (package.PublicParameters.GetValueOrDefault("imageFormat") == "BMP" ? "image/bmp" : "image/png")
                : "application/octet-stream";
            return Results.File(package.Data, mime, mime.StartsWith("image/", StringComparison.Ordinal) ? $"estego.{(mime == "image/bmp" ? "bmp" : "png")}" : name);
        });

        ui.MapPost("/consultas/{id}/inverse", async (string id, HttpRequest http, V2NodeService node, CancellationToken ct) =>
        {
            var body = await http.ReadFromJsonAsync<JsonElement>(ct);
            var secrets = body.TryGetProperty("secrets", out var s) ? Dict(s.GetRawText()) : new Dictionary<string, string>();
            var provider = body.TryGetProperty("provider", out var p) ? p.GetString() : null;
            var result = await node.InverseAsync(id, secrets, string.IsNullOrWhiteSpace(provider) ? null : provider, ct);
            return Results.Ok(Operation(result));
        });

        ui.MapPost("/consultas/{id}/send", async (string id, HttpRequest http, V2NodeService node, CancellationToken ct) =>
        {
            var body = await http.ReadFromJsonAsync<JsonElement>(ct);
            var target = body.GetProperty("target").GetString() ?? throw new V2ProtocolException("E-REQUEST", "Falta el destino.");
            var fileName = await node.SendAsync(id, target, ct);
            return Results.Ok(new { sent = true, fileName, target });
        });

        ui.MapPost("/consultas/import", async (HttpRequest http, V2NodeService node, CancellationToken ct) =>
        {
            var form = await http.ReadFormAsync(ct);
            var file = form.Files.FirstOrDefault() ?? throw new V2ProtocolException("E-REQUEST", "Elige un .zip.");
            var package = V2PackageCodec.Validate(await ReadAsync(file, ct));
            return Results.Ok(node.Store.Add(package, "consulta", package.PacketType == "result" ? "Resultado" : "Recibido"));
        });
    }

    private static object Entry(DirectoryEntry e) => new
    {
        e.NodeId,
        e.TeamNumber,
        e.Ip,
        e.HttpPort,
        e.HttpsPort,
        e.PinnedThumbprintSha256,
        e.SeenThumbprintSha256,
        e.Algorithms,
        e.Source,
        e.Status,
        e.LastSeenUtc,
        e.ProtocolVersion,
        e.Trusted,
        e.ThumbprintChanged,
        baseUrl = e.BaseUrl
    };

    private static object Operation(V2OperationResult result)
    {
        string? preview = null;
        if (result.Recovered is { Length: > 0 and < 20000 } bytes && LooksLikeText(bytes))
        {
            preview = Encoding.UTF8.GetString(bytes);
        }

        return new
        {
            record = result.Record,
            fileName = result.Package.FileName,
            packetId = result.Package.PacketId,
            packetType = result.Package.PacketType,
            provider = result.Provider,
            delegated = result.Delegated,
            publicParameters = result.Package.PublicParameters,
            encryptedSha256 = result.Package.Str("encryptedSha256"),
            recoveredBytes = result.Recovered?.Length,
            preview,
            verification = result.Verification?.ToJsonString()
        };
    }

    private static bool LooksLikeText(byte[] bytes)
    {
        var sample = bytes.AsSpan(0, Math.Min(bytes.Length, 2000));
        foreach (var b in sample)
        {
            if (b < 9 || (b > 13 && b < 32))
            {
                return false;
            }
        }

        return true;
    }

    private static Dictionary<string, string> Dict(string? json)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(json))
        {
            return result;
        }

        try
        {
            if (JsonNode.Parse(json) is JsonObject obj)
            {
                foreach (var pair in obj)
                {
                    var value = pair.Value is JsonValue v && v.TryGetValue<string>(out var s) ? s : pair.Value?.ToJsonString();
                    if (!string.IsNullOrEmpty(value))
                    {
                        result[pair.Key] = value;
                    }
                }
            }
        }
        catch (JsonException)
        {
            throw new V2ProtocolException("E-PARAMS", "Las opciones o secretos no son JSON válido.");
        }

        return result;
    }

    private static async Task<byte[]> ReadAsync(IFormFile file, CancellationToken ct)
    {
        await using var stream = file.OpenReadStream();
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, ct);
        return buffer.ToArray();
    }
}
