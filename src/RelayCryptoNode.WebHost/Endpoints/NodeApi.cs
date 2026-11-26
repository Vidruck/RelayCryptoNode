using System.Text.Json;
using RelayCryptoNode.Application.Abstractions;
using RelayCryptoNode.Application.Configuration;
using RelayCryptoNode.Application.Services;
using RelayCryptoNode.Application.UseCases;
using RelayCryptoNode.Domain.Catalog;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Inbound;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Persistence;
using RelayCryptoNode.Infrastructure.Realtime;
using RelayCryptoNode.WebHost.Hosting;

namespace RelayCryptoNode.WebHost.Endpoints;

/// <summary>
/// Endpoints REST del nodo: estado, certificado, recepción, bandeja, emisión, configuración y bitácora.
/// </summary>
public static class NodeApi
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    /// <summary>Endpoints del modo v1 (cadena de 3 nodos) bajo /api/v1.</summary>
    public static void MapNodeApi(this WebApplication app)
    {
        var api = app.MapGroup("/api/v1");

        api.MapPost("/requests/receive", ReceiveAsync);

        api.MapGet("/requests", async (string? status, IManageIncomingRequestsUseCase inbox, CancellationToken ct) =>
        {
            RequestStatus? filter = Enum.TryParse<RequestStatus>(status, true, out var parsed) ? parsed : null;
            var list = await inbox.GetRequestsAsync(filter, ct);
            return Results.Ok(list.Select(ApiModels.Request));
        });

        api.MapGet("/requests/{id:guid}", async (Guid id, ManageIncomingRequestsUseCase inbox, CancellationToken ct) =>
            Results.Ok(ApiModels.Request(await inbox.GetRequiredAsync(id, ct))));

        api.MapGet("/requests/{id:guid}/package", async (Guid id, ManageIncomingRequestsUseCase inbox, FileRequestRepository repository, IPackageSerializerPort serializer, CancellationToken ct) =>
        {
            var request = await inbox.GetRequiredAsync(id, ct);
            var path = repository.PackagePath(id);
            return File.Exists(path)
                ? Results.File(path, "application/zip", serializer.BuildStandardPackageFileName(request.Envelope))
                : Results.NotFound(new { error = "No se encontró el paquete guardado." });
        });

        api.MapPost("/requests/{id:guid}/accept", async (Guid id, RequestProcessingService processing, CancellationToken ct) =>
        {
            var result = await processing.AcceptAndProcessAsync(id, ct);
            return Results.Ok(ProcessingBody(result));
        });

        api.MapPost("/requests/{id:guid}/retry", async (Guid id, ManageIncomingRequestsUseCase inbox, RequestProcessingService processing, CancellationToken ct) =>
        {
            var request = await inbox.GetRequiredAsync(id, ct);
            if (request.Status != RequestStatus.Accepted)
            {
                throw new DomainException("Solo se puede reintentar una solicitud aceptada.", "REQUEST_INVALID_TRANSITION");
            }

            return Results.Ok(ProcessingBody(await processing.ProcessAcceptedAsync(id, ct)));
        });

        api.MapPost("/requests/{id:guid}/reject", async (Guid id, HttpRequest http, IManageIncomingRequestsUseCase inbox, CancellationToken ct) =>
        {
            var reason = "Rechazada por el operador.";
            if (http.HasJsonContentType())
            {
                var body = await http.ReadFromJsonAsync<JsonElement>(ct);
                if (body.ValueKind == JsonValueKind.Object && body.TryGetProperty("reason", out var r) && r.GetString() is { Length: > 0 } text)
                {
                    reason = text;
                }
            }

            var request = await inbox.RejectRequestAsync(id, reason, ct);
            return Results.Ok(ApiModels.Request(request));
        });

        api.MapGet("/audits/{packetId:guid}", async (Guid packetId, IEvidenceStoragePort evidence, CancellationToken ct) =>
        {
            var report = await evidence.GetAuditReportByPacketIdAsync(packetId, ct);
            return report is null ? Results.NotFound(new { error = "No hay auditoría para ese paquete." }) : Results.Ok(ApiModels.Audit(report));
        });

        api.MapGet("/evidence/{packetId:guid}/{fileName}", (Guid packetId, string fileName, FileSystemEvidenceStorage evidence) =>
        {
            var path = evidence.RecoveredFilePath(packetId, fileName);
            return path is null
                ? Results.NotFound(new { error = "No existe ese archivo recuperado." })
                : Results.File(path, "application/octet-stream", Path.GetFileName(path));
        });

        api.MapPost("/emit", EmitAsync);

        api.MapGet("/algorithms", (EnvelopeCryptoService crypto) =>
            Results.Ok(OfficialAlgorithmCatalog.GetAll()
                .Where(d => d.CipherAlgorithm is not null && crypto.SupportsCipher(d.CipherAlgorithm.Value))
                .Select(d => new
                {
                    code = d.OfficialCode,
                    name = d.DisplayName,
                    category = d.Category.ToString(),
                    sharedKeyMode = crypto.SupportsSharedKeyMode(d.CipherAlgorithm!.Value)
                })));

        api.MapGet("/catalog", () => Results.Ok(OfficialAlgorithmCatalog.GetAll().Select(d => new
        {
            code = d.OfficialCode,
            name = d.DisplayName,
            category = d.Category.ToString(),
            cipher = d.CipherAlgorithm?.ToString(),
            keyExchange = d.KeyExchangeAlgorithm?.ToString(),
            signature = d.SignatureAlgorithm?.ToString(),
            hash = d.HashAlgorithm?.ToString()
        })));

        api.MapGet("/config", (NodeRuntimeState state) => Results.Ok(ConfigBody(state)));

        api.MapPut("/config", async (HttpRequest http, NodeRuntimeState state, CancellationToken ct) =>
        {
            var body = await http.ReadFromJsonAsync<JsonElement>(ct);
            var current = state.Current;
            var updated = current with
            {
                Role = Enum.TryParse<NodeRole>(Get(body, "role"), true, out var role) ? role : current.Role,
                NextNodeEndpoint = body.TryGetProperty("nextNodeEndpoint", out _)
                    ? NormalizeOptionalEndpoint(Get(body, "nextNodeEndpoint"))
                    : current.NextNodeEndpoint,
                OutgoingAlgorithmCode = Get(body, "outgoingAlgorithmCode") ?? current.OutgoingAlgorithmCode,
                KeyExchange = Enum.TryParse<KeyExchangeAlgorithmType>(Get(body, "keyExchange"), true, out var kx) ? kx : current.KeyExchange,
                AutoProcess = body.TryGetProperty("autoProcess", out var auto) && auto.ValueKind is JsonValueKind.True or JsonValueKind.False
                    ? auto.GetBoolean()
                    : current.AutoProcess,
                SharedKeyFormat = body.TryGetProperty("sharedKeyFormat", out var shared) && shared.ValueKind is JsonValueKind.True or JsonValueKind.False
                    ? shared.GetBoolean()
                    : current.SharedKeyFormat
            };

            if (Get(body, "sharedAesKey") is { } aesKey)
            {
                state.SharedAesKey = aesKey;
            }

            if (body.TryGetProperty("preSharedKey", out var psk) && psk.ValueKind == JsonValueKind.String)
            {
                state.SetPreSharedKey(psk.GetString());
            }

            state.Update(updated);
            return Results.Ok(ConfigBody(state));
        });

        api.MapGet("/peer/status", async (string url, IHttpClientFactory factory, CancellationToken ct) =>
        {
            var endpoint = RemoteNodeResolver.NormalizeEndpoint(url);
            var client = factory.CreateClient("peers");
            try
            {
                using var response = await client.GetAsync(endpoint + "/api/status", ct);
                var text = await response.Content.ReadAsStringAsync(ct);
                return Results.Ok(new { endpoint, reachable = response.IsSuccessStatusCode, httpStatus = (int)response.StatusCode, body = text });
            }
            catch (HttpRequestException ex)
            {
                return Results.Ok(new { endpoint, reachable = false, httpStatus = 0, body = ex.Message });
            }
            catch (TaskCanceledException)
            {
                return Results.Ok(new { endpoint, reachable = false, httpStatus = 0, body = "Tiempo de espera agotado." });
            }
        });

        api.MapGet("/events", (int? max, InMemoryEventHub hub) => Results.Ok(hub.Recent(max ?? 100)));

        api.MapGet("/events/stream", async (HttpContext context, InMemoryEventHub hub) =>
        {
            context.Response.Headers.ContentType = "text/event-stream";
            context.Response.Headers.CacheControl = "no-cache";
            using var subscription = hub.Subscribe();
            var token = context.RequestAborted;
            await context.Response.WriteAsync(": conectado\n\n", token);
            await context.Response.Body.FlushAsync(token);
            try
            {
                while (!token.IsCancellationRequested)
                {
                    using var heartbeat = CancellationTokenSource.CreateLinkedTokenSource(token);
                    heartbeat.CancelAfter(TimeSpan.FromSeconds(20));
                    try
                    {
                        var item = await subscription.Reader.ReadAsync(heartbeat.Token);
                        var json = JsonSerializer.Serialize(item, WebJson);
                        await context.Response.WriteAsync($"data: {json}\n\n", token);
                    }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested)
                    {
                        await context.Response.WriteAsync(": ping\n\n", token);
                    }

                    await context.Response.Body.FlushAsync(token);
                }
            }
            catch (OperationCanceledException)
            {
                // El navegador cerró la conexión.
            }
        });
    }

    /// <summary>Recepción en formato v1 (NODO04 / contrato anterior) desde la ruta /api/v1.</summary>
    public static async Task<IResult> ReceiveAsync(
        HttpRequest http,
        IncomingPackageService reception,
        NodeSettingsStore settings,
        NodeRuntimeState state,
        RequestProcessingService processing,
        ILoggerFactory loggers,
        CancellationToken ct)
    {
        byte[] bytes;
        string? fileName = null;
        if (http.HasFormContentType)
        {
            var form = await http.ReadFormAsync(ct);
            var file = form.Files.GetFile("package") ?? form.Files.FirstOrDefault();
            if (file is null)
            {
                return Results.BadRequest(new { error = "Se requiere multipart/form-data con campo 'package'." });
            }

            fileName = file.FileName;
            await using var stream = file.OpenReadStream();
            using var buffer = new MemoryStream();
            await stream.CopyToAsync(buffer, ct);
            bytes = buffer.ToArray();
        }
        else
        {
            using var buffer = new MemoryStream();
            await http.Body.CopyToAsync(buffer, ct);
            bytes = buffer.ToArray();
        }

        return await ReceiveRawAsync(bytes, fileName, reception, settings, state, processing, loggers, ct);
    }

    /// <summary>Procesa un .zip en formato v1 ya leído.</summary>
    public static async Task<IResult> ReceiveRawAsync(
        byte[] bytes,
        string? fileName,
        IncomingPackageService reception,
        NodeSettingsStore settings,
        NodeRuntimeState state,
        RequestProcessingService processing,
        ILoggerFactory loggers,
        CancellationToken ct)
    {
        if (bytes.LongLength > settings.MaxPackageBytes)
        {
            return Results.Json(new { error = $"El paquete ZIP supera el límite de {settings.MaxPackageBytes / 1024 / 1024} MB." }, statusCode: StatusCodes.Status413PayloadTooLarge);
        }

        var result = await reception.ReceiveAsync(bytes, ct);
        switch (result.Outcome)
        {
            case ReceptionOutcome.Malformed:
                return Results.BadRequest(new { error = result.Message });
            case ReceptionOutcome.Unprocessable:
                return Results.UnprocessableEntity(new { error = result.Message });
        }

        var request = result.Request!;
        var current = state.Current;
        if (current.AutoProcess && request.SignatureValid && request.IntegrityValid)
        {
            var logger = loggers.CreateLogger("AutoProcess");
            _ = Task.Run(async () =>
            {
                try
                {
                    await processing.AcceptAndProcessAsync(request.RequestId, CancellationToken.None);
                }
                catch (Exception ex) when (ex is DomainException or HttpRequestException)
                {
                    logger.LogWarning("No se pudo procesar automáticamente {Id}: {Message}", request.RequestId, ex.Message);
                }
            }, CancellationToken.None);
        }

        var code = OfficialAlgorithmCatalog.TryFromCipherAlgorithm(request.Envelope.CipherAlgorithm, out var official)
            ? official.ToString()
            : request.Envelope.CipherAlgorithm.ToString();
        return Results.Accepted($"/api/requests/{request.RequestId}", new
        {
            requestId = request.RequestId,
            status = "Pendiente",
            zipFileName = fileName,
            algorithmCode = code,
            signatureValid = request.SignatureValid,
            message = result.Message
        });
    }

    private static async Task<IResult> EmitAsync(
        HttpRequest http,
        NodeRuntimeState state,
        PayloadBundleFactory bundles,
        RemoteNodeResolver resolver,
        IEmitInitialPackageUseCase emit,
        CancellationToken ct)
    {
        if (!http.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Envíe el formulario como multipart/form-data." });
        }

        var form = await http.ReadFormAsync(ct);
        var inputs = new List<PayloadFileInput>();
        foreach (var file in form.Files)
        {
            await using var stream = file.OpenReadStream();
            using var buffer = new MemoryStream();
            await stream.CopyToAsync(buffer, ct);
            inputs.Add(new PayloadFileInput(file.FileName, file.ContentType, buffer.ToArray()));
        }

        var text = form["text"].ToString();
        if (!string.IsNullOrEmpty(text))
        {
            var name = form["textFileName"].ToString();
            inputs.Add(new PayloadFileInput(
                string.IsNullOrWhiteSpace(name) ? "mensaje.txt" : name,
                "text/plain; charset=utf-8",
                System.Text.Encoding.UTF8.GetBytes(text)));
        }

        var current = state.Current;
        var destination = form["destination"].ToString();
        if (string.IsNullOrWhiteSpace(destination))
        {
            destination = current.NextNodeEndpoint ?? string.Empty;
        }

        var algorithm = form["algorithm"].ToString();
        if (string.IsNullOrWhiteSpace(algorithm))
        {
            algorithm = current.OutgoingAlgorithmCode;
        }

        var keyMode = form["keyExchange"].ToString();
        var sharedKey = string.Equals(keyMode, "SharedKey", StringComparison.OrdinalIgnoreCase);
        var keyExchange = sharedKey
            ? KeyExchangeAlgorithmType.PreSharedKey
            : Enum.TryParse<KeyExchangeAlgorithmType>(keyMode, true, out var kx) ? kx : current.KeyExchange;

        var bundle = bundles.Create(inputs);
        var resolved = await resolver.ResolveAsync(destination, sharedKey ? KeyExchangeAlgorithmType.PreSharedKey : keyExchange, cancellationToken: ct);
        var command = new EmitInitialPackageCommand(
            bundle,
            resolved.Identity,
            EnvelopeCryptoService.ResolveCipherFromCode(algorithm),
            keyExchange,
            SignatureAlgorithmType.RsaPssSha256,
            resolved.CertificatePem,
            sharedKey ? new Dictionary<string, string> { [LegacyFormat.MetadataKey] = LegacyFormat.SharedKeyValue } : null);

        var result = await emit.ExecuteAsync(command, ct);
        return Results.Ok(new
        {
            delivered = result.Delivered,
            packageFileName = result.PackageFileName,
            packetId = result.Envelope.PacketId,
            destination = resolved.Identity.EndpointAddress,
            destinationNode = resolved.Identity.NodeId,
            algorithm = result.Envelope.CipherAlgorithm.ToString(),
            keyExchange = sharedKey ? "SharedKey" : result.Envelope.KeyExchangeAlgorithm.ToString(),
            originalSha256 = result.Envelope.OriginalPayloadSha256.HexHash,
            encryptedSha256 = result.Envelope.EncryptedSha256.HexHash,
            remoteResponse = result.RemoteStatusMessage
        });
    }

    private static object ProcessingBody(RequestProcessingResult result) => new
    {
        requestId = result.RequestId,
        action = result.Action,
        success = result.Success,
        message = result.Message,
        relay = result.Relay is null
            ? null
            : new
            {
                incomingAlgorithm = result.Relay.IncomingAlgorithm.ToString(),
                outgoingAlgorithm = result.Relay.OutgoingEnvelope.CipherAlgorithm.ToString(),
                packageFileName = result.Relay.OutgoingPackageFileName,
                delivered = result.Relay.Delivered
            },
        audit = result.Audit is null
            ? null
            : new
            {
                report = ApiModels.Audit(result.Audit.AuditReport),
                files = result.Audit.RecoveredBundle.Items.Select(i => new { fileName = i.FileName, sizeBytes = i.SizeBytes, mimeType = i.MimeType })
            }
    };

    private static object ConfigBody(NodeRuntimeState state)
    {
        var current = state.Current;
        return new
        {
            nodeId = current.NodeId,
            publicEndpoint = current.PublicEndpoint,
            role = current.Role.ToString(),
            nextNodeEndpoint = current.NextNodeEndpoint,
            outgoingAlgorithmCode = current.OutgoingAlgorithmCode,
            keyExchange = current.KeyExchange.ToString(),
            autoProcess = current.AutoProcess,
            sharedKeyFormat = current.SharedKeyFormat,
            hasPreSharedKey = state.HasPreSharedKey,
            sharedAesKey = state.SharedAesKey
        };
    }

    private static string? Get(JsonElement body, string name) =>
        body.ValueKind == JsonValueKind.Object && body.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? NormalizeOptionalEndpoint(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : RemoteNodeResolver.NormalizeEndpoint(value);
}
