using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using RelayCryptoNode.Application.Abstractions;
using RelayCryptoNode.Application.Services;
using RelayCryptoNode.Application.UseCases;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Inbound;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms;
using RelayCryptoNode.Infrastructure.Algorithms.Asymmetric;
using RelayCryptoNode.Infrastructure.Algorithms.Integrity;
using RelayCryptoNode.Infrastructure.Certificates;
using RelayCryptoNode.Infrastructure.KeyExchange;
using RelayCryptoNode.Infrastructure.Packaging;
using RelayCryptoNode.Infrastructure.Persistence;
using RelayCryptoNode.Infrastructure.ProtocolV2;
using RelayCryptoNode.Infrastructure.ProtocolV2.Providers;
using RelayCryptoNode.Infrastructure.Realtime;
using RelayCryptoNode.Infrastructure.Transport;
using RelayCryptoNode.WebHost.Endpoints;
using RelayCryptoNode.WebHost.Hosting;

var builder = WebApplication.CreateBuilder(args);

var (settings, state) = NodeSettingsStore.Load(builder.Configuration, builder.Environment.ContentRootPath);

// Puertos: 5000 + número de equipo (v2.0) y, si está libre, el 5000 para nodos con el formato anterior.
var urls = new List<string> { $"http://0.0.0.0:{settings.HttpPort}" };
if (settings.LegacyPort > 0 && settings.LegacyPort != settings.HttpPort && PortIsFree(settings.LegacyPort))
{
    urls.Add($"http://0.0.0.0:{settings.LegacyPort}");
}

builder.WebHost.UseUrls(builder.Configuration["Node:Urls"] is { Length: > 0 } explicitUrls ? explicitUrls.Split(';') : urls.ToArray());
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = V2Format.MaxBodyBytes + (2 * 1024 * 1024));
builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = V2Format.MaxBodyBytes + (2 * 1024 * 1024));

var certificates = new LocalCertificateService(
    Path.Combine(settings.DataDirectory, "certificados"),
    state.Current.NodeId,
    builder.Configuration["Node:KeyPassword"]);
var identity = new V2Identity(settings.TeamNumber, certificates, settings.HttpPort) { Ip = NodeSettingsStore.DetectLanAddress() };
var registry = new AlgorithmModuleRegistry();
var serializer = new ZipPackageSerializer();

// Algoritmos que este nodo provee en v2.0: los de su equipo en la tabla 4.1 (o los indicados en Node:ProvidedAlgorithms).
IV2AlgorithmProvider[] implemented = [new LsbV2Provider(), new AffineV2Provider()];
var configured = builder.Configuration.GetSection("Node:ProvidedAlgorithms").Get<string[]>();
var provided = implemented
    .Where(p => configured is { Length: > 0 } ? configured.Contains(p.Algorithm.Code) : p.Algorithm.Team == settings.TeamNumber)
    .ToArray();

builder.Services.AddSingleton(settings);
builder.Services.AddSingleton(state);
builder.Services.AddSingleton(registry);
builder.Services.AddSingleton(identity);
builder.Services.AddSingleton<ICertificateServicePort>(certificates);
builder.Services.AddSingleton<IPackageSerializerPort>(serializer);
builder.Services.AddSingleton<IHashingServicePort, HashShaModule>();
builder.Services.AddSingleton<InMemoryEventHub>();
builder.Services.AddSingleton<IRealtimeNotifierPort>(sp => sp.GetRequiredService<InMemoryEventHub>());
builder.Services.AddSingleton(sp => new FileRequestRepository(Path.Combine(settings.DataDirectory, "bandeja"), serializer));
builder.Services.AddSingleton<IRequestRepositoryPort>(sp => sp.GetRequiredService<FileRequestRepository>());
builder.Services.AddSingleton(new FileSystemEvidenceStorage(Path.Combine(settings.DataDirectory, "evidencia")));
builder.Services.AddSingleton<IEvidenceStoragePort>(sp => sp.GetRequiredService<FileSystemEvidenceStorage>());

// Estándar v2.0
builder.Services.AddSingleton(new NodeDirectory(Path.Combine(settings.DataDirectory, "directorio-nodos.json")));
builder.Services.AddSingleton(new ReplayGuard(Path.Combine(settings.DataDirectory, "ids-vistos.txt")));
builder.Services.AddSingleton(new PacketStore(Path.Combine(settings.DataDirectory, "v2")));
builder.Services.AddHttpClient("v2", client => client.Timeout = TimeSpan.FromSeconds(75));
builder.Services.AddSingleton(sp =>
{
    var service = new V2NodeService(
        identity,
        provided,
        sp.GetRequiredService<NodeDirectory>(),
        sp.GetRequiredService<ReplayGuard>(),
        sp.GetRequiredService<PacketStore>(),
        sp.GetRequiredService<IHttpClientFactory>().CreateClient("v2"),
        sp.GetRequiredService<IRealtimeNotifierPort>());

    // Modo v3: los 21 algoritmos se pueden cifrar y descifrar en este nodo.
    service.EnableV3(implemented.Concat(V3LocalProviders.Create(identity, settings.DataDirectory)),
        Path.Combine(settings.DataDirectory, "modo-protocolo.txt"));
    service.LoadReception(Path.Combine(settings.DataDirectory, "requestid-obligatorio.txt"));
    service.LoadRefused(Path.Combine(settings.DataDirectory, "rechazados.json"));
    return service;
});
builder.Services.AddSingleton(sp => new DiscoveryService(sp.GetRequiredService<V2NodeService>(), sp.GetRequiredService<ILogger<DiscoveryService>>())
{
    ExtraHosts = (builder.Configuration["Node:ScanHosts"] ?? string.Empty)
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
});
builder.Services.AddHostedService(sp => sp.GetRequiredService<DiscoveryService>());

// Formato anterior (v1): los 15 módulos de cifrado y la cadena Initial → Intermediate → Final.
foreach (var code in Enum.GetValues<RelayCryptoNode.Domain.Enums.OfficialAlgorithmCode>())
{
    var descriptor = RelayCryptoNode.Domain.Catalog.OfficialAlgorithmCatalog.GetByCode(code);
    if (descriptor.CipherAlgorithm is { } cipher)
    {
        builder.Services.AddSingleton(registry.ResolveCipherStrategy(cipher));
    }
}

builder.Services.AddSingleton<IAsymmetricKeyWrapperPort>(new RsaModule(certificates.GetLocalPrivateKeyPem()));
builder.Services.AddSingleton<IAsymmetricKeyWrapperPort>(new PreSharedKeyWrapper(state.GetPreSharedKey));
builder.Services.AddSingleton<ILegacyPayloadCodec>(new SharedKeyLegacyCodec(() => state.SharedAesKey));

builder.Services.AddHttpClient("peers", client => client.Timeout = TimeSpan.FromSeconds(8));
builder.Services.AddHttpClient<INodeTransportSenderPort, HttpNodeTransportSender>(client => client.Timeout = TimeSpan.FromSeconds(60));

builder.Services.AddSingleton<PayloadBundleFactory>();
builder.Services.AddSingleton<EnvelopeCryptoService>();
builder.Services.AddSingleton<ManageIncomingRequestsUseCase>();
builder.Services.AddSingleton<IManageIncomingRequestsUseCase>(sp => sp.GetRequiredService<ManageIncomingRequestsUseCase>());
builder.Services.AddTransient<RemoteNodeResolver>();
builder.Services.AddTransient<IEmitInitialPackageUseCase, EmitInitialPackageUseCase>();
builder.Services.AddTransient<IRelayAndReEncryptUseCase, RelayAndReEncryptUseCase>();
builder.Services.AddTransient<IReceiveAndAuditFinalUseCase, ReceiveAndAuditFinalUseCase>();
builder.Services.AddTransient<IncomingPackageService>();
builder.Services.AddTransient<RequestProcessingService>();

// Login del panel: dos superusuarios (Auth:Users en appsettings.json).
var authEnabled = builder.Configuration.GetValue("Auth:Enabled", true);
var panelUsers = new PanelUsers(builder.Configuration.GetSection("Auth:Users").Get<PanelUser[]>() ?? []);
builder.Services.AddSingleton(panelUsers);
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "rcn_sesion";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.ExpireTimeSpan = TimeSpan.FromHours(10);
        options.SlidingExpiration = true;
        options.LoginPath = "/login.html";
    });

var app = builder.Build();
var inbound = new InboundLog(settings.DataDirectory);

// Conexiones que llegan de otras máquinas (otros nodos): se guardan con ruta, IP y respuesta,
// para revisar después si un equipo de verdad mandó algo y qué se le contestó.
app.Use(async (context, next) =>
{
    var ip = context.Connection.RemoteIpAddress;
    var remote = ip is not null && !System.Net.IPAddress.IsLoopback(ip);
    var watch = System.Diagnostics.Stopwatch.StartNew();
    string? error = null;
    try
    {
        await next();
    }
    catch (Exception ex)
    {
        error = ex.GetType().Name + ": " + ex.Message;
        throw;
    }
    finally
    {
        var path = context.Request.Path.Value ?? "/";
        var panelAsset = path.StartsWith("/api/ui", StringComparison.OrdinalIgnoreCase)
                         || path.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase)
                         || path.StartsWith("/css/", StringComparison.OrdinalIgnoreCase)
                         || path.StartsWith("/js/", StringComparison.OrdinalIgnoreCase)
                         || path is "/" or "/index.html" or "/login.html" or "/favicon.ico";
        if (remote && !panelAsset)
        {
            inbound.Add(new InboundEntry(
                DateTimeOffset.UtcNow,
                ip!.MapToIPv4().ToString(),
                context.Request.Method,
                path + context.Request.QueryString,
                error is null ? context.Response.StatusCode : 500,
                context.Request.ContentLength,
                watch.ElapsedMilliseconds,
                context.Request.Headers["X-CC-Node-Id"].FirstOrDefault() ?? context.Request.Headers["X-CC-Source-Node"].FirstOrDefault(),
                error));
        }
    }
});

app.MapGet("/api/ui/entradas", () => Results.Ok(inbound.Recent()));

app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (V2ProtocolException ex) when (!context.Response.HasStarted)
    {
        // Sección 14: application/problem+json con código del Anexo B.
        context.Response.StatusCode = ex.Status;
        context.Response.ContentType = "application/problem+json";
        var problem = new JsonObject
        {
            ["type"] = $"https://centrociber.local/errors/{ex.Code}",
            ["title"] = ex.Title,
            ["status"] = ex.Status,
            ["code"] = ex.Code,
            ["detail"] = ex.Message,
            ["nodeId"] = identity.NodeId,
            ["requestId"] = context.Request.Headers["X-CC-Request-Id"].FirstOrDefault(),
            ["timestampUtc"] = V2Format.Timestamp(DateTimeOffset.UtcNow),
            ["error"] = ex.Message
        };
        await context.Response.WriteAsync(problem.ToJsonString());
    }
    catch (Exception ex) when (!context.Response.HasStarted && ex is DomainException or HttpRequestException or CryptographicException or BadHttpRequestException)
    {
        var (status, message) = ex switch
        {
            UnsupportedAlgorithmException => (StatusCodes.Status422UnprocessableEntity, ex.Message),
            InvalidCertificateException => (StatusCodes.Status422UnprocessableEntity, ex.Message),
            DecryptionFailedException => (StatusCodes.Status422UnprocessableEntity, ex.Message),
            DomainException { ErrorCode: RequestErrorCodes.NotFound } => (StatusCodes.Status404NotFound, ex.Message),
            DomainException { ErrorCode: "REQUEST_INVALID_TRANSITION" or "REQUEST_INVALID_SIGNATURE" or "REQUEST_INVALID_INTEGRITY" } => (StatusCodes.Status409Conflict, ex.Message),
            DomainException => (StatusCodes.Status400BadRequest, ex.Message),
            HttpRequestException => (StatusCodes.Status502BadGateway, $"No se pudo contactar al otro nodo: {ex.Message}"),
            BadHttpRequestException bad => (bad.StatusCode, ex.Message),
            _ => (StatusCodes.Status422UnprocessableEntity, ex.Message)
        };
        context.Response.StatusCode = status;
        await context.Response.WriteAsJsonAsync(new { error = message });
    }
});

app.UseAuthentication();
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value ?? "/";
    var isPanel = path is "/" or "/index.html"
                  || path.StartsWith("/api/ui", StringComparison.OrdinalIgnoreCase)
                  || path.StartsWith("/api/v1", StringComparison.OrdinalIgnoreCase);
    if (authEnabled && isPanel && context.User.Identity?.IsAuthenticated != true)
    {
        if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Inicia sesión en el panel." });
            return;
        }

        context.Response.Redirect("/login.html");
        return;
    }

    await next();
});

app.MapPost("/auth/login", async (HttpContext context, PanelUsers users) =>
{
    var body = await System.Text.Json.JsonSerializer.DeserializeAsync<Dictionary<string, string>>(context.Request.Body) ?? new();
    var user = users.Check(body.GetValueOrDefault("user"), body.GetValueOrDefault("password"));
    if (user is null)
    {
        await Task.Delay(600);
        return Results.Json(new { error = "Usuario o contraseña incorrectos." }, statusCode: StatusCodes.Status401Unauthorized);
    }

    var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [new Claim(ClaimTypes.Name, user.User), new Claim("display", user.Name)],
        CookieAuthenticationDefaults.AuthenticationScheme));
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
    app.Logger.LogInformation("Sesión iniciada en el panel: {User}", user.User);
    return Results.Ok(new { user = user.User, name = user.Name });
});

app.MapPost("/auth/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { ok = true });
});

app.MapGet("/auth/me", (HttpContext context) => context.User.Identity?.IsAuthenticated == true
    ? Results.Ok(new { user = context.User.Identity.Name, name = context.User.FindFirst("display")?.Value, enabled = authEnabled })
    : Results.Ok(new { user = (string?)null, name = authEnabled ? null : "Operador", enabled = authEnabled }));

app.UseDefaultFiles();
// Sin caché para el panel: tras actualizar el nodo, el navegador siempre carga el HTML/JS/CSS nuevo.
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx => ctx.Context.Response.Headers.CacheControl = "no-cache, no-store, must-revalidate"
});
app.MapV2Api();
app.MapNodeApi();

app.Lifetime.ApplicationStarted.Register(() =>
{
    app.Logger.LogInformation(
        "Nodo {NodeId} (equipo {Team}) listo en http://{Ip}:{Port}/ · algoritmos propios: {Algorithms} · también escucha: {Urls}",
        identity.NodeId,
        identity.TeamNumber,
        identity.Ip,
        identity.HttpPort,
        string.Join(", ", provided.Select(p => p.Algorithm.Code)),
        string.Join(" ", app.Urls));
});

app.Run();

static bool PortIsFree(int port)
{
    try
    {
        var listener = new TcpListener(IPAddress.Any, port);
        listener.Start();
        listener.Stop();
        return true;
    }
    catch (SocketException)
    {
        return false;
    }
}

/// <summary>
/// Punto de entrada parcial para pruebas de integración con WebApplicationFactory en fases posteriores.
/// </summary>
public partial class Program
{
}
