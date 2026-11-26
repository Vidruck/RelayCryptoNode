using System.Security.Cryptography;
using Microsoft.AspNetCore.Http.Features;
using RelayCryptoNode.Application.Abstractions;
using RelayCryptoNode.Application.Configuration;
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
using RelayCryptoNode.Infrastructure.Realtime;
using RelayCryptoNode.Infrastructure.Transport;
using RelayCryptoNode.WebHost.Endpoints;
using RelayCryptoNode.WebHost.Hosting;

var builder = WebApplication.CreateBuilder(args);

var (settings, state) = NodeSettingsStore.Load(builder.Configuration, builder.Environment.ContentRootPath);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = settings.MaxPackageBytes + (1024 * 1024));
builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = settings.MaxPackageBytes + (1024 * 1024));

var certificates = new LocalCertificateService(Path.Combine(settings.DataDirectory, "certificados"), state.Current.NodeId);
var registry = new AlgorithmModuleRegistry();
var serializer = new ZipPackageSerializer();

builder.Services.AddSingleton(settings);
builder.Services.AddSingleton(state);
builder.Services.AddSingleton(registry);
builder.Services.AddSingleton<ICertificateServicePort>(certificates);
builder.Services.AddSingleton<IPackageSerializerPort>(serializer);
builder.Services.AddSingleton<IHashingServicePort, HashShaModule>();
builder.Services.AddSingleton<InMemoryEventHub>();
builder.Services.AddSingleton<IRealtimeNotifierPort>(sp => sp.GetRequiredService<InMemoryEventHub>());
builder.Services.AddSingleton(sp => new FileRequestRepository(Path.Combine(settings.DataDirectory, "bandeja"), serializer));
builder.Services.AddSingleton<IRequestRepositoryPort>(sp => sp.GetRequiredService<FileRequestRepository>());
builder.Services.AddSingleton(new FileSystemEvidenceStorage(Path.Combine(settings.DataDirectory, "evidencia")));
builder.Services.AddSingleton<IEvidenceStoragePort>(sp => sp.GetRequiredService<FileSystemEvidenceStorage>());

// Módulos de cifrado (los 15 que cifran datos.enc) y envoltura de clave de sesión.
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

var app = builder.Build();

app.Use(async (context, next) =>
{
    try
    {
        await next();
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

app.UseDefaultFiles();
app.UseStaticFiles();
app.MapNodeApi();

app.Lifetime.ApplicationStarted.Register(() =>
{
    var current = state.Current;
    app.Logger.LogInformation(
        "Nodo {NodeId} listo en {Endpoint} (rol {Role}). Panel: {Endpoint}/",
        current.NodeId,
        current.PublicEndpoint,
        current.Role,
        current.PublicEndpoint);
});

app.Run();

/// <summary>
/// Punto de entrada parcial para pruebas de integración con WebApplicationFactory en fases posteriores.
/// </summary>
public partial class Program
{
}
