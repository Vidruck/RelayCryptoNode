using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Infrastructure.Persistence;

/// <summary>
/// Bandeja persistida en disco: una carpeta por solicitud con <c>paquete.zip</c> y <c>solicitud.json</c>.
/// No requiere base de datos ni paquetes externos.
/// </summary>
public sealed class FileRequestRepository : IRequestRepositoryPort
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _root;
    private readonly IPackageSerializerPort _serializer;
    private readonly ConcurrentDictionary<Guid, IncomingRequest> _cache = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _loaded;

    /// <summary>
    /// Crea el repositorio en la carpeta indicada.
    /// </summary>
    public FileRequestRepository(string rootDirectory, IPackageSerializerPort serializer)
    {
        _root = rootDirectory;
        _serializer = serializer;
        Directory.CreateDirectory(_root);
    }

    /// <inheritdoc />
    public async Task AddAsync(IncomingRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var folder = FolderOf(request.RequestId);
            Directory.CreateDirectory(folder);
            var package = await _serializer.SerializeEnvelopeAsync(request.Envelope, cancellationToken).ConfigureAwait(false);
            await File.WriteAllBytesAsync(Path.Combine(folder, "paquete.zip"), package, cancellationToken).ConfigureAwait(false);
            await WriteStateAsync(request, cancellationToken).ConfigureAwait(false);
            _cache[request.RequestId] = request;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task UpdateAsync(IncomingRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteStateAsync(request, cancellationToken).ConfigureAwait(false);
            _cache[request.RequestId] = request;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<IncomingRequest?> GetByIdAsync(Guid requestId, CancellationToken cancellationToken = default)
    {
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
        return _cache.TryGetValue(requestId, out var request) ? request : null;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<IncomingRequest>> ListAsync(
        RequestStatus? statusFilter = null,
        CancellationToken cancellationToken = default)
    {
        await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);
        return _cache.Values
            .Where(r => statusFilter is null || r.Status == statusFilter)
            .OrderByDescending(r => r.ReceivedUtc)
            .ToList();
    }

    /// <summary>
    /// Ruta del <c>paquete.zip</c> guardado de una solicitud (para descargarlo desde el panel).
    /// </summary>
    public string PackagePath(Guid requestId) => Path.Combine(FolderOf(requestId), "paquete.zip");

    private string FolderOf(Guid requestId) => Path.Combine(_root, requestId.ToString("N"));

    private async Task WriteStateAsync(IncomingRequest request, CancellationToken cancellationToken)
    {
        var state = new StoredRequest(
            request.RequestId,
            request.ReceivedUtc,
            request.SignatureValid,
            request.IntegrityValid,
            request.ValidationNotes,
            request.Status.ToString(),
            request.RejectionReason,
            request.ProcessedUtc);
        var path = Path.Combine(FolderOf(request.RequestId), "solicitud.json");
        var temp = path + ".tmp";
        await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(state, JsonOptions), cancellationToken).ConfigureAwait(false);
        File.Move(temp, path, overwrite: true);
    }

    private async Task EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (_loaded)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_loaded)
            {
                return;
            }

            foreach (var folder in Directory.EnumerateDirectories(_root))
            {
                var statePath = Path.Combine(folder, "solicitud.json");
                var packagePath = Path.Combine(folder, "paquete.zip");
                if (!File.Exists(statePath) || !File.Exists(packagePath))
                {
                    continue;
                }

                try
                {
                    var state = JsonSerializer.Deserialize<StoredRequest>(
                        await File.ReadAllTextAsync(statePath, cancellationToken).ConfigureAwait(false));
                    if (state is null)
                    {
                        continue;
                    }

                    var envelope = await _serializer.DeserializeEnvelopeAsync(
                        await File.ReadAllBytesAsync(packagePath, cancellationToken).ConfigureAwait(false),
                        cancellationToken).ConfigureAwait(false);
                    var status = Enum.TryParse<RequestStatus>(state.Status, out var parsed) ? parsed : RequestStatus.Pending;
                    _cache[state.RequestId] = IncomingRequest.Rehydrate(
                        state.RequestId,
                        envelope,
                        state.ReceivedUtc,
                        state.SignatureValid,
                        state.IntegrityValid,
                        state.ValidationNotes,
                        status,
                        state.RejectionReason,
                        state.ProcessedUtc);
                }
                catch (Exception ex) when (ex is JsonException or IOException or Domain.Exceptions.DomainException)
                {
                    // Una solicitud dañada no debe impedir que arranque el nodo.
                    Console.Error.WriteLine(string.Create(CultureInfo.InvariantCulture, $"No se pudo cargar {folder}: {ex.Message}"));
                }
            }

            _loaded = true;
        }
        finally
        {
            _gate.Release();
        }
    }

    private sealed record StoredRequest(
        Guid RequestId,
        DateTimeOffset ReceivedUtc,
        bool SignatureValid,
        bool IntegrityValid,
        string? ValidationNotes,
        string Status,
        string? RejectionReason,
        DateTimeOffset? ProcessedUtc);
}
