using System.Text.Json;

namespace RelayCryptoNode.Infrastructure.ProtocolV2;

/// <summary>
/// Entrada del directorio local de nodos (sección 6.4).
/// </summary>
public sealed class DirectoryEntry
{
    /// <summary>nodeId.</summary>
    public string NodeId { get; set; } = string.Empty;

    /// <summary>Número de equipo.</summary>
    public int TeamNumber { get; set; }

    /// <summary>IP actual.</summary>
    public string Ip { get; set; } = string.Empty;

    /// <summary>Puerto HTTP.</summary>
    public int HttpPort { get; set; }

    /// <summary>Puerto HTTPS o <c>null</c>.</summary>
    public int? HttpsPort { get; set; }

    /// <summary>Huella confirmada por el usuario (TOFU).</summary>
    public string? PinnedThumbprintSha256 { get; set; }

    /// <summary>Huella que anuncia o presenta ahora.</summary>
    public string? SeenThumbprintSha256 { get; set; }

    /// <summary>Algoritmos que anuncia.</summary>
    public List<string> Algorithms { get; set; } = [];

    /// <summary><c>beacon</c>, <c>scan</c> o <c>manual</c>.</summary>
    public string Source { get; set; } = "manual";

    /// <summary><c>online</c> u <c>offline</c>.</summary>
    public string Status { get; set; } = "offline";

    /// <summary>Última vez visto.</summary>
    public DateTimeOffset LastSeenUtc { get; set; }

    /// <summary>Protocolos que habla (1.0 para nodos viejos).</summary>
    public string ProtocolVersion { get; set; } = V2Format.Version;

    /// <summary>Dirección base HTTP.</summary>
    public string BaseUrl => $"http://{Ip}:{HttpPort}";

    /// <summary>Si la huella está fijada y coincide con la vista.</summary>
    public bool Trusted => PinnedThumbprintSha256 is not null
                           && (SeenThumbprintSha256 is null || SeenThumbprintSha256 == PinnedThumbprintSha256);

    /// <summary>La huella cambió respecto a la fijada.</summary>
    public bool ThumbprintChanged => PinnedThumbprintSha256 is not null
                                     && SeenThumbprintSha256 is not null
                                     && SeenThumbprintSha256 != PinnedThumbprintSha256;
}

/// <summary>
/// Directorio local de nodos con huella fijada en el primer uso. Se guarda en <c>directorio-nodos.json</c>.
/// </summary>
public sealed class NodeDirectory
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly TimeSpan OfflineAfter = TimeSpan.FromSeconds(90);

    private readonly string _path;
    private readonly object _sync = new();
    private readonly Dictionary<string, DirectoryEntry> _entries;

    /// <summary>Carga el directorio.</summary>
    public NodeDirectory(string path)
    {
        _path = path;
        _entries = new Dictionary<string, DirectoryEntry>(StringComparer.Ordinal);
        if (File.Exists(path))
        {
            try
            {
                foreach (var entry in JsonSerializer.Deserialize<List<DirectoryEntry>>(File.ReadAllText(path)) ?? [])
                {
                    entry.Status = "offline";
                    _entries[entry.NodeId] = entry;
                }
            }
            catch (JsonException)
            {
                // Directorio dañado: se empieza vacío.
            }
        }
    }

    /// <summary>Se dispara cuando cambia algo.</summary>
    public event Action<DirectoryEntry>? Changed;

    /// <summary>Entradas con su estado actualizado.</summary>
    public List<DirectoryEntry> List()
    {
        lock (_sync)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var entry in _entries.Values.Where(e => e.Status == "online" && now - e.LastSeenUtc > OfflineAfter))
            {
                entry.Status = "offline";
            }

            return _entries.Values.OrderBy(e => e.TeamNumber).ThenBy(e => e.NodeId).Select(Clone).ToList();
        }
    }

    /// <summary>Busca un nodo.</summary>
    public DirectoryEntry? Get(string nodeId)
    {
        lock (_sync)
        {
            return _entries.TryGetValue(nodeId, out var entry) ? Clone(entry) : null;
        }
    }

    /// <summary>Registra o actualiza un nodo visto por anuncio, escaneo o alta manual.</summary>
    public DirectoryEntry Upsert(DirectoryEntry seen)
    {
        DirectoryEntry result;
        lock (_sync)
        {
            if (!_entries.TryGetValue(seen.NodeId, out var entry))
            {
                entry = new DirectoryEntry { NodeId = seen.NodeId, Source = seen.Source };
                _entries[seen.NodeId] = entry;
            }

            entry.TeamNumber = seen.TeamNumber;
            entry.Ip = seen.Ip;
            entry.HttpPort = seen.HttpPort;
            entry.HttpsPort = seen.HttpsPort;
            entry.ProtocolVersion = seen.ProtocolVersion;
            if (seen.SeenThumbprintSha256 is not null)
            {
                entry.SeenThumbprintSha256 = seen.SeenThumbprintSha256;
            }

            if (seen.Algorithms.Count > 0)
            {
                entry.Algorithms = seen.Algorithms.ToList();
            }

            if (entry.Source != "manual")
            {
                entry.Source = seen.Source;
            }

            entry.Status = seen.Status;
            entry.LastSeenUtc = DateTimeOffset.UtcNow;
            result = Clone(entry);
            SaveLocked();
        }

        Changed?.Invoke(result);
        return result;
    }

    /// <summary>Fija la huella vista (el usuario la confirmó).</summary>
    public DirectoryEntry Pin(string nodeId, string thumbprint)
    {
        DirectoryEntry result;
        lock (_sync)
        {
            if (!_entries.TryGetValue(nodeId, out var entry))
            {
                throw new V2ProtocolException("E-REQUEST", $"No hay ningún nodo {nodeId} en el directorio.");
            }

            entry.PinnedThumbprintSha256 = thumbprint;
            entry.SeenThumbprintSha256 = thumbprint;
            result = Clone(entry);
            SaveLocked();
        }

        Changed?.Invoke(result);
        return result;
    }

    /// <summary>Quita un nodo del directorio.</summary>
    public void Remove(string nodeId)
    {
        lock (_sync)
        {
            _entries.Remove(nodeId);
            SaveLocked();
        }
    }

    /// <summary>Huella fijada de un nodo o <c>null</c>.</summary>
    public string? PinnedThumbprint(string nodeId)
    {
        lock (_sync)
        {
            return _entries.TryGetValue(nodeId, out var entry) ? entry.PinnedThumbprintSha256 : null;
        }
    }

    private void SaveLocked()
    {
        try
        {
            File.WriteAllText(_path, JsonSerializer.Serialize(_entries.Values.ToList(), JsonOptions));
        }
        catch (IOException)
        {
            // Se vuelve a intentar en el siguiente cambio.
        }
    }

    private static DirectoryEntry Clone(DirectoryEntry e) => new()
    {
        NodeId = e.NodeId,
        TeamNumber = e.TeamNumber,
        Ip = e.Ip,
        HttpPort = e.HttpPort,
        HttpsPort = e.HttpsPort,
        PinnedThumbprintSha256 = e.PinnedThumbprintSha256,
        SeenThumbprintSha256 = e.SeenThumbprintSha256,
        Algorithms = e.Algorithms.ToList(),
        Source = e.Source,
        Status = e.Status,
        LastSeenUtc = e.LastSeenUtc,
        ProtocolVersion = e.ProtocolVersion
    };
}

/// <summary>
/// Registro de <c>packetId</c> y <c>requestId</c> ya vistos (protección contra repetición, 13.1 #14 y 13.2 #5).
/// </summary>
public sealed class ReplayGuard
{
    private readonly string _path;
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private readonly object _sync = new();

    /// <summary>Carga el registro.</summary>
    public ReplayGuard(string path)
    {
        _path = path;
        if (File.Exists(path))
        {
            foreach (var line in File.ReadAllLines(path))
            {
                if (line.Length > 0)
                {
                    _seen.Add(line);
                }
            }
        }
    }

    /// <summary>Indica si ya se vio.</summary>
    public bool Seen(string kind, string id)
    {
        lock (_sync)
        {
            return _seen.Contains($"{kind}:{id}");
        }
    }

    /// <summary>Registra un id; devuelve falso si ya estaba.</summary>
    public bool TryRecord(string kind, string id)
    {
        lock (_sync)
        {
            if (!_seen.Add($"{kind}:{id}"))
            {
                return false;
            }

            try
            {
                File.AppendAllText(_path, $"{kind}:{id}\n");
            }
            catch (IOException)
            {
                // Queda en memoria.
            }

            return true;
        }
    }
}
