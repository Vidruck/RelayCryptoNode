using System.Text.Json;

namespace RelayCryptoNode.WebHost.Hosting;

/// <summary>Una petición que llegó de otra máquina (otro nodo) al puerto del EQ06.</summary>
public sealed record InboundEntry(
    DateTimeOffset AtUtc,
    string Ip,
    string Method,
    string Path,
    int Status,
    long? Bytes,
    long Ms,
    string? Node,
    string? Error);

/// <summary>
/// Bitácora persistente de conexiones entrantes (datos/entradas.log, una línea JSON por petición).
/// Sirve para saber si un equipo de verdad le pegó al nodo, a qué ruta y qué se le respondió,
/// aunque el nodo se haya reiniciado después.
/// </summary>
public sealed class InboundLog
{
    private const long MaxFileBytes = 2 * 1024 * 1024;
    private readonly string _path;
    private readonly LinkedList<InboundEntry> _recent = new();
    private readonly object _gate = new();

    public InboundLog(string dataDirectory)
    {
        Directory.CreateDirectory(dataDirectory);
        _path = Path.Combine(dataDirectory, "entradas.log");
        if (!File.Exists(_path))
        {
            return;
        }

        foreach (var line in File.ReadLines(_path).TakeLast(300))
        {
            try
            {
                if (JsonSerializer.Deserialize<InboundEntry>(line) is { } entry)
                {
                    _recent.AddFirst(entry);
                }
            }
            catch (JsonException)
            {
            }
        }
    }

    /// <summary>Guarda una entrada.</summary>
    public void Add(InboundEntry entry)
    {
        lock (_gate)
        {
            _recent.AddFirst(entry);
            while (_recent.Count > 300)
            {
                _recent.RemoveLast();
            }

            try
            {
                if (File.Exists(_path) && new FileInfo(_path).Length > MaxFileBytes)
                {
                    File.Move(_path, _path + ".1", overwrite: true);
                }

                File.AppendAllText(_path, JsonSerializer.Serialize(entry) + Environment.NewLine);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>Las más recientes primero.</summary>
    public IReadOnlyList<InboundEntry> Recent()
    {
        lock (_gate)
        {
            return _recent.ToList();
        }
    }
}
