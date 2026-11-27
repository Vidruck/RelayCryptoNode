using System.Text.Json;
using System.Text.Json.Nodes;

namespace RelayCryptoNode.Infrastructure.ProtocolV2;

/// <summary>
/// Registro de la bandeja v2.0: Solicitudes (Pendiente / Aceptada / Rechazada) y Consultas
/// (origen Generado / Recibido / Resultado), sección 15.
/// </summary>
public sealed class PacketRecord
{
    /// <summary>Id local.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary><c>solicitud</c> o <c>consulta</c>.</summary>
    public string Kind { get; set; } = "consulta";

    /// <summary>Estado de la solicitud.</summary>
    public string Status { get; set; } = "Pendiente";

    /// <summary>Origen en Consultas.</summary>
    public string Origin { get; set; } = "Generado";

    /// <summary>Nombre del zip.</summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>IP de origen (bandeja).</summary>
    public string SourceIp { get; set; } = string.Empty;

    /// <summary>Resultado de validación para mostrar.</summary>
    public string Validation { get; set; } = string.Empty;

    /// <summary>packetId.</summary>
    public string PacketId { get; set; } = string.Empty;

    /// <summary>packetType.</summary>
    public string PacketType { get; set; } = "package";

    /// <summary>Emisor.</summary>
    public string SourceNode { get; set; } = string.Empty;

    /// <summary>Productor.</summary>
    public string ProducerNode { get; set; } = string.Empty;

    /// <summary>Algoritmo.</summary>
    public string AlgorithmCode { get; set; } = string.Empty;

    /// <summary>Operación.</summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>Nombre legible de la operación.</summary>
    public string OperationName { get; set; } = string.Empty;

    /// <summary>Archivo original.</summary>
    public string OriginalFileName { get; set; } = string.Empty;

    /// <summary>Tamaño del paquete.</summary>
    public long SizeBytes { get; set; }

    /// <summary>Fecha local de registro.</summary>
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Nota libre (por ejemplo el resultado de un inverse).</summary>
    public string? Note { get; set; }

    /// <summary>Archivo recuperado por un inverse (si existe).</summary>
    public string? RecoveredFileName { get; set; }

    /// <summary>Borrado de la vista (Recibidos / Consultas); sigue en el histórico y en disco.</summary>
    public bool Hidden { get; set; }

    /// <summary>Cuándo se borró de la vista.</summary>
    public DateTimeOffset? HiddenUtc { get; set; }
}

/// <summary>
/// Guarda paquetes v2.0 en <c>datos/v2/&lt;id&gt;/</c> (paquete.zip + registro.json).
/// </summary>
public sealed class PacketStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _root;
    private readonly object _sync = new();
    private readonly Dictionary<string, PacketRecord> _records = new(StringComparer.Ordinal);

    /// <summary>Carga los registros.</summary>
    public PacketStore(string root)
    {
        _root = root;
        Directory.CreateDirectory(root);
        foreach (var folder in Directory.EnumerateDirectories(root))
        {
            var path = Path.Combine(folder, "registro.json");
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                var record = JsonSerializer.Deserialize<PacketRecord>(File.ReadAllText(path));
                if (record is not null)
                {
                    _records[record.Id] = record;
                }
            }
            catch (JsonException)
            {
            }
        }
    }

    /// <summary>Agrega un paquete.</summary>
    public PacketRecord Add(V2Package package, string kind, string origin, string status = "Pendiente", string sourceIp = "", string validation = "")
    {
        var record = new PacketRecord
        {
            Kind = kind,
            Origin = origin,
            Status = status,
            FileName = package.FileName,
            SourceIp = sourceIp,
            Validation = validation,
            PacketId = package.PacketId,
            PacketType = package.PacketType,
            SourceNode = package.SourceNode,
            ProducerNode = package.ProducerNode,
            AlgorithmCode = package.AlgorithmCode,
            Operation = package.Operation,
            OperationName = package.Str("operationName"),
            OriginalFileName = package.Str("originalFileName"),
            SizeBytes = package.ZipBytes.LongLength
        };
        var folder = Path.Combine(_root, record.Id);
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, "paquete.zip"), package.ZipBytes);
        Save(record);
        return record;
    }

    /// <summary>Lista por tipo.</summary>
    public List<PacketRecord> List(string kind)
    {
        lock (_sync)
        {
            return _records.Values.Where(r => r.Kind == kind && !r.Hidden).OrderByDescending(r => r.CreatedUtc).ToList();
        }
    }

    /// <summary>Histórico: todos los registros, también los borrados de la vista.</summary>
    public List<PacketRecord> ListAll()
    {
        lock (_sync)
        {
            return _records.Values.OrderByDescending(r => r.CreatedUtc).ToList();
        }
    }

    /// <summary>Borra (o restaura) un registro de la vista. Nunca borra el archivo: queda en el histórico.</summary>
    public PacketRecord SetHidden(string id, bool hidden)
    {
        var record = Get(id);
        record.Hidden = hidden;
        record.HiddenUtc = hidden ? DateTimeOffset.UtcNow : null;
        Save(record);
        return record;
    }

    /// <summary>Busca un registro.</summary>
    public PacketRecord Get(string id)
    {
        lock (_sync)
        {
            return _records.TryGetValue(id, out var record)
                ? record
                : throw new V2ProtocolException("E-REQUEST", "No existe ese registro.");
        }
    }

    /// <summary>Guarda cambios de un registro.</summary>
    public void Save(PacketRecord record)
    {
        lock (_sync)
        {
            _records[record.Id] = record;
            File.WriteAllText(Path.Combine(_root, record.Id, "registro.json"), JsonSerializer.Serialize(record, JsonOptions));
        }
    }

    /// <summary>Bytes del zip.</summary>
    public byte[] ZipBytes(string id) => File.ReadAllBytes(Path.Combine(_root, Get(id).Id, "paquete.zip"));

    /// <summary>Manifiesto del paquete (para "ver el manifiesto").</summary>
    public JsonObject Manifest(string id)
    {
        using var zip = new System.IO.Compression.ZipArchive(new MemoryStream(ZipBytes(id)), System.IO.Compression.ZipArchiveMode.Read);
        using var stream = zip.GetEntry("manifest.json")!.Open();
        return (JsonObject)JsonNode.Parse(stream)!;
    }

    /// <summary>Guarda el archivo recuperado de un inverse.</summary>
    public void SaveRecovered(string id, string fileName, byte[] content)
    {
        var record = Get(id);
        var safe = Path.GetFileName(fileName);
        File.WriteAllBytes(Path.Combine(_root, record.Id, "recuperado_" + safe), content);
        record.RecoveredFileName = safe;
        Save(record);
    }

    /// <summary>Ruta del archivo recuperado.</summary>
    public string? RecoveredPath(string id)
    {
        var record = Get(id);
        if (record.RecoveredFileName is null)
        {
            return null;
        }

        var path = Path.Combine(_root, record.Id, "recuperado_" + record.RecoveredFileName);
        return File.Exists(path) ? path : null;
    }
}
