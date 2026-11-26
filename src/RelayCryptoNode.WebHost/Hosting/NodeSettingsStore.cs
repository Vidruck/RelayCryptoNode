using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using RelayCryptoNode.Application.Configuration;
using RelayCryptoNode.Domain.Enums;

namespace RelayCryptoNode.WebHost.Hosting;

/// <summary>
/// Lee la configuración inicial del nodo (appsettings.json + cambios guardados desde el panel)
/// y guarda los cambios en <c>datos/configuracion-nodo.json</c>.
/// </summary>
public sealed class NodeSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _path;

    private NodeSettingsStore(string path)
    {
        _path = path;
    }

    /// <summary>
    /// Carpeta raíz de datos del nodo (certificados, bandeja, evidencias).
    /// </summary>
    public required string DataDirectory { get; init; }

    /// <summary>
    /// Tamaño máximo aceptado del .zip en bytes.
    /// </summary>
    public required long MaxPackageBytes { get; init; }

    /// <summary>
    /// Crea el estado del nodo a partir de la configuración.
    /// </summary>
    public static (NodeSettingsStore Store, NodeRuntimeState State) Load(IConfiguration configuration, string contentRoot)
    {
        var section = configuration.GetSection("Node");
        var dataDirectory = section["DataDirectory"] is { Length: > 0 } dir ? dir : "datos";
        if (!Path.IsPathRooted(dataDirectory))
        {
            dataDirectory = Path.Combine(contentRoot, dataDirectory);
        }

        Directory.CreateDirectory(dataDirectory);
        var store = new NodeSettingsStore(Path.Combine(dataDirectory, "configuracion-nodo.json"))
        {
            DataDirectory = dataDirectory,
            MaxPackageBytes = (section.GetValue<long?>("MaxPackageMegabytes") ?? 50) * 1024 * 1024
        };

        var port = section.GetValue<int?>("Port") ?? 5000;
        var snapshot = new NodeRuntimeSnapshot(
            section["Id"] is { Length: > 0 } id ? id : "NODO06",
            section["PublicUrl"] is { Length: > 0 } url ? url : $"http://{DetectLanAddress()}:{port}",
            Enum.TryParse<NodeRole>(section["Role"], true, out var role) ? role : NodeRole.Final,
            section["NextNode"],
            section["OutgoingAlgorithm"] is { Length: > 0 } alg ? alg : "AESGCM",
            Enum.TryParse<KeyExchangeAlgorithmType>(section["KeyExchange"], true, out var kx) ? kx : KeyExchangeAlgorithmType.RsaOaepSha256,
            section.GetValue<bool?>("AutoProcess") ?? false,
            section.GetValue<bool?>("SharedKeyFormat") ?? false);
        var preSharedKey = section["PreSharedKey"];
        var sharedAesKey = section["SharedAesKey"];

        var saved = store.ReadSaved();
        if (saved is not null)
        {
            snapshot = snapshot with
            {
                Role = saved.Role,
                NextNodeEndpoint = saved.NextNodeEndpoint,
                OutgoingAlgorithmCode = saved.OutgoingAlgorithmCode,
                KeyExchange = saved.KeyExchange,
                AutoProcess = saved.AutoProcess,
                SharedKeyFormat = saved.SharedKeyFormat
            };
            preSharedKey = saved.PreSharedKey ?? preSharedKey;
            sharedAesKey = saved.SharedAesKey ?? sharedAesKey;
        }

        var state = new NodeRuntimeState(snapshot, preSharedKey) { SharedAesKey = sharedAesKey ?? NodeRuntimeState.DefaultSharedAesKey };
        state.Changed += _ => store.Save(state);
        return (store, state);
    }

    /// <summary>
    /// Guarda la configuración vigente (rol, siguiente nodo, algoritmo, claves compartidas).
    /// </summary>
    public void Save(NodeRuntimeState state)
    {
        var current = state.Current;
        var saved = new SavedSettings(
            current.Role,
            current.NextNodeEndpoint,
            current.OutgoingAlgorithmCode,
            current.KeyExchange,
            current.AutoProcess,
            current.SharedKeyFormat,
            state.GetPreSharedKey(),
            state.SharedAesKey);
        File.WriteAllText(_path, JsonSerializer.Serialize(saved, JsonOptions));
    }

    /// <summary>
    /// Busca la IPv4 de la red local (prefiere 192.168.x.x y 10.x.x.x).
    /// </summary>
    public static string DetectLanAddress()
    {
        try
        {
            var candidates = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Select(a => a.Address)
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.ToString())
                .ToList();
            return candidates.FirstOrDefault(a => a.StartsWith("192.168.", StringComparison.Ordinal))
                   ?? candidates.FirstOrDefault(a => a.StartsWith("10.", StringComparison.Ordinal))
                   ?? candidates.FirstOrDefault()
                   ?? "127.0.0.1";
        }
        catch (NetworkInformationException)
        {
            return "127.0.0.1";
        }
    }

    private SavedSettings? ReadSaved()
    {
        if (!File.Exists(_path))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<SavedSettings>(File.ReadAllText(_path));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed record SavedSettings(
        NodeRole Role,
        string? NextNodeEndpoint,
        string OutgoingAlgorithmCode,
        KeyExchangeAlgorithmType KeyExchange,
        bool AutoProcess,
        bool SharedKeyFormat,
        string? PreSharedKey,
        string? SharedAesKey);
}
