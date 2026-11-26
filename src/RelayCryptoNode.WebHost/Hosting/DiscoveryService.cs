using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using RelayCryptoNode.Infrastructure.ProtocolV2;

namespace RelayCryptoNode.WebHost.Hosting;

/// <summary>
/// Autodescubrimiento (sección 6): anuncio CC-BEACON por UDP 5099 cada 30 s a 255.255.255.255 y a la
/// difusión de cada subred, y escucha de los anuncios de los demás nodos.
/// </summary>
public sealed class DiscoveryService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    private readonly V2NodeService _node;
    private readonly ILogger<DiscoveryService> _logger;

    /// <summary>Crea el servicio.</summary>
    public DiscoveryService(V2NodeService node, ILogger<DiscoveryService> logger)
    {
        _node = node;
        _logger = logger;
    }

    /// <summary>Envía un anuncio inmediato (por ejemplo al presionar "Anunciarme").</summary>
    public void AnnounceNow(string status = "online")
    {
        foreach (var (address, broadcast) in LocalNetworks())
        {
            _node.Identity.Ip = _node.Identity.Ip is "127.0.0.1" ? address.ToString() : _node.Identity.Ip;
            var payload = _node.Beacon(address.ToString(), status);
            foreach (var target in new[] { IPAddress.Broadcast, broadcast }.Distinct())
            {
                try
                {
                    using var socket = new UdpClient(new IPEndPoint(address, 0)) { EnableBroadcast = true };
                    socket.Send(payload, payload.Length, new IPEndPoint(target, V2Format.BeaconPort));
                }
                catch (SocketException ex)
                {
                    _logger.LogDebug("No se pudo anunciar por {Address}: {Message}", address, ex.Message);
                }
            }
        }
    }

    private readonly SemaphoreSlim _scanning = new(1, 1);

    /// <summary>Hora del último escaneo HTTP terminado y cuántos nodos respondieron.</summary>
    public (DateTimeOffset? At, int Found, int Scanned) LastScan { get; private set; }

    /// <summary>
    /// Escanea la subred /24 de cada tarjeta en los puertos 5000 a 5020 (GET /api/status). Si ya hay un
    /// escaneo en curso regresa null.
    /// </summary>
    public async Task<(int Scanned, IReadOnlyList<DirectoryEntry> Found)?> ScanAsync(CancellationToken ct)
    {
        if (!await _scanning.WaitAsync(0, ct))
        {
            return null;
        }

        try
        {
            var hosts = new HashSet<string>(ExtraHosts);
            foreach (var (address, broadcast) in LocalNetworks())
            {
                // Toda la subred de la tarjeta (máximo un bloque /22 = 1022 equipos alrededor de la IP propia).
                var ip = ToUInt(address);
                var last = ToUInt(broadcast);
                var first = Math.Max(NetworkOf(ip, last), ip & 0xFFFFFC00u);
                for (var host = first + 1; host < last && host < first + 1023; host++)
                {
                    hosts.Add(new IPAddress(new[] { (byte)(host >> 24), (byte)(host >> 16), (byte)(host >> 8), (byte)host }).ToString());
                }
            }

            if (hosts.Count == 0 && IPAddress.TryParse(_node.Identity.Ip, out var own) && own.AddressFamily == AddressFamily.InterNetwork)
            {
                var prefix = string.Join('.', _node.Identity.Ip.Split('.')[..3]);
                foreach (var host in Enumerable.Range(1, 254))
                {
                    hosts.Add($"{prefix}.{host}");
                }
            }

            var targets = hosts.SelectMany(host => Enumerable.Range(5000, 21).Select(port => (Ip: host, Port: port))).ToList();
            var found = new System.Collections.Concurrent.ConcurrentBag<DirectoryEntry>();
            await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = 256, CancellationToken = ct }, async (target, token) =>
            {
                try
                {
                    var entry = await _node.ProbeAsync(target.Ip, target.Port, "scan", TimeSpan.FromMilliseconds(450), token);
                    if (entry is not null)
                    {
                        found.Add(entry);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogDebug("Escaneo {Ip}:{Port}: {Message}", target.Ip, target.Port, ex.Message);
                }
            });
            var list = found.GroupBy(f => f.NodeId).Select(g => g.First()).ToList();
            LastScan = (DateTimeOffset.UtcNow, list.Count, targets.Count);
            return (targets.Count, list);
        }
        finally
        {
            _scanning.Release();
        }
    }

    /// <summary>Equipos extra a escanear siempre (Node:ScanHosts, separados por coma), por ejemplo de otra subred.</summary>
    public IReadOnlyList<string> ExtraHosts { get; init; } = [];

    private static uint ToUInt(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    // La red es la IP con los bits de host (los que valen 1 en la difusión y forman el sufijo) en cero.
    private static uint NetworkOf(uint ip, uint broadcast)
    {
        var hostBits = 0u;
        for (var bit = 0; bit < 32 && ((broadcast >> bit) & 1) == 1; bit++)
        {
            hostBits |= 1u << bit;
        }

        return ip & ~hostBits;
    }

    private async Task AutoScanAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Escaneo automático: {Message}", ex.Message);
            }

            try
            {
                await Task.Delay(Interval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var listen = Task.Run(() => ListenAsync(stoppingToken), stoppingToken);
        var autoScan = Task.Run(() => AutoScanAsync(stoppingToken), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            var current = NodeSettingsStore.DetectLanAddress();
            if (current != "127.0.0.1")
            {
                _node.Identity.Ip = current;
            }

            AnnounceNow();
            try
            {
                await Task.Delay(Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        AnnounceNow("offline");
        await listen;
        try
        {
            await autoScan;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task ListenAsync(CancellationToken stoppingToken)
    {
        UdpClient listener;
        try
        {
            listener = new UdpClient(AddressFamily.InterNetwork);
            listener.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listener.Client.Bind(new IPEndPoint(IPAddress.Any, V2Format.BeaconPort));
            listener.EnableBroadcast = true;
        }
        catch (SocketException ex)
        {
            _logger.LogWarning("No se pudo escuchar el puerto UDP {Port}: {Message}. Use el escaneo o el alta manual.", V2Format.BeaconPort, ex.Message);
            return;
        }

        using (listener)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var received = await listener.ReceiveAsync(stoppingToken);
                    _node.HandleBeacon(received.Buffer);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException ex)
                {
                    _logger.LogDebug("Error al recibir anuncio: {Message}", ex.Message);
                }
            }
        }
    }

    /// <summary>IPv4 de cada interfaz real con su dirección de difusión.</summary>
    public static List<(IPAddress Address, IPAddress Broadcast)> LocalNetworks()
    {
        var result = new List<(IPAddress, IPAddress)>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                var text = (nic.Name + " " + nic.Description).ToLowerInvariant();
                if (nic.OperationalStatus != OperationalStatus.Up
                    || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback
                    || new[] { "virtualbox", "vmware", "hyper-v", "vethernet", "wsl", "virtual", "docker" }.Any(text.Contains))
                {
                    continue;
                }

                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetwork || unicast.IPv4Mask is null)
                    {
                        continue;
                    }

                    var ip = unicast.Address.GetAddressBytes();
                    var mask = unicast.IPv4Mask.GetAddressBytes();
                    var broadcast = new byte[4];
                    for (var i = 0; i < 4; i++)
                    {
                        broadcast[i] = (byte)(ip[i] | ~mask[i]);
                    }

                    result.Add((unicast.Address, new IPAddress(broadcast)));
                }
            }
        }
        catch (NetworkInformationException)
        {
        }

        return result;
    }
}
