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

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var listen = Task.Run(() => ListenAsync(stoppingToken), stoppingToken);
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
