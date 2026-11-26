using System.Collections.Concurrent;
using System.Threading.Channels;
using RelayCryptoNode.Domain.Ports.Outbound;

namespace RelayCryptoNode.Infrastructure.Realtime;

/// <summary>
/// Bitácora en memoria con suscriptores en vivo (el panel web los recibe por Server-Sent Events).
/// </summary>
public sealed class InMemoryEventHub : IRealtimeNotifierPort
{
    private const int HistorySize = 300;

    private readonly ConcurrentQueue<NodeEventNotification> _history = new();
    private readonly ConcurrentDictionary<Guid, Channel<NodeEventNotification>> _subscribers = new();

    /// <inheritdoc />
    public Task NotifyAsync(NodeEventNotification notification, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(notification);
        _history.Enqueue(notification);
        while (_history.Count > HistorySize && _history.TryDequeue(out _))
        {
        }

        foreach (var channel in _subscribers.Values)
        {
            channel.Writer.TryWrite(notification);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Últimos eventos, del más reciente al más antiguo.
    /// </summary>
    public IReadOnlyList<NodeEventNotification> Recent(int max = 100) =>
        _history.Reverse().Take(Math.Clamp(max, 1, HistorySize)).ToList();

    /// <summary>
    /// Se suscribe a los eventos nuevos. Al desechar la suscripción se deja de recibir.
    /// </summary>
    public EventSubscription Subscribe()
    {
        var id = Guid.NewGuid();
        var channel = Channel.CreateBounded<NodeEventNotification>(new BoundedChannelOptions(100)
        {
            FullMode = BoundedChannelFullMode.DropOldest
        });
        _subscribers[id] = channel;
        return new EventSubscription(channel.Reader, () => _subscribers.TryRemove(id, out _));
    }

    /// <summary>
    /// Suscripción activa a la bitácora.
    /// </summary>
    public sealed class EventSubscription : IDisposable
    {
        private readonly Action _onDispose;

        internal EventSubscription(ChannelReader<NodeEventNotification> reader, Action onDispose)
        {
            Reader = reader;
            _onDispose = onDispose;
        }

        /// <summary>Lector de eventos nuevos.</summary>
        public ChannelReader<NodeEventNotification> Reader { get; }

        /// <inheritdoc />
        public void Dispose() => _onDispose();
    }
}
