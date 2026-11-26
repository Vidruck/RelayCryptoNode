using RelayCryptoNode.Application.Abstractions;
using RelayCryptoNode.Application.Configuration;
using RelayCryptoNode.Application.Services;
using RelayCryptoNode.Application.UseCases;
using RelayCryptoNode.Domain.Catalog;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Domain.ValueObjects;
using RelayCryptoNode.Infrastructure.Algorithms;
using RelayCryptoNode.Infrastructure.Algorithms.Asymmetric;
using RelayCryptoNode.Infrastructure.Algorithms.Integrity;
using RelayCryptoNode.Infrastructure.Certificates;
using RelayCryptoNode.Infrastructure.KeyExchange;
using RelayCryptoNode.Infrastructure.Packaging;
using RelayCryptoNode.Infrastructure.Persistence;
using RelayCryptoNode.Infrastructure.Realtime;

namespace RelayCryptoNode.IntegrationTests;

/// <summary>
/// Nodo completo armado en memoria (mismas piezas que el WebHost) con una "red" falsa entre nodos.
/// </summary>
internal sealed class NodeHarness : IDisposable
{
    private readonly string _folder;

    public NodeHarness(string nodeId, NodeRole role, InMemoryNetwork network, string? nextNode = null, string outgoing = "AESGCM")
    {
        _folder = Path.Combine(Path.GetTempPath(), "rcn-tests", Guid.NewGuid().ToString("N"));
        Endpoint = $"http://{nodeId.ToLowerInvariant()}.test:5000";
        State = new NodeRuntimeState(
            new NodeRuntimeSnapshot(nodeId, Endpoint, role, nextNode, outgoing, KeyExchangeAlgorithmType.RsaOaepSha256, false),
            "psk-del-grupo");

        Certificates = new LocalCertificateService(Path.Combine(_folder, "certificados"), nodeId);
        Serializer = new ZipPackageSerializer();
        var hashing = new HashShaModule();
        var notifier = new InMemoryEventHub();
        var repository = new FileRequestRepository(Path.Combine(_folder, "bandeja"), Serializer);
        Evidence = new FileSystemEvidenceStorage(Path.Combine(_folder, "evidencia"));

        var registry = new AlgorithmModuleRegistry();
        var strategies = OfficialAlgorithmCatalog.GetAll()
            .Where(d => d.CipherAlgorithm is not null)
            .Select(d => registry.ResolveCipherStrategy(d.CipherAlgorithm!.Value))
            .ToList();
        var wrappers = new List<IAsymmetricKeyWrapperPort>
        {
            new RsaModule(Certificates.GetLocalPrivateKeyPem()),
            new PreSharedKeyWrapper(State.GetPreSharedKey)
        };

        Crypto = new EnvelopeCryptoService(
            strategies,
            wrappers,
            Certificates,
            hashing,
            Serializer,
            State,
            new SharedKeyLegacyCodec(() => State.SharedAesKey));
        Bundles = new PayloadBundleFactory(Serializer, hashing);
        var transport = network.TransportFor(this);
        var resolver = new RemoteNodeResolver(transport, Certificates);
        Inbox = new ManageIncomingRequestsUseCase(repository, notifier);
        Emit = new EmitInitialPackageUseCase(Crypto, Serializer, transport, resolver, notifier);
        Reception = new IncomingPackageService(Serializer, Certificates, hashing, Crypto, Inbox, notifier);
        Processing = new RequestProcessingService(
            State,
            Inbox,
            new RelayAndReEncryptUseCase(Inbox, repository, Crypto, Serializer, transport, resolver, notifier),
            new ReceiveAndAuditFinalUseCase(Inbox, repository, Crypto, Serializer, hashing, Evidence, notifier),
            resolver);

        network.Register(this);
    }

    public string Endpoint { get; }

    public NodeRuntimeState State { get; }

    public LocalCertificateService Certificates { get; }

    public ZipPackageSerializer Serializer { get; }

    public FileSystemEvidenceStorage Evidence { get; }

    public EnvelopeCryptoService Crypto { get; }

    public PayloadBundleFactory Bundles { get; }

    public ManageIncomingRequestsUseCase Inbox { get; }

    public EmitInitialPackageUseCase Emit { get; }

    public IncomingPackageService Reception { get; }

    public RequestProcessingService Processing { get; }

    public NodeIdentity IdentityFor(NodeHarness other) =>
        new(other.State.Current.NodeId, other.Endpoint, other.Certificates.ComputeThumbprintSha256(other.Certificates.GetLocalCertificatePem()));

    public void Dispose()
    {
        try
        {
            Directory.Delete(_folder, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

/// <summary>
/// Red falsa: entrega los .zip directamente al servicio de recepción del nodo destino.
/// </summary>
internal sealed class InMemoryNetwork
{
    private readonly Dictionary<string, NodeHarness> _nodes = new(StringComparer.OrdinalIgnoreCase);

    public void Register(NodeHarness node) => _nodes[node.Endpoint] = node;

    public INodeTransportSenderPort TransportFor(NodeHarness sender) => new Transport(this);

    private sealed class Transport(InMemoryNetwork network) : INodeTransportSenderPort
    {
        public async Task<TransportDeliveryResult> SendPackageAsync(
            NodeIdentity destinationNode,
            byte[] packageBytes,
            string packageFileName,
            CancellationToken cancellationToken = default)
        {
            if (!network._nodes.TryGetValue(destinationNode.EndpointAddress, out var target))
            {
                return new TransportDeliveryResult(false, 0, "Nodo inexistente.");
            }

            var result = await target.Reception.ReceiveAsync(packageBytes, cancellationToken);
            var status = result.Outcome switch
            {
                ReceptionOutcome.Registered => 202,
                ReceptionOutcome.Malformed => 400,
                _ => 422
            };
            return new TransportDeliveryResult(status == 202, status, result.Message);
        }

        public Task<string?> FetchRemoteCertificatePemAsync(string endpointAddress, CancellationToken cancellationToken = default) =>
            Task.FromResult(network._nodes.TryGetValue(endpointAddress, out var target)
                ? target.Certificates.GetLocalCertificatePem()
                : null);
    }
}
