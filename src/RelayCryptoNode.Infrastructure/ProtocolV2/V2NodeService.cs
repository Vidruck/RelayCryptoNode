using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.ProtocolV2.Providers;

namespace RelayCryptoNode.Infrastructure.ProtocolV2;

/// <summary>Partes de una petición <c>/api/crypto/*</c> (10.6).</summary>
public sealed class V2CryptoRequestParts
{
    /// <summary>Bytes exactos de la parte <c>request</c>.</summary>
    public byte[]? Request { get; init; }

    /// <summary>Firma Base64 de <c>request</c>.</summary>
    public string? RequestSignature { get; init; }

    /// <summary>Certificado PEM del solicitante.</summary>
    public string? RequesterCertificate { get; init; }

    /// <summary>Carga a procesar (forward).</summary>
    public byte[]? Payload { get; init; }

    /// <summary>Imagen portadora (LSBSTEGO).</summary>
    public byte[]? Cover { get; init; }

    /// <summary>Paquete a invertir (inverse).</summary>
    public byte[]? Package { get; init; }
}

/// <summary>Resultado de una operación hecha desde el panel.</summary>
/// <param name="Record">Registro guardado en Consultas.</param>
/// <param name="Package">Paquete producido.</param>
/// <param name="Delegated">Si se pidió a otro nodo.</param>
/// <param name="Provider">nodeId que ejecutó el algoritmo.</param>
/// <param name="Recovered">Bytes recuperados (inverse).</param>
/// <param name="Verification">Veredicto (hash, MAC o firma).</param>
public sealed record V2OperationResult(
    PacketRecord Record,
    V2Package Package,
    bool Delegated,
    string Provider,
    byte[]? Recovered,
    JsonObject? Verification);

/// <summary>Paquete que llegó a la bandeja y se rechazó.</summary>
public sealed record RefusedPacket(DateTimeOffset ReceivedUtc, string SourceIp, string? SourceNode, string? AlgorithmCode, string? FileName, string Code, string Reason, long SizeBytes);

/// <summary>
/// Lógica del estándar v2.0: receptor, proveedor, solicitante, emisor y directorio.
/// </summary>
public sealed class V2NodeService
{
    private static readonly TimeSpan SyncLimit = TimeSpan.FromSeconds(30);

    private readonly V2Identity _identity;
    private readonly Dictionary<string, IV2AlgorithmProvider> _providers;
    private readonly Dictionary<string, IV2AlgorithmProvider> _v3Providers = new(StringComparer.Ordinal);
    private string? _modeFile;
    private string _mode = "v2";
    private readonly NodeDirectory _directory;
    private readonly ReplayGuard _replay;
    private readonly PacketStore _store;
    private readonly HttpClient _http;
    private readonly IRealtimeNotifierPort _notifier;
    private readonly SemaphoreSlim _cryptoSlots = new(10, 10);

    /// <summary>Modo del panel: v1 (formato anterior), v2 (estándar: cada algoritmo con su dueño) o v3 (los 21 locales).</summary>
    public string Mode => _mode;

    /// <summary>Registra los proveedores locales del modo v3 y el archivo donde se guarda el modo elegido.</summary>
    public void EnableV3(IEnumerable<IV2AlgorithmProvider> providers, string modeFile)
    {
        foreach (var provider in providers)
        {
            _v3Providers[provider.Algorithm.Code] = provider;
        }

        _modeFile = modeFile;
        if (File.Exists(modeFile))
        {
            var saved = File.ReadAllText(modeFile).Trim();
            if (saved is "v1" or "v2" or "v3")
            {
                _mode = saved;
            }
        }
    }

    private string? _receptionFile;

    /// <summary>Candado de la bandeja: cerrado (true) exige requestId en los paquetes que llegan; abierto (false) no.</summary>
    public bool RequireRequestId { get; private set; } = true;

    /// <summary>Carga el estado del candado de requestId desde su archivo.</summary>
    public void LoadReception(string file)
    {
        _receptionFile = file;
        if (File.Exists(file) && bool.TryParse(File.ReadAllText(file).Trim(), out var saved))
        {
            RequireRequestId = saved;
        }
    }

    /// <summary>Abre o cierra el candado de requestId y lo guarda.</summary>
    public void SetRequireRequestId(bool value)
    {
        RequireRequestId = value;
        if (_receptionFile is not null)
        {
            File.WriteAllText(_receptionFile, value ? "true" : "false");
        }

        _ = Log("reception.changed", value
            ? "Candado cerrado: los paquetes deben traer requestId."
            : "Candado abierto: se aceptan paquetes sin requestId.");
    }

    /// <summary>Cambia el modo (v1, v2 o v3) y lo guarda.</summary>
    public void SetMode(string mode)
    {
        if (mode is not ("v1" or "v2" or "v3"))
        {
            throw new V2ProtocolException("E-REQUEST", "El modo debe ser v1, v2 o v3.");
        }

        _mode = mode;
        if (_modeFile is not null)
        {
            File.WriteAllText(_modeFile, mode);
        }
    }

    /// <summary>Proveedor que ejecuta el algoritmo en este nodo: los propios siempre; en v3, los 21.</summary>
    public IV2AlgorithmProvider? LocalProvider(string code)
    {
        if (_providers.TryGetValue(code, out var own))
        {
            return own;
        }

        return _mode == "v3" && _v3Providers.TryGetValue(code, out var local) ? local : null;
    }

    private readonly List<RefusedPacket> _refused = new();

    /// <summary>Últimos paquetes que llegaron y se rechazaron (para la bandeja de recibidos).</summary>
    public IReadOnlyList<RefusedPacket> Refused
    {
        get
        {
            lock (_refused)
            {
                return _refused.ToList();
            }
        }
    }

    private void AddRefused(byte[] zipBytes, string sourceIp, string code, string reason)
    {
        string? node = null, algorithm = null, file = null;
        try
        {
            using var zip = new System.IO.Compression.ZipArchive(new MemoryStream(zipBytes), System.IO.Compression.ZipArchiveMode.Read);
            var entry = zip.GetEntry("manifest.json");
            if (entry is not null)
            {
                using var stream = entry.Open();
                var manifest = JsonNode.Parse(stream) as JsonObject;
                node = (string?)manifest?["sourceNode"];
                algorithm = (string?)manifest?["algorithmCode"];
                file = (string?)manifest?["originalFileName"];
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or InvalidOperationException)
        {
        }

        lock (_refused)
        {
            _refused.Insert(0, new RefusedPacket(DateTimeOffset.UtcNow, sourceIp, node, algorithm, file, code, reason, zipBytes.LongLength));
            if (_refused.Count > 100)
            {
                _refused.RemoveAt(_refused.Count - 1);
            }
        }
    }

    /// <summary>Crea el servicio.</summary>
    public V2NodeService(
        V2Identity identity,
        IEnumerable<IV2AlgorithmProvider> providers,
        NodeDirectory directory,
        ReplayGuard replay,
        PacketStore store,
        HttpClient http,
        IRealtimeNotifierPort notifier)
    {
        _identity = identity;
        _providers = providers.ToDictionary(p => p.Algorithm.Code, StringComparer.Ordinal);
        _directory = directory;
        _replay = replay;
        _store = store;
        _http = http;
        _notifier = notifier;
    }

    /// <summary>Identidad del nodo.</summary>
    public V2Identity Identity => _identity;

    /// <summary>Directorio local.</summary>
    public NodeDirectory Directory => _directory;

    /// <summary>Bandeja v2.0.</summary>
    public PacketStore Store => _store;

    /// <summary>Algoritmos que provee este nodo.</summary>
    public IReadOnlyCollection<IV2AlgorithmProvider> Providers => _providers.Values;

    // ------------------------------------------------------------------ Estado y anuncio

    /// <summary>Cuerpo de <c>GET /api/status</c> (10.3).</summary>
    public JsonObject Status(bool acceptingPackages = true) => new()
    {
        ["nodeId"] = _identity.NodeId,
        ["teamNumber"] = _identity.TeamNumber,
        ["protocolVersion"] = V2Format.Version,
        ["status"] = "online",
        ["acceptingPackages"] = acceptingPackages,
        ["httpPort"] = _identity.HttpPort,
        ["httpsPort"] = null,
        ["algorithms"] = new JsonArray(_providers.Values.OrderBy(p => p.Algorithm.Id)
            .Select(p => (JsonNode)new JsonObject { ["algorithmId"] = p.Algorithm.Id, ["algorithmCode"] = p.Algorithm.Code })
            .ToArray()),
        ["certificateThumbprintSha256"] = _identity.Thumbprint,
        ["serverTimeUtc"] = V2Format.Timestamp(DateTimeOffset.UtcNow)
    };

    /// <summary>Cuerpo de <c>GET /api/algorithms</c> (10.4).</summary>
    public JsonObject AlgorithmsProfile() => new()
    {
        ["nodeId"] = _identity.NodeId,
        ["algorithms"] = new JsonArray(_providers.Values.OrderBy(p => p.Algorithm.Id).Select(p => (JsonNode)p.Profile()).ToArray())
    };

    /// <summary>Anuncio UDP (6.1).</summary>
    public byte[] Beacon(string ip, string status = "online") => Encoding.UTF8.GetBytes(new JsonObject
    {
        ["type"] = "CC-BEACON",
        ["protocolVersion"] = V2Format.Version,
        ["nodeId"] = _identity.NodeId,
        ["teamNumber"] = _identity.TeamNumber,
        ["ip"] = ip,
        ["httpPort"] = _identity.HttpPort,
        ["httpsPort"] = null,
        ["status"] = status,
        ["algorithms"] = new JsonArray(_providers.Keys.OrderBy(k => V2Catalog.ByCode(k)!.Id).Select(k => (JsonNode)k).ToArray()),
        ["certificateThumbprintSha256"] = _identity.Thumbprint,
        ["timestampUtc"] = V2Format.Timestamp(DateTimeOffset.UtcNow)
    }.ToJsonString());

    /// <summary>Procesa un anuncio recibido. Devuelve falso si se ignora.</summary>
    public bool HandleBeacon(byte[] datagram)
    {
        if (datagram.Length > 1024)
        {
            return false;
        }

        JsonObject? beacon;
        try
        {
            beacon = JsonNode.Parse(datagram) as JsonObject;
        }
        catch (JsonException)
        {
            return false;
        }

        if (beacon is null
            || (string?)beacon["type"] != "CC-BEACON"
            || (string?)beacon["protocolVersion"] != V2Format.Version
            || beacon["nodeId"] is not JsonValue
            || (string?)beacon["nodeId"] == _identity.NodeId)
        {
            return false;
        }

        var nodeId = (string)beacon["nodeId"]!;
        if (!V2Format.NodeIdPattern().IsMatch(nodeId) || beacon["httpPort"] is null || beacon["ip"] is null)
        {
            return false;
        }

        var before = _directory.Get(nodeId);
        var entry = _directory.Upsert(new DirectoryEntry
        {
            NodeId = nodeId,
            TeamNumber = beacon["teamNumber"]?.GetValue<int>() ?? 0,
            Ip = (string)beacon["ip"]!,
            HttpPort = beacon["httpPort"]!.GetValue<int>(),
            HttpsPort = beacon["httpsPort"] is JsonValue https ? https.GetValue<int>() : null,
            SeenThumbprintSha256 = (string?)beacon["certificateThumbprintSha256"],
            Algorithms = (beacon["algorithms"] as JsonArray)?.Select(a => (string?)a ?? string.Empty).Where(a => a.Length > 0).ToList() ?? [],
            Source = "beacon",
            Status = (string?)beacon["status"] == "offline" ? "offline" : "online"
        });

        if (before is null || before.Status != entry.Status)
        {
            _ = Log("node.beacon", $"Anuncio de {nodeId} ({entry.Ip}:{entry.HttpPort}) — {entry.Status}.");
        }

        if (entry.ThumbprintChanged)
        {
            _ = Log("node.thumbprint_changed", $"¡ALERTA! {nodeId} presenta una huella distinta a la fijada. No se usará hasta que lo aceptes de nuevo.");
        }

        return true;
    }

    // ------------------------------------------------------------------ Directorio

    /// <summary>Alta manual o por escaneo: consulta <c>/api/status</c> del nodo y lo registra.</summary>
    public async Task<DirectoryEntry?> ProbeAsync(string ip, int port, string source, TimeSpan timeout, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            using var response = await _http.GetAsync($"http://{ip}:{port}/api/status", cts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var status = JsonNode.Parse(await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false)) as JsonObject;
            if (status is null)
            {
                return null;
            }

            var nodeId = (string?)status["nodeId"] ?? string.Empty;
            var version = (string?)status["protocolVersion"] ?? "1.0";
            if (nodeId == _identity.NodeId)
            {
                return null;
            }

            var isV2 = version == V2Format.Version && V2Format.NodeIdPattern().IsMatch(nodeId);
            if (isV2 && status["httpPort"] is JsonValue declared && declared.TryGetValue<int>(out var declaredPort) && declaredPort != port)
            {
                // Un nodo v2.0 que también escucha en otro puerto (por ejemplo el 5000 de compatibilidad) se registra solo con el suyo.
                return null;
            }
            var thumb = (string?)status["certificateThumbprintSha256"] ?? (string?)status["certificateThumbprint"];
            var algorithms = status["algorithms"] is JsonArray list
                ? list.Select(a => a is JsonObject o ? (string?)o["algorithmCode"] : (string?)a).Where(a => a is not null).Select(a => a!).ToList()
                : [];
            return _directory.Upsert(new DirectoryEntry
            {
                NodeId = isV2 ? nodeId : $"{(nodeId.Length > 0 ? nodeId : "NODO")}@{ip}:{port}",
                TeamNumber = status["teamNumber"] is JsonValue t ? t.GetValue<int>() : 0,
                Ip = ip,
                HttpPort = port,
                SeenThumbprintSha256 = thumb?.ToUpperInvariant(),
                Algorithms = algorithms,
                Source = source,
                Status = "online",
                ProtocolVersion = isV2 ? V2Format.Version : "1.0"
            });
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Confirma un nodo (6.3): pide estado y certificado, revisa CN y huella, y devuelve la huella para que el usuario la fije.
    /// </summary>
    public async Task<(DirectoryEntry Entry, string Thumbprint, string Subject)> InspectAsync(string nodeId, CancellationToken ct = default)
    {
        var entry = _directory.Get(nodeId) ?? throw new V2ProtocolException("E-REQUEST", $"No hay ningún nodo {nodeId} en el directorio.");
        var pem = await FetchCertificateAsync(entry, ct).ConfigureAwait(false);
        string thumb;
        string subject;
        using (var certificate = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(pem))
        {
            subject = certificate.Subject;
        }

        thumb = V2Format.Thumbprint(pem);
        if (entry.ProtocolVersion == V2Format.Version)
        {
            try
            {
                V2PackageCodec.ValidateCertificate(pem, nodeId);
            }
            catch (V2ProtocolException ex)
            {
                // Se deja confirmar igual: el operador ve el aviso y decide comparando la huella.
                subject += $" · AVISO {ex.Code}: {ex.Message}";
            }
        }

        if (entry.SeenThumbprintSha256 is not null && entry.SeenThumbprintSha256 != thumb)
        {
            throw new V2ProtocolException("E-CERT-THUMBPRINT", "La huella anunciada no coincide con el certificado que entrega el nodo.");
        }

        return (entry, thumb, subject);
    }

    // ------------------------------------------------------------------ Receptor (bandeja)

    /// <summary>Recibe un paquete v2.0 en la bandeja (13.1 completa) y lo deja Pendiente.</summary>
    public async Task<PacketRecord> ReceiveAsync(byte[] zipBytes, string sourceIp, CancellationToken ct = default)
    {
        V2Package package;
        try
        {
            package = V2PackageCodec.Validate(zipBytes, RequireRequestId);
        }
        catch (V2ProtocolException ex)
        {
            AddRefused(zipBytes, sourceIp, ex.Code, ex.Message);
            await Log("package.refused", $"Paquete rechazado de {sourceIp}: {ex.Code} — {ex.Message}").ConfigureAwait(false);
            throw;
        }

        var pinned = _directory.PinnedThumbprint(package.SourceNode);
        var thumb = package.Str("certificateThumbprintSha256").ToUpperInvariant();
        if (pinned is not null && pinned != thumb)
        {
            AddRefused(zipBytes, sourceIp, "E-CERT-UNTRUSTED", "La huella no coincide con la fijada.");
            await Log("package.refused", $"{package.SourceNode} firmó con una huella distinta a la fijada (E-CERT-UNTRUSTED).").ConfigureAwait(false);
            throw new V2ProtocolException("E-CERT-UNTRUSTED", $"La huella de {package.SourceNode} no coincide con la fijada en este nodo.");
        }

        if (!_replay.TryRecord("packet", package.PacketId))
        {
            AddRefused(zipBytes, sourceIp, "E-DUPLICATE", "Ese packetId ya se había recibido.");
            throw new V2ProtocolException("E-DUPLICATE", $"El packetId {package.PacketId} ya se había recibido.");
        }

        var validation = pinned is null ? "Firma OK · Remitente no confirmado" : "Firma OK";
        var record = _store.Add(package, "solicitud", "Recibido", "Pendiente", sourceIp, validation);
        await Log("request.received", $"Solicitud de {package.SourceNode}: {package.AlgorithmCode} {package.Str("operationName")} — {package.FileName} ({validation}).").ConfigureAwait(false);
        return record;
    }

    /// <summary>Acepta una solicitud y la pasa a Consultas (origen Recibido).</summary>
    public PacketRecord Accept(string id)
    {
        var record = _store.Get(id);
        if (record.Kind != "solicitud" || record.Status != "Pendiente")
        {
            throw new V2ProtocolException("E-REQUEST", "Solo se aceptan solicitudes pendientes.");
        }

        record.Status = "Aceptada";
        _store.Save(record);
        var package = Load(id, validate: false);
        var consulta = _store.Add(package, "consulta", "Recibido");
        _ = Log("request.accepted", $"Solicitud {package.FileName} aceptada y movida a Consultas.");
        return consulta;
    }

    /// <summary>Rechaza una solicitud.</summary>
    public PacketRecord Reject(string id)
    {
        var record = _store.Get(id);
        if (record.Kind != "solicitud" || record.Status != "Pendiente")
        {
            throw new V2ProtocolException("E-REQUEST", "Solo se rechazan solicitudes pendientes.");
        }

        record.Status = "Rechazada";
        _store.Save(record);
        _ = Log("request.rejected", $"Solicitud {record.FileName} rechazada.");
        return record;
    }

    // ------------------------------------------------------------------ Proveedor (/api/crypto/*)

    /// <summary>Atiende <c>POST /api/crypto/forward</c> o <c>/inverse</c> (10.6 y 13.2).</summary>
    public async Task<V2Package> ProvideAsync(string operation, V2CryptoRequestParts parts, CancellationToken ct = default)
    {
        if (!await _cryptoSlots.WaitAsync(0, ct).ConfigureAwait(false))
        {
            throw new V2ProtocolException("E-BUSY", "Hay 10 peticiones en curso; intente de nuevo.");
        }

        try
        {
            var (request, requesterCert) = ValidateRequest(operation, parts);
            var requestId = (string)request["requestId"]!;
            var requester = (string)request["requesterNode"]!;
            var algorithm = V2Catalog.ByCode((string?)request["algorithmCode"])!;
            var provider = _providers[algorithm.Code];
            var secrets = OpenSecrets(request, requestId);
            var options = Strings(request["options"] as JsonObject);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(SyncLimit);

            if (operation == "forward")
            {
                if (parts.Payload is null)
                {
                    throw new V2ProtocolException("E-REQUEST", "forward requiere la parte payload.");
                }

                var fileName = (string?)request["originalFileName"] is { Length: > 0 } n ? Path.GetFileName(n) : "mensaje.txt";
                var output = await Task.Run(() => provider.Forward(new V2ForwardInput(
                    parts.Payload,
                    parts.Cover,
                    (string?)request["payloadMode"] ?? "file",
                    fileName,
                    options,
                    secrets)), timeout.Token).ConfigureAwait(false);
                var package = V2PackageCodec.Build(new V2PackageSpec
                {
                    RequestId = requestId,
                    Algorithm = algorithm,
                    AlgorithmName = output.AlgorithmName,
                    Operation = "forward",
                    PayloadMode = output.PayloadMode,
                    OriginalFileName = fileName,
                    OriginalSizeBytes = parts.Payload.LongLength,
                    ContentType = Mime(fileName),
                    Data = output.Data,
                    PublicParameters = output.PublicParameters
                }, _identity);
                await Log("provider.forward", $"{requester} pidió {algorithm.Code} {algorithm.ForwardName}: entregado {package.FileName}.").ConfigureAwait(false);
                return package;
            }

            if (parts.Package is null)
            {
                throw new V2ProtocolException("E-REQUEST", "inverse requiere la parte package.");
            }

            var incoming = V2PackageCodec.Validate(parts.Package);
            var pinned = _directory.PinnedThumbprint(incoming.SourceNode);
            if (pinned is not null && pinned != incoming.Str("certificateThumbprintSha256"))
            {
                throw new V2ProtocolException("E-CERT-UNTRUSTED", $"La huella de {incoming.SourceNode} no coincide con la fijada.");
            }

            if (incoming.AlgorithmCode != algorithm.Code)
            {
                throw new V2ProtocolException("E-PARAMS", "El paquete es de otro algoritmo que el indicado en la petición.");
            }

            var inverse = await Task.Run(() => provider.Inverse(incoming.Data, incoming.PublicParameters, secrets), timeout.Token).ConfigureAwait(false);
            var result = BuildResult(incoming, algorithm, requestId, requester, requesterCert, inverse);
            await Log("provider.inverse", $"{requester} pidió {algorithm.Code} {algorithm.InverseName} de {incoming.FileName}: resultado cifrado para {requester}.").ConfigureAwait(false);
            return result;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new V2ProtocolException("E-TIMEOUT", "La operación pasó de 30 s.");
        }
        finally
        {
            _cryptoSlots.Release();
        }
    }

    // ------------------------------------------------------------------ Panel: operar (local o delegado)

    /// <summary>
    /// Ejecuta forward con el algoritmo indicado: local si es propio, o pidiéndolo al dueño (11.2).
    /// </summary>
    public async Task<V2OperationResult> ForwardAsync(
        string algorithmCode,
        byte[] payload,
        string fileName,
        string payloadMode,
        byte[]? cover,
        IReadOnlyDictionary<string, string> options,
        IReadOnlyDictionary<string, string> secrets,
        string? providerNode,
        CancellationToken ct = default)
    {
        var algorithm = V2Catalog.ByCode(algorithmCode) ?? throw new V2ProtocolException("E-ALGORITHM", $"No existe {algorithmCode}.");
        V2Package package;
        string provider;
        var delegated = false;
        var own = LocalProvider(algorithm.Code);
        if (own is not null && (providerNode is null || providerNode == _identity.NodeId))
        {
            var output = own.Forward(new V2ForwardInput(payload, cover, payloadMode, fileName, options, secrets));
            package = V2PackageCodec.Build(new V2PackageSpec
            {
                Algorithm = algorithm,
                AlgorithmName = output.AlgorithmName,
                Operation = "forward",
                PayloadMode = output.PayloadMode,
                OriginalFileName = fileName,
                OriginalSizeBytes = payload.LongLength,
                ContentType = Mime(fileName),
                Data = output.Data,
                PublicParameters = output.PublicParameters
            }, _identity);
            provider = _identity.NodeId;
        }
        else
        {
            var target = ResolveProvider(algorithm, providerNode);
            package = await DelegateAsync(target, algorithm, "forward", payloadMode, fileName, options, secrets, payload, cover, null, ct).ConfigureAwait(false);
            provider = target.NodeId;
            delegated = true;
        }

        var record = _store.Add(package, "consulta", "Generado");
        record.Note = delegated ? $"Producido por {provider} (delegado)" : _providers.ContainsKey(algorithm.Code) ? "Producido localmente" : "Producido localmente (modo v3)";
        _store.Save(record);
        await Log("operate.forward", $"{algorithm.Code} {algorithm.ForwardName} de {fileName} por {provider}: {package.FileName}.").ConfigureAwait(false);
        return new V2OperationResult(record, package, delegated, provider, null, null);
    }

    /// <summary>
    /// Ejecuta inverse sobre un paquete de Consultas: local si el algoritmo es propio, o con el dueño (11.4).
    /// </summary>
    public async Task<V2OperationResult> InverseAsync(
        string consultaId,
        IReadOnlyDictionary<string, string> secrets,
        string? providerNode,
        CancellationToken ct = default)
    {
        var source = Load(consultaId, validate: false);
        var algorithm = V2Catalog.ByCode(source.AlgorithmCode) ?? throw new V2ProtocolException("E-ALGORITHM", "Algoritmo desconocido.");
        V2Package result;
        string provider;
        var delegated = false;
        var own = LocalProvider(algorithm.Code);
        if (own is not null && !_providers.ContainsKey(algorithm.Code) && source.ProducerNode != _identity.NodeId
            && source.PublicParameters.GetValueOrDefault("mode") != "v3-local")
        {
            // En v3 solo se invierte local lo que se produjo en modo v3; lo de otro equipo lo invierte su dueño.
            own = null;
        }

        if (own is not null && (providerNode is null || providerNode == _identity.NodeId))
        {
            var requestId = V2Format.NewUuid();
            var inverse = own.Inverse(source.Data, source.PublicParameters, secrets);
            result = BuildResult(source, algorithm, requestId, _identity.NodeId, _identity.CertificatePem, inverse);
            provider = _identity.NodeId;
        }
        else
        {
            var target = ResolveProvider(algorithm, providerNode);
            // El dueño valida la ventana de ±10 min: se reempaqueta con fecha nueva y firma propia (9.6).
            var fresh = V2PackageCodec.Rewrap(source, _identity);
            result = await DelegateAsync(target, algorithm, "inverse", source.Str("payloadMode"), source.Str("originalFileName"),
                new Dictionary<string, string>(), secrets, null, null, fresh.ZipBytes, ct, KeyIdOf(source)).ConfigureAwait(false);
            provider = target.NodeId;
            delegated = true;
        }

        var envelope = result.Manifest["resultEnvelope"] as JsonObject
                       ?? throw new V2ProtocolException("E-MANIFEST", "El resultado no trae resultEnvelope.");
        var original = CcEnvelope.Open(envelope, result.Data, _identity.NodeId, _identity.Thumbprint, _identity.PrivateKeyPem, result.PacketId);
        var record = _store.Add(result, "consulta", "Resultado");
        var name = source.Str("originalFileName");
        _store.SaveRecovered(record.Id, string.IsNullOrEmpty(name) ? "recuperado.bin" : name, original);
        var verification = result.Manifest["verification"] as JsonObject;
        record = _store.Get(record.Id);
        record.Note = (delegated ? $"Invertido por {provider}" : "Invertido localmente")
                      + (verification is not null ? $" · válido: {verification["valid"]}" : string.Empty);
        _store.Save(record);
        await Log("operate.inverse", $"{algorithm.Code} {algorithm.InverseName} de {source.FileName} por {provider}: {original.Length} bytes recuperados.").ConfigureAwait(false);
        return new V2OperationResult(record, result, delegated, provider, original, verification);
    }

    /// <summary>Envía un paquete de Consultas a la bandeja de otro nodo, reempaquetado con firma propia (9.6 y 11.3).</summary>
    public async Task<string> SendAsync(string consultaId, string target, CancellationToken ct = default)
    {
        var package = V2PackageCodec.Rewrap(Load(consultaId, validate: false), _identity);
        var url = TargetUrl(target);
        using var content = new MultipartFormDataContent();
        var file = new ByteArrayContent(package.ZipBytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        content.Add(file, "package", package.FileName);
        using var message = new HttpRequestMessage(HttpMethod.Post, url + "/api/requests/receive") { Content = content };
        AddHeaders(message, package.PacketId);
        using var response = await _http.SendAsync(message, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw RemoteError(response.StatusCode, body, url);
        }

        await Log("package.sent", $"{package.FileName} enviado a la bandeja de {url} (HTTP {(int)response.StatusCode}).").ConfigureAwait(false);
        return package.FileName;
    }

    /// <summary>Carga un paquete de la bandeja.</summary>
    public V2Package Load(string id, bool validate)
    {
        var zip = _store.ZipBytes(id);
        if (validate)
        {
            return V2PackageCodec.Validate(zip);
        }

        using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(zip), System.IO.Compression.ZipArchiveMode.Read);
        byte[] Read(string name)
        {
            using var s = archive.GetEntry(name)!.Open();
            using var b = new MemoryStream();
            s.CopyTo(b);
            return b.ToArray();
        }

        var manifest = (JsonObject)JsonNode.Parse(Read("manifest.json"))!;
        var dataName = archive.GetEntry("resultado.enc") is not null ? "resultado.enc" : "datos.enc";
        return new V2Package(zip, _store.Get(id).FileName, manifest, Read(dataName), Encoding.UTF8.GetString(Read("certificado.pem")));
    }

    // ------------------------------------------------------------------ Internos

    private V2Package BuildResult(V2Package source, V2Algorithm algorithm, string requestId, string requester, string requesterCert, V2InverseOutput inverse)
    {
        var packetId = V2Format.NewUuid();
        var (envelope, ciphertext) = CcEnvelope.Seal(inverse.Original, requester, requesterCert, packetId);
        return V2PackageCodec.Build(new V2PackageSpec
        {
            PacketType = "result",
            PacketId = packetId,
            RequestId = requestId,
            Algorithm = algorithm,
            AlgorithmName = source.Str("algorithmName"),
            Operation = "inverse",
            PayloadMode = source.Str("payloadMode") is { Length: > 0 } mode ? mode : "file",
            OriginalFileName = source.Str("originalFileName") is { Length: > 0 } name ? name : "recuperado.bin",
            OriginalSizeBytes = inverse.Original.LongLength,
            ContentType = source.Str("contentType") is { Length: > 0 } type ? type : "application/octet-stream",
            Data = ciphertext,
            Verification = inverse.Verification,
            ResultEnvelope = CcEnvelope.WithoutCiphertext(envelope)
        }, _identity);
    }

    private (JsonObject Request, string RequesterCert) ValidateRequest(string operation, V2CryptoRequestParts parts)
    {
        if (parts.Request is null || parts.RequestSignature is null || parts.RequesterCertificate is null)
        {
            throw new V2ProtocolException("E-REQUEST", "Faltan las partes request, requestSignature o requesterCertificate.");
        }

        if ((parts.Payload?.LongLength ?? 0) + (parts.Cover?.LongLength ?? 0) + (parts.Package?.LongLength ?? 0) > V2Format.MaxBodyBytes)
        {
            throw new V2ProtocolException("E-SIZE", "La petición supera 50 MB.");
        }

        JsonObject request;
        try
        {
            request = JsonNode.Parse(parts.Request) as JsonObject ?? throw new JsonException();
        }
        catch (JsonException)
        {
            throw new V2ProtocolException("E-REQUEST", "La parte request no es JSON válido.");
        }

        string Text(string name) => request[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : string.Empty;
        if (Text("version") != V2Format.Version)
        {
            throw new V2ProtocolException("E-VERSION", "La petición debe ser versión 2.0.");
        }

        if (!V2Format.UuidPattern().IsMatch(Text("requestId")) || !V2Format.NodeIdPattern().IsMatch(Text("requesterNode")))
        {
            throw new V2ProtocolException("E-REQUEST", "requestId o requesterNode con formato inválido.");
        }

        if (Text("operation") != operation)
        {
            throw new V2ProtocolException("E-REQUEST", $"La operación de la petición no es {operation}.");
        }

        var requester = Text("requesterNode");
        var thumb = V2PackageCodec.ValidateCertificate(parts.RequesterCertificate, requester);
        var pinned = _directory.PinnedThumbprint(requester);
        if (pinned is not null && pinned != thumb)
        {
            throw new V2ProtocolException("E-CERT-UNTRUSTED", $"La huella de {requester} no coincide con la fijada.");
        }

        if (!V2PackageCodec.VerifySignature(parts.RequesterCertificate, parts.Request, parts.RequestSignature.Trim()))
        {
            throw new V2ProtocolException("E-REQUEST-SIGNATURE", "requestSignature no es válida para la parte request.");
        }

        if (Text("targetNode") != _identity.NodeId)
        {
            throw new V2ProtocolException("E-REQUEST", $"targetNode es {Text("targetNode")}, no {_identity.NodeId}.");
        }

        if (!V2Format.TryParseTimestamp(Text("timestampUtc"), out var stamp) || (DateTimeOffset.UtcNow - stamp).Duration() > V2Format.TimeWindow)
        {
            throw new V2ProtocolException("E-TIMESTAMP", "timestampUtc de la petición fuera de la ventana de ±10 min.");
        }

        if (!_replay.TryRecord("request", Text("requestId")))
        {
            throw new V2ProtocolException("E-DUPLICATE", "Ese requestId ya se había recibido.");
        }

        if (!_providers.ContainsKey(Text("algorithmCode")))
        {
            throw new V2ProtocolException("E-ALGORITHM-NOT-PROVIDED", $"{_identity.NodeId} no provee {Text("algorithmCode")}.");
        }

        return (request, parts.RequesterCertificate);
    }

    private Dictionary<string, string> OpenSecrets(JsonObject request, string requestId)
    {
        if (request["secrets"] is not JsonObject envelope)
        {
            return new Dictionary<string, string>();
        }

        var bytes = CcEnvelope.Open(envelope, null, _identity.NodeId, _identity.Thumbprint, _identity.PrivateKeyPem, requestId);
        try
        {
            return Strings(JsonNode.Parse(bytes) as JsonObject ?? throw new JsonException());
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            throw new V2ProtocolException("E-PARAMS", "Los secretos deben ser un objeto JSON de cadenas.");
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    private DirectoryEntry ResolveProvider(V2Algorithm algorithm, string? preferred)
    {
        var candidates = _directory.List().Where(e => e.ProtocolVersion == V2Format.Version).ToList();
        DirectoryEntry? target = preferred is not null
            ? candidates.FirstOrDefault(e => e.NodeId == preferred)
            : candidates.FirstOrDefault(e => e.NodeId == algorithm.OwnerNode)
              ?? candidates.Where(e => e.Algorithms.Contains(algorithm.Code)).OrderBy(e => e.TeamNumber).FirstOrDefault();
        if (target is null)
        {
            throw new V2ProtocolException("E-ALGORITHM-NOT-PROVIDED",
                $"{algorithm.Code} no disponible: {(algorithm.OwnerNode ?? "ningún nodo")} no está en el directorio.");
        }

        if (target.ThumbprintChanged)
        {
            throw new V2ProtocolException("E-CERT-UNTRUSTED", $"{target.NodeId} cambió de huella; acéptalo de nuevo en Red.");
        }

        if (target.PinnedThumbprintSha256 is null)
        {
            throw new V2ProtocolException("E-CERT-UNTRUSTED", $"Confirma primero la huella de {target.NodeId} en la sección Red.");
        }

        return target;
    }

    /// <summary>
    /// keyId del paquete (keyRef.keyId, o publicParameters.keyId si no hay keyRef): el dueño lo usa en inverse
    /// para encontrar la llave que guardó al cifrar (13.2).
    /// </summary>
    private static string? KeyIdOf(V2Package source)
    {
        var fromRef = source.Manifest["keyRef"] is JsonObject keyRef && keyRef["keyId"] is JsonValue v && v.TryGetValue<string>(out var id) ? id : null;
        if (!string.IsNullOrWhiteSpace(fromRef))
        {
            return fromRef;
        }

        var fromParams = source.PublicParameters.GetValueOrDefault("keyId");
        return string.IsNullOrWhiteSpace(fromParams) ? null : fromParams;
    }

    private async Task<V2Package> DelegateAsync(
        DirectoryEntry target,
        V2Algorithm algorithm,
        string operation,
        string payloadMode,
        string fileName,
        IReadOnlyDictionary<string, string> options,
        IReadOnlyDictionary<string, string> secrets,
        byte[]? payload,
        byte[]? cover,
        byte[]? package,
        CancellationToken ct,
        string? keyId = null)
    {
        var targetCert = await FetchCertificateAsync(target, ct).ConfigureAwait(false);
        if (V2Format.Thumbprint(targetCert) != target.PinnedThumbprintSha256)
        {
            throw new V2ProtocolException("E-CERT-UNTRUSTED", $"El certificado de {target.NodeId} no coincide con la huella fijada.");
        }

        var requestId = V2Format.NewUuid();
        var optionsJson = new JsonObject();
        foreach (var pair in options)
        {
            optionsJson[pair.Key] = pair.Value;
        }

        JsonObject? secretsEnvelope = null;
        if (secrets.Count > 0)
        {
            var secretJson = new JsonObject();
            foreach (var pair in secrets)
            {
                secretJson[pair.Key] = pair.Value;
            }

            secretsEnvelope = CcEnvelope.Seal(Encoding.UTF8.GetBytes(secretJson.ToJsonString()), target.NodeId, targetCert, requestId).Envelope;
        }

        var request = new JsonObject
        {
            ["version"] = V2Format.Version,
            ["requestId"] = requestId,
            ["requesterNode"] = _identity.NodeId,
            ["targetNode"] = target.NodeId,
            ["timestampUtc"] = V2Format.Timestamp(DateTimeOffset.UtcNow),
            ["algorithmCode"] = algorithm.Code,
            ["operation"] = operation,
            ["payloadMode"] = payloadMode,
            ["originalFileName"] = fileName,
            ["options"] = optionsJson,
            ["keyId"] = string.IsNullOrEmpty(keyId) ? null : keyId,
            ["secrets"] = secretsEnvelope
        };
        var requestBytes = Encoding.UTF8.GetBytes(request.ToJsonString());

        using var content = new MultipartFormDataContent();
        var requestPart = new ByteArrayContent(requestBytes);
        requestPart.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Add(requestPart, "request");
        content.Add(new StringContent(Convert.ToBase64String(_identity.SignBytes(requestBytes))), "requestSignature");
        content.Add(new StringContent(_identity.CertificatePem), "requesterCertificate");
        if (payload is not null)
        {
            content.Add(new ByteArrayContent(payload), "payload", fileName);
        }

        if (cover is not null)
        {
            content.Add(new ByteArrayContent(cover), "cover", "cover");
        }

        if (package is not null)
        {
            var zip = new ByteArrayContent(package);
            zip.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
            content.Add(zip, "package", "package.zip");
        }

        using var message = new HttpRequestMessage(HttpMethod.Post, $"{target.BaseUrl}/api/crypto/{operation}") { Content = content };
        AddHeaders(message, requestId);
        using var response = await _http.SendAsync(message, ct).ConfigureAwait(false);
        byte[] zipBytes;
        if (response.StatusCode == HttpStatusCode.Accepted)
        {
            var job = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)) as JsonObject;
            zipBytes = await PollJobAsync(target, job, requestId, ct).ConfigureAwait(false);
        }
        else if (!response.IsSuccessStatusCode)
        {
            throw RemoteError(response.StatusCode, await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false), target.NodeId);
        }
        else
        {
            zipBytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        }

        var produced = V2PackageCodec.Validate(zipBytes);
        if (produced.SourceNode != target.NodeId || produced.Str("certificateThumbprintSha256") != target.PinnedThumbprintSha256)
        {
            throw new V2ProtocolException("E-CERT-UNTRUSTED", $"El paquete devuelto no viene firmado por {target.NodeId}.");
        }

        _replay.TryRecord("packet", produced.PacketId);
        return produced;
    }

    private async Task<byte[]> PollJobAsync(DirectoryEntry target, JsonObject? job, string requestId, CancellationToken ct)
    {
        var statusUrl = (string?)job?["statusUrl"] ?? $"/api/jobs/{(string?)job?["jobId"]}";
        var wait = TimeSpan.FromSeconds(Math.Clamp(job?["retryAfterSeconds"]?.GetValue<int>() ?? 5, 1, 30));
        for (var attempt = 0; attempt < 60; attempt++)
        {
            await Task.Delay(wait, ct).ConfigureAwait(false);
            using var message = new HttpRequestMessage(HttpMethod.Get, target.BaseUrl + statusUrl);
            AddHeaders(message, requestId);
            using var response = await _http.SendAsync(message, ct).ConfigureAwait(false);
            var state = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false)) as JsonObject;
            switch ((string?)state?["state"])
            {
                case "done":
                    using (var get = new HttpRequestMessage(HttpMethod.Get, target.BaseUrl + ((string?)state!["resultUrl"] ?? statusUrl + "/result")))
                    {
                        AddHeaders(get, requestId);
                        using var result = await _http.SendAsync(get, ct).ConfigureAwait(false);
                        return await result.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                    }

                case "failed":
                    throw new V2ProtocolException("E-INTERNAL", $"{target.NodeId} no pudo completar el trabajo: {state!["error"]}");
            }
        }

        throw new V2ProtocolException("E-TIMEOUT", $"{target.NodeId} no terminó el trabajo a tiempo.");
    }

    private async Task<string> FetchCertificateAsync(DirectoryEntry entry, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(HttpMethod.Get, entry.BaseUrl + "/api/certificate");
        AddHeaders(message, V2Format.NewUuid());
        using var response = await _http.SendAsync(message, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var pem = response.IsSuccessStatusCode ? V2Format.ExtractCertificatePem(body) : null;
        if (pem is null)
        {
            var sample = body.Length > 160 ? body[..160] + "…" : body;
            throw new V2ProtocolException("E-CERT", $"{entry.NodeId} no entregó un certificado legible en /api/certificate (HTTP {(int)response.StatusCode}): {sample}");
        }

        return pem;
    }

    private string TargetUrl(string target)
    {
        var entry = _directory.Get(target);
        if (entry is not null)
        {
            if (entry.ThumbprintChanged)
            {
                throw new V2ProtocolException("E-CERT-UNTRUSTED", $"{entry.NodeId} cambió de huella; acéptalo de nuevo en Red.");
            }

            return entry.BaseUrl;
        }

        var text = target.Trim().TrimEnd('/');
        return text.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? text : "http://" + text;
    }

    private void AddHeaders(HttpRequestMessage message, string requestId)
    {
        message.Headers.TryAddWithoutValidation("X-CC-Node", _identity.NodeId);
        message.Headers.TryAddWithoutValidation("X-CC-Protocol", V2Format.Version);
        message.Headers.TryAddWithoutValidation("X-CC-Request-Id", requestId);
    }

    private static V2ProtocolException RemoteError(HttpStatusCode status, string body, string who)
    {
        try
        {
            if (JsonNode.Parse(body) is JsonObject problem && problem["code"] is JsonValue)
            {
                return new V2ProtocolException((string)problem["code"]!, $"{who} respondió {(int)status}: {(string?)problem["detail"] ?? (string?)problem["title"]}");
            }

            if (JsonNode.Parse(body) is JsonObject simple && simple["error"] is JsonValue)
            {
                return new V2ProtocolException(Classify(status), $"{who} respondió {(int)status}: {(string?)simple["error"]}");
            }
        }
        catch (JsonException)
        {
        }

        return new V2ProtocolException(Classify(status), $"{who} respondió {(int)status}: {(body.Length > 200 ? body[..200] : body)}");
    }

    private static string Classify(HttpStatusCode status) => (int)status switch
    {
        413 => "E-SIZE",
        409 => "E-DUPLICATE",
        422 => "E-SIGNATURE",
        404 => "E-ALGORITHM-NOT-PROVIDED",
        503 => "E-BUSY",
        _ => "E-INTERNAL"
    };

    private static Dictionary<string, string> Strings(JsonObject? node)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (node is null)
        {
            return result;
        }

        foreach (var pair in node)
        {
            if (pair.Value is JsonValue value)
            {
                result[pair.Key] = value.TryGetValue<string>(out var s) ? s : value.ToJsonString();
            }
        }

        return result;
    }

    /// <summary>Tipo MIME por extensión.</summary>
    public static string Mime(string fileName) => Path.GetExtension(fileName).ToLowerInvariant() switch
    {
        ".txt" => "text/plain",
        ".pdf" => "application/pdf",
        ".png" => "image/png",
        ".bmp" => "image/bmp",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".json" => "application/json",
        ".zip" => "application/zip",
        ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".mp4" => "video/mp4",
        ".mp3" => "audio/mpeg",
        _ => "application/octet-stream"
    };

    private Task Log(string type, string message) =>
        _notifier.NotifyAsync(new NodeEventNotification(type, message, DateTimeOffset.UtcNow));
}
