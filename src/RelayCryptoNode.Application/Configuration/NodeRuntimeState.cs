using RelayCryptoNode.Domain.Catalog;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;

namespace RelayCryptoNode.Application.Configuration;

/// <summary>
/// Configuración operativa del nodo que puede cambiarse en caliente desde el panel o la API.
/// </summary>
/// <param name="NodeId">Identificador del nodo en mayúsculas (por ejemplo <c>NODO06</c>).</param>
/// <param name="PublicEndpoint">Dirección base con la que otros nodos alcanzan a este nodo.</param>
/// <param name="Role">Rol activo del nodo.</param>
/// <param name="NextNodeEndpoint">Dirección base del siguiente nodo de la cadena (rol Initial o Intermediate).</param>
/// <param name="OutgoingAlgorithmCode">Código oficial del algoritmo con el que se cifra la salida.</param>
/// <param name="KeyExchange">Mecanismo de envoltura de la clave de sesión para la salida.</param>
/// <param name="AutoProcess">Si es verdadero, las solicitudes válidas se aceptan y procesan sin intervención.</param>
/// <param name="SharedKeyFormat">
/// Si es verdadero, la salida usa el formato de clave compartida del grupo (compatible con NODO04, solo AES-GCM)
/// en lugar de envolver una clave de sesión.
/// </param>
public sealed record NodeRuntimeSnapshot(
    string NodeId,
    string PublicEndpoint,
    NodeRole Role,
    string? NextNodeEndpoint,
    string OutgoingAlgorithmCode,
    KeyExchangeAlgorithmType KeyExchange,
    bool AutoProcess,
    bool SharedKeyFormat = false);

/// <summary>
/// Estado mutable y seguro entre hilos con la configuración operativa del nodo.
/// </summary>
public sealed class NodeRuntimeState
{
    private readonly object _sync = new();
    private NodeRuntimeSnapshot _current;
    private string? _preSharedKey;
    private string _sharedAesKey = DefaultSharedAesKey;

    /// <summary>
    /// Clave AES compartida por defecto del grupo (la misma que trae el NODO04 en su configuración).
    /// </summary>
    public const string DefaultSharedAesKey = "clave-aes-256-segura";

    /// <summary>
    /// Crea el estado inicial del nodo.
    /// </summary>
    public NodeRuntimeState(NodeRuntimeSnapshot initial, string? preSharedKey = null)
    {
        _current = Validate(initial);
        _preSharedKey = string.IsNullOrWhiteSpace(preSharedKey) ? null : preSharedKey;
    }

    /// <summary>
    /// Se dispara cada vez que cambia la configuración.
    /// </summary>
    public event Action<NodeRuntimeSnapshot>? Changed;

    /// <summary>
    /// Copia inmutable de la configuración vigente.
    /// </summary>
    public NodeRuntimeSnapshot Current
    {
        get
        {
            lock (_sync)
            {
                return _current;
            }
        }
    }

    /// <summary>
    /// Indica si hay una clave precompartida configurada (nunca se expone su valor).
    /// </summary>
    public bool HasPreSharedKey
    {
        get
        {
            lock (_sync)
            {
                return _preSharedKey is not null;
            }
        }
    }

    /// <summary>
    /// Devuelve la clave precompartida del grupo (solo para adaptadores de envoltura de clave).
    /// </summary>
    public string? GetPreSharedKey()
    {
        lock (_sync)
        {
            return _preSharedKey;
        }
    }

    /// <summary>
    /// Reemplaza la configuración vigente.
    /// </summary>
    public NodeRuntimeSnapshot Update(NodeRuntimeSnapshot updated)
    {
        var validated = Validate(updated);
        lock (_sync)
        {
            _current = validated;
        }

        Changed?.Invoke(validated);
        return validated;
    }

    /// <summary>
    /// Cambia la clave precompartida del grupo. Una cadena vacía la elimina.
    /// </summary>
    public void SetPreSharedKey(string? preSharedKey)
    {
        lock (_sync)
        {
            _preSharedKey = string.IsNullOrWhiteSpace(preSharedKey) ? null : preSharedKey;
        }

        Changed?.Invoke(Current);
    }

    /// <summary>
    /// Clave de texto para AES-GCM en el modo de clave compartida con otros equipos.
    /// </summary>
    public string SharedAesKey
    {
        get
        {
            lock (_sync)
            {
                return _sharedAesKey;
            }
        }

        set
        {
            lock (_sync)
            {
                _sharedAesKey = string.IsNullOrWhiteSpace(value) ? DefaultSharedAesKey : value.Trim();
            }
        }
    }

    private static NodeRuntimeSnapshot Validate(NodeRuntimeSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (string.IsNullOrWhiteSpace(snapshot.NodeId) || snapshot.NodeId.Any(char.IsWhiteSpace))
        {
            throw new DomainException("El identificador del nodo no puede estar vacío ni tener espacios.", "NODE_ID_INVALID");
        }

        if (string.IsNullOrWhiteSpace(snapshot.PublicEndpoint))
        {
            throw new DomainException("La dirección pública del nodo es obligatoria.", "NODE_ENDPOINT_EMPTY");
        }

        var code = OfficialAlgorithmCatalog.ParseOrThrow(snapshot.OutgoingAlgorithmCode);
        var descriptor = OfficialAlgorithmCatalog.GetByCode(code);
        if (descriptor.CipherAlgorithm is null)
        {
            throw new UnsupportedAlgorithmException(
                snapshot.OutgoingAlgorithmCode,
                $"El algoritmo '{descriptor.OfficialCode}' no cifra carga útil; elija uno de cifrado.");
        }

        return snapshot with
        {
            NodeId = snapshot.NodeId.Trim().ToUpperInvariant(),
            PublicEndpoint = snapshot.PublicEndpoint.Trim().TrimEnd('/'),
            NextNodeEndpoint = string.IsNullOrWhiteSpace(snapshot.NextNodeEndpoint)
                ? null
                : snapshot.NextNodeEndpoint.Trim().TrimEnd('/'),
            OutgoingAlgorithmCode = descriptor.OfficialCode
        };
    }
}
