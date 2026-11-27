using System.Text.Json.Nodes;

namespace RelayCryptoNode.Infrastructure.ProtocolV2.Providers;

/// <summary>Entrada de una operación <c>forward</c>.</summary>
/// <param name="Payload">Archivo, texto o imagen a procesar.</param>
/// <param name="Cover">Imagen portadora (solo LSBSTEGO).</param>
/// <param name="PayloadMode">Modo de la carga.</param>
/// <param name="FileName">Nombre original.</param>
/// <param name="Options">Parámetros públicos elegidos por el usuario.</param>
/// <param name="Secrets">Secretos (ya fuera del sobre).</param>
public sealed record V2ForwardInput(
    byte[] Payload,
    byte[]? Cover,
    string PayloadMode,
    string FileName,
    IReadOnlyDictionary<string, string> Options,
    IReadOnlyDictionary<string, string> Secrets);

/// <summary>Salida de <c>forward</c>: contenido de datos.enc y parámetros públicos.</summary>
/// <param name="Data">Bytes de datos.enc.</param>
/// <param name="PublicParameters">Parámetros públicos del manifiesto.</param>
/// <param name="PayloadMode">Modo final de la carga (por ejemplo <c>image</c>).</param>
/// <param name="AlgorithmName">Variante usada.</param>
/// <param name="PacketId">packetId fijo cuando el cifrado depende de él (AAD de AESGCM, tabla 4.2).</param>
/// <param name="KeyRef">keyRef del manifiesto (<c>keyId</c> y <c>ownerNode</c>) cuando el dueño guarda la llave.</param>
public sealed record V2ForwardOutput(
    byte[] Data,
    Dictionary<string, string> PublicParameters,
    string PayloadMode,
    string AlgorithmName,
    string? PacketId = null,
    JsonObject? KeyRef = null);

/// <summary>Salida de <c>inverse</c>.</summary>
/// <param name="Original">Bytes recuperados.</param>
/// <param name="Verification">Veredicto (solo hash, MAC o firma).</param>
public sealed record V2InverseOutput(byte[] Original, JsonObject? Verification = null);

/// <summary>
/// Algoritmo que este nodo provee a los demás (rol Proveedor).
/// </summary>
public interface IV2AlgorithmProvider
{
    /// <summary>Fila de la tabla 4.1.</summary>
    V2Algorithm Algorithm { get; }

    /// <summary>Perfil para <c>GET /api/algorithms</c> (10.4).</summary>
    JsonObject Profile();

    /// <summary>Ejecuta <c>forward</c>.</summary>
    V2ForwardOutput Forward(V2ForwardInput input);

    /// <summary>Ejecuta <c>inverse</c> sobre datos.enc con sus parámetros públicos.</summary>
    V2InverseOutput Inverse(byte[] data, IReadOnlyDictionary<string, string> publicParameters, IReadOnlyDictionary<string, string> secrets);
}
