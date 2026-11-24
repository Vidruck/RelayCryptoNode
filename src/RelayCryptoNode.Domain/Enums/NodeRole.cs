namespace RelayCryptoNode.Domain.Enums;

/// <summary>
/// Define el rol operativo activo del nodo dentro de la cadena criptográfica de relevo.
/// </summary>
public enum NodeRole
{
    /// <summary>
    /// Nodo emisor inicial: empaqueta, calcula la huella testigo original, cifra, firma y transmite.
    /// </summary>
    Initial = 1,

    /// <summary>
    /// Nodo intermedio de relevo: valida, autodetecta el algoritmo entrante, descifra en memoria RAM, re-encripta con el algoritmo configurado y reenvía.
    /// </summary>
    Intermediate = 2,

    /// <summary>
    /// Nodo receptor final: valida, descifra y ejecuta auditoría de integridad bit a bit contra el paquete original.
    /// </summary>
    Final = 3
}
