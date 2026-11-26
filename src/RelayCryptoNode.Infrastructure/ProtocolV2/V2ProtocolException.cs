namespace RelayCryptoNode.Infrastructure.ProtocolV2;

/// <summary>
/// Error del estándar v2.0 con código del Anexo B; el WebHost lo responde como <c>application/problem+json</c>.
/// </summary>
public sealed class V2ProtocolException : Exception
{
    private static readonly Dictionary<string, (int Status, string Title)> Catalog = new()
    {
        ["E-SIZE"] = (413, "Paquete demasiado grande"),
        ["E-ZIP-INVALID"] = (400, "No es un zip válido"),
        ["E-ZIP-STRUCTURE"] = (400, "Estructura del zip inválida"),
        ["E-ZIP-BOMB"] = (400, "Zip demasiado grande al descomprimir"),
        ["E-MANIFEST"] = (400, "Manifiesto inválido"),
        ["E-VERSION"] = (400, "Versión no soportada"),
        ["E-ALGORITHM"] = (400, "Algoritmo inexistente o inconsistente"),
        ["E-PARAMS"] = (400, "Parámetros inválidos"),
        ["E-REQUEST"] = (400, "Petición mal formada"),
        ["E-REQUEST-SIGNATURE"] = (401, "Firma de la petición inválida"),
        ["E-ENV-RECIPIENT"] = (401, "El sobre no es para este nodo"),
        ["E-ENV-DECRYPT"] = (401, "No se pudo abrir el sobre"),
        ["E-CERT-UNTRUSTED"] = (403, "Huella distinta a la fijada"),
        ["E-ALGORITHM-NOT-PROVIDED"] = (404, "Este nodo no provee el algoritmo"),
        ["E-KEY-NOT-FOUND"] = (404, "keyId desconocido"),
        ["E-KEY-FORBIDDEN"] = (403, "keyId no permitido"),
        ["E-JOB-NOT-FOUND"] = (404, "Trabajo desconocido"),
        ["E-DUPLICATE"] = (409, "Paquete o petición repetida"),
        ["E-UNSUPPORTED-MEDIA"] = (415, "Tipo de contenido no soportado"),
        ["E-HASH"] = (422, "Integridad inválida"),
        ["E-PARAMS-HASH"] = (422, "Hash de parámetros inválido"),
        ["E-CERT"] = (422, "Certificado inválido"),
        ["E-CERT-THUMBPRINT"] = (422, "Huella de certificado distinta"),
        ["E-SIGNATURE"] = (422, "Firma del manifiesto inválida"),
        ["E-TIMESTAMP"] = (422, "Fecha fuera de la ventana"),
        ["E-VERIFY-FAILED"] = (422, "Verificación fallida"),
        ["E-INTERNAL"] = (500, "Error interno"),
        ["E-BUSY"] = (503, "Nodo ocupado"),
        ["E-TIMEOUT"] = (504, "Tiempo agotado")
    };

    /// <summary>Crea el error con su código y detalle en español.</summary>
    public V2ProtocolException(string code, string detail)
        : base(detail)
    {
        Code = Catalog.ContainsKey(code) ? code : "E-INTERNAL";
        (Status, Title) = Catalog[Code];
    }

    /// <summary>Código del Anexo B.</summary>
    public string Code { get; }

    /// <summary>Código HTTP.</summary>
    public int Status { get; }

    /// <summary>Título corto.</summary>
    public string Title { get; }
}
