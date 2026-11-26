namespace RelayCryptoNode.Infrastructure.ProtocolV2;

/// <summary>
/// Fila de la tabla 4.1 del estándar v2.0.
/// </summary>
/// <param name="Id">algorithmId (1–21).</param>
/// <param name="Code">algorithmCode oficial.</param>
/// <param name="Name">Nombre descriptivo.</param>
/// <param name="Category">Categoría.</param>
/// <param name="Team">Equipo dueño o <c>null</c> si está reservado.</param>
/// <param name="ForwardName">Significado de <c>forward</c>.</param>
/// <param name="InverseName">Significado de <c>inverse</c>.</param>
/// <param name="KeyType">Tipo de llave.</param>
public sealed record V2Algorithm(
    int Id,
    string Code,
    string Name,
    string Category,
    int? Team,
    string ForwardName,
    string InverseName,
    string KeyType)
{
    /// <summary>nodeId del dueño (<c>EQNN</c>) o <c>null</c>.</summary>
    public string? OwnerNode => Team is { } team ? V2Format.NodeIdFor(team) : null;
}

/// <summary>
/// Diccionario oficial de equipos y algoritmos (sección 4.1).
/// </summary>
public static class V2Catalog
{
    /// <summary>Los 21 algoritmos en orden.</summary>
    public static readonly IReadOnlyList<V2Algorithm> All =
    [
        new(1, "AESGCM", "AES-256-GCM", "Simétrico por bloques", 1, "cifrar", "descifrar", "Secreta"),
        new(2, "DES", "DES 56-bit", "Simétrico legado", 1, "cifrar", "descifrar", "Secreta"),
        new(3, "TRIPLEDES", "Triple DES / 3DES", "Simétrico legado", 2, "cifrar", "descifrar", "Secreta"),
        new(4, "CHACHA20", "ChaCha20-Poly1305", "Simétrico de flujo (AEAD)", 2, "cifrar", "descifrar", "Secreta"),
        new(5, "RSA", "RSA-OAEP / RSA-PSS", "Asimétrico", 3, "cifrar", "descifrar", "keyId"),
        new(6, "ECC", "ECDH / ECIES / ECDSA", "Asimétrico (curva elíptica)", 3, "cifrar", "descifrar", "keyId"),
        new(7, "DIFFIEHELLMAN", "Diffie-Hellman", "Acuerdo de claves", 4, "cifrar", "descifrar", "keyId"),
        new(8, "CAESAR", "Cifrado César", "Clásico", 4, "cifrar", "descifrar", "Secreta"),
        new(9, "VIGENERE", "Cifrado Vigenère", "Clásico polialfabético", 5, "cifrar", "descifrar", "Secreta"),
        new(10, "XORASM", "XOR en registro (WREG / ROL / ROR)", "Bajo nivel", 5, "cifrar", "descifrar", "Secreta"),
        new(11, "LSBSTEGO", "Esteganografía LSB en PNG/BMP", "Esteganografía", 6, "ocultar", "extraer", "Secreta opcional"),
        new(12, "EUCLIDESAFFINE", "Euclides extendido / Afín", "Teoría de números", 6, "cifrar", "descifrar", "Secreta"),
        new(13, "MILLERRABIN", "Miller–Rabin + cifrado modular", "Primalidad", 7, "cifrar", "descifrar", "keyId"),
        new(14, "FISHERYATES", "Permutación Fisher–Yates", "Transposición", 7, "permutar", "restaurar", "Secreta"),
        new(15, "HASHSHA", "SHA-256 / SHA-512 / SHA-3", "Integridad", 8, "calcular hash", "verificar", "Ninguna"),
        new(16, "HMACSHA256", "HMAC-SHA256 / HMAC-SHA512", "Autenticación", 8, "calcular MAC", "verificar", "Secreta"),
        new(17, "DIGITALSIG", "Firma digital RSA-PSS / ECDSA", "Autenticidad", null, "firmar", "verificar", "keyId"),
        new(18, "QUANTUMPQC", "QKD BB84 + PQC (ML-KEM / LWE)", "Poscuántica", null, "cifrar", "descifrar", "keyId"),
        new(19, "DFTSPECTRAL", "Transformada discreta de Fourier", "Señales", null, "transformar", "invertir", "Secreta opcional"),
        new(20, "LAGRANGESHAMIR", "Shamir en GF(256)", "Umbral", null, "dividir", "reconstruir", "Ninguna"),
        new(21, "LORENZSZ40", "Lorenz SZ40/42", "Flujo electromecánico", null, "cifrar", "descifrar", "Secreta")
    ];

    /// <summary>Busca por código exacto (sensible a mayúsculas).</summary>
    public static V2Algorithm? ByCode(string? code) => All.FirstOrDefault(a => a.Code == code);

    /// <summary>Busca por número.</summary>
    public static V2Algorithm? ById(int id) => All.FirstOrDefault(a => a.Id == id);
}
