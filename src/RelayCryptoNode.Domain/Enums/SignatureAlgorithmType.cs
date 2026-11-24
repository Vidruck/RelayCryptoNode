namespace RelayCryptoNode.Domain.Enums;

/// <summary>
/// Algoritmos de firma digital vigentes (clásicos y poscuánticos) para autenticar el manifiesto y los paquetes del nodo.
/// </summary>
public enum SignatureAlgorithmType
{
    /// <summary>
    /// Firma RSA con relleno probabilístico PSS y resumen SHA-256 (PKCS#1 v2.1 / RFC 8017).
    /// </summary>
    RsaPssSha256 = 1,

    /// <summary>
    /// Firma ECDSA sobre curva NIST P-256 (secp256r1) con resumen SHA-256.
    /// </summary>
    EcdsaP256 = 2,

    /// <summary>
    /// Firma EdDSA sobre Curve25519 conforme a RFC 8032.
    /// </summary>
    Ed25519 = 3,

    /// <summary>
    /// Firma poscuántica basada en retículos ML-DSA-65 (NIST FIPS 204 / Dilithium3).
    /// </summary>
    MlDsa65 = 4,

    /// <summary>
    /// Firma ECDSA sobre curva NIST P-384 con SHA-384 (reservado para extensión futura).
    /// </summary>
    EcdsaP384 = 5,

    /// <summary>
    /// Firma poscuántica ML-DSA-87 nivel de seguridad 5 (NIST FIPS 204, reservado para extensión futura).
    /// </summary>
    MlDsa87 = 6,

    /// <summary>
    /// Firma poscuántica sin estado basada en hash SLH-DSA-SHA2-128s (NIST FIPS 205, reservado para extensión futura).
    /// </summary>
    SlhDsaSha2_128s = 7
}
