using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.ValueObjects;

namespace RelayCryptoNode.Domain.Entities;

/// <summary>
/// Entidad inmutable que representa el sobre criptográfico autocontenido intercambiado entre nodos de la cadena.
/// </summary>
public sealed record CryptoEnvelope
{
    private readonly byte[] _ciphertextBytes;
    private readonly byte[] _manifestSignature;

    /// <summary>
    /// Identificador único del paquete cifrado.
    /// </summary>
    public Guid PacketId { get; }

    /// <summary>
    /// Identidad verificable del nodo que emitió o re-encriptó este sobre.
    /// </summary>
    public NodeIdentity SourceNode { get; }

    /// <summary>
    /// Marca temporal UTC de emisión del sobre.
    /// </summary>
    public DateTimeOffset TimestampUtc { get; }

    /// <summary>
    /// Algoritmo simétrico utilizado para cifrar <see cref="CiphertextBytes"/>.
    /// </summary>
    public CipherAlgorithmType CipherAlgorithm { get; }

    /// <summary>
    /// Algoritmo utilizado para envolver o acordar la clave de sesión.
    /// </summary>
    public KeyExchangeAlgorithmType KeyExchangeAlgorithm { get; }

    /// <summary>
    /// Algoritmo de firma digital utilizado sobre el manifiesto.
    /// </summary>
    public SignatureAlgorithmType SignatureAlgorithm { get; }

    /// <summary>
    /// Parámetros criptográficos auxiliares (IV/Nonce, AuthTag, clave envuelta, sal y metadatos).
    /// </summary>
    public CryptoParameters Parameters { get; }

    /// <summary>
    /// Copia defensiva del texto cifrado binario.
    /// </summary>
    public byte[] CiphertextBytes => _ciphertextBytes.ToArray();

    /// <summary>
    /// Resumen SHA-256 del bloque cifrado <see cref="CiphertextBytes"/>.
    /// </summary>
    public IntegrityDigest EncryptedSha256 { get; }

    /// <summary>
    /// Certificado X.509 del emisor codificado en formato PEM.
    /// </summary>
    public string SenderCertificatePem { get; }

    /// <summary>
    /// Copia defensiva de la firma digital del manifiesto.
    /// </summary>
    public byte[] ManifestSignature => _manifestSignature.ToArray();

    /// <summary>
    /// Huella digital SHA-256 testigo del paquete original antes de cualquier cifrado en la cadena.
    /// </summary>
    public IntegrityDigest OriginalPayloadSha256 { get; }

    /// <summary>
    /// Nombre original del archivo o lote de entrada.
    /// </summary>
    public string OriginalFileName { get; }

    /// <summary>
    /// Extensión original del archivo o lote de entrada.
    /// </summary>
    public string OriginalExtension { get; }

    /// <summary>
    /// Tamaño original exacto en bytes de la carga útil antes de cifrar.
    /// </summary>
    public long OriginalSizeBytes { get; }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="CryptoEnvelope"/> validando todas las invariantes estructurales.
    /// </summary>
    /// <param name="packetId">Identificador único del paquete.</param>
    /// <param name="sourceNode">Identidad del nodo emisor.</param>
    /// <param name="timestampUtc">Marca temporal UTC de emisión.</param>
    /// <param name="cipherAlgorithm">Algoritmo simétrico empleado.</param>
    /// <param name="keyExchangeAlgorithm">Algoritmo de intercambio o envoltura de clave.</param>
    /// <param name="signatureAlgorithm">Algoritmo de firma digital del manifiesto.</param>
    /// <param name="parameters">Parámetros criptográficos del cifrado.</param>
    /// <param name="ciphertextBytes">Bytes cifrados no vacíos.</param>
    /// <param name="encryptedSha256">Resumen SHA-256 de los bytes cifrados.</param>
    /// <param name="senderCertificatePem">Certificado X.509 del emisor en PEM.</param>
    /// <param name="manifestSignature">Firma digital del manifiesto.</param>
    /// <param name="originalPayloadSha256">Resumen SHA-256 testigo del contenido original.</param>
    /// <param name="originalFileName">Nombre del archivo o paquete original.</param>
    /// <param name="originalExtension">Extensión original del archivo.</param>
    /// <param name="originalSizeBytes">Tamaño original en bytes.</param>
    /// <exception cref="DomainException">Se lanza si algún campo obligatorio incumple las reglas de dominio.</exception>
    public CryptoEnvelope(
        Guid packetId,
        NodeIdentity sourceNode,
        DateTimeOffset timestampUtc,
        CipherAlgorithmType cipherAlgorithm,
        KeyExchangeAlgorithmType keyExchangeAlgorithm,
        SignatureAlgorithmType signatureAlgorithm,
        CryptoParameters parameters,
        byte[] ciphertextBytes,
        IntegrityDigest encryptedSha256,
        string senderCertificatePem,
        byte[] manifestSignature,
        IntegrityDigest originalPayloadSha256,
        string originalFileName,
        string originalExtension,
        long originalSizeBytes)
    {
        if (packetId == Guid.Empty)
        {
            throw new DomainException("El PacketId del CryptoEnvelope no puede ser Guid.Empty.", "ENVELOPE_PACKET_ID_EMPTY");
        }

        if (sourceNode is null)
        {
            throw new DomainException("El SourceNode del CryptoEnvelope es obligatorio.", "ENVELOPE_SOURCE_NODE_NULL");
        }

        if (parameters is null)
        {
            throw new DomainException("Los CryptoParameters del CryptoEnvelope son obligatorios.", "ENVELOPE_PARAMETERS_NULL");
        }

        if (ciphertextBytes is null || ciphertextBytes.Length == 0)
        {
            throw new DomainException("El CiphertextBytes no puede ser nulo ni estar vacío.", "ENVELOPE_CIPHERTEXT_EMPTY");
        }

        if (encryptedSha256 is null || encryptedSha256.HexHash.Length != 64)
        {
            throw new DomainException("El EncryptedSha256 debe ser un hash SHA-256 válido.", "ENVELOPE_ENCRYPTED_SHA_INVALID");
        }

        if (string.IsNullOrWhiteSpace(senderCertificatePem))
        {
            throw new DomainException("El certificado PEM del emisor es obligatorio.", "ENVELOPE_CERT_PEM_EMPTY");
        }

        if (manifestSignature is null || manifestSignature.Length == 0)
        {
            throw new DomainException("La firma del manifiesto no puede ser nula ni estar vacía.", "ENVELOPE_SIGNATURE_EMPTY");
        }

        if (originalPayloadSha256 is null || originalPayloadSha256.HexHash.Length != 64)
        {
            throw new DomainException("El OriginalPayloadSha256 debe ser un hash SHA-256 válido.", "ENVELOPE_ORIGINAL_SHA_INVALID");
        }

        if (string.IsNullOrWhiteSpace(originalFileName))
        {
            throw new DomainException("El nombre de archivo original no puede estar vacío.", "ENVELOPE_ORIGINAL_NAME_EMPTY");
        }

        if (originalExtension is null)
        {
            throw new DomainException("La extensión original no puede ser nula.", "ENVELOPE_ORIGINAL_EXT_NULL");
        }

        if (originalSizeBytes < 0)
        {
            throw new DomainException("El tamaño original en bytes no puede ser negativo.", "ENVELOPE_ORIGINAL_SIZE_NEGATIVE");
        }

        PacketId = packetId;
        SourceNode = sourceNode;
        TimestampUtc = timestampUtc;
        CipherAlgorithm = cipherAlgorithm;
        KeyExchangeAlgorithm = keyExchangeAlgorithm;
        SignatureAlgorithm = signatureAlgorithm;
        Parameters = parameters;
        _ciphertextBytes = ciphertextBytes.ToArray();
        EncryptedSha256 = encryptedSha256;
        SenderCertificatePem = senderCertificatePem.Trim();
        _manifestSignature = manifestSignature.ToArray();
        OriginalPayloadSha256 = originalPayloadSha256;
        OriginalFileName = originalFileName.Trim();
        OriginalExtension = originalExtension.Trim();
        OriginalSizeBytes = originalSizeBytes;
    }
}
