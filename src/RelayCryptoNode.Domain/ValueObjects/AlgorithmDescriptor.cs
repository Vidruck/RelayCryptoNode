using System.Collections.ObjectModel;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;

namespace RelayCryptoNode.Domain.ValueObjects;

/// <summary>
/// Descriptor inmutable de un algoritmo perteneciente al catálogo oficial de 21 módulos.
/// </summary>
public sealed record AlgorithmDescriptor
{
    /// <summary>
    /// Código enumerado oficial del algoritmo.
    /// </summary>
    public OfficialAlgorithmCode Code { get; }

    /// <summary>
    /// Cadena canónica oficial (en mayúsculas, por ejemplo <c>AESGCM</c>).
    /// </summary>
    public string OfficialCode { get; }

    /// <summary>
    /// Nombre descriptivo oficial para visualización e interoperabilidad.
    /// </summary>
    public string DisplayName { get; }

    /// <summary>
    /// Categoría funcional del módulo.
    /// </summary>
    public AlgorithmCategory Category { get; }

    /// <summary>
    /// Algoritmo de cifrado equivalente cuando el módulo opera sobre carga útil.
    /// </summary>
    public CipherAlgorithmType? CipherAlgorithm { get; }

    /// <summary>
    /// Algoritmo de intercambio o envoltura de clave asociado, si aplica.
    /// </summary>
    public KeyExchangeAlgorithmType? KeyExchangeAlgorithm { get; }

    /// <summary>
    /// Algoritmo de firma digital asociado, si aplica.
    /// </summary>
    public SignatureAlgorithmType? SignatureAlgorithm { get; }

    /// <summary>
    /// Algoritmo de resumen o MAC asociado, si aplica.
    /// </summary>
    public HashAlgorithmType? HashAlgorithm { get; }

    /// <summary>
    /// Lista de alias aceptados al parsear manifiestos heterogéneos.
    /// </summary>
    public IReadOnlyList<string> AcceptedAliases { get; }

    /// <summary>
    /// Inicializa un descriptor oficial validando código, nombre y alias.
    /// </summary>
    /// <param name="code">Código enumerado oficial.</param>
    /// <param name="officialCode">Cadena oficial canónica.</param>
    /// <param name="displayName">Nombre descriptivo oficial.</param>
    /// <param name="category">Categoría del módulo.</param>
    /// <param name="cipherAlgorithm">Algoritmo de cifrado asociado opcional.</param>
    /// <param name="keyExchangeAlgorithm">Algoritmo de intercambio asociado opcional.</param>
    /// <param name="signatureAlgorithm">Algoritmo de firma asociado opcional.</param>
    /// <param name="hashAlgorithm">Algoritmo de integridad asociado opcional.</param>
    /// <param name="acceptedAliases">Alias aceptados adicionalmente en manifiestos.</param>
    public AlgorithmDescriptor(
        OfficialAlgorithmCode code,
        string officialCode,
        string displayName,
        AlgorithmCategory category,
        CipherAlgorithmType? cipherAlgorithm = null,
        KeyExchangeAlgorithmType? keyExchangeAlgorithm = null,
        SignatureAlgorithmType? signatureAlgorithm = null,
        HashAlgorithmType? hashAlgorithm = null,
        IReadOnlyList<string>? acceptedAliases = null)
    {
        if (string.IsNullOrWhiteSpace(officialCode))
        {
            throw new DomainException("El código oficial del algoritmo no puede estar vacío.", "ALGORITHM_CODE_EMPTY");
        }

        if (string.IsNullOrWhiteSpace(displayName))
        {
            throw new DomainException("El nombre descriptivo del algoritmo no puede estar vacío.", "ALGORITHM_NAME_EMPTY");
        }

        Code = code;
        OfficialCode = officialCode.Trim().ToUpperInvariant();
        DisplayName = displayName.Trim();
        Category = category;
        CipherAlgorithm = cipherAlgorithm;
        KeyExchangeAlgorithm = keyExchangeAlgorithm;
        SignatureAlgorithm = signatureAlgorithm;
        HashAlgorithm = hashAlgorithm;
        AcceptedAliases = acceptedAliases is null
            ? new ReadOnlyCollection<string>(Array.Empty<string>())
            : new ReadOnlyCollection<string>(acceptedAliases.Where(static a => !string.IsNullOrWhiteSpace(a)).Select(static a => a.Trim()).ToArray());
    }
}
