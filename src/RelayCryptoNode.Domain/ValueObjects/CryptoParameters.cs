using System.Collections.ObjectModel;
using RelayCryptoNode.Domain.Exceptions;

namespace RelayCryptoNode.Domain.ValueObjects;

/// <summary>
/// Value Object inmutable que encapsula los parámetros criptográficos auxiliares necesarios para descifrar un paquete.
/// </summary>
public sealed record CryptoParameters
{
    private readonly byte[] _ivOrNonce;
    private readonly byte[]? _authTag;
    private readonly byte[]? _encryptedSessionKey;
    private readonly byte[]? _salt;

    /// <summary>
    /// Vector de inicialización (IV) o nonce utilizado por el algoritmo simétrico.
    /// </summary>
    public byte[] IvOrNonce => _ivOrNonce.ToArray();

    /// <summary>
    /// Etiqueta de autenticación AEAD o HMAC cuando aplique.
    /// </summary>
    public byte[]? AuthTag => _authTag?.ToArray();

    /// <summary>
    /// Clave de sesión envuelta/encapsulada mediante el mecanismo asimétrico o PQC configurado.
    /// </summary>
    public byte[]? EncryptedSessionKey => _encryptedSessionKey?.ToArray();

    /// <summary>
    /// Sal criptográfica opcional usada en derivación de claves.
    /// </summary>
    public byte[]? Salt => _salt?.ToArray();

    /// <summary>
    /// Metadatos extensibles de parámetros criptográficos específicos de un algoritmo.
    /// </summary>
    public IReadOnlyDictionary<string, string> ExtraMetadata { get; }

    /// <summary>
    /// Inicializa una nueva instancia de <see cref="CryptoParameters"/> aplicando copias defensivas e invariantes.
    /// </summary>
    /// <param name="ivOrNonce">IV o nonce obligatorio.</param>
    /// <param name="authTag">Etiqueta de autenticación opcional.</param>
    /// <param name="encryptedSessionKey">Clave de sesión envuelta opcional.</param>
    /// <param name="salt">Sal criptográfica opcional.</param>
    /// <param name="extraMetadata">Diccionario opcional de metadatos adicionales.</param>
    /// <exception cref="DomainException">Se lanza si <paramref name="ivOrNonce"/> es nulo o vacío.</exception>
    public CryptoParameters(
        byte[] ivOrNonce,
        byte[]? authTag = null,
        byte[]? encryptedSessionKey = null,
        byte[]? salt = null,
        IReadOnlyDictionary<string, string>? extraMetadata = null)
    {
        if (ivOrNonce is null || ivOrNonce.Length == 0)
        {
            throw new DomainException("El vector IvOrNonce es obligatorio y no puede estar vacío.", "CRYPTO_IV_EMPTY");
        }

        _ivOrNonce = ivOrNonce.ToArray();
        _authTag = authTag?.ToArray();
        _encryptedSessionKey = encryptedSessionKey?.ToArray();
        _salt = salt?.ToArray();
        ExtraMetadata = extraMetadata is null
            ? new ReadOnlyDictionary<string, string>(new Dictionary<string, string>())
            : new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(extraMetadata));
    }

    /// <summary>
    /// Compara estructuralmente dos instancias de <see cref="CryptoParameters"/> por contenido binario y metadatos.
    /// </summary>
    /// <param name="other">Otra instancia a comparar.</param>
    /// <returns><c>true</c> si todos los arreglos de bytes y metadatos coinciden; de lo contrario, <c>false</c>.</returns>
    public bool Equals(CryptoParameters? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return ByteArraysEqual(_ivOrNonce, other._ivOrNonce)
               && ByteArraysEqual(_authTag, other._authTag)
               && ByteArraysEqual(_encryptedSessionKey, other._encryptedSessionKey)
               && ByteArraysEqual(_salt, other._salt)
               && DictionariesEqual(ExtraMetadata, other.ExtraMetadata);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        AddBytesToHash(ref hash, _ivOrNonce);
        AddBytesToHash(ref hash, _authTag);
        AddBytesToHash(ref hash, _encryptedSessionKey);
        AddBytesToHash(ref hash, _salt);

        foreach (var pair in ExtraMetadata.OrderBy(static kv => kv.Key, StringComparer.Ordinal))
        {
            hash.Add(pair.Key, StringComparer.Ordinal);
            hash.Add(pair.Value, StringComparer.Ordinal);
        }

        return hash.ToHashCode();
    }

    private static bool ByteArraysEqual(byte[]? left, byte[]? right)
    {
        if (left is null && right is null)
        {
            return true;
        }

        if (left is null || right is null)
        {
            return false;
        }

        return left.AsSpan().SequenceEqual(right);
    }

    private static bool DictionariesEqual(
        IReadOnlyDictionary<string, string> left,
        IReadOnlyDictionary<string, string> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        foreach (var pair in left)
        {
            if (!right.TryGetValue(pair.Key, out var rightValue) ||
                !string.Equals(pair.Value, rightValue, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static void AddBytesToHash(ref HashCode hash, byte[]? bytes)
    {
        if (bytes is null)
        {
            hash.Add(-1);
            return;
        }

        hash.Add(bytes.Length);
        foreach (var b in bytes)
        {
            hash.Add(b);
        }
    }
}
