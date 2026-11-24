using System.Numerics;
using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.ModularMath;

/// <summary>
/// Módulo oficial <c>MILLERRABIN</c> (#13): prueba probabilística de primalidad Miller-Rabin y transformación modular exponencial sobre <c>Z_257^*</c>.
/// </summary>
public sealed class MillerRabinModule : ISymmetricCipherStrategy, IModularMathCryptoPort
{
    private const string DomainLabel = "MILLERRABIN";
    private const int PrimeModulus = 257; // primo de Fermat F_3 verificado por Miller-Rabin
    private readonly EuclidesAffineModule _euclides = new();

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.MILLERRABIN;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.MillerRabin;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.MillerRabin;

    /// <summary>
    /// Cifra bytes mediante exponenciación modular <c>(x + 1)^e mod 257</c> con exponente coprimo con <c>phi(257)=256</c>.
    /// </summary>
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var (e, _) = DeriveExponentPair(key, nonce);

        // Cada byte x in [0..255] se mapea a (x + 1) in [1..256]; 257 es primo verificado por Miller-Rabin
        var ciphertext = new byte[plaintext.Length * 2];
        for (var i = 0; i < plaintext.Length; i++)
        {
            var m = plaintext[i] + 1;
            var c = (ushort)BigInteger.ModPow(m, e, PrimeModulus);
            ciphertext[i * 2] = (byte)(c >> 8);
            ciphertext[(i * 2) + 1] = (byte)(c & 0xFF);
        }

        var tag = CryptoModuleHelpers.ComputeTag(key, nonce, ciphertext, associatedData, DomainLabel);
        return new SymmetricEncryptionResult(ciphertext, nonce, tag);
    }

    /// <inheritdoc />
    public byte[] Decrypt(
        byte[] ciphertext,
        byte[] key,
        byte[] ivOrNonce,
        byte[]? authTag,
        byte[]? associatedData = null)
    {
        CryptoModuleHelpers.ValidateDecryptInputs(ciphertext, key, ivOrNonce, Algorithm);
        CryptoModuleHelpers.VerifyTagOrThrow(key, ivOrNonce, ciphertext, authTag, associatedData, DomainLabel, Algorithm);

        if ((ciphertext.Length & 1) != 0)
        {
            throw new DecryptionFailedException("Longitud de texto cifrado Miller-Rabin inválida.", Algorithm);
        }

        var (_, d) = DeriveExponentPair(key, ivOrNonce);
        var plaintext = new byte[ciphertext.Length / 2];

        for (var i = 0; i < plaintext.Length; i++)
        {
            var c = (ciphertext[i * 2] << 8) | ciphertext[(i * 2) + 1];
            var m = (int)BigInteger.ModPow(c, d, PrimeModulus);
            if (m is < 1 or > 256)
            {
                throw new DecryptionFailedException("Símbolo fuera de rango tras exponenciación inversa Miller-Rabin.", Algorithm);
            }

            plaintext[i] = (byte)(m - 1);
        }

        return plaintext;
    }

    /// <inheritdoc />
    public ExtendedGcdResult ExtendedGcd(long a, long b) => _euclides.ExtendedGcd(a, b);

    /// <inheritdoc />
    public long ModularInverse(long a, long modulus) => _euclides.ModularInverse(a, modulus);

    /// <inheritdoc />
    public bool IsProbablePrime(byte[] unsignedBigEndianInteger, int rounds = 20) =>
        CheckPrimality(unsignedBigEndianInteger, rounds);

    /// <inheritdoc />
    public byte[] EncryptAffine(byte[] plaintext, byte a, byte b) => _euclides.EncryptAffine(plaintext, a, b);

    /// <inheritdoc />
    public byte[] DecryptAffine(byte[] ciphertext, byte a, byte b) => _euclides.DecryptAffine(ciphertext, a, b);

    /// <summary>
    /// Ejecuta la prueba probabilística de Miller-Rabin sobre un entero positivo big-endian.
    /// </summary>
    public static bool CheckPrimality(byte[] unsignedBigEndianInteger, int rounds = 20)
    {
        ArgumentNullException.ThrowIfNull(unsignedBigEndianInteger);
        if (unsignedBigEndianInteger.Length == 0 || rounds <= 0)
        {
            return false;
        }

        var n = new BigInteger(unsignedBigEndianInteger, isUnsigned: true, isBigEndian: true);
        if (n < 2)
        {
            return false;
        }

        if (n == 2 || n == 3)
        {
            return true;
        }

        if (n.IsEven)
        {
            return false;
        }

        var d = n - 1;
        var s = 0;
        while (d.IsEven)
        {
            d >>= 1;
            s++;
        }

        var bitLength = n.GetByteCount(isUnsigned: true);
        for (var r = 0; r < rounds; r++)
        {
            var a = RandomBetweenTwoAndNMinusTwo(n, bitLength);
            var x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1)
            {
                continue;
            }

            var composite = true;
            for (var j = 1; j < s; j++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1)
                {
                    composite = false;
                    break;
                }
            }

            if (composite)
            {
                return false;
            }
        }

        return true;
    }

    private (int E, int D) DeriveExponentPair(byte[] key, byte[] nonce)
    {
        if (!CheckPrimality([0x01, 0x01], 20))
        {
            throw new DomainException("Fallo interno en verificación prima de módulo.", "MILLERRABIN_MODULUS_ERROR");
        }

        var derived = CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:EXP", 1);
        var e = (derived[0] | 1);
        if (e <= 1)
        {
            e = 3;
        }

        var d = (int)_euclides.ModularInverse(e, PrimeModulus - 1);
        return (e, d);
    }

    private static BigInteger RandomBetweenTwoAndNMinusTwo(BigInteger n, int byteCount)
    {
        var upperBound = n - 3;
        while (true)
        {
            var bytes = RandomNumberGenerator.GetBytes(byteCount);
            var candidate = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
            if (candidate <= upperBound)
            {
                return candidate + 2;
            }

            return (candidate % upperBound) + 2;
        }
    }
}
