using System.Numerics;
using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.ModularMath;

/// <summary>
/// Módulo oficial <c>EUCLIDESAFFINE</c> (#12): Algoritmo de Euclides Extendido, inverso modular y cifrado Afín invertible sobre <c>mod 256</c>.
/// </summary>
public sealed class EuclidesAffineModule : ISymmetricCipherStrategy, IModularMathCryptoPort
{
    private const string DomainLabel = "EUCLIDESAFFINE";

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.EUCLIDESAFFINE;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.EuclidesAffine;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.EuclidesAffine;

    /// <inheritdoc />
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var (a, b) = DeriveAffineParams(key, nonce);
        var ciphertext = EncryptAffine(plaintext, a, b);
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
        var (a, b) = DeriveAffineParams(key, ivOrNonce);
        return DecryptAffine(ciphertext, a, b);
    }

    /// <inheritdoc />
    public ExtendedGcdResult ExtendedGcd(long a, long b)
    {
        long oldR = a, r = b;
        long oldS = 1, s = 0;
        long oldT = 0, t = 1;

        while (r != 0)
        {
            var quotient = oldR / r;
            (oldR, r) = (r, oldR - (quotient * r));
            (oldS, s) = (s, oldS - (quotient * s));
            (oldT, t) = (t, oldT - (quotient * t));
        }

        if (oldR < 0)
        {
            return new ExtendedGcdResult(-oldR, -oldS, -oldT);
        }

        return new ExtendedGcdResult(oldR, oldS, oldT);
    }

    /// <inheritdoc />
    public long ModularInverse(long a, long modulus)
    {
        if (modulus <= 1)
        {
            throw new DomainException("El módulo debe ser mayor que 1.", "MODULAR_INVALID_MODULUS");
        }

        var normalizedA = ((a % modulus) + modulus) % modulus;
        var egcd = ExtendedGcd(normalizedA, modulus);
        if (egcd.Gcd != 1)
        {
            throw new DomainException(
                $"No existe inverso modular para {a} módulo {modulus} (MCD = {egcd.Gcd}).",
                "MODULAR_INVERSE_NOT_FOUND");
        }

        return ((egcd.X % modulus) + modulus) % modulus;
    }

    /// <inheritdoc />
    public bool IsProbablePrime(byte[] unsignedBigEndianInteger, int rounds = 20) =>
        MillerRabinModule.CheckPrimality(unsignedBigEndianInteger, rounds);

    /// <inheritdoc />
    public byte[] EncryptAffine(byte[] plaintext, byte a, byte b)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if ((a & 1) == 0)
        {
            throw new DomainException("El multiplicador 'a' del cifrado Afín mod 256 debe ser impar (coprimo con 256).", "AFFINE_INVALID_A");
        }

        var output = new byte[plaintext.Length];
        for (var i = 0; i < plaintext.Length; i++)
        {
            output[i] = (byte)(((a * plaintext[i]) + b) & 0xFF);
        }

        return output;
    }

    /// <inheritdoc />
    public byte[] DecryptAffine(byte[] ciphertext, byte a, byte b)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        var aInv = (int)ModularInverse(a, 256);
        var output = new byte[ciphertext.Length];

        for (var i = 0; i < ciphertext.Length; i++)
        {
            var diff = (ciphertext[i] - b) & 0xFF;
            output[i] = (byte)((aInv * diff) & 0xFF);
        }

        return output;
    }

    private static (byte A, byte B) DeriveAffineParams(byte[] key, byte[] nonce)
    {
        var derived = CryptoModuleHelpers.DeriveFixedBytes(key, nonce, $"{DomainLabel}:AB", 2);
        var a = (byte)(derived[0] | 1); // garantizar impar => mcd(a, 256) == 1
        var b = derived[1];
        return (a, b);
    }
}
