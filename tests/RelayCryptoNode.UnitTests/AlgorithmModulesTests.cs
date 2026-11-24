using System.Security.Cryptography;
using System.Text;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Infrastructure.Algorithms;
using RelayCryptoNode.Infrastructure.Algorithms.Asymmetric;
using RelayCryptoNode.Infrastructure.Algorithms.Steganography;
using Xunit;

namespace RelayCryptoNode.UnitTests;

public sealed class AlgorithmModulesTests
{
    [Theory]
    [InlineData("AESGCM")]
    [InlineData("DES")]
    [InlineData("TRIPLEDES")]
    [InlineData("CHACHA20")]
    [InlineData("CAESAR")]
    [InlineData("VIGENERE")]
    [InlineData("XORASM")]
    [InlineData("LSBSTEGO")]
    [InlineData("EUCLIDESAFFINE")]
    [InlineData("MILLERRABIN")]
    [InlineData("FISHERYATES")]
    [InlineData("QUANTUMPQC")]
    [InlineData("DFTSPECTRAL")]
    [InlineData("LAGRANGESHAMIR")]
    [InlineData("LORENZSZ40")]
    public void SymmetricAndTransformModules_ShouldRoundTripBitExactPlaintext(string officialCode)
    {
        var registry = new AlgorithmModuleRegistry();
        var strategy = registry.ResolveCipherStrategy(officialCode);

        var plaintext = Encoding.UTF8.GetBytes($"RelayCryptoNode-Payload-{officialCode}-0123456789-áéíóú!");
        var key = RandomNumberGenerator.GetBytes(32);
        var aad = Encoding.UTF8.GetBytes("NODO01->NODO02");

        var encrypted = strategy.Encrypt(plaintext, key, aad);
        var decrypted = strategy.Decrypt(encrypted.Ciphertext, key, encrypted.IvOrNonce, encrypted.AuthTag, aad);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void RsaModule_ShouldWrapAndUnwrapSessionKeyWithOaepSha256()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();
        var privatePem = rsa.ExportPkcs8PrivateKeyPem();

        var module = new RsaModule(privatePem);
        var sessionKey = RandomNumberGenerator.GetBytes(32);

        var wrapped = module.WrapSessionKey(sessionKey, publicPem);
        var unwrapped = module.UnwrapSessionKey(wrapped.WrappedKey);

        Assert.Equal(sessionKey, unwrapped);
    }

    [Fact]
    public void EccModule_ShouldWrapUnwrapEcdhAndSignVerifyEcdsaP256()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicPem = ecdsa.ExportSubjectPublicKeyInfoPem();
        var privatePem = ecdsa.ExportPkcs8PrivateKeyPem();

        var module = new EccModule(privatePem);
        var sessionKey = RandomNumberGenerator.GetBytes(32);

        var wrapped = module.WrapSessionKey(sessionKey, publicPem);
        var unwrapped = module.UnwrapSessionKey(wrapped.WrappedKey, wrapped.Salt);
        Assert.Equal(sessionKey, unwrapped);

        var payload = Encoding.UTF8.GetBytes("Mensaje autenticado con ECC P-256");
        var signature = EccModule.SignEcdsaP256(payload, privatePem);
        Assert.True(EccModule.VerifyEcdsaP256(payload, signature, publicPem));
        payload[0] ^= 0xFF;
        Assert.False(EccModule.VerifyEcdsaP256(payload, signature, publicPem));
    }

    [Fact]
    public void DiffieHellmanModule_ShouldDeriveIdenticalSharedSecretAndWrapSessionKey()
    {
        var alice = DiffieHellmanModule.GenerateKeyPair();
        var bob = DiffieHellmanModule.GenerateKeyPair();

        var aliceSecret = DiffieHellmanModule.DeriveSharedKey(alice.PrivateExponent, bob.PublicKeyBytes);
        var bobSecret = DiffieHellmanModule.DeriveSharedKey(bob.PrivateExponent, alice.PublicKeyBytes);
        Assert.Equal(aliceSecret, bobSecret);

        var bobModule = new DiffieHellmanModule(bob);
        var sessionKey = RandomNumberGenerator.GetBytes(32);
        var wrapped = bobModule.WrapSessionKey(sessionKey, Convert.ToBase64String(bob.PublicKeyBytes));
        var unwrapped = bobModule.UnwrapSessionKey(wrapped.WrappedKey, wrapped.Salt);
        Assert.Equal(sessionKey, unwrapped);
    }

    [Fact]
    public void LsbStegoModule_ShouldEmbedAndExtractBitExactPayloadInBmpAndPng()
    {
        var stego = new LsbStegoModule();
        var secret = Encoding.UTF8.GetBytes("Evidencia oculta LSBSTEGO BMP y PNG 2026");

        var bmpCarrier = LsbStegoModule.CreateBlankBmp24(48, 48);
        var stegoBmp = stego.EmbedPayload(bmpCarrier, secret);
        Assert.Equal(secret, stego.ExtractPayload(stegoBmp));

        var pngCarrier = LsbStegoModule.CreateBlankPngRgb(48, 48);
        var stegoPng = stego.EmbedPayload(pngCarrier, secret);
        Assert.Equal(secret, stego.ExtractPayload(stegoPng));
    }

    [Fact]
    public void EuclidesAffineAndMillerRabin_ShouldComputeInverseAndDetectPrimes()
    {
        var registry = new AlgorithmModuleRegistry();
        var gcd = registry.EuclidesAffine.ExtendedGcd(240, 46);
        Assert.Equal(2, gcd.Gcd);
        Assert.Equal(2, (240 * gcd.X) + (46 * gcd.Y));

        var inv = registry.EuclidesAffine.ModularInverse(17, 256);
        Assert.Equal(1L, (17 * inv) % 256);

        var primeBytes = new byte[] { 0x01, 0x01 }; // 257 (primo)
        var compositeBytes = new byte[] { 0x01, 0x03 }; // 259 = 7 * 37 (compuesto)
        Assert.True(registry.MillerRabin.IsProbablePrime(primeBytes, 25));
        Assert.False(registry.MillerRabin.IsProbablePrime(compositeBytes, 25));
    }

    [Fact]
    public void HashShaHmacSha256AndDigitalSig_ShouldHashVerifyAndDetectTampering()
    {
        var registry = new AlgorithmModuleRegistry();
        var data = Encoding.UTF8.GetBytes("Integridad HASHSHA + HMACSHA256 + DIGITALSIG");

        var hashModule = registry.ResolveHashingService(OfficialAlgorithmCode.HASHSHA);
        var sha256 = hashModule.ComputeHash(data, HashAlgorithmType.Sha256);
        var sha512 = hashModule.ComputeHash(data, HashAlgorithmType.Sha512);
        Assert.Equal(64, sha256.HexHash.Length);
        Assert.Equal(128, sha512.HexHash.Length);
        Assert.True(hashModule.VerifyHash(data, sha256));
        Assert.True(hashModule.VerifyHash(data, sha512));

        var hmacModule = registry.ResolveHashingService(OfficialAlgorithmCode.HMACSHA256);
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        var mac = hmacModule.ComputeHash(data, HashAlgorithmType.HmacSha256, hmacKey);
        Assert.True(hmacModule.VerifyHash(data, mac, hmacKey));

        using var rsa = RSA.Create(2048);
        var signature = registry.DigitalSignature.Sign(data, rsa.ExportPkcs8PrivateKeyPem());
        Assert.True(registry.DigitalSignature.Verify(data, signature, rsa.ExportSubjectPublicKeyInfoPem()));
        data[0] ^= 0x01;
        Assert.False(registry.DigitalSignature.Verify(data, signature, rsa.ExportSubjectPublicKeyInfoPem()));
    }

    [Fact]
    public void QuantumPqcModule_ShouldSimulateBb84CleanVsEavesdropper()
    {
        var registry = new AlgorithmModuleRegistry();

        var clean = registry.QuantumPqc.SimulateBb84KeyExchange(bitCount: 512, simulateEavesdropper: false);
        Assert.Equal(32, clean.SharedKey.Length);
        Assert.Equal(0.0, clean.EstimatedQber);
        Assert.False(clean.EavesdroppingDetected);

        var eavesdropped = registry.QuantumPqc.SimulateBb84KeyExchange(bitCount: 1024, simulateEavesdropper: true);
        Assert.True(eavesdropped.EstimatedQber > 0.11);
        Assert.True(eavesdropped.EavesdroppingDetected);
    }

    [Fact]
    public void LagrangeShamirModule_ShouldReconstructFromThresholdAndFailBelowThreshold()
    {
        var registry = new AlgorithmModuleRegistry();
        var secret = Encoding.UTF8.GetBytes("Secreto critico Shamir GF(256)");

        var shares = registry.LagrangeShamir.SplitSecret(secret, totalShares: 5, threshold: 3);
        Assert.Equal(5, shares.Count);

        var recovered = registry.LagrangeShamir.ReconstructSecret([shares[0], shares[2], shares[4]]);
        Assert.Equal(secret, recovered);

        Assert.Throws<DomainException>(() =>
            registry.LagrangeShamir.ReconstructSecret([shares[0], shares[1]]));
    }
}
