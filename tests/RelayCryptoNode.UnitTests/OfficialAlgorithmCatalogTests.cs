using RelayCryptoNode.Domain.Catalog;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Infrastructure.Algorithms;
using Xunit;

namespace RelayCryptoNode.UnitTests;

public sealed class OfficialAlgorithmCatalogTests
{
    [Fact]
    public void Catalog_ShouldContainExactlyAll21OfficialAlgorithms()
    {
        var all = OfficialAlgorithmCatalog.GetAll();
        var registry = new AlgorithmModuleRegistry();

        Assert.Equal(21, all.Count);
        Assert.Equal(21, Enum.GetValues<OfficialAlgorithmCode>().Length);

        foreach (var code in Enum.GetValues<OfficialAlgorithmCode>())
        {
            Assert.Contains(all, d => d.Code == code);
            Assert.True(registry.IsModuleImplemented(code), $"Falta módulo implementado para {code}");
        }
    }

    [Theory]
    [InlineData("AESGCM", OfficialAlgorithmCode.AESGCM)]
    [InlineData("aes-256-gcm", OfficialAlgorithmCode.AESGCM)]
    [InlineData("DES", OfficialAlgorithmCode.DES)]
    [InlineData("TRIPLEDES", OfficialAlgorithmCode.TRIPLEDES)]
    [InlineData("3des", OfficialAlgorithmCode.TRIPLEDES)]
    [InlineData("CHACHA20", OfficialAlgorithmCode.CHACHA20)]
    [InlineData("RSA", OfficialAlgorithmCode.RSA)]
    [InlineData("ECC", OfficialAlgorithmCode.ECC)]
    [InlineData("DIFFIEHELLMAN", OfficialAlgorithmCode.DIFFIEHELLMAN)]
    [InlineData("CAESAR", OfficialAlgorithmCode.CAESAR)]
    [InlineData("VIGENERE", OfficialAlgorithmCode.VIGENERE)]
    [InlineData("XORASM", OfficialAlgorithmCode.XORASM)]
    [InlineData("LSBSTEGO", OfficialAlgorithmCode.LSBSTEGO)]
    [InlineData("EUCLIDESAFFINE", OfficialAlgorithmCode.EUCLIDESAFFINE)]
    [InlineData("MILLERRABIN", OfficialAlgorithmCode.MILLERRABIN)]
    [InlineData("FISHERYATES", OfficialAlgorithmCode.FISHERYATES)]
    [InlineData("HASHSHA", OfficialAlgorithmCode.HASHSHA)]
    [InlineData("HMACSHA256", OfficialAlgorithmCode.HMACSHA256)]
    [InlineData("DIGITALSIG", OfficialAlgorithmCode.DIGITALSIG)]
    [InlineData("QUANTUMPQC", OfficialAlgorithmCode.QUANTUMPQC)]
    [InlineData("DFTSPECTRAL", OfficialAlgorithmCode.DFTSPECTRAL)]
    [InlineData("LAGRANGESHAMIR", OfficialAlgorithmCode.LAGRANGESHAMIR)]
    [InlineData("LORENZSZ40", OfficialAlgorithmCode.LORENZSZ40)]
    public void ParseOrThrow_ShouldResolveAllOfficialCodesAndAliases(string input, OfficialAlgorithmCode expected)
    {
        var resolved = OfficialAlgorithmCatalog.ParseOrThrow(input);
        Assert.Equal(expected, resolved);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("UNKNOWN_ALGO_99")]
    public void ParseOrThrow_ShouldThrowUnsupportedAlgorithmException_WhenIdentifierIsNotRegistered(string unknown)
    {
        Assert.Throws<UnsupportedAlgorithmException>(() => OfficialAlgorithmCatalog.ParseOrThrow(unknown));
    }
}
