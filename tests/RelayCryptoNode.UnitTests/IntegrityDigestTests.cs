using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.ValueObjects;
using Xunit;

namespace RelayCryptoNode.UnitTests;

public sealed class IntegrityDigestTests
{
    [Fact]
    public void Sha256_ShouldAcceptValid64CharHexAndNormalizeLowercase()
    {
        var digest = IntegrityDigest.Sha256($"  {TestFixtures.ValidSha256Upper}  ");

        Assert.Equal("SHA-256", digest.AlgorithmName);
        Assert.Equal(TestFixtures.ValidSha256A, digest.HexHash);
        Assert.Equal("aaaaaaaa", digest.ShortHex());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("abcd")]
    public void Sha256_ShouldRejectInvalidLength(string invalidHash)
    {
        Assert.Throws<DomainException>(() => IntegrityDigest.Sha256(invalidHash));
    }

    [Fact]
    public void Sha256_ShouldRejectLength63AndLength65()
    {
        Assert.Throws<DomainException>(() => IntegrityDigest.Sha256(new string('a', 63)));
        Assert.Throws<DomainException>(() => IntegrityDigest.Sha256(new string('a', 65)));
    }

    [Fact]
    public void Sha256_ShouldRejectNonHexCharacters()
    {
        var nonHex = new string('z', 64);
        Assert.Throws<DomainException>(() => IntegrityDigest.Sha256(nonHex));
    }

    [Fact]
    public void Constructor_ShouldValidateSha512As128HexCharacters()
    {
        var validSha512 = new string('F', 128);
        var digest = new IntegrityDigest("sha-512", validSha512);

        Assert.Equal("SHA-512", digest.AlgorithmName);
        Assert.Equal(new string('f', 128), digest.HexHash);
        Assert.Throws<DomainException>(() => new IntegrityDigest("SHA-512", TestFixtures.ValidSha256A));
    }
}
