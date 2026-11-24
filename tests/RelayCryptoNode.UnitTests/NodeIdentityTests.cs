using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.ValueObjects;
using Xunit;

namespace RelayCryptoNode.UnitTests;

public sealed class NodeIdentityTests
{
    [Fact]
    public void Constructor_ShouldNormalizeNodeIdToUppercaseAndThumbprintToLowercase()
    {
        var identity = new NodeIdentity("  nodo02  ".Trim(), " http://192.168.1.20:5000 ", TestFixtures.ValidSha256Upper);

        Assert.Equal("NODO02", identity.NodeId);
        Assert.Equal("http://192.168.1.20:5000", identity.EndpointAddress);
        Assert.Equal(TestFixtures.ValidSha256A, identity.CertificateThumbprintSha256);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("NODO 01")]
    [InlineData("NODO\t01")]
    [InlineData(" NODO01")]
    public void Constructor_ShouldThrowDomainException_WhenNodeIdIsEmptyOrContainsWhitespace(string invalidNodeId)
    {
        var ex = Assert.Throws<DomainException>(() =>
            new NodeIdentity(invalidNodeId, "http://192.168.1.10:5000", TestFixtures.ValidSha256A));

        Assert.NotNull(ex);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_ShouldThrowDomainException_WhenEndpointIsEmpty(string invalidEndpoint)
    {
        Assert.Throws<DomainException>(() =>
            new NodeIdentity("NODO01", invalidEndpoint, TestFixtures.ValidSha256A));
    }

    [Fact]
    public void Constructor_ShouldThrowDomainException_WhenThumbprintIsNotValidSha256()
    {
        Assert.Throws<DomainException>(() =>
            new NodeIdentity("NODO01", "http://192.168.1.10:5000", "1234"));
    }
}
