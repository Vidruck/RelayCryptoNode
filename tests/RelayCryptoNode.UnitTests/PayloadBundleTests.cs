using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.ValueObjects;
using Xunit;

namespace RelayCryptoNode.UnitTests;

public sealed class PayloadBundleTests
{
    [Fact]
    public void Constructor_ShouldThrowDomainException_WhenItemsListIsEmpty()
    {
        var ex = Assert.Throws<DomainException>(() =>
            new PayloadBundle(
                Guid.NewGuid(),
                PayloadKind.Document,
                Array.Empty<PayloadItem>(),
                IntegrityDigest.Sha256(TestFixtures.ValidSha256A),
                DateTimeOffset.UtcNow));

        Assert.Equal("PAYLOAD_BUNDLE_EMPTY", ex.ErrorCode);
    }

    [Fact]
    public void Constructor_ShouldComputeTotalSizeBytesAcrossMultipleItems()
    {
        var item1 = TestFixtures.CreatePayloadItem("doc1.pdf", new byte[120]);
        var item2 = TestFixtures.CreatePayloadItem("img1.png", new byte[380]);

        var bundle = new PayloadBundle(
            Guid.NewGuid(),
            PayloadKind.MultiPartBundle,
            [item1, item2],
            IntegrityDigest.Sha256(TestFixtures.ValidSha256B),
            DateTimeOffset.UtcNow);

        Assert.Equal(2, bundle.Items.Count);
        Assert.Equal(500L, bundle.TotalSizeBytes);
    }

    [Fact]
    public void PayloadItem_ShouldThrowDomainException_WhenDeclaredSizeDoesNotMatchByteLength()
    {
        Assert.Throws<DomainException>(() =>
            new PayloadItem(
                "foto.png",
                ".png",
                "image/png",
                sizeBytes: 999,
                rawBytes: [1, 2, 3],
                sha256Hash: IntegrityDigest.Sha256(TestFixtures.ValidSha256A)));
    }
}
