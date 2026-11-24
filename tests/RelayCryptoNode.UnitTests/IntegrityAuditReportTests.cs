using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.ValueObjects;
using Xunit;

namespace RelayCryptoNode.UnitTests;

public sealed class IntegrityAuditReportTests
{
    [Fact]
    public void CreateComparison_ShouldReportZeroLossAndBitExactMatch_WhenHashesAndSizesMatch()
    {
        var expectedHash = IntegrityDigest.Sha256(TestFixtures.ValidSha256A);
        var actualHash = IntegrityDigest.Sha256(TestFixtures.ValidSha256A);
        var itemAudit = ItemAuditResult.CreateComparison("foto.png", expectedHash, actualHash, 4096, 4096);

        var report = IntegrityAuditReport.CreateComparison(
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            expectedHash,
            actualHash,
            expectedSizeBytes: 4096,
            actualSizeBytes: 4096,
            itemAuditResults: [itemAudit]);

        Assert.True(report.IsBitExactMatch);
        Assert.Equal(0L, report.ByteLossCount);
        Assert.Single(report.ItemAuditResults);
        Assert.True(report.ItemAuditResults[0].IsBitExactMatch);
    }

    [Fact]
    public void CreateComparison_ShouldDetectCorruption_WhenSizeMatchesButHashDiffers()
    {
        var expectedHash = IntegrityDigest.Sha256(TestFixtures.ValidSha256A);
        var corruptedHash = IntegrityDigest.Sha256(TestFixtures.ValidSha256B);
        var itemAudit = ItemAuditResult.CreateComparison("contrato.pdf", expectedHash, corruptedHash, 2048, 2048);

        var report = IntegrityAuditReport.CreateComparison(
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            expectedHash,
            corruptedHash,
            expectedSizeBytes: 2048,
            actualSizeBytes: 2048,
            itemAuditResults: [itemAudit]);

        Assert.False(report.IsBitExactMatch);
        Assert.Equal(0L, report.ByteLossCount);
        Assert.False(report.ItemAuditResults[0].IsBitExactMatch);
    }

    [Fact]
    public void CreateComparison_ShouldCalculateExactByteLossCount_WhenBytesAreTruncated()
    {
        var expectedHash = IntegrityDigest.Sha256(TestFixtures.ValidSha256A);
        var actualHash = IntegrityDigest.Sha256(TestFixtures.ValidSha256B);

        var report = IntegrityAuditReport.CreateComparison(
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            expectedHash,
            actualHash,
            expectedSizeBytes: 10_000,
            actualSizeBytes: 9_750);

        Assert.False(report.IsBitExactMatch);
        Assert.Equal(250L, report.ByteLossCount);
    }

    [Fact]
    public void CreateComparison_ShouldFailGlobalMatch_WhenAnyItemAuditFails()
    {
        var globalHash = IntegrityDigest.Sha256(TestFixtures.ValidSha256A);
        var badItem = ItemAuditResult.CreateComparison(
            "anexo.bin",
            IntegrityDigest.Sha256(TestFixtures.ValidSha256A),
            IntegrityDigest.Sha256(TestFixtures.ValidSha256B),
            512,
            500);

        var report = IntegrityAuditReport.CreateComparison(
            Guid.NewGuid(),
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            globalHash,
            globalHash,
            expectedSizeBytes: 512,
            actualSizeBytes: 512,
            itemAuditResults: [badItem]);

        Assert.False(report.IsBitExactMatch);
        Assert.Equal(12L, badItem.ByteLossCount);
    }
}
