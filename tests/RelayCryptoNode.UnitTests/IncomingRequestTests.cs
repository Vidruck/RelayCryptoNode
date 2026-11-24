using RelayCryptoNode.Domain.Entities;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using Xunit;

namespace RelayCryptoNode.UnitTests;

public sealed class IncomingRequestTests
{
    [Fact]
    public void Accept_ShouldTransitionFromPendingToAccepted_WhenSignatureAndIntegrityAreValid()
    {
        var request = new IncomingRequest(
            Guid.NewGuid(),
            TestFixtures.CreateEnvelope(),
            DateTimeOffset.UtcNow,
            signatureValid: true,
            integrityValid: true,
            validationNotes: "Validación X.509 correcta");

        Assert.Equal(RequestStatus.Pending, request.Status);

        request.Accept();

        Assert.Equal(RequestStatus.Accepted, request.Status);
        Assert.NotNull(request.ProcessedUtc);
    }

    [Fact]
    public void Accept_ShouldThrowDomainException_WhenSignatureIsInvalid()
    {
        var request = new IncomingRequest(
            Guid.NewGuid(),
            TestFixtures.CreateEnvelope(),
            DateTimeOffset.UtcNow,
            signatureValid: false,
            integrityValid: true);

        var ex = Assert.Throws<DomainException>(() => request.Accept());

        Assert.Equal("REQUEST_INVALID_SIGNATURE", ex.ErrorCode);
        Assert.Equal(RequestStatus.Pending, request.Status);
    }

    [Fact]
    public void Accept_ShouldThrowDomainException_WhenIntegrityIsInvalid()
    {
        var request = new IncomingRequest(
            Guid.NewGuid(),
            TestFixtures.CreateEnvelope(),
            DateTimeOffset.UtcNow,
            signatureValid: true,
            integrityValid: false);

        var ex = Assert.Throws<DomainException>(() => request.Accept());

        Assert.Equal("REQUEST_INVALID_INTEGRITY", ex.ErrorCode);
        Assert.Equal(RequestStatus.Pending, request.Status);
    }

    [Fact]
    public void Reject_ShouldTransitionFromPendingToRejectedAndStoreReason()
    {
        var request = new IncomingRequest(
            Guid.NewGuid(),
            TestFixtures.CreateEnvelope(),
            DateTimeOffset.UtcNow,
            signatureValid: true,
            integrityValid: true);

        request.Reject("Certificado no pertenece al equipo esperado.");

        Assert.Equal(RequestStatus.Rejected, request.Status);
        Assert.Equal("Certificado no pertenece al equipo esperado.", request.RejectionReason);
        Assert.NotNull(request.ProcessedUtc);
    }

    [Fact]
    public void Reject_ShouldThrowDomainException_WhenReasonIsEmpty()
    {
        var request = new IncomingRequest(
            Guid.NewGuid(),
            TestFixtures.CreateEnvelope(),
            DateTimeOffset.UtcNow,
            signatureValid: true,
            integrityValid: true);

        Assert.Throws<DomainException>(() => request.Reject("   "));
        Assert.Equal(RequestStatus.Pending, request.Status);
    }

    [Fact]
    public void StateTransitions_ShouldRejectIllegalTransitionsAndAllowValidTerminalTransitions()
    {
        var requestForRelay = new IncomingRequest(
            Guid.NewGuid(),
            TestFixtures.CreateEnvelope(),
            DateTimeOffset.UtcNow,
            signatureValid: true,
            integrityValid: true);

        Assert.Throws<DomainException>(() => requestForRelay.MarkRelayed());

        requestForRelay.Accept();
        Assert.Throws<DomainException>(() => requestForRelay.Accept());
        Assert.Throws<DomainException>(() => requestForRelay.Reject("Tarde"));

        requestForRelay.MarkRelayed();
        Assert.Equal(RequestStatus.Relayed, requestForRelay.Status);
        Assert.Throws<DomainException>(() => requestForRelay.MarkAudited());

        var requestForAudit = new IncomingRequest(
            Guid.NewGuid(),
            TestFixtures.CreateEnvelope(),
            DateTimeOffset.UtcNow,
            signatureValid: true,
            integrityValid: true);
        requestForAudit.Accept();
        requestForAudit.MarkAudited();
        Assert.Equal(RequestStatus.Audited, requestForAudit.Status);
    }
}
