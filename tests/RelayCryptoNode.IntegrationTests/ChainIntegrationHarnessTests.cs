using RelayCryptoNode.Application;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Infrastructure;
using Xunit;

namespace RelayCryptoNode.IntegrationTests;

/// <summary>
/// Esqueleto base para las pruebas de integración de cadena de 3 nodos (Initial -> Intermediate -> Final) en Fase 3.
/// </summary>
public sealed class ChainIntegrationHarnessTests
{
    [Fact]
    public void SolutionWiring_ShouldExposeDomainApplicationInfrastructureAndWebHost()
    {
        var applicationAssembly = typeof(ApplicationAssemblyMarker).Assembly;
        var infrastructureAssembly = typeof(InfrastructureAssemblyMarker).Assembly;
        var webHostAssembly = typeof(Program).Assembly;

        Assert.NotNull(applicationAssembly);
        Assert.NotNull(infrastructureAssembly);
        Assert.NotNull(webHostAssembly);
        Assert.Equal(3, Enum.GetValues<NodeRole>().Length);
    }
}
