var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

app.MapGet("/api/status", (IConfiguration configuration) =>
{
    var nodeId = configuration["Node:Id"] ?? "NODO01";
    return Results.Ok(new
    {
        nodeId,
        protocolVersion = "1.0",
        status = "online",
        acceptingPackages = true
    });
});

app.Run();

/// <summary>
/// Punto de entrada parcial para pruebas de integración con WebApplicationFactory en fases posteriores.
/// </summary>
public partial class Program
{
}
