using System.Security.Cryptography;
using System.Text;

namespace RelayCryptoNode.WebHost.Hosting;

/// <summary>Usuario del panel (superusuario).</summary>
public sealed class PanelUser
{
    /// <summary>Nombre para entrar.</summary>
    public string User { get; set; } = string.Empty;

    /// <summary>Nombre que se muestra en el panel.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Hash PBKDF2: <c>pbkdf2-sha256$iteraciones$salBase64$hashBase64</c>.</summary>
    public string PasswordHash { get; set; } = string.Empty;
}

/// <summary>
/// Usuarios que pueden entrar al panel. Solo protege la interfaz (/, /api/ui y /api/v1); los endpoints que usan
/// los otros nodos (/api/status, /api/certificate, /api/requests/receive, /api/crypto/*) siguen abiertos.
/// </summary>
public sealed class PanelUsers
{
    private readonly IReadOnlyList<PanelUser> _users;

    /// <summary>Crea la lista.</summary>
    public PanelUsers(IEnumerable<PanelUser> users) => _users = users.ToList();

    /// <summary>Regresa el usuario si la contraseña es correcta.</summary>
    public PanelUser? Check(string? user, string? password)
    {
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrEmpty(password))
        {
            return null;
        }

        var found = _users.FirstOrDefault(u => string.Equals(u.User, user.Trim(), StringComparison.OrdinalIgnoreCase));
        return found is not null && Verify(password, found.PasswordHash) ? found : null;
    }

    /// <summary>Genera el hash PBKDF2 de una contraseña (para cambiarla en appsettings.json).</summary>
    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 100_000, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2-sha256$100000${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    private static bool Verify(string password, string stored)
    {
        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" || !int.TryParse(parts[1], out var iterations))
        {
            return false;
        }

        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
