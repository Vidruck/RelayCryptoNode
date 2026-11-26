using System.Security.Cryptography;
using System.Text;
using RelayCryptoNode.Infrastructure.Certificates;

namespace RelayCryptoNode.Infrastructure.ProtocolV2;

/// <summary>
/// Identidad v2.0 del nodo: número de equipo, nodeId, puertos y certificado.
/// </summary>
public sealed class V2Identity
{
    private readonly LocalCertificateService _certificates;

    /// <summary>Crea la identidad.</summary>
    public V2Identity(int teamNumber, LocalCertificateService certificates, int? httpPort = null)
    {
        if (teamNumber is < 1 or > 99)
        {
            throw new ArgumentOutOfRangeException(nameof(teamNumber), "El número de equipo va de 1 a 99.");
        }

        TeamNumber = teamNumber;
        NodeId = V2Format.NodeIdFor(teamNumber);
        HttpPort = httpPort ?? V2Format.HttpPortFor(teamNumber);
        _certificates = certificates;
        CertificatePem = certificates.GetLocalCertificatePem();
        Thumbprint = V2Format.Thumbprint(CertificatePem);
    }

    /// <summary>Número de equipo (1–99).</summary>
    public int TeamNumber { get; }

    /// <summary>nodeId (<c>EQNN</c>).</summary>
    public string NodeId { get; }

    /// <summary>Puerto HTTP v2.0.</summary>
    public int HttpPort { get; }

    /// <summary>Certificado PEM.</summary>
    public string CertificatePem { get; }

    /// <summary>Huella SHA-256 en MAYÚSCULAS.</summary>
    public string Thumbprint { get; }

    /// <summary>IP con la que se anuncia el nodo (se actualiza con la red).</summary>
    public string Ip { get; set; } = "127.0.0.1";

    /// <summary>Llave privada en PEM (solo en memoria).</summary>
    public string PrivateKeyPem => _certificates.GetLocalPrivateKeyPem();

    /// <summary>Firma RSA-PSS-SHA256 (sal de 32 bytes) de un texto UTF-8.</summary>
    public string SignText(string text) => Convert.ToBase64String(SignBytes(Encoding.UTF8.GetBytes(text)));

    /// <summary>Firma RSA-PSS-SHA256 de bytes.</summary>
    public byte[] SignBytes(byte[] data)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(PrivateKeyPem);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
}
