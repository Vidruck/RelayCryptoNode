namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Fragmento individual generado por el esquema de umbral de Shamir sobre <c>GF(256)</c>.
/// </summary>
/// <param name="ShareIndex">Coordenada X no nula (<c>1..255</c>) del fragmento.</param>
/// <param name="Threshold">Cantidad mínima de fragmentos requeridos para reconstruir el secreto.</param>
/// <param name="Data">Evaluaciones polinomiales correspondientes a cada byte del secreto.</param>
public sealed record SecretShare(byte ShareIndex, byte Threshold, byte[] Data);

/// <summary>
/// Puerto de salida para compartición de secretos por umbral de Shamir en <c>GF(256)</c> con interpolación de Lagrange.
/// </summary>
public interface ISecretSharingPort
{
    /// <summary>
    /// Divide un secreto en <paramref name="totalShares"/> fragmentos requiriendo al menos <paramref name="threshold"/> para reconstruirlo.
    /// </summary>
    /// <param name="secret">Bytes del secreto original.</param>
    /// <param name="totalShares">Número total de fragmentos a emitir (<c>1..255</c>).</param>
    /// <param name="threshold">Umbral mínimo <c>k &lt;= totalShares</c>.</param>
    /// <returns>Lista de fragmentos independientes.</returns>
    IReadOnlyList<SecretShare> SplitSecret(byte[] secret, byte totalShares, byte threshold);

    /// <summary>
    /// Reconstruye exactamente el secreto original mediante interpolación de Lagrange sobre <c>GF(256)</c> a partir de al menos <c>k</c> fragmentos.
    /// </summary>
    /// <param name="shares">Subconjunto de fragmentos disponibles.</param>
    /// <returns>Bytes originales reconstruidos.</returns>
    byte[] ReconstructSecret(IReadOnlyList<SecretShare> shares);
}
