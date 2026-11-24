namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Puerto de salida para cifrado por transposición determinista mediante permutación Fisher-Yates.
/// </summary>
public interface IPermutationCipherPort
{
    /// <summary>
    /// Permuta deterministamente la posición de los bytes de <paramref name="data"/> usando clave y nonce.
    /// </summary>
    /// <param name="data">Bytes originales.</param>
    /// <param name="key">Clave secreta para derivar la secuencia pseudoaleatoria de permutación.</param>
    /// <param name="nonce">Vector único por operación.</param>
    /// <returns>Arreglo de bytes permutado.</returns>
    byte[] Permute(byte[] data, byte[] key, byte[] nonce);

    /// <summary>
    /// Revierte exactamente la permutación Fisher-Yates recuperando los bytes en su orden original.
    /// </summary>
    /// <param name="permutedData">Bytes permutados.</param>
    /// <param name="key">Misma clave secreta usada en la permutación.</param>
    /// <param name="nonce">Mismo nonce usado en la permutación.</param>
    /// <returns>Arreglo de bytes en orden original.</returns>
    byte[] InversePermute(byte[] permutedData, byte[] key, byte[] nonce);
}
