namespace RelayCryptoNode.Domain.Ports.Outbound;

/// <summary>
/// Resultado del algoritmo de Euclides Extendido: <c>Gcd = a*X + b*Y</c>.
/// </summary>
/// <param name="Gcd">Máximo común divisor de <c>a</c> y <c>b</c>.</param>
/// <param name="X">Coeficiente de Bézout correspondiente a <c>a</c>.</param>
/// <param name="Y">Coeficiente de Bézout correspondiente a <c>b</c>.</param>
public sealed record ExtendedGcdResult(long Gcd, long X, long Y);

/// <summary>
/// Puerto de salida para primitivas de aritmética modular (Euclides Extendido, Cifrado Afín y Miller-Rabin).
/// </summary>
public interface IModularMathCryptoPort
{
    /// <summary>
    /// Calcula el máximo común divisor y los coeficientes de Bézout mediante Euclides Extendido.
    /// </summary>
    /// <param name="a">Primer entero.</param>
    /// <param name="b">Segundo entero.</param>
    /// <returns>Resultado con MCD y coeficientes <c>X</c>, <c>Y</c>.</returns>
    ExtendedGcdResult ExtendedGcd(long a, long b);

    /// <summary>
    /// Calcula el inverso multiplicativo modular de <paramref name="a"/> módulo <paramref name="modulus"/>.
    /// </summary>
    /// <param name="a">Entero invertible respecto al módulo.</param>
    /// <param name="modulus">Módulo positivo mayor que 1.</param>
    /// <returns>Inverso multiplicativo en el rango <c>[0, modulus - 1]</c>.</returns>
    long ModularInverse(long a, long modulus);

    /// <summary>
    /// Evalúa mediante la prueba probabilística de Miller-Rabin si un entero positivo grande es probablemente primo.
    /// </summary>
    /// <param name="unsignedBigEndianInteger">Representación big-endian sin signo del entero candidato.</param>
    /// <param name="rounds">Número de rondas aleatorias de verificación.</param>
    /// <returns><c>true</c> si supera todas las rondas como primo probable; <c>false</c> si es compuesto.</returns>
    bool IsProbablePrime(byte[] unsignedBigEndianInteger, int rounds = 20);

    /// <summary>
    /// Cifra bytes aplicando la transformación afín invertible <c>E(x) = (a*x + b) mod 256</c>.
    /// </summary>
    /// <param name="plaintext">Bytes en claro.</param>
    /// <param name="a">Multiplicador coprimo con 256 (impar).</param>
    /// <param name="b">Desplazamiento aditivo.</param>
    /// <returns>Bytes cifrados.</returns>
    byte[] EncryptAffine(byte[] plaintext, byte a, byte b);

    /// <summary>
    /// Descifra bytes cifrados mediante la transformación afín inversa <c>D(y) = a^-1 * (y - b) mod 256</c>.
    /// </summary>
    /// <param name="ciphertext">Bytes cifrados.</param>
    /// <param name="a">Multiplicador coprimo con 256 (impar).</param>
    /// <param name="b">Desplazamiento aditivo.</param>
    /// <returns>Bytes originales en claro.</returns>
    byte[] DecryptAffine(byte[] ciphertext, byte a, byte b);
}
