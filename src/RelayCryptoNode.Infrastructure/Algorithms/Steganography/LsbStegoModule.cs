using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using RelayCryptoNode.Domain.Enums;
using RelayCryptoNode.Domain.Exceptions;
using RelayCryptoNode.Domain.Ports.Outbound;
using RelayCryptoNode.Infrastructure.Algorithms.Internal;

namespace RelayCryptoNode.Infrastructure.Algorithms.Steganography;

/// <summary>
/// Módulo oficial <c>LSBSTEGO</c> (#11): esteganografía LSB bit a bit sobre imágenes BMP (24/32-bit) y PNG (RGB/RGBA 8-bit).
/// </summary>
public sealed class LsbStegoModule : ISymmetricCipherStrategy, ISteganographyPort
{
    private const uint MagicHeader = 0x4C534243; // "LSBC" (mismo formato que EQ01)
    private const uint LegacyMagicHeader = 0x52434E53; // "RCNS" (imágenes anteriores del EQ06)
    private const string DomainLabel = "LSBSTEGO";
    private static readonly byte[] PngSignature = [137, 80, 78, 71, 13, 10, 26, 10];
    private static readonly uint[] CrcTable = BuildCrc32Table();

    /// <summary>
    /// Código oficial del módulo en el catálogo.
    /// </summary>
    public OfficialAlgorithmCode OfficialCode => OfficialAlgorithmCode.LSBSTEGO;

    /// <inheritdoc />
    public CipherAlgorithmType Algorithm => CipherAlgorithmType.LsbStego;

    /// <inheritdoc />
    public bool CanHandle(CipherAlgorithmType algorithm) => algorithm == CipherAlgorithmType.LsbStego;

    /// <summary>
    /// Cuando se invoca como estrategia simétrica genérica, enmascara el contenido y lo incrusta vía LSB en un portador BMP generado al vuelo.
    /// </summary>
    public SymmetricEncryptionResult Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var mask = ExpandKeystream(key, nonce, plaintext.Length);
        var masked = new byte[plaintext.Length];
        for (var i = 0; i < plaintext.Length; i++)
        {
            masked[i] = (byte)(plaintext[i] ^ mask[i]);
        }

        // 8 bits por byte + cabecera de 8 bytes -> se necesitan al menos (masked.Length + 8) * 8 bytes de píxeles
        var requiredPixelBytes = (masked.Length + 8) * 8;
        var side = (int)Math.Ceiling(Math.Sqrt(requiredPixelBytes / 3.0)) + 2;
        var carrierBmp = CreateBlankBmp24(side, side);
        var stegoBmp = EmbedPayload(carrierBmp, masked);
        var tag = CryptoModuleHelpers.ComputeTag(key, nonce, stegoBmp, associatedData, DomainLabel);

        return new SymmetricEncryptionResult(stegoBmp, nonce, tag);
    }

    /// <inheritdoc />
    public byte[] Decrypt(
        byte[] ciphertext,
        byte[] key,
        byte[] ivOrNonce,
        byte[]? authTag,
        byte[]? associatedData = null)
    {
        CryptoModuleHelpers.ValidateDecryptInputs(ciphertext, key, ivOrNonce, Algorithm);
        CryptoModuleHelpers.VerifyTagOrThrow(key, ivOrNonce, ciphertext, authTag, associatedData, DomainLabel, Algorithm);

        var masked = ExtractPayload(ciphertext);
        var mask = ExpandKeystream(key, ivOrNonce, masked.Length);
        var plaintext = new byte[masked.Length];
        for (var i = 0; i < masked.Length; i++)
        {
            plaintext[i] = (byte)(masked[i] ^ mask[i]);
        }

        return plaintext;
    }

    /// <inheritdoc />
    public byte[] EmbedPayload(byte[] carrierImageBytes, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(carrierImageBytes);
        ArgumentNullException.ThrowIfNull(payload);

        var packet = BuildEmbeddedPacket(payload);

        if (IsBmp(carrierImageBytes))
        {
            return EmbedInBmp(carrierImageBytes, packet);
        }

        if (IsPng(carrierImageBytes))
        {
            return EmbedInPng(carrierImageBytes, packet);
        }

        throw new DomainException("Formato de imagen no soportado para LSBSTEGO; use BMP o PNG.", "STEGO_UNSUPPORTED_IMAGE");
    }

    /// <inheritdoc />
    public byte[] ExtractPayload(byte[] stegoImageBytes)
    {
        ArgumentNullException.ThrowIfNull(stegoImageBytes);

        if (IsBmp(stegoImageBytes))
        {
            return ExtractFromBmp(stegoImageBytes);
        }

        if (IsPng(stegoImageBytes))
        {
            return ExtractFromPng(stegoImageBytes);
        }

        throw new DomainException("Formato de imagen no soportado para LSBSTEGO; use BMP o PNG.", "STEGO_UNSUPPORTED_IMAGE");
    }

    /// <summary>
    /// Crea una imagen BMP RGB de 24 bits válida utilizable como portadora esteganográfica.
    /// </summary>
    public static byte[] CreateBlankBmp24(int width, int height)
    {
        var rowStride = ((width * 3) + 3) & ~3;
        var pixelSize = rowStride * height;
        var totalSize = 54 + pixelSize;
        var bmp = new byte[totalSize];

        bmp[0] = (byte)'B';
        bmp[1] = (byte)'M';
        BinaryPrimitives.WriteInt32LittleEndian(bmp.AsSpan(2, 4), totalSize);
        BinaryPrimitives.WriteInt32LittleEndian(bmp.AsSpan(10, 4), 54);
        BinaryPrimitives.WriteInt32LittleEndian(bmp.AsSpan(14, 4), 40);
        BinaryPrimitives.WriteInt32LittleEndian(bmp.AsSpan(18, 4), width);
        BinaryPrimitives.WriteInt32LittleEndian(bmp.AsSpan(22, 4), height);
        BinaryPrimitives.WriteInt16LittleEndian(bmp.AsSpan(26, 2), 1);
        BinaryPrimitives.WriteInt16LittleEndian(bmp.AsSpan(28, 2), 24);
        BinaryPrimitives.WriteInt32LittleEndian(bmp.AsSpan(34, 4), pixelSize);

        for (var i = 54; i < bmp.Length; i++)
        {
            bmp[i] = 128;
        }

        return bmp;
    }

    /// <summary>
    /// Crea una imagen PNG RGB de 8 bits válida utilizable como portadora esteganográfica.
    /// </summary>
    public static byte[] CreateBlankPngRgb(int width, int height)
    {
        var channels = 3;
        var scanlineSize = 1 + (width * channels);
        var rawScanlines = new byte[scanlineSize * height];
        for (var y = 0; y < height; y++)
        {
            var rowOffset = y * scanlineSize;
            rawScanlines[rowOffset] = 0; // Filter None
            Array.Fill(rawScanlines, (byte)128, rowOffset + 1, width * channels);
        }

        return EncodePng(width, height, colorType: 2, bitDepth: 8, rawScanlines);
    }

    private static byte[] BuildEmbeddedPacket(byte[] payload)
    {
        var packet = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(0, 4), MagicHeader);
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(4, 4), payload.Length);
        Buffer.BlockCopy(payload, 0, packet, 8, payload.Length);
        return packet;
    }

    // ---------------------------------------------------------------------------------------------
    // Formato compatible con EQ01 (ModuloCrypto): cabecera "LSBC" + longitud int32 big-endian,
    // bits del más significativo al menos significativo, 1 bit por canal en orden R, G, B
    // (sin alfa), píxeles de arriba hacia abajo y de izquierda a derecha.
    // La lectura también acepta las imágenes anteriores (cabecera "RCNS" en bytes crudos).
    // ---------------------------------------------------------------------------------------------

    /// <summary>Mapa canal lógico (R,G,B por píxel, de arriba a abajo) → posición del byte en el arreglo.</summary>
    private readonly record struct ChannelMap(int Channels, Func<int, int> Offset);

    private static ChannelMap PngMap(int width, int height, int bytesPerPixel) =>
        new(width * height * 3, i => ((i / 3) * bytesPerPixel) + (i % 3));

    private static ChannelMap BmpMap(byte[] bmp, out int pixelOffset)
    {
        pixelOffset = BinaryPrimitives.ReadInt32LittleEndian(bmp.AsSpan(10, 4));
        var width = BinaryPrimitives.ReadInt32LittleEndian(bmp.AsSpan(18, 4));
        var rawHeight = BinaryPrimitives.ReadInt32LittleEndian(bmp.AsSpan(22, 4));
        var bitsPerPixel = BinaryPrimitives.ReadInt16LittleEndian(bmp.AsSpan(28, 2));
        if (pixelOffset < 54 || pixelOffset >= bmp.Length || width <= 0 || rawHeight == 0 || bitsPerPixel is not (24 or 32))
        {
            throw new DomainException("Solo se soportan BMP de 24 o 32 bits sin compresión.", "STEGO_INVALID_BMP");
        }

        var height = Math.Abs(rawHeight);
        var topDown = rawHeight < 0;
        var bpp = bitsPerPixel / 8;
        var stride = ((width * bpp) + 3) & ~3;
        if (pixelOffset + ((long)stride * height) > bmp.Length)
        {
            throw new DomainException("Archivo BMP truncado.", "STEGO_INVALID_BMP");
        }

        var start = pixelOffset;
        return new ChannelMap(width * height * 3, i =>
        {
            var pixel = i / 3;
            var x = pixel % width;
            var y = pixel / width;
            var row = topDown ? y : height - 1 - y;
            return start + (row * stride) + (x * bpp) + (2 - (i % 3)); // BMP guarda B,G,R
        });
    }

    private static void WriteMapped(Span<byte> target, ChannelMap map, ReadOnlySpan<byte> packet)
    {
        if ((long)packet.Length * 8 > map.Channels)
        {
            throw new DomainException("La imagen es demasiado pequeña para ocultar la carga útil.", "STEGO_CAPACITY_EXCEEDED");
        }

        var bitIndex = 0;
        foreach (var dataByte in packet)
        {
            for (var bit = 7; bit >= 0; bit--)
            {
                var at = map.Offset(bitIndex++);
                target[at] = (byte)((target[at] & 0xFE) | ((dataByte >> bit) & 1));
            }
        }
    }

    private static byte[] ReadMapped(ReadOnlySpan<byte> source, ChannelMap map, int startBit, int count)
    {
        var result = new byte[count];
        var bitIndex = startBit;
        for (var i = 0; i < count; i++)
        {
            byte value = 0;
            for (var bit = 7; bit >= 0; bit--)
            {
                value |= (byte)((source[map.Offset(bitIndex++)] & 1) << bit);
            }

            result[i] = value;
        }

        return result;
    }

    /// <summary>Lee la carga con el formato nuevo (LSBC por píxel); si no está, prueba el formato anterior (RCNS en bytes crudos).</summary>
    private static byte[] ReadAnyPacket(ReadOnlySpan<byte> pixels, ChannelMap map, ReadOnlySpan<byte> legacyBytes)
    {
        if (map.Channels >= 64)
        {
            var header = ReadMapped(pixels, map, 0, 8);
            var magic = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4));
            if (magic is MagicHeader or LegacyMagicHeader)
            {
                var length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(4, 4));
                if (length < 0 || ((long)length + 8) * 8 > map.Channels)
                {
                    throw new DecryptionFailedException("Longitud de carga esteganográfica inválida o truncada.", CipherAlgorithmType.LsbStego);
                }

                return ReadMapped(pixels, map, 64, length);
            }
        }

        return ReadLsbPacket(legacyBytes);
    }

    private static byte[] EmbedInBmp(byte[] bmpBytes, byte[] packet)
    {
        if (bmpBytes.Length < 54)
        {
            throw new DomainException("Archivo BMP inválido o truncado.", "STEGO_INVALID_BMP");
        }

        var map = BmpMap(bmpBytes, out _);
        var output = bmpBytes.ToArray();
        WriteMapped(output, map, packet);
        return output;
    }

    private static byte[] ExtractFromBmp(byte[] bmpBytes)
    {
        if (bmpBytes.Length < 54)
        {
            throw new DomainException("Archivo BMP inválido o truncado.", "STEGO_INVALID_BMP");
        }

        var map = BmpMap(bmpBytes, out var pixelOffset);
        return ReadAnyPacket(bmpBytes, map, bmpBytes.AsSpan(pixelOffset));
    }

    private static byte[] EmbedInPng(byte[] pngBytes, byte[] packet)
    {
        var parsed = ParsePng(pngBytes);
        var bytesPerPixel = parsed.ColorType switch
        {
            2 => 3, // RGB
            6 => 4, // RGBA
            _ => throw new DomainException("Solo se soportan PNG RGB (tipo 2) o RGBA (tipo 6) de 8 bits.", "STEGO_UNSUPPORTED_PNG_FORMAT")
        };

        if (parsed.BitDepth != 8)
        {
            throw new DomainException("Solo se soportan PNG de 8 bits por canal.", "STEGO_UNSUPPORTED_PNG_FORMAT");
        }

        var rawPixels = DecompressZlib(parsed.CompressedIdat);
        var stride = 1 + (parsed.Width * bytesPerPixel);
        if (rawPixels.Length != stride * parsed.Height)
        {
            throw new DomainException("Dimensiones de datos IDAT inválidas en PNG.", "STEGO_INVALID_PNG");
        }

        // Reconstruir píxeles filtrados sin pérdida (forzando filter=0 para preservar LSB exacto tras re-empaquetado)
        var unencodedPixels = UnfilterScanlines(rawPixels, parsed.Width, parsed.Height, bytesPerPixel);
        WriteMapped(unencodedPixels, PngMap(parsed.Width, parsed.Height, bytesPerPixel), packet);

        var scanlines = new byte[stride * parsed.Height];
        for (var y = 0; y < parsed.Height; y++)
        {
            var srcRow = y * parsed.Width * bytesPerPixel;
            var dstRow = y * stride;
            scanlines[dstRow] = 0;
            Buffer.BlockCopy(unencodedPixels, srcRow, scanlines, dstRow + 1, parsed.Width * bytesPerPixel);
        }

        return EncodePng(parsed.Width, parsed.Height, parsed.ColorType, parsed.BitDepth, scanlines);
    }

    private static byte[] ExtractFromPng(byte[] pngBytes)
    {
        var parsed = ParsePng(pngBytes);
        var bytesPerPixel = parsed.ColorType switch
        {
            2 => 3,
            6 => 4,
            _ => throw new DomainException("Solo se soportan PNG RGB (tipo 2) o RGBA (tipo 6) de 8 bits.", "STEGO_UNSUPPORTED_PNG_FORMAT")
        };

        var rawPixels = DecompressZlib(parsed.CompressedIdat);
        var unencodedPixels = UnfilterScanlines(rawPixels, parsed.Width, parsed.Height, bytesPerPixel);
        return ReadAnyPacket(unencodedPixels, PngMap(parsed.Width, parsed.Height, bytesPerPixel), unencodedPixels);
    }

    private static byte[] ReadLsbPacket(ReadOnlySpan<byte> carrierBytes)
    {
        if (carrierBytes.Length < 64)
        {
            throw new DecryptionFailedException("No hay suficientes bits para leer cabecera LSBSTEGO.", CipherAlgorithmType.LsbStego);
        }

        Span<byte> header = stackalloc byte[8];
        ReadLsbBytes(carrierBytes, header, 0);

        var magic = BinaryPrimitives.ReadUInt32BigEndian(header[..4]);
        if (magic is not (MagicHeader or LegacyMagicHeader))
        {
            throw new DecryptionFailedException("No se encontró firma esteganográfica LSBSTEGO válida.", CipherAlgorithmType.LsbStego);
        }

        var payloadLength = BinaryPrimitives.ReadInt32BigEndian(header[4..8]);
        if (payloadLength < 0 || ((long)payloadLength + 8) * 8 > carrierBytes.Length)
        {
            throw new DecryptionFailedException("Longitud de carga esteganográfica inválida o truncada.", CipherAlgorithmType.LsbStego);
        }

        var payload = new byte[payloadLength];
        ReadLsbBytes(carrierBytes, payload, 64);
        return payload;
    }

    private static void ReadLsbBytes(ReadOnlySpan<byte> carrierBytes, Span<byte> destination, int startBitOffset)
    {
        var bitIndex = startBitOffset;
        for (var i = 0; i < destination.Length; i++)
        {
            byte value = 0;
            for (var bit = 7; bit >= 0; bit--)
            {
                value |= (byte)((carrierBytes[bitIndex] & 1) << bit);
                bitIndex++;
            }

            destination[i] = value;
        }
    }

    private static byte[] ExpandKeystream(byte[] key, byte[] nonce, int length)
    {
        var stream = new byte[length];
        var counter = 0;
        var offset = 0;
        Span<byte> ctrBytes = stackalloc byte[4];

        while (offset < length)
        {
            BinaryPrimitives.WriteInt32BigEndian(ctrBytes, counter++);
            var block = CryptoModuleHelpers.DeriveFixedBytes(key, [.. nonce, .. ctrBytes], $"{DomainLabel}:MASK", 32);
            var toCopy = Math.Min(block.Length, length - offset);
            Buffer.BlockCopy(block, 0, stream, offset, toCopy);
            offset += toCopy;
        }

        return stream;
    }

    private static bool IsBmp(byte[] bytes) => bytes.Length >= 2 && bytes[0] == (byte)'B' && bytes[1] == (byte)'M';

    private static bool IsPng(byte[] bytes) => bytes.Length >= 8 && bytes.AsSpan(0, 8).SequenceEqual(PngSignature);

    private sealed record ParsedPng(int Width, int Height, byte BitDepth, byte ColorType, byte[] CompressedIdat);

    private static ParsedPng ParsePng(byte[] pngBytes)
    {
        var pos = 8;
        int width = 0, height = 0;
        byte bitDepth = 0, colorType = 0;
        var ihdrFound = false;
        using var idatStream = new MemoryStream();

        while (pos + 12 <= pngBytes.Length)
        {
            var chunkLength = BinaryPrimitives.ReadInt32BigEndian(pngBytes.AsSpan(pos, 4));
            pos += 4;
            var chunkType = System.Text.Encoding.ASCII.GetString(pngBytes, pos, 4);
            pos += 4;

            if (chunkLength < 0 || pos + chunkLength + 4 > pngBytes.Length)
            {
                throw new DomainException("Chunk PNG truncado o corrupto.", "STEGO_INVALID_PNG");
            }

            var chunkData = pngBytes.AsSpan(pos, chunkLength);
            pos += chunkLength + 4; // saltar CRC

            if (chunkType == "IHDR" && chunkLength >= 13)
            {
                width = BinaryPrimitives.ReadInt32BigEndian(chunkData[..4]);
                height = BinaryPrimitives.ReadInt32BigEndian(chunkData.Slice(4, 4));
                bitDepth = chunkData[8];
                colorType = chunkData[9];
                ihdrFound = true;
            }
            else if (chunkType == "IDAT")
            {
                idatStream.Write(chunkData);
            }
            else if (chunkType == "IEND")
            {
                break;
            }
        }

        if (!ihdrFound || width <= 0 || height <= 0 || idatStream.Length == 0)
        {
            throw new DomainException("PNG inválido: faltan chunks IHDR o IDAT.", "STEGO_INVALID_PNG");
        }

        return new ParsedPng(width, height, bitDepth, colorType, idatStream.ToArray());
    }

    private static byte[] DecompressZlib(byte[] compressed)
    {
        using var input = new MemoryStream(compressed);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        return output.ToArray();
    }

    private static byte[] CompressZlib(byte[] raw)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(raw, 0, raw.Length);
        }

        return output.ToArray();
    }

    private static byte[] UnfilterScanlines(byte[] rawScanlines, int width, int height, int bpp)
    {
        var stride = 1 + (width * bpp);
        var rowBytes = width * bpp;
        var pixels = new byte[rowBytes * height];

        for (var y = 0; y < height; y++)
        {
            var srcRow = y * stride;
            var dstRow = y * rowBytes;
            var filter = rawScanlines[srcRow];

            for (var x = 0; x < rowBytes; x++)
            {
                var raw = rawScanlines[srcRow + 1 + x];
                var a = x >= bpp ? pixels[dstRow + x - bpp] : (byte)0;
                var b = y > 0 ? pixels[dstRow - rowBytes + x] : (byte)0;
                var c = (x >= bpp && y > 0) ? pixels[dstRow - rowBytes + x - bpp] : (byte)0;

                pixels[dstRow + x] = filter switch
                {
                    0 => raw,
                    1 => (byte)(raw + a),
                    2 => (byte)(raw + b),
                    3 => (byte)(raw + ((a + b) / 2)),
                    4 => (byte)(raw + PaethPredictor(a, b, c)),
                    _ => throw new DomainException($"Filtro PNG no soportado ({filter}).", "STEGO_INVALID_PNG")
                };
            }
        }

        return pixels;
    }

    private static byte PaethPredictor(byte a, byte b, byte c)
    {
        var p = a + b - c;
        var pa = Math.Abs(p - a);
        var pb = Math.Abs(p - b);
        var pc = Math.Abs(p - c);
        if (pa <= pb && pa <= pc)
        {
            return a;
        }

        return pb <= pc ? b : c;
    }

    private static byte[] EncodePng(int width, int height, byte colorType, byte bitDepth, byte[] scanlines)
    {
        using var ms = new MemoryStream();
        ms.Write(PngSignature);

        var ihdr = new byte[13];
        BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(0, 4), width);
        BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(4, 4), height);
        ihdr[8] = bitDepth;
        ihdr[9] = colorType;
        WritePngChunk(ms, "IHDR", ihdr);

        var compressedIdat = CompressZlib(scanlines);
        WritePngChunk(ms, "IDAT", compressedIdat);
        WritePngChunk(ms, "IEND", Array.Empty<byte>());

        return ms.ToArray();
    }

    private static void WritePngChunk(Stream stream, string type, byte[] data)
    {
        Span<byte> lenBytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(lenBytes, data.Length);
        stream.Write(lenBytes);

        var typeBytes = System.Text.Encoding.ASCII.GetBytes(type);
        stream.Write(typeBytes);
        stream.Write(data);

        var crc = ComputeCrc32(typeBytes, data);
        Span<byte> crcBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(crcBytes, crc);
        stream.Write(crcBytes);
    }

    private static uint ComputeCrc32(byte[] typeBytes, byte[] data)
    {
        var crc = 0xFFFFFFFFU;
        foreach (var b in typeBytes)
        {
            crc = CrcTable[(crc ^ b) & 0xFF] ^ (crc >> 8);
        }

        foreach (var b in data)
        {
            crc = CrcTable[(crc ^ b) & 0xFF] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFFU;
    }

    private static uint[] BuildCrc32Table()
    {
        var table = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            var c = n;
            for (var k = 0; k < 8; k++)
            {
                c = (c & 1) != 0 ? 0xEDB88320U ^ (c >> 1) : c >> 1;
            }

            table[n] = c;
        }

        return table;
    }
}
