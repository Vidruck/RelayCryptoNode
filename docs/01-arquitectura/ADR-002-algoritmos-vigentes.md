# ADR-002: Catálogo Oficial de 21 Algoritmos y Módulos Criptográficos

- **Estado:** Actualizado y Aceptado (reemplaza la versión previa restrictiva)
- **Fecha:** 2026-11-24
- **Contexto:** Catálogo completo de 21 módulos criptográficos, matemáticos, espectrales, esteganográficos y poscuánticos de `RelayCryptoNode`.

---

## 1. Decisión Arquitectónica

Se adopta un catálogo unificado de **21 módulos oficiales** expuestos en `RelayCryptoNode.Domain.Catalog.OfficialAlgorithmCatalog` (`OfficialAlgorithmCode`) e implementados de forma individual y desacoplada en `RelayCryptoNode.Infrastructure/Algorithms/`.

Cada módulo implementa las interfaces de puerto correspondientes en `Domain/Ports/Outbound/`:
- `ISymmetricCipherStrategy`
- `IAsymmetricKeyWrapperPort`
- `IHashingServicePort`
- `ISteganographyPort`
- `IModularMathCryptoPort`
- `IPermutationCipherPort`
- `IQuantumPqcSimulationPort`
- `ISpectralTransformPort`
- `ISecretSharingPort`
- `IStreamRotorCipherPort`

Esta actualización **elimina cualquier prohibición previa** sobre algoritmos clásicos o heredados (`DES`, `TRIPLEDES`, `CAESAR`, `VIGENERE`, `LORENZSZ40`), integrándolos con autenticación o verificación determinista sin pérdida para demostración, relevo polimórfico e interoperabilidad entre los 6 nodos del proyecto.

---

## 2. Catálogo Oficial Completo (21 Módulos)

| # | Código Oficial | Nombre / Descripción | Categoría | Puerto(s) de Dominio | Módulo Dedicado (`Infrastructure/Algorithms/`) |
|---|---|---|---|---|---|
| 1 | `AESGCM` | AES-256-GCM | `SymmetricCipher` | `ISymmetricCipherStrategy` | `Symmetric/AesGcmModule.cs` |
| 2 | `DES` | DES 56-bit | `SymmetricCipher` | `ISymmetricCipherStrategy` | `Symmetric/DesModule.cs` |
| 3 | `TRIPLEDES` | Triple DES / 3DES | `SymmetricCipher` | `ISymmetricCipherStrategy` | `Symmetric/TripleDesModule.cs` |
| 4 | `CHACHA20` | ChaCha20-Poly1305 | `SymmetricCipher` | `ISymmetricCipherStrategy` | `Symmetric/ChaCha20Poly1305Module.cs` |
| 5 | `RSA` | RSA-OAEP / RSA-PSS | `AsymmetricKeyExchange` | `IAsymmetricKeyWrapperPort` | `Asymmetric/RsaModule.cs` |
| 6 | `ECC` | ECDH / ECDSA | `AsymmetricKeyExchange` | `IAsymmetricKeyWrapperPort` | `Asymmetric/EccModule.cs` |
| 7 | `DIFFIEHELLMAN` | Diffie-Hellman | `AsymmetricKeyExchange` | `IAsymmetricKeyWrapperPort` | `Asymmetric/DiffieHellmanModule.cs` |
| 8 | `CAESAR` | Cifrado César | `ClassicalAndTransposition` | `ISymmetricCipherStrategy` | `Classical/CaesarModule.cs` |
| 9 | `VIGENERE` | Cifrado Vigenère | `ClassicalAndTransposition` | `ISymmetricCipherStrategy` | `Classical/VigenereModule.cs` |
| 10 | `XORASM` | XOR en Registro | `ClassicalAndTransposition` | `ISymmetricCipherStrategy`, `IStreamRotorCipherPort` | `Classical/XorAsmModule.cs` |
| 11 | `LSBSTEGO` | Esteganografía LSB en PNG/BMP | `Steganography` | `ISymmetricCipherStrategy`, `ISteganographyPort` | `Steganography/LsbStegoModule.cs` |
| 12 | `EUCLIDESAFFINE` | Euclides Extendido / Afín | `ModularMath` | `ISymmetricCipherStrategy`, `IModularMathCryptoPort` | `ModularMath/EuclidesAffineModule.cs` |
| 13 | `MILLERRABIN` | Miller-Rabin Modular | `ModularMath` | `ISymmetricCipherStrategy`, `IModularMathCryptoPort` | `ModularMath/MillerRabinModule.cs` |
| 14 | `FISHERYATES` | Permutación Fisher-Yates | `ClassicalAndTransposition` | `ISymmetricCipherStrategy`, `IPermutationCipherPort` | `Transposition/FisherYatesModule.cs` |
| 15 | `HASHSHA` | SHA-256 / SHA-512 | `HashingAndMac` | `IHashingServicePort` | `Integrity/HashShaModule.cs` |
| 16 | `HMACSHA256` | HMAC-SHA256 | `HashingAndMac` | `IHashingServicePort` | `Integrity/HmacSha256Module.cs` |
| 17 | `DIGITALSIG` | Firma Digital RSA-PSS | `DigitalSignature` | Servicio de firma dedicado | `Signature/DigitalSignatureRsaPssModule.cs` |
| 18 | `QUANTUMPQC` | Simulación QKD BB84 / LWE | `PostQuantumSimulation` | `ISymmetricCipherStrategy`, `IQuantumPqcSimulationPort` | `PostQuantum/QuantumPqcModule.cs` |
| 19 | `DFTSPECTRAL` | Transformada Discreta de Fourier | `SpectralTransform` | `ISymmetricCipherStrategy`, `ISpectralTransformPort` | `Spectral/DftSpectralModule.cs` |
| 20 | `LAGRANGESHAMIR` | Umbral Shamir GF(256) | `SecretSharing` | `ISymmetricCipherStrategy`, `ISecretSharingPort` | `SecretSharing/LagrangeShamirModule.cs` |
| 21 | `LORENZSZ40` | Cifrado Lorenz SZ40/42 | `ClassicalAndTransposition` | `ISymmetricCipherStrategy`, `IStreamRotorCipherPort` | `Classical/LorenzSz40Module.cs` |

---

## 3. Política de Validación en Tiempo de Ejecución

1. Todo identificador recibido en `manifest.json` (`algorithmCode` o `algorithm`) se resuelve mediante `OfficialAlgorithmCatalog.ParseOrThrow(...)`.
2. Únicamente los identificadores **desconocidos o no registrados** fuera del catálogo oficial de 21 módulos (y sus alias declarados) lanzan `UnsupportedAlgorithmException` (HTTP `422 Unprocessable Entity`).
3. Todas las implementaciones operan sobre la biblioteca base oficial de **.NET 8 LTS** sin dependencias nativas externas.
