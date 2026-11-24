# Bitácora de Control de Agentes IA

Registro cronológico obligatorio de cada intervención realizada sobre el repositorio `RelayCryptoNode`. Todo agente que trabaje en Fases 2, 3 o 4 debe añadir una nueva entrada al final manteniendo este formato estándar.

---

## Formato Estándar de Entrada

- **Fecha / Fase:** `<YYYY-MM-DD> — Fase X`
- **Contexto Consultado:** Archivos y especificaciones leídas antes de editar.
- **Acciones Realizadas:** Resumen concreto de archivos creados o modificados.
- **Contratos Dummy / Hardcodeados / Pendientes:** Qué permanece como marcador o contrato fijo temporal.
- **Completado y Validado:** Evidencia real de compilación y pruebas ejecutadas.

---

## Registro de Intervenciones

### Entrada #01 — 2026-11-24 — Fase 1 (Fundación, Dominio Puro y Documentación Base)

- **Acciones Realizadas:**
  - Creación de `RelayCryptoNode/global.json`, `.gitignore`, `LICENSE` (Licencia Propietaria), `README.md` y `RelayCryptoNode.sln`.
  - Implementación completa de `src/RelayCryptoNode.Domain` (C# 12 puro, `<GenerateDocumentationFile>true</GenerateDocumentationFile>`, 0 paquetes NuGet, 0 referencias de proyecto):
    - `Enums/`: `NodeRole`, `CipherAlgorithmType`, `SignatureAlgorithmType`, `KeyExchangeAlgorithmType`, `HashAlgorithmType`, `PayloadKind`, `RequestStatus`.
    - `Exceptions/`: `DomainException`, `UnsupportedAlgorithmException`, `DecryptionFailedException`, `IntegrityMismatchException`, `InvalidCertificateException`.
    - `ValueObjects/`: `IntegrityDigest`, `NodeIdentity`, `CryptoParameters`.
    - `Entities/`: `PayloadItem`, `PayloadBundle`, `CryptoEnvelope`, `IncomingRequest`, `IntegrityAuditReport` (incluyendo `ItemAuditResult`).
    - `Ports/Inbound/`: `IEmitInitialPackageUseCase`, `IRelayAndReEncryptUseCase`, `IReceiveAndAuditFinalUseCase`, `IManageIncomingRequestsUseCase`.
    - `Ports/Outbound/`: `ISymmetricCipherStrategy`, `IAsymmetricKeyWrapperPort`, `ICertificateServicePort`, `IHashingServicePort`, `IPackageSerializerPort`, `INodeTransportSenderPort`, `IRequestRepositoryPort`, `IEvidenceStoragePort`, `IRealtimeNotifierPort`.
  - Creación de esqueletos de solución: `src/RelayCryptoNode.Application`, `src/RelayCryptoNode.Infrastructure`, `src/RelayCryptoNode.WebHost`, `tests/RelayCryptoNode.UnitTests` y `tests/RelayCryptoNode.IntegrationTests`.
  - Redacción de documentación completa en `docs/` (`ADR-001`, `ADR-002`, `diagramas-flujo-roles.md`, `contrato-intercambio-zip-http.md`, `manual-entorno-desarrollo.md`), reglas en `prompts-agentes/00-contexto-global-reglas.md` y hoja de ruta en `AVANCES_Y_FASES_FUTURAS.md`.
- **Contratos Dummy / Hardcodeados / Pendientes:**
  - `src/RelayCryptoNode.Application`: contiene únicamente `ApplicationAssemblyMarker.cs` (pendiente implementar casos de uso en Fase 2).
  - `src/RelayCryptoNode.Infrastructure`: contiene únicamente `InfrastructureAssemblyMarker.cs` (pendiente implementar adaptadores criptográficos, X.509, ZIP, HTTP, SQLite y almacenamiento en Fase 2).
  - `src/RelayCryptoNode.WebHost/Program.cs`: expone únicamente el endpoint mínimo `GET /api/status` con `protocolVersion: "1.0"`, `status: "online"`, `acceptingPackages: true` y `nodeId` leído de `Node:Id` en `appsettings.json` (valor por defecto `"NODO01"`). Aún no existen `POST /api/requests/receive`, SignalR/SSE ni `wwwroot/`.
  - `tests/RelayCryptoNode.IntegrationTests/ChainIntegrationHarnessTests.cs`: contiene únicamente una prueba de humo de cableado entre ensamblados (pendiente cadena de 3 nodos en Fase 3).
- **Completado y Validado:**
  - `dotnet restore RelayCryptoNode.sln` ejecutado correctamente sobre los 6 proyectos.
  - `dotnet build RelayCryptoNode.sln --no-restore -warnaserror`: compilación correcta con **0 Errores** y **0 Advertencia(s)**.
  - `dotnet test RelayCryptoNode.sln --no-build --verbosity normal`: **29/29** pruebas unitarias aprobadas en `RelayCryptoNode.UnitTests` y **1/1** prueba aprobada en `RelayCryptoNode.IntegrationTests` (0 fallidas, 0 omitidas).
  - Verificación de pureza hexagonal sobre `src/RelayCryptoNode.Domain`: 0 coincidencias de `PackageReference`, `ProjectReference`, `System.Net.Http`, `System.IO.Compression`, `System.Text.Json`, `Microsoft.AspNetCore` o `Microsoft.EntityFrameworkCore`.

### Entrada #02 — 2026-11-24 — Actualización a Catálogo Oficial de 21 Algoritmos y Módulos Dedicados

- **Contexto Consultado:**
  - `prompts-agentes/00-contexto-global-reglas.md`, `docs/01-arquitectura/ADR-002-algoritmos-vigentes.md`, `docs/02-especificacion-protocolo/contrato-intercambio-zip-http.md` y lista oficial actualizada de 21 códigos de algoritmo.
- **Acciones Realizadas:**
  - **Dominio (`src/RelayCryptoNode.Domain`):**
    - Creación de `Enums/OfficialAlgorithmCode.cs` (21 códigos: `AESGCM`, `DES`, `TRIPLEDES`, `CHACHA20`, `RSA`, `ECC`, `DIFFIEHELLMAN`, `CAESAR`, `VIGENERE`, `XORASM`, `LSBSTEGO`, `EUCLIDESAFFINE`, `MILLERRABIN`, `FISHERYATES`, `HASHSHA`, `HMACSHA256`, `DIGITALSIG`, `QUANTUMPQC`, `DFTSPECTRAL`, `LAGRANGESHAMIR`, `LORENZSZ40`), `Enums/AlgorithmCategory.cs`, `ValueObjects/AlgorithmDescriptor.cs` y `Catalog/OfficialAlgorithmCatalog.cs`.
    - Actualización de `CipherAlgorithmType.cs`, `KeyExchangeAlgorithmType.cs` y `UnsupportedAlgorithmException.cs`, eliminando la restricción previa contra algoritmos clásicos o heredados.
    - Incorporación de 7 puertos de salida especializados en `Ports/Outbound/`: `ISteganographyPort`, `IModularMathCryptoPort`, `IPermutationCipherPort`, `IQuantumPqcSimulationPort`, `ISpectralTransformPort`, `ISecretSharingPort` e `IStreamRotorCipherPort`.
  - **Infraestructura (`src/RelayCryptoNode.Infrastructure/Algorithms/`):**
    - Implementación de los 21 módulos dedicados sobre BCL pura de .NET 8 (0 paquetes NuGet externos): `AesGcmModule`, `DesModule`, `TripleDesModule`, `ChaCha20Poly1305Module`, `RsaModule`, `EccModule`, `DiffieHellmanModule`, `CaesarModule`, `VigenereModule`, `XorAsmModule`, `LsbStegoModule` (BMP/PNG), `EuclidesAffineModule`, `MillerRabinModule`, `FisherYatesModule`, `HashShaModule`, `HmacSha256Module`, `DigitalSignatureRsaPssModule`, `QuantumPqcModule` (BB84 + LWE), `DftSpectralModule`, `LagrangeShamirModule` (GF(256)), `LorenzSz40Module` y el registro `AlgorithmModuleRegistry`.
  - **Pruebas y Documentación:**
    - Agregados `OfficialAlgorithmCatalogTests.cs` y `AlgorithmModulesTests.cs` en `tests/RelayCryptoNode.UnitTests/`.
    - Actualizados `00-contexto-global-reglas.md`, `ADR-002-algoritmos-vigentes.md`, `contrato-intercambio-zip-http.md` y `AVANCES_Y_FASES_FUTURAS.md` con el catálogo completo de 21 códigos oficiales.
- **Contratos Dummy / Hardcodeados / Pendientes:**
  - `src/RelayCryptoNode.Application`: sigue conteniendo únicamente `ApplicationAssemblyMarker.cs` (pendiente implementar casos de uso).
  - `src/RelayCryptoNode.Infrastructure`: implementados los 21 módulos de algoritmos, pero aún pendientes los adaptadores de certificados X.509 locales, serialización `.zip` de 3 archivos, transporte HTTP, SQLite y almacenamiento de evidencia.
  - `src/RelayCryptoNode.WebHost/Program.cs`: mantiene únicamente `GET /api/status`.
  - `tests/RelayCryptoNode.IntegrationTests`: mantiene únicamente la prueba base de cableado.
- **Completado y Validado:**
  - `dotnet build RelayCryptoNode.sln --no-restore -warnaserror`: **0 Errores** y **0 Advertencia(s)**.
  - `dotnet test RelayCryptoNode.sln --no-build --verbosity normal`: **79/79** pruebas correctas en `RelayCryptoNode.UnitTests` y **1/1** prueba correcta en `RelayCryptoNode.IntegrationTests` (80/80 totales, 0 fallidas, 0 omitidas).
