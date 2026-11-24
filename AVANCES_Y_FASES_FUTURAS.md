# Avances del Proyecto y Hoja de Ruta de Fases Futuras

**Proyecto:** `RelayCryptoNode`  
**Fecha de corte:** 2026-11-24  
**Plataforma base:** `.NET 8 LTS (SDK 8.0.x, C# 12)` — Multiplataforma (Windows 11 y Arch Linux).

---

## 1. Resumen Ejecutivo de Avances (Fase 1 + Catálogo Completo de 21 Módulos)

Se completó la **Fase 1** y la expansión integral del **Catálogo Oficial de 21 Algoritmos** dentro de `RelayCryptoNode/`, respetando estrictamente la Arquitectura Hexagonal (`WebHost -> Infrastructure -> Application -> Domain`) sin dependencias NuGet externas en producción ni herramientas nativas obligatorias.

### 1.1 Componentes Completados y Verificados

| Área | Entregables Implementados | Estado |
| :--- | :--- | :--- |
| **Raíz y Gobierno** | `global.json`, `.gitignore`, `LICENSE` (Licencia Propietaria), `README.md`, `RelayCryptoNode.sln` | Validado |
| **Dominio Puro (`RelayCryptoNode.Domain`)** | Catálogo oficial de 21 códigos (`OfficialAlgorithmCode`, `OfficialAlgorithmCatalog`, `AlgorithmDescriptor`), 9 Enums totales, 5 Excepciones, 3 Value Objects base, 5 Entidades (`PayloadItem`, `PayloadBundle`, `CryptoEnvelope`, `IncomingRequest`, `IntegrityAuditReport` + `ItemAuditResult`), 4 Puertos Inbound y 16 Puertos Outbound (incluyendo puertos dedicados para esteganografía, aritmética modular, permutación, PQC/BB84, DFT espectral, Shamir GF(256) y rotores) | Compilado (0 warnings) |
| **21 Módulos Dedicados (`RelayCryptoNode.Infrastructure/Algorithms/`)** | `AesGcmModule`, `DesModule`, `TripleDesModule`, `ChaCha20Poly1305Module`, `RsaModule`, `EccModule`, `DiffieHellmanModule`, `CaesarModule`, `VigenereModule`, `XorAsmModule`, `LsbStegoModule` (BMP/PNG), `EuclidesAffineModule`, `MillerRabinModule`, `FisherYatesModule`, `HashShaModule`, `HmacSha256Module`, `DigitalSignatureRsaPssModule`, `QuantumPqcModule` (BB84 + LWE), `DftSpectralModule`, `LagrangeShamirModule` (GF(256)), `LorenzSz40Module` + `AlgorithmModuleRegistry` | 21/21 implementados y probados |
| **Esqueletos de Capas** | `RelayCryptoNode.Application`, `RelayCryptoNode.WebHost` (`GET /api/status`), `RelayCryptoNode.IntegrationTests` | Compilado y enlazado |
| **Pruebas Automatizadas** | `RelayCryptoNode.UnitTests` (79 pruebas xUnit de dominio, catálogo oficial y round-trip de los 21 módulos) + `RelayCryptoNode.IntegrationTests` (1 prueba de cableado) | 80/80 aprobadas |
| **Documentación Técnica** | `ADR-001`, `ADR-002` (catálogo oficial de 21 módulos), `diagramas-flujo-roles.md`, `contrato-intercambio-zip-http.md`, `manual-entorno-desarrollo.md`, `00-contexto-global-reglas.md`, `bitacora-agentes-ia.md` | Completa |

### 1.2 Evidencia de Validación

- **Compilación estricta (`dotnet build RelayCryptoNode.sln --no-restore -warnaserror`):** `0 Errores`, `0 Advertencia(s)`.
- **Ejecución de pruebas (`dotnet test RelayCryptoNode.sln --no-build --verbosity normal`):**
  - `RelayCryptoNode.UnitTests`: **79/79** pruebas correctas.
  - `RelayCryptoNode.IntegrationTests`: **1/1** prueba correcta.
- **Pureza Hexagonal:** Verificado que `RelayCryptoNode.Domain` tiene **0** paquetes NuGet externos, **0** referencias de proyecto y **0** dependencias a HTTP, ZIP, JSON, ASP.NET Core o Entity Framework.

### 1.3 Elementos Pendientes / Contratos Dummy Actuales

1. `RelayCryptoNode.Application` solo contiene `ApplicationAssemblyMarker.cs`; falta implementar los casos de uso (`Initial`, `Intermediate`, `Final`, gestión de bandeja).
2. `RelayCryptoNode.Infrastructure` ya cuenta con los 21 módulos de algoritmos, pero aún faltan los adaptadores de certificados X.509 locales (`ICertificateServicePort`), empaquetado `.zip` de 3 archivos (`IPackageSerializerPort`), transporte HTTP (`INodeTransportSenderPort`), repositorio SQLite (`IRequestRepositoryPort`) y almacenamiento de evidencia (`IEvidenceStoragePort`).
3. `RelayCryptoNode.WebHost/Program.cs` solo expone `GET /api/status` leyendo `Node:Id` (`"NODO01"` por defecto) desde `appsettings.json`.
4. `RelayCryptoNode.IntegrationTests` solo verifica el enlace entre ensamblados; falta la prueba de cadena completa de 3 nodos.

---

## 2. Fases Futuras a Implementar

### Fase 2 — Capa de Aplicación e Infraestructura de Certificados, ZIP, HTTP y SQLite

**Objetivo:** Conectar los 21 módulos criptográficos ya implementados con los casos de uso de los 3 roles, el empaquetado `.zip` y la persistencia local.

1. **Casos de Uso en `RelayCryptoNode.Application`:**
   - Implementar `EmitInitialPackageUseCase` (`IEmitInitialPackageUseCase`): cálculo de hashes SHA-256 originales por ítem y global, serialización de `PayloadBundle`, cifrado con cualquiera de los módulos seleccionados en `AlgorithmModuleRegistry`, envoltura de clave (`RSA`, `ECC`, `DIFFIEHELLMAN`, `QUANTUMPQC` o PSK), firma de manifiesto, empaquetado `.zip` y envío por `INodeTransportSenderPort`.
   - Implementar `RelayAndReEncryptUseCase` (`IRelayAndReEncryptUseCase`): autodetección de algoritmo mediante `OfficialAlgorithmCatalog.ParseOrThrow(...)`, descifrado exclusivamente en memoria RAM (sin escribir texto claro en disco), re-encriptación con el algoritmo de salida configurado, re-firma y reenvío.
   - Implementar `ReceiveAndAuditFinalUseCase` (`IReceiveAndAuditFinalUseCase`): descifrado final, recálculo de SHA-256 global y por archivo, generación de `IntegrityAuditReport.CreateComparison(...)` y resguardo mediante `IEvidenceStoragePort`.
   - Implementar `ManageIncomingRequestsUseCase` (`IManageIncomingRequestsUseCase`) con notificaciones en vivo vía `IRealtimeNotifierPort`.
2. **Adaptadores Restantes en `RelayCryptoNode.Infrastructure`:**
   - Servicio X.509 (`ICertificateServicePort`): carga/generación de `.pfx` local en `.NET 8`, validación de vigencia/formato PEM, cálculo de huella SHA-256, firma y verificación (`RsaPssSha256`, `EcdsaP256`).
   - `ZipPackageSerializerAdapter` (`IPackageSerializerPort`): genera `.zip` con exactamente `datos.enc`, `certificado.pem` y `manifest.json`, nomenclatura `<NODO_ORIGEN>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8>.zip`, y estrategia defensiva dual (`algorithmCode` + `algorithm`).
   - `HttpNodeTransportSender` (`INodeTransportSenderPort`): cliente `HttpClient` enviando `multipart/form-data` a `/api/requests/receive`.
   - `SqliteRequestRepository` (`IRequestRepositoryPort`) y `FileSystemEvidenceStorage` (`IEvidenceStoragePort`).
3. **Pruebas de Fase 2:**
   - Pruebas unitarias de `Application` con dobles de puertos y pruebas cruzadas de re-encriptación entre los 21 códigos oficiales.

---

### Fase 3 — WebHost API REST, Tiempo Real, Interfaz Web y Pruebas de Cadena de 3 Nodos

**Objetivo:** Exponer la operación completa del nodo por HTTP + panel web en tiempo real y verificar la cadena completa de 3 roles en pruebas automatizadas.

1. **Endpoints REST en `RelayCryptoNode.WebHost`:**
   - `POST /api/requests/receive`: recibe `multipart/form-data`, valida tamaño (`413`), estructura ZIP (`400`), código de algoritmo fuera del catálogo de 21 / certificado (`422`) y registra en bandeja devolviendo `202 Accepted`.
   - Endpoints operativos: cambio de rol en caliente (`Initial` / `Intermediate` / `Final`), selector de los 21 algoritmos oficiales, configuración de nodo destino, aprobación/rechazo en bandeja y consulta de auditorías.
   - `RealtimeNotifierAdapter` (`IRealtimeNotifierPort`) mediante SignalR o Server-Sent Events (SSE).
2. **Interfaz Web Embebida (`RelayCryptoNode.WebHost/wwwroot/`):**
   - Separación estricta obligatoria: `index.html` (estructura semántica sin JS/CSS inline), `css/*.css` y `js/*.js`.
   - Vistas operativas para selector de rol en caliente, selector de algoritmo entre los 21 módulos, emisor inicial multi-archivo/imagen (incluyendo portadores BMP/PNG para `LSBSTEGO`), bandeja de solicitudes (`Accept` / `Reject`), log de relevos y visor de auditoría bit a bit (`IsBitExactMatch`, `ByteLossCount`).
3. **Pruebas de Integración End-to-End (`RelayCryptoNode.IntegrationTests`):**
   - Levantar 3 instancias reales en memoria con `WebApplicationFactory<Program>` (`Initial` -> `Intermediate` -> `Final`) ejecutando transmisión real `.zip` sobre HTTP, cambio de algoritmo en el nodo intermedio (por ejemplo `AESGCM` -> `LORENZSZ40` -> auditoría final) y verificación `IsBitExactMatch == true` y `ByteLossCount == 0`.

---

### Fase 4 — Despliegue LAN de 6 Nodos Heterogéneos y Pruebas de Interoperabilidad

**Objetivo:** Validar interoperabilidad real entre los 6 equipos físicos (Windows 11 y Arch Linux) conectados en red local.

1. **Despliegue en Red Local (Access Point / LAN):**
   - Levantar los 6 equipos escuchando en puerto TCP `5000`, intercambiando certificados `.pem` y ejecutando cadenas multi-salto con rotación dinámica entre los 21 algoritmos del catálogo.
2. **Pruebas de Campo y Auditoría Final:**
   - Validación de compatibilidad `algorithmCode` / `algorithm` con las implementaciones de los otros equipos.
   - Pruebas con texto plano, documentos PDF, imágenes PNG/BMP (`LSBSTEGO`), lotes multiparte y registro final en `prompts-agentes/bitacora-agentes-ia.md`.
