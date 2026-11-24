# ADR-001: Arquitectura Hexagonal y Paridad Multiplataforma sobre .NET 8 LTS

- **Estado:** Aceptado
- **Fecha:** 2026-11-24
- **Contexto:** Proyecto RelayCryptoNode — Cadena criptográfica polimórfica de 6 nodos heterogéneos (Windows 11 y Arch Linux).

---

## 1. Contexto del Problema

RelayCryptoNode debe operar en una red local (LAN) conformada por 6 equipos con sistemas operativos mixtos (**Windows 11** y **Arch Linux**), intercambiando paquetes multimedia y documentos cifrados entre tres roles intercambiables (`Initial`, `Intermediate`, `Final`).

Adicionalmente, el sistema requiere:
1. Soportar múltiples algoritmos simétricos, asimétricos, de firma e integridad, con capacidad de incorporar algoritmos poscuánticos (`ML-KEM-768`, `ML-DSA-65`) sin reescribir la lógica de negocio.
2. Desacoplar el mecanismo de transporte actual (HTTP REST + `.zip` sobre LAN/Access Point) de posibles transportes futuros (TCP sockets directos, gRPC o colas locales).
3. Operar sin dependencias nativas externas obligatorias (como `openssl` CLI), evitando diferencias de instalación o rutas entre Windows y Linux.

---

## 2. Decisión Arquitectónica

### 2.1 Arquitectura Hexagonal (Ports & Adapters)

Se adopta una separación estricta en 4 capas:

1. **`RelayCryptoNode.Domain` (Núcleo Puro):**
   - Modela entidades (`PayloadBundle`, `PayloadItem`, `CryptoEnvelope`, `IncomingRequest`, `IntegrityAuditReport`), Value Objects (`NodeIdentity`, `CryptoParameters`, `IntegrityDigest`), excepciones de dominio y contratos de entrada/salida (`Ports/Inbound` y `Ports/Outbound`).
   - No conoce HTTP, ZIP, SQLite ni formatos JSON concretos.
2. **`RelayCryptoNode.Application`:**
   - Orquesta los 3 casos de uso principales (`Initial`, `Intermediate`, `Final`) y la bandeja de solicitudes consumiendo exclusivamente los puertos del Dominio.
3. **`RelayCryptoNode.Infrastructure`:**
   - Implementa los adaptadores concretos: estrategias simétricas (`ISymmetricCipherStrategy`), envoltura de claves (`IAsymmetricKeyWrapperPort`), validación X.509 (`ICertificateServicePort`), empaquetado `.zip` (`IPackageSerializerPort`), cliente HTTP (`INodeTransportSenderPort`), persistencia SQLite (`IRequestRepositoryPort`) y almacenamiento de evidencia (`IEvidenceStoragePort`).
4. **`RelayCryptoNode.WebHost`:**
   - Expone la API REST (`/api/status`, `/api/requests/receive`, control operativo), notificaciones en tiempo real y el panel web estático embebido en `wwwroot/`.

### 2.2 Stack Único .NET 8 LTS + Web Embebida

- **.NET 8 LTS (`net8.0`):** Proporciona un único SDK oficial multiplataforma con soporte nativo para primitivas criptográficas modernas (`AesGcm`, `ChaCha20Poly1305`, `RSA`, `ECDsa`, `ECDiffieHellman`, `X509Certificate2`), compresión ZIP (`System.IO.Compression`), servidor Kestrel embebido y cliente HTTP estándar tanto en Windows 11 x64 como en Arch Linux x64.
- **Web embebida en Kestrel (`wwwroot/`):** Elimina frameworks pesados de escritorio dependientes de plataforma (WPF solo Windows, GTK/Qt con fricción entre entornos), permitiendo que cualquier operador controle su nodo desde el navegador local o LAN sin instalación adicional.

---

## 3. Consecuencias

### Positivas
- **Pruebas unitarias deterministas:** El Dominio se prueba en milisegundos sin levantar servidores HTTP, bases de datos ni archivos en disco.
- **Extensibilidad polimórfica:** Agregar un nuevo algoritmo (por ejemplo `XChaCha20Poly1305` o `MlKem768`) solo exige registrar una nueva implementación de `ISymmetricCipherStrategy` o `IAsymmetricKeyWrapperPort` en `Infrastructure`.
- **Paridad de desarrollo:** Un mismo código y un mismo `global.json` compilan y pasan idénticas pruebas en Windows 11 y Arch Linux.

### Compromisos Asumidos
- Mayor número de interfaces y DTOs de frontera entre capas, compensado por el aislamiento limpio frente a cambios en transporte o almacenamiento.
- Para algoritmos no incluidos aún en la BCL base de .NET 8 en ciertas configuraciones (como `ML-KEM`, `ML-DSA` o `Ed25519`/`SHA3` según backend OpenSSL/Windows CNG), los adaptadores de `Infrastructure` podrán encapsular bibliotecas administradas aprobadas manteniendo intacto el `Domain`.
