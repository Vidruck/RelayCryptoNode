# RelayCryptoNode

Nodo criptográfico polimórfico multiplataforma sobre **.NET 8 LTS (C# 12)** diseñado para operar dentro de una cadena LAN de  equipos heterogéneos (**Windows 11** y **Arch Linux**).

Cada nodo puede asumir en caliente cualquiera de tres modalidades operativas:
- **`Initial`**: Empaqueta documentos, texto, imágenes o lotes multimedia, calcula la huella testigo `SHA-256`, cifra con el algoritmo elegido, firma con su certificado X.509 local y transmite al siguiente nodo.
- **`Intermediate`**: Recibe paquetes `.zip` firmados, valida certificado e integridad, autodetecta el algoritmo entrante, descifra exclusivamente en memoria RAM, re-encripta cambiando al algoritmo de salida configurado y reenvía.
- **`Final`**: Valida certificado, descifra y ejecuta una auditoría bit a bit (tamaño, cantidad de ítems y `SHA-256` por archivo y global) frente al paquete original para cuantificar pérdidas.

---

## Arquitectura de la Solución

La solución sigue **Arquitectura Hexagonal (Ports & Adapters)** con dirección estricta de dependencias (`WebHost -> Infrastructure -> Application -> Domain`):

```text
RelayCryptoNode/
├── global.json                                 # SDK .NET 8.0.x (rollForward: latestMinor)
├── .gitignore                                  # .NET, SQLite (*.db) y certificados (*.pfx, *.pem, *.key)
├── LICENSE                                     # Licencia Propietaria
├── RelayCryptoNode.sln
├── README.md
├── AVANCES_Y_FASES_FUTURAS.md                  # Estado actual y hoja de ruta Fases 2, 3 y 4
├── prompts-agentes/
│   ├── 00-contexto-global-reglas.md            # Reglas arquitectónicas inmutables
│   └── bitacora-agentes-ia.md                  # Bitácora de control de agentes IA
├── docs/
│   ├── 01-arquitectura/
│   │   ├── ADR-001-arquitectura-hexagonal.md
│   │   ├── ADR-002-algoritmos-vigentes.md
│   │   └── diagramas-flujo-roles.md
│   ├── 02-especificacion-protocolo/
│   │   └── contrato-intercambio-zip-http.md
│   └── 03-manuales/
│       └── manual-entorno-desarrollo.md
├── src/
│   ├── RelayCryptoNode.Domain/                 # Capa 1: C# puro, 0 NuGet externos
│   ├── RelayCryptoNode.Application/            # Capa 2: Esqueleto (Fase 2)
│   ├── RelayCryptoNode.Infrastructure/         # Capa 3: Esqueleto (Fase 2)
│   └── RelayCryptoNode.WebHost/                # Capa 4: ASP.NET Core 8 (GET /api/status activo)
└── tests/
    ├── RelayCryptoNode.UnitTests/              # Pruebas xUnit del Dominio
    └── RelayCryptoNode.IntegrationTests/       # Esqueleto de pruebas de cadena 3 nodos (Fase 3)
```

---

## Arranque Rápido (Windows 11 y Linux)

Requiere únicamente **.NET 8 SDK LTS** (sin dependencias nativas obligatorias como OpenSSL).

### Restaurar, compilar y ejecutar pruebas

```bash
cd RelayCryptoNode
dotnet restore RelayCryptoNode.sln
dotnet build RelayCryptoNode.sln --no-restore -warnaserror
dotnet test RelayCryptoNode.sln --no-build --verbosity normal
```

### Arrancar el host HTTP mínimo (Puerto 5000)

```bash
dotnet run --project src/RelayCryptoNode.WebHost/RelayCryptoNode.WebHost.csproj
```

Verificar estado del nodo:

```bash
curl http://localhost:5000/api/status
```

Respuesta esperada:

```json
{
  "nodeId": "NODO01",
  "protocolVersion": "1.0",
  "status": "online",
  "acceptingPackages": true
}
```

Para configurar el entorno de red, certificados y reglas de firewall en Windows 11 y Arch Linux, consulte [manual-entorno-desarrollo.md](docs/03-manuales/manual-entorno-desarrollo.md).

---

## Licencia

Distribuido bajo **Licencia Propietaria** — Todos los derechos reservados. Consulte el archivo [LICENSE](LICENSE).
