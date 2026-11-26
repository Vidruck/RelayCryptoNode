# RelayCryptoNode

Nodo criptográfico polimórfico multiplataforma sobre **.NET 8 LTS (C# 12)** diseñado para operar dentro de una cadena LAN de equipos heterogéneos (**Windows 11** y **Arch Linux**).

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
│   ├── RelayCryptoNode.Application/            # Capa 2: casos de uso Initial / Intermediate / Final y bandeja
│   ├── RelayCryptoNode.Infrastructure/         # Capa 3: 21 algoritmos, X.509, ZIP, HTTP, bandeja en disco, evidencias
│   └── RelayCryptoNode.WebHost/                # Capa 4: API REST + panel web (wwwroot) + bitácora en vivo (SSE)
├── INICIAR_NODO.bat                            # Arranque rápido en Windows (opcional)
└── tests/
    ├── RelayCryptoNode.UnitTests/              # Pruebas xUnit del Dominio, algoritmos y empaquetado
    └── RelayCryptoNode.IntegrationTests/       # Cadena real de 3 nodos en memoria + compatibilidad NODO04
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

### Arrancar el nodo (Puerto 5000)

```bash
dotnet run --project src/RelayCryptoNode.WebHost/RelayCryptoNode.WebHost.csproj
```

En Windows también se puede dar doble clic a `INICIAR_NODO.bat`. El panel queda en `http://localhost:5000/` y, desde otra
computadora de la red, en `http://<IP-del-equipo>:5000/`.

La primera vez el nodo genera su certificado X.509 (RSA 2048, `CN=NODO06`) en `src/RelayCryptoNode.WebHost/datos/certificados/`.
La carpeta `datos/` también guarda la bandeja (`bandeja/`), las evidencias de auditoría (`evidencia/`) y la configuración
que se cambie desde el panel (`configuracion-nodo.json`). Está excluida de git.

Verificar estado del nodo:

```bash
curl http://localhost:5000/api/status
```

Respuesta esperada:

```json
{
  "nodeId": "NODO06",
  "protocolVersion": "1.0",
  "status": "online",
  "acceptingPackages": true,
  "certificateThumbprint": "9E0FE9EC…",
  "role": "Final",
  "endpoint": "http://192.168.1.6:5000"
}
```

### Configuración (`src/RelayCryptoNode.WebHost/appsettings.json`)

| Clave `Node:*` | Valor por defecto | Uso |
| :--- | :--- | :--- |
| `Id` | `NODO06` | Identificador del nodo y CN del certificado. |
| `Role` | `Final` | `Initial`, `Intermediate` o `Final` (se cambia en caliente desde el panel). |
| `PublicUrl` | *(vacío)* | Dirección que se anuncia; vacío = IP de la red local detectada + puerto. |
| `NextNode` | *(vacío)* | Siguiente nodo de la cadena (`IP:puerto`). |
| `OutgoingAlgorithm` | `AESGCM` | Código del catálogo con el que se cifra la salida. |
| `KeyExchange` | `RsaOaepSha256` | Envoltura de la clave de sesión: `RsaOaepSha256` o `PreSharedKey`. |
| `SharedKeyFormat` | `false` | Salida en formato de clave compartida del grupo (compatible con NODO04, solo AES-GCM). |
| `SharedAesKey` | `clave-aes-256-segura` | Clave de texto de AES-GCM en formato compartido (la misma que trae el NODO04). |
| `PreSharedKey` | *(vacío)* | PSK del grupo para envolver la clave de sesión sin certificados. |
| `AutoProcess` | `false` | Acepta y procesa solos los paquetes válidos. |
| `MaxPackageMegabytes` | `50` | Límite del `.zip` (responde `413` si se excede). |

### Endpoints

| Método y ruta | Uso |
| :--- | :--- |
| `GET /api/status` | Estado del nodo (contrato común). |
| `GET /api/certificate` | Certificado PEM público del nodo (para envolver la clave de sesión con RSA-OAEP). |
| `POST /api/requests/receive` | Recibe el `.zip` (`multipart/form-data`, campo `package`): `202`, `400`, `413` o `422`. |
| `GET /api/requests[?status=Pending]` | Bandeja de solicitudes. |
| `POST /api/requests/{id}/accept` | Acepta y procesa según el rol: Intermediate reenvía; Initial/Final descifran y auditan. |
| `POST /api/requests/{id}/reject` | Rechaza (`{"reason":"…"}`). |
| `GET /api/requests/{id}/package` | Descarga el `.zip` recibido. |
| `POST /api/emit` | Emite un paquete (archivos y/o texto, destino, algoritmo y clave de sesión). |
| `GET /api/audits/{packetId}` · `GET /api/evidence/{packetId}/{archivo}` | Reporte de auditoría y archivos recuperados. |
| `GET/PUT /api/config` | Rol, siguiente nodo, algoritmo de salida y claves. |
| `GET /api/events` · `GET /api/events/stream` | Bitácora y bitácora en vivo (Server-Sent Events). |

### Compatibilidad con otros equipos

El `manifest.json` que emite el nodo es el formato plano que usa el grupo (el mismo del NODO04) y la firma
`manifestSignatureBase64` es RSA-PSS-SHA256 sobre `encryptedSha256|HUELLA_SHA256_DEL_CERTIFICADO|timestampUtc`.
Los datos propios de RelayCryptoNode (nonce, etiqueta, clave de sesión envuelta, huella del original) viajan en
`publicParameters` con prefijo `rcn.`, que los demás nodos ignoran. Al recibir, se aceptan tanto ese formato como el
anidado descrito en el contrato. Detalle en [contrato-intercambio-zip-http.md](docs/02-especificacion-protocolo/contrato-intercambio-zip-http.md).

Para configurar el entorno de red, certificados y reglas de firewall en Windows 11 y Arch Linux, consulte [manual-entorno-desarrollo.md](docs/03-manuales/manual-entorno-desarrollo.md).

---

## Licencia

Distribuido bajo **Licencia Propietaria** — Todos los derechos reservados. Consulte el archivo [LICENSE](LICENSE).
