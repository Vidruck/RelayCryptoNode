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
│   │   ├── contrato-intercambio-zip-http.md     # Formato v1 (NODO04)
│   │   └── estandar-v2.md                      # Implementación del Estándar v2.0
│   └── 03-manuales/
│       └── manual-entorno-desarrollo.md
├── src/
│   ├── RelayCryptoNode.Domain/                 # Capa 1: C# puro, 0 NuGet externos
│   ├── RelayCryptoNode.Application/            # Capa 2: casos de uso Initial / Intermediate / Final y bandeja
│   ├── RelayCryptoNode.Infrastructure/         # Capa 3: 21 algoritmos, X.509, ZIP, HTTP, bandeja, evidencias y ProtocolV2/
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

### Arrancar el nodo

```bash
dotnet run --project src/RelayCryptoNode.WebHost/RelayCryptoNode.WebHost.csproj
```

En Windows también se puede dar doble clic a `INICIAR_NODO.bat`. El nodo escucha en dos puertos:

| Puerto | Uso |
| :--- | :--- |
| **TCP 5006** (`5000 + equipo`) | Estándar de Comunicación **v2.0** y panel web: `http://<IP>:5006/` |
| **TCP 5000** | Formato anterior (v1 / NODO04), para los nodos que todavía no migran. Se omite si el puerto está ocupado. |
| **UDP 5099** | Anuncio `CC-BEACON` cada 30 s y escucha de los demás nodos. |

En Windows hay que abrir los tres en el firewall (ver el [manual](docs/03-manuales/manual-entorno-desarrollo.md)).

La primera vez el nodo genera su certificado X.509 (`CN=EQ06, OU=Equipo 06, O=Centro de Ciberseguridad, C=MX`, RSA 2048,
365 días; llave privada PKCS#8 cifrada) en `src/RelayCryptoNode.WebHost/datos/certificados/`. Si encuentra un certificado
viejo (`CN=NODO06`) lo reemplaza. La carpeta `datos/` también guarda el directorio de nodos, los paquetes v2 (`v2/`),
la bandeja v1 (`bandeja/`), las evidencias y la configuración. Está excluida de git.

```bash
curl http://localhost:5006/api/status
```

```json
{
  "nodeId": "EQ06",
  "teamNumber": 6,
  "protocolVersion": "2.0",
  "status": "online",
  "httpPort": 5006,
  "certificateThumbprintSha256": "C93E2767…",
  "supportedProtocolVersions": ["2.0", "1.0"]
}
```

### Acceso, versiones y escaneo

- **Login:** el panel pide usuario y contraseña. Hay dos superusuarios en `Auth:Users` de `appsettings.json`:
  `gatica` y `tellez` (contraseñas con hash PBKDF2-SHA256). Para cambiar una contraseña se reemplaza su `PasswordHash`.
  El login solo protege el panel (`/`, `/api/ui`, `/api/v1`); lo que usan los otros nodos (`/api/status`,
  `/api/certificate`, `/api/algorithms`, `/api/requests/receive`, `/api/crypto/*`) sigue abierto.
- **Versiones** (selector arriba a la derecha):
  - **v1:** formato anterior (NODO04), en la pestaña *Modo v1*.
  - **v2:** estándar: el EQ06 ejecuta el 11 y el 12 y los demás se le piden al equipo dueño.
  - **v3:** los **21 algoritmos** se cifran y descifran en este nodo. Los paquetes siguen siendo v2.0 válidos
    (misma firma y manifiesto). Si no se escribe clave, el nodo genera una y la guarda en `datos/v3/llaves.json`
    para poder invertir después sin volver a escribirla.
- **Escaneo automático:** cada 30 s el nodo revisa la subred de su tarjeta de red (hasta un bloque /22) en los puertos
  5000 a 5020, además de los anuncios UDP 5099. `Node:ScanHosts` agrega IPs fijas a revisar (separadas por coma).

### Panel (interfaz)

| Pestaña | Qué hace |
| :--- | :--- |
| **Consola** | Identidad y huella del nodo, radar de la LAN, contadores y matriz de los 21 algoritmos con su disponibilidad. |
| **Operar** | `forward` de cualquier algoritmo: local si es del EQ06 (11 LSBSTEGO, 12 EUCLIDESAFFINE) o delegado al nodo dueño. Los parámetros y secretos salen del perfil que publica cada nodo. |
| **Red** | Directorio de nodos (anuncio UDP, escaneo HTTP de la subred o alta manual) y confirmación de la huella (TOFU). |
| **Solicitudes** | Paquetes v2 que llegan a la bandeja: aceptar o rechazar. |
| **Consultas** | Paquetes generados, aceptados y resultados: descargar, ver manifiesto, invertir, enviar a otro nodo. |
| **Modo v1** | Cadena del formato anterior (rol Initial/Intermediate/Final, emisión y bandeja v1). |
| **Bitácora** | Eventos en vivo (SSE). |

### Configuración (`src/RelayCryptoNode.WebHost/appsettings.json`)

| Clave `Node:*` | Valor por defecto | Uso |
| :--- | :--- | :--- |
| `TeamNumber` | `6` | Número de equipo: define `EQ06`, el puerto `5006` y los algoritmos propios. |
| `LegacyPort` | `5000` | Puerto del formato v1 (`0` para desactivarlo). |
| `Urls` | *(vacío)* | Fuerza las direcciones de escucha (separadas por `;`). |
| `ProvidedAlgorithms` | *(vacío)* | Sustituye la lista de algoritmos propios (por defecto la de la tabla 4.1). |
| `Role`, `NextNode`, `OutgoingAlgorithm`, `KeyExchange`, `SharedKeyFormat`, `SharedAesKey`, `PreSharedKey`, `AutoProcess` | | Cadena v1 (igual que antes; se cambian en la pestaña *Modo v1*). |
| `MaxPackageMegabytes` | `50` | Límite del `.zip`. |

### Endpoints del estándar v2.0

| Método y ruta | Uso |
| :--- | :--- |
| `GET /api/status` · `GET /api/certificate` · `GET /api/algorithms` | Estado, certificado PEM y perfil de algoritmos. |
| `POST /api/requests/receive` | Bandeja: `202` con un paquete v2 válido; errores `problem+json` (`E-ZIP-STRUCTURE`, `E-HASH`, `E-SIGNATURE`, `E-TIMESTAMP`, `E-DUPLICATE` 409, `E-CERT-UNTRUSTED` 403…). Si el zip es del formato anterior se procesa como v1. |
| `POST /api/crypto/forward` · `POST /api/crypto/inverse` | Servicio de algoritmo para otros nodos (secretos en sobre CC-ENV-1, resultado `RES_*.zip` firmado). |
| `GET /api/jobs/{id}` · `GET /api/keys/{id}` | Responden `E-JOB-NOT-FOUND` / `E-KEY-NOT-FOUND` (el nodo trabaja en modo síncrono). |

El formato anterior queda bajo `/api/v1/*` (`requests`, `emit`, `config`, `algorithms`, `audits`, `evidence`, `events`).
Detalle en [estandar-v2.md](docs/02-especificacion-protocolo/estandar-v2.md) y
[contrato-intercambio-zip-http.md](docs/02-especificacion-protocolo/contrato-intercambio-zip-http.md) (v1).

### Compatibilidad con el formato anterior

Un paquete cuyo `manifest.json` no trae `"version": "2.x"` se procesa con la lógica v1: manifiesto plano del grupo
(el del NODO04), firma RSA-PSS-SHA256 sobre `encryptedSha256|HUELLA|timestampUtc` y AES-GCM de clave compartida.
Funciona tanto en el puerto 5006 como en el 5000, y la pestaña *Modo v1* sigue emitiendo en ese formato.

---

## Licencia

Distribuido bajo **Licencia Propietaria** — Todos los derechos reservados. Consulte el archivo [LICENSE](LICENSE).
