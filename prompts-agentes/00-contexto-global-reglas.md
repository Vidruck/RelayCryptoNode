# Contexto Global y Reglas Inmutables para Agentes (Fases 2, 3 y 4)

Este documento define las **restricciones arquitectónicas, operativas y de privacidad no negociables** que todo agente de desarrollo o refactorización debe cumplir al trabajar sobre `RelayCryptoNode`.

---

## 0. Directiva Global de Privacidad, Datos Personales y Rutas Relativas (Cero Tolerancia)

1. **Prohibido usar o registrar rutas absolutas del equipo local:**
   - Nunca escribir rutas absolutas de disco del usuario ni de la máquina (por ejemplo rutas de perfil de usuario, `C:\Users\...`, etc.) en código fuente, pruebas, documentación, manifiestos o respuestas.
   - Utilizar exclusivamente rutas relativas a la raíz del repositorio (por ejemplo `RelayCryptoNode/src/...`, `src/RelayCryptoNode.Domain/...`).
2. **Prohibido exponer datos personales o del equipo:**
   - Nunca incluir nombres de usuario del sistema operativo, nombres de host, direcciones personales ni identificadores de arquitectura/máquina local en el repositorio o en salidas generadas.

---

## 1. Reglas de Arquitectura Hexagonal (Cero Tolerancia)

1. **`RelayCryptoNode.Domain` es C# puro (.NET 8):**
   - Prohibido agregar `<PackageReference>` externos o referencias de proyecto.
   - Prohibido importar o usar `System.Net.Http`, `System.IO.Compression`, `System.Text.Json`, `Microsoft.AspNetCore.*`, `Microsoft.EntityFrameworkCore.*` o librerías de SQLite dentro de `Domain`.
   - Toda entidad, Value Object, puerto y excepción pública debe mantener validación estricta de invariantes y documentación XML (`/// <summary>`).

2. **Dirección estricta de dependencias entre proyectos:**
   - `RelayCryptoNode.Domain` -> *(sin dependencias)*
   - `RelayCryptoNode.Application` -> `RelayCryptoNode.Domain`
   - `RelayCryptoNode.Infrastructure` -> `RelayCryptoNode.Domain`, `RelayCryptoNode.Application`
   - `RelayCryptoNode.WebHost` -> `RelayCryptoNode.Application`, `RelayCryptoNode.Infrastructure`
   - Nunca invertir esta dirección ni saltarse capas desde `WebHost` hacia implementaciones internas omitiendo puertos.

---

## 2. Catálogo Oficial de Algoritmos Soportados (21 Módulos Obligatorios)

Se **anula cualquier directiva previa** que restringía o descartaba algoritmos clásicos o heredados. Todos los 21 códigos oficiales del catálogo (`OfficialAlgorithmCatalog`) están habilitados con módulo dedicado en `RelayCryptoNode.Infrastructure/Algorithms/` y son seleccionables en caliente:

| # | Código Oficial | Nombre / Descripción |
|---|---|---|
| 1 | `AESGCM` | AES-256-GCM |
| 2 | `DES` | DES 56-bit |
| 3 | `TRIPLEDES` | Triple DES / 3DES |
| 4 | `CHACHA20` | ChaCha20-Poly1305 |
| 5 | `RSA` | RSA-OAEP / RSA-PSS |
| 6 | `ECC` | ECDH / ECDSA |
| 7 | `DIFFIEHELLMAN` | Diffie-Hellman |
| 8 | `CAESAR` | Cifrado César |
| 9 | `VIGENERE` | Cifrado Vigenère |
| 10 | `XORASM` | XOR en Registro |
| 11 | `LSBSTEGO` | Esteganografía LSB en PNG/BMP |
| 12 | `EUCLIDESAFFINE` | Euclides Extendido / Afín |
| 13 | `MILLERRABIN` | Miller-Rabin Modular |
| 14 | `FISHERYATES` | Permutación Fisher-Yates |
| 15 | `HASHSHA` | SHA-256 / SHA-512 |
| 16 | `HMACSHA256` | HMAC-SHA256 |
| 17 | `DIGITALSIG` | Firma Digital RSA-PSS |
| 18 | `QUANTUMPQC` | Simulación QKD BB84 / LWE |
| 19 | `DFTSPECTRAL` | Transformada Discreta de Fourier |
| 20 | `LAGRANGESHAMIR` | Umbral Shamir GF(256) |
| 21 | `LORENZSZ40` | Cifrado Lorenz SZ40/42 |

- Solo se lanzará `UnsupportedAlgorithmException` (HTTP `422`) cuando un paquete declare un identificador **no registrado** fuera de este catálogo oficial y sus alias aceptados.
- **Procesamiento en memoria RAM para nodos intermedios:** Un nodo en rol `Intermediate` debe descifrar el `PayloadBundle` exclusivamente en memoria RAM y re-encriptarlo con el algoritmo de salida configurado sin persistir texto plano en disco.
- **Multiplataforma pura (.NET 8 LTS):** Prohibido invocar binarios externos (`openssl`, `gpg`, `curl` por subproceso) como requisito de ejecución.

---

## 3. Reglas de Interoperabilidad ZIP / HTTP

1. Respetar exactamente el contrato definido en `docs/02-especificacion-protocolo/contrato-intercambio-zip-http.md`:
   - Nomenclatura: `<NODO_ORIGEN>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8>.zip`
   - Exactamente 3 entradas en raíz del ZIP: `datos.enc`, `certificado.pem`, `manifest.json`.
   - **Estrategia defensiva:** al emitir `manifest.json`, serializar **ambos** campos (`algorithmCode` y `algorithm`); al leer, aceptar cualquiera de los dos priorizando `algorithmCode`.

---

## 4. Reglas de Frontend en `RelayCryptoNode.WebHost/wwwroot/`

1. **Separación estricta de responsabilidades:**
   - `wwwroot/index.html` (y vistas HTML): únicamente estructura semántica; **prohibido** JavaScript inline (`<script>...</script>`, `onclick="..."`) y estilos inline (`style="..."`).
   - `wwwroot/css/*.css`: únicamente hojas de estilo.
   - `wwwroot/js/*.js`: únicamente lógica de cliente en módulos ES limpios o scripts separados, consumiendo la API REST y notificaciones en tiempo real (SignalR/SSE).

---

## 5. Calidad de Compilación y Control en Bitácora

1. `dotnet build RelayCryptoNode.sln --no-restore -warnaserror` y `dotnet test RelayCryptoNode.sln --no-build` deben finalizar con **0 errores y 0 advertencias**.
2. **Obligación de registro:** al concluir cualquier intervención técnica, el agente debe añadir una entrada cronológica en `prompts-agentes/bitacora-agentes-ia.md` documentando contexto consultado, archivos modificados, contratos dummy/hardcodeados pendientes y evidencia de compilación/pruebas (siempre con rutas relativas).
