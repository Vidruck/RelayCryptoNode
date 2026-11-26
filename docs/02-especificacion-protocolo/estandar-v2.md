# Estándar de Comunicación v2.0 — implementación del EQ06

Resumen de cómo implementa RelayCryptoNode el Estándar de Comunicación v2.0 del Centro de Ciberseguridad y qué se
probó. El documento normativo es el PDF del grupo; aquí se citan sus secciones.

## 1. Identidad y red

| Concepto | Valor en el EQ06 |
| :--- | :--- |
| `nodeId` | `EQ06` (`EQ` + equipo a dos dígitos) |
| Puerto HTTP | `5006` (`5000 + equipo`); el formato anterior sigue en `5000` |
| Certificado | `CN=EQ06, OU=Equipo 06, O=Centro de Ciberseguridad, C=MX`, RSA-2048, 365 días |
| Huella | SHA-256 del DER en hexadecimal MAYÚSCULAS |
| Hash de contenido | SHA-256 en hexadecimal minúsculas |
| Anuncio | `CC-BEACON` por UDP `5099` cada 30 s (difusión general y de la subred); al apagar manda `offline` |
| Descubrimiento | Anuncios + escaneo HTTP de la `/24` en puertos `5001–5020` (500 ms, 64 en paralelo) + alta manual |
| Confianza | Huella fijada en el primer uso tras compararla con el otro equipo (TOFU). Si cambia: alerta y `403 E-CERT-UNTRUSTED` |

Los nodos pasan a *fuera de línea* a los 90 s sin anuncio. El directorio se guarda en `datos/directorio-nodos.json`.

## 2. Paquete (`.zip`)

- `package`: `manifest.json`, `datos.enc`, `certificado.pem` (exactamente esos tres, en la raíz).
- `result`: `manifest.json`, `resultado.enc`, `certificado.pem`, con `resultEnvelope` (sobre CC-ENV-1 para quien pidió).
- Nombre: `EQ06_ALGORITMO_yyyyMMdd_HHmmss_SHA8.zip` (prefijo `RES_` en resultados).
- Firma RSA-PSS-SHA256 (sal 32) sobre la cadena de la sección 8.4:

```
version|packetType|packetId|sourceNode|producerNode|algorithmCode|operation|timestampUtc|encryptedSha256|publicParametersSha256|certificateThumbprintSha256
```

- `publicParametersSha256`: SHA-256 de las líneas `clave=valor` ordenadas (orden ordinal) unidas con `\n`.
- Reenvío (9.6): nuevo `packetId`, `sourceNode` y fecha, misma carga y `producerNode` original, firma del que reenvía.

## 3. Validación al recibir (13.1)

Orden: tamaño (50 MB) → estructura del zip → bomba zip → JSON → campos y formatos → `version` → `algorithmId`/`algorithmCode`
→ SHA-256 → partes → `publicParametersSha256` → certificado (RSA-2048, CN, vigencia) → huella → firma → ventana de ±10 min
→ huella fijada → repetidos (`packetId` y `requestId`, `409`).

Un zip cuyo manifiesto no tiene `version` 2 o mayor se manda a la lógica v1 (compatibilidad NODO04).

## 4. Servicio de algoritmos (13.2)

`POST /api/crypto/forward` y `/api/crypto/inverse` (`multipart/form-data`): `request` (JSON), `requestSignature`,
`requesterCertificate`, `payload`/`cover` o `package`. Los secretos viajan en un sobre **CC-ENV-1**
(AES-256-GCM + RSA-OAEP-SHA256, AAD = `requestId`). El nodo responde un `RES_*.zip` firmado cuyo `resultEnvelope`
va cifrado para el que pidió (AAD = `packetId` del resultado). Máximo 10 operaciones a la vez y 30 s por operación.

### Algoritmos del EQ06

| Id | Código | Parámetros públicos | Secretos |
| :--- | :--- | :--- | :--- |
| 11 | `LSBSTEGO` | `bitsPerChannel`, `channels`, `header=RCNS-BE32`, `imageFormat`, `passwordProtected`, `payloadLengthBytes` | `password` (opcional; AES-256-GCM con SHA-256 de la contraseña) |
| 12 | `EUCLIDESAFFINE` | `modulus` (`256` cada byte, `26` solo letras) | `a` (coprimo con el módulo), `b` |

Los demás algoritmos se piden al nodo dueño de la tabla 4.1 (deben estar en el directorio y confirmados).

## 5. Pruebas de conformidad (16.2) realizadas

| Caso | Resultado |
| :--- | :--- |
| Zip con 4 archivos | `400 E-ZIP-STRUCTURE` |
| `datos.enc` alterado | `422 E-HASH` |
| Firma alterada / manifiesto alterado sin volver a firmar | `422 E-SIGNATURE` |
| `publicParameters` alterados | `422 E-PARAMS-HASH` |
| `version` 9.0 | `400 E-VERSION` |
| Paquete bien firmado de hace más de 10 min | `422 E-TIMESTAMP` |
| Mismo `packetId` dos veces | `409 E-DUPLICATE` |
| Huella distinta a la fijada | `403 E-CERT-UNTRUSTED` y alerta en el panel |
| Afín delegado ida y vuelta, `a=8` | correcto / `E-PARAMS` |
| LSB con contraseña ida y vuelta | correcto |
| NODO04 (formato anterior) → EQ06 y EQ06 → NODO04 | `202`, firma válida y descifrado correcto en ambos sentidos |
