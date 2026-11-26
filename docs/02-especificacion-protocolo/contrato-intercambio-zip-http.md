# Contrato de Intercambio ZIP y HTTP REST entre Equipos

Este documento especifica el formato estándar de interoperabilidad en red local (LAN) entre los 6 nodos heterogéneos de **RelayCryptoNode** (Windows 11 y Arch Linux).

---

## 1. Nomenclatura Obligatoria del Archivo `.zip`

Todo paquete emitido o reenviado debe utilizar exactamente la siguiente convención de nombre:

```text
<NODO_ORIGEN>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8>.zip
```

Donde:
- `<NODO_ORIGEN>`: `NodeId` en mayúsculas y sin espacios (ejemplo: `NODO01`).
- `<ALGORITMO>`: Código oficial canónico en mayúsculas del algoritmo aplicado según el catálogo oficial de 21 módulos (`AESGCM`, `DES`, `TRIPLEDES`, `CHACHA20`, `RSA`, `ECC`, `DIFFIEHELLMAN`, `CAESAR`, `VIGENERE`, `XORASM`, `LSBSTEGO`, `EUCLIDESAFFINE`, `MILLERRABIN`, `FISHERYATES`, `HASHSHA`, `HMACSHA256`, `DIGITALSIG`, `QUANTUMPQC`, `DFTSPECTRAL`, `LAGRANGESHAMIR`, `LORENZSZ40`).
- `<YYYYMMDD_HHMMSS>`: Marca temporal UTC de emisión en formato compacto (ejemplo: `20261124_203512`).
- `<SHA8>`: Primeros 8 caracteres hexadecimales en minúsculas del hash `EncryptedSha256` (ejemplo: `a3f91c04`).

Ejemplo completo:

```text
NODO01_AES256GCM_20261124_203512_a3f91c04.zip
```

---

## 2. Estructura Interna del Archivo `.zip` (3 Entradas en Raíz)

El archivo `.zip` debe contener **exactamente 3 archivos** en la raíz (sin subcarpetas obligatorias):

| Archivo en ZIP | Obligatorio | Contenido |
| :--- | :--- | :--- |
| `datos.enc` | Sí | Bytes crudos (`CiphertextBytes`) resultantes del cifrado simétrico del `PayloadBundle`. |
| `certificado.pem` | Sí | Certificado X.509 público del nodo emisor en formato PEM estándar (`-----BEGIN CERTIFICATE-----`). |
| `manifest.json` | Sí | Metadatos criptográficos, testigo original, parámetros de descifrado y firma digital codificada en Base64. |

---

## 3. Especificación de `manifest.json` y Estrategia Defensiva

### 3.1 Estrategia Defensiva (`algorithmCode` + `algorithm`)

Para garantizar compatibilidad total entre versiones o implementaciones paralelas de los 6 equipos:
- **Al emitir:** Todo nodo **DEBE escribir ambos campos** con el identificador equivalente:
  - `algorithmCode`: código oficial canónico en mayúsculas del catálogo (ejemplo: `"AESGCM"`, `"CHACHA20"`, `"LORENZSZ40"`).
  - `algorithm`: nombre descriptivo o alias estándar equivalente (ejemplo: `"AES-256-GCM"`, `"ChaCha20-Poly1305"`, `"Cifrado Lorenz SZ40/42"`).
- **Al leer:** El deserializador **DEBE aceptar cualquiera de los dos campos** mediante `OfficialAlgorithmCatalog.ParseOrThrow(...)` (priorizando `algorithmCode` si ambos están presentes y normalizando mayúsculas/guiones antes de mapear al módulo oficial).

### 3.2 Ejemplo Completo de `manifest.json`

```json
{
  "protocolVersion": "1.0",
  "packetId": "8f3c2d9a-41b0-4f7c-9c83-2d6a1f9100e1",
  "sourceNode": {
    "nodeId": "NODO01",
    "endpointAddress": "http://192.168.1.10:5000",
    "certificateThumbprintSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "timestampUtc": "2026-11-24T20:35:12Z",
  "algorithmCode": "AESGCM",
  "algorithm": "AES-256-GCM",
  "keyExchangeAlgorithm": "RsaOaepSha256",
  "signatureAlgorithm": "RsaPssSha256",
  "cryptoParameters": {
    "ivOrNonceBase64": "AQIDBAUGBwgJCgsM",
    "authTagBase64": "ChQeKDFASk5UX2hocHhqew==",
    "encryptedSessionKeyBase64": "b2ZmaWNpYWxLZXlXcmFw...",
    "saltBase64": null,
    "extraMetadata": {}
  },
  "encryptedSha256": "a3f91c04b9d8e2c7f1a09483b2c1d0e9f8a7b6c5d4e3f2a10987654321abcdef",
  "originalPayload": {
    "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "fileName": "reporte_evidencia.pdf",
    "extension": ".pdf",
    "sizeBytes": 248320
  },
  "manifestSignatureBase64": "MEUCIQDx9..."
}
```

*Nota:* La firma `manifestSignatureBase64` se calcula sobre la representación canónica del manifiesto excluyendo el propio campo `manifestSignatureBase64`, evitando ambigüedades al verificar en el receptor.

---

## 4. Endpoints HTTP REST y Códigos de Respuesta

### 4.1 `GET /api/status`

Consulta de disponibilidad y capacidades del nodo (activo desde Fase 1).

- **Respuesta `200 OK`:**

```json
{
  "nodeId": "NODO01",
  "protocolVersion": "1.0",
  "status": "online",
  "acceptingPackages": true
}
```

### 4.2 `POST /api/requests/receive`

Recepción de un paquete `.zip` enviado por el nodo predecesor.

- **Content-Type esperado:** `multipart/form-data` (campo `package` con el archivo `.zip`) o `application/zip` según adaptador acordado en Fase 2/3 (el servidor soportará `multipart/form-data` como primario).
- **Códigos HTTP obligatorios:**

| Código HTTP | Significado Operativo | Condición de Disparo |
| :--- | :--- | :--- |
| **`202 Accepted`** | Paquete recibido, desempaquetado y encolado en bandeja (`Pending`). | ZIP válido con 3 entradas, esquema correcto, firma/integridad verificables (el operador o regla automática puede inspeccionarlo). |
| **`400 Bad Request`** | Solicitud HTTP o ZIP malformado. | Falta el archivo `.zip`, no contiene las 3 entradas (`datos.enc`, `certificado.pem`, `manifest.json`), JSON inválido o campos obligatorios ausentes. |
| **`413 Payload Too Large`** | Tamaño de carga excedido. | El archivo `.zip` supera el límite máximo configurado en Kestrel/aplicación. |
| **`422 Unprocessable Entity`** | Error criptográfico o de política semántica. | Algoritmo no registrado en el catálogo oficial (`UnsupportedAlgorithmException`), certificado X.509 corrupto/inválido o discrepancia estructural en `EncryptedSha256`. |

---

## 5. Formato que emite el nodo (compatible con el NODO04)

Al probar contra el nodo del equipo 4 (`CentroCiberseguridad.Web`, que publicó la propuesta del grupo) se confirmó que su
`manifest.json` es **plano** y que su firma no cubre el manifiesto completo. Para que los paquetes se acepten en ambos
sentidos, RelayCryptoNode **emite** ese formato y **lee** los dos (el plano y el anidado de la sección 3).

### 5.1 `manifest.json` emitido

```json
{
  "version": "1.0",
  "protocolVersion": "1.0",
  "packetId": "4711cbcc-81ae-4d3b-99ee-9992293fa147",
  "sourceNode": "NODO06",
  "sourceIp": "192.168.1.6",
  "timestampUtc": "2026-11-26T00:57:19.0000000Z",
  "algorithm": "AES-256-GCM",
  "algorithmCode": "AESGCM",
  "payloadMode": "file",
  "originalFileName": "para4.txt",
  "originalExtension": ".txt",
  "originalSizeBytes": 51,
  "encryptedSha256": "2f46c5e5d30e97ae0ef47b4b95200302cf44eeb1aae94c1fee3824be3d8219ef",
  "publicParameters": {
    "rcn.protocol": "RelayCryptoNode/1.0",
    "rcn.endpointAddress": "http://192.168.1.6:5000",
    "rcn.keyExchangeAlgorithm": "RsaOaepSha256",
    "rcn.originalSha256": "fc6888f3…",
    "rcn.ivOrNonceBase64": "…",
    "rcn.authTagBase64": "…",
    "rcn.encryptedSessionKeyBase64": "…",
    "hopCount": "1",
    "payloadFormat": "RAW"
  },
  "certificateThumbprintSha256": "9E0FE9EC2C24FD91A0649655043D0451F91EB79AEE6588059E644788B4AA40D9",
  "keyExchangeAlgorithm": "RsaOaepSha256",
  "signatureAlgorithm": "RSA-PSS-SHA256",
  "manifestSignatureBase64": "…"
}
```

- `sourceNode` es texto (el NODO04 lo deserializa como `string`; un objeto haría que responda `400`).
- Los campos con prefijo `rcn.` y los metadatos (`hopCount`, `originNode`, `payloadFormat`…) son propios de este nodo; los demás los ignoran.
- `certificateThumbprintSha256` va en hexadecimal **mayúsculas**, igual que el NODO04.

### 5.2 Firma

`manifestSignatureBase64` = RSA-PSS-SHA256 (clave privada del nodo) sobre el texto UTF-8:

```text
<encryptedSha256>|<SHA-256 del certificado.pem en hex MAYÚSCULAS>|<timestampUtc tal cual aparece en el manifiesto>
```

Para manifiestos anidados (sección 3) se verifica sobre el JSON compacto sin el campo `manifestSignatureBase64`.

### 5.3 Clave de sesión

| Modo | `encryptedSessionKeyBase64` | Uso |
| :--- | :--- | :--- |
| RSA-OAEP-SHA256 | Clave AES/… aleatoria de 32 bytes cifrada con el certificado del destino (`GET /api/certificate`). | Entre nodos RelayCryptoNode. Funciona con los 15 algoritmos que cifran `datos.enc`. |
| PSK del grupo | Clave de sesión cifrada con AES-256-GCM; KEK = PBKDF2-SHA256(PSK, `rcn.saltBase64`, 100 000). | Cuando el destino no publica certificado. |
| Clave compartida (NODO04) | *(no va)* | `datos.enc` = nonce (12) ‖ etiqueta (16) ‖ cifrado, con clave = SHA-256(UTF-8(`clave-aes-256-segura`)). Solo AES-GCM. |

Un paquete sin `encryptedSessionKeyBase64` se interpreta como clave compartida.

### 5.4 Códigos HTTP (alineados con el NODO04)

| Código | Caso |
| :--- | :--- |
| `202` | Paquete válido registrado en la bandeja. |
| `400` | No es ZIP, faltan entradas, JSON roto o faltan `encryptedSha256` / `manifestSignatureBase64` / `packetId`. |
| `413` | El `.zip` supera `Node:MaxPackageMegabytes` (50 MB por defecto, igual que el NODO04). |
| `422` | Algoritmo fuera del catálogo, certificado inválido o vencido, `encryptedSha256` distinto o **firma inválida**. |

### 5.5 Pruebas de interoperabilidad realizadas

Se ejecutó el NODO04 publicado junto a tres instancias de RelayCryptoNode:

- NODO04 → NODO06: `202`, firma válida; NODO06 descifró el AES-GCM con la clave compartida y recuperó el texto original.
- NODO06 → NODO04 (clave compartida): `202`, `signatureValid: true`; el NODO04 aceptó el paquete y lo descifró con su propio motor.
- NODO01 → NODO02 → NODO06 con los 15 algoritmos (RSA-OAEP y PSK): auditoría bit a bit limpia en los 30 casos.
