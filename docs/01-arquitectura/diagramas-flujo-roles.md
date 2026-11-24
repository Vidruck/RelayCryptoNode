# Diagramas de Flujo por Rol Operativo

Este documento describe los flujos principales de los tres roles intercambiables de `RelayCryptoNode` (`Initial`, `Intermediate`, `Final`) y la máquina de estados de `IncomingRequest`.

---

## 1. Rol `Initial` (Emisor Inicial)

```mermaid
sequenceDiagram
    actor Operador
    participant UI as "Panel Web / API"
    participant App as "IEmitInitialPackageUseCase"
    participant Hash as "IHashingServicePort"
    participant Cipher as "ISymmetricCipherStrategy"
    participant Wrap as "IAsymmetricKeyWrapperPort"
    participant Cert as "ICertificateServicePort"
    participant Zip as "IPackageSerializerPort"
    participant Net as "INodeTransportSenderPort"

    Operador->>UI: "Selecciona archivos, algoritmo y nodo destino"
    UI->>App: "EmitInitialPackageCommand"
    App->>Hash: "Calcula SHA-256 por ítem y global (testigo original)"
    App->>Zip: "Serializa PayloadBundle a bytes en claro"
    App->>Cipher: "Cifra en RAM con clave de sesión (ej. Aes256Gcm)"
    App->>Wrap: "Envuelve clave de sesión para certificado destino"
    App->>Hash: "Calcula EncryptedSha256 sobre CiphertextBytes"
    App->>Cert: "Firma manifest canónico con certificado local"
    App->>Zip: "Empaqueta datos.enc + certificado.pem + manifest.json"
    App->>Net: "POST /api/requests/receive hacia siguiente nodo"
    Net-->>UI: "Resultado HTTP 202 y PacketId emitido"
```

---

## 2. Rol `Intermediate` (Relevo Polimórfico en RAM)

```mermaid
flowchart TD
    A["Recepción HTTP POST /api/requests/receive"] --> B["Desempaquetar ZIP: datos.enc, certificado.pem, manifest.json"]
    B --> C["Validar certificado X.509, firma de manifiesto y EncryptedSha256"]
    C --> D["Registrar IncomingRequest en estado Pending"]
    D --> E{"Decisión en Bandeja"}
    E -- "Reject(reason)" --> F["Estado Rejected (sin descifrar)"]
    E -- "Accept()" --> G["Autodetectar CipherAlgorithmType entrante"]
    G --> H["Desenvolver clave de sesión con clave privada local"]
    H --> I["Descifrar en memoria RAM (cero escritura en claro a disco)"]
    I --> J["Re-encriptar en RAM con algoritmo de salida configurado"]
    J --> K["Firmar nuevo manifiesto con certificado local"]
    K --> L["Emitir nuevo ZIP al siguiente nodo"]
    L --> M["Transición a Relayed o Failed"]
```

---

## 3. Rol `Final` (Receptor y Auditor Bit a Bit)

```mermaid
flowchart TD
    A["IncomingRequest validado y aceptado"] --> B["Autodetectar algoritmo entrante y desenvolver clave"]
    B --> C["Descifrar PayloadBundle en memoria"]
    C --> D["Recalcular SHA-256 global y por cada PayloadItem"]
    D --> E["IntegrityAuditReport.CreateComparison(...)"]
    E --> F{"IsBitExactMatch == true y ByteLossCount == 0?"}
    F -- "Sí" --> G["Auditoría Limpia: 0 pérdidas bit a bit"]
    F -- "No" --> H["Alerta de Corrupción / Pérdida (ByteLossCount o hash distinto)"]
    G --> I["Persistir evidencia recuperada + reporte JSON"]
    H --> I
    I --> J["Transición IncomingRequest -> Audited y notificar panel"]
```

---

## 4. Máquina de Estados de `IncomingRequest`

```mermaid
stateDiagram-v2
    [*] --> Pending: "RegisterIncomingAsync()"
    Pending --> Accepted: "Accept() [SignatureValid && IntegrityValid]"
    Pending --> Rejected: "Reject(reason)"
    Pending --> Failed: "MarkFailed(reason)"
    Accepted --> Relayed: "MarkRelayed() [Rol Intermediate]"
    Accepted --> Audited: "MarkAudited() [Rol Final]"
    Accepted --> Failed: "MarkFailed(reason)"
    Rejected --> [*]
    Relayed --> [*]
    Audited --> [*]
    Failed --> [*]
```
