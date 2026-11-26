# Manual de Entorno de Desarrollo Multiplataforma (Windows 11 y Arch Linux)

Guía práctica para preparar cualquier equipo del proyecto **RelayCryptoNode** garantizando paridad completa usando exclusivamente el SDK oficial de **.NET 8 LTS** y habilitando comunicación LAN en los puertos TCP `5000 + equipo` (v2.0), TCP `5000` (v1) y UDP `5099` (anuncios).

---

## 1. Requisitos Comunes

- **.NET 8 SDK LTS** (versión `8.0.x`; fijada mediante `global.json` con `rollForward: latestMinor`).
- **Git** (opcional para control de versiones del equipo).
- **Red local (LAN / Access Point):** Todos los nodos deben residir en la misma subred IPv4 (por ejemplo `192.168.1.0/24` o `10.0.0.0/24`) y alcanzar el puerto TCP `5000`.
- **Sin dependencias nativas externas obligatorias:** No se requiere instalar OpenSSL CLI ni bibliotecas C/C++ externas.

---

## 2. Instalación en Windows 11

### 2.1 Instalar .NET 8 SDK LTS

Desde PowerShell o Windows Terminal:

```powershell
winget install Microsoft.DotNet.SDK.8
```

Verificar instalación (abrir una nueva terminal si es necesario):

```powershell
dotnet --info
```

### 2.2 Permitir Puerto TCP 5000 en Firewall de Windows Defender

Ejecutar PowerShell **como Administrador**:

```powershell
# Estándar v2.0 (equipo 6 = 5006) y anuncio UDP; repetir el bloque de abajo para el 5000 (formato v1).
New-NetFirewallRule -DisplayName "RelayCryptoNode v2 TCP 5006" -Direction Inbound -Protocol TCP -LocalPort 5006 -Action Allow -Profile Private
New-NetFirewallRule -DisplayName "RelayCryptoNode beacon UDP 5099" -Direction Inbound -Protocol UDP -LocalPort 5099 -Action Allow -Profile Private
New-NetFirewallRule `
  -DisplayName "RelayCryptoNode HTTP 5000 (LAN)" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 5000 `
  -Action Allow `
  -Profile Private,Domain
```

*Nota:* Si la red del Access Point se detectó como perfil **Público** en Windows 11, cámbiela a **Red privada** en Configuración -> Red e Internet o incluya `Public` temporalmente solo durante pruebas en laboratorio aislado.

---

## 3. Instalación en Arch Linux

### 3.1 Instalar .NET 8 SDK LTS

Desde terminal con `pacman`:

```bash
sudo pacman -Syu dotnet-sdk-8.0 aspnet-runtime-8.0
```

Verificar versión activa:

```bash
dotnet --info
```

### 3.2 Abrir Puerto TCP 5000 en Firewall (según herramienta activa)

Verifique qué firewall está habilitado en el equipo y aplique **solo el que corresponda**:

- **Con `ufw`:**

```bash
sudo ufw allow 5000/tcp
sudo ufw allow 5006/tcp
sudo ufw allow 5099/udp
sudo ufw reload
sudo ufw status
```

- **Con `firewalld`:**

```bash
sudo firewall-cmd --add-port=5000/tcp --permanent
sudo firewall-cmd --add-port=5006/tcp --permanent
sudo firewall-cmd --add-port=5099/udp --permanent
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports
```

- **Con `nftables` (si se usa conjunto por defecto `inet filter`):**

```bash
sudo nft add rule inet filter input tcp dport { 5000, 5006 } accept
sudo nft add rule inet filter input udp dport 5099 accept
```

---

## 4. Compilación, Pruebas y Ejecución del Nodo

Los comandos son idénticos en **PowerShell (Windows 11)** y **Bash/Zsh (Arch Linux)**:

```bash
cd RelayCryptoNode
dotnet restore RelayCryptoNode.sln
dotnet build RelayCryptoNode.sln --no-restore -warnaserror
dotnet test RelayCryptoNode.sln --no-build --verbosity normal
```

Para iniciar el servidor web embebido escuchando en todas las interfaces (`http://0.0.0.0:5000`):

```bash
dotnet run --project src/RelayCryptoNode.WebHost/RelayCryptoNode.WebHost.csproj --launch-profile http
```

Desde otro equipo en la LAN, valide conectividad sustituyendo `<IP_NODO>`:

```bash
curl http://<IP_NODO>:5006/api/status   # v2.0
curl http://<IP_NODO>:5000/api/status   # v1 (puerto de compatibilidad)
```
