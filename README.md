# CellInspector 🕵️‍♂️📱

**Auditor de seguridad para dispositivos Android vía ADB** — analiza, detecta y remedia amenazas con CLI colorida, termómetro de severidad y guías localizadas.

---

## ✨ Características

| Modo | Flag | Descripción |
|------|------|-------------|
| 🔍 **Escaneo completo** | *(ninguno)* | 7 módulos de seguridad: red, procesos, paquetes, logcat, notificaciones, dispositivo, VPN/Proxy |
| 🛠️ **Auto-fix** | `-f` / `--fixall` | Corrige automáticamente lo detectable y re-verifica con delta report |
| 🎯 **Modo Kill** | `-k` / `--kill` | Lista y mata procesos sospechosos interactivamente |
| 🔔 **Notificaciones** | `-n` / `--notifications` | Gestión interactiva de listeners, canales y purga de notificaciones |
| 📡 **Monitor** | `-m` / `--monitor` | Escaneo en tiempo real cada N segundos |
| 🕵️ **Pegasus detect** | `--pegasus-detect` | Detecta indicadores del spyware Pegasus en el dispositivo |
| 🚨 **Zero-Day scan** | `--0days` | Busca PoCs/exploits activos en GitHub para tu dispositivo |
| 🌐 **Deep scan** | `--0days --deep` | Búsqueda extendida en Reddit, Pastebin y foros especializados |
| 🚀 **Full analysis** | `--all` | Escaneo completo + Zero-Day + Pegasus + VPN/Proxy (con o sin internet) |
| 📡 **Live logcat** | `--live` | Streaming de logcat en tiempo real con alertas coloreadas |
| 📄 **Reporte Markdown** | `-r` / `--report` | Genera reporte Markdown en `reports/` |
| 📄 **Reporte JSON+MITRE** | `--json` | Exporta resultados JSON con mapeo MITRE ATT&CK for Mobile |
| 🔌 **Modo offline** | `--offline` | Salta checks que requieren internet (C2, GitHub, DuckDuckGo) |
| 🔄 **IOC Auto-update** | `--update-ioc` | Descarga feeds de MalwareBazaar + CISA + AlienVault OTX |
| 🕵️ **MVT Check** | `--mvt-check` | Detecta Pegasus, Predator y +15 familias con IOCs de MVT (Amnesty) |
| 🛡️ **VirusTotal** | `VT_API_KEY` | Consulta detección VT para hashes de APKs (env var) |
| 📖 **Guías localizadas** | *(automático)* | Detecta el idioma del dispositivo y muestra guías paso a paso en ese idioma |

---

## 📋 Requisitos

- 🐍 Python 3.8+
- 🔌 ADB instalado y en `PATH`
- 📱 Dispositivo Android con depuración USB activada
- 🎨 `rich` (CLI colorida)

```bash
pip install rich
```

---

## 🚀 Instalación

```bash
# Opción 1: pip install (recomendado)
pip install git+https://github.com/Sud4ka/CellInspector.git

# Opción 2: clonar y ejecutar
git clone <repo> cellinspector
cd cellinspector
chmod +x cellinspector.py
```

---

## 💻 Uso

### 🔍 Escaneo completo de seguridad

```bash
python3 cellinspector.py
```

Ejecuta los 6 módulos de análisis y muestra:

- 📊 **Termómetro de severidad** — visual del nivel de amenaza máximo
- 🗂️ **Tabla resumen** — todos los hallazgos agrupados por severidad
- 📖 **Guías paso a paso** — en el idioma del dispositivo para problemas manuales

```
python3 cellinspector.py --wireless     # Escaneo vía WiFi
python3 cellinspector.py --verbose      # Modo detallado
python3 cellinspector.py --version      # Ver versión
```

### 🚀 Full Analysis (`--all`)

```bash
python3 cellinspector.py --all           # Escaneo completo + Zero-Day + Pegasus + VPN/Proxy
python3 cellinspector.py --all --json    # Lo mismo + export JSON
python3 cellinspector.py --all --offline # Sin checks de internet
```

Ejecuta **todo** secuencialmente: escaneo de 7 módulos → Zero-Day exploit search → Pegasus detection → VPN/Proxy analysis. Ideal para auditorías completas en un solo comando.

### 📡 Live Logcat Monitor (`--live`)

```bash
python3 cellinspector.py --live
```

Streaming en tiempo real de `adb logcat` con resaltado por colores:
- 🔴 **Rojo negrita** — `FATAL EXCEPTION`, `CRASH`
- 🟠 **Naranja** — `ANR`
- 🟡 **Amarillo** — errores generales
- 🚨 **Rojo con alerta** — patrones de `frida`, `ptrace` (indicadores de debugging/exploits)

### 📄 JSON Export + MITRE ATT&CK (`--json`)

```bash
python3 cellinspector.py --all --json
```

Genera `reports/cellinspector_report_<timestamp>.json` con:
- Hallazgos con severidad, categoría, detalles y recomendaciones
- **Mapeo MITRE ATT&CK for Mobile** — cada hallazgo incluye técnica(s) MITRE (T1437, T1412, T1503, etc.)
- Estructura lista para importar a SIEM (Splunk, ELK, etc.)

Ejemplo de hallazgo en JSON:
```json
{
  "severity": "critical",
  "title": "Stalkerware Detected",
  "category": "Stalkerware",
  "mitre_attack": [
    {"id": "T1413", "name": "Capture Location"},
    {"id": "T1412", "name": "Capture Data"},
    {"id": "T1424", "name": "Capture Audio"}
  ]
}
```

### 🕵️ MVT-Powered Detection (`--mvt-check`)

```bash
cellinspector.py --mvt-check
```

Utiliza los indicadores STIX2 del proyecto **MVT (Mobile Verification Toolkit)** de Amnesty International para detectar **+15 familias de spyware**:

| Malware | Fuente |
|---------|--------|
| 🦠 **Pegasus** (NSO Group) | AmnestyTech investigations |
| 👁️ **Predator** (Intellexa) | Citizen Lab, Meta, Amnesty |
| 🔬 **RCS Lab** | Google, Lookout |
| 👑 **KingSpawn** (Quadream) | Citizen Lab, Microsoft |
| 🔺 **Operation Triangulation** | Kaspersky |
| 🐉 **WyrmSpy / DragonEgg** | Lookout |
| 👻 **Candiru (DevilsTongue)** | Microsoft, Recorded Future |
| 🦇 **ResidentBat** | RSF, RESIDENT.NGO |
| 📱 **Cellebrite** | Citizen Lab |
| ⚔️ **DarkSword** | Google TAG, iVerify, Lookout |
| 🌊 **Coruna (CryptoWaters)** | Google TAG, iVerify |
| 👁️ **Stalkerware** (ECHAP) | AssoEchap |
| 📡 **Wintego Helios** | Amnesty International |
| 🇷🇸 **NoviSpy (Serbia)** | Amnesty International |

**Cómo funciona:**
1. Descarga archivos `.stix2` desde los repositorios oficiales de MVT y AmnestyTech
2. Parsea los patrones STIX2 (dominios, IPs, hashes SHA256, package names, rutas de archivo)
3. Cruza contra el dispositivo vía ADB (procesos, paquetes, archivos, hashes de system binaries)
4. Muestra qué familia de malware coincide y cuántos indicadores se detectaron

**Crédito:** Los indicadores STIX2 son mantenidos por el proyecto [MVT](https://github.com/mvt-project/mvt) de [Amnesty International](https://www.amnesty.org). Distribuidos bajo licencia MIT.

### 🔄 IOC Auto-Update (`--update-ioc`)

```bash
cellinspector.py --update-ioc
```

Descarga automáticamente inteligencia de amenazas a `data/iocs.json`:

| Fuente | API Key | Contenido |
|--------|---------|-----------|
| 🦠 **MalwareBazaar** (AbuseCH) | `MB_API_KEY` | Hashes SHA256 de malware Android, package names |
| 👾 **AlienVault OTX** | `OTX_API_KEY` | Hashes, dominios, IPs maliciosas de pulses Android |
| 🏛️ **CISA KEV** | *(ninguna)* | CVEs de Android explotados activamente |

```bash
# Con todas las fuentes:
MB_API_KEY=tu_key OTX_API_KEY=tu_key cellinspector.py --update-ioc
```

Los IOCs descargados se usan automáticamente en el escaneo de paquetes y APKs.

### 🛡️ VirusTotal Integration

CellInspector puede consultar VirusTotal para cada APK instalado:

```bash
VT_API_KEY=tu_key cellinspector.py --all
```

- Envía SHA256 de cada APK a la API v3 de VirusTotal
- Muestra detecciones (ej. `☢ 5/62 VT`) junto al paquete
- **Rate limiting:** respeta el límite gratuito (~4 req/min)
- Obtén API key gratis en https://www.virustotal.com/gui/join

**Nota:** Solo se consultan los primeros 30 paquetes para mantener el rate limit dentro de lo razonable.

### 🔌 Modo Offline (`--offline`)

```bash
python3 cellinspector.py --all --offline
```

Salta todos los checks que requieren conexión a internet: C2 connectivity, GitHub API, DuckDuckGo. Útil para auditorías en dispositivos sin conectividad o en entornos aislados.

### 🛠️ Auto-fix (`-f` / `--fixall`)

```bash
python3 cellinspector.py --fixall
```

1. 📥 **Escaneo inicial** completo
2. 🔧 **Correcciones automáticas**:
   - 🚫 Remueve acceso de notification listeners sospechosos
   - 🔕 Cancela notificaciones de apps con alta carga (10+)
   - 🧹 Descarta todas las notificaciones activas
   - 🚷 Bloquea canales de notificaciones persistentes
   - 💀 Mata procesos sospechosos / root
3. 🔄 **Re-escaneo** para verificar cambios
4. 📊 **Delta Report** — tabla comparativa antes/después

```
python3 cellinspector.py --fixall --wireless
```

### 🎯 Modo Kill (`-k` / `--kill`)

```bash
python3 cellinspector.py --kill
```

- Lista procesos sospechosos + root
- Permite seleccionar y matar interactivamente
- Monitorea resurrección por 15s
- Si resucita: ofrece watcher permanente o deshabilitar paquete

### 🔔 Modo Notificaciones (`-n` / `--notifications`)

```bash
python3 cellinspector.py --notifications
```

Menú interactivo con 4 opciones:

| # | Opción | Descripción |
|---|--------|-------------|
| 1️⃣ | 🔍 **Escaneo de listeners** | Muestra apps con acceso, marca sospechosas, permite remover su acceso, force-stop o deshabilitar |
| 2️⃣ | 💬 **Gestión de notificaciones** | Purga/cancelación de activas, dismiss all, cancelar por app, bloquear canales |
| 3️⃣ | 🚫 **Notificaciones persistentes** | Apps con notifs no descartables — bloquea canales o force-stop |
| 4️⃣ | 📋 **Reporte completo** | Análisis detallado de todas las notificaciones |

### 📡 Modo Monitor (`-m` / `--monitor`)

```bash
python3 cellinspector.py --monitor
python3 cellinspector.py --monitor --interval 30   # cada 30 segundos
```

### 🕵️ Pegasus Spyware Detection (`--pegasus-detect`)

```bash
python3 cellinspector.py --pegasus-detect
```

Analiza el dispositivo en busca de **6 tipos de indicadores** del spyware Pegasus de NSO Group:

| Capa | Check | Método |
|------|-------|--------|
| 1️⃣ | **Procesos** | Busca procesos con nombres conocidos de Pegasus (`pegasus`, `pexd`, etc.) |
| 2️⃣ | **Paquetes** | Lista paquetes instalados contra IOC database (`com.nso.pegasus`, `com.android.systemupdate`, etc.) |
| 3️⃣ | **Archivos** | Verifica existencia de rutas conocidas (`/data/local/tmp/pex`, `/system/bin/pegasus`, etc.) |
| 4️⃣ | **Módulos kernel** | Inspecciona módulos cargados (`lsmod`) en busca de `pegasus.ko`, `hide_proc.ko` |
| 5️⃣ | **Hash matching** | Calcula SHA256 de system binaries y compara con hashes de muestras reales de Pegasus |
| 6️⃣ | **C2 servers** | Verifica resolución DNS y conectividad con servidores de comando y control conocidos |

#### IOC Database

Los indicadores provienen de fuentes reales:

| Fuente | Contenido |
|--------|-----------|
| 🗃️ `9aylas/Pegasus-samples` | Hashes SHA256 de muestras reales de Pegasus |
| 🚫 `0n1cOn3/The-NSO-Blacklist` | IPs y dominios de servidores C2 de NSO Group |
| 📚 Investigación pública | Paquetes, procesos, rutas de archivos y módulos kernel asociados a Pegasus |

Salida:
```
🕵️ Pegasus Spyware Detector
Checking device for indicators of compromise...

  ✔ Running processes...
  ✔ Installed packages...
  ✔ Known file paths...
  ✔ Kernel modules...
  ✔ File hash matching...
  ✔ C2 connectivity...

✅ No Pegasus indicators detected.
```

**Nota:** Pegasus opera principalmente a nivel kernel y utiliza técnicas de ocultamiento avanzadas. Este escaneo no puede garantizar la ausencia de infección. Un resultado negativo no significa necesariamente que el dispositivo esté libre de Pegasus.

### 🚨 Zero-Day Exploit Scanner (`--0days`)

```bash
python3 cellinspector.py --0days           # Solo GitHub
python3 cellinspector.py --0days --deep    # GitHub + Reddit + Pastebin + foros
```

Busca PoCs/exploits activos para tu dispositivo:

| Modo | Fuentes |
|------|---------|
| 🐙 **Normal** (`--0days`) | GitHub (API de repositorios) |
| 🌐 **Deep** (`--0days --deep`) | GitHub + Reddit + Pastebin + DuckDuckGo (breach forums, exploit.in, etc.) |

#### Normal (`--0days`)

| Paso | Acción |
|------|--------|
| 1️⃣ | Detecta modelo, versión de Android, API level, parche de seguridad |
| 2️⃣ | Genera **~80 dorks multilingües** (EN, PT, ES, FR, IT, RU, ZH, JA, KO) y selecciona 12-15 cubriendo todos los idiomas |
| 3️⃣ | Consulta GitHub API con cada dork |
| 4️⃣ | **Verifica HTTP 200** — en paralelo (10 threads) descarta repos que devuelvan 404 |
| 5️⃣ | Filtra por relevancia (CVE, exploit, RCE, root, escalada de privilegios, y keywords en 9 idiomas) |
| 6️⃣ | Muestra resultados con enlace, estrellas, lenguaje y fecha |

Idiomas de los dorks:

| Idioma | Keywords |
|--------|----------|
| 🇬🇧 Inglés | `exploit`, `poc`, `cve`, `rce`, `vulnerability`, `kernel exploit`, `0day` |
| 🇧🇷 Portugués | `vulnerabilidade` |
| 🇪🇸 Español | `vulnerabilidad` |
| 🇫🇷 Francés | `vulnérabilité` |
| 🇮🇹 Italiano | `vulnerabilità` |
| 🇷🇺 Ruso | `эксплойт+уязвимость`, `poc+взлом` |
| 🇨🇳 Chino | `漏洞+exploit`, `利用+poc` |
| 🇯🇵 Japonés | `脆弱性+exploit`, `エクスプロイト+poc` |
| 🇰🇷 Coreano | `취약점+exploit`, `익스플로잇+poc` |

Salida:
```
🔍 Scanning GitHub for active exploits...
  Device: Pixel 7 | Android: 14

🚨 5 GitHub PoC(s) encontrados!

╭─ 💥 GitHub Exploit #1 ──────────────────────────╮
│ 0x36/Pixel_GPU_Exploit                           │
│ Android 14 kernel exploit for Pixel7/8 Pro       │
│                                                   │
│ 🔗 https://github.com/0x36/Pixel_GPU_Exploit      │
│ ⭐ 551  📁 C  📅 2025-08-15                       │
╰───────────────────────────────────────────────────╯
```

#### Deep Scan (`--0days --deep`)

Además de la búsqueda en GitHub, ejecuta:

| Fuente | API/Método | Resultados |
|--------|-----------|------------|
| 🔴 Reddit | DuckDuckGo `site:reddit.com` | Posts sobre exploits/CVE para el dispositivo |
| 📋 Pastebin | DuckDuckGo `site:pastebin.com` | Pastes con código de exploit |
| 🛡️ Foros | DuckDuckGo con dorks | BreachForums, exploit.in, xss.is, hackforums |
| 🌐 Web | DuckDuckGo | Búsqueda general de exploits/PoC en internet |

**Nota:** El deep scan depende de DuckDuckGo. Si no está accesible desde tu red, el deep scan se omitirá automáticamente sin bloquear el análisis.

**GitHub Token (opcional):** Para evitar límites de tasa (60 req/h sin autenticar vs. 5000 autenticado), exporta tu token antes de ejecutar:

```bash
export GITHUB_TOKEN="ghp_tu_token_aqui"
```

Puedes generar un token en https://github.com/settings/tokens (no requiere permisos especiales para búsqueda pública).

Cada fuente se muestra en paneles con su propio color (naranja para Reddit, amarillo para Pastebin, rojo para foros, azul para web).

### 📄 Modo Reporte (`-r` / `--report`)

```bash
python3 cellinspector.py --report
python3 cellinspector.py --report --wireless
```

Genera `reports/cellinspector_report_<timestamp>.md`

---

## 🗂️ Módulos de Análisis

### 1️⃣ 🌐 Network Analysis

- 🔌 Lee conexiones TCP/UDP desde `/proc/net/tcp` y `/proc/net/udp`
- 🌍 Resuelve IPs remotas a nombres de dominio
- 🚩 Detecta conexiones a IPs sospechosas (IOC database)
- 🔒 Identifica conexiones externas por puerto/servicio

### 2️⃣ ⚙️ Process Scanner

- 📋 Lista todos los procesos vía `ps -A`
- 🚩 Detecta procesos con nombres sospechosos (IOC database)
- 👑 Identifica procesos corriendo como root
- 🧹 Clasifica kernel vs. user-space

### 3️⃣ 📦 Package Analysis

- 📋 Lista todos los paquetes instalados
- 🚩 Cruza contra IOC database de malware y patrones sospechosos
- 🔑 Detecta permisos de alto riesgo
- 📊 Identifica paquetes con nombres sospechosos
- 🦠 **Stalkerware detection** — 38 paquetes de spyware comercial (mSpy, FlexiSPY, TheTruthSpy, Cocospy, Hoverwatch, etc.)
- ⚠️ **Permission risk combos** — detecta 8 combinaciones peligrosas (Full Surveillance, Keylogger, Call Recording, Accessibility Abuse, Overlay Attack, etc.)
- 🔐 **APK integrity** — calcula SHA256 de APKs instalados y compara contra hashes de malware conocido y Pegasus

### 4️⃣ 📝 Logcat Monitor

- 📋 Obtiene logs del dispositivo (`logcat -d -t N`)
- 🚩 Busca patrones IOC: ejecución remota, exploits, instalaciones
- 💥 Detecta crashes, ANRs y errores de red

### 5️⃣ 🔔 Notification Analysis

- 👂 **Escáner de listeners** — detecta apps con `NotificationListenerService`
- 🚫 **Notificaciones no descartables** — identifica notifs con `deleteIntent=null`
- 📊 **Volumen por app** — alerta sobre sobrecarga (20+, 50+)
- 🔒 **Flags persistentes** — detecta 0x710, 0x702 (foreground service)

### 6️⃣ 🛡️ Device Security

| Check | Descripción |
|-------|-------------|
| Build type | user / userdebug / eng |
| Security patch | Nivel del parche |
| 🔍 **CVE Scanner** | 37 CVEs desde 2021 — compara parche vs base de datos local |
| Root | Busca binario `su` |
| Verified boot | Estado de verificación |
| 🔒 SELinux | Enforcing / permissive |
| 🔌 USB debugging | Estado |
| 🔐 Encryption | Cifrado de almacenamiento |
| 📲 Unknown sources | Instalación fuera de Play Store |
| ⚙️ Developer options | Estado |

### 7️⃣ 🔒 VPN/Proxy Detection

- 🌐 Detecta interfaces VPN activas (tun, tap, ppp)
- 📱 Lista apps de VPN/WireGuard/OpenVPN/Psiphon instaladas
- 🧅 Detecta Tor/Orbot/Orfox
- ⚙️ Verifica proxy HTTP global configurado
- 🚇 Detecta túneles IP

---

## 🌐 Guías Localizadas

CellInspector detecta automáticamente el **idioma del dispositivo** al conectarse y genera guías paso a paso en ese idioma para los hallazgos que requieren intervención manual.

Idiomas disponibles:

| Idioma | Código |
|--------|--------|
| 🇪🇸 Español | `es` |
| 🇺🇸 English | `en` |

Cada guía incluye pasos numerados con las rutas exactas de configuración. Ejemplo:

```
📖 Guía paso a paso — Soluciones manuales

╭──────────── Revocar acceso a notificaciones de apps sospechosas ─────────────╮
│  1. Abre Configuración (Settings)                                            │
│  2. Ve a 'Apps' > 'Acceso especial' > 'Acceso a notificaciones'              │
│  3. Identifica las apps marcadas como sospechosas                            │
│  4. Desactiva el permiso para cada una                                       │
│  5. Considera desinstalar estas aplicaciones                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
```

---

## 📡 Modo Wireless ADB

1. 📱 Dispositivo conectado por USB
2. 🏁 Ejecutar `--wireless`
3. 🌐 Obtiene IP WiFi, inicia `adb tcpip <puerto_aleatorio>`
4. 🔗 Conecta vía `adb connect`
5. 🔌 Permite desconectar cable USB
6. 🧹 Cleanup automático al salir: cierra WiFi y revierte a USB

Requiere Android 11+ con "Depuración inalámbrica" activada.

---

## 💀 Kill + Resurrection Monitoring

Cuando se mata un proceso en modo `--kill`:

1. 💀 Intenta `kill <PID>`
2. 🔄 Si falla, `am force-stop <package>`
3. 👁️ Monitorea 15s si reaparece
4. ⚰️ Si resucita: ofrece watcher persistente (script bash cada 5s) o deshabilitar paquete

---

## 🔢 Severity Levels

```
▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰
  THREAT LEVEL:  ██████████████━━━━━
  Current: 🔴 CRITICAL
▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰
```

| Nivel | 🎨 Color | Significado |
|-------|----------|-------------|
| ℹ️ INFO | Cyan | Informativo |
| ⚠️ LOW | Yellow | Riesgo menor |
| ⚠️ MEDIUM | Orange | Requiere atención |
| ❌ HIGH | Orange-Red | Acción recomendada |
| 🚨 CRITICAL | Red | Acción inmediata |

---

## 📁 Estructura del Proyecto

```
CellInspector/
├── 📜 cellinspector.py              # Entry point + CLI
├── core/
│   ├── 📡 adb_client.py             # Comunicación ADB
│   ├── 🎨 display.py                # UI rich (paneles, termómetro, reportes, JSON+MITRE)
│   ├── 📏 severity.py               # Enum Severity
│   ├── 📖 guides.py                 # Guías localizadas paso a paso
│   ├── 🗃️ ioc_db.py                 # IOC database general + stalkerware
│   ├── 🦠 pegasus_ioc.py            # IOC database de Pegasus (hashes, C2, packages, procesos)
│   ├── 🔄 ioc_updater.py            # Auto-update: MalwareBazaar, AlienVault OTX, CISA
│   ├── 🛡️ vt_integration.py         # VirusTotal API v3 (hash lookup con rate limiting)
│   └── 🧬 mitre_attack.py           # MITRE ATT&CK for Mobile mapping (T1437, T1412, etc.)
├── modules/
│   ├── 🌐 network_analyzer.py       # Conexiones de red
│   ├── ⚙️ process_scanner.py        # Procesos
│   ├── 📦 package_analyzer.py       # Paquetes + stalkerware + permission combos + APK integrity
│   ├── 📝 logcat_monitor.py         # Logs del sistema
│   ├── 🔔 notification_analyzer.py  # Notificaciones + remediación interactiva
│   ├── 🛡️ device_analyzer.py        # Seguridad + CVE scanner local (37 CVEs)
│   ├── 🩹 remediation.py            # Matar procesos, watchers
│   ├── 🚨 zero_day_checker.py       # PoCs multilingüe: GitHub + deep web (Reddit, Pastebin, foros)
│   ├── 🦠 pegasus_detector.py       # Detector de spyware Pegasus (6 capas de detección)
│   ├── 🕵️ mvt_check.py              # MVT-powered detection (STIX2 IOCs de Amnesty International)
│   └── 🔒 vpn_detector.py           # VPN/Proxy/Tor detection
├── reports/                         # 📄 Reportes Markdown y JSON
├── data/                            # Datos externos
└── 📦 pyproject.toml                # Configuración pip
```

---

## 🗃️ IOC Databases

### `core/ioc_db.py` — IOC general

| Categoría | Descripción |
|-----------|-------------|
| 🚩 `SUSPICIOUS_PACKAGES` | Paquetes maliciosos conocidos |
| 🔍 `SUSPICIOUS_PACKAGE_PATTERNS` | Patrones de nombre sospechosos |
| ⚙️ `SUSPICIOUS_PROCESSES` | Procesos maliciosos |
| 🌐 `SUSPICIOUS_IPS` | IPs maliciosas |
| 🌍 `SUSPICIOUS_DOMAINS` | Dominios maliciosos |
| 🔑 `SUSPICIOUS_PERMISSIONS` | Permisos de alto riesgo |
| 📝 `SUSPICIOUS_LOGCAT_PATTERNS` | Patrones de log maliciosos |
| ☠️ `KNOWN_MALWARE_PACKAGES` | Hashes de malware conocido |
| 🦠 `STALKERWARE_PACKAGES` | 38 paquetes de spyware comercial (mSpy, FlexiSPY, Cocospy, etc.) |
| 🦠 `STALKERWARE_PROCESSES` | 19 procesos de stalkerware |
| 🌍 `STALKERWARE_C2_DOMAINS` | 12 dominios C2 de stalkerware |

### `core/pegasus_ioc.py` — Pegasus Spyware

| Categoría | Descripción |
|-----------|-------------|
| 🧬 `PEGASUS_SHA256` | Hashes SHA256 de muestras reales de Pegasus |
| 📦 `PEGASUS_PACKAGES` | Paquetes asociados a Pegasus |
| ⚙️ `PEGASUS_PROCESSES` | Nombres de procesos de Pegasus |
| 📁 `PEGASUS_FILE_PATHS` | Rutas de archivo conocidas |
| 🌐 `PEGASUS_C2_IPS` | IPs de servidores C2 (fuente: NSO Blacklist) |
| 🌍 `PEGASUS_C2_DOMAINS` | Dominios C2 (fuente: NSO Blacklist) |
| 🧩 `PEGASUS_KERNEL_MODULES` | Módulos kernel de Pegasus |

---

## ⚠️ Notas

- 📱 **Sin root**: usa `kill` vía ADB y `am force-stop` (no `kill -9`)
- 🔐 ADB puede requerir `sudo` en algunas distribuciones. Configurable vía variable de entorno:
  - `export CELLINSPECTOR_SUDO_PASSWORD="tu_password"` (recomendado)
  - `export SUDO_PASSWORD="tu_password"` (alternativa)
  - También configurable directamente en `core/adb_client.py`
- 📜 Los watchers persistentes son scripts bash independientes, no servicios Android
- 🌐 La detección de idioma usa `persist.sys.locale`, `ro.product.locale` y `system_locales`

---

<div align="center">
  <sub>CellInspector — Auditor de seguridad Android vía ADB</sub>
</div>

---

## 🙌 Agradecimientos

- **[MVT (Mobile Verification Toolkit)](https://github.com/mvt-project/mvt)** de **Amnesty International** — por su increíble trabajo en la recopilación y estandarización de indicadores STIX2 de spyware. Sus IOCs (licencia MIT) potencian el módulo `--mvt-check` de CellInspector. El trabajo de Amnesty International en la investigación de spyware de estado-nación es fundamental para la seguridad digital global.
- **[AbuseCH](https://abuse.ch)** — por MalwareBazaar y sus feeds de malware.
- **[AlienVault OTX](https://otx.alienvault.com)** — por su plataforma abierta de inteligencia de amenazas.
- **[CISA](https://www.cisa.gov)** — por el feed de Known Exploited Vulnerabilities.
- **[VirusTotal](https://www.virustotal.com)** — por su API de análisis de malware.
- **Comunidad open source** — a todos los investigadores que contribuyen a la seguridad móvil.
