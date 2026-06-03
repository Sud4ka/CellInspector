# CellInspector 🕵️‍♂️📱

**Auditor de seguridad para dispositivos Android vía ADB** — analiza, detecta y remedia amenazas con CLI colorida, termómetro de severidad y guías localizadas.

---

## ✨ Características

| Modo | Flag | Descripción |
|------|------|-------------|
| 🔍 **Escaneo completo** | *(ninguno)* | 6 módulos de seguridad: red, procesos, paquetes, logcat, notificaciones, dispositivo |
| 🛠️ **Auto-fix** | `-f` / `--fixall` | Corrige automáticamente lo detectable y re-verifica con delta report |
| 🎯 **Modo Kill** | `-k` / `--kill` | Lista y mata procesos sospechosos interactivamente |
| 🔔 **Notificaciones** | `-n` / `--notifications` | Gestión interactiva de listeners, canales y purga de notificaciones |
| 📡 **Monitor** | `-m` / `--monitor` | Escaneo en tiempo real cada N segundos |
| 🚨 **Zero-Day scan** | `--0days` | Busca PoCs/exploits activos en GitHub para tu dispositivo |
| 📄 **Reporte** | `-r` / `--report` | Genera reporte Markdown en `reports/` |
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
```

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

### 🚨 Zero-Day Exploit Scanner (`--0days`)

```bash
python3 cellinspector.py --0days
```

Busca en GitHub PoCs/exploits activos para tu dispositivo:

| Paso | Acción |
|------|--------|
| 1️⃣ | Detecta modelo, versión de Android, API level, parche de seguridad |
| 2️⃣ | Consulta GitHub API con 4 queries distintas |
| 3️⃣ | Filtra por relevancia (CVE, exploit, RCE, root, escalada de privilegios) |
| 4️⃣ | Muestra resultados en rojo con enlace, estrellas, lenguaje y fecha |

Salida:
```
🔍 Scanning GitHub for active exploits...
  Device: moto g72 | Android: 13

🚨 3 exploit(s) activo(s) con PoC detectado(s)!

╭─ 💥 Exploit #1 ─────────────────────────────╮
│ user/CVE-2023-xxx-android-poc                │
│ PoC for CVE-2023-xxx in Android 13...        │
│                                              │
│ 🔗 https://github.com/user/repo              │
│ ⭐ 42  📁 Python  📅 2025-10-01              │
╰──────────────────────────────────────────────╯
```

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
| Root | Busca binario `su` |
| Verified boot | Estado de verificación |
| 🔒 SELinux | Enforcing / permissive |
| 🔌 USB debugging | Estado |
| 🔐 Encryption | Cifrado de almacenamiento |
| 📲 Unknown sources | Instalación fuera de Play Store |
| ⚙️ Developer options | Estado |

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
│   ├── 🎨 display.py                # UI rich (paneles, termómetro, reportes)
│   ├── 📏 severity.py               # Enum Severity
│   ├── 📖 guides.py                 # Guías localizadas paso a paso
│   └── 🗃️ ioc_db.py                 # IOC database
├── modules/
│   ├── 🌐 network_analyzer.py       # Conexiones de red
│   ├── ⚙️ process_scanner.py        # Procesos
│   ├── 📦 package_analyzer.py       # Paquetes instalados
│   ├── 📝 logcat_monitor.py         # Logs del sistema
│   ├── 🔔 notification_analyzer.py  # Notificaciones + remediación interactiva
│   ├── 🛡️ device_analyzer.py        # Seguridad del dispositivo
│   ├── 🩹 remediation.py            # Matar procesos, watchers
│   └── 🚨 zero_day_checker.py       # Búsqueda de PoCs en GitHub
├── reports/                         # 📄 Reportes Markdown
└── data/                            # Datos externos
```

---

## 🗃️ IOC Database

`core/ioc_db.py` contiene indicadores de compromiso:

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
