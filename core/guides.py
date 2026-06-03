from typing import List, Optional
from core.severity import Severity
from core.display import console
from core.adb_client import get_device_locale
from rich.panel import Panel
from rich import box
from rich.table import Table

GUIDES = {
    "es": {
        "title": "Guia paso a paso - Soluciones manuales",
        "intro": "Los siguientes problemas requieren intervencion manual en el dispositivo:",
        "USB Debugging": {
            "title": "Deshabilitar depuracion USB",
            "steps": [
                "1. Abre Configuracion (Settings) en el dispositivo",
                "2. Ve a 'Sistema' > 'Opciones de desarrollador'",
                "3. Busca 'Depuracion USB' y desactivarla",
                "4. Si no ves Opciones de desarrollador: ve a 'Acerca del telefono' y toca 7 veces 'Numero de compilacion'",
            ],
        },
        "Developer Options Enabled": {
            "title": "Deshabilitar opciones de desarrollador",
            "steps": [
                "1. Abre Configuracion (Settings)",
                "2. Ve a 'Sistema' > 'Opciones de desarrollador'",
                "3. Toca el interruptor superior para desactivar todo",
            ],
        },
        "Unknown Sources Enabled": {
            "title": "Deshabilitar instalacion de fuentes desconocidas",
            "steps": [
                "1. Abre Configuracion (Settings)",
                "2. Ve a 'Seguridad' > 'Instalar apps desconocidas'",
                "3. Desactiva el permiso para cada app que no necesites",
            ],
        },
        "Device Not Encrypted": {
            "title": "Cifrar el dispositivo",
            "steps": [
                "1. Abre Configuracion (Settings)",
                "2. Ve a 'Seguridad' > 'Cifrar telefono'",
                "3. Conecta el cargador (requisito obligatorio)",
                "4. Toca 'Cifrar telefono' y espera (puede tardar 1 hora)",
                "5. IMPORTANTE: No apagues el telefono durante el proceso",
            ],
        },
        "Suspicious Notification Listeners Detected": {
            "title": "Revocar acceso a notificaciones de apps sospechosas",
            "steps": [
                "1. Abre Configuracion (Settings)",
                "2. Ve a 'Apps' > 'Acceso especial' > 'Acceso a notificaciones'",
                "3. Identifica las apps marcadas como sospechosas",
                "4. Desactiva el permiso para cada una",
                "5. Considera desinstalar estas aplicaciones",
            ],
        },
        "Non-Dismissible Notifications": {
            "title": "Bloquear notificaciones persistentes",
            "steps": [
                "1. Manten presionada la notificacion persistente",
                "2. Toca 'Configurar' o el engranaje",
                "3. Desactiva el canal de notificacion especifico",
                "4. Alternativamente: ve a Configuracion > Apps > [App] > Notificaciones",
                "5. Desactiva los canales que no quieras recibir",
            ],
        },
        "High Notification Volume": {
            "title": "Reducir volumen de notificaciones",
            "steps": [
                "1. Abre Configuracion (Settings)",
                "2. Ve a 'Apps' y selecciona la app con muchas notificaciones",
                "3. Toca 'Notificaciones'",
                "4. Desactiva los canales innecesarios o baja su importancia",
            ],
        },
        "Security Patch Level": {
            "title": "Actualizar parche de seguridad",
            "steps": [
                "1. Abre Configuracion (Settings)",
                "2. Ve a 'Seguridad' > 'Actualizacion de seguridad'",
                "3. Toca 'Buscar actualizacion'",
                "4. Instala cualquier actualizacion disponible",
            ],
        },
        "Multiple Notification Listeners Active": {
            "title": "Revisar listeners de notificaciones activos",
            "steps": [
                "1. Abre Configuracion (Settings)",
                "2. Ve a 'Apps' > 'Acceso especial' > 'Acceso a notificaciones'",
                "3. Revisa la lista y desactiva los que no uses",
                "4. Cada listener puede leer todas tus notificaciones",
            ],
        },
        "Engineering/Debug Build": {
            "title": "Actualizar a build de produccion",
            "steps": [
                "1. Descarga la ROM stock para tu modelo",
                "2. Flashea usando fastboot o la herramienta del fabricante",
                "3. Esto requiere desbloquear el bootloader (borra datos)",
                "4. Recomendacion: contacta al servicio tecnico",
            ],
        },
        "Device is Rooted": {
            "title": "Dispositivo rooteado",
            "steps": [
                "1. Si necesitas root: instala Magisk para root seguro",
                "2. Si no necesitas root: busca la ROM stock y flasheala",
                "3. Algunas apps bancarias no funcionan con root",
            ],
        },
        "Verified Boot Status": {
            "title": "Verificar estado del boot",
            "steps": [
                "1. Reinicia el dispositivo en modo fastboot",
                "2. Ejecuta: fastboot oem lock (borra todos los datos)",
                "3. O reinstala la ROM stock del fabricante",
            ],
        },
        "SELinux is Disabled": {
            "title": "Activar SELinux",
            "steps": [
                "1. SELinux deshabilitado indica modificacion del sistema",
                "2. Flashea la ROM stock para restaurar SELinux",
                "3. Si tienes root: ejecuta 'setenforce 1' en terminal",
            ],
        },
    },
    "en": {
        "title": "Step-by-step guide - Manual fixes",
        "intro": "The following issues require manual intervention on the device:",
        "USB Debugging": {
            "title": "Disable USB Debugging",
            "steps": [
                "1. Open Settings on the device",
                "2. Go to 'System' > 'Developer options'",
                "3. Find 'USB debugging' and turn it off",
                "4. If you don't see Developer options: go to 'About phone' and tap 'Build number' 7 times",
            ],
        },
        "Developer Options Enabled": {
            "title": "Disable Developer Options",
            "steps": [
                "1. Open Settings",
                "2. Go to 'System' > 'Developer options'",
                "3. Toggle the top switch to turn off all developer options",
            ],
        },
        "Unknown Sources Enabled": {
            "title": "Disable unknown sources installation",
            "steps": [
                "1. Open Settings",
                "2. Go to 'Security' > 'Install unknown apps'",
                "3. Disable permission for any app you don't trust",
            ],
        },
        "Device Not Encrypted": {
            "title": "Encrypt the device",
            "steps": [
                "1. Open Settings",
                "2. Go to 'Security' > 'Encrypt phone'",
                "3. Plug in the charger (required)",
                "4. Tap 'Encrypt phone' and wait (may take 1 hour)",
                "5. IMPORTANT: Do not turn off the device during encryption",
            ],
        },
        "Suspicious Notification Listeners Detected": {
            "title": "Revoke notification access for suspicious apps",
            "steps": [
                "1. Open Settings",
                "2. Go to 'Apps' > 'Special access' > 'Notification access'",
                "3. Identify suspicious apps",
                "4. Turn off the permission for each one",
                "5. Consider uninstalling suspicious apps",
            ],
        },
        "Non-Dismissible Notifications": {
            "title": "Block persistent notifications",
            "steps": [
                "1. Long-press the persistent notification",
                "2. Tap 'Settings' or the gear icon",
                "3. Turn off the specific notification channel",
                "4. Alternatively: Settings > Apps > [App] > Notifications",
                "5. Disable any channels you don't want to see",
            ],
        },
        "High Notification Volume": {
            "title": "Reduce notification volume",
            "steps": [
                "1. Open Settings",
                "2. Go to 'Apps' and select the high-volume app",
                "3. Tap 'Notifications'",
                "4. Disable unnecessary channels or lower their importance",
            ],
        },
        "Security Patch Level": {
            "title": "Update security patch",
            "steps": [
                "1. Open Settings",
                "2. Go to 'Security' > 'Security update'",
                "3. Tap 'Check for update'",
                "4. Install any available update",
            ],
        },
        "Multiple Notification Listeners Active": {
            "title": "Review active notification listeners",
            "steps": [
                "1. Open Settings",
                "2. Go to 'Apps' > 'Special access' > 'Notification access'",
                "3. Review the list and disable any you don't need",
                "4. Each listener can read all of your notifications",
            ],
        },
        "Engineering/Debug Build": {
            "title": "Flash a production build",
            "steps": [
                "1. Download the stock ROM for your device model",
                "2. Flash using fastboot or the manufacturer's tool",
                "3. This requires unlocking the bootloader (wipes data)",
                "4. Recommendation: contact technical support",
            ],
        },
        "Device is Rooted": {
            "title": "Rooted device",
            "steps": [
                "1. If you need root: install Magisk for safe root management",
                "2. If you don't need root: find your stock ROM and flash it",
                "3. Banking apps typically won't work on rooted devices",
            ],
        },
        "Verified Boot Status": {
            "title": "Verify boot status",
            "steps": [
                "1. Reboot to fastboot mode",
                "2. Run: fastboot oem lock (this wipes all data)",
                "3. Or reinstall the manufacturer's stock ROM",
            ],
        },
        "SELinux is Disabled": {
            "title": "Enable SELinux",
            "steps": [
                "1. Disabled SELinux indicates system modification",
                "2. Flash the stock ROM to restore SELinux",
                "3. If rooted: run 'setenforce 1' in a terminal",
            ],
        },
    },
}


def get_guide_for_finding(title: str, locale: str = "es") -> Optional[dict]:
    lang = locale if locale in GUIDES else "en"
    guides = GUIDES.get(lang, GUIDES["en"])
    return guides.get(title, None)


def find_matching_guide(finding_title: str, locale: str = "es") -> Optional[dict]:
    lang = locale if locale in GUIDES else "en"
    title_lower = finding_title.lower()
    for key, guide in GUIDES.get(lang, GUIDES["en"]).items():
        if key.lower() in title_lower or title_lower in key.lower():
            return guide
    return None


def render_manual_guides(findings: list, locale: Optional[str] = None):
    if not locale:
        detected = get_device_locale()
        locale = detected if detected else "en"

    seen = set()
    guides_shown = []

    for f in findings:
        if len(f) < 4:
            continue
        title = f[1]
        if title in seen:
            continue
        seen.add(title)
        guide = find_matching_guide(title, locale)
        if guide and guide.get("steps"):
            guides_shown.append((title, guide))

    if not guides_shown:
        return

    lang = locale if locale in GUIDES else "en"
    header = GUIDES[lang]["title"]
    intro = GUIDES[lang]["intro"]

    console.print(f"\n[bold cyan]\U0001f4d6 {header}[/]")
    console.print(f"[dim]{intro}[/]\n")

    for title, guide in guides_shown:
        step_count = len(guide["steps"])
        panel = Panel(
            "\n".join(guide["steps"]),
            title=f"[bold yellow]{guide['title']}[/]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
        console.print(panel)
        console.print()
