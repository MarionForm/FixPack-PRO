#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FixPack PRO - Diagnóstico + Fixes seguros + Reportes (Windows/Linux/macOS)
Autor: MarionForm
Versión: 2.0.0

Características:
- Multi-plataforma (Windows/Linux/macOS) con acciones adaptadas
- Menú tipo TUI (sin dependencias externas)
- Modo DRY-RUN (simulación)
- Autodetección de problemas: DNS, conectividad, proxy, disco bajo, etc.
- Reporte exportable en JSON y HTML para adjuntar a tickets
- Logs automáticos en ./logs/
- Launcher portable .bat (Windows)

Notas:
- Algunas acciones avanzadas son específicas de Windows (SFC, DISM, netsh).
- En Linux/macOS se ejecutan equivalentes seguros (p.ej. limpiar DNS cache si aplica, info red, etc.)
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


APP_NAME = "FixPack PRO"
VERSION = "2.0.0"

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"fixpack_{RUN_ID}.log"


# -----------------------------
# Utilidades: salida, colores, logging
# -----------------------------
def supports_ansi() -> bool:
    # En Windows moderno suele funcionar; si no, no pasa nada (solo sin color).
    if platform.system().lower() != "windows":
        return True
    # Windows Terminal / VSCode terminal / ConPTY: normalmente sí.
    # Si no, se verá sin colores (no es crítico).
    return True


ANSI = supports_ansi()


def c(text: str, code: str) -> str:
    if not ANSI:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    line = f"[{ts()}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except Exception:
        pass


def hr() -> None:
    log("-" * 78)


def clear_screen() -> None:
    os.system("cls" if platform.system().lower() == "windows" else "clear")


def pause() -> None:
    input("\nPulsa ENTER para continuar...")


# -----------------------------
# Subprocess robusto
# -----------------------------
def run_cmd(
    cmd: List[str],
    *,
    timeout: int = 900,
    dry_run: bool = False,
    shell: bool = False,
    cwd: Optional[Path] = None
) -> Tuple[int, str, str]:
    cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
    log(f"▶ {cmd_str}")

    if dry_run:
        log("🟡 DRY-RUN: simulación (no se ejecuta).")
        return 0, "(dry-run) stdout vacío", "(dry-run) stderr vacío"

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=shell,
            cwd=str(cwd) if cwd else None,
        )
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if out:
            log(f"STDOUT:\n{out}")
        if err:
            log(f"STDERR:\n{err}")
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        log("❌ Timeout: el comando tardó demasiado y se canceló.")
        return 124, "", "TimeoutExpired"
    except FileNotFoundError:
        log("❌ Comando no encontrado (PATH / disponibilidad).")
        return 127, "", "FileNotFoundError"
    except Exception as e:
        log(f"❌ Error inesperado: {e}")
        return 1, "", str(e)


def run_powershell(ps_command: str, *, dry_run: bool = False, timeout: int = 900) -> Tuple[int, str, str]:
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command]
    return run_cmd(cmd, dry_run=dry_run, timeout=timeout)


# -----------------------------
# Sistema / permisos (Windows)
# -----------------------------
def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_macos() -> bool:
    return platform.system().lower() == "darwin"


def is_admin_windows() -> bool:
    if not is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin_notice(action_name: str) -> None:
    if is_windows() and not is_admin_windows():
        log(f"⚠️ '{action_name}' puede requerir ejecutar como Administrador.")
        log("   Consejo: abre PowerShell/CMD como Admin y ejecuta:  py fixpack_pro.py")


# -----------------------------
# Modelos para reporte
# -----------------------------
@dataclass
class CheckResult:
    name: str
    status: str  # OK / WARN / FAIL / INFO
    detail: str
    data: Dict[str, object]


@dataclass
class ActionResult:
    name: str
    status: str  # OK / WARN / FAIL
    detail: str
    return_code: int
    stdout: str
    stderr: str


class Session:
    def __init__(self) -> None:
        self.started_at = ts()
        self.os = platform.platform()
        self.python = sys.version.split()[0]
        self.hostname = socket.gethostname()
        self.user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
        self.dry_run = False

        self.checks: List[CheckResult] = []
        self.actions: List[ActionResult] = []

    def add_check(self, cr: CheckResult) -> None:
        self.checks.append(cr)

    def add_action(self, ar: ActionResult) -> None:
        self.actions.append(ar)

    def to_dict(self) -> Dict[str, object]:
        return {
            "app": APP_NAME,
            "version": VERSION,
            "run_id": RUN_ID,
            "started_at": self.started_at,
            "os": self.os,
            "python": self.python,
            "hostname": self.hostname,
            "user": self.user,
            "dry_run": self.dry_run,
            "log_file": str(LOG_FILE),
            "checks": [asdict(x) for x in self.checks],
            "actions": [asdict(x) for x in self.actions],
        }


SESSION = Session()


# -----------------------------
# Autodetección (checks)
# -----------------------------
def check_disk_space(min_free_gb: float = 5.0) -> CheckResult:
    drives = []
    warn = False

    if is_windows():
        candidates = ["C:\\", "D:\\", "E:\\", "F:\\"]
    else:
        candidates = ["/"]

    for d in candidates:
        if Path(d).exists():
            usage = shutil.disk_usage(d)
            free_gb = usage.free / (1024**3)
            total_gb = usage.total / (1024**3)
            drives.append({"mount": d, "free_gb": round(free_gb, 2), "total_gb": round(total_gb, 2)})
            if free_gb < min_free_gb:
                warn = True

    status = "WARN" if warn else "OK"
    detail = "Espacio libre bajo en al menos una unidad." if warn else "Espacio libre OK."
    return CheckResult("Disco: espacio libre", status, detail, {"drives": drives, "min_free_gb": min_free_gb})


def check_proxy() -> CheckResult:
    env_proxy = {}
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"]:
        v = os.environ.get(k)
        if v:
            env_proxy[k] = v

    winhttp_proxy = None
    if is_windows():
        rc, out, err = run_cmd(["netsh", "winhttp", "show", "proxy"], timeout=30, dry_run=False)
        if rc == 0:
            winhttp_proxy = out
        else:
            winhttp_proxy = f"(no disponible) {err}"

    active = bool(env_proxy) or (winhttp_proxy and "Direct access" not in winhttp_proxy)
    status = "WARN" if active else "OK"
    detail = "Proxy detectado (puede causar problemas de acceso)." if active else "Sin proxy detectado."
    return CheckResult("Red: proxy", status, detail, {"env_proxy": env_proxy, "winhttp_proxy": winhttp_proxy})


def check_dns_resolution(domain: str = "google.com") -> CheckResult:
    try:
        ip = socket.gethostbyname(domain)
        return CheckResult("DNS: resolución", "OK", f"Resolución OK: {domain} -> {ip}", {"domain": domain, "ip": ip})
    except Exception as e:
        return CheckResult("DNS: resolución", "FAIL", f"Fallo resolviendo {domain}: {e}", {"domain": domain, "error": str(e)})


def check_connectivity_ping() -> CheckResult:
    # Ping básico a IP (no DNS) para separar “internet” vs “DNS”
    target_ip = "1.1.1.1"
    if is_windows():
        cmd = ["ping", "-n", "2", target_ip]
    else:
        cmd = ["ping", "-c", "2", target_ip]

    rc, out, err = run_cmd(cmd, timeout=20, dry_run=False)
    if rc == 0:
        return CheckResult("Red: conectividad IP", "OK", f"Ping OK a {target_ip}", {"target": target_ip})
    return CheckResult("Red: conectividad IP", "FAIL", f"Ping FAIL a {target_ip}", {"target": target_ip, "stderr": err})


def run_autodetection() -> None:
    hr()
    log("🧠 Autodetección: analizando sistema...")
    checks = [
        check_disk_space(),
        check_proxy(),
        check_connectivity_ping(),
        check_dns_resolution(),
    ]
    for cr in checks:
        SESSION.add_check(cr)
        icon = {"OK": "✅", "WARN": "⚠️", "FAIL": "❌", "INFO": "ℹ️"}.get(cr.status, "•")
        log(f"{icon} {cr.name}: {cr.status} — {cr.detail}")
    hr()


# -----------------------------
# Export report JSON + HTML
# -----------------------------
def export_report_json() -> Path:
    out = REPORT_DIR / f"fixpack_report_{RUN_ID}.json"
    data = SESSION.to_dict()
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    log(f"📄 Report JSON guardado: {out}")
    return out


def export_report_html() -> Path:
    out = REPORT_DIR / f"fixpack_report_{RUN_ID}.html"
    data = SESSION.to_dict()

    def esc(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    checks_html = ""
    for ckr in data["checks"]:
        checks_html += f"""
        <tr>
          <td>{esc(ckr["name"])}</td>
          <td><b>{esc(ckr["status"])}</b></td>
          <td>{esc(ckr["detail"])}</td>
        </tr>
        """

    actions_html = ""
    for ar in data["actions"]:
        actions_html += f"""
        <details style="margin:10px 0;">
          <summary><b>{esc(ar["name"])}</b> — <span>{esc(ar["status"])}</span> — {esc(ar["detail"])}</summary>
          <pre>{esc(ar["stdout"])}</pre>
          <pre style="color:#a00;">{esc(ar["stderr"])}</pre>
        </details>
        """

    html = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <title>FixPack Report {RUN_ID}</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <style>
    body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; padding:20px;}}
    .card{{border:1px solid #ddd; border-radius:12px; padding:16px; margin:12px 0;}}
    table{{width:100%; border-collapse:collapse;}}
    td,th{{border-bottom:1px solid #eee; padding:10px; text-align:left; vertical-align:top;}}
    code,pre{{background:#f6f6f6; padding:12px; border-radius:10px; overflow:auto;}}
    .muted{{color:#666}}
  </style>
</head>
<body>
  <h1>FixPack PRO — Reporte</h1>
  <p class="muted"><b>Run ID:</b> {esc(RUN_ID)} &nbsp;|&nbsp; <b>Fecha:</b> {esc(data["started_at"])}</p>

  <div class="card">
    <h2>Entorno</h2>
    <p><b>OS:</b> {esc(data["os"])}<br/>
       <b>Host:</b> {esc(data["hostname"])}<br/>
       <b>Usuario:</b> {esc(data["user"])}<br/>
       <b>Python:</b> {esc(data["python"])}<br/>
       <b>Dry-run:</b> {esc(str(data["dry_run"]))}<br/>
       <b>Log:</b> {esc(data["log_file"])}
    </p>
  </div>

  <div class="card">
    <h2>Autodetección (Checks)</h2>
    <table>
      <thead><tr><th>Check</th><th>Estado</th><th>Detalle</th></tr></thead>
      <tbody>
        {checks_html}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Acciones ejecutadas</h2>
    {actions_html if actions_html else "<p class='muted'>No se ejecutaron acciones.</p>"}
  </div>

</body>
</html>
"""
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    log(f"📄 Report HTML guardado: {out}")
    return out


# -----------------------------
# Acciones (fixes)
# -----------------------------
def record_action(name: str, rc: int, out: str, err: str, detail_ok: str = "Acción completada.") -> None:
    status = "OK" if rc == 0 else "FAIL"
    detail = detail_ok if rc == 0 else "La acción devolvió error. Revisa stdout/stderr."
    SESSION.add_action(ActionResult(name, status, detail, rc, out, err))


def action_network_reset(dry_run: bool) -> None:
    hr()
    log("🌐 Reset de red (según sistema)")

    if is_windows():
        require_admin_notice("Reset de red (Windows)")
        steps = [
            (["ipconfig", "/flushdns"], 60),
            (["netsh", "winsock", "reset"], 120),
            (["netsh", "int", "ip", "reset"], 120),
            (["ipconfig", "/release"], 120),
            (["ipconfig", "/renew"], 180),
        ]
        last_rc = 0
        last_out = ""
        last_err = ""
        for cmd, t in steps:
            rc, out, err = run_cmd(cmd, timeout=t, dry_run=dry_run)
            last_rc, last_out, last_err = rc, out, err
        record_action("Reset de red (Windows)", last_rc, last_out, last_err, "Reset aplicado (puede requerir reinicio).")
    elif is_macos():
        # En macOS: flush DNS (varía por versión). Esto suele funcionar en versiones recientes.
        cmd = ["sudo", "dscacheutil", "-flushcache"]
        rc, out, err = run_cmd(cmd, timeout=60, dry_run=dry_run)
        # mDNSResponder restart
        cmd2 = ["sudo", "killall", "-HUP", "mDNSResponder"]
        rc2, out2, err2 = run_cmd(cmd2, timeout=60, dry_run=dry_run)
        record_action("Reset de red (macOS)", rc or rc2, out + "\n" + out2, err + "\n" + err2,
                      "DNS cache limpiada (si sudo estaba disponible).")
    else:
        # Linux: depende del sistema, probamos opciones “seguras” sin romper:
        # - systemd-resolve / resolvectl flush-caches
        # - restart NetworkManager (si existe)
        cmds = []
        if shutil.which("resolvectl"):
            cmds.append((["resolvectl", "flush-caches"], 30))
        elif shutil.which("systemd-resolve"):
            cmds.append((["systemd-resolve", "--flush-caches"], 30))

        if shutil.which("nmcli"):
            # Esto puede requerir sudo según distro
            cmds.append((["sudo", "systemctl", "restart", "NetworkManager"], 60))

        if not cmds:
            log("⚠️ No se detectaron herramientas estándar para flush DNS/restart red en este Linux.")
            record_action("Reset de red (Linux)", 1, "", "Herramientas no detectadas",
                          "No se encontró método estándar en este sistema.")
        else:
            last_rc = 0
            last_out = ""
            last_err = ""
            for cmd, t in cmds:
                rc, out, err = run_cmd(cmd, timeout=t, dry_run=dry_run)
                last_rc, last_out, last_err = rc, out, err
            record_action("Reset de red (Linux)", last_rc, last_out, last_err,
                          "Acción aplicada (según herramientas detectadas).")
    hr()


def action_dns_test(dry_run: bool) -> None:
    hr()
    log("🔎 Test rápido DNS / conectividad (ping + resolución)")

    # Ping IP
    target_ip = "1.1.1.1"
    ping_cmd = ["ping", "-n", "2", target_ip] if is_windows() else ["ping", "-c", "2", target_ip]
    rc1, out1, err1 = run_cmd(ping_cmd, timeout=20, dry_run=dry_run)

    # Ping dominio (si DNS funciona)
    target_host = "google.com"
    ping_cmd2 = ["ping", "-n", "2", target_host] if is_windows() else ["ping", "-c", "2", target_host]
    rc2, out2, err2 = run_cmd(ping_cmd2, timeout=25, dry_run=dry_run)

    # Resolución por socket
    try:
        ip = socket.gethostbyname(target_host) if not dry_run else "0.0.0.0 (dry-run)"
        res_detail = f"Resolución: {target_host} -> {ip}"
        res_rc = 0
        res_err = ""
    except Exception as e:
        res_detail = ""
        res_rc = 1
        res_err = str(e)

    combined_out = "\n".join([out1, out2, res_detail]).strip()
    combined_err = "\n".join([err1, err2, res_err]).strip()
    record_action("Test DNS/Red", 0 if (rc1 == 0 and (rc2 == 0 or res_rc == 0)) else 1, combined_out, combined_err,
                  "Test completado.")
    hr()


def action_clear_temp(dry_run: bool) -> None:
    hr()
    log("🧹 Limpieza de temporales (segura)")

    removed_files = 0
    removed_dirs = 0
    errors = 0

    paths: List[Path] = []
    if is_windows():
        paths = [Path(os.environ.get("TEMP", "")), Path(r"C:\Windows\Temp")]
    else:
        # Linux/macOS: /tmp y cache usuario (solo lo más seguro)
        paths = [Path("/tmp"), Path.home() / ".cache"]

    for p in paths:
        if not p.exists() or not p.is_dir():
            continue
        log(f"📁 Limpiando: {p}")

        if dry_run:
            log("🟡 DRY-RUN: no se borran archivos.")
            continue

        # OJO: en .cache puede ser grande; borramos solo contenido, no la carpeta.
        for item in p.glob("*"):
            try:
                # Evitar borrar cosas críticas en sistemas *nix:
                if not is_windows() and str(p) == "/tmp":
                    # /tmp es OK para limpiar, pero puede haber sockets/locks: ignorar si falla
                    pass

                if item.is_file() or item.is_symlink():
                    item.unlink(missing_ok=True)
                    removed_files += 1
                elif item.is_dir():
                    shutil.rmtree(item, ignore_errors=False)
                    removed_dirs += 1
            except Exception:
                errors += 1

    out = f"Borrados: {removed_files} archivos, {removed_dirs} carpetas. Errores: {errors}"
    log(f"✅ {out}")
    record_action("Limpieza de temporales", 0 if errors == 0 else 1, out, "" if errors == 0 else "Hubo errores al borrar")
    hr()


def action_disk_info(dry_run: bool) -> None:
    hr()
    log("💽 Estado de discos (espacio libre)")

    lines = []
    if is_windows():
        candidates = ["C:\\", "D:\\", "E:\\", "F:\\"]
    else:
        candidates = ["/"]

    for d in candidates:
        if Path(d).exists():
            u = shutil.disk_usage(d)
            total = u.total / (1024**3)
            free = u.free / (1024**3)
            used = (u.total - u.free) / (1024**3)
            lines.append(f"{d} -> Total {total:.1f}GB | Usado {used:.1f}GB | Libre {free:.1f}GB")

    out = "\n".join(lines) if lines else "No se pudieron leer unidades."
    log(out)
    record_action("Info discos", 0, out, "")
    hr()


def action_sfc(dry_run: bool) -> None:
    hr()
    log("🛠️ SFC /scannow (solo Windows)")
    if not is_windows():
        log("⚠️ SFC no aplica fuera de Windows.")
        record_action("SFC", 1, "", "No aplica en este sistema")
        hr()
        return

    require_admin_notice("SFC /scannow")
    rc, out, err = run_cmd(["sfc", "/scannow"], timeout=3600, dry_run=dry_run)
    record_action("SFC /scannow", rc, out, err, "SFC completado.")
    hr()


def action_dism(dry_run: bool) -> None:
    hr()
    log("🧱 DISM RestoreHealth (solo Windows)")
    if not is_windows():
        log("⚠️ DISM no aplica fuera de Windows.")
        record_action("DISM RestoreHealth", 1, "", "No aplica en este sistema")
        hr()
        return

    require_admin_notice("DISM RestoreHealth")
    rc, out, err = run_cmd(["dism", "/online", "/cleanup-image", "/restorehealth"], timeout=5400, dry_run=dry_run)
    record_action("DISM RestoreHealth", rc, out, err, "DISM completado.")
    hr()


def action_show_proxy(dry_run: bool) -> None:
    hr()
    log("🕵️ Mostrar configuración de proxy")

    env_proxy = {}
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"]:
        if os.environ.get(k):
            env_proxy[k] = os.environ.get(k)

    out_lines = ["ENV proxy variables:"]
    if env_proxy:
        for k, v in env_proxy.items():
            out_lines.append(f"  {k}={v}")
    else:
        out_lines.append("  (none)")

    winhttp = ""
    if is_windows():
        rc, out, err = run_cmd(["netsh", "winhttp", "show", "proxy"], timeout=30, dry_run=dry_run)
        winhttp = out if rc == 0 else err
        out_lines.append("\nWinHTTP proxy:")
        out_lines.append(winhttp or "(sin salida)")

    out = "\n".join(out_lines)
    log(out)
    record_action("Mostrar proxy", 0, out, "")
    hr()


# -----------------------------
# TUI (menu)
# -----------------------------
def banner() -> None:
    clear_screen()
    title = f"{APP_NAME} v{VERSION}"
    subtitle = f"Run: {RUN_ID} | Logs: {LOG_FILE.name} | Reports: {REPORT_DIR.name}/"
    mode = f"DRY-RUN: {'ON ✅' if SESSION.dry_run else 'OFF ❌'}"

    print(c("╔" + "═" * 76 + "╗", "36"))
    print(c("║", "36") + f" {c(title, '1;37')}".ljust(76) + c("║", "36"))
    print(c("║", "36") + f" {subtitle}".ljust(76) + c("║", "36"))
    print(c("║", "36") + f" {c(mode, '33')}".ljust(76) + c("║", "36"))
    print(c("╚" + "═" * 76 + "╝", "36"))


def menu() -> None:
    # Info inicial
    hr()
    log(f"{APP_NAME} iniciado.")
    log(f"OS: {platform.platform()} | Python: {sys.version.split()[0]}")
    if is_windows():
        log(f"Admin (Windows): {'Sí' if is_admin_windows() else 'No'}")
    log(f"Logs: {LOG_FILE}")
    hr()

    # Autodetección inicial
    run_autodetection()

    while True:
        banner()
        print("\n" + c("Opciones:", "1;37"))
        print("  1) Autodetección (re-ejecutar checks)")
        print("  2) Test DNS/Red (ping + resolución)")
        print("  3) Reset de red (según sistema)")
        print("  4) Limpiar temporales (seguro)")
        print("  5) Info discos")
        print("  6) Mostrar proxy")
        print("  7) SFC /scannow (Windows)")
        print("  8) DISM RestoreHealth (Windows)")
        print("  9) Exportar report JSON + HTML")
        print("  D) Toggle DRY-RUN (simulación)")
        print("  L) Abrir carpeta de reports (Windows)")
        print("  0) Salir")

        choice = input("\nElige: ").strip().lower()

        if choice == "1":
            run_autodetection()
            pause()
        elif choice == "2":
            action_dns_test(SESSION.dry_run)
            pause()
        elif choice == "3":
            action_network_reset(SESSION.dry_run)
            pause()
        elif choice == "4":
            action_clear_temp(SESSION.dry_run)
            pause()
        elif choice == "5":
            action_disk_info(SESSION.dry_run)
            pause()
        elif choice == "6":
            action_show_proxy(SESSION.dry_run)
            pause()
        elif choice == "7":
            action_sfc(SESSION.dry_run)
            pause()
        elif choice == "8":
            action_dism(SESSION.dry_run)
            pause()
        elif choice == "9":
            export_report_json()
            export_report_html()
            pause()
        elif choice == "d":
            SESSION.dry_run = not SESSION.dry_run
            log(f"🔁 DRY-RUN ahora: {'ON' if SESSION.dry_run else 'OFF'}")
        elif choice == "l":
            if is_windows():
                # apre cartella reports
                run_cmd(["explorer", str(REPORT_DIR)], timeout=10, dry_run=False, shell=False)
            else:
                log("ℹ️ Opción solo Windows (usa tu explorador/terminal para abrir la carpeta).")
            pause()
        elif choice == "0":
            log("👋 Saliendo. Exportando report final...")
            export_report_json()
            export_report_html()
            log("✅ Listo. Adjunta el HTML/JSON al ticket si hace falta.")
            break
        else:
            log("❌ Opción no válida.")
            time.sleep(0.8)


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        log("\n⛔ Interrumpido por el usuario (CTRL+C). Exportando report...")
        try:
            export_report_json()
            export_report_html()
        except Exception:
            pass
