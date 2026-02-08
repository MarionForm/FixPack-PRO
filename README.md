# FixPack PRO 🧰 (Windows / Linux / macOS)
**FixPack PRO** es un kit de diagnóstico + reparaciones rápidas para Soporte Técnico / HelpDesk.

Incluye:
- ✅ Menú tipo TUI (sin dependencias externas)
- ✅ Modo **DRY-RUN** (simulación sin aplicar cambios)
- ✅ Autodetección de problemas: DNS, conectividad, proxy, disco bajo…
- ✅ Export de reportes **JSON + HTML** para adjuntar a tickets
- ✅ Acciones específicas Windows (SFC/DISM/Reset red) y equivalentes seguros en Linux/macOS

## Requisitos
- Python 3.10+ (recomendado)
- Windows 10/11, Linux o macOS

## Uso rápido
Ejecuta:

```bash
python fixpack_pro.py

Seguridad
Incluye DRY-RUN para probar sin aplicar cambios y evitar “toquetear” sistemas en producción.
#En Windows también puedes usar el launcher:
fixpack.bat (doble click)
Para acciones avanzadas en Windows (SFC/DISM/Reset red), ejecutar como Administrador.
