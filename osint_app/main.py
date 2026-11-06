"""OSINT App v2 — Entry Point."""
import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


def main():
    # La consola de Windows (cp1252) no admite los emojis de --check-tools y --keys: se caía con UnicodeEncodeError
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="OSINT Framework v2")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (no GUI)")
    parser.add_argument("--check-tools", action="store_true",
                        help="Print tool availability and exit")
    parser.add_argument("--keys", action="store_true",
                        help="Muestra qué claves de API están configuradas (nunca su valor)")
    parser.add_argument("--set-key", metavar="NOMBRE",
                        help="Guarda una clave de API; la pide por teclado sin mostrarla (ej: --set-key GitHub)")
    parser.add_argument("--backup", metavar="CARPETA", nargs="?", const="",
                        help="Copia de seguridad de casos, informes y CTI en un .zip (por defecto, en Documentos)")
    parser.add_argument("--restore", metavar="ARCHIVO",
                        help="Restaura una copia (.zip) con SENTINEL cerrado; antes guarda una copia del estado actual")
    parser.add_argument("--setup", action="store_true",
                        help="Comprueba la instalación paso a paso y ofrece arreglar lo que falte, preguntando antes")
    args = parser.parse_args()

    if args.setup:
        from osint_app.utils.setup_check import render, run_checks, run_interactive
        steps = run_checks()
        print(render(steps))
        # En una consola, ofrece arreglar lo que se pueda, preguntando antes de cada paso (sin consola, solo revisa)
        if sys.stdin and sys.stdin.isatty():
            run_interactive(steps)
        return
    if args.backup is not None:
        from osint_app.utils.backup import make_backup
        from osint_app.utils.data_paths import synced_warning
        folder = Path(args.backup) if args.backup else Path.home() / "Documents"
        made = make_backup(folder)
        print(f"✅ Copia guardada en {made} ({made.stat().st_size // 1024} KB). Tiene datos personales: guárdala "
              f"en un lugar seguro.")
        warning = synced_warning(folder)
        if warning:
            print("⚠️ Esa carpeta se sincroniza con la nube: los datos personales de la copia se subirían.")
        return
    if args.restore:
        import zipfile
        from osint_app.utils.backup import restore_backup
        try:
            previous = restore_backup(args.restore)
        except (OSError, ValueError, zipfile.BadZipFile) as e:
            sys.exit(f"❌ No se restauró nada: {e}")
        print(f"✅ Copia restaurada. Lo que había antes quedó guardado en {previous}.")
        return

    if args.keys or args.set_key:
        from osint_app.utils import key_cli
        sys.exit(key_cli.show_keys() if args.keys else key_cli.set_key_interactive(args.set_key))

    if args.check_tools:
        from osint_app.tools import build_tool_registry
        tools = build_tool_registry()
        print("\n🔍 OSINT Framework v2 — Tool Status\n" + "─"*44)
        for name, tool in tools.items():
            icon = "✅" if tool.is_available else "⬜"
            heavy = " [pesada]" if tool.is_heavy else ""
            api = " [API key]" if tool.requires_api_key else ""
            print(f"  {icon}  {name:<25}{heavy}{api}")
        print()
        return

    if args.cli:
        print("Modo CLI — crea un caso y corre herramientas individualmente.")
        print("Usa la GUI para la experiencia completa: python main.py")
        return

    # Launch GUI
    try:
        import os
        # Escala fija durante la sesión (evaluación 4): con la escala por monitor de Qt, un aviso de cambio de DPI de
        # Windows a mitad de uso redibujaba la ventana a 100 % encima de la de 125 % ("ventana doble") y la letra
        # cambiaba de tamaño entre pestañas. Con la escala del sistema se ve igual (mismo 125 %) y esos avisos no
        # llegan. Quien lo necesite puede cambiarlo con su propia variable QT_QPA_PLATFORM.
        if sys.platform == "win32":
            os.environ.setdefault("QT_QPA_PLATFORM", "windows:dpiawareness=1")
        from PySide6.QtWidgets import QApplication
        from osint_app.gui.app import OSINTGUI
        
        # El PDF de la ficha usa el motor web de Qt, que exige compartir contextos OpenGL antes de crear la app
        from PySide6.QtCore import QCoreApplication, Qt
        QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
        app = QApplication(sys.argv)

        # Noticias CTI: la primera vez se copian desde la carpeta del proyecto a la de datos del usuario
        from osint_app.utils.data_paths import prepare_cti_store
        prepare_cti_store()
        
        # Load QSS styles
        qss_path = os.path.join(os.path.dirname(__file__), 'gui', 'style.qss')
        if os.path.exists(qss_path):
            with open(qss_path, 'r', encoding='utf-8') as f:
                app.setStyleSheet(f.read())
                
        window = OSINTGUI()
        window.show()

        # Copia de seguridad diaria en segundo plano (no retrasa la apertura; ver utils/backup.py)
        import threading
        from osint_app.utils.backup import auto_backup
        threading.Thread(target=auto_backup, name="copia-diaria", daemon=True).start()

        # Los casos tienen datos personales de terceros: avisar si quedan en una carpeta sincronizada con la nube
        from osint_app.db.feedback_db import DB_PATH
        from osint_app.utils.data_paths import synced_warning
        cloud_warning = synced_warning(DB_PATH.parent)
        if cloud_warning:
            logging.warning(cloud_warning)
            window.toast.show(cloud_warning, kind="error")
        # Y si el disco no está cifrado: un equipo perdido o robado expondría los casos (en Windows Home se llama
        # "Cifrado de dispositivo"; se consulta sin permisos de administrador)
        from osint_app.utils.data_paths import disk_encryption_warning
        disk_warning = disk_encryption_warning(DB_PATH.parent)
        if disk_warning:
            logging.warning(disk_warning)
            window.toast.show(disk_warning, kind="warning")
        sys.exit(app.exec())
    except Exception as e:
        logging.critical(f"Error al lanzar GUI: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
