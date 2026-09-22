"""OSINT App v2 — Entry Point."""
import argparse
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


def main():
    parser = argparse.ArgumentParser(description="OSINT Framework v2")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (no GUI)")
    parser.add_argument("--check-tools", action="store_true",
                        help="Print tool availability and exit")
    args = parser.parse_args()

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
        from PySide6.QtWidgets import QApplication
        from osint_app.gui.app import OSINTGUI
        
        app = QApplication(sys.argv)
        
        # Load QSS styles
        qss_path = os.path.join(os.path.dirname(__file__), 'gui', 'style.qss')
        if os.path.exists(qss_path):
            with open(qss_path, 'r') as f:
                app.setStyleSheet(f.read())
                
        window = OSINTGUI()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        logging.critical(f"Error al lanzar GUI: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
