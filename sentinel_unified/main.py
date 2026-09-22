#!/usr/bin/env python3
"""
SENTINEL UNIFIED
Plataforma unificada de OSINT + CTI

Modulos:
- PROFILE: Perfilamiento de personas
- RECON: Reconocimiento de infraestructura
- CTI: Threat Intelligence (feeds, dossiers, boletines)

Uso:
    python main.py           # Lanza GUI
    python main.py --cli     # Modo CLI
    python main.py --check   # Verificar herramientas
"""
import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def check_tools():
    """Verificar disponibilidad de herramientas"""
    print("\n SENTINEL UNIFIED - Tool Status\n" + "=" * 50)

    tools = {
        "PROFILE": [
            ("sherlock", "sherlock --help"),
            ("holehe", "holehe --help"),
            ("maigret", "maigret --help"),
            ("ghunt", "ghunt --help"),
        ],
        "RECON": [
            ("subfinder", "subfinder -version"),
            ("amass", "amass -version"),
            ("theharvester", "theHarvester -h"),
            ("waybackurls", "waybackurls -h"),
        ],
        "CTI": [
            ("harvest.py", None),  # internal
            ("dossier.py", None),  # internal
            ("render.py", None),   # internal
        ],
    }

    import subprocess

    for module, tool_list in tools.items():
        print(f"\n[{module}]")
        for name, cmd in tool_list:
            if cmd is None:
                # Internal tool
                path = Path(__file__).parent / "modules" / module.lower() / f"{name}"
                status = "OK" if path.exists() else "MISSING"
                icon = "+" if status == "OK" else " "
                print(f"  {icon}  {name:<20} [{status}]")
            else:
                try:
                    subprocess.run(
                        cmd.split(),
                        capture_output=True,
                        timeout=5
                    )
                    print(f"  +  {name:<20} [OK]")
                except Exception:
                    print(f"     {name:<20} [NOT FOUND]")

    print()


def cli_mode():
    """Modo CLI interactivo"""
    print("\nSENTINEL UNIFIED - CLI Mode")
    print("Comandos: new, list, select <id>, profile, recon, cti, exit\n")

    from core import db, Case, CaseType

    current_case = None

    while True:
        try:
            cmd = input(f"sentinel [{current_case or 'no case'}]> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if cmd == "exit":
            break
        elif cmd == "new":
            name = input("Nombre del caso: ").strip()
            if name:
                case = Case(name=name, case_type=CaseType.MIXED)
                case_id = db.create_case(case)
                print(f"Caso creado: ID {case_id}")
        elif cmd == "list":
            cases = db.get_cases()
            for c in cases:
                print(f"  [{c.id}] {c.name} ({c.case_type.value})")
        elif cmd.startswith("select "):
            try:
                case_id = int(cmd.split()[1])
                case = db.get_case(case_id)
                if case:
                    current_case = case.name
                    print(f"Caso activo: {case.name}")
                else:
                    print("Caso no encontrado")
            except (ValueError, IndexError):
                print("Uso: select <id>")
        elif cmd == "profile":
            print("Modulo PROFILE - herramientas de perfilamiento")
            # TODO: submenu de herramientas
        elif cmd == "recon":
            print("Modulo RECON - herramientas de reconocimiento")
            # TODO: submenu de herramientas
        elif cmd == "cti":
            print("Modulo CTI - threat intelligence")
            # TODO: submenu de herramientas
        elif cmd == "":
            continue
        else:
            print(f"Comando desconocido: {cmd}")


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL UNIFIED - OSINT + CTI Platform"
    )
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--check", action="store_true", help="Check tool availability")
    args = parser.parse_args()

    if args.check:
        check_tools()
        return

    if args.cli:
        cli_mode()
        return

    # Launch GUI
    try:
        from gui.app import main as gui_main
        gui_main()
    except ImportError as e:
        logger.error(f"Error importing GUI: {e}")
        logger.info("Falling back to CLI mode...")
        cli_mode()
    except Exception as e:
        logger.critical(f"Error launching GUI: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
