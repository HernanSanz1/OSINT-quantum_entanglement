"""Resource monitor — warns before running heavy tools."""
import psutil


class ResourceMonitor:
    """Platform-independent CPU/RAM checker."""

    def __init__(self, cpu_threshold: float = 70.0, ram_threshold: float = 80.0):
        self.cpu_threshold = cpu_threshold
        self.ram_threshold = ram_threshold

    def cpu_percent(self) -> float:
        return psutil.cpu_percent(interval=0.5)

    def ram_percent(self) -> float:
        return psutil.virtual_memory().percent

    def ram_available_gb(self) -> float:
        return psutil.virtual_memory().available / (1024 ** 3)

    def is_overloaded(self) -> bool:
        return (
            self.cpu_percent() > self.cpu_threshold
            or self.ram_percent() > self.ram_threshold
        )

    def status_message(self) -> str:
        cpu = self.cpu_percent()
        ram = self.ram_percent()
        avail = self.ram_available_gb()
        return (
            f"CPU: {cpu:.0f}%  |  RAM: {ram:.0f}%  |  "
            f"Disponible: {avail:.1f} GB"
        )

    def warning_message(self) -> str:
        return (
            f"⚠️  Sistema bajo carga alta\n"
            f"CPU: {self.cpu_percent():.0f}%  RAM: {self.ram_percent():.0f}%\n"
            "Ejecutar una herramienta pesada puede ralentizar el sistema.\n"
            "¿Deseas continuar?"
        )
