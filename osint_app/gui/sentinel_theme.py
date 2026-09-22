# Dummy PySide6 theme adapter to maintain import compatibility during rewrite
class _SentinelTheme:
    success = "#00ff66"
    warning = "#ffaa00"
    danger = "#ff3333"
    info = "#00d4ff"
    offline = "#555555"
    bg_surface = "#0c111d"
    bg_deep = "#070A12"
    text_primary = "#E0E6ED"
    success_dim = "#004d1f"
    warning_dim = "#4d3300"
    danger_dim = "#4d0f0f"
    offline_dim = "#222222"

ST = _SentinelTheme()
F = {"body": "Inter", "mono": "Courier", "h1": "Inter", "h2": "Inter"}

def apply_theme(*args): pass
def bind_hover(*args): pass
def pulse_dot(*args): pass
def animate_canvas_x(*args): pass
