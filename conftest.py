"""Configuración global de pytest (se carga antes que cualquier import del proyecto).

Los tests usan una carpeta de datos temporal para que nunca creen, migren ni toquen los casos reales del usuario.
"""
import os
import tempfile

os.environ.setdefault("SENTINEL_DATA_DIR", tempfile.mkdtemp(prefix="sentinel-tests-"))
