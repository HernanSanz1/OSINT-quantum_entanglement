"""Cifrado de Windows (DPAPI) sin dependencias: solo el mismo usuario de Windows, en el mismo equipo, puede descifrar.

Se usa para guardar las claves de API. No sirve para compartir el archivo con otra persona ni otro equipo: es lo que se busca.
"""
import ctypes
import sys
from ctypes import wintypes

AVAILABLE = sys.platform == "win32"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))), buf


def _call(function_name: str, data: bytes) -> bytes:
    if not AVAILABLE:
        raise OSError("DPAPI solo existe en Windows")
    blob_in, keepalive = _blob(data)
    blob_out = _Blob()
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    func = getattr(crypt32, function_name)
    if not func(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise OSError(f"{function_name} falló (código {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)
        del keepalive


def protect(data: bytes) -> bytes:
    return _call("CryptProtectData", data)


def unprotect(data: bytes) -> bytes:
    return _call("CryptUnprotectData", data)
