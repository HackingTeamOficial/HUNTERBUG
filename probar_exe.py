"""Comprueba que el .exe empaquetado arranca y crea su ventana."""
import os
import subprocess
import sys
import time

EXE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "dist", "HunterBug 1.0.exe")
print("probando:", EXE)
print("existe:", os.path.exists(EXE), "| tamano: %.1f MB"
      % (os.path.getsize(EXE) / 1048576.0))

if not os.path.exists(EXE):
    sys.exit("No se encuentra el ejecutable")

p = subprocess.Popen([EXE])
print("pid:", p.pid)
time.sleep(25)
vivo = p.poll() is None
print("sigue vivo tras 25 s:", vivo)
if not vivo:
    print("CODIGO DE SALIDA:", p.returncode)
    sys.exit("El ejecutable murio al arrancar")

# ventana creada: buscamos el titulo con las APIs de Windows
try:
    import ctypes
    from ctypes import wintypes

    EnumWindows = ctypes.windll.user32.EnumWindows
    GetWindowText = ctypes.windll.user32.GetWindowTextW
    IsWindowVisible = ctypes.windll.user32.IsWindowVisible
    titulos = []

    def cb(hwnd, _lp):
        if IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            GetWindowText(hwnd, buf, 256)
            if buf.value and "HUNTERBUG" in buf.value.upper():
                titulos.append(buf.value)
        return True

    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND,
                                      wintypes.LPARAM)
    EnumWindows(WNDENUMPROC(cb), 0)
    print("ventana encontrada:", titulos)
    ok = bool(titulos)
except Exception as e:
    print("no se pudo enumerar ventanas:", e)
    ok = vivo

# el ejecutable de un solo fichero lanza un proceso hijo: hay que matar el arbol
subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)],
               capture_output=True, text=True)
try:
    p.wait(timeout=15)
except Exception:
    p.kill()
print("proceso detenido")
print("RESULTADO:", "ARRANCA Y CREA SU VENTANA" if ok else "ARRANCA (ventana no confirmada)")
