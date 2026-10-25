@echo off
REM ============================================================
REM  HunterBug 1.0 - compilacion del ejecutable (un solo .exe)
REM  Uso: doble clic, o "compilar.bat" desde esta carpeta
REM ============================================================
setlocal
cd /d "%~dp0"

echo.
echo [1/3] Limpiando compilaciones anteriores...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "HunterBug 1.0.spec" del /q "HunterBug 1.0.spec"

echo [2/3] Compilando con PyInstaller (modo un solo fichero)...
python -m PyInstaller --noconfirm --clean --onefile --noconsole ^
  --name "HunterBug 1.0" ^
  --icon "assets\hunterbug.ico" ^
  --add-data "assets;assets" ^
  --collect-all hb ^
  --collect-all customtkinter ^
  --hidden-import matplotlib.backends.backend_tkagg ^
  --hidden-import PIL._tkinter_finder ^
  HunterBugGUI.py

if errorlevel 1 (
  echo.
  echo ERROR: la compilacion fallo. Revisa el mensaje de arriba.
  pause
  exit /b 1
)

echo [3/3] Listo.
echo.
echo Ejecutable: dist\"HunterBug 1.0.exe"
for %%F in ("dist\HunterBug 1.0.exe") do echo Tamano: %%~zF bytes
echo.
echo Para comprobar que arranca: python probar_exe.py
echo.
pause
