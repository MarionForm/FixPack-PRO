@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo   FixPack PRO - Launcher
echo ============================================
echo.

REM Prova con py (Python Launcher) se presente
where py >nul 2>nul
if %errorlevel%==0 (
  py fixpack_pro.py
  goto end
)

REM Fallback: python
where python >nul 2>nul
if %errorlevel%==0 (
  python fixpack_pro.py
  goto end
)

echo [ERROR] No se encontro Python en el PATH.
echo Instala Python desde python.org y marca "Add to PATH".
pause

:end
echo.
pause
endlocal
