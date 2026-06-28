@echo off
REM Avvia da Windows la preparazione automatica dell'ambiente Docker di test.
setlocal
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup-testing.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
  echo.
  echo [ERRORE] Preparazione non completata.
  exit /b %EXIT_CODE%
)

echo.
echo [OK] Progetto pronto per i test.
exit /b 0
