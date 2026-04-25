@echo off
:: uninstall.cmd — remove TrustForgeService from the Windows SCM.
::
:: Status: Draft — Phase 0. Experimental, not production-ready.
::
:: Must be run from an ELEVATED Command Prompt.

setlocal

:: Stop first; ignore "service not running" failures.
sc stop TrustForge
sc delete TrustForge
if errorlevel 1 (
    echo ERROR: sc delete failed.
    exit /b %errorlevel%
)

echo TrustForge service removed.
echo Optional cleanup:
echo   rmdir /s /q "C:\Program Files\TrustForge"
echo   rmdir /s /q "C:\ProgramData\TrustForge"

endlocal
exit /b 0
