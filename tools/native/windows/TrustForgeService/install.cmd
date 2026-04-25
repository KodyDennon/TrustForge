@echo off
:: install.cmd — register TrustForgeService with the Windows SCM.
::
:: Status: Draft — Phase 0. Experimental, not production-ready.
::
:: Must be run from an ELEVATED Command Prompt (Run as administrator).
:: Place TrustForgeService.exe at C:\Program Files\TrustForge\ before
:: running this script.

setlocal

set "TF_EXE=C:\Program Files\TrustForge\TrustForgeService.exe"

if not exist "%TF_EXE%" (
    echo ERROR: %TF_EXE% not found.
    echo        Copy TrustForgeService.exe into C:\Program Files\TrustForge\ first.
    exit /b 2
)

:: Create the service. start=auto means "start on boot".
:: type=own  means own process (we are not a shared service host).
sc create TrustForge ^
    binPath= "\"%TF_EXE%\"" ^
    start= auto ^
    type= own ^
    displayname= "TrustForge Authorization Daemon"
if errorlevel 1 (
    echo ERROR: sc create failed.
    exit /b %errorlevel%
)

:: Optional friendly description and recovery actions.
sc description TrustForge "Brokers TrustForge authorization decisions for the local system."
sc failure     TrustForge reset= 86400 actions= restart/5000/restart/5000/restart/30000

:: Start it now.
sc start TrustForge
if errorlevel 1 (
    echo NOTE: sc start failed. Check the Application event log for details.
    exit /b %errorlevel%
)

echo TrustForge service installed and started.
endlocal
exit /b 0
