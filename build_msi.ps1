@echo off
setlocal

REM Set the installation code (GUID) that will be embedded in the MSI
set INSTALLATION_CODE=%1
if "%INSTALLATION_CODE%"=="" (
    echo No installation code provided, generating a new one...
    for /F "tokens=*" %%a in ('powershell -Command "[guid]::NewGuid().ToString()"') do set INSTALLATION_CODE=%%a
)

echo Using Installation Code: %INSTALLATION_CODE%
echo Building MSI installer...
dotnet build MyInstaller.wixproj -p:InstallationCode="%INSTALLATION_CODE%" -c Release
