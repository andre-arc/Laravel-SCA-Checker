@echo off
:: Laravel Supply Chain Attack Checker — Windows CMD wrapper
:: Usage: check.bat C:\path\to\laravel-project [extra args]

setlocal

if "%~1"=="" (
    echo Usage: check.bat C:\path\to\laravel-project [--no-audit] [--no-vendor-scan]
    exit /b 1
)

set "PROJECT=%~f1"
shift

:: Convert backslashes to forward slashes for Docker
set "DOCKER_PATH=%PROJECT:\=/%"

echo Scanning: %PROJECT%

docker run --rm ^
    -v "%DOCKER_PATH%:/project:ro" ^
    laravel-sca-checker ^
    /project %*

exit /b %ERRORLEVEL%
