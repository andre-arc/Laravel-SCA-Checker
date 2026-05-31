# Laravel Supply Chain Attack Checker — PowerShell wrapper
# Usage: .\check.ps1 C:\path\to\laravel-project [extra args]
# Compatible with: Windows PowerShell 5.1+, PowerShell 7+

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ProjectPath,
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$ExtraArgs
)

# Resolve absolute path
$AbsPath = Resolve-Path $ProjectPath -ErrorAction Stop | Select-Object -ExpandProperty Path

# Docker on Windows needs forward slashes for volume mounts
# Convert C:\path\to\project → C:/path/to/project
$DockerPath = $AbsPath -replace '\\', '/'

Write-Host "Scanning: $AbsPath" -ForegroundColor Cyan

docker run --rm `
    -v "${DockerPath}:/project:ro" `
    laravel-sca-checker `
    /project @ExtraArgs

exit $LASTEXITCODE
