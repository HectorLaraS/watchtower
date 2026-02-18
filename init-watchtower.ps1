<#
WATCHTOWER - Project Structure Initializer
Crea la estructura base del proyecto y archivos __init__.py
a partir del directorio actual
#>

$Root = Get-Location

Write-Host "Initializing WATCHTOWER project structure at:"
Write-Host "  $Root"
Write-Host ""

$folders = @(
    "src",
    "src\watchtower",
    "src\watchtower\receiver",
    "src\watchtower\routing",
    "src\watchtower\analyzers",
    "src\watchtower\storage",
    "src\watchtower\storage\mssql",
    "src\watchtower\domain",
    "src\watchtower\config",
    "src\watchtower\logging",
    "service",
    "tests",
    "logs"
)

foreach ($folder in $folders) {
    $fullPath = Join-Path $Root $folder

    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath | Out-Null
        Write-Host "Created: $folder"
    } else {
        Write-Host "Exists:  $folder"
    }
}

# Crear __init__.py en paquetes Python
$initFiles = @(
    "src\watchtower",
    "src\watchtower\receiver",
    "src\watchtower\routing",
    "src\watchtower\analyzers",
    "src\watchtower\storage",
    "src\watchtower\storage\mssql",
    "src\watchtower\domain",
    "src\watchtower\logging"
)

foreach ($path in $initFiles) {
    $initPath = Join-Path $Root "$path\__init__.py"

    if (-not (Test-Path $initPath)) {
        New-Item -ItemType File -Path $initPath | Out-Null
        Write-Host "Created: $path\__init__.py"
    } else {
        Write-Host "Exists:  $path\__init__.py"
    }
}

Write-Host ""
Write-Host "WATCHTOWER structure and __init__.py files created successfully."
