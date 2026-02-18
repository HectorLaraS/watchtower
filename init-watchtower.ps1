# init-watchtower.ps1
# Crea estructura base de Watchtower desde el directorio actual.

$ErrorActionPreference = "Stop"

Write-Host "Creating Watchtower structure..."

$basePath = Get-Location

# Folders to create
$folders = @(
    "src",
    "src\domain",
    "src\service",
    "src\storage",
    "src\core",
    "src\logs",
    "tests",
    "docs"
)

foreach ($folder in $folders) {
    $fullPath = Join-Path $basePath $folder
    if (-not (Test-Path -LiteralPath $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath | Out-Null
        Write-Host ("Created folder: " + $folder)
    }
}

# __init__.py files
$initFiles = @(
    "src\__init__.py",
    "src\domain\__init__.py",
    "src\service\__init__.py",
    "src\storage\__init__.py",
    "src\core\__init__.py",
    "src\logs\__init__.py",
    "tests\__init__.py"
)

foreach ($file in $initFiles) {
    $fullPath = Join-Path $basePath $file
    if (-not (Test-Path -LiteralPath $fullPath)) {
        New-Item -ItemType File -Path $fullPath | Out-Null
        Write-Host ("Created file: " + $file)
    }
}

# main.py
$mainFile = Join-Path $basePath "src\main.py"
if (-not (Test-Path -LiteralPath $mainFile)) {
    Set-Content -Path $mainFile -Value "# Watchtower entrypoint`r`n" -Encoding UTF8
    Write-Host "Created file: src\main.py"
}

# requirements.txt
$requirementsFile = Join-Path $basePath "requirements.txt"
if (-not (Test-Path -LiteralPath $requirementsFile)) {
    Set-Content -Path $requirementsFile -Value "" -Encoding UTF8
    Write-Host "Created file: requirements.txt"
}

# .gitignore (simple, safe)
$gitignoreFile = Join-Path $basePath ".gitignore"
if (-not (Test-Path -LiteralPath $gitignoreFile)) {
    $gitignoreLines = @(
        "# Python",
        "__pycache__/",
        "*.pyc",
        "*.pyo",
        "*.pyd",
        ".env",
        ".venv/",
        "",
        "# Logs",
        "*.log",
        "",
        "# VSCode",
        ".vscode/",
        "",
        "# OS",
        "Thumbs.db",
        ".DS_Store"
    )
    Set-Content -Path $gitignoreFile -Value $gitignoreLines -Encoding UTF8
    Write-Host "Created file: .gitignore"
}

Write-Host "Done."
