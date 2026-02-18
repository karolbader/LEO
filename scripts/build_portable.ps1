param(
    [string]$LeoRepo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path,
    [string]$CupolaRepo = "E:\CupolaCore",
    [string]$AegisRepo = "E:\Sanctuary\products\aegis"
)

$ErrorActionPreference = "Stop"

function Require-File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
}

function Require-Directory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Label is missing: $Path"
    }
}

$leoRepoResolved = (Resolve-Path -LiteralPath $LeoRepo).Path
$cupolaRepoResolved = (Resolve-Path -LiteralPath $CupolaRepo).Path
$aegisRepoResolved = (Resolve-Path -LiteralPath $AegisRepo).Path

Push-Location $leoRepoResolved
try {
    Write-Host "Building leo.exe (release)..."
    cargo build --release
}
finally {
    Pop-Location
}

$leoExe = Join-Path $leoRepoResolved "target\release\leo.exe"
$cupolaExe = Join-Path $cupolaRepoResolved "target\release\cupola-cli.exe"
$epiExe = Join-Path $cupolaRepoResolved "target\release\epi-cli.exe"
$aegisExe = Join-Path $aegisRepoResolved "target\release\aegis.exe"
$aegisData = Join-Path $aegisRepoResolved "data"
$installDoc = Join-Path $leoRepoResolved "docs\INSTALL_PORTABLE.md"
$configFile = Join-Path $leoRepoResolved "config\leo.toml"

Require-File -Path $leoExe -Label "leo.exe"
Require-File -Path $cupolaExe -Label "cupola-cli.exe"
Require-File -Path $epiExe -Label "epi-cli.exe"
Require-File -Path $aegisExe -Label "aegis.exe"
Require-Directory -Path $aegisData -Label "aegis data directory"
Require-File -Path $installDoc -Label "INSTALL_PORTABLE.md"
Require-File -Path $configFile -Label "config\\leo.toml"

$distRoot = Join-Path $leoRepoResolved "dist\LEO"
$distToolsCupola = Join-Path $distRoot "tools\cupola"
$distToolsEpi = Join-Path $distRoot "tools\epi"
$distToolsAegis = Join-Path $distRoot "tools\aegis"
$distDocs = Join-Path $distRoot "docs"
$distConfig = Join-Path $distRoot "config"

if (Test-Path -LiteralPath $distRoot) {
    Remove-Item -LiteralPath $distRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $distToolsCupola -Force | Out-Null
New-Item -ItemType Directory -Path $distToolsEpi -Force | Out-Null
New-Item -ItemType Directory -Path $distToolsAegis -Force | Out-Null
New-Item -ItemType Directory -Path $distDocs -Force | Out-Null
New-Item -ItemType Directory -Path $distConfig -Force | Out-Null

Copy-Item -LiteralPath $leoExe -Destination (Join-Path $distRoot "leo.exe") -Force
Copy-Item -LiteralPath $cupolaExe -Destination (Join-Path $distToolsCupola "cupola-cli.exe") -Force
Copy-Item -LiteralPath $epiExe -Destination (Join-Path $distToolsEpi "epi-cli.exe") -Force
Copy-Item -LiteralPath $aegisExe -Destination (Join-Path $distToolsAegis "aegis.exe") -Force
Copy-Item -LiteralPath $aegisData -Destination $distToolsAegis -Recurse -Force
Copy-Item -LiteralPath $installDoc -Destination (Join-Path $distDocs "INSTALL_PORTABLE.md") -Force
Copy-Item -LiteralPath $configFile -Destination (Join-Path $distConfig "leo.toml") -Force

Write-Host "Portable release folder created: $distRoot"
