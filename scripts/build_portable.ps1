param(
    [string]$LeoRepo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path,
    [string]$CupolaRepo,
    [string]$AegisRepo
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
$leoProductsRoot = Split-Path -Parent $leoRepoResolved
$leoWorkspaceRoot = Split-Path -Parent $leoProductsRoot
$driveRoot = Split-Path -Parent $leoWorkspaceRoot

if ([string]::IsNullOrWhiteSpace($CupolaRepo)) {
    if (-not [string]::IsNullOrWhiteSpace($env:CUPOLA_REPO)) {
        $CupolaRepo = $env:CUPOLA_REPO
    }
    else {
        $CupolaRepo = Join-Path $leoProductsRoot "cupola-core"
    }
}

if ([string]::IsNullOrWhiteSpace($AegisRepo)) {
    if (-not [string]::IsNullOrWhiteSpace($env:AEGIS_REPO)) {
        $AegisRepo = $env:AEGIS_REPO
    }
    else {
        $AegisRepo = Join-Path $leoProductsRoot "aegis"
    }
}

$cupolaRepoResolved = (Resolve-Path -LiteralPath $CupolaRepo).Path
$aegisRepoResolved = (Resolve-Path -LiteralPath $AegisRepo).Path

Push-Location $leoRepoResolved
try {
    Write-Host "Building release binaries (leo + cargo-shim)..."
    cargo build --release --bins
}
finally {
    Pop-Location
}

$leoExe = Join-Path $leoRepoResolved "target\release\leo.exe"
$cargoShimExe = Join-Path $leoRepoResolved "target\release\cargo-shim.exe"
$cupolaExe = Join-Path $cupolaRepoResolved "target\release\cupola-cli.exe"
$epiExe = Join-Path $cupolaRepoResolved "target\release\epi-cli.exe"
$cupolaContractsV1 = Join-Path $cupolaRepoResolved "contracts\v1"
$aegisExe = Join-Path $aegisRepoResolved "target\release\aegis.exe"
$aegisData = Join-Path $aegisRepoResolved "data"
$aegisIntake = Join-Path $aegisData "intake.json"
$installDoc = Join-Path $leoRepoResolved "docs\INSTALL_PORTABLE.md"
$configFile = Join-Path $leoRepoResolved "config\leo.toml"
$libraryCatalogFile = Join-Path $leoRepoResolved "config\library_catalog.json"
$leoContractsV1 = Join-Path $leoRepoResolved "config\contracts\v1"
$smokeScript = Join-Path $leoRepoResolved "scripts\smoke_e2e.ps1"
$selfAuditScript = Join-Path $leoRepoResolved "scripts\RUN_SELF_AUDIT.ps1"

Require-File -Path $leoExe -Label "leo.exe"
Require-File -Path $cupolaExe -Label "cupola-cli.exe"
Require-File -Path $epiExe -Label "epi-cli.exe"
Require-Directory -Path $cupolaContractsV1 -Label "contracts\\v1"
Require-File -Path $aegisExe -Label "aegis.exe"
Require-Directory -Path $aegisData -Label "aegis data directory"
Require-File -Path $aegisIntake -Label "aegis data\\intake.json"
Require-File -Path $installDoc -Label "INSTALL_PORTABLE.md"
Require-File -Path $configFile -Label "config\\leo.toml"
Require-File -Path $libraryCatalogFile -Label "config\\library_catalog.json"
Require-Directory -Path $leoContractsV1 -Label "config\\contracts\\v1"
Require-File -Path $smokeScript -Label "scripts\\smoke_e2e.ps1"
Require-File -Path $selfAuditScript -Label "scripts\\RUN_SELF_AUDIT.ps1"
Require-File -Path $cargoShimExe -Label "cargo-shim.exe"

$distRoot = Join-Path $leoRepoResolved "dist\LEO"
$distToolsCupola = Join-Path $distRoot "tools\cupola"
$distToolsCupolaRepoRelease = Join-Path $distToolsCupola "target\release"
$distToolsEpi = Join-Path $distRoot "tools\epi"
$distToolsAegis = Join-Path $distRoot "tools\aegis"
$distDocs = Join-Path $distRoot "docs"
$distConfig = Join-Path $distRoot "config"
$distData = Join-Path $distRoot "data"
$distScripts = Join-Path $distRoot "scripts"
$distContracts = Join-Path $distRoot "contracts"
$distContractsV1 = Join-Path $distContracts "v1"

if (Test-Path -LiteralPath $distRoot) {
    Remove-Item -LiteralPath $distRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $distToolsCupola -Force | Out-Null
New-Item -ItemType Directory -Path $distToolsCupolaRepoRelease -Force | Out-Null
New-Item -ItemType Directory -Path $distToolsEpi -Force | Out-Null
New-Item -ItemType Directory -Path $distToolsAegis -Force | Out-Null
New-Item -ItemType Directory -Path $distDocs -Force | Out-Null
New-Item -ItemType Directory -Path $distConfig -Force | Out-Null
New-Item -ItemType Directory -Path $distData -Force | Out-Null
New-Item -ItemType Directory -Path $distScripts -Force | Out-Null
New-Item -ItemType Directory -Path $distContracts -Force | Out-Null
New-Item -ItemType Directory -Path $distContractsV1 -Force | Out-Null

Copy-Item -LiteralPath $leoExe -Destination (Join-Path $distRoot "leo.exe") -Force
Copy-Item -LiteralPath $cargoShimExe -Destination (Join-Path $distRoot "cargo.exe") -Force
Copy-Item -LiteralPath $cupolaExe -Destination (Join-Path $distToolsCupola "cupola-cli.exe") -Force
Copy-Item -LiteralPath $cupolaExe -Destination (Join-Path $distToolsCupolaRepoRelease "cupola-cli.exe") -Force
Copy-Item -LiteralPath $epiExe -Destination (Join-Path $distToolsEpi "epi-cli.exe") -Force
Copy-Item -LiteralPath $aegisExe -Destination (Join-Path $distToolsAegis "aegis.exe") -Force
Copy-Item -LiteralPath $aegisData -Destination $distToolsAegis -Recurse -Force
Copy-Item -LiteralPath $cupolaContractsV1 -Destination $distContracts -Recurse -Force
Copy-Item -Path (Join-Path $leoContractsV1 "*") -Destination $distContractsV1 -Recurse -Force
Copy-Item -LiteralPath $aegisIntake -Destination (Join-Path $distData "intake.json") -Force
Copy-Item -LiteralPath $installDoc -Destination (Join-Path $distDocs "INSTALL_PORTABLE.md") -Force
Copy-Item -LiteralPath $configFile -Destination (Join-Path $distConfig "leo.toml") -Force
Copy-Item -LiteralPath $libraryCatalogFile -Destination (Join-Path $distConfig "library_catalog.json") -Force
Copy-Item -LiteralPath $smokeScript -Destination (Join-Path $distScripts "smoke_e2e.ps1") -Force
Copy-Item -LiteralPath $selfAuditScript -Destination (Join-Path $distRoot "RUN_SELF_AUDIT.ps1") -Force

Write-Host "Portable release folder created: $distRoot"
