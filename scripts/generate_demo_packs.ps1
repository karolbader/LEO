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

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Args,
        [string]$Workdir
    )

    if ([string]::IsNullOrWhiteSpace($Workdir)) {
        $output = & $Exe @Args 2>&1
    }
    else {
        Push-Location $Workdir
        try {
            $output = & $Exe @Args 2>&1
        }
        finally {
            Pop-Location
        }
    }

    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $rendered = ($output | ForEach-Object { $_.ToString() }) -join " "
        throw "command failed (exit=$exitCode): $Exe $($Args -join ' ') $rendered"
    }

    return ,$output
}

try {
    $leoRoot = Split-Path -Parent $PSScriptRoot
    $productsRoot = Split-Path -Parent $leoRoot
    $aegisRoot = Join-Path $productsRoot "aegis"
    $packsRoot = "E:\_packs"
    $vaultRoot = Join-Path $packsRoot "_demo_vault"
    $cupolaRepo = "E:\CupolaCore"

    $cupolaExe = Join-Path $leoRoot "dist\LEO\tools\cupola\cupola-cli.exe"
    $aegisDistExe = Join-Path $leoRoot "dist\LEO\tools\aegis\aegis.exe"
    $pdfRenderer = Join-Path $leoRoot "scripts\render_decision_pack_pdf.mjs"
    $fontRegular = Join-Path $leoRoot "scripts\fonts\SourceSans3-Regular.otf"
    $fontBold = Join-Path $leoRoot "scripts\fonts\SourceSans3-Bold.otf"
    $fontItalic = Join-Path $leoRoot "scripts\fonts\SourceSans3-It.otf"

    Require-File -Path $cupolaExe -Label "cupola-cli.exe"
    Require-File -Path $aegisDistExe -Label "aegis.exe"
    Require-File -Path $pdfRenderer -Label "render_decision_pack_pdf.mjs"
    Require-File -Path $fontRegular -Label "SourceSans3-Regular.otf"
    Require-File -Path $fontBold -Label "SourceSans3-Bold.otf"
    Require-File -Path $fontItalic -Label "SourceSans3-It.otf"
    Require-File -Path (Join-Path $aegisRoot "Cargo.toml") -Label "aegis Cargo.toml"
    Require-File -Path (Join-Path $leoRoot "Cargo.toml") -Label "leo Cargo.toml"

    New-Item -ItemType Directory -Path $packsRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $vaultRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $vaultRoot "docs") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $vaultRoot "evidence") -Force | Out-Null

    Set-Content -LiteralPath (Join-Path $vaultRoot "README.md") -Value @"
# Demo Vault

Deterministic vault content for LEO smoke pack generation.
"@
    Set-Content -LiteralPath (Join-Path $vaultRoot "docs\security-policy.md") -Value @"
# Security Policy

All privileged access requires approval and periodic review.
Incident response runbooks are maintained and tested quarterly.
"@
    Set-Content -LiteralPath (Join-Path $vaultRoot "evidence\controls.json") -Value @"
{
  "controls": [
    { "id": "CTRL-001", "status": "implemented", "owner": "security" },
    { "id": "CTRL-002", "status": "monitoring", "owner": "platform" }
  ]
}
"@

    $libraries = @(
        @{ Id = "vendorsecurity/v1"; Meta = "vendorsecurity-v1"; Safe = "vendorsecurity-v1" },
        @{ Id = "dfir-lite/v1"; Meta = "dfir-lite-v1"; Safe = "dfir-lite-v1" },
        @{ Id = "iso27001-lite/v1"; Meta = "iso27001-lite-v1"; Safe = "iso27001-lite-v1" }
    )

    foreach ($library in $libraries) {
        $safeLibrary = $library.Safe
        $libraryId = $library.Id
        $libraryMetaId = $library.Meta
        $clientId = ("demo-{0}" -f $safeLibrary)
        $engagementId = "starter"
        $packId = "PACK-001"
        $demoRoot = Join-Path $packsRoot ("DEMO_{0}_PACK-001" -f $safeLibrary)
        $packRoot = Join-Path $demoRoot "pack"
        $intakePath = Join-Path $demoRoot "intake.json"
        $verifyPath = Join-Path $demoRoot "verify.json"
        $packZipPath = Join-Path $demoRoot "pack.zip"

        New-Item -ItemType Directory -Path $demoRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $packRoot -Force | Out-Null

        $intake = [ordered]@{
            schema_version = "aegis.intake.v1"
            client_id = $clientId
            engagement_id = $engagementId
            pack_type = "trust_audit"
            library_pack = $libraryId
            output_mode = "out_dir"
            scope = [ordered]@{
                in_scope = "Starter pack smoke generation"
                out_of_scope = "Live incident response"
            }
            claims = [ordered]@{
                "C-001" = $true
            }
            deadlines = [ordered]@{
                due_date = "2027-12-31"
            }
            pack_meta = [ordered]@{
                pack_type = "demo"
                library = $libraryMetaId
                client = $clientId
                engagement = $engagementId
                pack_id = $packId
            }
        }
        $intake | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $intakePath

        Invoke-Native -Exe "cargo" -Args @(
            "run",
            "--",
            "run",
            "--vault", $vaultRoot,
            "--cupola-repo", $cupolaRepo,
            "--intake", $intakePath,
            "--out", $packRoot
        ) -Workdir $aegisRoot | Out-Null

        $decisionPackHtml = Get-ChildItem -LiteralPath $packRoot -Recurse -File -Filter "DecisionPack.html" |
            Select-Object -First 1
        if ($null -eq $decisionPackHtml) {
            throw "DecisionPack.html is missing under $packRoot"
        }

        $decisionPackDir = Split-Path -Parent $decisionPackHtml.FullName
        $decisionPackPdf = Join-Path $decisionPackDir "DecisionPack.pdf"
        $decisionPackSha = Join-Path $decisionPackDir "SHA256.txt"

        Invoke-Native -Exe "node" -Args @(
            $pdfRenderer,
            "--html", $decisionPackHtml.FullName,
            "--pdf", $decisionPackPdf,
            "--library", $libraryId,
            "--client", $clientId,
            "--engagement", $engagementId,
            "--pack-id", $packId,
            "--font-regular", $fontRegular,
            "--font-bold", $fontBold,
            "--font-italic", $fontItalic
        ) | Out-Null

        Require-File -Path $decisionPackPdf -Label "DecisionPack.pdf"
        $pdfSize = (Get-Item -LiteralPath $decisionPackPdf).Length
        if ($pdfSize -le 51200) {
            throw "DecisionPack.pdf is too small ($pdfSize bytes): $decisionPackPdf"
        }

        $pdfHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $decisionPackPdf).Hash.ToLowerInvariant()
        Set-Content -LiteralPath $decisionPackSha -Value ("{0}  DecisionPack.pdf" -f $pdfHash)
        Require-File -Path $decisionPackSha -Label "SHA256.txt"

        Invoke-Native -Exe "cargo" -Args @(
            "run",
            "--",
            "pack",
            "--vault", $vaultRoot,
            "--intake", $intakePath,
            "--out", $demoRoot,
            "--cupola-bin", $cupolaExe,
            "--aegis-bin", $aegisDistExe
        ) -Workdir $leoRoot | Out-Null

        Require-File -Path $packZipPath -Label "pack.zip"

        $requiredPackFiles = @(
            "epi.decision_pack.v1.json",
            "epi.claims.v1.json",
            "epi.drift_report.v1.json"
        )
        foreach ($fileName in $requiredPackFiles) {
            $path = Join-Path $packRoot $fileName
            Require-File -Path $path -Label $fileName
        }

        $decisionPackHtmlAfterPack = Get-ChildItem -LiteralPath $packRoot -Recurse -File -Filter "DecisionPack.html" |
            Select-Object -First 1
        if ($null -eq $decisionPackHtmlAfterPack) {
            throw "DecisionPack.html is missing under $packRoot"
        }
        $decisionPackPdfAfterPack = Get-ChildItem -LiteralPath $packRoot -Recurse -File -Filter "DecisionPack.pdf" |
            Select-Object -First 1
        if ($null -eq $decisionPackPdfAfterPack) {
            throw "DecisionPack.pdf is missing under $packRoot"
        }
        $pdfSizeAfterPack = $decisionPackPdfAfterPack.Length
        if ($pdfSizeAfterPack -le 51200) {
            throw "DecisionPack.pdf is too small after pack ($pdfSizeAfterPack bytes): $($decisionPackPdfAfterPack.FullName)"
        }
        $pdfHashAfterPack = (Get-FileHash -Algorithm SHA256 -LiteralPath $decisionPackPdfAfterPack.FullName).Hash.ToLowerInvariant()
        $shaLine = (Get-Content -LiteralPath $decisionPackSha -ErrorAction Stop | Select-Object -First 1).Trim()
        if ($shaLine -notmatch [Regex]::Escape($pdfHashAfterPack)) {
            throw "SHA256.txt does not match DecisionPack.pdf in $decisionPackDir"
        }

        $decisionPackJsonPath = Join-Path $packRoot "epi.decision_pack.v1.json"
        Require-File -Path $decisionPackJsonPath -Label "epi.decision_pack.v1.json"
        $decisionPackJson = Get-Content -Raw -LiteralPath $decisionPackJsonPath | ConvertFrom-Json
        if ($null -eq $decisionPackJson.pack_meta) {
            throw "epi.decision_pack.v1.json is missing pack_meta"
        }

        $actualPackType = [string]$decisionPackJson.pack_meta.pack_type
        $actualLibrary = [string]$decisionPackJson.pack_meta.library
        $actualClient = [string]$decisionPackJson.pack_meta.client
        $actualEngagement = [string]$decisionPackJson.pack_meta.engagement
        $requiredMeta = @(
            @{ Name = "pack_type"; Value = $actualPackType },
            @{ Name = "library"; Value = $actualLibrary },
            @{ Name = "client"; Value = $actualClient },
            @{ Name = "engagement"; Value = $actualEngagement }
        )
        foreach ($entry in $requiredMeta) {
            if ([string]::IsNullOrWhiteSpace($entry.Value)) {
                throw "epi.decision_pack.v1.json pack_meta.$($entry.Name) is blank"
            }
        }
        if ($actualPackType.Trim() -ne "demo") {
            throw "epi.decision_pack.v1.json pack_meta.pack_type must be demo, got '$actualPackType'"
        }
        if ($actualLibrary.Trim() -ne $libraryMetaId) {
            throw "epi.decision_pack.v1.json pack_meta.library mismatch: expected '$libraryMetaId', got '$actualLibrary'"
        }
        if ($actualClient.Trim() -ne $clientId) {
            throw "epi.decision_pack.v1.json pack_meta.client mismatch: expected '$clientId', got '$actualClient'"
        }
        if ($actualEngagement.Trim() -ne $engagementId) {
            throw "epi.decision_pack.v1.json pack_meta.engagement mismatch: expected '$engagementId', got '$actualEngagement'"
        }

        $verifyObject = [ordered]@{
            ok = $true
            pack_zip = $packZipPath
            decision_pack_html = $decisionPackHtmlAfterPack.FullName
            decision_pack_pdf = $decisionPackPdfAfterPack.FullName
            decision_pack_pdf_bytes = $pdfSizeAfterPack
            decision_pack_pdf_sha256 = $pdfHashAfterPack
            library = $libraryMetaId
            client = $clientId
            engagement = $engagementId
            pack_id = $packId
        }
        $verifyObject | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $verifyPath
        Require-File -Path $verifyPath -Label "verify.json"

        Write-Output ("OK {0}" -f $demoRoot)
    }
}
catch {
    Write-Output "FAIL $($_.Exception.Message)"
    exit 1
}
