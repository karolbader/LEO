# LEO Portable Install (Windows)

This layout runs `leo.exe` without requiring Rust toolchains or local source repos.

## Expected Layout

LEO resolves tools from the folder that contains `leo.exe`:

- `tools\cupola\cupola-cli.exe`
- `tools\epi\epi-cli.exe`
- `tools\aegis\aegis.exe`
- `tools\aegis\data\...` (Aegis control packs)
- `config\leo.toml`
- `data\intake.json`
- `scripts\smoke_e2e.ps1`

Tool lookup order:

1. Embedded `tools\...` paths
2. `config\leo.toml` (`cupola_bin`, `aegis_bin`, `epi_bin`)
3. Environment variables: `CUPOLA_CLI`, `AEGIS_EXE`, `EPI_CLI`

## Quick Start

1. Unzip the portable folder.
2. Open PowerShell in the folder containing `leo.exe`.
3. Run `.\leo.exe doctor`.
4. Run the quick smoke:
   - `pwsh -File .\scripts\smoke_e2e.ps1`

## Quick Smoke

`smoke_e2e.ps1` performs a self-contained rail smoke:

- creates a synthetic vault in `%TEMP%\leo-smoke\vault\...`
- writes output to `%TEMP%\leo-smoke\run-...`
- runs `leo.exe doctor`
- runs `leo.exe run --vault ... --intake .\data\intake.json --out ...`
- runs `tools\epi\epi-cli.exe verify <out>\pack.zip --json`

The script prints one line:

- `PASS <verify-json>` on success
- `FAIL <reason>` on failure (exit code non-zero)

## Verify Output Pack (Manual)

- `.\tools\epi\epi-cli.exe verify "<out>\pack.zip" --json`

## Demo PDF Smoke

Single command:

- `pwsh -ExecutionPolicy Bypass -File E:\Sanctuary\products\leo\scripts\generate_demo_packs.ps1`

This generates three demo outputs:

- `E:\_packs\DEMO_vendorsecurity-v1_PACK-001`
- `E:\_packs\DEMO_dfir-lite-v1_PACK-001`
- `E:\_packs\DEMO_iso27001-lite-v1_PACK-001`

Each output includes:

- `pack.zip`
- `verify.json`
- `pack\epi.*.json`
- `pack\<client>\<engagement>\PACK-001\DecisionPack.html`
- `pack\<client>\<engagement>\PACK-001\DecisionPack.pdf`
- `pack\<client>\<engagement>\PACK-001\SHA256.txt` (SHA256 of `DecisionPack.pdf`)

## Notes

- No network calls are required.
- Deterministic pack behavior is unchanged.
- Chromium PDF metadata fields may vary by render run:
  - `/CreationDate`
  - `/ModDate`
  - document `/ID`

