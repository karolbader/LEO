# LEO Portable Install (Windows)

This layout runs `leo.exe` without requiring Rust toolchains or local source repos.

## Expected Layout

LEO resolves tools from the folder that contains `leo.exe`:

- `tools\cupola\cupola-cli.exe`
- `tools\epi\epi-cli.exe`
- `tools\aegis\aegis.exe`
- `tools\aegis\data\...` (Aegis control packs)
- `config\leo.toml`

Tool lookup order:

1. Embedded `tools\...` paths
2. `config\leo.toml` (`cupola_bin`, `aegis_bin`, `epi_bin`)
3. Environment variables: `CUPOLA_CLI`, `AEGIS_EXE`, `EPI_CLI`

## Quick Start

1. Unzip the portable folder.
2. Open PowerShell in the folder containing `leo.exe`.
3. Run `.\leo.exe doctor`.
4. Run:
   - `.\leo.exe run --vault "E:\Sanctuary\products\aegis" --intake "<path-to-intake.json>" --out "E:\_packs\LEO-<ts>"`

## Verify Output Pack

- `.\tools\epi\epi-cli.exe verify "<out>\pack.zip"`

## Notes

- No network calls are required.
- Deterministic pack behavior is unchanged.
