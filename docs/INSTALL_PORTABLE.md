# LEO Portable Install (Windows)

## Customer Workflow

1. Unzip the portable `LEO` folder anywhere (`Desktop`, `Downloads`, `Temp`, network share, etc.).
2. Open PowerShell in the folder that contains `leo.exe`.
3. Run:
   - `.\RUN_SELF_AUDIT.ps1`

If script policy blocks execution, run:

- `powershell -ExecutionPolicy Bypass -File .\RUN_SELF_AUDIT.ps1`

`RUN_SELF_AUDIT.ps1` is the only required customer command. It:

- resolves all tool/input/output paths to absolute paths from the bundle root
- runs `leo.exe doctor`
- runs `leo.exe run` with bundled `cupola-cli.exe`, `aegis.exe`, and `epi-cli.exe`
- uses bundled verifier contracts from `contracts\v1`
- prints the final `DecisionPack.html`, `DecisionPack.pdf`, `verify.json`, and `pack.zip` paths

## Expected Outputs

The run writes to `out\self-audit-<timestamp>\` and must produce:

- `pack\<client>\<engagement>\PACK-001\DecisionPack.html`
- `pack\<client>\<engagement>\PACK-001\DecisionPack.pdf` (`>= 50 KB`)
- `pack\<client>\<engagement>\PACK-001\DecisionPack.manifest.json`
- `pack\<client>\<engagement>\PACK-001\DecisionPack.seal.json`
- `verify.json` with `ok=true`
- `pack.zip` (verifiable with `epi-cli verify`)

