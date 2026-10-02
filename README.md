# NSP.NPS

Windows NPS (RADIUS) for NSP VPN deployments, plus the **NPS Manager** dashboard (formerly the
zip-delivered NPS-Manager in NSP-FGTIPSecTools). Windows PowerShell **5.1** compatible (and 7+);
imports on a bare host. NSP.Toolkit / NSP.Console / NSP.Bootstrap are loaded when the dashboard
starts.

## Start it

```powershell
Start-NSPNpsManager                       # the dashboard (relaunches elevated)
Start-NSPToolkit -Tool NPS                # same, via the NSP.Toolkit launcher
New-NSPNpsShim -ClientAnswers .\EXAMPLE.json -Path C:\Temp\NPS-Manager.ps1   # a launcher for the NPS server
```

## What's in it

| Function | Purpose |
|---|---|
| `Start-NSPNpsManager` | The dashboard - same menus as the zip-era NPS-Manager: install/authorize NPS, NPS Extension, import Kickstart definitions from the Orchestrator, clients & templates, rules, troubleshooting, hand-back (menu 7). |
| `New-NSPNpsShim` | Write a launcher (NSP.ClientScripts ToolShim recipe) carrying a client's RADIUS answers; the launcher blanks them from itself once handed over. |
| `ConvertTo-NSPNpsAnswers` | One ClientAnswers object -> the answers NPS Manager imports, with `IsComplete` (the mapping Import Kickstart Definitions uses). |
| `Get-NSPNpsStatus` | Read-only snapshot of the server's NPS setup (role, AD registration, policy/client counts, NPS Extension). |

## What changed from the zip-era tool

- Answers live in `%ProgramData%\NSP\Toolkit\NPS\Answers\Answers.json` (Administrators and SYSTEM
  only). The AD server, AD username (never a password) and "always ask for AD credentials" flag the
  old tool wrote into its shim are saved there instead.
- Menu 7 writes `<Company>_NPS_Response.json`, an NSP.Toolkit hand-off (shared header around the
  same SchemaVersion 1 payload), into the work folder's `Responses\`. Copy it to the Orchestrator's
  `Staging\<Abbrev>\Inbox\`.
- The first start on a server offers to move the zip-era tool's files (`NPSStaging\`, old shims with
  answers embedded) into the work folder (`Move-NSPToolLegacyData`).

## Source layout

The engine files (`Private\NPSCore.ps1`, `NPSInteractive.ps1`, `NPSExtension.ps1`,
`NPSTroubleshooting.ps1`, `NPSHandoff.ps1`, `OrchestratorImport.ps1`, and `Dashboard.ps1` - the old
script's menu functions) were moved verbatim, with small marked edits (`NSP.NPS:` comments). They
are still several functions per file and are not linted yet (`tools\AnalyzerBaseline.txt`);
splitting them one function per file, and promoting reusable engine functions to `Verb-NSPNps*`
public names, comes next.

## Tests

```powershell
.\tools\Test-Repo.ps1      # PSScriptAnalyzer + Pester 5 under Windows PowerShell 5.1 and pwsh
```

`Tests\Legacy\*.LegacyTest.ps1` are NSP-FGTIPSecTools' NPS tests (its AST-extraction harness),
re-pointed at this module's files and run by `Tests\Legacy.Tests.ps1`.
