# Ported from NSP-FGTIPSecTools Tests\NPSManager.ADManagerCrossLink.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for NPS-Manager's new AD-Manager cross-links (2026-09-14), per the maintainer: "cross-link to AD
    Manager from the appropriate places in the RADIUS / CA managers." Covers the two interactive
    "no AD group found - create one?" decision points (Read-ANDConditionGroups in NPSInteractive.ps1,
    Resolve-NPSGroupInteractive in NPSCore.ps1) and New-NPSADGroup's own doc-comment - each now points
    at AD-Manager (PushableTools\ADManager\, menu 2) as the fuller, OU-browsable scaffold tool, since
    both of these only ever create ONE bare group with no OU structure of its own.

    Repo convention (Tests\README.md) - NOT Pester. Source-introspection only (Get-Command ...
    .Definition) - these two functions have heavy interactive/AD-search call chains already covered
    (or deliberately not covered) elsewhere; this file exists purely to guard the new cross-link text
    and the doc-comment, not to re-test the functions' whole zero/one/many-hit search behavior.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$NPSModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$Root = "C:\GitRepo\NSP-FGTIPSecTools"
$Mod  = "$NPSModuleRoot\Private"

Test-ScriptParses -Path "$Mod\NPSCore.ps1"        -Because "NPSCore.ps1 parses after New-NPSADGroup's AD-Manager cross-link"
Test-ScriptParses -Path "$Mod\NPSInteractive.ps1" -Because "NPSInteractive.ps1 parses after Read-ANDConditionGroups' AD-Manager cross-link"

# ---------------------------------------------------------------------------
# 1. New-NPSADGroup - doc-comment cross-reference
# ---------------------------------------------------------------------------
$rawCore = Get-Content -Path "$Mod\NPSCore.ps1" -Raw
Assert-Match -Actual $rawCore -Pattern '(?s)function New-NPSADGroup \{.*?See also: PushableTools\\ADManager' -Because "New-NPSADGroup's own doc-comment cross-references AD-Manager for a future reader of the code"
Assert-Match -Actual $rawCore -Pattern '(?s)function New-NPSADGroup \{.*?menu 2.*?menu 3' -Because "names AD-Manager's two relevant menu items - the scaffold AND the nesting step, not just a bare mention"

# ---------------------------------------------------------------------------
# 2. Resolve-NPSGroupInteractive (NPSCore.ps1) - the zero-hit "create?" decision point
# ---------------------------------------------------------------------------
Assert-Match -Actual $rawCore -Pattern '(?s)No AD groups found matching .{0,700}?AD-Manager \(PushableTools\\ADManager\\.{0,100}?menu 2\)' -Because "the zero-hit path in Resolve-NPSGroupInteractive tips the operator at AD-Manager before they pick 'C' to create a bare one-off group"

# ---------------------------------------------------------------------------
# 3. Read-ANDConditionGroups (NPSInteractive.ps1) - the SAME decision point in the other AD-group
#    resolver this tool has (the wildcard-search flow feeding NPS policy conditions)
# ---------------------------------------------------------------------------
$rawInteractive = Get-Content -Path "$Mod\NPSInteractive.ps1" -Raw
Assert-Match -Actual $rawInteractive -Pattern '(?s)No AD groups found matching .{0,700}?AD-Manager \(PushableTools\\ADManager\\.{0,100}?menu 2\)' -Because "the zero-hit path in Read-ANDConditionGroups gets the same tip - both AD-group resolvers in this tool point at AD-Manager consistently"

Write-TestSummary -Suite "NPS-Manager AD-Manager Cross-Links (2026-09-14)"
