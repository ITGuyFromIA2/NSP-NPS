# Ported from NSP-FGTIPSecTools Tests\NPSKickstart.TroubleshootingMenuRework.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for the NPS Manager troubleshooting screen rework, 2026-09-03, per the maintainer (second tech
    feedback batch, item 6): "We need to streamline the NPS Manager troubleshooting screen. Also
    need to add a service restart option to it." First clarified via AskUserQuestion into a T1
    (flat/streamlined) vs T2 (categorized submenus, condensed descriptions) live A/B comparison; the maintainer
    then picked a specific direction later the same day - see
    Tests\NPSKickstart.TroubleshootingDashboardDirect.Tests.ps1 for that follow-up (categories directly
    hittable from the main dashboard as "6a"-"6e", full verbose descriptions restored, option numbers
    colorized) which superseded the T1/T2 split entirely. This file's own ActionId<->switch-case
    cross-consistency checks stay valid regardless of menu presentation and are still exercised here.

.DESCRIPTION
    The original single flat 18-option `Invoke-TroubleshootingMenu` (NPS-Manager.ps1) was refactored
    into `Invoke-TroubleshootingAction` (the actual work, keyed by a stable ActionId string instead of
    a raw menu number) and `Get-NPSTroubleshootingActions` (one shared ordered action list - label/
    category/ActionId - every menu presentation renders from, T1/T2 at the time this file was written,
    the dashboard-direct rework now). A new standalone `Invoke-NPSServiceRestartAction`
    (Modules\NPSTroubleshooting.ps1) backs the new restart option.

    NPS-Manager.ps1 is NOT safe to dot-source whole - it ends in a literal top-level
    ":MainMenu while ($true) { ... }" interactive loop that would start running immediately. Every
    function tested here is extracted individually via Get-FunctionSource, same convention already
    established elsewhere in this repo's tests.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$NPSModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$KickstartPath        = "$NPSModuleRoot\Tests\Legacy\_NPS-Manager.combined.ps1"
$NPSTroubleshootingPath = "$NPSModuleRoot\Private\NPSTroubleshooting.ps1"

Test-ScriptParses -Path $KickstartPath -Because "NPS-Manager.ps1 parses cleanly after the troubleshooting menu rework"
Test-ScriptParses -Path $NPSTroubleshootingPath -Because "NPSTroubleshooting.ps1 parses cleanly after the new Invoke-NPSServiceRestartAction"

# ===========================================================================
# Get-NPSTroubleshootingActions - the shared action list both T1 and T2 render from
# ===========================================================================
$GetActionsSrc = Get-FunctionSource -Path $KickstartPath -FunctionName "Get-NPSTroubleshootingActions"
Invoke-Expression $GetActionsSrc
$actions = @(Get-NPSTroubleshootingActions)

Assert-Equal -Actual $actions.Count -Expected 20 -Because "18 original actions + RestartService + ForceIASConfigWrite (item 7, added later the same day) = 20 total"
$actionIds = @($actions | ForEach-Object { $_.ActionId })
Assert-Equal -Actual ($actionIds | Select-Object -Unique).Count -Expected 20 -Because "Every ActionId is unique - no accidental duplicates from the extraction"

$restartAction = $actions | Where-Object { $_.ActionId -eq 'RestartService' }
Assert-True -Condition ($null -ne $restartAction) -Because "THE ACTUAL NEW FEATURE: a RestartService action exists"
Assert-Equal -Actual $restartAction.Category -Expected 'Troubleshooters / Debugging' -Because "Placed in the existing Troubleshooters/Debugging category, per the maintainer's own answer - not a new category, not appended at the end"

$adCredsAction = $actions | Where-Object { $_.ActionId -eq 'ADCredsToggle' }
Assert-Equal -Actual $adCredsAction.Category -Expected 'Settings' -Because "Incidental fix while categorizing for real (T2): the AD-credentials toggle used to be filed under 'Backup / Restore NPS Configuration' purely because it happened to print right after option 9 in the old flat list - it gets its own honest category now"

$categories = @($actions | Select-Object -ExpandProperty Category -Unique)
Assert-Equal -Actual $categories.Count -Expected 5 -Because "5 real categories: Troubleshooters/Debugging, Prerequisites/Script Troubleshooters, Backup/Restore, Settings, AD/Hardening Diagnostics"
Assert-Contains -Haystack ($categories -join ',') -Needle 'Troubleshooters / Debugging' -Because "Category exists"
Assert-Contains -Haystack ($categories -join ',') -Needle 'AD / Hardening Diagnostics' -Because "Category exists"

# ===========================================================================
# Consistency: EVERY ActionId in the shared list has a matching case in Invoke-TroubleshootingAction,
# and vice versa - the two are independently-maintained (a plain data array vs a switch statement), so
# nothing enforces this at the language level. A drift here means an action shows up in the menu but
# silently does nothing (falls to the switch's default case) - exactly the kind of bug this test exists
# to catch before it ships.
# ===========================================================================
$ActionRegionSrc = Get-FunctionSource -Path $KickstartPath -FunctionName "Invoke-TroubleshootingAction"
$switchCaseIds = @([regex]::Matches($ActionRegionSrc, "(?m)^\s{8}'([A-Za-z0-9]+)'\s*\{") | ForEach-Object { $_.Groups[1].Value })

Assert-Equal -Actual $switchCaseIds.Count -Expected 20 -Because "Invoke-TroubleshootingAction has exactly 20 real (non-default) case labels, matching the 20 actions in the shared list"
foreach ($id in $actionIds) {
    Assert-Contains -Haystack ($switchCaseIds -join ',') -Needle $id -Because "ActionId '$id' from the shared action list has a matching case in Invoke-TroubleshootingAction - not silently falling through to the default 'Invalid selection' case"
}
foreach ($caseId in $switchCaseIds) {
    Assert-Contains -Haystack ($actionIds -join ',') -Needle $caseId -Because "Case '$caseId' in Invoke-TroubleshootingAction has a matching entry in the shared action list - no orphaned/unreachable case"
}

# ===========================================================================
# Invoke-NPSServiceRestartAction (Modules\NPSTroubleshooting.ps1) - THE NEW restart option's own logic
# ===========================================================================
$RestartActionSrc = Get-FunctionSource -Path $NPSTroubleshootingPath -FunctionName "Invoke-NPSServiceRestartAction"

function Invoke-RestartActionTest {
    param(
        [string[]]$Responses,
        [string]$ServiceStatus = "Running",
        [bool]$GetServiceThrows = $false,
        [bool]$RestartServiceThrows = $false
    )
    $script:__RestartServiceCalled = $false
    function global:Get-Service {
        param($Name)
        if ($GetServiceThrows) { throw "Service not found" }
        return [pscustomobject]@{ Status = $ServiceStatus }
    }
    function global:Restart-Service {
        param($Name, [switch]$Force)
        $script:__RestartServiceCalled = $true
        if ($RestartServiceThrows) { throw "Access denied" }
    }
    Invoke-Expression $RestartActionSrc
    Use-QueuedReadHost -Responses $Responses
    $output = Invoke-NPSServiceRestartAction *>&1 | Out-String
    Restore-RealReadHost
    Remove-Item -Path function:global:Get-Service -ErrorAction SilentlyContinue
    Remove-Item -Path function:global:Restart-Service -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Output = $output; RestartServiceCalled = $script:__RestartServiceCalled }
}

$restartYesResult = Invoke-RestartActionTest -Responses @("Y")
Assert-True -Condition $restartYesResult.RestartServiceCalled -Because "Answering Y actually calls Restart-Service"
Assert-Contains -Haystack $restartYesResult.Output -Needle "Service restarted" -Because "Success message shown after a Y confirm"

$restartNoResult = Invoke-RestartActionTest -Responses @("N")
Assert-False -Condition $restartNoResult.RestartServiceCalled -Because "Answering N does NOT call Restart-Service - never silent about a service restart"
Assert-Contains -Haystack $restartNoResult.Output -Needle "Cancelled" -Because "Explicit cancellation message shown"

$restartGetServiceFailResult = Invoke-RestartActionTest -Responses @() -GetServiceThrows $true
Assert-False -Condition $restartGetServiceFailResult.RestartServiceCalled -Because "If the service can't even be queried, it never even reaches the confirm prompt (no responses needed/queued) - fails safe"
Assert-Contains -Haystack $restartGetServiceFailResult.Output -Needle "Could not query the service" -Because "Clear error message when Get-Service itself fails"

$restartServiceFailResult = Invoke-RestartActionTest -Responses @("Y") -RestartServiceThrows $true
Assert-Contains -Haystack $restartServiceFailResult.Output -Needle "ERROR restarting service" -Because "A Restart-Service failure is caught and reported, not left as an unhandled exception"

# ===========================================================================
# Cross-file: the restart action calls the real IAS service name, matching this module's own
# already-verified convention (see Invoke-ToggleNPSExtensionRegistry's own doc comment - "IAS" not
# "NPS", verified via web search, not guessed)
# ===========================================================================
$rawNPSTroubleshooting = Get-Content -Path $NPSTroubleshootingPath -Raw
Assert-Match -Actual $rawNPSTroubleshooting -Pattern "Restart-Service -Name IAS -Force" -Because "Invoke-NPSServiceRestartAction uses the same real service name/cmdlet shape as every other restart call site in this module"

Write-TestSummary -Suite "NPS Kickstart Troubleshooting Menu Rework (2026-09-03)"
