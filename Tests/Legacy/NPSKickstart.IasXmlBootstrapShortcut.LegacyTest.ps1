# Ported from NSP-FGTIPSecTools Tests\NPSKickstart.IasXmlBootstrapShortcut.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for item 7 of the maintainer's 2026-09-03 second-tech-feedback punch list ("ias.xml chicken/egg,
    take 2"): "ran into the NPS bug where a brand new install doesn't have an ias.xml. Seems that it's
    completely synthesized until you add SOMETHING to the config via the GUI. We need a way to
    shortcut this."

.DESCRIPTION
    This goes beyond the earlier project_nps_iasxml_chickenegg fix (which made Option 1 start the IAS
    service so ias.xml gets created at all) - starting the service alone isn't always enough. The new
    shortcut is `Initialize-IASConfigFile` (Modules\NPSCore.ps1), which points `netsh nps export`
    straight at the LIVE ias.xml path itself - forcing IAS to flush its current (still-default) config
    to disk, the same practical effect as a GUI edit, without needing one - wrapped by a confirm-then-
    run prompt `Invoke-IASConfigBootstrapPrompt` (Modules\NPSTroubleshooting.ps1) that both
    Invoke-InstallAuthorizeNPS (Option 1) and a new standalone Troubleshooting action
    ('ForceIASConfigWrite') call.

    NPS-Manager.ps1 is NOT safe to dot-source whole - it ends in a literal top-level
    ":MainMenu while ($true) { ... }" interactive loop. Every function tested here is extracted
    individually via Get-FunctionSource, same convention as this repo's other tests.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$NPSModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$KickstartPath          = "$NPSModuleRoot\Tests\Legacy\_NPS-Manager.combined.ps1"
$NPSCorePath            = "$NPSModuleRoot\Private\NPSCore.ps1"
$NPSTroubleshootingPath = "$NPSModuleRoot\Private\NPSTroubleshooting.ps1"

Test-ScriptParses -Path $KickstartPath -Because "NPS-Manager.ps1 parses cleanly after wiring in the ias.xml bootstrap shortcut"
Test-ScriptParses -Path $NPSCorePath -Because "NPSCore.ps1 parses cleanly after the new Initialize-IASConfigFile"
Test-ScriptParses -Path $NPSTroubleshootingPath -Because "NPSTroubleshooting.ps1 parses cleanly after the new Invoke-IASConfigBootstrapPrompt"

$ScratchDir = Join-Path $env:TEMP "IasXmlBootstrapTests_$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $ScratchDir -Force | Out-Null

# ===========================================================================
# Initialize-IASConfigFile (NPSCore.ps1) - the actual netsh-export-onto-the-live-path trick
# ===========================================================================
$InitSrc = Get-FunctionSource -Path $NPSCorePath -FunctionName "Initialize-IASConfigFile"
Invoke-Expression $InitSrc

# -WhatIf: no execution, just the command preview - never touches the filesystem
$whatIfTarget = Join-Path $ScratchDir "whatif_ias.xml"
$preview = Initialize-IASConfigFile -IASConfigPath $whatIfTarget -WhatIf
$expectedCmd = "netsh nps export filename=`"$whatIfTarget`" exportPSK=YES"
$expectedCmdPattern = [regex]::Escape($expectedCmd)
Assert-Match -Actual $preview.WouldRun -Pattern $expectedCmdPattern -Because "-WhatIf previews the real netsh command, quoted path included, same convention as Register-NPSServerInAD"
Assert-False -Condition (Test-Path $whatIfTarget) -Because "-WhatIf never actually runs anything"

function global:cmd {
    # Overrides the external cmd.exe for the scope of this test file - same 'function shadows a
    # same-named external command' mechanism already documented for the cls/Clear-Host gotcha
    # elsewhere in this repo's test conventions.
    $script:__CmdInvoked = $true
    $global:LASTEXITCODE = $script:__MockExitCode
    if ($script:__MockCreatesFile -and $script:__MockTargetPath) {
        Set-Content -Path $script:__MockTargetPath -Value "<Root></Root>" -NoNewline
    }
    return $script:__MockOutputLines
}

# Success path: mocked netsh "writes" the file and exits 0
$successTarget = Join-Path $ScratchDir "nested\success_ias.xml"
$script:__CmdInvoked = $false
$script:__MockExitCode = 0
$script:__MockCreatesFile = $true
$script:__MockTargetPath = $successTarget
$script:__MockOutputLines = @("Ok.")
$successResult = Initialize-IASConfigFile -IASConfigPath $successTarget
Assert-True -Condition $script:__CmdInvoked -Because "Without -WhatIf, the netsh command actually runs"
Assert-True -Condition (Test-Path (Split-Path -Path $successTarget -Parent)) -Because "The parent directory (C:\Windows\System32\ias\ equivalent) is created first if missing - a truly fresh box may not have it yet"
Assert-True -Condition $successResult.Succeeded -Because "Exit code 0 AND the file now existing together mean success"
Assert-Equal -Actual $successResult.ExitCode -Expected 0 -Because "Reports the real exit code"

# Failure path: netsh runs but never actually produces the file (non-zero exit)
$failTarget = Join-Path $ScratchDir "fail_ias.xml"
$script:__CmdInvoked = $false
$script:__MockExitCode = 1
$script:__MockCreatesFile = $false
$script:__MockTargetPath = $failTarget
$script:__MockOutputLines = @("The following command was not found: nps export.")
$failResult = Initialize-IASConfigFile -IASConfigPath $failTarget
Assert-False -Condition $failResult.Succeeded -Because "A non-zero exit code (or a still-missing file) must never be reported as success"
Assert-Contains -Haystack $failResult.Output -Needle "not found" -Because "The real netsh output is preserved for the caller to display, not swallowed"

# Done exercising the REAL Initialize-IASConfigFile - remove it from this script's own scope before
# the next section, which needs to mock it. Command-name resolution in PowerShell walks the CALLER's
# scope chain (not the function's own lexical definition site), so a same-named function left sitting
# in THIS script's scope can shadow a `function global:...` mock defined several calls deeper - caught
# live via a real cross-context flakiness (passed running this file alone via `pwsh -File`, failed when
# invoked via `&` from inside another script/session, e.g. a full-suite test runner) rather than assumed.
Remove-Item -Path function:Initialize-IASConfigFile -ErrorAction SilentlyContinue

Remove-Item -Path function:global:cmd -ErrorAction SilentlyContinue

# ===========================================================================
# Invoke-IASConfigBootstrapPrompt (NPSTroubleshooting.ps1) - confirm-then-run wrapper, shared by both
# Invoke-InstallAuthorizeNPS (Option 1) and the new standalone Troubleshooting action
# ===========================================================================
$PromptSrc = Get-FunctionSource -Path $NPSTroubleshootingPath -FunctionName "Invoke-IASConfigBootstrapPrompt"

function Invoke-BootstrapPromptTest {
    param(
        [string[]]$Responses,
        [bool]$FileAlreadyExists = $false,
        [bool]$MockSucceeded = $true,
        [bool]$MockThrows = $false
    )
    $target = Join-Path $ScratchDir "prompt_test_$([guid]::NewGuid().ToString('N')).xml"
    if ($FileAlreadyExists) { Set-Content -Path $target -Value "<Root></Root>" -NoNewline }

    $script:__InitCalled = $false
    $script:__InitCalledForReal = $false
    function global:Initialize-IASConfigFile {
        param([string]$IASConfigPath, [switch]$WhatIf)
        $script:__InitCalled = $true
        if ($WhatIf) { return [pscustomobject]@{ WouldRun = "netsh nps export filename=`"$IASConfigPath`" exportPSK=YES" } }
        $script:__InitCalledForReal = $true
        if ($MockThrows) { throw "mock netsh failure" }
        return [pscustomobject]@{ Command = "mock"; Output = "mock output"; ExitCode = $(if ($MockSucceeded) { 0 } else { 7 }); Succeeded = $MockSucceeded }
    }

    Invoke-Expression $PromptSrc
    Use-QueuedReadHost -Responses $Responses
    $output = Invoke-IASConfigBootstrapPrompt -IASConfigPath $target *>&1 | Out-String
    Restore-RealReadHost
    Remove-Item -Path function:global:Initialize-IASConfigFile -ErrorAction SilentlyContinue

    return [pscustomobject]@{ Output = $output; InitCalled = $script:__InitCalled; InitCalledForReal = $script:__InitCalledForReal }
}

$alreadyExistsResult = Invoke-BootstrapPromptTest -Responses @() -FileAlreadyExists $true
Assert-False -Condition $alreadyExistsResult.InitCalled -Because "If ias.xml already exists, Initialize-IASConfigFile is never even previewed - this is purely a 'make the file exist' helper, never re-run once it's there"
Assert-Contains -Haystack $alreadyExistsResult.Output -Needle "already exists" -Because "Clear message when there's genuinely nothing to do"

$cancelResult = Invoke-BootstrapPromptTest -Responses @("N")
Assert-True -Condition $cancelResult.InitCalled -Because "The -WhatIf preview still runs (shown to the tech before asking) even on a cancel"
Assert-False -Condition $cancelResult.InitCalledForReal -Because "Answering N must NEVER actually run the real (non-WhatIf) netsh call - never silent about forcing a config write"
Assert-Contains -Haystack $cancelResult.Output -Needle "Cancelled" -Because "Explicit cancellation message, same convention as Invoke-NPSServiceRestartAction"

$successResultPrompt = Invoke-BootstrapPromptTest -Responses @("Y") -MockSucceeded $true
Assert-True -Condition $successResultPrompt.InitCalledForReal -Because "Answering Y actually runs the real (non-WhatIf) call"
Assert-Contains -Haystack $successResultPrompt.Output -Needle "now exists" -Because "Success message shown after a Y confirm that actually succeeded"

$failResultPrompt = Invoke-BootstrapPromptTest -Responses @("Y") -MockSucceeded $false
Assert-Contains -Haystack $failResultPrompt.Output -Needle "exit code 7" -Because "A netsh failure surfaces its real exit code to the tech, not a generic error"

$throwResultPrompt = Invoke-BootstrapPromptTest -Responses @("Y") -MockThrows $true
Assert-Contains -Haystack $throwResultPrompt.Output -Needle "ERROR forcing the ias.xml write" -Because "An unhandled exception from the real call is caught and reported, not left as a crash"

# ===========================================================================
# Get-NPSTroubleshootingActions / Invoke-TroubleshootingAction - the new ForceIASConfigWrite action
# is correctly registered and dispatches to Invoke-IASConfigBootstrapPrompt, same ActionId-keyed
# dispatcher pattern item 6 established (Tests\NPSKickstart.TroubleshootingMenuRework.Tests.ps1
# already re-verifies the full 20-action ActionId<->switch-case cross-consistency; this just confirms
# THIS specific new action landed where item 7 needs it)
# ===========================================================================
$GetActionsSrc = Get-FunctionSource -Path $KickstartPath -FunctionName "Get-NPSTroubleshootingActions"
Invoke-Expression $GetActionsSrc
$actions = @(Get-NPSTroubleshootingActions)
$iasAction = $actions | Where-Object { $_.ActionId -eq 'ForceIASConfigWrite' }
Assert-True -Condition ($null -ne $iasAction) -Because "THE ACTUAL NEW FEATURE (item 7): a ForceIASConfigWrite action exists"
Assert-Equal -Actual $iasAction.Category -Expected 'Troubleshooters / Debugging' -Because "Placed in the same category as item 6's RestartService - a fresh-install fix a tech would reasonably look for alongside 'restart the service'"

$ActionRegionSrc = Get-FunctionSource -Path $KickstartPath -FunctionName "Invoke-TroubleshootingAction"
Assert-Match -Actual $ActionRegionSrc -Pattern "'ForceIASConfigWrite'\s*\{" -Because "Invoke-TroubleshootingAction has a real case for ForceIASConfigWrite, not silently falling to the default 'Invalid selection' case"
Assert-Match -Actual $ActionRegionSrc -Pattern "Invoke-IASConfigBootstrapPrompt" -Because "The ForceIASConfigWrite case actually calls the new shared prompt wrapper, not a re-implementation"

# ===========================================================================
# Invoke-InstallAuthorizeNPS (Option 1) - both branches now call the shortcut instead of dead-ending
# ===========================================================================
$InstallAuthSrc = Get-FunctionSource -Path $KickstartPath -FunctionName "Invoke-InstallAuthorizeNPS"
Assert-Match -Actual $InstallAuthSrc -Pattern "Invoke-IASConfigBootstrapPrompt" -Because "Option 1 calls the new shortcut somewhere in its ias.xml section"
$bootstrapCallCount = [regex]::Matches($InstallAuthSrc, "Invoke-IASConfigBootstrapPrompt").Count
Assert-Equal -Actual $bootstrapCallCount -Expected 2 -Because "Both branches call it: the 'service already running but ias.xml still missing' branch, AND the 'just started the service but ias.xml still missing' branch - starting the service alone isn't reliably enough, per the maintainer"
Assert-NoMatch -Actual $InstallAuthSrc -Pattern "see Troubleshooting > option for a service that won't start correctly" -Because "The old dead-end message (just pointing at Troubleshooting with no actual fix offered) is gone, replaced by actually running the shortcut"

Remove-Item -Path $ScratchDir -Recurse -Force -ErrorAction SilentlyContinue

Write-TestSummary -Suite "NPS Kickstart ias.xml Bootstrap Shortcut (item 7, 2026-09-03)"
