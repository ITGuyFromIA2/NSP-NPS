# Ported from NSP-FGTIPSecTools Tests\OrchestratorImport.PairADResolution.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for Invoke-SingleNPSPairImport (OrchestratorImport.ps1) - covers both the 2026-08-31
    UserGroupName->UserGroupValue AD-resolution fix (real live bug, the maintainer, at a client: "Cannot find an
    object with identity: 'FGT_IKEv2_CorpLan_Users'") AND the same-day pair-import restructure that
    extracted the old inline per-pair loop into this function with its own back-navigable step
    sequence + progress dashboard (the maintainer: "show me all the things we're answering... highlight the
    one we're answering... allow us to go back and edit a messed up answer before import").

.DESCRIPTION
    Invoke-SingleNPSPairImport and its own Write-NPSPairImportProgress dependency are extracted via
    Get-FunctionSource (AST) rather than dot-sourcing all of OrchestratorImport.ps1. Every AD/NPS-side
    dependency (Resolve-NPSGroupInteractive, Read-ANDConditionGroups, Get-VsaNamesForSide,
    Get-NPSPolicySummary, Add-NPSPolicySet, Add-NPSSingleRule, Write-NPSHeader) is mocked function-
    scoped, recording what it was called with - this test cares about WHAT gets asked/passed, not
    real AD/NPS I/O. `cls` (Clear-Host) is also stubbed to a no-op - the real one can throw when this
    runs under a non-interactive host.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$NPSModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$OrchestratorImportPath = "$NPSModuleRoot\Private\OrchestratorImport.ps1"

Test-ScriptParses -Path $OrchestratorImportPath -Because "OrchestratorImport.ps1 parses cleanly after the pair-import restructure (picker + back-navigable per-pair steps + progress dashboard)"

$ProgressSrc = Get-FunctionSource -Path $OrchestratorImportPath -FunctionName "Write-NPSPairImportProgress"
$ImportSrc   = Get-FunctionSource -Path $OrchestratorImportPath -FunctionName "Invoke-SingleNPSPairImport"

function Invoke-SinglePairImportTest {
    param([pscustomobject]$Pair)

    # `cls` is an ALIAS to Clear-Host, and PowerShell resolves aliases ahead of same-named local
    # functions - shadowing "cls" itself here does nothing. Override the underlying Clear-Host
    # function instead (what the alias actually points to) - the real one can throw
    # "CursorPosition... handle is invalid" under this non-interactive test host.
    function Clear-Host {}
    function Write-NPSHeader { param($Text) }

    $script:__ResolveCalls = [System.Collections.Generic.List[string]]::new()
    function Resolve-NPSGroupInteractive {
        param([string]$GroupNameOrSID, [string]$ADServer, [System.Management.Automation.PSCredential]$ADCredential, [string]$ShimPath)
        $script:__ResolveCalls.Add($GroupNameOrSID)
        return [pscustomobject]@{ Resolved = $true; Name = $GroupNameOrSID; SID = "S-1-5-21-FAKE-$GroupNameOrSID"; ADServer = $ADServer; ADCredential = $ADCredential }
    }
    function Read-ANDConditionGroups {
        param([string]$SideLabel, [string]$ADServer, [System.Management.Automation.PSCredential]$ADCredential)
        return [pscustomobject]@{ SidSets = @(); RequiredNames = @() }
    }
    function Get-VsaNamesForSide {
        param([string]$SideLabel, [string[]]$RequiredNames, [string]$ADServer, [System.Management.Automation.PSCredential]$ADCredential, [string]$ShimPath)
        return @()
    }
    function Get-NPSPolicySummary {
        param([string]$Path, [string]$PolicyType)
        return @()
    }
    $script:__AddPolicySetCalls = 0
    $script:__AddSingleRuleCalls = 0
    function Add-NPSPolicySet {
        param($Path, $BaseName, $ClientIPAddress, $IPSecGroupSidSets, $SSLVPNGroupSidSets, $IPSecVsaGroupNames, $SSLVPNVsaGroupNames, $InsertAtSequence, [switch]$WhatIf)
        $script:__AddPolicySetCalls++
        return [pscustomobject]@{ ShiftedSequences = $false; BackupPath = "fake-backup" }
    }
    function Add-NPSSingleRule {
        param($Path, $DisplayName, $ClientIPAddress, $GroupSidSets, $VsaGroupNames, $InsertAtSequence, [switch]$WhatIf)
        $script:__AddSingleRuleCalls++
        return [pscustomobject]@{ ShiftedSequences = $false; BackupPath = "fake-backup" }
    }

    Invoke-Expression $ProgressSrc
    Invoke-Expression $ImportSrc

    $result = Invoke-SingleNPSPairImport -Pair $Pair -IASConfigPath "C:\fake\ias.xml" -ClientIPAddress "10.0.0.1" -ADServer "dc1.test.local" -ADCredential $null -ShimPath $null
    return [pscustomobject]@{
        Result           = $result
        ResolveCalls     = @($script:__ResolveCalls)
        AddPolicySetCalls  = $script:__AddPolicySetCalls
        AddSingleRuleCalls = $script:__AddSingleRuleCalls
    }
}

# ===========================================================================
# AD resolution uses UserGroupVALUE, not UserGroupName (2026-08-31 real bug)
# ===========================================================================
$nonTriplicatePair = [pscustomobject]@{
    Label = "Audit"; UserGroupName = "FGT_IKEv2_Audit_Users"; UserGroupValue = "ikev2_audit_users"
    UserGroupValueSSLVPN = ""; IsTriplicate = $false
}
Use-QueuedReadHost -Responses @("", "", "", "", "", "Y")   # Simul(default No), AddMore(No), IpsecVsa(continue), BaseName(default), Sequence(default), confirm Y
$straightResult = Invoke-SinglePairImportTest -Pair $nonTriplicatePair
Restore-RealReadHost

Assert-Contains -Haystack ($straightResult.ResolveCalls -join ',') -Needle "ikev2_audit_users" -Because "AD resolution uses UserGroupValue (the real AD group)"
Assert-NotContains -Haystack ($straightResult.ResolveCalls -join ',') -Needle "FGT_IKEv2_Audit_Users" -Because "REGRESSION GUARD: must never search AD for the FortiGate-side object name"
Assert-True -Condition $straightResult.Result.Completed -Because "A straightforward non-triplicate import, confirmed Y, completes"
Assert-Equal -Actual $straightResult.AddSingleRuleCalls -Expected 2 -Because "Non-triplicate pair calls Add-NPSSingleRule twice (WhatIf preview + real commit), never Add-NPSPolicySet"
Assert-Equal -Actual $straightResult.AddPolicySetCalls -Expected 0 -Because "Non-triplicate pair never calls the triplicate (3-policy) path"

# ===========================================================================
# Blank UserGroupValue skips before any AD resolution attempt
# ===========================================================================
$blankPair = [pscustomobject]@{ Label = "BlankVSA"; UserGroupName = "FGT_Something"; UserGroupValue = ""; UserGroupValueSSLVPN = ""; IsTriplicate = $false }
Use-QueuedReadHost -Responses @("")   # "Press Enter to continue" after the skip message
$blankResult = Invoke-SinglePairImportTest -Pair $blankPair
Restore-RealReadHost
Assert-False -Condition $blankResult.Result.Completed -Because "A pair with no captured AD group (UserGroupValue blank) is skipped, not imported"
Assert-Equal -Actual $blankResult.ResolveCalls.Count -Expected 0 -Because "No AD resolution is even attempted for a blank UserGroupValue"

# ===========================================================================
# Back navigation - stepping back into 'Simul' and changing the answer resets everything downstream,
# and the rest of the sequence completes cleanly afterward (2026-08-31 per the maintainer: "let's also allow
# us to go back and edit a messed up answer before import")
# ===========================================================================
$backNavPair = [pscustomobject]@{ Label = "BackNavTest"; UserGroupName = "FGT_BackNav"; UserGroupValue = "backnav_users"; UserGroupValueSSLVPN = ""; IsTriplicate = $null }
Use-QueuedReadHost -Responses @(
    "Y",    # Simul: Yes (triplicate)
    "B",    # AddMore: back up to Simul instead
    "N",    # Simul (re-asked): No (non-triplicate now) - resets AddMore/IpsecVsa/BaseName/Sequence
    "",     # AddMore: default No
    "",     # IpsecVsa: continue
    "",     # BaseName: default
    "",     # Sequence: default
    "N"     # confirm: decline (just proving the flow completes correctly end-to-end)
)
$backNavResult = Invoke-SinglePairImportTest -Pair $backNavPair
Restore-RealReadHost

Assert-False -Condition $backNavResult.Result.Completed -Because "Declining the final confirm after a back-navigation edit still returns Completed=false cleanly (no crash)"
Assert-Equal -Actual $backNavResult.AddSingleRuleCalls -Expected 1 -Because "After backing up and changing Simul from Yes to No, the pair ends up on the non-triplicate (single-rule) path - only the WhatIf preview call happens since confirm was declined"
Assert-Equal -Actual $backNavResult.AddPolicySetCalls -Expected 0 -Because "Confirms the back-navigation edit actually took effect - never took the triplicate path despite answering Yes first"

# ===========================================================================
# Pair picker (Invoke-ImportKickstartDefinitions itself) - source-text sanity checks only. That
# function is too large/deeply side-effecting (templates, live client, CRP, THEN the picker) to mock
# end-to-end here - same reasoning already documented for the AD-resolution fix before this restructure.
# ===========================================================================
$InvokeImportSrc = Get-FunctionSource -Path $OrchestratorImportPath -FunctionName "Invoke-ImportKickstartDefinitions"
Assert-Contains -Haystack $InvokeImportSrc -Needle "Enter a number to import that pair, A for all remaining, or Q to finish" `
    -Because "The pair picker (2026-08-31 per the maintainer: 'could we do a listing of the RADIUS group pairs and allow us to pick and choose') exists"
Assert-Contains -Haystack $InvokeImportSrc -Needle "importedThisSession" `
    -Because "Already-imported pairs are tracked session-local and excluded from the list, so it can 'drop back to the overall list (empty if already imported)'"
Assert-Contains -Haystack $InvokeImportSrc -Needle "Invoke-SingleNPSPairImport -Pair `$pairToImport" `
    -Because "The picker delegates each chosen pair to Invoke-SingleNPSPairImport rather than re-implementing the per-pair flow inline"

Write-TestSummary -Suite "OrchestratorImport Single Pair Import (AD resolution + back-navigable steps)"
