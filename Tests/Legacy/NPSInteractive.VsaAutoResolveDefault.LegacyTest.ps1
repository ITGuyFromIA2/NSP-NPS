# Ported from NSP-FGTIPSecTools Tests\NPSInteractive.VsaAutoResolveDefault.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for three 2026-08-31 changes, all requested live by the maintainer while working through a client's real
    NPS Manager import:
    1. Get-VsaNamesForSide's "Auto-resolve nested AD group membership...?" prompt now defaults to Yes
       (blank/Enter auto-resolves; previously only an explicit Y did, and blank silently skipped
       straight to manual VSA entry).
    2. The three "existing policy sequence numbers" prompts (OrchestratorImport.ps1 x1,
       NPSInteractive.ps1 x2) now show each policy's NAME alongside its sequence number (via
       Get-NPSPolicySummary), not just a bare list of numbers - "can we show the list of policy names
       so we can pick the right one, similar to how it's shown on the first page of NPS Manager."
    3. Get-VsaNamesForSide's own candidate-selection prompt ("Include which as ... VSAs?") now defaults
       blank to ALL candidates (was blank=none/'A'=all) - "let's make this screen a 'blank for all,
       comma separated or n for none'". 'N' is the new explicit way to say none; 'A' still works too.

.DESCRIPTION
    Get-VsaNamesForSide is extracted via Get-FunctionSource (AST) rather than dot-sourcing all of
    NPSInteractive.ps1 - Test-RSATAvailable/Resolve-NestedADGroups are mocked (function-scoped, shadow
    the real ones for the extracted source's own calls) so this stays isolated from any real AD/RSAT
    dependency. The "show policy names" change is verified via source-text checks (Get-NPSPolicySummary
    now appears at all three call sites, in place of the old bare Get-NPSExistingSequences join) rather
    than a full functional run - those three call sites sit deep inside large, heavily-interactive
    functions not practical to exercise end-to-end here (same reasoning already documented in
    OrchestratorImport.PairADResolution.Tests.ps1 for a sibling fix in the same function).
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$NPSModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$NPSInteractivePath = "$NPSModuleRoot\Private\NPSInteractive.ps1"
$OrchestratorImportPath = "$NPSModuleRoot\Private\OrchestratorImport.ps1"

Test-ScriptParses -Path $NPSInteractivePath -Because "NPSInteractive.ps1 parses cleanly after the VSA auto-resolve default + policy-name-listing changes"
Test-ScriptParses -Path $OrchestratorImportPath -Because "OrchestratorImport.ps1 parses cleanly after the policy-name-listing change"

# ===========================================================================
# Get-VsaNamesForSide - auto-resolve now defaults to Yes
# ===========================================================================
$GetVsaNamesForSideSrc = Get-FunctionSource -Path $NPSInteractivePath -FunctionName "Get-VsaNamesForSide"

function Invoke-GetVsaNamesForSideTest {
    param([string[]]$RequiredNames)
    function Test-RSATAvailable { return $true }
    function Resolve-NestedADGroups { param($GroupName, $Server, $Credential) return @() }
    $ADServer = "dc1.test.local"
    $ADCredential = $null
    $ShimPath = $null
    Invoke-Expression $GetVsaNamesForSideSrc
    return Get-VsaNamesForSide -SideLabel "IPSec" -RequiredNames $RequiredNames -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath
}

Use-QueuedReadHost -Responses @("", "A")   # blank = default (now Yes) -> auto-resolve; "A" = include all candidates found
$blankResult = Invoke-GetVsaNamesForSideTest -RequiredNames @("IKEv2_PSGI_Users")
Assert-Contains -Haystack ($blankResult -join ',') -Needle "ikev2_psgi_users" -Because "Blank response to the auto-resolve prompt now defaults to Yes - the required group itself (lowercased) ends up as a VSA candidate, selected via 'A'"

Use-QueuedReadHost -Responses @("N", "manual_vsa_1, manual_vsa_2")
$explicitNoResult = Invoke-GetVsaNamesForSideTest -RequiredNames @("IKEv2_PSGI_Users")
Assert-Equal -Actual ($explicitNoResult -join ',') -Expected "manual_vsa_1,manual_vsa_2" -Because "An explicit N still skips straight to manual VSA entry, unchanged"

Use-QueuedReadHost -Responses @("Y", "A")
$explicitYesResult = Invoke-GetVsaNamesForSideTest -RequiredNames @("IKEv2_Audit_Users")
Assert-Contains -Haystack ($explicitYesResult -join ',') -Needle "ikev2_audit_users" -Because "An explicit Y still works exactly as before"

# --- Candidate-selection prompt ("Include which as ... VSAs?") - blank now means ALL, 'N' means none ---
Use-QueuedReadHost -Responses @("Y", "")   # auto-resolve Yes, then blank at the selection prompt
$selectionBlankResult = Invoke-GetVsaNamesForSideTest -RequiredNames @("IKEv2_PSGI_Users")
Assert-Contains -Haystack ($selectionBlankResult -join ',') -Needle "ikev2_psgi_users" -Because "Blank at the selection prompt now means ALL candidates (was 'none') - the required group itself is still a candidate, so it's included"

Use-QueuedReadHost -Responses @("Y", "N", "")   # auto-resolve Yes, explicit N at selection, then blank at the manual-entry fallback (selecting none falls through to it, same as before)
$selectionNoneResult = Invoke-GetVsaNamesForSideTest -RequiredNames @("IKEv2_PSGI_Users")
Assert-Equal -Actual $selectionNoneResult.Count -Expected 0 -Because "'N' is the new explicit way to select none at the candidate-selection prompt, since blank no longer means that"

Restore-RealReadHost

# ===========================================================================
# Policy sequence prompts now show Name alongside Sequence (Get-NPSPolicySummary)
# ===========================================================================
$OrchestratorImportRaw = Get-Content -Path $OrchestratorImportPath -Raw
$NPSInteractiveRaw     = Get-Content -Path $NPSInteractivePath -Raw

Assert-Match -Actual $OrchestratorImportRaw -Pattern 'Get-NPSPolicySummary -Path \$IASConfigPath -PolicyType NetworkPolicy' `
    -Because "OrchestratorImport.ps1's per-pair 'Policy Naming and Order' prompt now pulls the full policy summary (name + sequence), not just Get-NPSExistingSequences's bare number list"
Assert-Match -Actual $OrchestratorImportRaw -Pattern '"    \{0,3\}\. \{1\}\{2\}" -f \$p\.Sequence, \$p\.Name, \$stateTag' `
    -Because "Uses the SAME rendering NPS-Manager.ps1's own 'Current Network Policies' status view already uses, not a fourth independently-drifting copy"

# 3, not 2: Invoke-ReprocessNPSVsaWizard already had its own pre-existing, unrelated
# Get-NPSPolicySummary call (picking an EXISTING policy from a list) - the two NEW ones are the
# "Policy Order" insert-at-sequence prompts this fix targets.
$policySummaryOccurrences = ([regex]::Matches($NPSInteractiveRaw, 'Get-NPSPolicySummary -Path \$IASConfigPath -PolicyType NetworkPolicy')).Count
Assert-Equal -Actual $policySummaryOccurrences -Expected 3 -Because "Both of NPSInteractive.ps1's own 'Policy Order' prompts (the 2-side wizard and the single-rule wizard) were fixed, plus Invoke-ReprocessNPSVsaWizard's own pre-existing, unrelated usage"

Write-TestSummary -Suite "NPSInteractive VSA Auto-Resolve Default + Policy Name Listing"
