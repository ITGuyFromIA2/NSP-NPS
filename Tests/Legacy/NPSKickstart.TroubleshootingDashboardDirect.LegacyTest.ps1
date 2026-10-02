# Ported from NSP-FGTIPSecTools Tests\NPSKickstart.TroubleshootingDashboardDirect.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for the follow-up troubleshooting-menu rework, 2026-09-03 (same day as item 6's original
    T1/T2 build, see Tests\NPSKickstart.TroubleshootingMenuRework.Tests.ps1), per the maintainer's live
    feedback after seeing both: "Can we maybe take the 'grouped' troubleshooting tools and make those
    categories directly hittable from the NPS Manager dashboard? Go back to the more verbose
    descriptions. Descriptions should always go on a new, indented line after the 'entry'... Can we
    colorize the numbers so they 'stand out' (maybe yellow)."

.DESCRIPTION
    Replaces the T1 (flat, condensed) / T2 (categorized submenus, condensed) A/B split entirely - no
    more "which style" prompt. Three pieces:
    - `Show-TroubleshootingCategoryLinks` - the "6a. Debugging   6b. Prerequisites..." quick-link row(s)
      now printed directly under the main dashboard's "6. Troubleshooting Tools" line, so a category is
      one keystroke from the dashboard itself instead of a separate picker screen.
    - `Invoke-TroubleshootingCategoryMenu -Category <string>` - one category's action list, reached
      directly via "6a"-"6e" at the main menu prompt. Full verbose format: label, then an indented
      "-detail" line below it (when Detail isn't empty), blank line between entries - the format from
      BEFORE the T1/T2 condensed rework, restored per the maintainer's explicit ask.
    - `Invoke-TroubleshootingMenu` - repurposed from "ask T1 vs T2" into the flat ALL-categories view,
      now reached via bare "6" (the "I don't know which category" catch-all) - same verbose format.

    All three colorize their option identifiers (Yellow) - the leading "1.", "6a.", "M." etc - via
    paired `Write-Host -NoNewline -ForegroundColor Yellow` + a second plain `Write-Host` for the rest of
    the line, since a single Write-Host call can't mix two colors on one line.

    NPS-Manager.ps1 is NOT safe to dot-source whole - it ends in a literal top-level
    ":MainMenu while ($true) { ... }" interactive loop. Every function tested here is extracted
    individually via Get-FunctionSource, same convention already established elsewhere in this repo's
    tests. `Write-NPSHeader` (Modules\NPSInteractive.ps1) is mocked, not extracted for real - it's a
    Clear-Host-based screen redraw, irrelevant to what's being verified here and actively unwanted in a
    non-interactive test run.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$NPSModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$KickstartPath = "$NPSModuleRoot\Tests\Legacy\_NPS-Manager.combined.ps1"

Test-ScriptParses -Path $KickstartPath -Because "NPS-Manager.ps1 parses cleanly after the troubleshooting-menu dashboard-direct rework"

function global:Write-NPSHeader { param([string]$Title) }

$GetActionsSrc = Get-FunctionSource -Path $KickstartPath -FunctionName "Get-NPSTroubleshootingActions"
$LinksSrc      = Get-FunctionSource -Path $KickstartPath -FunctionName "Show-TroubleshootingCategoryLinks"
$CatMenuSrc    = Get-FunctionSource -Path $KickstartPath -FunctionName "Invoke-TroubleshootingCategoryMenu"
$AllMenuSrc    = Get-FunctionSource -Path $KickstartPath -FunctionName "Invoke-TroubleshootingMenu"
Invoke-Expression $GetActionsSrc
Invoke-Expression $LinksSrc
Invoke-Expression $CatMenuSrc
Invoke-Expression $AllMenuSrc

$actions = @(Get-NPSTroubleshootingActions)
$expectedCategories = @($actions | Select-Object -ExpandProperty Category -Unique)

# ===========================================================================
# Show-TroubleshootingCategoryLinks - the dashboard's own "6a. ... 6b. ..." quick-link row(s)
# ===========================================================================
$linksOutput = Show-TroubleshootingCategoryLinks *>&1 | Out-String

for ($i = 0; $i -lt $expectedCategories.Count; $i++) {
    $letter = [string][char](97 + $i)
    Assert-Contains -Haystack $linksOutput -Needle "6$letter." -Because "Category #$($i+1) ('$($expectedCategories[$i])') gets letter '$letter', derived the same first-seen-order way the main menu's own 6<letter> dispatch derives it"
}
Assert-Contains -Haystack $linksOutput -Needle "Debugging" -Because "'Troubleshooters / Debugging' gets shortened to just 'Debugging' on the dashboard row - 'Troubleshooters' is redundant right under a 'Troubleshooting Tools' heading"
Assert-NoMatch -Actual $linksOutput -Pattern "Troubleshooters / Debugging" -Because "The FULL category name should NOT appear on the dashboard row itself - only the shortened form does (the full name is reserved for the category's own header once you're inside it)"
Assert-Contains -Haystack $linksOutput -Needle "AD / Hardening Diagnostics" -Because "Every OTHER category keeps its full name on the dashboard row - only Debugging is shortened"

# ===========================================================================
# Invoke-TroubleshootingCategoryMenu - one category, full verbose format, reached directly via 6<letter>
# ===========================================================================
Use-QueuedReadHost -Responses @("M")
$catOutput = Invoke-TroubleshootingCategoryMenu -Category 'Troubleshooters / Debugging' *>&1 | Out-String
Restore-RealReadHost

Assert-Contains -Haystack $catOutput -Needle "Download & run Microsoft's MFA_NPS_Troubleshooter" -Because "The category view lists that category's own actions"
Assert-Contains -Haystack $catOutput -Needle "-MFA prompts not reaching users" -Because "Verbose format restored: the detail text appears as its own indented '-detail' line, per the maintainer - 'Descriptions should always go on a new, indented line after the entry'"
Assert-NoMatch -Actual $catOutput -Pattern "MFA_NPS_Troubleshooter - MFA prompts" -Because "The condensed 'Label - Detail' single-line form (from the short-lived T1/T2 build) must be gone"
Assert-NoMatch -Actual $catOutput -Pattern "Back up ias.xml now" -Because "A DIFFERENT category's action (BackupIAS is 'Backup / Restore NPS Configuration') must not leak into the Troubleshooters/Debugging view"
Assert-Contains -Haystack $catOutput -Needle "M." -Because "Category view offers 'M' to return"
Assert-Contains -Haystack $catOutput -Needle "Return to main menu" -Because "Category view returns to the MAIN dashboard directly - there's no more intermediate 'categories' screen to go 'back' to. Checked as two separate Contains (not one spanning literal) because the 'M.' and the rest of the line are printed via two separate Write-Host calls to mix colors - pwsh can inject an ANSI reset between them in captured output, breaking a literal match that spans the boundary"
Assert-NoMatch -Actual $catOutput -Pattern "Back to categories" -Because "The old T2 'B. Back to categories' wording is gone - there's nothing to go back to anymore"

# Empty-Detail actions (BackupIAS etc.) never print a bare '-' detail line
Use-QueuedReadHost -Responses @("M")
$backupCatOutput = Invoke-TroubleshootingCategoryMenu -Category 'Backup / Restore NPS Configuration' *>&1 | Out-String
Restore-RealReadHost
Assert-NoMatch -Actual $backupCatOutput -Pattern "(?m)^\s+-\s*$" -Because "An action with empty Detail text (Back up ias.xml now, etc.) skips the detail line entirely rather than printing a bare, empty '-' line"

# ===========================================================================
# Invoke-TroubleshootingMenu - repurposed: flat, ALL categories, same verbose format, reached via
# bare "6" (was the T1-vs-T2 style picker before this rework)
# ===========================================================================
Use-QueuedReadHost -Responses @("M")
$allOutput = Invoke-TroubleshootingMenu *>&1 | Out-String
Restore-RealReadHost

Assert-Contains -Haystack $allOutput -Needle "Force the initial ias.xml write" -Because "The flat view covers every action across every category, not just one"
foreach ($cat in $expectedCategories) {
    Assert-Contains -Haystack $allOutput -Needle $cat -Because "Category header '$cat' still appears in the flat view (grouped, not interleaved)"
}
Assert-Contains -Haystack $allOutput -Needle "-Common first troubleshooting step" -Because "The flat view also uses the restored verbose 'indented -detail line' format, not the condensed one"
Assert-Match -Actual $allOutput -Pattern "(?m)^\s+\d+\." -Because "Uses plain running numbers (1, 2, 3...) across the whole list, same as before this rework - only the presentation format and detail-line placement changed"

# ===========================================================================
# Cross-file: no leftover references to the removed T1/T2/style-picker mechanism
# ===========================================================================
$rawKickstart = Get-Content -Path $KickstartPath -Raw
Assert-NoMatch -Actual $rawKickstart -Pattern "function Invoke-TroubleshootingMenuT1" -Because "The old T1-specific function is gone - merged into the repurposed Invoke-TroubleshootingMenu"
Assert-NoMatch -Actual $rawKickstart -Pattern "function Invoke-TroubleshootingMenuT2" -Because "The old T2-specific function is gone - its category-picker top level is obsolete (categories are picked AT the dashboard now) and its per-category rendering moved into Invoke-TroubleshootingCategoryMenu"
Assert-NoMatch -Actual $rawKickstart -Pattern "TroubleshootingMenuStyle" -Because "The session-remembered 'which style did the maintainer pick' state is gone - there's only one presentation now, no ask"

# ===========================================================================
# Main menu loop wiring: bare "6" and "6<letter>" are both dispatched, and the dashboard's option
# numbers (1-6, Q) are colorized
# ===========================================================================
Assert-Match -Actual $rawKickstart -Pattern "'\^6\$'\s*\{\s*Invoke-TroubleshootingMenu" -Because "Bare '6' still dispatches to the (now repurposed) flat all-categories view"
Assert-Match -Actual $rawKickstart -Pattern "'\^6\[A-Za-z\]\$'" -Because "A NEW switch case accepts '6<letter>' at the main menu prompt"
Assert-Match -Actual $rawKickstart -Pattern "Invoke-TroubleshootingCategoryMenu -Category \`$troubleshootCategories\[\`$letterIdx\]" -Because "The 6<letter> case actually resolves the letter to a category and opens that category's menu, not a re-implementation"
Assert-Match -Actual $rawKickstart -Pattern "Show-TroubleshootingCategoryLinks" -Because "The main menu loop calls the quick-links row so 6a-6e actually show up on the dashboard, not just work if you happen to know the letters"

$mainMenuNumberColorMatches = [regex]::Matches($rawKickstart, 'Write-Host\s+"\s*\d\."\s+-NoNewline\s+-ForegroundColor\s+Yellow')
Assert-True -Condition ($mainMenuNumberColorMatches.Count -ge 5) -Because "The main dashboard's own option numbers (1-5 at minimum; 6/Q use the same pattern) are colorized Yellow, per the maintainer - 'colorize the numbers so they stand out'"

Write-TestSummary -Suite "NPS Kickstart Troubleshooting Dashboard-Direct Rework (2026-09-03, follow-up)"
