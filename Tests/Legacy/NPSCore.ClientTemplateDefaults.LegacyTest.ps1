# Ported from NSP-FGTIPSecTools Tests\NPSCore.ClientTemplateDefaults.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for the 2026-08-27 NPS Client Template default change (the maintainer: "the default template should
    include the 'Requires message authenticator' item checked").

.DESCRIPTION
    New-NPSClientTemplate's own -RequireSignature parameter default flipped from $false to $true (was
    silently unchecked for every new template, since Invoke-AddClientTemplate in NPS-Manager.ps1
    didn't ask about it at all before this change). Covers: the function's own default actually
    produces Require_Signature=1 in the generated XML fragment when the caller doesn't pass
    -RequireSignature at all (the exact shape the OLD Invoke-AddClientTemplate call site used), an
    explicit -RequireSignature:$false override still works (not hardcoded true), and
    Invoke-AddClientTemplate's own new prompt defaults to Yes/checked the same way its existing
    "Enabled?" prompt already defaults to Yes.

    NPSCore.ps1 has no top-level executable code (script-scoped variable init only, confirmed via AST)
    - safe to dot-source directly. New-NPSClientTemplate is exercised with -WhatIf against a small
    synthetic iastemplates.xml fixture (self-closing "<Children/>" RADIUS_Clients_Templates container -
    the real "fresh/empty container" shape this module's own Add-NPSChildFragmentToRawContent doc
    comment describes hitting live on a fresh NPS server) so nothing is actually written to disk.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$NPSModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$NPSCorePath = "$NPSModuleRoot\Private\NPSCore.ps1"
$KickstartPath = "$NPSModuleRoot\Tests\Legacy\_NPS-Manager.combined.ps1"

Test-ScriptParses -Path $NPSCorePath -Because "NPSCore.ps1 parses cleanly after the RequireSignature default change"
Test-ScriptParses -Path $KickstartPath -Because "NPS-Manager.ps1 parses cleanly after Invoke-AddClientTemplate's new prompt"

. $NPSCorePath

$tmpTemplatesPath = Join-Path ([System.IO.Path]::GetTempPath()) "iastemplates_ClientTemplateDefaults_Test_$([guid]::NewGuid().ToString('N')).xml"
$fixtureXml = @'
<?xml version="1.0"?>
<Root>
  <Microsoft_Internet_Authentication_Service_Templates name="Microsoft_Internet_Authentication_Service_Templates">
    <Children>
      <RADIUS_Clients_Templates name="RADIUS_Clients_Templates">
        <Children/>
      </RADIUS_Clients_Templates>
    </Children>
  </Microsoft_Internet_Authentication_Service_Templates>
</Root>
'@
Set-Content -Path $tmpTemplatesPath -Value $fixtureXml -Encoding UTF8

try {
    # --- Default (no -RequireSignature passed at all) - the exact shape the OLD Invoke-AddClientTemplate
    # call site used, and still what any OTHER future caller gets if it doesn't override it. ---
    $defaultResult = New-NPSClientTemplate -Path $tmpTemplatesPath -Name "TestTemplateDefault" -IPAddress "10.0.0.1" -SharedSecret "s3cr3t" -WhatIf
    Assert-Contains -Haystack $defaultResult.Fragment -Needle '<Require_Signature xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="boolean">1</Require_Signature>' `
        -Because "New-NPSClientTemplate's own default (no -RequireSignature passed) now produces Require_Signature=1 (checked) - was 0 (unchecked) before this change"

    # --- Explicit override still works - the default flip didn't hardcode the value. ---
    $overrideResult = New-NPSClientTemplate -Path $tmpTemplatesPath -Name "TestTemplateOverride" -IPAddress "10.0.0.2" -SharedSecret "s3cr3t" -RequireSignature:$false -WhatIf
    Assert-Contains -Haystack $overrideResult.Fragment -Needle '<Require_Signature xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="boolean">0</Require_Signature>' `
        -Because "Explicitly passing -RequireSignature:`$false still produces Require_Signature=0 - the new default is a default, not a hardcoded value"

    $explicitTrueResult = New-NPSClientTemplate -Path $tmpTemplatesPath -Name "TestTemplateExplicitTrue" -IPAddress "10.0.0.3" -SharedSecret "s3cr3t" -RequireSignature:$true -WhatIf
    Assert-Contains -Haystack $explicitTrueResult.Fragment -Needle '<Require_Signature xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="boolean">1</Require_Signature>' `
        -Because "Explicitly passing -RequireSignature:`$true also still works"
} finally {
    Remove-Item -Path $tmpTemplatesPath -Force -ErrorAction SilentlyContinue
}

# --- Invoke-AddClientTemplate's new prompt - AST-checked (it's an interactive wizard function with its
# own Read-Host calls and Write-NPSHeader/other dependencies not worth standing up a full mock for here;
# the [Enter for Yes] shape/wording is what's actually being verified, matching the existing Enabled?
# prompt's own established convention). ---
$AddClientTemplateSrc = Get-FunctionSource -Path $KickstartPath -FunctionName "Invoke-AddClientTemplate"
# NOTE: -Needle deliberately avoids literal '[' ']' - Assert-Contains's -like comparison treats them as
# wildcard character-class syntax, not literal brackets (found while writing this very test).
Assert-Contains -Haystack $AddClientTemplateSrc -Needle 'Require message authenticator in every request?' `
    -Because "Invoke-AddClientTemplate now explicitly asks about Require Signature, defaulting to Yes/checked, same [Enter for Yes] wording Enabled? already uses"
Assert-Match -Actual $AddClientTemplateSrc -Pattern 'RequireSignature\s*=\s*\$requireSig' `
    -Because "The captured response is actually threaded into New-NPSClientTemplate's \$params, not just asked and discarded"

Write-TestSummary -Suite "NPSCore Client Template Defaults (RequireSignature)"
