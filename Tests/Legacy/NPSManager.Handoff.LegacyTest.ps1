# Ported from NSP-FGTIPSecTools Tests\NPSManager.Handoff.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for NPS-Manager menu 7 (2026-09-30): the <Company>_NPSResponse.json hand-back to the
    Orchestrator - facts plus a copy of ias.xml with every secret removed.

    Repo convention (Tests\README.md) - NOT Pester. Modules\NPSHandoff.ps1 is dot-sourced whole, with
    NPSCore.ps1's Read-NPSConfig / Get-NPSConfigEncoding / Get-NPSClients AST-extracted, and run against
    an invented UTF-16 LE ias.xml (the live file's encoding) in a temp folder. Secrets are made-up
    markers, so a leak is a plain substring hit.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$NPSModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$NPSDir = $NPSModuleRoot
$HandoffPath = Join-Path $NPSDir 'Private\NPSHandoff.ps1'
$CorePath = Join-Path $NPSDir 'Private\NPSCore.ps1'
$ManagerPath = Join-Path $NPSDir 'Tests\Legacy\_NPS-Manager.combined.ps1'

Test-ScriptParses -Path $HandoffPath -Because "NPSHandoff.ps1 parses"
Test-ScriptParses -Path $ManagerPath -Because "NPS-Manager.ps1 parses with menu 7"

. $HandoffPath
foreach ($name in 'Get-NPSConfigEncoding', 'Read-NPSConfig', 'Get-NPSClients') {
    Invoke-Expression (Get-FunctionSource -Path $CorePath -FunctionName $name)
}

$dt = 'xmlns:dt="urn:schemas-microsoft-com:datatypes"'
function New-TestIasXml {
    # Two RADIUS clients (one a range, one disabled), a remote RADIUS server with auth/accounting
    # secrets, a schema-section container named like a secret (children, no text), an empty secret,
    # and a secret holding XML entities.
    @"
<?xml version="1.0"?>
<Root $dt>
<Children>
<Microsoft_Internet_Authentication_Service name="Microsoft_Internet_Authentication_Service">
<Children>
<Protocols name="Protocols"><Children><Microsoft_Radius_Protocol name="Microsoft_Radius_Protocol"><Children>
<Clients name="Clients"><Children>
<FortiGate name="FortiGate"><Properties>
<IP_Address $dt dt:dt="string">10.20.30.1</IP_Address>
<Radius_Client_Enabled $dt dt:dt="boolean">1</Radius_Client_Enabled>
<Shared_Secret $dt dt:dt="string">LEAKMARK-client-one</Shared_Secret>
</Properties></FortiGate>
<Branches name="Branches"><Properties>
<IP_Address $dt dt:dt="string">10.99.0.0/16</IP_Address>
<Radius_Client_Enabled $dt dt:dt="boolean">0</Radius_Client_Enabled>
<Shared_Secret $dt dt:dt="string">LEAKMARK-&amp;-&lt;two&gt;</Shared_Secret>
</Properties></Branches>
</Children></Clients>
</Children></Microsoft_Radius_Protocol></Children></Protocols>
<RadiusServerGroups name="RadiusServerGroups"><Children><Upstream name="Upstream"><Properties>
<Authentication_Secret $dt dt:dt="string">LEAKMARK-auth</Authentication_Secret>
<Accounting_Secret $dt dt:dt="string">LEAKMARK-acct</Accounting_Secret>
<Some_Password $dt dt:dt="string"></Some_Password>
</Properties></Upstream></Children></RadiusServerGroups>
</Children>
</Microsoft_Internet_Authentication_Service>
<SDO_Schema name="SDO_Schema"><Children>
<Accounting_Secret name="Accounting_Secret"><Properties><Alias dt:dt="int">1027</Alias></Properties></Accounting_Secret>
<Client_Secret_Template_Guid $dt dt:dt="string">{00000000-0000-0000-0000-000000000000}</Client_Secret_Template_Guid>
</Children></SDO_Schema>
</Children>
</Root>
"@ -replace "`r?`n", "`r`n"
}

# --- ConvertTo-NPSRedactedIasXml / Get-NPSUnredactedSecret (PURE) ------------------------------------
$raw = New-TestIasXml
$before = @(Get-NPSUnredactedSecret -RawContent $raw)
Assert-Equal -Actual $before.Count -Expected 4 -Because "two client secrets and the remote server's auth/accounting secrets are found (the empty one and the schema container are not)"
Assert-NoMatch -Actual ($before -join ' ') -Pattern 'LEAKMARK' -Because "the unredacted list names elements, never their values"
$red = ConvertTo-NPSRedactedIasXml -RawContent $raw
Assert-Equal -Actual $red.Count -Expected 4 -Because "four secrets are counted as removed"
Assert-NoMatch -Actual $red.Content -Pattern 'LEAKMARK' -Because "no secret value survives, entity-escaped ones included"
Assert-Equal -Actual @(Get-NPSUnredactedSecret -RawContent $red.Content).Count -Expected 0 -Because "the redacted content checks clean"
Assert-Match -Actual $red.Content -Pattern '<Shared_Secret [^>]*>&lt;redacted&gt;</Shared_Secret>' -Because "a removed secret reads <redacted>, not blank (blank would look like no secret)"
Assert-Match -Actual $red.Content -Pattern '<Some_Password [^>]*></Some_Password>' -Because "an empty secret stays empty"
Assert-Match -Actual $red.Content -Pattern '<Accounting_Secret name="Accounting_Secret"><Properties><Alias' -Because "the schema section's same-named container is untouched"
Assert-Match -Actual $red.Content -Pattern '\{00000000-0000-0000-0000-000000000000\}</Client_Secret_Template_Guid>' -Because "template GUIDs are not secrets"
Assert-Match -Actual $red.Content -Pattern '<IP_Address [^>]*>10\.20\.30\.1</IP_Address>' -Because "client addresses are kept"
$again = ConvertTo-NPSRedactedIasXml -RawContent $red.Content
Assert-Equal -Actual $again.Count -Expected 0 -Because "redacting twice removes nothing more"
Assert-Equal -Actual $again.Content -Expected $red.Content -Because "redaction is idempotent"
$ok = $true; try { [xml]$red.Content | Out-Null } catch { $ok = $false }
Assert-True -Condition $ok -Because "the redacted copy is still valid XML"

# --- New-NPSHandoffResponse + Write-NPSHandoffFile, against a UTF-16 LE file ---------------------------
$tmp = Join-Path $env:TEMP ("npshandoff_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $ias = Join-Path $tmp 'ias.xml'
    [IO.File]::WriteAllText($ias, $raw, [Text.Encoding]::Unicode)
    (Get-Item $ias).LastWriteTime = [datetime]'2026-09-29 14:15:16'
    $status = [pscustomobject]@{ NPSRoleInstalled = $true; ExtensionInstalled = $true; OverrideNumberMatching = 1; PolicyCount = 3; ConnectionRequestPolicyCount = 1 }
    $resp = New-NPSHandoffResponse -IASConfigPath $ias -Company 'Contoso, Ltd.' -Status $status -ExtensionVersion '1.2.2893.1' -ToolVersion '1.1.0' -Now ([datetime]'2026-09-30 10:00')

    Assert-Equal -Actual $resp.SchemaVersion -Expected 1 -Because "schema 1"
    Assert-Equal -Actual $resp.Company -Expected 'Contoso, Ltd.' -Because "the company is recorded as typed"
    Assert-Equal -Actual $resp.Generated -Expected '2026-09-30T10:00:00' -Because "Generated is sortable ISO time"
    Assert-Equal -Actual $resp.Nps.ExtensionVersion -Expected '1.2.2893.1' -Because "the extension version is carried"
    Assert-Equal -Actual $resp.Nps.NumberMatchingOverride -Expected '1' -Because "the number-matching override is carried"
    Assert-Equal -Actual $resp.Nps.NetworkPolicyCount -Expected 3 -Because "policy counts are carried"
    Assert-Equal -Actual (@($resp.RadiusClients | ForEach-Object { "$($_.Name)=$($_.Address)=$($_.Enabled)" }) -join ';') -Expected 'FortiGate=10.20.30.1=True;Branches=10.99.0.0/16=False' -Because "RADIUS clients: name, address, enabled"
    Assert-Equal -Actual (@($resp.RadiusClients[0].PSObject.Properties.Name) -join ',') -Expected 'Name,Address,Enabled' -Because "RADIUS client entries carry no secret field"
    Assert-Equal -Actual $resp.IasXml.SecretsRemoved -Expected 4 -Because "the secret count is recorded"
    Assert-Equal -Actual $resp.IasXml.LastWriteTime -Expected '2026-09-29T14:15:16' -Because "the live file's own time is recorded"

    [byte[]]$bytes = [Convert]::FromBase64String($resp.IasXml.ContentBase64)
    Assert-Equal -Actual ('{0:X2}{1:X2}' -f $bytes[0], $bytes[1]) -Expected 'FFFE' -Because "the copy keeps ias.xml's UTF-16 LE byte-order mark"
    $decoded = [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    Assert-Equal -Actual $decoded -Expected $red.Content -Because "the embedded copy is exactly the redacted content"

    $out = Join-Path $tmp 'Handoff'
    $path = Write-NPSHandoffFile -Response $resp -OutputDir $out
    Assert-Equal -Actual $path -Expected (Join-Path $out 'ContosoLtd_NPSResponse.json') -Because "the file is <stem>_NPSResponse.json, stem like CA-Manager's"
    $fileText = [IO.File]::ReadAllText($path)
    Assert-NoMatch -Actual $fileText -Pattern 'LEAKMARK' -Because "no secret appears in the hand-back file"
    Assert-NoMatch -Actual ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($fileText | ConvertFrom-Json).IasXml.ContentBase64))) -Pattern 'LEAKMARK' -Because "nor inside its embedded ias.xml"
    Assert-Equal -Actual ((Write-NPSHandoffFile -Response $resp -OutputDir $out)) -Expected $path -Because "re-running overwrites the same file"

    # A tampered response (hash mismatch) fails the read-back check and leaves no file behind.
    $bad = $resp | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $bad.IasXml.Sha256 = '00'
    $bad.Company = 'Tampered'
    $threw = $false
    try { Write-NPSHandoffFile -Response $bad -OutputDir $out | Out-Null } catch { $threw = $_.Exception.Message }
    Assert-Match -Actual "$threw" -Pattern 'does not match its hash' -Because "a copy that doesn't match its hash is refused"
    Assert-False -Condition (Test-Path (Join-Path $out 'Tampered_NPSResponse.json')) -Because "the refused file is deleted"

    # A secret smuggled past redaction fails the read-back check too.
    $leaky = $resp | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $leakBytes = [Text.Encoding]::Unicode.GetPreamble() + [Text.Encoding]::Unicode.GetBytes($raw)
    $leaky.IasXml.ContentBase64 = [Convert]::ToBase64String($leakBytes)
    $sha = [Security.Cryptography.SHA256]::Create(); $leaky.IasXml.Sha256 = ([BitConverter]::ToString($sha.ComputeHash([byte[]]$leakBytes)) -replace '-', ''); $sha.Dispose()
    $leaky.Company = 'Leaky'
    $threw = $false
    try { Write-NPSHandoffFile -Response $leaky -OutputDir $out | Out-Null } catch { $threw = $_.Exception.Message }
    Assert-Match -Actual "$threw" -Pattern 'secrets still present' -Because "a hand-back still holding a secret is refused"
    Assert-NoMatch -Actual "$threw" -Pattern 'LEAKMARK' -Because "the refusal names elements, not values"
    Assert-False -Condition (Test-Path (Join-Path $out 'Leaky_NPSResponse.json')) -Because "the leaky file is deleted"
} finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Dashboard wiring ----------------------------------------------------------------------------------
$rawManager = Get-Content -Path $ManagerPath -Raw
Assert-True -Condition (Test-Path "$NPSModuleRoot\Private\NPSHandoff.ps1") -Because "NSP.NPS: the hand-back module is a Private file the module loader dot-sources (was: NPS-Manager.ps1 dot-sourced it)"
Assert-Match -Actual $rawManager -Pattern 'Write-Host " Hand back to the Orchestrator' -Because "the dashboard lists menu 7"
Assert-Match -Actual $rawManager -Pattern "'\^7\`$'\s+\{ Invoke-NPSMenuHandoff -IASConfigPath \`$IASConfigPath -ScriptRoot \`$script:BaseDir -Status \`$status \}" -Because "7 runs the hand-back with the dashboard's status (NSP.NPS: ScriptRoot is the work folder's Answers\ via `$script:BaseDir)"
Assert-Match -Actual $rawManager -Pattern '\$script:NPSManagerVersion = Get-NSPNpsModuleVersion' -Because "NSP.NPS: the version is the module manifest's (was the 1.1.0 constant)"

Write-TestSummary -Suite "NPS-Manager - hand-back to the Orchestrator"
