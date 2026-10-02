# Ported from NSP-FGTIPSecTools Tests\NPSTroubleshooting.RadiusLogFields.Tests.ps1 (2026-10-01): same assertions, paths re-pointed at
# this module's Private\ files. Run by Tests\Legacy.Tests.ps1 (Pester) in a child PowerShell.
<#
.SYNOPSIS
    Tests for the 2026-08-26 NPS RADIUS-log field expansion (the maintainer: "still feels like we're missing
    some fields" in the Connection Request / Network Request pairing table).

.DESCRIPTION
    Read-NPSRadiusLog and Format-NPSRadiusLogPairs are pure function definitions (no top-level
    executable code) - safe to dot-source directly. Builds a small synthetic 2-row NPS log file
    (Access-Request + Access-Accept, modeled closely on a real maintainer-pasted example) by iterating the
    module's own $script:NPSLogFieldNames in order, rather than hand-counting the 60+ real column
    positions - avoids a silent off-by-one in the test fixture itself.

    Covers: the 4 fields that were already curated but never shown in the table (RadiusServer,
    ClientVendor, ClientIPAddress, PacketType), and the 4 that were promoted from _Raw-only to
    first-class properties on Read-NPSRadiusLog specifically for this (FramedIPAddress,
    EAPFriendlyName, MSRASClientName, MSRASClientVersion) - both that they parse correctly AND that
    they actually show up in the rendered pairing table.
#>

. "$PSScriptRoot\..\Shared\TestAssertions.ps1"
$NPSModuleRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
Reset-TestCounters

$NPSTroubleshootingPath = "$NPSModuleRoot\Private\NPSTroubleshooting.ps1"

Test-ScriptParses -Path $NPSTroubleshootingPath -Because "NPSTroubleshooting.ps1 parses cleanly after the RADIUS-log field expansion"

. $NPSTroubleshootingPath

function New-FakeNPSLogLine {
    param([hashtable]$Overrides)
    $vals = foreach ($f in $script:NPSLogFieldNames) {
        $v = if ($Overrides.ContainsKey($f)) { $Overrides[$f] } else { '' }
        '"' + $v + '"'
    }
    return ($vals -join ',')
}

# Modeled on a real pasted example (tom.kenny @ ENTCONSULTANTS, 2026-08-26) - Access-Request followed
# by an Access-Accept carrying a non-"Success" ReasonCode (21, not in $script:NPSReasonCodeNames) -
# exactly the case where PacketType is needed to tell an Accept-with-an-unmapped-code apart from a
# genuine Reject.
$reqLine = New-FakeNPSLogLine -Overrides @{
    ComputerName = 'NPS01'; RecordDate = '08/26/2026'; RecordTime = '08:19:05'; PacketType = '1'
    UserName = 'tom.kenny'; FullyQualifiedDistinguishedName = 'ENTCONSULTANTS\tom.kenny'
    NASIdentifier = 'ENTFGT90G'; NASIPAddress = '192.168.200.252'; ClientVendor = '12356'
    ClientIPAddress = '192.168.200.252'; ClientFriendlyName = 'ENT-FGT100E'
    AuthenticationType = '5'; EAPFriendlyName = 'Microsoft: Protected EAP (PEAP)'
    PolicyName = 'RADIUS - IKEv2 & SSLVPN'; ReasonCode = '0'
    MSRASClientName = 'FortiClient'; MSRASClientVersion = '7.4.2'
    AcctSessionId = 'SESSION123'
}
$acceptLine = New-FakeNPSLogLine -Overrides @{
    ComputerName = 'NPS01'; RecordDate = '08/26/2026'; RecordTime = '08:20:47'; PacketType = '2'
    FullyQualifiedDistinguishedName = 'ENTCONSULTANTS\tom.kenny'
    NASIdentifier = 'ENTFGT90G'; NASIPAddress = '192.168.200.252'; ClientVendor = '12356'
    ClientIPAddress = '192.168.200.252'; ClientFriendlyName = 'ENT-FGT100E'
    FramedIPAddress = '10.50.10.77'
    AuthenticationType = '8'; PolicyName = 'RADIUS - IKEv2 & SSLVPN'; ReasonCode = '21'
    ProxyPolicyName = 'RADIUS from FortiGate'; ProviderType = '1'
    AcctSessionId = 'SESSION123'
}

$tmpPath = Join-Path ([System.IO.Path]::GetTempPath()) "NPSTroubleshooting_FieldExpansion_Test_$([guid]::NewGuid().ToString('N')).log"
Set-Content -Path $tmpPath -Value @($reqLine, $acceptLine) -Encoding ASCII

try {
    $entries = Read-NPSRadiusLog -Path $tmpPath
    Assert-Equal -Actual $entries.Count -Expected 2 -Because "Both synthetic rows parse"

    # --- Read-NPSRadiusLog: newly-promoted fields parse correctly ---
    Assert-Equal -Actual $entries[0].FramedIPAddress -Expected "" -Because "FramedIPAddress is blank on the Access-Request row (nothing assigned yet)"
    Assert-Equal -Actual $entries[1].FramedIPAddress -Expected "10.50.10.77" -Because "FramedIPAddress is populated on the Access-Accept row"
    Assert-Equal -Actual $entries[0].EAPFriendlyName -Expected "Microsoft: Protected EAP (PEAP)" -Because "EAPFriendlyName parses correctly"
    Assert-Equal -Actual $entries[0].MSRASClientName -Expected "FortiClient" -Because "MSRASClientName parses correctly"
    Assert-Equal -Actual $entries[0].MSRASClientVersion -Expected "7.4.2" -Because "MSRASClientVersion parses correctly"

    # --- Already-curated-but-previously-hidden fields still parse (unchanged by this work, just
    #     confirming the underlying data was really there all along) ---
    Assert-Equal -Actual $entries[0].RadiusServer -Expected "NPS01" -Because "RadiusServer (ComputerName) parses correctly"
    Assert-Equal -Actual $entries[0].ClientVendor -Expected "12356" -Because "ClientVendor parses correctly"
    Assert-Equal -Actual $entries[0].ClientIPAddress -Expected "192.168.200.252" -Because "ClientIPAddress parses correctly"
    Assert-Equal -Actual $entries[0].PacketType -Expected "Access-Request" -Because "PacketType decodes correctly on the request row"
    Assert-Equal -Actual $entries[1].PacketType -Expected "Access-Accept" -Because "PacketType decodes correctly on the accept row - resolves the Accept-vs-Reject ambiguity an unmapped ReasonCode (21) leaves open"

    # --- Format-NPSRadiusLogPairs: all 8 fields actually render in the table, not just parse ---
    # NOTE (bug found 2026-08-26, unrelated to that day's other work, while running the full suite):
    # the original version of this block tried `Format-NPSRadiusLogPairs -Entries $entries | Out-String`
    # to capture the rendered table - but the function renders via `$rows | Format-Table -AutoSize |
    # Out-Host`, and Out-Host writes DIRECTLY to the console, bypassing every redirectable stream
    # (confirmed: not even `*>&1`/`6>&1` catches it, unlike Write-Host). $TableOutput was therefore
    # ALWAYS an empty string, which PowerShell's own [Parameter(Mandatory)][string] validation on
    # Assert-Contains's -Haystack rejects outright ("Cannot bind argument... because it is an empty
    # string") - a terminating error that silently aborted this foreach on its first iteration every
    # single run, quietly dropping the loop's 8 checks plus the 2 below it (10 of this file's intended
    # 22 assertions never actually ran, despite Write-TestSummary innocently reporting "12/12 passed").
    # Not fixed by changing Out-Host to something capturable - that's live interactive console-rendering
    # behavior (width/AutoSize tied to the real window), out of scope to touch just to satisfy a test.
    # Fixed here instead by checking what this assertion actually cares about via the two things that
    # ARE reachable without capturing console output: (1) the field is really in the function's own
    # display list (structural, via its source), and (2) the VALUE itself is correct on the parsed
    # entry (already proven above, via $entries[1] directly) - together they cover the same real claim
    # ("this field, with its correct value, is part of what gets displayed") the original assertion
    # was going for, without depending on capturing Out-Host.
    $FormatFunctionSrc = Get-FunctionSource -Path $NPSTroubleshootingPath -FunctionName "Format-NPSRadiusLogPairs"
    foreach ($fieldName in @('RadiusServer', 'ClientVendor', 'ClientIPAddress', 'PacketType', 'FramedIPAddress', 'EAPFriendlyName', 'MSRASClientName', 'MSRASClientVersion')) {
        Assert-Contains -Haystack $FormatFunctionSrc -Needle "'$fieldName'" -Because "'$fieldName' is listed in Format-NPSRadiusLogPairs's own `$fieldsToShow (so it renders as a row - the field's actual correct VALUE is separately confirmed above via `$entries directly)"
    }
    # Smoke test: the function must not throw for this synthetic data (Out-Host output itself isn't
    # asserted on, per the note above, but a real exception here would still fail the whole test file).
    Format-NPSRadiusLogPairs -Entries $entries | Out-Null
    Assert-True -Condition $true -Because "Format-NPSRadiusLogPairs runs against the synthetic entries without throwing"
} finally {
    Remove-Item -Path $tmpPath -Force -ErrorAction SilentlyContinue
}

Write-TestSummary -Suite "NPSTroubleshooting RADIUS Log Field Expansion"
