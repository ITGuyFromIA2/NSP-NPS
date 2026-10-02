function ConvertTo-NSPNpsAnswers {
    <#
    .SYNOPSIS
        Turns one client's Orchestrator answers (ClientAnswers\<Abbrev>.json) into the answers NPS
        Manager imports: CompanyName, RADIUSFGTIntIP, RADIUSSecret, RADIUSNPSFGTName, the user group
        names/values, RadiusGroupPairs, tunnel names, and IsComplete.

    .DESCRIPTION
        The same mapping NPS Manager's "Import Kickstart Definitions" uses when it reads a ClientAnswers
        folder (Get-NPSOrchestratorClients), so the Orchestrator and the tool share one copy.
        IsComplete is $false when the FortiGate IP is a placeholder, or the secret or the user group is
        missing. Returns $null for a client whose AuthType is not RADIUS.

    .PARAMETER ClientAnswers
        A parsed ClientAnswers object, or a path to the .json file.

    .EXAMPLE
        ConvertTo-NSPNpsAnswers -ClientAnswers 'C:\...\ClientAnswers\EXAMPLE.json'

    .EXAMPLE
        $nps = ConvertTo-NSPNpsAnswers -ClientAnswers $answers
        if (-not $nps.IsComplete) { Write-Warning 'RADIUS answers are incomplete.' }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$ClientAnswers)
    process {
        $path = ''
        if ($ClientAnswers -is [string]) {
            $path = (Resolve-Path -LiteralPath $ClientAnswers).ProviderPath
            $ClientAnswers = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        }
        if ($ClientAnswers.AuthType -ne 'RADIUS') { return $null }
        $client = ConvertTo-NPSOrchestratorClient -Json $ClientAnswers -FileName $(if ($path) { Split-Path -Leaf $path } else { '' }) -FullPath $path
        # The same fields Export-NPSOrchestratorAnswerFile stages (no file locations).
        $client | Select-Object CompanyName, RADIUSFGTIntIP, RADIUSSecret, RADIUSNPSFGTName, AuthUserGroupName, AuthUserGroupValue,
            AuthUserGroupValueSSLVPN, RadiusGroupPairs, IPSecTunnelName, SSLTunnelName, IsComplete
    }
}
