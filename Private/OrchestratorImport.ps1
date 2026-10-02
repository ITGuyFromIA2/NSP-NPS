<#
.SYNOPSIS
    Option 3 - "Import Kickstart Definitions" - reads Master Orchestrator's per-client
    ClientAnswers/*.json files and imports their already-known RADIUS settings (FortiGate internal
    IP, shared secret, required AD group, VSA group name) into NPS, so a tech who already ran Master
    Orchestrator for a client doesn't have to re-type the same values a second time here. Named for
    what it actually covers now - a Shared Secret Template, a RADIUS Client Template, the live RADIUS
    Client itself, AND optionally its NPS rule(s) - not just "rules", which is all the older name
    ("Import kickstarted rules") implied.

.DESCRIPTION
    Requires Modules\NPSCore.ps1 AND Modules\NPSInteractive.ps1 to already be dot-sourced (uses
    Get-ADGroupSID, Add-NPSClientFromTemplate, New-NPSSharedSecretTemplate, New-NPSClientTemplate,
    Set-NPSSharedSecretTemplateValue, Set-NPSClientTemplateAttribute, Get-NPSSharedSecretTemplates,
    Get-NPSClientTemplates, Set-NPSClientAttribute, Get-NPSClients, Add-NPSPolicySet,
    Add-NPSSingleRule, Get-NPSExistingSequences, Read-ANDConditionGroups, Get-VsaNamesForSide,
    Write-NPSHeader, Get-NPSTemplatesPathFor).

    TEMPLATES-FIRST (per the maintainer's explicit choice over a lighter "optional extra step" alternative):
    every import creates/updates a Shared Secret Template and a RADIUS Client Template from the
    imported data FIRST, then provisions the live RADIUS Client FROM that template
    (Add-NPSClientFromTemplate) rather than directly - so the imported config is reusable for a
    second client/server later (a backup NPS box, an additional FortiGate) without re-typing
    anything, matching how Option 4's own "Manage Templates" -> "Add a Client from a template" flow
    already works. Naming convention: "<ClientName>-Secret" for the Shared Secret Template,
    "<ClientName>" for the RADIUS Client Template - <ClientName> is whatever the tech confirms/enters
    in Step 1, defaulting to Master Orchestrator's own suggested RADIUSNPSFGTName.

    Master Orchestrator's ClientAnswers schema tracks a PRIMARY AD group / VSA pair per client
    (Auth_UserGroup_Name / Auth_UserGroup_Value), plus an OPTIONAL separate SSLVPN-side value
    (Auth_UserGroup_Value_SSLVPN, renamed from Auth_UserGroup_Name_SSLVPN 2026-08-20 - it was never a
    FortiGate object name, just an AD group name doing double duty as the SSLVPN VSA seed). When a
    client captured that separate value (confirmed real via actual client NPS exports - real clients
    use genuinely different VSAs per side), it's used to seed the SSLVPN side's
    baseline instead of reusing the IPSec one. Absent for clients saved before this field existed, or
    that don't need simultaneous SSLVPN+IPSec support - falls back to reusing the primary pair's value
    for both sides in that case, same as it always has. Either way, you can layer EXTRA
    AND-conditions on top of the imported baseline per side if needed.

    RADIUS_FGTInt_IP/RADIUS_NPS_FGTName default to Contoso/DEMOCLIENT-derived placeholder text
    ("192.168.x.xxx" / "Contoso_FGTXXY") on any client where RADIUS was never actually walked through
    the CLI Builder yet - detected here by the IP containing a literal 'x' - and flagged clearly
    rather than silently imported as if it were real, live data.

    Deliberately does NOT hardcode a path to the ClientAnswers folder - Master Orchestrator's own
    $AnswersDir is just "$BaseDir\ClientAnswers", relative to wherever THAT toolset happens to be
    deployed (a share, a tech's local copy, etc.), not a fixed location this NPS-server-resident script
    could assume. Callers must supply -AnswersPath (NPS-Manager.ps1's Option 3 prompts for it) - THAT
    live-folder-based flow is the standalone-usable path (works with zero staging/setup, matching
    The maintainer's explicit requirement that NPSManager keep working as a grab-and-run tool outside Master
    Orchestrator too).

    ALSO supports a second, additive path: a client's data pre-baked into a small NPSAnswers.json file
    sitting next to NPS-Manager.ps1 (see Export-NPSOrchestratorAnswerFile / Get-NPSBakedInAnswers
    below) - meant for when this NPS Manager package gets physically separated from the rest of
    Master Orchestrator's staging output and copied onto a standalone NPS server that has no network
    path back to ClientAnswers at all. When present, Option 3 uses it directly instead of prompting for
    -AnswersPath. This is ADDITIVE, not a replacement - its absence just falls back to the live-folder
    flow exactly as before, so a plain copy of NPS-Manager.ps1 run on its own keeps working unchanged.
#>

# ---------------------------------------------------------------------------
function Get-NPSOrchestratorClients {
    <#
    .SYNOPSIS
        Reads every ClientAnswers/*.json file under -AnswersPath and returns the RADIUS-relevant
        subset of fields for clients whose AuthType is "RADIUS" (AuthType is the reliable signal here -
        NOT "NeedsRadius", which tracks whether THIS RUN of the CLI Builder still needed to configure
        RADIUS, not whether the client uses it at all - confirmed against IPSec-MasterOrchestrator.ps1's
        own use of that flag; a client can be NeedsRadius=false and AuthType=RADIUS simultaneously,
        meaning RADIUS was already fully set up in an earlier pass).

        Flags each result IsComplete=$true only if the IP isn't a placeholder, AND a secret is
        present, AND a required group name is present - callers should warn distinctly on
        IsComplete=$false rather than silently importing placeholder data as if it were real.
    #>
    param([Parameter(Mandatory)][string]$AnswersPath)

    if (-not (Test-Path $AnswersPath)) { throw "ClientAnswers path not found: $AnswersPath" }

    $files = Get-ChildItem -Path $AnswersPath -Filter '*.json' -File -ErrorAction SilentlyContinue
    $results = foreach ($file in $files) {
        try {
            $json = Get-Content -Path $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {
            continue  # skip unparseable/unrelated files rather than aborting the whole listing
        }
        if ($json.AuthType -ne 'RADIUS') { continue }  # Local-auth clients have nothing relevant here

        ConvertTo-NPSOrchestratorClient -Json $json -FileName $file.Name -FullPath $file.FullName
    }
    return @($results)
}

function ConvertTo-NPSOrchestratorClient {
    <#
    .SYNOPSIS
        One ClientAnswers object -> the RADIUS-relevant answer shape (see Get-NPSOrchestratorClients),
        with IsComplete. Split out (NSP.NPS, 2026-10-01) so the Orchestrator and a single-client
        caller (ConvertTo-NSPNpsAnswers) share one mapping instead of hand copies.
    #>
    param([Parameter(Mandatory)]$Json, [string]$FileName = '', [string]$FullPath = '')
    & {
        $json = $Json
        $file = [pscustomobject]@{ Name = $FileName; FullName = $FullPath }
        $ip = $json.RADIUS_FGTInt_IP
        $isPlaceholderIp = [string]::IsNullOrWhiteSpace($ip) -or ($ip -match '[xX]')
        $hasSecret = -not [string]::IsNullOrWhiteSpace($json.RADIUS_Secret)
        $hasGroup  = -not [string]::IsNullOrWhiteSpace($json.Auth_UserGroup_Name)

        [pscustomobject]@{
            CompanyName        = $json.Company_Name
            FileName           = $file.Name
            FullPath           = $file.FullName
            RADIUSFGTIntIP     = $ip
            RADIUSSecret       = $json.RADIUS_Secret
            RADIUSNPSFGTName   = $json.RADIUS_NPS_FGTName
            AuthUserGroupName  = $json.Auth_UserGroup_Name
            AuthUserGroupValue = $json.Auth_UserGroup_Value
            # Blank/absent for every client onboarded before this field existed, or one that doesn't
            # need simultaneous SSLVPN+IPSec support - Invoke-ImportKickstartDefinitions falls back
            # to reusing AuthUserGroupValue for both sides in that case, same as it always has.
            #
            # Field renamed Auth_UserGroup_Name_SSLVPN -> Auth_UserGroup_Value_SSLVPN (2026-08-20) -
            # never a FortiGate object name (no SSLVPN-side "config user group" is ever created), it's
            # an AD group name that doubles as the VSA seed for the SSLVPN side, same as
            # Auth_UserGroup_Value is for IPSec. Reads the new key first, falls back to the old one so
            # already-saved ClientAnswers files keep working unchanged.
            AuthUserGroupValueSSLVPN = if ($json.PSObject.Properties['Auth_UserGroup_Value_SSLVPN']) {
                $json.Auth_UserGroup_Value_SSLVPN
            } else {
                $json.Auth_UserGroup_Name_SSLVPN
            }
            # Blank/absent for every client saved before multi-group-pair support existed -
            # Invoke-ImportKickstartDefinitions synthesizes a single implicit pair from the flat
            # AuthUserGroupName/Value/ValueSSLVPN fields above in that case.
            RadiusGroupPairs   = $json.RadiusGroupPairs
            IPSecTunnelName    = $json.IPSecTunnelName
            SSLTunnelName      = $json.SSLTunnelName
            IsComplete         = (-not $isPlaceholderIp) -and $hasSecret -and $hasGroup
        }
    }
}

# ---------------------------------------------------------------------------
function Export-NPSOrchestratorAnswerFile {
    <#
    .SYNOPSIS
        Writes ONE client's already-known RADIUS answer data (same shape Get-NPSOrchestratorClients
        produces) to a small, self-contained JSON file - meant to be staged alongside NPS-Manager.ps1
        so it keeps working with zero network path back to ClientAnswers, e.g. once copied off onto a
        standalone NPS server. Intended caller: Master Orchestrator's own staging step (once wired
        in - not yet), but works equally well run by hand for a one-off package.

    .PARAMETER AnswersPath
        Master Orchestrator's ClientAnswers folder (reachable from wherever THIS is run - normally the
        tech's own machine during staging, not the eventual NPS server).

    .PARAMETER CompanyName
        Which client to export - matched against Company_Name (case-insensitive), same value shown by
        Get-NPSOrchestratorClients.

    .PARAMETER OutputPath
        Where to write the answer file. Defaults to "NPSAnswers.json" - Get-NPSBakedInAnswers looks for
        exactly that filename next to NPS-Manager.ps1, so don't rename it unless you also update that
        lookup.
    #>
    param(
        [Parameter(Mandatory)][string]$AnswersPath,
        [Parameter(Mandatory)][string]$CompanyName,
        [string]$OutputPath = "NPSAnswers.json"
    )

    $clients = Get-NPSOrchestratorClients -AnswersPath $AnswersPath
    $match = $clients | Where-Object { $_.CompanyName -eq $CompanyName } | Select-Object -First 1
    if (-not $match) { throw "No RADIUS-auth client named '$CompanyName' found under '$AnswersPath'." }

    # Drop FileName/FullPath - those are only meaningful on the machine that had ClientAnswers
    # reachable in the first place, and would be actively misleading baked into a package that's
    # explicitly meant to travel to a machine WITHOUT that reachability.
    $exportable = $match | Select-Object CompanyName, RADIUSFGTIntIP, RADIUSSecret, RADIUSNPSFGTName, AuthUserGroupName, AuthUserGroupValue, AuthUserGroupValueSSLVPN, RadiusGroupPairs, IPSecTunnelName, SSLTunnelName, IsComplete
    $exportable | ConvertTo-Json | Set-Content -Path $OutputPath -Encoding UTF8

    return [pscustomobject]@{ CompanyName = $CompanyName; OutputPath = (Resolve-Path $OutputPath).Path; IsComplete = $match.IsComplete }
}

# ---------------------------------------------------------------------------
function Get-NPSBakedInAnswers {
    <#
    .SYNOPSIS
        Looks for a pre-staged NPSAnswers.json (see Export-NPSOrchestratorAnswerFile) next to
        NPS-Manager.ps1. Returns $null (not an error) if absent - that's the normal case for a
        standalone/grab-and-run copy, and callers should fall back to the live-folder-prompt flow.
    #>
    param([string]$ScriptRoot = $PSScriptRoot)

    # NSP.NPS: the work folder's Answers.json (seeded by a launcher) first, then the zip-era name.
    $path = $null
    foreach ($candidate in @((Join-Path $ScriptRoot "Answers.json"), (Join-Path $ScriptRoot "NPSAnswers.json"))) {
        if (Test-Path $candidate) { $path = $candidate; break }
    }
    if (-not $path) { return $null }
    try {
        return Get-Content -Path $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Host "Found NPSAnswers.json at $path but couldn't parse it - $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

# ---------------------------------------------------------------------------
function Write-NPSPairImportProgress {
    <#
    .SYNOPSIS
        "Where am I / what's already decided" dashboard for ONE RADIUS group pair's own import Q&A -
        mirrors CLIBuilder's own Write-CLIBuilderProgress (2026-08-31 per the maintainer: "show me all the
        things we're answering up above and highlight the one we're answering"). Printed at the top
        of every step's own screen inside Invoke-SingleNPSPairImport, same "unconditional, not an
        opt-in peek" convention CLIBuilder settled on.

    .PARAMETER CurrentStep
        Which step's row (if any) gets the `***`/highlight treatment - one of 'Simul', 'AddMore',
        'IpsecVsa', 'SslvpnVsa', 'BaseName', 'Sequence', or $null/blank for none.
    #>
    param(
        [Parameter(Mandatory)][string]$PairLabel,
        [Parameter(Mandatory)][string]$ResolvedGroupDisplay,
        [bool]$IsTriplicateKnown,
        [bool]$IsTriplicate,
        [string]$AddMoreGroupsAnswer,
        [string[]]$IpsecVsas,
        [string[]]$SslvpnVsas,
        [string]$BaseName,
        [string]$InsertAt,
        [string]$CurrentStep
    )

    function Format-NPSProgressCell {
        param([string]$Text, [int]$Width, [int]$MinGap = 2)
        if ($null -eq $Text) { $Text = "" }
        $padCount = [Math]::Max($MinGap, $Width - $Text.Length)
        return $Text + (' ' * $padCount)
    }
    function New-NPSProgressRow { param([string]$Key, [string]$Label, [string]$Value) [pscustomobject]@{ Key = $Key; Label = $Label; Value = $Value } }
    $pending = "(not answered yet)"

    $rows = [System.Collections.Generic.List[object]]::new()
    $rows.Add((New-NPSProgressRow $null "Resolved AD Group:" $ResolvedGroupDisplay))
    $rows.Add((New-NPSProgressRow 'Simul' "Simultaneous SSLVPN+IPSec:" $(if ($IsTriplicateKnown) { if ($IsTriplicate) { "Yes" } else { "No" } } else { $pending })))
    $rows.Add((New-NPSProgressRow 'AddMore' "Additional required group(s):" $(if ($AddMoreGroupsAnswer) { $AddMoreGroupsAnswer } else { $pending })))
    $rows.Add((New-NPSProgressRow 'IpsecVsa' "IPSec VSA(s):" $(if ($IpsecVsas -and $IpsecVsas.Count -gt 0) { $IpsecVsas -join ', ' } else { $pending })))
    if ($IsTriplicateKnown -and $IsTriplicate) {
        $rows.Add((New-NPSProgressRow 'SslvpnVsa' "SSLVPN VSA(s):" $(if ($SslvpnVsas -and $SslvpnVsas.Count -gt 0) { $SslvpnVsas -join ', ' } else { $pending })))
    }
    $rows.Add((New-NPSProgressRow 'BaseName' "Policy Base Name:" $(if ($BaseName) { $BaseName } else { $pending })))
    $rows.Add((New-NPSProgressRow 'Sequence' "Insert Sequence:" $(if ($InsertAt) { $InsertAt } else { $pending })))

    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  Importing '$PairLabel' - Progress So Far" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    foreach ($r in $rows) {
        $isCurrent = $CurrentStep -and $r.Key -eq $CurrentStep
        $marker = if ($isCurrent) { "*** " } else { "    " }
        $label = Format-NPSProgressCell $r.Label 32 -MinGap 1
        $line = "  $marker$label$($r.Value)"
        if ($isCurrent) { Write-Host $line -ForegroundColor Green } else { Write-Host $line }
    }
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ---------------------------------------------------------------------------
function Invoke-SingleNPSPairImport {
    <#
    .SYNOPSIS
        Imports ONE RADIUS group pair's NPS policy set/rule - extracted 2026-08-31 (per the maintainer, same
        request as the pair-picker in Invoke-ImportKickstartDefinitions and the progress dashboard
        above: "let's also allow us to go back and edit a messed up answer before import") from what
        used to be one big inline `foreach` loop body, so it could become its own back-navigable
        step sequence and be called once per pair the tech actually picks, instead of always running
        front-to-back over every pair in one committed batch.

    .DESCRIPTION
        Steps ('Simul' / 'AddMore' / 'IpsecVsa' / 'SslvpnVsa' / 'BaseName' / 'Sequence') are walked by
        index, same "recompute fresh, re-render the dashboard, allow B to step back one" convention
        CLIBuilder's own $EntryIdx walkthrough uses - going back always re-does the step you land on
        from scratch. 'SslvpnVsa' only exists once 'Simul' has been answered Yes - skipped
        transparently in whichever direction it's approached from. Answering back INTO 'Simul' and
        changing it (or changing 'AddMore') resets every step's own answer that came after it, so nothing
        downstream is ever left stale after an upstream edit - required group/VSA sets are rebuilt from
        the resolved primary group fresh each time 'Simul' completes.

        AD resolution of the pair's own primary (and, if triplicate, SSLVPN-side) group happens ONCE
        up front, outside the back-navigable steps - it's a fact about the pair, not a question with a
        typed answer to revise, same as CLIBuilder treats Company_Name as fixed dashboard header info
        rather than a walkable field.

    .OUTPUTS
        [pscustomobject]@{ Completed = <bool - did this pair actually get committed>;
                            ADServer = <possibly-updated>; ADCredential = <possibly-updated> }
    #>
    param(
        [Parameter(Mandatory)][pscustomobject]$Pair,
        [Parameter(Mandatory)][string]$IASConfigPath,
        [Parameter(Mandatory)][string]$ClientIPAddress,
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential,
        [string]$ShimPath
    )

    # AD resolution below uses UserGroupVALUE, not UserGroupName - REAL BUG, confirmed live
    # 2026-08-31 against a real client's actual AD (the maintainer): UserGroupName is the FortiGate's own local
    # `config user group` object name (e.g. "FGT_IKEv2_CorpLan_Users") - purely a FortiGate-side
    # identifier CLIBuilder uses for `edit "..."`/`set groups "..."`, NEVER a real AD-resolvable
    # group. UserGroupValue IS the real AD group (and, per the maintainer, the same value minus possible
    # case doubles as the VSA NPS sends back - "the AD Group name and VSA value should be the same
    # (minus possible case difference)"). This whole per-pair AD-resolution block used to search AD
    # for UserGroupName instead, which only ever "worked" for a client whose FortiGate object
    # happened to be named identically to its real AD group - failed loudly for a client's real
    # FGT_-prefixed naming convention ("Cannot find an object with identity: 'FGT_IKEv2_CorpLan_Users'").
    if ([string]::IsNullOrWhiteSpace($Pair.UserGroupValue)) {
        Write-Host "No required AD group captured for pair '$($Pair.Label)' - skipping. Use Option 5 to add it manually instead." -ForegroundColor Yellow
        Read-Host "Press Enter to continue"
        return [pscustomobject]@{ Completed = $false; ADServer = $ADServer; ADCredential = $ADCredential }
    }

    # IncludeInNPSImport (2026-08-21, custom app-access rules) - a pair captured with this
    # explicitly set to $false (CLIBuilder's Select-OrCreateGroupPair defaults new app-rule groups
    # to $false) is skipped SILENTLY here - no preview, no Y/N prompt at all. A pair with the
    # property absent entirely (every pair saved before this field existed) or explicitly $true is
    # processed exactly as before.
    if ($Pair.PSObject.Properties['IncludeInNPSImport'] -and $null -ne $Pair.IncludeInNPSImport -and -not [bool]$Pair.IncludeInNPSImport) {
        Write-Host "Pair '$($Pair.Label)' is excluded from batch import - add manually via NPS Manager Option 5 if needed." -ForegroundColor Gray
        Read-Host "Press Enter to continue"
        return [pscustomobject]@{ Completed = $false; ADServer = $ADServer; ADCredential = $ADCredential }
    }

    # Exact-name resolution first, falling back to Resolve-NPSGroupInteractive's search/pick when
    # that misses (a typo, a rename since the name was captured, different capitalization, etc.)
    # instead of just failing the whole pair - confirmed live (the maintainer, 2026-08-18) this was the
    # actual gap: the group was genuinely findable by a partial-name search, but importing just
    # skipped it and sent the tech to Option 5 to fix by hand.
    $resolveResult = Resolve-NPSGroupInteractive -GroupNameOrSID $Pair.UserGroupValue -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath
    $ADServer = $resolveResult.ADServer
    $ADCredential = $resolveResult.ADCredential
    if (-not $resolveResult.Resolved) {
        Write-Host "Could not resolve '$($Pair.UserGroupValue)' for pair '$($Pair.Label)' - skipping. Use Option 5 to add it manually instead." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return [pscustomobject]@{ Completed = $false; ADServer = $ADServer; ADCredential = $ADCredential }
    }
    $importedSid = $resolveResult.SID
    if ($resolveResult.Name -ne $Pair.UserGroupValue) {
        Write-Host "Using '$($resolveResult.Name)' (matched via search) in place of '$($Pair.UserGroupValue)'." -ForegroundColor Green
    } else {
        Write-Host "Resolved imported group '$($Pair.UserGroupValue)' -> $importedSid" -ForegroundColor Green
    }
    $resolvedGroupDisplay = "$($resolveResult.Name) ($importedSid)"
    $hasSeparateSslvpnGroup = -not [string]::IsNullOrWhiteSpace($Pair.UserGroupValueSSLVPN)

    # --- Back-navigable step sequence ---
    $isTriplicateKnown = $false
    $isTriplicate = $false
    $addMoreAnswer = $null
    $ipsecSidSets = $null; $ipsecNames = $null
    $sslvpnSidSets = $null; $sslvpnNames = $null
    $ipsecVsas = $null; $sslvpnVsas = $null
    $baseName = $null
    $insertAt = $null

    $stepNames = @('Simul', 'AddMore', 'IpsecVsa', 'SslvpnVsa', 'BaseName', 'Sequence')
    $stepIdx = 0
    while ($stepIdx -lt $stepNames.Count) {
        $step = $stepNames[$stepIdx]

        cls
        Write-NPSPairImportProgress -PairLabel $Pair.Label -ResolvedGroupDisplay $resolvedGroupDisplay `
            -IsTriplicateKnown $isTriplicateKnown -IsTriplicate $isTriplicate -AddMoreGroupsAnswer $addMoreAnswer `
            -IpsecVsas $ipsecVsas -SslvpnVsas $sslvpnVsas -BaseName $baseName -InsertAt $insertAt -CurrentStep $step

        $canGoBack = $stepIdx -gt 0
        $goBack = $false

        switch ($step) {
            'Simul' {
                $simulDefaultIsYes = if ($null -ne $Pair.IsTriplicate) { [bool]$Pair.IsTriplicate } else { $true }
                $simulSupportDefaultHint = if ($null -ne $Pair.IsTriplicate) {
                    if ($simulDefaultIsYes) { "captured as YES when this pair was set up" } else { "captured as NO when this pair was set up" }
                } elseif ($hasSeparateSslvpnGroup) {
                    "this client has a separate SSLVPN group captured ('$($Pair.UserGroupValueSSLVPN)')"
                } else {
                    "this client has both an IPSecTunnelName and SSLTunnelName on file"
                }
                $simulSupport = Read-Host "Are you needing to simultaneously support SSLVPN and IPSEC through RADIUS for '$($Pair.Label)'? (Y/N$(if ($canGoBack) { '/B to go back' }))`n  (Enter defaults to $(if ($simulDefaultIsYes) { 'Yes' } else { 'No' }) - $simulSupportDefaultHint)"
                if ($canGoBack -and $simulSupport -match '^[Bb](ack)?$') {
                    $goBack = $true
                } else {
                    $isTriplicate = if ([string]::IsNullOrWhiteSpace($simulSupport)) { $simulDefaultIsYes } else { $simulSupport -match '^[Yy]' }
                    $isTriplicateKnown = $true

                    # (Re)seed the IPSec/SSLVPN SID/name lists fresh from the resolved primary group -
                    # redone every time this step completes (first pass OR after backing up and
                    # re-answering) so a later "additional groups" answer never accumulates onto a
                    # stale base list.
                    $ipsecSidSets = [System.Collections.Generic.List[string[]]]::new()
                    $ipsecSidSets.Add(@($importedSid))
                    $ipsecNames = [System.Collections.Generic.List[string]]::new()
                    $ipsecNames.Add($Pair.UserGroupValue)
                    $sslvpnSidSets = [System.Collections.Generic.List[string[]]]::new()
                    $sslvpnNames = [System.Collections.Generic.List[string]]::new()
                    $sslvpnBaselineSid = $importedSid
                    $sslvpnBaselineName = $Pair.UserGroupValue
                    if ($isTriplicate -and $hasSeparateSslvpnGroup) {
                        $sslvpnResolveResult = Resolve-NPSGroupInteractive -GroupNameOrSID $Pair.UserGroupValueSSLVPN -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath
                        $ADServer = $sslvpnResolveResult.ADServer
                        $ADCredential = $sslvpnResolveResult.ADCredential
                        if ($sslvpnResolveResult.Resolved) {
                            $sslvpnBaselineSid = $sslvpnResolveResult.SID
                            $sslvpnBaselineName = $sslvpnResolveResult.Name
                            if ($sslvpnResolveResult.Name -ne $Pair.UserGroupValueSSLVPN) {
                                Write-Host "Using '$($sslvpnResolveResult.Name)' (matched via search) in place of '$($Pair.UserGroupValueSSLVPN)' for the SSLVPN side." -ForegroundColor Green
                            } else {
                                Write-Host "Resolved imported SSLVPN-side group '$($Pair.UserGroupValueSSLVPN)' -> $sslvpnBaselineSid" -ForegroundColor Green
                            }
                        } else {
                            Write-Host "Could not resolve SSLVPN-side group '$($Pair.UserGroupValueSSLVPN)'." -ForegroundColor Yellow
                            Write-Host "Falling back to '$($Pair.UserGroupValue)' for the SSLVPN side too - fix and re-run Option 3, or adjust manually via Option 5, if that's not right." -ForegroundColor Yellow
                        }
                        Read-Host "Press Enter to continue"
                    }
                    $sslvpnSidSets.Add(@($sslvpnBaselineSid))
                    $sslvpnNames.Add($sslvpnBaselineName)

                    # Everything downstream of this step gets re-answered, not left stale - an edited
                    # Simul answer can change whether the SSLVPN VSA step even exists at all.
                    $addMoreAnswer = $null; $ipsecVsas = $null; $sslvpnVsas = $null; $baseName = $null; $insertAt = $null
                }
            }
            'AddMore' {
                $addMore = Read-Host "Add additional required group(s) on top of the imported one for '$($Pair.Label)'? (Y/N$(if ($canGoBack) { '/B to go back' }))"
                if ($canGoBack -and $addMore -match '^[Bb](ack)?$') {
                    $goBack = $true
                } else {
                    if ($addMore -match '^[Yy]') {
                        $addMoreAnswer = 'Yes'
                        Write-NPSHeader "Additional IPSec Conditions - $($Pair.Label)"
                        $extraIpsec = Read-ANDConditionGroups -SideLabel "IPSec (additional)" -ADServer $ADServer -ADCredential $ADCredential
                        foreach ($s in $extraIpsec.SidSets) { $ipsecSidSets.Add($s) }
                        $ipsecNames.AddRange([string[]]$extraIpsec.RequiredNames)
                        if ($isTriplicate) {
                            Write-NPSHeader "Additional SSLVPN Conditions - $($Pair.Label)"
                            $extraSslvpn = Read-ANDConditionGroups -SideLabel "SSLVPN (additional)" -ADServer $ADServer -ADCredential $ADCredential
                            foreach ($s in $extraSslvpn.SidSets) { $sslvpnSidSets.Add($s) }
                            $sslvpnNames.AddRange([string[]]$extraSslvpn.RequiredNames)
                        }
                    } else {
                        $addMoreAnswer = 'No'
                    }
                    $ipsecVsas = $null; $sslvpnVsas = $null; $baseName = $null; $insertAt = $null
                }
            }
            'IpsecVsa' {
                Write-NPSHeader "VSA Group Names - $($Pair.Label)"
                Write-Host "Imported VSA group name: $($Pair.UserGroupValue)" -ForegroundColor Cyan
                if ($canGoBack) {
                    $backCheck = Read-Host "Press Enter to continue, or B to go back"
                    if ($backCheck -match '^[Bb](ack)?$') { $goBack = $true }
                }
                if (-not $goBack) {
                    $newIpsecVsas = [System.Collections.Generic.List[string]]::new()
                    if ($Pair.UserGroupValue) { $newIpsecVsas.Add($Pair.UserGroupValue) }
                    $extraIpsecVsas = Get-VsaNamesForSide -SideLabel "IPSec" -RequiredNames @($ipsecNames | Select-Object -Unique) -ADServer $ADServer -ADCredential $ADCredential
                    foreach ($v in $extraIpsecVsas) { if ($newIpsecVsas -notcontains $v) { $newIpsecVsas.Add($v) } }
                    $ipsecVsas = @($newIpsecVsas)
                    $baseName = $null; $insertAt = $null
                }
            }
            'SslvpnVsa' {
                # Seed from THIS pair's own SSLVPN-side value when captured, not IPSec's - a client
                # needing different VSAs per side (confirmed real via actual client NPS exports) would
                # otherwise get the wrong VSA sent back for the SSLVPN side.
                $sslvpnSeedVsa = if ($Pair.UserGroupValueSSLVPN) { $Pair.UserGroupValueSSLVPN } else { $Pair.UserGroupValue }
                if ($canGoBack) {
                    $backCheck = Read-Host "Press Enter to continue, or B to go back"
                    if ($backCheck -match '^[Bb](ack)?$') { $goBack = $true }
                }
                if (-not $goBack) {
                    $newSslvpnVsas = [System.Collections.Generic.List[string]]::new()
                    if ($sslvpnSeedVsa) { $newSslvpnVsas.Add($sslvpnSeedVsa) }
                    $extraSslvpnVsas = Get-VsaNamesForSide -SideLabel "SSLVPN" -RequiredNames @($sslvpnNames | Select-Object -Unique) -ADServer $ADServer -ADCredential $ADCredential
                    foreach ($v in $extraSslvpnVsas) { if ($newSslvpnVsas -notcontains $v) { $newSslvpnVsas.Add($v) } }
                    $sslvpnVsas = @($newSslvpnVsas)
                    $baseName = $null; $insertAt = $null
                }
            }
            'BaseName' {
                $defaultBaseName = "RADIUS - $($Pair.Label)"
                $baseNameResp = Read-Host "Base name for this policy [Enter for '$defaultBaseName'$(if ($canGoBack) { ', or B to go back' })]"
                if ($canGoBack -and $baseNameResp -match '^[Bb](ack)?$') {
                    $goBack = $true
                } else {
                    $baseName = if ([string]::IsNullOrWhiteSpace($baseNameResp)) { $defaultBaseName } else { $baseNameResp }
                    $insertAt = $null
                }
            }
            'Sequence' {
                # Re-read fresh EVERY time this step is reached (first pass or after a back-up) - a
                # PRIOR pair's own Add-NPSPolicySet/Add-NPSSingleRule call writes to $IASConfigPath and
                # shifts existing sequence numbers, so this listing/insert-at prompt always needs to
                # reflect current on-disk state, not stale data.
                #
                # Shows Name alongside Sequence (2026-08-31 per the maintainer: "can we show the list of
                # policy names so we can pick the right one, similar to how it's shown on the first
                # page of NPS Manager") - a bare list of numbers gave no way to tell WHICH existing
                # policy sits at any given sequence before picking where to insert. Same rendering
                # NPS-Manager.ps1's own "Current Network Policies" status view already uses (Option
                # 1's dashboard), reused here rather than a third independently-drifting copy.
                $policySummary = Get-NPSPolicySummary -Path $IASConfigPath -PolicyType NetworkPolicy
                if ($policySummary.Count -eq 0) {
                    Write-Host "No existing Network Policies yet - this will be the first." -ForegroundColor Gray
                } else {
                    Write-Host "Current Network Policies (evaluated top to bottom, first match wins):" -ForegroundColor Cyan
                    foreach ($p in $policySummary) {
                        $stateTag = if ($p.Enabled) { '' } else { ' [DISABLED]' }
                        Write-Host ("    {0,3}. {1}{2}" -f $p.Sequence, $p.Name, $stateTag)
                    }
                }
                $seqInput = Read-Host "Insert at sequence number [Enter for 1 = top priority$(if ($canGoBack) { ', or B to go back' })]"
                if ($canGoBack -and $seqInput -match '^[Bb](ack)?$') {
                    $goBack = $true
                } else {
                    $insertAt = if ([string]::IsNullOrWhiteSpace($seqInput)) { 1 } else { [int]$seqInput }
                }
            }
        }

        if ($goBack) {
            $stepIdx -= 1
            # Step back OVER 'SslvpnVsa' if it doesn't apply to this pair (landing there would show a
            # step that can't actually be answered for a non-triplicate pair).
            if ($stepIdx -ge 0 -and $stepNames[$stepIdx] -eq 'SslvpnVsa' -and -not ($isTriplicateKnown -and $isTriplicate)) { $stepIdx -= 1 }
        } else {
            $stepIdx += 1
            if ($stepIdx -lt $stepNames.Count -and $stepNames[$stepIdx] -eq 'SslvpnVsa' -and -not ($isTriplicateKnown -and $isTriplicate)) { $stepIdx += 1 }
        }
    }

    # --- Preview + commit - unchanged from the original inline loop, just reading from the step
    # sequence's own variables instead of one straight-line collection. ---
    if ($isTriplicate) {
        $preview = Add-NPSPolicySet -Path $IASConfigPath -BaseName $baseName -ClientIPAddress $ClientIPAddress `
            -IPSecGroupSidSets $ipsecSidSets.ToArray() -SSLVPNGroupSidSets $sslvpnSidSets.ToArray() `
            -IPSecVsaGroupNames @($ipsecVsas) -SSLVPNVsaGroupNames @($sslvpnVsas) `
            -InsertAtSequence $insertAt -WhatIf

        Write-NPSHeader "Preview - $($Pair.Label)"
        Write-Host "Would create 3 policies starting at sequence $insertAt (Combined / IPSec-only / SSLVPN-only)." -ForegroundColor Cyan
        Write-Host "  IPSec groups:  $($ipsecNames -join ', ')"
        Write-Host "  SSLVPN groups: $($sslvpnNames -join ', ')"
        Write-Host "  IPSec VSAs:    $($ipsecVsas -join ', ')"
        Write-Host "  SSLVPN VSAs:   $($sslvpnVsas -join ', ')"
        if ($preview.ShiftedSequences) { Write-Host "Existing policies at/after $insertAt will shift back by 3." -ForegroundColor Yellow }
        $confirm = Read-Host "Apply this to $IASConfigPath now? A timestamped backup will be made first. (Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "Skipped '$($Pair.Label)' - nothing changed for this pair." -ForegroundColor Gray
            return [pscustomobject]@{ Completed = $false; ADServer = $ADServer; ADCredential = $ADCredential }
        }

        $result = Add-NPSPolicySet -Path $IASConfigPath -BaseName $baseName -ClientIPAddress $ClientIPAddress `
            -IPSecGroupSidSets $ipsecSidSets.ToArray() -SSLVPNGroupSidSets $sslvpnSidSets.ToArray() `
            -IPSecVsaGroupNames @($ipsecVsas) -SSLVPNVsaGroupNames @($sslvpnVsas) `
            -InsertAtSequence $insertAt
        Write-Host "Done. Backup: $($result.BackupPath)" -ForegroundColor Green
    } else {
        $preview = Add-NPSSingleRule -Path $IASConfigPath -DisplayName $baseName -ClientIPAddress $ClientIPAddress `
            -GroupSidSets $ipsecSidSets.ToArray() -VsaGroupNames @($ipsecVsas) -InsertAtSequence $insertAt -WhatIf

        Write-NPSHeader "Preview - $($Pair.Label)"
        Write-Host "Would create 1 policy at sequence $insertAt`: $baseName" -ForegroundColor Cyan
        Write-Host "  Groups: $($ipsecNames -join ', ')"
        Write-Host "  VSAs:   $($ipsecVsas -join ', ')"
        if ($preview.ShiftedSequences) { Write-Host "Existing policies at/after $insertAt will shift back by 1." -ForegroundColor Yellow }
        $confirm = Read-Host "Apply this to $IASConfigPath now? A timestamped backup will be made first. (Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "Skipped '$($Pair.Label)' - nothing changed for this pair." -ForegroundColor Gray
            return [pscustomobject]@{ Completed = $false; ADServer = $ADServer; ADCredential = $ADCredential }
        }

        $result = Add-NPSSingleRule -Path $IASConfigPath -DisplayName $baseName -ClientIPAddress $ClientIPAddress `
            -GroupSidSets $ipsecSidSets.ToArray() -VsaGroupNames @($ipsecVsas) -InsertAtSequence $insertAt
        Write-Host "Done. Backup: $($result.BackupPath)" -ForegroundColor Green
    }

    return [pscustomobject]@{ Completed = $true; ADServer = $ADServer; ADCredential = $ADCredential }
}

# ---------------------------------------------------------------------------
function Invoke-ImportKickstartDefinitions {
    <#
    .SYNOPSIS
        The full interactive Option 3 flow - pick an imported client, create/update a Shared Secret
        Template + RADIUS Client Template from its data, provision the live RADIUS Client FROM those
        templates, then optionally roll straight into a policy-set creation pre-seeded with the
        imported group/VSA (reusing Read-ANDConditionGroups/Get-VsaNamesForSide/Add-NPSPolicySet/
        Add-NPSSingleRule exactly as Option 5 does, rather than a parallel implementation).
    #>
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [string]$AnswersPath,
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential,
        # Where to look for a staged NPSAnswers.json - MUST be NPS-Manager.ps1's own directory
        # ($BaseDir there), NOT this function's own $PSScriptRoot: PowerShell resolves $PSScriptRoot
        # lexically to the .ps1 FILE a function is DEFINED in (Modules\OrchestratorImport.ps1's own
        # folder) regardless of call site, so defaulting Get-NPSBakedInAnswers's lookup here would
        # silently search the wrong directory (Modules\, not where NPSAnswers.json actually gets
        # staged next to the dashboard script) - caught by testing this end-to-end, not by inspection.
        [string]$ScriptRoot = $PSScriptRoot,
        # Threaded through to Resolve-NPSGroupInteractive's AD fallback (Invoke-NPSADFallbackPrompt),
        # same as every other AD-touching interactive flow in this dashboard - lets a learned-good DC
        # get saved back into the staged shim for future launches instead of only helping THIS run.
        [string]$ShimPath
    )

    Write-NPSHeader "Import Kickstart Definitions"

    # Pre-staged data wins if present (see Export-NPSOrchestratorAnswerFile/Get-NPSBakedInAnswers) -
    # this is what lets a physically-separated NPS Manager package (no network path back to
    # ClientAnswers) still import without the tech needing to hunt down a UNC path by hand. Its
    # absence is the normal case for a standalone/grab-and-run copy and just falls through to the
    # exact same live-folder-prompt flow this always had.
    $picked = Get-NPSBakedInAnswers -ScriptRoot $ScriptRoot
    if ($picked) {
        Write-Host "Using pre-staged answer data for '$($picked.CompanyName)' (NPSAnswers.json found next to this script)." -ForegroundColor Green
    } else {
        if ([string]::IsNullOrWhiteSpace($AnswersPath)) {
            $AnswersPath = Read-Host "Path to Master Orchestrator's 'IPSEC AIO\ClientAnswers' folder (UNC or local)"
        }
        if ([string]::IsNullOrWhiteSpace($AnswersPath)) { Write-Host "Cancelled." -ForegroundColor Gray; return }

        try {
            $clients = Get-NPSOrchestratorClients -AnswersPath $AnswersPath
        } catch {
            Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
            Read-Host "Press Enter to continue"
            return
        }
        if ($clients.Count -eq 0) {
            Write-Host "No RADIUS-auth clients found under '$AnswersPath'." -ForegroundColor Yellow
            return
        }

        Write-Host "RADIUS-auth clients found:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $clients.Count; $i++) {
            $c = $clients[$i]
            $flag = if ($c.IsComplete) { '' } else { '  [INCOMPLETE - placeholder/missing data]' }
            Write-Host ("    {0}. {1}{2}" -f ($i + 1), $c.CompanyName, $flag)
        }
        $sel = Read-Host "Pick a client by number [Enter to cancel]"
        $idx = ($sel -as [int]) - 1
        if ($idx -lt 0 -or $idx -ge $clients.Count) { Write-Host "Cancelled." -ForegroundColor Gray; return }
        $picked = $clients[$idx]
    }

    Write-Host ""
    Write-Host "Imported data for '$($picked.CompanyName)':" -ForegroundColor Cyan
    Write-Host "  FortiGate Internal IP: $($picked.RADIUSFGTIntIP)"
    Write-Host "  RADIUS Secret:         (hidden - $($picked.RADIUSSecret.Length) chars)"
    Write-Host "  Suggested Client Name: $($picked.RADIUSNPSFGTName)"
    # 2026-08-31 real bug, confirmed live against a real client's AD (the maintainer): AuthUserGroupName is the
    # FortiGate's own local group object name (e.g. "FGT_IKEv2_CorpLan_Users") - it's NEVER a real,
    # AD-resolvable group, purely a FortiGate-side identifier. AuthUserGroupValue IS the real AD group
    # (and, per the maintainer, the same value minus possible case - "IKEv2_CorpLan_Users" - doubling as the
    # VSA NPS sends back). Was previously shown backwards here (labeled "Required AD Group" but sourced
    # from AuthUserGroupName) - this whole function's own AD-resolution logic below had the identical
    # bug, now fixed alongside this display.
    Write-Host "  Required AD Group / VSA: $($picked.AuthUserGroupValue)"
    Write-Host "  FortiGate Group Name:    $($picked.AuthUserGroupName)"
    if (-not $picked.IsComplete) {
        Write-Host ""
        Write-Host "WARNING: this client's data looks incomplete (placeholder IP, missing secret, or" -ForegroundColor Yellow
        Write-Host "missing group) - RADIUS may never have actually been set up for this client via the" -ForegroundColor Yellow
        Write-Host "CLI Builder yet." -ForegroundColor Yellow
        $proceedAnyway = Read-Host "Proceed anyway, filling gaps manually below? (Y/N)"
        if ($proceedAnyway -notmatch '^[Yy]') { Write-Host "Cancelled." -ForegroundColor Gray; return }
    }

    # --- Names/values shared by both steps below ---
    $clientName = Read-Host "Client display name [Enter for '$($picked.RADIUSNPSFGTName)']"
    if ([string]::IsNullOrWhiteSpace($clientName)) { $clientName = $picked.RADIUSNPSFGTName }
    $clientIP = Read-Host "FortiGate internal IP [Enter for '$($picked.RADIUSFGTIntIP)']"
    if ([string]::IsNullOrWhiteSpace($clientIP)) { $clientIP = $picked.RADIUSFGTIntIP }
    if ([string]::IsNullOrWhiteSpace($clientName) -or [string]::IsNullOrWhiteSpace($clientIP) -or $clientIP -match '[xX]') {
        Write-Host "ERROR: need a real client name and IP (no placeholders) to continue." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    $secret = $picked.RADIUSSecret
    if ([string]::IsNullOrWhiteSpace($secret)) {
        $secret = Read-NPSSharedSecret -Prompt "No secret was imported - enter the Shared Secret for '$clientName'"
    }
    if ([string]::IsNullOrWhiteSpace($secret)) {
        Write-Host "ERROR: a shared secret is required." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }

    # --- Step 1: Templates - created/updated FIRST, so the imported config is reusable later (a
    # second client/server for the same company) without re-typing anything, matching Option 4's
    # "Manage Templates" -> "Add a Client from a template" flow. See module header for the naming
    # convention ("<ClientName>-Secret" / "<ClientName>") and why this order was chosen. ---
    Write-NPSHeader "Step 1: Templates"
    $templatesPath = Get-NPSTemplatesPathFor -IASConfigPath $IASConfigPath
    $sstName = "$clientName-Secret"
    $rctName = $clientName

    $existingSst = Get-NPSSharedSecretTemplates -Path $templatesPath | Where-Object Name -eq $sstName
    if ($existingSst) {
        Write-Host "Shared Secret Template '$sstName' already exists." -ForegroundColor Yellow
        $updateSst = Read-Host "Update its value to the imported secret? (cascades to anything already linked to it) (Y/N)"
        if ($updateSst -match '^[Yy]') {
            $sstResult = Set-NPSSharedSecretTemplateValue -TemplateName $sstName -NewSecret $secret -Path $templatesPath -IASConfigPath $IASConfigPath
            if ($sstResult.Changed) {
                Write-Host "Updated. Backup: $($sstResult.BackupPath)" -ForegroundColor Green
                if ($sstResult.CascadedClientTemplateNames -contains $rctName) {
                    Write-Host "'$rctName' (RADIUS Client Template) received the new value via that cascade." -ForegroundColor Green
                }
            } else {
                Write-Host "Already up to date." -ForegroundColor Gray
            }
        }
    } else {
        try {
            $sstResult = New-NPSSharedSecretTemplate -Path $templatesPath -Name $sstName -SharedSecret $secret
            Write-Host "Created Shared Secret Template '$sstName'." -ForegroundColor Green
            Write-Host "Backup: $($sstResult.BackupPath)" -ForegroundColor Green
        } catch {
            Write-Host "ERROR creating Shared Secret Template: $($_.Exception.Message)" -ForegroundColor Red
            Read-Host "Press Enter to continue"
            return
        }
    }

    $existingRct = Get-NPSClientTemplates -Path $templatesPath | Where-Object Name -eq $rctName
    if ($existingRct) {
        Write-Host "RADIUS Client Template '$rctName' already exists (IP $($existingRct.IPAddress))." -ForegroundColor Yellow
        # IP only here - NOT SharedSecret: a direct secret edit would decouple it from '$sstName'
        # (Set-NPSClientTemplateAttribute's own established behavior), which is exactly wrong here -
        # if it's already linked, the Set-NPSSharedSecretTemplateValue cascade above already delivered
        # the new secret; re-editing it directly would just needlessly sever that link.
        $updateRctIp = Read-Host "Update its IP to '$clientIP'? (Y/N)"
        if ($updateRctIp -match '^[Yy]') {
            $ipResult = Set-NPSClientTemplateAttribute -Path $templatesPath -Name $rctName -Attribute IPAddress -Value $clientIP
            if ($ipResult.Changed) { Write-Host "IP updated. Backup: $($ipResult.BackupPath)" -ForegroundColor Green }
            else { Write-Host "IP was already up to date." -ForegroundColor Gray }
        }
    } else {
        try {
            $rctResult = New-NPSClientTemplate -Path $templatesPath -Name $rctName -IPAddress $clientIP -SharedSecret $secret -SharedSecretTemplateName $sstName -TemplatesPath $templatesPath
            Write-Host "Created RADIUS Client Template '$rctName' (linked to '$sstName')." -ForegroundColor Green
            Write-Host "Backup: $($rctResult.BackupPath)" -ForegroundColor Green
        } catch {
            Write-Host "ERROR creating RADIUS Client Template: $($_.Exception.Message)" -ForegroundColor Red
            Read-Host "Press Enter to continue"
            return
        }
    }

    # --- Step 2: RADIUS Client - provisioned FROM the template above (Add-NPSClientFromTemplate),
    # not created directly - see module header. ---
    Write-NPSHeader "Step 2: RADIUS Client"
    $existingClients = Get-NPSClients -Path $IASConfigPath
    $existing = $existingClients | Where-Object Name -eq $clientName
    if ($existing) {
        Write-Host "A RADIUS client named '$clientName' already exists (IP $($existing.IPAddress))." -ForegroundColor Yellow
        $updateExisting = Read-Host "Update its IP/Shared Secret to the imported values? (Y/N)"
        if ($updateExisting -match '^[Yy]') {
            $ipEdit = Set-NPSClientAttribute -Path $IASConfigPath -Name $clientName -Attribute IPAddress -Value $clientIP
            if ($ipEdit.Changed) { Write-Host "IP updated." -ForegroundColor Green }
            $secResult = Set-NPSClientAttribute -Path $IASConfigPath -Name $clientName -Attribute SharedSecret -Value $secret
            if ($secResult.Changed) {
                Write-Host "Secret updated. Backup: $($secResult.BackupPath)" -ForegroundColor Green
                if ($secResult.Decoupled) { Write-Host "Note: this broke its existing template link (direct edit)." -ForegroundColor Yellow }
            } else {
                Write-Host "Secret was already up to date." -ForegroundColor Gray
            }
        }
    } else {
        try {
            $addResult = Add-NPSClientFromTemplate -Path $IASConfigPath -ClientTemplateName $rctName -NewClientName $clientName -IPAddress $clientIP -TemplatesPath $templatesPath
            Write-Host "Created RADIUS client '$clientName' ($clientIP), provisioned from template '$rctName'." -ForegroundColor Green
            Write-Host "Backup: $($addResult.BackupPath)" -ForegroundColor Green
        } catch {
            Write-Host "ERROR creating client: $($_.Exception.Message)" -ForegroundColor Red
            Read-Host "Press Enter to continue"
            return
        }
    }

    # --- Step 3: Connection Request Policy (optional) - governs WHETHER/HOW NPS even processes a
    # request from this client's FortiGate at all, before Network Policy authorization ever applies -
    # a real, working CRP always turned out to need a paired Proxy_Profiles entry too
    # (Add-NPSConnectionRequestRule now creates one, see its own corrected notes) - Import used to
    # never touch CRPs at all, leaving a tech to build one by hand in the NPS console every single
    # time (confirmed live, 2026-08-18 - recognizable as a "MANUAL - ..." entry in a real client's own
    # ias.xml). Matches this MSP's existing "RADIUS from FortiGate" naming convention and
    # Client-IP-Address condition (the same shape both the real auto-built entry and the maintainer's manual
    # one already use) rather than inventing a new one - a tech who wants something different can
    # still rename/adjust via Option 5 afterward.
    Write-NPSHeader "Step 3: Connection Request Policy"
    $suggestedCrpName = "RADIUS from FortiGate"
    $existingCrps = Get-NPSPolicySummary -Path $IASConfigPath -PolicyType ConnectionRequest
    $existingCrp = $existingCrps | Where-Object Name -eq $suggestedCrpName
    if ($existingCrp) {
        Write-Host "A Connection Request Policy named '$suggestedCrpName' already exists." -ForegroundColor Yellow
        Write-Host "  Current condition(s): $($existingCrp.Constraints -join '; ')" -ForegroundColor Gray
        Write-Host "Leaving it as-is - use Option 5 (Manage NPS Rules) to review/adjust it if needed." -ForegroundColor Gray
    } else {
        $crpName = Read-Host "Connection Request Policy name [Enter for '$suggestedCrpName']"
        if ([string]::IsNullOrWhiteSpace($crpName)) { $crpName = $suggestedCrpName }
        $addCrp = Read-Host "Create Connection Request Policy '$crpName' matching Client-IP-Address=${clientIP}? (Y/N, default Y)"
        if ([string]::IsNullOrWhiteSpace($addCrp) -or $addCrp -match '^[Yy]') {
            try {
                $crpResult = Add-NPSConnectionRequestRule -Path $IASConfigPath -DisplayName $crpName -Conditions @("MATCH(`"Client-IP-Address=$clientIP`")")
                Write-Host "Created Connection Request Policy '$crpName'." -ForegroundColor Green
                Write-Host "Backup: $($crpResult.BackupPath)" -ForegroundColor Green
            } catch {
                Write-Host "ERROR creating Connection Request Policy: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Skipping - use Option 5 to add it manually instead." -ForegroundColor Yellow
                Read-Host "Press Enter to continue"
            }
        } else {
            Write-Host "Skipped - use Option 5 later to add it manually if needed." -ForegroundColor Gray
        }
    }

    # --- Step 4: policy set(s) (optional) - picks and imports pairs one at a time from a list
    # (multi-group-pair support, per the maintainer 2026-08-14; restructured to a pair-PICKER 2026-08-31, see
    # Invoke-SingleNPSPairImport's own header). Pre-existing clients saved before that feature
    # existed have no RadiusGroupPairs array - a single pair is SYNTHESIZED from the older flat
    # AuthUserGroupName/Value/NameSSLVPN fields so this whole step still works EXACTLY as it always
    # did for them (a "list" of just one). ---
    Write-NPSHeader "Step 4: NPS Rule(s)"
    $addRules = Read-Host "Also create the NPS rule(s) for this client now? (Y/N)"
    if ($addRules -notmatch '^[Yy]') {
        Write-Host "Done - client only. Use Option 5 later to add rules." -ForegroundColor Green
        return
    }

    # IsTriplicate is $null on the synthesized pair (unknown ahead of time, same as this always
    # worked - asked interactively below with the old tunnel-name-based hint). A REAL captured pair
    # already has its own IsTriplicate decided at CLI Builder time - used as this pair's PRE-FILLED
    # default below instead, but still asked (so a tech can override) rather than trusted blindly.
    $pairsToProcess = if ($picked.RadiusGroupPairs -and @($picked.RadiusGroupPairs).Count -gt 0) {
        @($picked.RadiusGroupPairs)
    } else {
        @([pscustomobject]@{
            Label                = $picked.CompanyName
            UserGroupName        = $picked.AuthUserGroupName
            UserGroupValue       = $picked.AuthUserGroupValue
            UserGroupValueSSLVPN = $picked.AuthUserGroupValueSSLVPN
            IsTriplicate         = $null
        })
    }

    # UserGroupNameSSLVPN -> UserGroupValueSSLVPN rename (2026-08-20) - pairs pulled straight from an
    # already-saved RadiusGroupPairs array (the branch above) still carry the OLD property name as-is,
    # since that array is read verbatim off disk, not rebuilt through the synthesized-pair path below
    # it. Every downstream reference in this function uses the new name, so alias it onto each pair
    # here (PSCustomObjects from ConvertFrom-Json support adding a note property directly) rather than
    # requiring every real client's saved JSON to be edited first.
    foreach ($p in $pairsToProcess) {
        if ($p.PSObject.Properties['UserGroupNameSSLVPN'] -and -not $p.PSObject.Properties['UserGroupValueSSLVPN']) {
            $p | Add-Member -NotePropertyName 'UserGroupValueSSLVPN' -NotePropertyValue $p.UserGroupNameSSLVPN -Force
        }
    }

    # Pair PICKER (2026-08-31 per the maintainer: "could we do a listing of the RADIUS group pairs and allow
    # us to pick and choose which one(s) we want to do? When done importing it should drop back to
    # the overall list (empty if already imported)"). Replaces the old unconditional "foreach every
    # pair in order" batch loop - a tech can now import one pair, review the result, then come back
    # for the next, instead of being committed to the whole list front to back. "Already imported"
    # is tracked SESSION-LOCAL only (not detected from existing policy names on disk) - simple and
    # predictable; re-running Option 3 later shows the full list again, which is fine since
    # re-importing an already-existing policy just updates it (Add-NPSPolicySet/Add-NPSSingleRule are
    # both upsert-safe).
    $importedThisSession = [System.Collections.Generic.List[string]]::new()
    while ($true) {
        $remaining = @($pairsToProcess | Where-Object { $importedThisSession -notcontains $_.Label })
        if ($remaining.Count -eq 0) {
            if ($importedThisSession.Count -gt 0) {
                Write-Host "All RADIUS group pairs imported this session." -ForegroundColor Green
            } else {
                Write-Host "No RADIUS group pairs to import." -ForegroundColor Yellow
            }
            break
        }

        Write-NPSHeader "Step 4: NPS Rule(s) - Pick a Pair"
        Write-Host "RADIUS group pairs for '$($picked.CompanyName)':" -ForegroundColor Cyan
        for ($i = 0; $i -lt $remaining.Count; $i++) {
            $rp = $remaining[$i]
            $tripTag = if ($null -eq $rp.IsTriplicate) { " (asks IKEv2/SSLVPN when imported)" } elseif ($rp.IsTriplicate) { " (IKEv2 + SSLVPN)" } else { " (IKEv2 only)" }
            Write-Host ("  {0}. {1}{2}" -f ($i + 1), $rp.Label, $tripTag)
        }
        if ($importedThisSession.Count -gt 0) {
            Write-Host "  Already imported this session: $($importedThisSession -join ', ')" -ForegroundColor DarkGray
        }
        Write-Host ""
        $pickResp = Read-Host "Enter a number to import that pair, A for all remaining, or Q to finish"
        if ($pickResp -match '^[Qq]$') { break }

        $toImport = if ($pickResp -match '^[Aa]$') {
            @($remaining)
        } else {
            $pickIdx = ($pickResp -as [int]) - 1
            if ($pickIdx -lt 0 -or $pickIdx -ge $remaining.Count) {
                Write-Host "Invalid selection." -ForegroundColor Yellow
                Read-Host "Press Enter to continue"
                continue
            }
            @($remaining[$pickIdx])
        }

        foreach ($pairToImport in $toImport) {
            $importResult = Invoke-SingleNPSPairImport -Pair $pairToImport -IASConfigPath $IASConfigPath -ClientIPAddress $clientIP `
                -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath
            # AD server/credential fallbacks discovered mid-import (Invoke-NPSADFallbackPrompt) apply
            # for the rest of THIS session too - same "sticks for every AD call after this one"
            # behavior the old inline loop already had, just threaded back out through the return
            # value now that this lives in its own function.
            $ADServer = $importResult.ADServer
            $ADCredential = $importResult.ADCredential
            if ($importResult.Completed) { $importedThisSession.Add($pairToImport.Label) }
        }
    }
}
