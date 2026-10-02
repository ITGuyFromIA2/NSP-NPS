<#
.SYNOPSIS
    Option 6 - troubleshooting tools: MFA_NPS_Troubleshooter.ps1 (download+review+confirm+run, per
    the confirmed design decision earlier this session), NPS Extension registry disable/restore, a
    polished RADIUS log reader, a full read-only config summary (Show-NPSConfigSummary - also has a
    -Compact mode the MAIN dashboard uses directly, see NPS-Manager.ps1's main menu loop), and an
    extension prereq check.

.DESCRIPTION
    Requires Modules\NPSCore.ps1 to already be dot-sourced (uses Get-NPSConfigEncoding-style
    conventions only indirectly - this module reads ias.xml's Microsoft_Accounting section directly).
#>

# ---------------------------------------------------------------------------
function Show-NPSConfigSummary {
    <#
    .SYNOPSIS
        Read-only "everything in one place" dump - rules/policies, RADIUS clients, and both template
        types (Shared Secret / RADIUS Client Templates) - so a tech can see the whole picture without
        navigating Options 4/5 separately. Shared secrets are never shown (masked by design, not just
        by default) - this is a troubleshooting overview, not a place to go reveal one.

    .PARAMETER IASConfigPath
        ias.xml's path - iastemplates.xml (a separate file, see Get-NPSSharedSecretTemplates) is
        derived as its sibling in the same directory, same convention used everywhere else this
        pairing comes up (Get-NPSTemplatesPathFor in NPS-Manager.ps1).

    .PARAMETER Compact
        Table-like per-rule form (sequence/name/enabled-state on one line, conditions and - for
        Network Policies - VSA group grants on the line(s) below it, same "Order / Name / Status"
        shape the native NPS console itself uses) - what the main dashboard shows on every redraw
        (per the maintainer's request to fold rule detail into the main screen, not bury it in Troubleshooting
        -> 9). Capped at $maxDetailRows per policy type - a server with a LOT of rules falls back to a
        "... and N more" tail past that cap instead of burying the menu itself; the FULL form (this
        function without -Compact) has no cap and stays the place to see everything.
    #>
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [switch]$Compact
    )

    $templatesPath = Join-Path -Path (Split-Path -Path $IASConfigPath -Parent) -ChildPath "iastemplates.xml"

    if ($Compact) {
        $maxShown = 6
        $maxDetailRows = 8
        function Format-NPSCompactList([string[]]$Items) {
            if ($Items.Count -eq 0) { return '(none)' }
            if ($Items.Count -le $maxShown) { return ($Items -join ', ') }
            return (($Items | Select-Object -First $maxShown) -join ', ') + " ... and $($Items.Count - $maxShown) more"
        }

        # Draws one policy TYPE's block - sequence/name/enabled-state as a table-ish line (mirrors the
        # native NPS console's own Order/Name/Status columns). Deliberately just this one line per
        # policy (no conditions/VSA grants dump) - per the maintainer, that level of detail belongs in
        # Troubleshooting -> 9's full form, not on every single dashboard redraw. Capped at
        # $maxDetailRows so a server with many rules doesn't bury the menu itself under this either.
        function Write-NPSCompactPolicyBlock {
            param([string]$Header, [object[]]$Policies)
            Write-Host "$Header ($($Policies.Count)):" -ForegroundColor Cyan
            if ($Policies.Count -eq 0) {
                Write-Host "  (none)" -ForegroundColor Gray
                return
            }
            foreach ($p in ($Policies | Select-Object -First $maxDetailRows)) {
                $stateTag = if ($p.Enabled) { 'Enabled ' } else { 'Disabled' }
                $stateColor = if ($p.Enabled) { 'Green' } else { 'DarkGray' }
                Write-Host ("  {0,3}. [{1}] {2}" -f $p.Sequence, $stateTag, $p.Name) -ForegroundColor $stateColor
            }
            if ($Policies.Count -gt $maxDetailRows) {
                Write-Host "  ... and $($Policies.Count - $maxDetailRows) more (full detail: Troubleshooting -> 9)" -ForegroundColor Gray
            }
        }

        # Network Policies and Connection Request Policies are two entirely separate universes (see
        # NPSCore.ps1 module NOTES) - always fetched and shown separately, never merged into one list.
        # Connection Request Policies listed above Network Policies - mirrors the native NPS console's
        # own tree layout (per the maintainer), same order applied in the full form below.
        $crps = @()
        try { $crps = @(Get-NPSPolicySummary -Path $IASConfigPath -PolicyType ConnectionRequest) } catch {}
        Write-NPSCompactPolicyBlock -Header "Connection Request Policies" -Policies $crps
        Write-Host ""

        $nps = @()
        try { $nps = @(Get-NPSPolicySummary -Path $IASConfigPath -PolicyType NetworkPolicy) } catch {}
        Write-NPSCompactPolicyBlock -Header "Network Policies" -Policies $nps
        Write-Host ""

        $clientNames = @()
        try {
            $clientNames = @(Get-NPSClients -Path $IASConfigPath | ForEach-Object {
                if ($_.Enabled) { "$($_.Name) ($($_.IPAddress))" } else { "$($_.Name) ($($_.IPAddress)) [DISABLED]" }
            })
        } catch {}

        $templateNames = [System.Collections.Generic.List[string]]::new()
        try { foreach ($n in (Get-NPSClientTemplates -Path $templatesPath | Select-Object -ExpandProperty Name)) { $templateNames.Add($n) } } catch {}
        try { foreach ($n in (Get-NPSSharedSecretTemplates -Path $templatesPath | Select-Object -ExpandProperty Name)) { $templateNames.Add($n) } } catch {}

        Write-Host ("Clients ({0}):   {1}" -f $clientNames.Count, (Format-NPSCompactList $clientNames)) -ForegroundColor Gray
        Write-Host ("Templates ({0}): {1}" -f $templateNames.Count, (Format-NPSCompactList @($templateNames))) -ForegroundColor Gray
        return
    }

    # Connection Request Policies listed above Network Policies - mirrors the native NPS console's
    # own tree layout (per the maintainer).
    Write-Host "=== Connection Request Policies (routing - where/how to authenticate) ===" -ForegroundColor Cyan
    try {
        $crps = @(Get-NPSPolicySummary -Path $IASConfigPath -PolicyType ConnectionRequest)
        if ($crps.Count -eq 0) {
            Write-Host "  (none)" -ForegroundColor Gray
        } else {
            foreach ($p in $crps) {
                $stateTag = if ($p.Enabled) { '' } else { ' [DISABLED]' }
                Write-Host ("  {0,3}. {1}{2}" -f $p.Sequence, $p.Name, $stateTag)
                foreach ($c in $p.Constraints) { Write-Host "        - $c" -ForegroundColor Gray }
            }
        }
    } catch {
        Write-Host "  ERROR reading Connection Request Policies: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "=== Network Policies (access/authorization) ===" -ForegroundColor Cyan
    try {
        $policies = @(Get-NPSPolicySummary -Path $IASConfigPath -PolicyType NetworkPolicy)
        if ($policies.Count -eq 0) {
            Write-Host "  (none)" -ForegroundColor Gray
        } else {
            foreach ($p in $policies) {
                $stateTag = if ($p.Enabled) { '' } else { ' [DISABLED]' }
                Write-Host ("  {0,3}. {1}{2}" -f $p.Sequence, $p.Name, $stateTag)
                foreach ($c in $p.Constraints) { Write-Host "        - $c" -ForegroundColor Gray }
            }
        }
    } catch {
        Write-Host "  ERROR reading policies: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "=== RADIUS Clients ===" -ForegroundColor Cyan
    try {
        $clients = @(Get-NPSClients -Path $IASConfigPath)
        if ($clients.Count -eq 0) {
            Write-Host "  (none)" -ForegroundColor Gray
        } else {
            foreach ($c in $clients) {
                $stateTag = if ($c.Enabled) { '' } else { ' [DISABLED]' }
                $isZeroGuid = (-not $c.ClientSecretTemplateGuid) -or ($c.ClientSecretTemplateGuid -eq '{00000000-0000-0000-0000-000000000000}')
                $templateNote = if (-not $isZeroGuid) { " (secret from a template)" } else { "" }
                Write-Host ("  {0}  ({1}){2}{3}" -f $c.Name, $c.IPAddress, $stateTag, $templateNote)
            }
        }
    } catch {
        Write-Host "  ERROR reading clients: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "=== Shared Secret Templates ===" -ForegroundColor Cyan
    try {
        $sst = @(Get-NPSSharedSecretTemplates -Path $templatesPath)
        if ($sst.Count -eq 0) { Write-Host "  (none)" -ForegroundColor Gray }
        else { foreach ($t in $sst) { Write-Host "  $($t.Name)" } }
    } catch {
        Write-Host "  (none / iastemplates.xml not found at $templatesPath)" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "=== RADIUS Client Templates ===" -ForegroundColor Cyan
    try {
        $rct = @(Get-NPSClientTemplates -Path $templatesPath)
        if ($rct.Count -eq 0) { Write-Host "  (none)" -ForegroundColor Gray }
        else { foreach ($t in $rct) { Write-Host ("  {0}  ({1})" -f $t.Name, $t.IPAddress) } }
    } catch {
        Write-Host "  (none / iastemplates.xml not found at $templatesPath)" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
function Show-NPSExtensionPrereqCheck {
    <#
    .SYNOPSIS
        Read-only combination of Test-NPSExtensionPrereqs + Test-NPSExtensionAutoDownloadCapability -
        the same two checks Option 2 -> 1 runs, surfaced here too so a tech troubleshooting the
        extension doesn't have to go find them under Manage NPS Extension first. Deliberately does
        NOT offer to install anything from here (unlike Option 2's version) - this is a diagnostic
        view; installing prereqs is a lifecycle action and stays under Option 2 where it already
        lives, consistent with this menu's own established diagnostic-vs-lifecycle split (see
        NPS-Manager.ps1's Invoke-TroubleshootingMenu header notes).
    #>
    $prereqs = Test-NPSExtensionPrereqs
    Write-Host "  .NET Framework:  $($prereqs.DotNetLabel)" -ForegroundColor $(if ($prereqs.DotNetOk) { 'Green' } else { 'Red' })
    Write-Host "  PowerShell:      $($prereqs.PSVersion)  $(if ($prereqs.PSOk) { '(OK - 5.1+)' } else { '(BELOW 5.1)' })" -ForegroundColor $(if ($prereqs.PSOk) { 'Green' } else { 'Red' })
    if (-not $prereqs.AllOk) {
        Write-Host "  Resolve the above before installing the extension." -ForegroundColor Yellow
    }

    Write-Host ""
    $autoCap = Test-NPSExtensionAutoDownloadCapability
    Write-Host "  Automated headless download:  $(if ($autoCap.Available) { 'Available' } else { "Not available - $($autoCap.Reason)" })" -ForegroundColor $(if ($autoCap.Available) { 'Green' } else { 'Yellow' })
    Write-Host "  (optional - the manual 'open the download page' flow always works regardless)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  To install missing prereqs, use Option 2 -> Install or Update the NPS Extension." -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
function Invoke-DownloadAndReviewMFATroubleshooter {
    <#
    .SYNOPSIS
        Downloads MFA_NPS_Troubleshooter.ps1 from the official Azure-Samples GitHub repo, shows it to
        the tech for review, and only runs it after explicit confirmation - never blind-executes a
        downloaded script (confirmed design decision from this session's earlier planning).
    #>
    param([string]$DownloadDir = $env:TEMP)

    $url = 'https://raw.githubusercontent.com/Azure-Samples/azure-mfa-nps-extension-health-check/refs/heads/main/MFA_NPS_Troubleshooter.ps1'
    $destPath = Join-Path $DownloadDir 'MFA_NPS_Troubleshooter.ps1'

    Write-Host "Downloading from:" -ForegroundColor Cyan
    Write-Host "  $url" -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $destPath -UseBasicParsing -ErrorAction Stop
        Write-Host "Saved to $destPath" -ForegroundColor Green
    } catch {
        Write-Host "ERROR downloading: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "--- Script contents (review before running - this is a THIRD-PARTY download) ---" -ForegroundColor Yellow
    Get-Content -Path $destPath -Raw | Write-Host
    Write-Host "--- End of script contents ---" -ForegroundColor Yellow
    Write-Host ""

    $confirm = Read-Host "Run this script now? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Not run. Saved at $destPath if you want to run it manually later." -ForegroundColor Gray
        return
    }

    Write-Host "Running $destPath ..." -ForegroundColor Cyan
    try {
        & $destPath
    } catch {
        Write-Host "ERROR running script: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
function Get-NPSExtensionRegistryState {
    <#
    .SYNOPSIS
        Reads the CURRENT AuthorizationDLLs/ExtensionDLL values under
        HKLM:\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters - the values NPS actually loads its
        secondary-authentication (Azure MFA) provider from. Used both to display current state and to
        capture a snapshot before disabling, so Restore-NPSExtensionRegistryState can put it back.
    #>
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters'
    $result = [pscustomobject]@{
        Path              = $path
        AuthorizationDLLs = $null
        ExtensionDLL      = $null
        Exists            = (Test-Path $path)
    }
    if ($result.Exists) {
        $result.AuthorizationDLLs = (Get-ItemProperty -Path $path -Name 'AuthorizationDLLs' -ErrorAction SilentlyContinue).AuthorizationDLLs
        $result.ExtensionDLL      = (Get-ItemProperty -Path $path -Name 'ExtensionDLL' -ErrorAction SilentlyContinue).ExtensionDLL
    }
    return $result
}

# ---------------------------------------------------------------------------
function Disable-NPSExtensionRegistry {
    <#
    .SYNOPSIS
        Clears AuthorizationDLLs/ExtensionDLL under AuthSrv\Parameters so NPS stops loading secondary
        (Azure MFA) authentication - per the maintainer's original spec, verbatim registry path/keys. Does NOT
        restart the Network Policy Server service itself (that's a separate, explicit step - a
        service restart is disruptive enough to warrant its own confirmation, not a hidden side effect).
    #>
    param([string]$BackupPath)

    $state = Get-NPSExtensionRegistryState
    if (-not $state.Exists) { throw "AuthSrv\Parameters key not found - is the NPS role installed?" }

    if ($BackupPath) {
        $state | Select-Object Path, AuthorizationDLLs, ExtensionDLL | ConvertTo-Json | Set-Content -Path $BackupPath -Encoding UTF8
    }

    Set-ItemProperty -Path $state.Path -Name 'AuthorizationDLLs' -Value '' -Type MultiString
    Set-ItemProperty -Path $state.Path -Name 'ExtensionDLL' -Value '' -Type MultiString

    return [pscustomobject]@{ Disabled = $true; PreviousState = $state; BackupPath = $BackupPath }
}

# ---------------------------------------------------------------------------
function Restore-NPSExtensionRegistry {
    <#
    .SYNOPSIS
        Restores AuthorizationDLLs/ExtensionDLL from a snapshot captured by Disable-NPSExtensionRegistry
        (-BackupPath), or from explicitly-supplied values if you already know them (e.g. reading them
        off another, correctly-configured NPS server).
    #>
    param(
        [string]$BackupPath,
        [string[]]$AuthorizationDLLs,
        [string[]]$ExtensionDLL
    )

    if ($BackupPath) {
        if (-not (Test-Path $BackupPath)) { throw "Backup file not found: $BackupPath" }
        $saved = Get-Content -Path $BackupPath -Raw | ConvertFrom-Json
        $AuthorizationDLLs = @($saved.AuthorizationDLLs)
        $ExtensionDLL      = @($saved.ExtensionDLL)
    }
    if (-not $AuthorizationDLLs -and -not $ExtensionDLL) {
        throw "Nothing to restore - supply -BackupPath, or -AuthorizationDLLs/-ExtensionDLL explicitly."
    }

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters'
    if ($AuthorizationDLLs) { Set-ItemProperty -Path $path -Name 'AuthorizationDLLs' -Value $AuthorizationDLLs -Type MultiString }
    if ($ExtensionDLL)      { Set-ItemProperty -Path $path -Name 'ExtensionDLL' -Value $ExtensionDLL -Type MultiString }

    return [pscustomobject]@{ Restored = $true; AuthorizationDLLs = $AuthorizationDLLs; ExtensionDLL = $ExtensionDLL }
}

# ---------------------------------------------------------------------------
function Invoke-ToggleNPSExtensionRegistry {
    <#
    .SYNOPSIS
        The interactive dashboard flow for temporarily disabling/restoring the NPS Extension via
        registry, with the required Network Policy Server service restart offered (confirmed,
        never silent) each time - per the maintainer's original spec.

    .DESCRIPTION
        Service name "IAS" (not "NPS") verified via web search - the Network Policy Server role kept
        its legacy Internet Authentication Service internal service name for backward compatibility
        when renamed starting with Windows Server 2008; `Restart-Service ias` is the documented way
        to restart it. Not guessed.
    #>
    $backupPath = Join-Path $env:TEMP 'NPSExtension_RegistryBackup.json'
    $state = Get-NPSExtensionRegistryState

    if (-not $state.Exists) {
        Write-Host "AuthSrv\Parameters key not found - is the NPS role installed?" -ForegroundColor Red
        return
    }

    $isDisabled = [string]::IsNullOrWhiteSpace(($state.AuthorizationDLLs -join '')) -and [string]::IsNullOrWhiteSpace(($state.ExtensionDLL -join ''))
    Write-Host "Current AuthorizationDLLs: $($state.AuthorizationDLLs -join '; ')" -ForegroundColor $(if ($isDisabled) { 'Yellow' } else { 'Green' })
    Write-Host "Current ExtensionDLL:      $($state.ExtensionDLL -join '; ')" -ForegroundColor $(if ($isDisabled) { 'Yellow' } else { 'Green' })
    Write-Host ""

    if ($isDisabled) {
        Write-Host "The extension DLLs are currently EMPTY - secondary (Azure MFA) authentication is" -ForegroundColor Yellow
        Write-Host "NOT loading. If a backup snapshot exists at $backupPath, it can be restored." -ForegroundColor Yellow
        if (Test-Path $backupPath) {
            $confirm = Read-Host "Restore from that snapshot now? (Y/N)"
            if ($confirm -match '^[Yy]') {
                Restore-NPSExtensionRegistry -BackupPath $backupPath | Out-Null
                Write-Host "Restored." -ForegroundColor Green
                $restartConfirm = Read-Host "Restart the Network Policy Server service now, to apply this? (Y/N)"
                if ($restartConfirm -match '^[Yy]') {
                    try { Restart-Service -Name IAS -Force; Write-Host "Service restarted." -ForegroundColor Green }
                    catch { Write-Host "ERROR restarting service: $($_.Exception.Message)" -ForegroundColor Red }
                } else {
                    Write-Host "Not restarted - the extension will keep NOT loading until the service is restarted." -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "No snapshot found at $backupPath - restore manually via the NPS console/registry if needed." -ForegroundColor Yellow
        }
    } else {
        Write-Host "This will temporarily DISABLE secondary (Azure MFA) authentication for troubleshooting" -ForegroundColor Yellow
        Write-Host "- a snapshot of the current values is saved first, to restore later." -ForegroundColor Yellow
        $confirm = Read-Host "Disable the NPS Extension now? (Y/N)"
        if ($confirm -match '^[Yy]') {
            Disable-NPSExtensionRegistry -BackupPath $backupPath | Out-Null
            Write-Host "Disabled. Snapshot saved to $backupPath for restoring later." -ForegroundColor Green
            $restartConfirm = Read-Host "Restart the Network Policy Server service now, to apply this? (Y/N)"
            if ($restartConfirm -match '^[Yy]') {
                try { Restart-Service -Name IAS -Force; Write-Host "Service restarted." -ForegroundColor Green }
                catch { Write-Host "ERROR restarting service: $($_.Exception.Message)" -ForegroundColor Red }
            } else {
                Write-Host "Not restarted - the extension will keep loading normally until the service is restarted." -ForegroundColor Yellow
            }
        }
    }
}

# ---------------------------------------------------------------------------
function Invoke-NPSServiceRestartAction {
    <#
    .SYNOPSIS
        Standalone "restart the Network Policy Server service" troubleshooting action (2026-09-03, per
        The maintainer - a second tech's real run-through: streamline the troubleshooting screen and add a
        service restart option to it). Every OTHER place in this module that restarts the service does
        so as a side effect of some OTHER fix (extension toggle, NTLMv2 fix, TemplatesTimestamp sync) -
        this is the first standalone entry point for "just restart it," a common first troubleshooting
        step in its own right that shouldn't require going through one of those other flows first.

    .DESCRIPTION
        Same `Restart-Service -Name IAS -Force` call and confirmation-before-acting convention already
        established elsewhere in this module (Invoke-ToggleNPSExtensionRegistry etc.) - "IAS" (not
        "NPS") is the service's real internal name, verified via web search, not guessed. Shows current
        status first so the tech isn't restarting blind.
    #>
    try {
        $svc = Get-Service -Name IAS -ErrorAction Stop
        Write-Host "Current status: $($svc.Status)" -ForegroundColor $(if ($svc.Status -eq 'Running') { 'Green' } else { 'Yellow' })
    } catch {
        Write-Host "Could not query the service - $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    $confirm = Read-Host "Restart the Network Policy Server service now? (Y/N)"
    if ($confirm -match '^[Yy]') {
        try {
            Restart-Service -Name IAS -Force
            Write-Host "Service restarted." -ForegroundColor Green
        } catch {
            Write-Host "ERROR restarting service: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Cancelled." -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
function Invoke-IASConfigBootstrapPrompt {
    <#
    .SYNOPSIS
        Confirm-then-run wrapper around Initialize-IASConfigFile (NPSCore.ps1) - the "ias.xml chicken/
        egg, take 2" shortcut (2026-09-03, per the maintainer - a second tech's real run-through: "a brand new
        install doesn't have an ias.xml... completely synthesized until you add SOMETHING to the config
        via the GUI. We need a way to shortcut this."). Called both from Invoke-InstallAuthorizeNPS
        (Option 1, NPS-Manager.ps1) when starting the IAS service alone didn't produce ias.xml, and
        as its own standalone Troubleshooting menu action for a tech who hits this later (e.g. the
        service was already running with ias.xml still missing, or Option 1 wasn't the entry point
        that noticed).

    .DESCRIPTION
        Same confirm-before-acting convention as every other action-shaped function in this module -
        never silently forces a file write. Shows the real command via -WhatIf first (same pattern
        Invoke-InstallAuthorizeNPS's own AD-registration step already uses for Register-NPSServerInAD),
        so what's about to run is never a black box.
    #>
    param([string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml")

    if (Test-Path $IASConfigPath) {
        Write-Host "ias.xml already exists at $IASConfigPath - nothing to do." -ForegroundColor Green
        return
    }

    $preview = Initialize-IASConfigFile -IASConfigPath $IASConfigPath -WhatIf
    Write-Host "This forces IAS to write its current (still-default) config out to ias.xml, the same" -ForegroundColor Cyan
    Write-Host "effect as touching anything in the NPS MMC console once - without needing the GUI." -ForegroundColor Cyan
    Write-Host "Would run: $($preview.WouldRun)" -ForegroundColor Cyan
    $confirm = Read-Host "Force the initial ias.xml write now? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Gray
        return
    }

    try {
        $result = Initialize-IASConfigFile -IASConfigPath $IASConfigPath
        if ($result.Output) { Write-Host $result.Output }
        if ($result.Succeeded) {
            Write-Host "ias.xml now exists at $IASConfigPath." -ForegroundColor Green
        } else {
            Write-Host "netsh reported exit code $($result.ExitCode), and ias.xml still isn't there - see the output above." -ForegroundColor Red
        }
    } catch {
        Write-Host "ERROR forcing the ias.xml write: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
function Get-NPSNtlmv2CompatibilityState {
    <#
    .SYNOPSIS
        Reads the CURRENT "Enable NTLMv2 Compatibility" DWORD under
        HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy - confirmed live in the field
        (2026-08-13) as the actual root cause of a "no RADIUS auth requests succeed" outage at a site
        with CIS-hardened "LAN Manager authentication level: Send NTLMv2 response only. Refuse LM &
        NTLM" enforced domain-wide. NPS's own legacy RemoteAccess Policy engine - the same component
        that does the Netlogon/MSV1_0 pass-through credential check for MS-CHAPv2 - predates automatic
        NTLMv2 negotiation and defaults to attempting NTLM/LM unless this override tells it to use
        NTLMv2. Against a DC that refuses anything but NTLMv2, that mismatch surfaced as Event 4776
        error 0xC000006A (STATUS_WRONG_PASSWORD) even with a fully correct password - a genuinely
        confusing failure mode to trace back to this one DWORD; cost real investigation time.

    .DESCRIPTION
        Absent (not just 0) is the NORMAL/default state on a server that's never needed this override -
        confirmed by checking a known-working site that also has no value here at all. Missing
        does NOT by itself mean anything is wrong; it only matters at a site where the domain has ALSO
        been hardened to refuse NTLM/LM (see the hardening report elsewhere in this menu for that half
        of the picture) - this function is deliberately just the read, callers decide what it means.
    #>
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy'
    $result = [pscustomobject]@{
        Path     = $path
        Exists   = (Test-Path $path)
        ValueSet = $false
        Value    = $null
    }
    if ($result.Exists) {
        $prop = Get-ItemProperty -Path $path -Name 'Enable NTLMv2 Compatibility' -ErrorAction SilentlyContinue
        if ($null -ne $prop.'Enable NTLMv2 Compatibility') {
            $result.ValueSet = $true
            $result.Value = $prop.'Enable NTLMv2 Compatibility'
        }
    }
    return $result
}

# ---------------------------------------------------------------------------
function Set-NPSNtlmv2Compatibility {
    <#
    .SYNOPSIS
        Sets the "Enable NTLMv2 Compatibility" DWORD under
        HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy - see
        Get-NPSNtlmv2CompatibilityState's notes for what this actually does and why it matters.
        Does NOT restart the Network Policy Server service itself - same "never a hidden side effect"
        reasoning as Disable-NPSExtensionRegistry; a service restart gets its own explicit confirmation.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet(0, 1)][int]$Value
    )
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy'
    if (-not (Test-Path $path)) { throw "RemoteAccess\Policy key not found at '$path' - is the NPS/RRAS role installed?" }
    Set-ItemProperty -Path $path -Name 'Enable NTLMv2 Compatibility' -Value $Value -Type DWord
    return [pscustomobject]@{ Path = $path; Value = $Value }
}

# ---------------------------------------------------------------------------
function Invoke-NPSNtlmv2CompatibilityCheck {
    <#
    .SYNOPSIS
        The interactive dashboard flow for checking/fixing "Enable NTLMv2 Compatibility" - see
        Get-NPSNtlmv2CompatibilityState's notes for the full story of why this matters. Offered as a
        deliberate, confirmed action (never silently applied) - same pattern as every other
        registry-touching fix in this menu.
    #>
    $state = Get-NPSNtlmv2CompatibilityState
    if (-not $state.Exists) {
        Write-Host "RemoteAccess\Policy key not found - is the NPS/RRAS role installed?" -ForegroundColor Red
        return
    }

    if ($state.ValueSet -and $state.Value -eq 1) {
        Write-Host "Enable NTLMv2 Compatibility is already set to 1 - NPS's RemoteAccess Policy engine" -ForegroundColor Green
        Write-Host "is using NTLMv2 for its own internal credential pass-through. Nothing to do." -ForegroundColor Green
        return
    }

    $currentLabel = if ($state.ValueSet) { $state.Value } else { '(not set - default)' }
    Write-Host "Current value: $currentLabel" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "This DWORD controls whether NPS's own legacy RemoteAccess Policy engine - the same" -ForegroundColor Gray
    Write-Host "component that validates MS-CHAPv2 credentials via a Netlogon/MSV1_0 pass-through to the" -ForegroundColor Gray
    Write-Host "DC - uses NTLMv2 for that internal check, instead of defaulting to older NTLM/LM. If this" -ForegroundColor Gray
    Write-Host "domain's DCs are hardened to REFUSE anything but NTLMv2 (LAN Manager authentication" -ForegroundColor Gray
    Write-Host "level = 'Send NTLMv2 response only. Refuse LM & NTLM', or similar), leaving this unset can" -ForegroundColor Gray
    Write-Host "cause EVERY RADIUS auth request to fail with what looks like a wrong password (DC Event" -ForegroundColor Gray
    Write-Host "4776, error 0xC000006A) even when the password is correct - confirmed live in the field" -ForegroundColor Gray
    Write-Host "on 2026-08-13. Setting it to 1 is a security IMPROVEMENT, not a downgrade - it makes NPS" -ForegroundColor Gray
    Write-Host "speak the stronger protocol the DC already requires, instead of quietly failing." -ForegroundColor Gray
    Write-Host ""

    $confirm = Read-Host "Set 'Enable NTLMv2 Compatibility' to 1 now? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Skipped." -ForegroundColor Gray; return }

    Set-NPSNtlmv2Compatibility -Value 1 | Out-Null
    Write-Host "Set to 1." -ForegroundColor Green

    $restartConfirm = Read-Host "Restart the Network Policy Server service now, to apply this? (Y/N)"
    if ($restartConfirm -match '^[Yy]') {
        try { Restart-Service -Name IAS -Force; Write-Host "Service restarted." -ForegroundColor Green }
        catch { Write-Host "ERROR restarting service: $($_.Exception.Message)" -ForegroundColor Red }
    } else {
        Write-Host "Not restarted - this won't take effect until the service is restarted." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
function ConvertTo-NPSTemplatesTimestampValue {
    <#
    .SYNOPSIS
        Encodes a UTC DateTime into ias.xml's "high,low" TemplatesTimestamp format - a Windows FILETIME
        split into two comma-separated signed 32-bit integers (high DWORD first, then low DWORD).

    .DESCRIPTION
        Uses BitConverter to split the 64-bit FILETIME, NOT [int32]($ft -band 0xFFFFFFFF)/-shr - that
        approach throws an OverflowException whenever the relevant 32 bits have the high bit set,
        since PowerShell's [int32] cast is checked, unlike a C-style unchecked cast. Also, separately,
        0xFFFFFFFF as a bare hex literal parses as a negative Int32 (-1) in PowerShell and sign-extends
        across the full 64 bits when ANDed against an Int64, silently turning the mask into a no-op.
        Both cost real debugging time against a live corrupted value in the field before landing on
        this approach - worth keeping this exact method, not "simplifying" back to bitwise operators.
    #>
    param([Parameter(Mandatory)][DateTime]$UtcDateTime)
    $ft = $UtcDateTime.ToFileTimeUtc()
    $bytes = [BitConverter]::GetBytes($ft)
    $low  = [BitConverter]::ToInt32($bytes, 0)
    $high = [BitConverter]::ToInt32($bytes, 4)
    return "$high,$low"
}

# ---------------------------------------------------------------------------
function ConvertFrom-NPSTemplatesTimestampValue {
    <#
    .SYNOPSIS
        Decodes ias.xml's "high,low" TemplatesTimestamp format back into a UTC DateTime - the reverse
        of ConvertTo-NPSTemplatesTimestampValue. Verified live against a real working ias.xml: the
        decoded value matched its paired iastemplates.xml's actual LastWriteTimeUtc exactly.
    #>
    param([Parameter(Mandatory)][string]$RawValue)
    $parts = $RawValue -split ','
    if ($parts.Count -ne 2) { throw "TemplatesTimestamp value '$RawValue' isn't in the expected 'high,low' shape." }
    $highBytes = [BitConverter]::GetBytes([int32]$parts[0])
    $lowBytes  = [BitConverter]::GetBytes([int32]$parts[1])
    $ft = [BitConverter]::ToInt64(($lowBytes + $highBytes), 0)
    return [DateTime]::FromFileTimeUtc($ft)
}

# ---------------------------------------------------------------------------
function Get-NPSTemplatesTimestampState {
    <#
    .SYNOPSIS
        Compares ias.xml's cached TemplatesTimestamp field against iastemplates.xml's actual current
        LastWriteTimeUtc. iastemplates.xml is assumed to be ias.xml's sibling (same directory) - the
        same convention this whole module already uses elsewhere.

    .DESCRIPTION
        TemplatesTimestamp is a cached snapshot NPS itself writes when it last synced with
        iastemplates.xml - this tool's own raw-text-splice writes to ias.xml never touch it, so it
        silently goes stale the moment iastemplates.xml changes (by hand, by netsh, or via this tool's
        own template CRUD functions) after ias.xml was last saved.

        Confirmed live in the field (2026-08-13): this drift is real and reproducible, but drift alone
        was NOT proven to be what actually broke that specific incident's NPS startup (traced to
        something else, still unresolved as of this writing). Surfaced here anyway because it's a real,
        cheap-to-check, cheap-to-fix inconsistency worth correcting on general principle, not because
        it's a confirmed fix for any specific symptom.
    #>
    param([Parameter(Mandatory)][string]$IASConfigPath)

    $templatesPath = Join-Path -Path (Split-Path -Path $IASConfigPath -Parent) -ChildPath "iastemplates.xml"
    $result = [pscustomobject]@{
        IASConfigPath      = $IASConfigPath
        TemplatesPath      = $templatesPath
        IASExists          = (Test-Path $IASConfigPath)
        TemplatesExists    = (Test-Path $templatesPath)
        CachedValueRaw     = $null
        CachedValueUtc     = $null
        ActualTemplatesUtc = $null
        InSync             = $false
    }
    if (-not $result.IASExists -or -not $result.TemplatesExists) { return $result }

    $content = Get-Content -Path $IASConfigPath -Raw
    $m = [regex]::Match($content, 'TemplatesTimestamp[^>]*>([^<]*)<')
    if ($m.Success) {
        $result.CachedValueRaw = $m.Groups[1].Value
        try { $result.CachedValueUtc = ConvertFrom-NPSTemplatesTimestampValue -RawValue $result.CachedValueRaw } catch {}
    }
    $result.ActualTemplatesUtc = (Get-Item $templatesPath).LastWriteTimeUtc

    # Compared to the SECOND, not millisecond - FILETIME's 100ns resolution vs. filesystem timestamp
    # rounding means an exact tick-for-tick match isn't guaranteed even when nothing is actually
    # stale; a couple seconds' difference is noise, not drift.
    if ($result.CachedValueUtc) {
        $diff = [Math]::Abs(($result.ActualTemplatesUtc - $result.CachedValueUtc).TotalSeconds)
        $result.InSync = ($diff -lt 2)
    }
    return $result
}

# ---------------------------------------------------------------------------
function Set-NPSTemplatesTimestamp {
    <#
    .SYNOPSIS
        Recomputes and writes ias.xml's TemplatesTimestamp field to match iastemplates.xml's actual
        CURRENT LastWriteTimeUtc - see Get-NPSTemplatesTimestampState for the full story. Backs up
        first (Save-NPSConfig -> Backup-NPSConfig) and preserves the source file's own detected
        encoding - same discipline as every other ias.xml write in this codebase.
    #>
    param([Parameter(Mandatory)][string]$IASConfigPath)

    $templatesPath = Join-Path -Path (Split-Path -Path $IASConfigPath -Parent) -ChildPath "iastemplates.xml"
    if (-not (Test-Path $templatesPath)) { throw "iastemplates.xml not found at '$templatesPath' - nothing to sync against." }

    $config = Read-NPSConfig -Path $IASConfigPath
    $newValue = ConvertTo-NPSTemplatesTimestampValue -UtcDateTime (Get-Item $templatesPath).LastWriteTimeUtc

    $fixed = [regex]::Replace($config.RawContent, '(TemplatesTimestamp[^>]*>)[^<]*(<)',
        [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $m.Groups[1].Value + $newValue + $m.Groups[2].Value })

    $backupPath = Save-NPSConfig -Path $IASConfigPath -RawContent $fixed -Encoding $config.Encoding
    return [pscustomobject]@{ NewValue = $newValue; BackupPath = $backupPath }
}

# ---------------------------------------------------------------------------
function Invoke-NPSTemplatesTimestampCheck {
    <#
    .SYNOPSIS
        The interactive dashboard flow for checking/fixing ias.xml's TemplatesTimestamp drift against
        iastemplates.xml - see Get-NPSTemplatesTimestampState's notes for what this is, and (honestly)
        what it ISN'T confirmed to fix by itself.
    #>
    param([Parameter(Mandatory)][string]$IASConfigPath)

    $state = Get-NPSTemplatesTimestampState -IASConfigPath $IASConfigPath
    if (-not $state.IASExists) { Write-Host "ias.xml not found at $IASConfigPath." -ForegroundColor Red; return }
    if (-not $state.TemplatesExists) { Write-Host "iastemplates.xml not found at $($state.TemplatesPath)." -ForegroundColor Red; return }
    if (-not $state.CachedValueRaw) {
        Write-Host "No TemplatesTimestamp field found in ias.xml - nothing to check." -ForegroundColor Yellow
        return
    }

    Write-Host "ias.xml's cached value:         $($state.CachedValueUtc)" -ForegroundColor $(if ($state.InSync) { 'Green' } else { 'Yellow' })
    Write-Host "iastemplates.xml's actual time: $($state.ActualTemplatesUtc)" -ForegroundColor $(if ($state.InSync) { 'Green' } else { 'Yellow' })

    if ($state.InSync) {
        Write-Host "`nIn sync - nothing to do." -ForegroundColor Green
        return
    }

    Write-Host ""
    Write-Host "These are out of sync - ias.xml's cached snapshot of when iastemplates.xml was last" -ForegroundColor Yellow
    Write-Host "modified doesn't match its real current state. This drift alone isn't confirmed to break" -ForegroundColor Yellow
    Write-Host "NPS startup by itself (a real field incident with this exact drift traced to a" -ForegroundColor Yellow
    Write-Host "different, still-unresolved cause) - but it's cheap and safe to correct regardless." -ForegroundColor Yellow
    Write-Host ""

    $confirm = Read-Host "Recompute and fix TemplatesTimestamp now? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Skipped." -ForegroundColor Gray; return }

    try {
        $result = Set-NPSTemplatesTimestamp -IASConfigPath $IASConfigPath
        Write-Host "Fixed - new value: $($result.NewValue)" -ForegroundColor Green
        Write-Host "Backup saved to: $($result.BackupPath)" -ForegroundColor Gray
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# NPS RADIUS log reader - field list verified against Microsoft's own documented "database-compatible"
# log format (learn.microsoft.com "Interpret NPS Database Format Log Files"), NOT re-derived by
# guessing at the maintainer's original ReadRadiusLogs.ps1's unlabeled indices. Cross-checked directly against
# that script's existing (correctly-guessed) fields - Packet-Type, Reason-Code, and Authentication-Type
# enum values all matched exactly, confirming this really is the format his NPS servers write, and
# resolving what had been three genuinely unknown columns (14, 26, 61) - now known to be Client-Vendor,
# Class, and Provider-Type respectively.
$script:NPSLogFieldNames = @(
    'ComputerName', 'ServiceName', 'RecordDate', 'RecordTime', 'PacketType', 'UserName',
    'FullyQualifiedDistinguishedName', 'CalledStationID', 'CallingStationID', 'CallbackNumber',
    'FramedIPAddress', 'NASIdentifier', 'NASIPAddress', 'NASPort', 'ClientVendor', 'ClientIPAddress',
    'ClientFriendlyName', 'EventTimestamp', 'PortLimit', 'NASPortType', 'ConnectInfo', 'FramedProtocol',
    'ServiceType', 'AuthenticationType', 'PolicyName', 'ReasonCode', 'Class', 'SessionTimeout',
    'IdleTimeout', 'TerminationAction', 'EAPFriendlyName', 'AcctStatusType', 'AcctDelayTime',
    'AcctInputOctets', 'AcctOutputOctets', 'AcctSessionId', 'AcctAuthentic', 'AcctSessionTime',
    'AcctInputPackets', 'AcctOutputPackets', 'AcctTerminateCause', 'AcctMultiSsnID', 'AcctLinkCount',
    'AcctInterimInterval', 'TunnelType', 'TunnelMediumType', 'TunnelClientEndpt', 'TunnelServerEndpt',
    'AcctTunnelConn', 'TunnelPvtGroupID', 'TunnelAssignmentID', 'TunnelPreference', 'MSAcctAuthType',
    'MSAcctEAPType', 'MSRASVersion', 'MSRASVendor', 'MSCHAPError', 'MSCHAPDomain',
    'MSMPPEEncryptionTypes', 'MSMPPEEncryptionPolicy', 'ProxyPolicyName', 'ProviderType',
    'ProviderName', 'RemoteServerAddress', 'MSRASClientName', 'MSRASClientVersion'
)

$script:NPSPacketTypeNames = @{
    1 = 'Access-Request'; 2 = 'Access-Accept'; 3 = 'Access-Reject'; 4 = 'Accounting-Request'
    5 = 'Accounting-Response'; 11 = 'Access-Challenge'
}
$script:NPSAuthTypeNames = @{ 1 = 'PAP'; 2 = 'CHAP'; 3 = 'MS-CHAP'; 4 = 'MS-CHAP v2'; 5 = 'EAP'; 7 = 'None'; 8 = 'Custom' }
$script:NPSReasonCodeNames = @{
    0='Success'; 1='Internal error'; 2='Access denied'; 3='Malformed request'; 4='Global catalog unavailable'
    5='Domain unavailable'; 6='Server unavailable'; 7='No such domain'; 8='No such user'
    16='Authentication failure'; 17='Password change failure'; 18='Unsupported authentication type'
    32='Local users only'; 33='Password must change'; 34='Account disabled'; 35='Account expired'
    36='Account locked out'; 37='Invalid logon hours'; 38='Account restriction'
    48='Did not match network policy'; 49='Did not match connection request policy'
    64='Dial-in locked out'; 65='Dial-in disabled'; 66='Invalid authentication type'
    67='Invalid calling station'; 68='Invalid dial-in hours'; 69='Invalid called station'
    70='Invalid port type'; 71='Invalid restriction'; 80='No record'; 96='Session timed out'
    97='Unexpected request'
}
$script:NPSProviderTypeNames = @{ 0 = 'None'; 1 = 'Windows (local)'; 2 = 'RADIUS Proxy' }

# ---------------------------------------------------------------------------
function Get-NPSLogRotationInfo {
    <#
    .SYNOPSIS
        Reads ias.xml's Microsoft_Accounting section for the configured log directory and rotation
        setting - informational only. Deliberately does NOT use New_Log_Frequency to COMPUTE which
        filename is "currently active" (see Get-NPSActiveLogFiles for why - the documented enum for
        this value isn't published anywhere Microsoft-authoritative that could be found, so a
        best-effort label is shown here, but file SELECTION is driven by actually listing the log
        directory and sorting by recency instead - correct regardless of rotation scheme, and doesn't
        depend on getting this enum right).
    #>
    param([string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml")

    $raw = Get-Content -Path $IASConfigPath -Raw
    $freqMatch = [regex]::Match($raw, 'New_Log_Frequency[^>]*>([^<]*)<')
    $dirMatch  = [regex]::Match($raw, 'Log_File_Directory[^>]*>([^<]*)<')
    $sizeMatch = [regex]::Match($raw, 'New_Log_Size[^>]*>([^<]*)<')

    $freq = if ($freqMatch.Success) { $freqMatch.Groups[1].Value.Trim() } else { $null }
    # Best-effort label only, per the caveat above - not relied on for file selection.
    $freqLabel = switch ($freq) {
        '0' { 'Never (single unlimited-size file) [best-effort guess]' }
        '1' { 'Daily [best-effort guess]' }
        '2' { 'Weekly [best-effort guess]' }
        '3' { 'Monthly [best-effort guess]' }
        '4' { 'Yearly [best-effort guess]' }
        default { "Unknown value: $freq" }
    }

    $dir = if ($dirMatch.Success) { $dirMatch.Groups[1].Value.Trim() } else { $null }
    if ([string]::IsNullOrWhiteSpace($dir)) { $dir = "$env:SystemDrive\Windows\System32\LogFiles" }

    return [pscustomobject]@{
        LogFrequencyRaw   = $freq
        LogFrequencyLabel = $freqLabel
        LogDirectory      = $dir
        MaxSizeMB         = if ($sizeMatch.Success) { $sizeMatch.Groups[1].Value.Trim() } else { $null }
    }
}

# ---------------------------------------------------------------------------
function Get-NPSActiveLogFiles {
    <#
    .SYNOPSIS
        Lists every IN*.log file actually present in the log directory, sorted by LastWriteTime
        descending (most-recently-written first) - the robust way to find "the log currently in use"
        regardless of whatever rotation scheme is configured, since it's driven by what's really on
        disk rather than a computed/guessed filename.
    #>
    param([Parameter(Mandatory)][string]$LogDirectory)

    if (-not (Test-Path $LogDirectory)) { return @() }
    $files = Get-ChildItem -Path $LogDirectory -Filter 'IN*.log' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    return @($files)
}

# ---------------------------------------------------------------------------
function Read-NPSRadiusLog {
    <#
    .SYNOPSIS
        Parses one NPS database-compatible-format log file using the full, Microsoft-documented field
        list (see $script:NPSLogFieldNames above) - proper CSV parsing (Import-Csv, handles quoted
        commas correctly) rather than a naive .Split(',').

    .DESCRIPTION
        Every field $script:NPSLogFieldNames already knows how to name and decode is surfaced directly
        on the returned object - not just the 8-ish fields the dashboard's log viewer originally
        showed. Confirmed live (the maintainer, pasting side-by-side abbreviated-vs-desired examples) that the
        abbreviated view was hiding real, already-correctly-parsed data (RadiusServer, ServiceName,
        UserFQDN, CalledStationID, NASIdentifier, ClientVendor [his "Index14"], NASPortType,
        ConnectInfo, Class [his "?Unsure:26?"], the Connection Request Policy name) rather than that
        data not existing - this function was never the bottleneck, only what got displayed was. Both
        the RAW and DECODED form are kept side-by-side for the three enum-coded fields (PacketType,
        AuthenticationType/AuthType, ReasonCode) - the raw number is what actually got logged, the
        decoded label is what a human wants to read; neither replaces the other.

        _Raw is still included underneath everything - the complete, unmodified 60+-field row - as a
        safety net for anything genuinely exotic (e.g. accounting-only fields like AcctSessionTime)
        that this curated set doesn't promote to a first-class property.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) { throw "Log file not found: $Path" }

    $rows = Import-Csv -Path $Path -Header $script:NPSLogFieldNames
    $results = foreach ($row in $rows) {
        [pscustomobject]@{
            RadiusServer        = $row.ComputerName
            ServiceName         = $row.ServiceName
            RecordDate          = $row.RecordDate
            RecordTime          = $row.RecordTime
            PacketTypeRaw       = $row.PacketType
            PacketType          = if ($row.PacketType -ne '' -and $script:NPSPacketTypeNames.ContainsKey([int]$row.PacketType)) { $script:NPSPacketTypeNames[[int]$row.PacketType] } else { "Unknown ($($row.PacketType))" }
            UserName            = $row.UserName
            UserFQDN            = $row.FullyQualifiedDistinguishedName
            CalledStationID     = $row.CalledStationID
            CallingStationID    = $row.CallingStationID
            NASIdentifier       = $row.NASIdentifier
            NASIPAddress        = $row.NASIPAddress
            ClientVendor        = $row.ClientVendor
            ClientIPAddress     = $row.ClientIPAddress
            ClientFriendlyName  = $row.ClientFriendlyName
            NASPortType         = $row.NASPortType
            ConnectInfo         = $row.ConnectInfo
            # The actual VPN IP address assigned to the user on a successful connection - only ever
            # populated on the Accept row (an Access-Request/Reject has nothing to assign yet), same
            # "blank unless this row is the one that would carry it" shape as UserName/ReasonCode
            # already have elsewhere in this object. Added 2026-08-26 per the maintainer - previously only
            # reachable via _Raw, not a first-class property.
            FramedIPAddress     = $row.FramedIPAddress
            AuthenticationType  = if ($row.AuthenticationType -and $script:NPSAuthTypeNames.ContainsKey([int]$row.AuthenticationType)) { $script:NPSAuthTypeNames[[int]$row.AuthenticationType] } else { $row.AuthenticationType }
            # Which specific EAP method (e.g. "Microsoft: Protected EAP (PEAP)") - AuthenticationType
            # above only says the generic "EAP" bucket; this is the thing that actually distinguishes
            # a plain EAP flow from the Entra NPS Extension's own EAP type. Blank whenever the auth
            # flow isn't EAP at all (PAP/CHAP/MS-CHAP). Added 2026-08-26 per the maintainer, same reasoning as
            # FramedIPAddress above.
            EAPFriendlyName     = $row.EAPFriendlyName
            # Whatever the NAS itself sent for the connecting client software - NOT guaranteed to be
            # populated (depends entirely on what the FortiGate chooses to send in these RADIUS
            # attributes), but when it is, this is potentially the actual FortiClient version string -
            # valuable enough for an MSP that tracks FortiClient versions to surface even though it's
            # not a sure thing. Added 2026-08-26 per the maintainer, same reasoning as the two fields above.
            MSRASClientName     = $row.MSRASClientName
            MSRASClientVersion  = $row.MSRASClientVersion
            PolicyName          = $row.PolicyName
            ReasonCodeRaw       = $row.ReasonCode
            ReasonCode          = if ($row.ReasonCode -ne '' -and $script:NPSReasonCodeNames.ContainsKey([int]$row.ReasonCode)) { $script:NPSReasonCodeNames[[int]$row.ReasonCode] } else { $row.ReasonCode }
            Class               = $row.Class
            ProxyPolicyName     = $row.ProxyPolicyName
            ProviderType        = if ($row.ProviderType -ne '' -and $script:NPSProviderTypeNames.ContainsKey([int]$row.ProviderType)) { $script:NPSProviderTypeNames[[int]$row.ProviderType] } else { $row.ProviderType }
            _Raw                = $row
        }
    }
    return @($results)
}

# ---------------------------------------------------------------------------
function Get-NPSRadiusLogGroupKey {
    <#
    .SYNOPSIS
        Computes the same Connection-Request/Network-Request correlation key Format-NPSRadiusLogPairs
        groups on, as a standalone function so a username filter can match by GROUP instead of by row
        (see Invoke-ReadRadiusLogsMenu's views 3/4) - filtering by row alone can silently drop a
        group's own response before it ever reaches the pairing logic, since NPS only writes UserName
        on the Access-Request half of a pair and UserFQDN's format isn't consistent even within one
        group (e.g. "DOMAIN\testvpn" on the Access-Request vs.
        "domain.local/MyBusiness/Users/O365/Test VPN" - space and all - on its own Access-Challenge/
        Access-Accept rows, confirmed live in a real sample, 2026-08-17). A dropped response row
        makes a real answer look like "no response logged," which is exactly the diagnostic this
        whole feature exists to get right.
    #>
    param([Parameter(Mandatory)]$Entry)
    if ($Entry._Raw.AcctSessionId) { "SID:$($Entry._Raw.AcctSessionId)" }
    else { "TS:$($Entry.RadiusServer)|$($Entry.RecordDate)|$($Entry.RecordTime)|$($Entry.UserFQDN)" }
}

# ---------------------------------------------------------------------------
function Format-NPSRadiusLogPairs {
    <#
    .SYNOPSIS
        Groups Read-NPSRadiusLog entries into Connection Request / Network Request pairs and renders
        each as a small two-column table (field name down the left, the two packets' values across)
        instead of two independent Format-List blocks - condenses "what went out" and "what came
        back" for one attempt onto one screen, and makes a MISSING Network Request (the request
        never reached a decision - discarded before Network Policy evaluation, e.g. an auth-method
        mismatch) visually obvious instead of just... not being there.

    .DESCRIPTION
        Pairs are grouped by AcctSessionId when the log actually wrote one (the field RADIUS itself
        designed for exactly this correlation) - falls back to RadiusServer+RecordDate+RecordTime+
        UserFQDN when it didn't (confirmed live against a real sample, 2026-08-17: roughly 15% of
        rows have no AcctSessionId at all - typically simpler non-EAP auth flows - but still land in
        the same second as their paired decision row).

        A group can hold more than 2 rows - a real EAP/MFA negotiation logs an Access-Challenge (11)
        row for each round-trip before the final Accept/Reject. This view deliberately stays
        two-column as asked: "Connection Request" is the FIRST Access-Request in the group,
        "Network Request" is the LAST Accept/Reject in the group (the actual outcome) - the
        challenge rounds in between aren't dropped from the data, just not given their own column
        here; a group's challenge count is called out in the pair's header line instead.
    #>
    param([Parameter(Mandatory)][array]$Entries)

    # Expanded 2026-08-26 per the maintainer ("still feels like we're missing some fields") - 4 fields were
    # already curated by Read-NPSRadiusLog but never added to this display list (RadiusServer,
    # ClientVendor, ClientIPAddress, PacketType - the last one resolves the "was the outcome actually
    # Accept or Reject" ambiguity that a plain unmapped ReasonCode number leaves open), and 4 more were
    # promoted from _Raw-only to first-class properties on that same function specifically for this
    # (FramedIPAddress, EAPFriendlyName, MSRASClientName, MSRASClientVersion - see that function's own
    # comments for what each one means and its caveats).
    $fieldsToShow = @(
        'RecordDate', 'RecordTime', 'RadiusServer',
        'UserName', 'UserFQDN',
        'CalledStationID', 'CallingStationID',
        'NASIdentifier', 'NASIPAddress', 'ClientVendor', 'ClientFriendlyName', 'ClientIPAddress',
        'NASPortType', 'ConnectInfo', 'FramedIPAddress',
        'AuthenticationType', 'EAPFriendlyName', 'MSRASClientName', 'MSRASClientVersion',
        'PolicyName', 'PacketType', 'ReasonCode', 'Class', 'ProxyPolicyName', 'ProviderType'
    )

    $groups = $Entries | Group-Object -Property { Get-NPSRadiusLogGroupKey -Entry $_ }

    foreach ($grp in $groups) {
        $req  = $grp.Group | Where-Object { $_.PacketType -eq 'Access-Request' } | Select-Object -First 1
        $resp = $grp.Group | Where-Object { $_.PacketType -in @('Access-Accept', 'Access-Reject') } | Select-Object -Last 1
        $challengeCount = @($grp.Group | Where-Object { $_.PacketType -eq 'Access-Challenge' }).Count

        $who  = if ($req) { $req.UserName } elseif ($resp) { $resp.UserFQDN } else { $grp.Group[0].UserFQDN }
        $when = "$($grp.Group[0].RecordDate) $($grp.Group[0].RecordTime)"
        $challengeNote = if ($challengeCount -gt 0) { " ($challengeCount challenge round-trip$(if ($challengeCount -ne 1) {'s'}))" } else { '' }
        Write-Host "`n=== $who @ $when$challengeNote ===" -ForegroundColor Cyan

        if (-not $req) {
            Write-Host "  (no Connection Request found - only a response was logged for this group)" -ForegroundColor Yellow
        }
        if (-not $resp) {
            Write-Host "  No Network Request logged - discarded before Network Policy evaluation" -ForegroundColor Yellow
            Write-Host "  (auth-method mismatch, EAP/cert failure, or a Connection Request Policy issue - check the Security log's own 6274 event for the reason)" -ForegroundColor Yellow
        }

        $rows = foreach ($f in $fieldsToShow) {
            [pscustomobject]@{
                Field                 = $f
                'Connection Request'  = if ($req)  { $req.$f }  else { '' }
                'Network Request'     = if ($resp) { $resp.$f } else { '(none)' }
            }
        }
        $rows | Format-Table -AutoSize | Out-Host
    }
}

# ---------------------------------------------------------------------------
function Invoke-ReadRadiusLogsMenu {
    <#
    .SYNOPSIS
        The interactive dashboard flow - shows rotation config, lists real files on disk (newest
        first), lets the tech pick one (default = newest), parses it, and offers simple filters
        (failures only, by username) since a raw multi-thousand-row dump isn't very "polished" on
        its own.

    .DESCRIPTION
        The username filter (views 3 and 4) matches on UserName OR UserFQDN, not UserName alone -
        confirmed live (the maintainer, real IN*.log sample, 2026-08-17) that NPS only writes UserName on the
        Access-Request row of a pair; the paired Access-Accept/Access-Reject row always leaves it
        blank (by design - that's how the raw log format works, not a parsing bug), while UserFQDN is
        populated on both. Filtering on UserName alone silently dropped every Accept/Reject row for a
        searched user - exactly half the real story for that session (the request went out, but you'd
        never see whether it was actually accepted or why it was rejected). Read-NPSRadiusLog itself
        was never the bottleneck here - confirmed it already parses every physical line 1:1 via
        Import-Csv - this was purely a downstream filter-predicate gap.
    #>
    param([string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml")

    Write-NPSHeader "RADIUS Log Reader"

    $rotationInfo = $null
    if (Test-Path $IASConfigPath) {
        try { $rotationInfo = Get-NPSLogRotationInfo -IASConfigPath $IASConfigPath } catch {}
    }
    $logDir = if ($rotationInfo) { $rotationInfo.LogDirectory } else { "$env:SystemDrive\Windows\System32\LogFiles" }

    if ($rotationInfo) {
        Write-Host "Configured rotation: $($rotationInfo.LogFrequencyLabel)" -ForegroundColor Cyan
        Write-Host "Log directory:       $($rotationInfo.LogDirectory)" -ForegroundColor Cyan
    }

    $files = Get-NPSActiveLogFiles -LogDirectory $logDir
    if ($files.Count -eq 0) {
        Write-Host "No IN*.log files found in $logDir." -ForegroundColor Yellow
        $manualDir = Read-Host "Enter a different log directory to search [Enter to cancel]"
        if ([string]::IsNullOrWhiteSpace($manualDir)) { return }
        $files = Get-NPSActiveLogFiles -LogDirectory $manualDir
        if ($files.Count -eq 0) { Write-Host "Still nothing found." -ForegroundColor Red; return }
    }

    Write-Host ""
    Write-Host "Log files found (newest first):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $files.Count; $i++) {
        $f = $files[$i]
        Write-Host ("    {0}. {1}  (modified {2:yyyy-MM-dd HH:mm}, {3:N0} KB)" -f ($i + 1), $f.Name, $f.LastWriteTime, ($f.Length / 1KB))
    }
    $sel = Read-Host "Pick a file by number [Enter for #1 = newest]"
    $idx = if ([string]::IsNullOrWhiteSpace($sel)) { 0 } else { ($sel -as [int]) - 1 }
    if ($idx -lt 0 -or $idx -ge $files.Count) { Write-Host "Invalid selection." -ForegroundColor Yellow; return }
    $picked = $files[$idx]

    Write-Host "Parsing $($picked.FullName) ..." -ForegroundColor Cyan
    try {
        $entries = Read-NPSRadiusLog -Path $picked.FullName
    } catch {
        Write-Host "ERROR parsing log: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    Write-Host "$($entries.Count) record(s) parsed." -ForegroundColor Green

    Write-Host ""
    Write-Host "  1. Show all records"
    Write-Host "  2. Show failures only (Access-Reject, or ReasonCode <> Success)"
    Write-Host "  3. Filter by username"
    Write-Host "  4. Show EVERY raw field (all 60+ log columns, not just the common ones below)"
    Write-Host "  M. Return to menu"
    $viewChoice = Read-Host "Select a view"

    $showAllRawFields = ($viewChoice -match '^4$')
    $toShow = switch -Regex ($viewChoice) {
        '^2$' { $entries | Where-Object { $_.PacketType -eq 'Access-Reject' -or ($_.ReasonCode -and $_.ReasonCode -ne 'Success') } }
        '^3$' {
            $uname = Read-Host "Username (partial match ok)"
            # Match by GROUP (Connection Request + its Network Request), not by individual row - NPS
            # only writes UserName on the Access-Request half of a pair, and UserFQDN's format isn't
            # even consistent within one group (see Get-NPSRadiusLogGroupKey's notes) - matching rows
            # in isolation can silently drop a real response before it ever reaches the pairing view,
            # making an answered request look unanswered.
            $matchedKeys = @($entries | Where-Object { $_.UserName -like "*$uname*" -or $_.UserFQDN -like "*$uname*" } |
                ForEach-Object { Get-NPSRadiusLogGroupKey -Entry $_ } | Select-Object -Unique)
            $entries | Where-Object { (Get-NPSRadiusLogGroupKey -Entry $_) -in $matchedKeys }
        }
        '^4$' {
            $uname = Read-Host "Filter by username first? (partial match ok, or Enter for all)"
            if ([string]::IsNullOrWhiteSpace($uname)) {
                $entries
            } else {
                $matchedKeys = @($entries | Where-Object { $_.UserName -like "*$uname*" -or $_.UserFQDN -like "*$uname*" } |
                    ForEach-Object { Get-NPSRadiusLogGroupKey -Entry $_ } | Select-Object -Unique)
                $entries | Where-Object { (Get-NPSRadiusLogGroupKey -Entry $_) -in $matchedKeys }
            }
        }
        default { $entries }
    }

    if ($showAllRawFields) {
        # Escape hatch to the COMPLETE, unmodified 60+-field row ($script:NPSLogFieldNames) - for the
        # rare case even the curated set below (already the full "what the maintainer asked for" field list,
        # not the old 8-field abbreviated view) is missing something exotic, e.g. an accounting-only
        # field on an Accounting-Request record. Left as an untouched per-record Format-List dump -
        # the paired Connection/Network table below only makes sense for the curated field set, this
        # view's whole point is seeing every raw column with nothing summarized away.
        $toShow | ForEach-Object { $_._Raw } | Format-List | Out-Host
    } else {
        # Condensed side-by-side: each Access-Request paired with its Access-Accept/Reject as a
        # two-column table (Connection Request / Network Request) instead of two separate per-record
        # Format-List dumps - makes a request that never got a Network Request answer (discarded
        # before Network Policy evaluation) visually obvious instead of just silently absent.
        Format-NPSRadiusLogPairs -Entries $toShow
    }

    Write-Host "$($toShow.Count) of $($entries.Count) record(s) shown." -ForegroundColor Gray
    Read-Host "Press Enter to continue"
}

# ---------------------------------------------------------------------------
function Get-NPSServiceStartFailureEvents {
    <#
    .SYNOPSIS
        Reads Service Control Manager events for the Network Policy Server service from the System
        log within the last -LookbackMinutes, newest first - 7023 (terminated with error), 7024
        (service-specific error), 7031 (crashed and was restarted), 7034 (terminated unexpectedly),
        and 7036 (entered running/stopped state, for context on the surrounding timeline).
    #>
    param([int]$LookbackMinutes = 60)
    $since = (Get-Date).AddMinutes(-$LookbackMinutes)
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $since } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.Message -match 'Network Policy Server' }
    return @($events | Sort-Object TimeCreated -Descending)
}

# ---------------------------------------------------------------------------
function Get-NPSEventWindow {
    <#
    .SYNOPSIS
        Pulls every System + Application log entry within +/- -WindowSeconds of -AroundTime - the
        technique that actually found the real failure signal during a live field investigation
        (2026-08-13). The generic 7023 event text alone never has more detail than its one line - no
        module name, no stack - but a companion event from the REAL failing component sometimes lands
        in the same tight window under a different Event ID/provider.
    #>
    param(
        [Parameter(Mandatory)][DateTime]$AroundTime,
        [int]$WindowSeconds = 10
    )
    $start = $AroundTime.AddSeconds(-$WindowSeconds)
    $end = $AroundTime.AddSeconds($WindowSeconds)
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; StartTime = $start; EndTime = $end } -ErrorAction SilentlyContinue
    return @($events | Sort-Object TimeCreated)
}

# ---------------------------------------------------------------------------
function Invoke-NPSServiceStartFailureReport {
    <#
    .SYNOPSIS
        Server-side sibling to the FCT toolkit's Test-FortiClientIKEv2Readiness.ps1 - pulls everything
        needed to START diagnosing "why won't the Network Policy Server service start" into one saved
        report, instead of manually hunting through Event Viewer across two logs one event at a time
        (the exact process a live field investigation went through by hand on 2026-08-13).

    .DESCRIPTION
        Confirmed live: the generic SCM 7023 event ("...service terminated with the following error:
        <text>") is a dead end for detail on its own - no module name, no stack, nothing beyond that
        one line, regardless of how many times you re-read it. What actually moves an investigation
        forward is (a) a tight-window dump of BOTH the System and Application logs around the exact
        failure timestamp, which THIS report automates, and, if that's still not enough, (b) an actual
        Process Monitor trace of the service-start attempt - which isn't something this function can
        run for you, so it prints the exact filter/steps that worked live instead of leaving that as
        undocumented tribal knowledge.

        Does not itself resolve anything - purely a "gather everything into one place fast" report,
        same spirit as the FCT client-side readiness script.
    #>
    param(
        [int]$LookbackMinutes = 60,
        [int]$WindowSeconds = 10,
        [string]$OutputPath = "$env:USERPROFILE\Desktop\NPS_ServiceStartFailure_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    )
    $sb = New-Object System.Text.StringBuilder
    function Add-Line([string]$Text = '') { [void]$sb.AppendLine($Text); Write-Host $Text }
    function Add-Section([string]$Title) { Add-Line ''; Add-Line "===== $Title =====" }

    Add-Section "Network Policy Server (IAS) - Current Service State"
    try {
        $svc = Get-Service -Name IAS -ErrorAction Stop
        Add-Line "Status:    $($svc.Status)"
        Add-Line "StartType: $($svc.StartType)"
    } catch {
        Add-Line "Could not query the IAS service - $($_.Exception.Message)"
    }

    Add-Section "Recent Service Control Manager Events (last $LookbackMinutes min)"
    $scmEvents = Get-NPSServiceStartFailureEvents -LookbackMinutes $LookbackMinutes
    if ($scmEvents.Count -eq 0) {
        Add-Line "No Network Policy Server-related SCM events found in this window."
    } else {
        foreach ($e in $scmEvents) {
            Add-Line ""
            Add-Line "[$($e.TimeCreated)] Id=$($e.Id)"
            Add-Line $e.Message
        }
    }

    $failureEvent = $scmEvents | Where-Object { $_.Id -in 7023, 7024, 7031, 7034 } | Select-Object -First 1
    if ($failureEvent) {
        Add-Section "Log Window Around the Most Recent Failure (+/- $WindowSeconds sec of $($failureEvent.TimeCreated))"
        $windowEvents = Get-NPSEventWindow -AroundTime $failureEvent.TimeCreated -WindowSeconds $WindowSeconds
        if ($windowEvents.Count -eq 0) {
            Add-Line "No other events found in this window."
        } else {
            foreach ($e in $windowEvents) {
                Add-Line ""
                Add-Line "[$($e.TimeCreated)] $($e.LogName) Id=$($e.Id) [$($e.ProviderName)] $($e.LevelDisplayName)"
                Add-Line $e.Message
            }
        }
    } else {
        Add-Section "No Explicit Failure Event Found"
        Add-Line "No 7023/7024/7031/7034 event in the last $LookbackMinutes minutes - if the service IS"
        Add-Line "currently failing, try again with a longer -LookbackMinutes, or trigger a fresh failure"
        Add-Line "first (Start-Service IAS) so this report actually captures it."
    }

    Add-Section "If This Isn't Enough - Process Monitor Capture"
    Add-Line "Confirmed live in the field (2026-08-13): the generic SCM error text alone was never"
    Add-Line "enough to find the real cause - an actual Procmon trace of the service-start attempt was"
    Add-Line "what it took. Steps:"
    Add-Line ""
    Add-Line "  1. Get Process Monitor (procmon.exe) onto this server."
    Add-Line "  2. Filter: Process Name is svchost.exe AND Command Line contains '-k netsvcs -p'"
    Add-Line "     (IAS shares this svchost group with many unrelated services - this filter is still"
    Add-Line "     noisy; that's expected, see step 7 for how to cut through it)."
    Add-Line "  3. Start capturing."
    Add-Line "  4. Run: Start-Service IAS   (to trigger the failure fresh, while capturing)"
    Add-Line "  5. Stop capturing the moment it fails."
    Add-Line "  6. Add a second filter: Result is not SUCCESS."
    Add-Line "  7. Save -> the filtered view -> CSV (choose 'events displayed using current filter',"
    Add-Line "     NOT 'all events' - an unfiltered capture is enormous and mostly unrelated noise)."
    Add-Line "  8. Scan the LAST ~30-50 rows before the process exits - that's almost always where the"
    Add-Line "     real answer is. Watch for a several-second gap in timestamps partway through - that's"
    Add-Line "     SCM killing and respawning the process; everything right before that gap is what"
    Add-Line "     actually matters, not whatever the fresh restart does afterward."

    $sb.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`nReport saved to: $OutputPath" -ForegroundColor Green
    return $OutputPath
}

# ---------------------------------------------------------------------------
function Show-NPSNtlmKerberosHardeningReport {
    <#
    .SYNOPSIS
        Read-only report of the local NTLM-related hardening settings most likely to interact badly
        with NPS's own legacy credential-validation path - see Get-NPSNtlmv2CompatibilityState's notes
        for the confirmed-real example of exactly this class of problem. Reads the actual EFFECTIVE
        registry values these GPO settings write to on THIS machine, not an RSOP/GPO report.

    .DESCRIPTION
        Deliberately read-only - every value here is GPO-driven, pushed from Active Directory; this
        tool should never silently change any of it (unlike Enable NTLMv2 Compatibility, which is
        NPS's own non-GPO-managed setting and safe to offer as a confirmed fix). Every value defaulting
        to "Not configured" is completely normal on a server whose domain hasn't specifically hardened
        NTLM - absence is not itself a problem, only relevant in combination with symptoms like the
        ones described in Get-NPSNtlmv2CompatibilityState's notes.

        Domain-wide "Restrict NTLM: NTLM authentication in this domain" is a DC-side setting
        (Netlogon\Parameters\RestrictNTLMInDomain, on the DOMAIN CONTROLLERS themselves, pushed by a
        GPO scoped to DCs) - this report can't see it from the NPS server without remote registry
        access to a DC, so it's called out explicitly as NOT checked rather than silently omitted.
    #>
    Write-Host "NTLM / Kerberos Hardening - Local Effective Settings" -ForegroundColor Cyan
    Write-Host "(Read-only - GPO-driven values are never changed by this tool. 'Not configured' is" -ForegroundColor Gray
    Write-Host "normal on a server whose domain hasn't specifically hardened NTLM.)" -ForegroundColor Gray
    Write-Host ""

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $msvPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

    $lmLevel = (Get-ItemProperty -Path $lsaPath -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel
    $lmLabel = switch ($lmLevel) {
        0 { 'Send LM & NTLM responses' }
        1 { 'Send LM & NTLM - use NTLMv2 session security if negotiated' }
        2 { 'Send NTLM response only' }
        3 { 'Send NTLMv2 response only' }
        4 { 'Send NTLMv2 response only. Refuse LM' }
        5 { 'Send NTLMv2 response only. Refuse LM & NTLM' }
        default { 'Not configured (OS default - varies by version)' }
    }
    Write-Host "LAN Manager authentication level: $lmLabel" -ForegroundColor $(if ($lmLevel -ge 4) { 'Yellow' } else { 'Gray' })
    if ($lmLevel -ge 4) {
        Write-Host "  (Refuses LM/NTLM - generally fine for NPS, but confirm NTLMv2 is actually being" -ForegroundColor Gray
        Write-Host "  negotiated end-to-end if auth starts failing after a change here.)" -ForegroundColor Gray
    }
    Write-Host ""

    foreach ($pair in @(
            @{ Name = 'NTLMMinClientSec'; Label = 'Minimum session security for NTLM SSP clients' }
            @{ Name = 'NTLMMinServerSec'; Label = 'Minimum session security for NTLM SSP servers' }
        )) {
        $val = (Get-ItemProperty -Path $msvPath -Name $pair.Name -ErrorAction SilentlyContinue).($pair.Name)
        if ($null -eq $val) {
            Write-Host "$($pair.Label): Not configured" -ForegroundColor Gray
        } else {
            $flags = @()
            if ($val -band 0x20000000) { $flags += 'Require NTLMv2 session security' }
            if ($val -band 0x20) { $flags += 'Require 128-bit encryption' }
            $flagLabel = if ($flags.Count -gt 0) { $flags -join '; ' } else { "raw value 0x$($val.ToString('X8'))" }
            Write-Host "$($pair.Label): $flagLabel" -ForegroundColor Yellow
        }
    }
    Write-Host ""
    Write-Host "  (Top suspect for a total, non-account-specific auth failure if either is set to require" -ForegroundColor Gray
    Write-Host "  NTLMv2 session security - unconfirmed as an actual NPS-breaker so far, but was the" -ForegroundColor Gray
    Write-Host "  leading theory before the real root cause at a prior client turned out to be the separate" -ForegroundColor Gray
    Write-Host "  Enable NTLMv2 Compatibility setting - see Option 11.)" -ForegroundColor Gray
    Write-Host ""

    foreach ($pair in @(
            @{ Name = 'RestrictSendingNTLMTraffic'; Label = 'Restrict NTLM: Outgoing NTLM traffic to remote servers'; Map = @{ 0 = 'Allow all'; 1 = 'Audit all'; 2 = 'Deny all' } }
            @{ Name = 'RestrictReceivingNTLMTraffic'; Label = 'Restrict NTLM: Incoming NTLM traffic'; Map = @{ 0 = 'Allow all'; 1 = 'Deny for domain accounts'; 2 = 'Deny all domain accounts' } }
            @{ Name = 'AuditReceivingNTLMTraffic'; Label = 'Restrict NTLM: Audit Incoming NTLM Traffic'; Map = @{ 0 = 'Disable'; 1 = 'Enable for domain accounts'; 2 = 'Enable for all accounts' } }
        )) {
        $val = (Get-ItemProperty -Path $msvPath -Name $pair.Name -ErrorAction SilentlyContinue).($pair.Name)
        if ($null -eq $val) {
            Write-Host "$($pair.Label): Not configured" -ForegroundColor Gray
        } else {
            $label = if ($pair.Map.ContainsKey($val)) { $pair.Map[$val] } else { "raw value $val" }
            # Deny/Audit are meaningfully different severities - only an actual Deny (not the Audit
            # variant, which never blocks anything) gets flagged red.
            $isDeny = ($pair.Name -ne 'AuditReceivingNTLMTraffic') -and ($val -eq 2 -or ($pair.Name -eq 'RestrictReceivingNTLMTraffic' -and $val -ge 1))
            $color = if ($isDeny) { 'Red' } elseif ($val -gt 0) { 'Yellow' } else { 'Gray' }
            Write-Host "$($pair.Label): $label" -ForegroundColor $color
        }
    }
    Write-Host ""
    Write-Host "NOT checked here (needs remote registry access to a DC, out of scope for a local check):" -ForegroundColor Gray
    Write-Host "  Restrict NTLM: NTLM authentication in this domain (Netlogon\Parameters\RestrictNTLMInDomain" -ForegroundColor Gray
    Write-Host "  on the domain controllers themselves) - ask your AD team, or check directly on a DC." -ForegroundColor Gray

    Write-Host ""
    Write-Host "Also worth checking (NPS-specific, not a GPO-driven NTLM setting): Option 11's" -ForegroundColor Cyan
    Write-Host "'Enable NTLMv2 Compatibility' check - confirmed live as the actual root cause of a total" -ForegroundColor Cyan
    Write-Host "RADIUS auth-failure outage at a site with hardening like what's shown above." -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
function Test-NPSClockSkew {
    <#
    .SYNOPSIS
        Checks this server's clock offset against -TargetServer (a DC, or any other reachable host)
        via "w32tm /stripchart" - confirmed live in the field (2026-08-13) as a real, working way to
        check this without needing WinRM/PSRemoting, just standard Windows time-service connectivity.

    .DESCRIPTION
        Kerberos requires client/DC clocks within 5 minutes (300 seconds) by default - a skew beyond
        that produces authentication failures with confusing generic .NET error text ("Either the
        target name is incorrect or the server has rejected the client credentials") that looks
        nothing like a time problem on its face. -MaxSkewSeconds defaults to 300 to match that default
        Kerberos tolerance.
    #>
    param(
        [Parameter(Mandatory)][string]$TargetServer,
        [int]$MaxSkewSeconds = 300
    )
    $raw = & w32tm /stripchart /computer:$TargetServer /dataonly /samples:1 2>&1 | Out-String
    $m = [regex]::Match($raw, 'Offset:\s*([+-]?[\d.]+)s')
    $result = [pscustomobject]@{
        TargetServer  = $TargetServer
        RawOutput     = $raw
        OffsetSeconds = $null
        WithinLimit   = $null
        Error         = $null
    }
    if (-not $m.Success) {
        $result.Error = "Could not parse an offset from w32tm's output - target may be unreachable, or w32tm's output format differs. Raw output:`n$raw"
        return $result
    }
    $result.OffsetSeconds = [double]$m.Groups[1].Value
    $result.WithinLimit = ([Math]::Abs($result.OffsetSeconds) -le $MaxSkewSeconds)
    return $result
}

# ---------------------------------------------------------------------------
function Invoke-NPSClockSkewCheck {
    <#
    .SYNOPSIS
        The interactive dashboard flow for Test-NPSClockSkew - prompts for a target if one isn't
        already known, reports the result plainly.
    #>
    param([string]$TargetServer)
    if ([string]::IsNullOrWhiteSpace($TargetServer)) {
        $TargetServer = Read-Host "Domain Controller (or any reachable host) to check clock skew against"
        if ([string]::IsNullOrWhiteSpace($TargetServer)) { Write-Host "Skipped." -ForegroundColor Gray; return }
    }
    Write-Host "Checking clock offset against '$TargetServer'..." -ForegroundColor Cyan
    $result = Test-NPSClockSkew -TargetServer $TargetServer
    if ($result.Error) {
        Write-Host $result.Error -ForegroundColor Red
        return
    }
    $color = if ($result.WithinLimit) { 'Green' } else { 'Red' }
    Write-Host "Offset: $($result.OffsetSeconds) seconds" -ForegroundColor $color
    if ($result.WithinLimit) {
        Write-Host "Within Kerberos' default 5-minute tolerance - clock skew is not a factor here." -ForegroundColor Green
    } else {
        Write-Host "OUTSIDE Kerberos' default 5-minute tolerance - this alone can cause confusing" -ForegroundColor Red
        Write-Host "authentication failures unrelated to credentials/passwords. Fix time sync first." -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
function Get-NPSRecentWindowsUpdates {
    <#
    .SYNOPSIS
        Lists recently-installed Windows Updates, newest first - confirmed live in the field
        (2026-08-13) as a fast, cheap way to spot "did an update land right around when this started
        failing" correlation before chasing anything more exotic. That specific correlation turned out
        to be a red herring that session (the real cause was unrelated), but it's still a legitimate,
        cheap first check worth automating rather than re-deriving it manually every time.
    #>
    param([int]$Count = 10)
    return @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First $Count)
}

# ---------------------------------------------------------------------------
function Show-NPSRecentWindowsUpdatesReport {
    <#
    .SYNOPSIS
        Displays Get-NPSRecentWindowsUpdates' results - optionally highlights updates installed
        on/after -SinceDate (e.g. when a problem started) so the correlation is visual, not something
        the tech has to eyeball-compare dates for.
    #>
    param(
        [int]$Count = 10,
        [Nullable[DateTime]]$SinceDate
    )
    $updates = Get-NPSRecentWindowsUpdates -Count $Count
    if ($updates.Count -eq 0) {
        Write-Host "No installed updates found via Get-HotFix." -ForegroundColor Yellow
        return
    }
    Write-Host "Most recent $($updates.Count) installed update(s):" -ForegroundColor Cyan
    $anyRecent = $false
    foreach ($u in $updates) {
        $isRecent = $SinceDate -and $u.InstalledOn -and ($u.InstalledOn -ge $SinceDate)
        if ($isRecent) { $anyRecent = $true }
        $color = if ($isRecent) { 'Yellow' } else { 'Gray' }
        $flag = if ($isRecent) { '  <<< on/after the date you gave' } else { '' }
        Write-Host ("  {0,-14} {1,-16} {2}{3}" -f $u.HotFixID, $u.InstalledOn, $u.Description, $flag) -ForegroundColor $color
    }
    if ($SinceDate -and -not $anyRecent) {
        Write-Host "`nNone of these were installed on/after $SinceDate - an update landing around your" -ForegroundColor Gray
        Write-Host "problem's start time isn't the explanation here." -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
function Invoke-NPSRecentWindowsUpdatesCheck {
    <#
    .SYNOPSIS
        The interactive dashboard flow for Show-NPSRecentWindowsUpdatesReport - optionally asks for a
        reference date/time (e.g. when a problem started) to highlight correlated updates against.
    #>
    $sinceInput = Read-Host "Highlight updates on/after a specific date? Enter it (e.g. 2026-08-13), or blank to just list recent updates"
    $sinceDate = $null
    if (-not [string]::IsNullOrWhiteSpace($sinceInput)) {
        try { $sinceDate = [DateTime]::Parse($sinceInput) }
        catch { Write-Host "Could not parse '$sinceInput' as a date - listing without highlighting." -ForegroundColor Yellow }
    }
    Show-NPSRecentWindowsUpdatesReport -SinceDate $sinceDate
}

# ---------------------------------------------------------------------------
function Get-NPSServerCertificates {
    <#
    .SYNOPSIS
        Lists certificates in LocalMachine\My - the store NPS's own PEAP/EAP-TLS server certificate
        must live in - with the properties that actually matter for that use: whether it has a private
        key (mandatory; NPS can't select a certificate for its EAP endpoint without one) and expiry.
    #>
    return @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Select-Object Subject, Thumbprint, NotBefore, NotAfter, HasPrivateKey)
}

# ---------------------------------------------------------------------------
function Show-NPSServerCertificateReport {
    <#
    .SYNOPSIS
        Read-only report of LocalMachine\My certificates - flags anything expired, expiring soon, or
        missing a private key, all of which make a certificate unusable/unreliable as NPS's PEAP/
        EAP-TLS server certificate. A configured server cert that can no longer be resolved is one
        documented cause of NPS startup failing with a generic "not found"-style error.
    #>
    param([int]$WarnDaysBeforeExpiry = 30)
    $certs = Get-NPSServerCertificates
    if ($certs.Count -eq 0) {
        Write-Host "No certificates found in LocalMachine\My." -ForegroundColor Yellow
        Write-Host "If any Network Policy here uses PEAP/EAP-TLS, NPS has nothing to select from." -ForegroundColor Yellow
        return
    }
    Write-Host "Certificates in LocalMachine\My ($($certs.Count)):" -ForegroundColor Cyan
    $now = Get-Date
    foreach ($c in $certs) {
        $daysLeft = [int]($c.NotAfter - $now).TotalDays
        $status = if ($now -gt $c.NotAfter) { 'EXPIRED' }
        elseif ($daysLeft -le $WarnDaysBeforeExpiry) { "expires in $daysLeft day(s)" }
        else { 'OK' }
        $color = if ($status -eq 'EXPIRED' -or -not $c.HasPrivateKey) { 'Red' }
        elseif ($status -ne 'OK') { 'Yellow' }
        else { 'Green' }
        $pkNote = if ($c.HasPrivateKey) { '' } else { '  [NO PRIVATE KEY - cannot be used as a server cert]' }
        Write-Host ("  {0}  ({1})  {2}{3}" -f $c.Subject, $c.Thumbprint, $status, $pkNote) -ForegroundColor $color
    }
    $usable = @($certs | Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt $now })
    if ($usable.Count -eq 0) {
        Write-Host "`nNo usable (private-key + not-expired) certificate found - if any Network Policy" -ForegroundColor Red
        Write-Host "here uses PEAP/EAP-TLS, this is very likely why." -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
function Get-NPSAuthFailureCorrelation {
    <#
    .SYNOPSIS
        Given a timestamp, pulls matching entries from every source a live investigation ended up
        manually cross-referencing one at a time: the RADIUS log (ReasonCode, via Read-NPSRadiusLog),
        this server's own NTLM Operational log, and - if -DCServer is given - that DC's NTLM
        Operational log and its Security log 4776 Credential Validation event. One call instead of
        four separate manual Event Viewer hunts.

    .DESCRIPTION
        -DCServer is optional and remote (Get-WinEvent -ComputerName) - needs the caller to already
        have working AD connectivity/credentials to that DC, same as everywhere else in this dashboard
        that reaches one. A failure reaching any ONE source is recorded in -Errors and does not stop
        the others from being collected - a DC being unreachable shouldn't hide what the RADIUS log
        and local NTLM log already show.
    #>
    param(
        [Parameter(Mandatory)][DateTime]$AroundTime,
        [int]$WindowSeconds = 30,
        [string]$RadiusLogPath,
        [string]$DCServer,
        [System.Management.Automation.PSCredential]$Credential
    )
    $result = [ordered]@{
        AroundTime       = $AroundTime
        WindowSeconds    = $WindowSeconds
        RadiusLogEntries = @()
        LocalNtlmEvents  = @()
        DCNtlmEvents     = @()
        DC4776Events     = @()
        Errors           = @()
    }
    $start = $AroundTime.AddSeconds(-$WindowSeconds)
    $end = $AroundTime.AddSeconds($WindowSeconds)

    if ($RadiusLogPath -and (Test-Path $RadiusLogPath)) {
        try {
            $entries = Read-NPSRadiusLog -Path $RadiusLogPath
            $result.RadiusLogEntries = @($entries | Where-Object {
                    try {
                        $ts = [DateTime]::Parse("$($_.RecordDate) $($_.RecordTime)")
                        $ts -ge $start -and $ts -le $end
                    } catch { $false }
                })
        } catch {
            $result.Errors += "RADIUS log: $($_.Exception.Message)"
        }
    }

    try {
        $result.LocalNtlmEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational'; StartTime = $start; EndTime = $end } -ErrorAction Stop)
    } catch {
        $result.Errors += "Local NTLM Operational log: $($_.Exception.Message)"
    }

    if ($DCServer) {
        $wevtParams = @{ ComputerName = $DCServer; ErrorAction = 'Stop' }
        if ($Credential) { $wevtParams['Credential'] = $Credential }
        try {
            $result.DCNtlmEvents = @(Get-WinEvent @wevtParams -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational'; StartTime = $start; EndTime = $end })
        } catch {
            $result.Errors += "DC NTLM Operational log ($DCServer): $($_.Exception.Message)"
        }
        try {
            $result.DC4776Events = @(Get-WinEvent @wevtParams -FilterHashtable @{ LogName = 'Security'; Id = 4776; StartTime = $start; EndTime = $end })
        } catch {
            $result.Errors += "DC Security 4776 ($DCServer): $($_.Exception.Message)"
        }
    }

    return [pscustomobject]$result
}

# ---------------------------------------------------------------------------
function Show-NPSAuthFailureCorrelation {
    <#
    .SYNOPSIS
        The interactive dashboard flow for Get-NPSAuthFailureCorrelation - prompts for a timestamp
        (and optionally a DC), auto-locates the currently-active RADIUS log the same way the RADIUS
        log reader does, then shows everything found side by side.
    #>
    param([string]$IASConfigPath)

    $tsInput = Read-Host "Timestamp to correlate around (e.g. '2026-08-13 14:22:05', or blank for now)"
    $aroundTime = $null
    if ([string]::IsNullOrWhiteSpace($tsInput)) {
        $aroundTime = Get-Date
    } else {
        try { $aroundTime = [DateTime]::Parse($tsInput) }
        catch { Write-Host "Could not parse '$tsInput' as a date/time." -ForegroundColor Red; return }
    }
    $dcInput = Read-Host "Domain Controller to also check DC-side logs on (blank to skip)"

    $radiusLogPath = $null
    if ($IASConfigPath -and (Test-Path $IASConfigPath)) {
        try {
            $rotationInfo = Get-NPSLogRotationInfo -IASConfigPath $IASConfigPath
            $logDir = if ($rotationInfo) { $rotationInfo.LogDirectory } else { $null }
            if ($logDir) {
                $activeFiles = Get-NPSActiveLogFiles -LogDirectory $logDir
                if ($activeFiles.Count -gt 0) { $radiusLogPath = $activeFiles[0].FullName }
            }
        } catch {}
    }

    Write-Host "`nCorrelating around $aroundTime (+/- 30 sec)..." -ForegroundColor Cyan
    $corr = Get-NPSAuthFailureCorrelation -AroundTime $aroundTime -WindowSeconds 30 -RadiusLogPath $radiusLogPath -DCServer $dcInput

    Write-Host "`n=== RADIUS Log ($(if ($radiusLogPath) { $radiusLogPath } else { 'not found' })) ===" -ForegroundColor Cyan
    if ($corr.RadiusLogEntries.Count -eq 0) {
        Write-Host "  No matching records in this window."
    } else {
        $corr.RadiusLogEntries | Select-Object RecordDate, RecordTime, UserName, PacketType, ReasonCodeRaw, ReasonCode | Format-Table -AutoSize | Out-Host
    }

    Write-Host "`n=== This Server's NTLM Operational Log ===" -ForegroundColor Cyan
    if ($corr.LocalNtlmEvents.Count -eq 0) {
        Write-Host "  No entries in this window."
    } else {
        $corr.LocalNtlmEvents | ForEach-Object { Write-Host "`n[$($_.TimeCreated)] Id=$($_.Id)"; Write-Host $_.Message }
    }

    if ($dcInput) {
        Write-Host "`n=== $dcInput's NTLM Operational Log ===" -ForegroundColor Cyan
        if ($corr.DCNtlmEvents.Count -eq 0) {
            Write-Host "  No entries in this window (or unreachable - see errors below)."
        } else {
            $corr.DCNtlmEvents | ForEach-Object { Write-Host "`n[$($_.TimeCreated)] Id=$($_.Id)"; Write-Host $_.Message }
        }

        Write-Host "`n=== $dcInput's Security Log - 4776 Credential Validation ===" -ForegroundColor Cyan
        if ($corr.DC4776Events.Count -eq 0) {
            Write-Host "  No entries in this window (or unreachable - see errors below)."
        } else {
            $corr.DC4776Events | ForEach-Object { Write-Host "`n[$($_.TimeCreated)]"; Write-Host $_.Message }
        }
    }

    if ($corr.Errors.Count -gt 0) {
        Write-Host "`n=== Errors ===" -ForegroundColor Yellow
        $corr.Errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    }
}
