<#
.SYNOPSIS
    Shared engine for NPSManager - reading/editing a live NPS (IAS) config XML in place, resolving
    AD group nesting, and building the standard 3-policy (IPSec-only / SSLVPN-only / Both)
    Network Policy + RADIUS Profile XML fragments.

.DESCRIPTION
    Reverse-engineered against real exports in NPSManager\Samples\*-NPSBackup.xml (netsh nps export
    format, same schema as the live C:\Windows\System32\ias\ias.xml the NPS/IAS service reads
    directly) - see each function's own notes for exactly what was verified and against which
    sample data point.

    This operates the same way NPSManager\SampleScript.ps1 (a reorder script found online, kept
    here as reference/prior art) does: load the live ias.xml as [xml], edit it in place, save it
    back - no netsh export/import round-trip. NPS watches ias.xml and picks up changes on its own.
    A timestamped backup is taken before every write (see Backup-NPSConfig) - this file gates a
    client's entire remote-access authentication, a bad edit here is not a "revert the commit" kind
    of mistake.

.NOTES
    THE "HEX HASH" FIELD - msRADIUSAnyVSA (Fortinet-Group-Name vendor-specific attribute), e.g.
    "01000030440110azuremfa_ikev2". Verified against every VSA value across both samples
    (12 distinct values, lengths 14-33 decimal). Format:
        01                          - fixed flag byte
        00003044                    - Fortinet's IANA enterprise number (12356 decimal) as 4 hex bytes
        01                          - Fortinet-Group-Name VSA type (always 1 in every sample seen)
        <2-digit hex>               - length byte = (ASCII value length + 2), uppercase when it
                                      contains A-F (confirmed via e.g. "vpnfw_rdp_northsidesubnet",
                                      25 chars -> 27 -> "1B")
        <ASCII value>               - the literal Fortinet group name, unmodified

    XML TAG SANITIZATION - NPS's exporter turns a policy/profile's display name into its XML tag by
    replacing every character that isn't [A-Za-z0-9_] with a single "_" (1:1, not collapsed - e.g.
    "IKE ONLY  - CBORDP" -> "IKE_ONLY____CBORDP", the double space + dash + space becomes 4
    underscores), THEN, separately, if the result still starts with a digit, that leading character
    is *also* replaced with "_" (XML names can't start with a digit) - e.g. "10a - RADIUS..." ->
    "_0a___RADIUS..." (only the leading "1" is replaced; the "0" right after it is not, since it's
    no longer in leading position). Verified against 7+ distinct real tag names in both samples,
    including ones with "&", "+", double spaces, and leading digits.

    A REAL PRODUCTION 3-POLICY BASELINE IS ASYMMETRIC - verified property-by-property against a real
    client's *-NPSBackup.xml sample. The Combined and IPSec-only RADIUS Profiles both carry
    msIgnoreUserDialinProperties=1 and msRASBapLinednLimit/Time; the SSLVPN-only profile carries
    neither. New-NPSProfileXmlFragment below reproduces this exactly per -Kind rather than treating
    all three as structurally identical.

    EVALUATION ORDER MATTERS - NPS matches top-down (lowest msNPSequence first) and stops at the
    first match. That reference client's Combined policy (seq=1) is evaluated before its IPSec-only (seq=2) and
    SSLVPN-only (seq=3) siblings - if the narrower ones came first, a user qualifying for BOTH
    groups would get caught by (e.g.) the SSLVPN-only policy first and never receive the IKEv2 VSA.
    Add-NPSPolicySet always emits Combined, then IPSecOnly, then SSLVPNOnly, in that relative order.

    FUTURE DIRECTION (not built yet, noted so it isn't lost) - Add-NPSPolicySet's current shape is
    "one BaseName -> exactly 3 parallel policies (Combined/IPSecOnly/SSLVPNOnly), each scoped by an
    IPSec-side and/or SSLVPN-side required-group set". That models real clients' *existing* baselines
    correctly, but per the maintainer: eventually this won't be about 3 parallel variants of one base name at
    all - it'll be about many distinct groups, each potentially needing its own independent policy
    shape (not just "the same 3-way split with different SIDs"). Don't design further generic-N-
    groups support into this module speculatively - when that need actually shows up, expect
    Add-NPSPolicySet's fixed Combined/IPSecOnly/SSLVPNOnly Kinds model to need real rethinking, not
    just another parameter.
#>

$script:FortinetVendorHex = "00003044"     # Fortinet IANA enterprise number 12356, as 4 hex bytes
$script:PeapPolicyEapType  = "1a000000000000000000000000000000"   # msNPAllowedEapType bin.hex - PEAP, constant across every sample profile
$script:ZeroGuid           = "{00000000-0000-0000-0000-000000000000}"
$script:XmlDtNs             = 'xmlns:dt="urn:schemas-microsoft-com:datatypes"'

# ---------------------------------------------------------------------------
function Set-ConsoleFullScreen {
    <#
    .SYNOPSIS
        Best-effort maximizes THIS console window, so a tech reading a multi-section menu isn't stuck
        squinting at whatever small window size Windows/the shortcut happened to open with.

    .DESCRIPTION
        UI Automation's WindowPattern.SetWindowVisualState(Maximized) - replaced the original
        GetForegroundWindow()+ShowWindowAsync(SW_MAXIMIZE) P/Invoke implementation (2026-08-21) after
        that Add-Type/DllImport(user32.dll) block was confirmed, via a real Microsoft Defender for
        Endpoint alert against IPSec-MasterOrchestrator.ps1 (see Examples_Sources\DefenderAlert.txt),
        to be the sole cause of 2 of 7 flagged ATT&CK capabilities ("Native API"/T1106, "Dynamic API
        Resolution"/T1027.007 - Add-Type compiling DllImport declarations IS, mechanically, dynamic
        native-method resolution at the CLR level, so the flag was technically accurate about
        mechanism even though nothing here ever called LoadLibrary/GetProcAddress by name). This
        version uses ZERO unmanaged interop - UIAutomationClient/UIAutomationTypes are standard,
        signed .NET Framework assemblies loaded via Add-Type -AssemblyName (the same API accessibility
        tools and UI test frameworks use to command a window's state directly), not a compiled
        P/Invoke block.

        Starts from AutomationElement.FocusedElement (nothing else has taken focus yet at script
        startup, so whatever currently has it should legitimately be this console/terminal - same
        reasoning that made the old implementation's GetForegroundWindow(), not GetConsoleWindow(),
        the right choice) - but confirmed live (2026-08-21) that FocusedElement itself resolves to a
        CHILD control inside the console (its text/input area), which doesn't support WindowPattern;
        only an element whose ControlType is actually Window does. Walks UP the automation tree
        (TreeWalker.ControlViewWalker.GetParent, repeatedly) from the focused element until a
        Window-type ancestor is found, then calls WindowPattern on THAT.

        Wrapped so it can't throw or block the menu from showing - a host with no real console window,
        no UI Automation support, or running under PowerShell 7+ (UIAutomationClient/Types are classic
        .NET Framework assemblies, not confirmed to resolve under pwsh/.NET) just stays whatever size
        it already was. Live-tested and confirmed working by the maintainer, 2026-08-21, before replacing the
        P/Invoke version everywhere - see project_console_fullscreen_menus memory for that version's
        own 5-round iteration history. Same helper as IPSEC AIO\SuperScriptBuilder\Modules\Helpers.ps1's
        own copy - identical, stateless utility, kept in both places since neither script tree
        dot-sources the other.
    #>
    try {
        Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
        Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop

        $focused = [System.Windows.Automation.AutomationElement]::FocusedElement
        if ($focused) {
            $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
            $current = $focused
            $windowElement = $null
            $hops = 0
            while ($current -and $hops -lt 15) {
                if ($current.Current.ControlType -eq [System.Windows.Automation.ControlType]::Window) {
                    $windowElement = $current
                    break
                }
                $current = $walker.GetParent($current)
                $hops++
            }
            if ($windowElement) {
                $patternObj = $null
                if ($windowElement.TryGetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern, [ref]$patternObj)) {
                    ([System.Windows.Automation.WindowPattern]$patternObj).SetWindowVisualState([System.Windows.Automation.WindowVisualState]::Maximized)
                }
            }
        }
    } catch {
        # Best-effort only.
    }
}

# ---------------------------------------------------------------------------
function ConvertTo-NPSXmlTagName {
    <#
    .SYNOPSIS
        Reproduces NPS's own display-name -> XML-tag-name sanitization. See module header NOTES.
    #>
    param([Parameter(Mandatory)][string]$DisplayName)

    $tag = [regex]::Replace($DisplayName, '[^A-Za-z0-9_]', '_')
    if ($tag -match '^[0-9]') { $tag = '_' + $tag.Substring(1) }
    return $tag
}

# ---------------------------------------------------------------------------
function Get-NPSPolicyContainerTag {
    <#
    .SYNOPSIS
        Maps the friendly, UI-facing -PolicyType value ('NetworkPolicy' / 'ConnectionRequest') to the
        real ias.xml container tag ('NetworkPolicy' / 'Proxy_Policies' - the latter is NPS's own
        legacy/IAS-era internal name for what the console calls "Connection Request Policies"). The
        ONE place this mapping lives - "Proxy_Policies" should never leak into UI-facing text anywhere
        else in this codebase, only ever "Connection Request Policy".
    #>
    param([Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType)
    if ($PolicyType -eq 'ConnectionRequest') { return 'Proxy_Policies' }
    return 'NetworkPolicy'
}

# ---------------------------------------------------------------------------
function New-FortinetGroupVSA {
    <#
    .SYNOPSIS
        Builds a msRADIUSAnyVSA hex string (Fortinet-Group-Name) for one FortiGate group name.
        See module header NOTES for the verified format.

    .PARAMETER ToLowerCase
        Defaults to $true - FortiGate's own local-group matching against Fortinet-Group-Name is CASE
        SENSITIVE (confirmed live, the maintainer), so a VSA value that doesn't exactly match the case of the
        group as configured on the FortiGate silently fails to place the user into it - auth still
        SUCCEEDS, they just don't land in the intended firewall group, which is about the worst kind
        of failure since nothing in NPS/RADIUS logs looks wrong. Lowercasing by default sidesteps the
        whole "AD group is 'AzureMFA_IKEv2', FortiGate group is 'azuremfa_ikev2'" mismatch outright -
        every real FortiGate group name sample seen is already all-lowercase. This is the guaranteed
        backstop (applies no matter which caller adds a VSA, present or future) - Get-VsaNamesForSide
        also normalizes at collection time so the wizard's own preview text isn't showing the tech a
        different case than what actually gets written. Pass -ToLowerCase:$false only if a specific
        VSA genuinely needs to preserve mixed case.
    #>
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [bool]$ToLowerCase = $true
    )

    if ($GroupName -notmatch '^[\x20-\x7E]+$') {
        throw "Group name '$GroupName' contains non-ASCII/control characters - Fortinet-Group-Name VSAs are plain ASCII only."
    }
    if ($ToLowerCase) { $GroupName = $GroupName.ToLowerInvariant() }
    $lengthByte = '{0:X2}' -f ($GroupName.Length + 2)
    return "01$($script:FortinetVendorHex)01$lengthByte$GroupName"
}

# ---------------------------------------------------------------------------
function Backup-NPSConfig {
    <#
    .SYNOPSIS
        Timestamped copy of the live (or sample/target) ias.xml before any edit, saved into a
        dedicated "ConfigBackups" subfolder next to it - NOT directly alongside the live file itself
        (see .DESCRIPTION for why that distinction is now load-bearing).

    .DESCRIPTION
        Used to save backups directly in the SAME directory as the live ias.xml (matching
        SampleScript.ps1's original backup-line convention). Confirmed live in the field (the maintainer,
        2026-08-13): a pile of "ias_BACKUP_*.xml"/"iastemplates_BACKUP_*.xml" files had accumulated
        directly in C:\Windows\System32\ias\ - inevitable, since this runs before EVERY single write
        this whole tool ever makes (Save-NPSConfig calls this before every one) - and the NPS/IAS
        service failed to start after a routine reboot with a generic COM "Member not found" error.
        Confirmed directly: removing the stray backup files from that directory let the service start
        again. NPS's own service startup apparently doesn't tolerate unexpected extra files sitting in
        its config directory. Every client this tool has EVER touched has been silently accumulating
        this exact landmine, waiting for their next reboot - this is the second real production outage
        this backup mechanism has caused (see Save-NPSConfig's own notes on the earlier encoding one).

        Self-healing: on every call, first sweeps any backups already sitting directly in $Path's
        directory (the old, dangerous location) into the new subfolder, best-effort - so simply using
        this tool normally clears the landmine at every already-deployed client automatically, without
        a tech needing to do the manual cleanup the maintainer did by hand in the field. A failed sweep (e.g.
        a locked file) must never block the backup THIS call actually needs to take.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) { throw "Cannot back up - '$Path' does not exist." }
    $dir = Split-Path -Path $Path -Parent
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $backupDir = Join-Path $dir 'ConfigBackups'
    if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }

    try {
        Get-ChildItem -Path $dir -Filter "${baseName}_BACKUP_*.xml" -File -ErrorAction SilentlyContinue | ForEach-Object {
            $dest = Join-Path $backupDir $_.Name
            if (-not (Test-Path $dest)) { Move-Item -Path $_.FullName -Destination $dest -Force -ErrorAction Stop }
        }
    } catch {
        Write-Warning "Could not fully sweep old backups out of '$dir' into '$backupDir' - $($_.Exception.Message)"
    }

    $backupPath = Join-Path $backupDir "${baseName}_BACKUP_$(Get-Date -Format 'MMddyy_HHmmss').xml"
    Copy-Item -Path $Path -Destination $backupPath -Force
    return $backupPath
}

# ---------------------------------------------------------------------------
function Get-NPSConfigBackups {
    <#
    .SYNOPSIS
        Lists every timestamped backup Backup-NPSConfig has taken for a given ias.xml, from its
        "ConfigBackups" subfolder (see Backup-NPSConfig's own notes on why backups no longer live
        directly alongside the live file), newest first - a backup exists for every single write this
        tool has ever made (Save-NPSConfig calls Backup-NPSConfig before every one), so this is
        normally a long list; callers should page/limit for display.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $dir = Join-Path (Split-Path -Path $Path -Parent) 'ConfigBackups'
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    if (-not (Test-Path $dir)) { return @() }

    return @(Get-ChildItem -Path $dir -Filter "${baseName}_BACKUP_*.xml" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
}

# ---------------------------------------------------------------------------
function Restore-NPSConfigFromBackup {
    <#
    .SYNOPSIS
        Restores ias.xml from one of its own timestamped backups (see Get-NPSConfigBackups) - the
        recovery counterpart to every mutating function's automatic pre-write backup.

    .DESCRIPTION
        Takes a fresh backup of the CURRENT (about-to-be-overwritten) state before restoring, same as
        every other write in this module - a restore is itself a write, and "I restored the wrong
        backup" needs the same undo path as any other mistake here, not a special exception.
        Validates the backup parses as XML before trusting it, for the same reason Save-NPSConfig's
        callers validate their fragments before writing - a corrupted/truncated backup file should
        fail loudly here, not get copied over a working live config.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$BackupPath
    )

    if (-not (Test-Path $BackupPath)) { throw "Backup not found at '$BackupPath'." }
    try {
        [xml](Get-Content -Path $BackupPath -Raw) | Out-Null
    } catch {
        throw "Backup at '$BackupPath' does not parse as valid XML - refusing to restore it. $($_.Exception.Message)"
    }

    $preRestoreBackup = if (Test-Path $Path) { Backup-NPSConfig -Path $Path } else { $null }
    Copy-Item -Path $BackupPath -Destination $Path -Force
    return [pscustomobject]@{ RestoredFrom = $BackupPath; PreRestoreBackup = $preRestoreBackup }
}

# ---------------------------------------------------------------------------
function Test-RSATAvailable {
    <#
    .SYNOPSIS
        Whether the ActiveDirectory PowerShell module (RSAT) is installed on this machine.
    #>
    return [bool](Get-Module -ListAvailable -Name ActiveDirectory)
}

# ---------------------------------------------------------------------------
function Install-RSATActiveDirectoryModule {
    <#
    .SYNOPSIS
        Installs the ActiveDirectory PowerShell module (RSAT) if it isn't already present.

    .DESCRIPTION
        Detects Server vs. client Windows and uses the right install path for each, since this tool
        realistically runs in both contexts - directly on the NPS server itself (almost always
        Windows Server), or from a tech's client workstation with RSAT installed for remote admin:
          - Windows Server: Install-WindowsFeature RSAT-AD-PowerShell (ServerManager module).
            A Domain Controller already has this via the AD DS role itself; this mainly matters for
            a member server running just NPS.
          - Windows client (10/11): Add-WindowsCapability -Online for the Rsat.ActiveDirectory.*
            Feature-on-Demand package - needs internet/WSUS reachability, and can be blocked by
            Group Policy (Feature-on-Demand install disabled), in which case this fails with a clear
            error rather than hanging.
        Requires an elevated session (both install cmdlets do) - both callers in this module already
        assume that.

    .OUTPUTS
        $true if the module is available after this call (including if it already was), $false
        otherwise - e.g. install succeeded but a restart is needed before it's usable, or the
        install itself failed.
    #>
    if (Test-RSATAvailable) {
        Write-Host "ActiveDirectory module is already available." -ForegroundColor Green
        return $true
    }

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "ERROR: Installing RSAT requires an elevated (administrator) session." -ForegroundColor Red
        return $false
    }

    $isServerOS = $false
    try {
        $isServerOS = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType -ne 1   # 1 = workstation
    } catch {
        Write-Host "Could not determine OS type ($($_.Exception.Message)) - assuming client OS." -ForegroundColor Yellow
    }

    if ($isServerOS -and (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
        Write-Host "Windows Server detected - installing RSAT-AD-PowerShell via Install-WindowsFeature..." -ForegroundColor Cyan
        try {
            $result = Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop
            if ($result.RestartNeeded -eq 'Yes') {
                Write-Host "Installed, but a RESTART is needed before the ActiveDirectory module can be used." -ForegroundColor Yellow
                return $false
            }
        } catch {
            Write-Host "Install-WindowsFeature failed - $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    } elseif (Get-Command Add-WindowsCapability -ErrorAction SilentlyContinue) {
        Write-Host "Windows client OS detected - installing RSAT: Active Directory tools via Add-WindowsCapability..." -ForegroundColor Cyan
        Write-Host "(Needs internet/WSUS reachability to download the Feature-on-Demand package.)" -ForegroundColor Gray
        try {
            $capability = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory*" -ErrorAction Stop | Select-Object -First 1
            if (-not $capability) { throw "Could not find an Rsat.ActiveDirectory.* capability on this machine." }
            Add-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "Add-WindowsCapability failed - $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Common causes: no internet/WSUS access, or Feature-on-Demand installs blocked by Group Policy." -ForegroundColor Yellow
            return $false
        }
    } else {
        Write-Host "Could not determine how to install RSAT on this OS - neither Install-WindowsFeature nor Add-WindowsCapability is available." -ForegroundColor Red
        return $false
    }

    # Re-import to pick up the freshly installed module in THIS session, if possible - some install
    # paths need a new session/restart regardless, hence the re-check rather than assuming success.
    try { Import-NPSActiveDirectoryModule } catch {}
    $nowAvailable = Test-RSATAvailable
    if ($nowAvailable) {
        Write-Host "ActiveDirectory module installed and available." -ForegroundColor Green
    } else {
        Write-Host "Install command completed, but the ActiveDirectory module still isn't available in this session - a new PowerShell session (or a restart) may be required." -ForegroundColor Yellow
    }
    return $nowAvailable
}

# ---------------------------------------------------------------------------
function Uninstall-RSATActiveDirectoryModule {
    <#
    .SYNOPSIS
        Removes the ActiveDirectory PowerShell module (RSAT) if present - the uninstall counterpart
        to Install-RSATActiveDirectoryModule, same Server-vs-client OS split in reverse
        (Remove-WindowsFeature / Remove-WindowsCapability). Mainly a troubleshooting/cleanup action -
        e.g. ruling out a corrupted RSAT install by removing and reinstalling it - not something a
        normal workflow needs.

    .OUTPUTS
        $true if the module is confirmed gone afterward (including if it was never installed),
        $false otherwise (removal failed, or a restart is needed before it's actually gone).
    #>
    if (-not (Test-RSATAvailable)) {
        Write-Host "ActiveDirectory module is not installed - nothing to remove." -ForegroundColor Green
        return $true
    }

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "ERROR: Removing RSAT requires an elevated (administrator) session." -ForegroundColor Red
        return $false
    }

    $isServerOS = $false
    try {
        $isServerOS = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType -ne 1   # 1 = workstation
    } catch {
        Write-Host "Could not determine OS type ($($_.Exception.Message)) - assuming client OS." -ForegroundColor Yellow
    }

    if ($isServerOS -and (Get-Command Remove-WindowsFeature -ErrorAction SilentlyContinue)) {
        Write-Host "Windows Server detected - removing RSAT-AD-PowerShell via Remove-WindowsFeature..." -ForegroundColor Cyan
        try {
            $result = Remove-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop
            if ($result.RestartNeeded -eq 'Yes') {
                Write-Host "Removed, but a RESTART is needed before it's fully gone." -ForegroundColor Yellow
                return $false
            }
        } catch {
            Write-Host "Remove-WindowsFeature failed - $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    } elseif (Get-Command Remove-WindowsCapability -ErrorAction SilentlyContinue) {
        Write-Host "Windows client OS detected - removing RSAT: Active Directory tools via Remove-WindowsCapability..." -ForegroundColor Cyan
        try {
            $capability = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory*" -ErrorAction Stop |
                Where-Object { $_.State -eq 'Installed' } | Select-Object -First 1
            if (-not $capability) { throw "Could not find an INSTALLED Rsat.ActiveDirectory.* capability to remove." }
            Remove-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "Remove-WindowsCapability failed - $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "Could not determine how to remove RSAT on this OS - neither Remove-WindowsFeature nor Remove-WindowsCapability is available." -ForegroundColor Red
        return $false
    }

    # The module can still show as "loaded" in THIS session even after removal until the session
    # restarts - Test-RSATAvailable checks Get-Module -ListAvailable (on-disk), not what's currently
    # imported, so this re-check is meaningful even though nothing un-imports it from this session.
    $stillAvailable = Test-RSATAvailable
    if (-not $stillAvailable) {
        Write-Host "Removed." -ForegroundColor Green
    } else {
        Write-Host "Removal command completed, but the module still shows as available - a restart may be required to fully complete it." -ForegroundColor Yellow
    }
    return (-not $stillAvailable)
}

# ---------------------------------------------------------------------------
function Import-NPSActiveDirectoryModule {
    <#
    .SYNOPSIS
        Imports the ActiveDirectory module the way that actually works at clients with flaky ADWS
        (Active Directory Web Services) - e.g. at a site with flaky ADWS, per the maintainer. Plain `Import-Module
        ActiveDirectory` auto-creates a default "AD:" PSDrive at import time, which requires an ADWS
        round-trip to establish - if ADWS is slow/misbehaving there, just IMPORTING the module can
        hang for a long time or fail outright, before any cmdlet is even called.

        Setting $Env:ADPS_LoadDefaultDrive = 0 before the import skips that default-drive creation
        entirely. None of this module's functions reference "AD:\" paths - they call cmdlets
        directly (Get-ADGroup, Get-ADPrincipalGroupMembership) - so the default drive was never
        actually needed here; skipping it removes a hang risk for free.

        Deliberately does NOT hardcode a server/DC - a working DC hostname is client-specific
        (the maintainer's own prior working snippet pointed at a real DC name for one specific client, which
        does not belong baked into a shared, multi-client tool). If normal DC auto-discovery is ALSO
        unreliable at a given client (not just the default-drive creation), pass -Server explicitly
        to Resolve-NestedADGroups/Get-ADGroupSID instead - both accept it and pass it straight
        through to the underlying cmdlets.

        Import-Module's own output is explicitly discarded (`$null =`) - it shouldn't normally emit
        anything to the success stream without -PassThru, but this function is called bare (no
        `| Out-Null`) from inside other functions that immediately build their OWN return value
        afterward (see Find-NPSADGroupsByWildcard) - any stray object this ever emitted would
        silently get prepended into THEIR return array too. Cheap insurance against exactly the kind
        of "why does my array have an extra unexpected element" bug that's a nightmare to diagnose
        once it's three call frames away from where it actually happened.
    #>
    $Env:ADPS_LoadDefaultDrive = 0
    $null = Import-Module ActiveDirectory -ErrorAction Stop
}

# ---------------------------------------------------------------------------
function Test-NPSADAuthError {
    <#
    .SYNOPSIS
        Heuristic check for whether an AD call's failure looks like a credentials/authentication
        problem, as opposed to something a credential retry wouldn't fix anyway (a typo'd/deleted
        group name, an unrelated network error, etc.) - confirmed live (the maintainer) exact wording: "The
        operation being requested was not performed because the user has not been authenticated."

        Lives here (the engine layer), not in NPSInteractive.ps1 (the interactive UI layer), even
        though it's only ever ACTED on by interactive code (offering Invoke-NPSADFallbackPrompt) -
        Resolve-NestedADGroups below needs it too, to decide whether to re-throw an auth-looking
        failure instead of silently swallowing it (see that function's own catch block), and
        NPSCore.ps1 must never depend on NPSInteractive.ps1 (the dependency only ever runs the other
        way - see NPSInteractive.ps1's own header).
    #>
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    return $ErrorRecord.Exception.Message -match 'not been authenticated|access is denied|logon failure|rejected the client credentials'
}

# ---------------------------------------------------------------------------
function Resolve-NestedADGroups {
    <#
    .SYNOPSIS
        Recursively walks a group's AD membership (the "is a member of" direction - same relationship
        GroupRelations.txt captured by hand) and returns every group found, deduplicated, excluding
        the starting group itself.

    .DESCRIPTION
        Requires the ActiveDirectory module (RSAT) and live AD connectivity - run from a DC or a
        machine with RSAT installed, same assumption MiscTools\Enable-LiveMode.ps1 already makes
        elsewhere in this framework (see Install-RSATActiveDirectoryModule above to install it on
        demand instead). Walks breadth-first so a cycle (which AD itself should prevent, but
        defensively) can't infinite-loop - each group is only expanded once.

    .PARAMETER Server
        Optional - a specific DC/server to query, passed straight through to
        Get-ADPrincipalGroupMembership. Leave blank for normal AD site/DC auto-discovery; only set
        this when discovery itself is unreliable at a given client (see Import-NPSActiveDirectoryModule
        above for the more common case - a slow/broken default PSDrive - which this does NOT require
        -Server to fix).

    .PARAMETER Credential
        Optional - confirmed live (the maintainer) as needed alongside -Server at a site where this
        session's own identity isn't valid/trusted against that DC ("The server has rejected the
        client credentials") - same credential captured once via Invoke-NPSADFallbackPrompt and
        reused for the rest of the session (see NPS-Manager.ps1's $script:ADCredential), not
        re-prompted for on every single AD-touching call.

        Confirmed live: passing a bare NAME STRING to Get-ADPrincipalGroupMembership -Identity (as
        this function's queue naturally produces) forces it to do an internal identity resolution
        first, and THAT internal step failed under -Credential with the same generic "not
        authenticated" error seen elsewhere in this session - even though Get-ADGroup -Identity with
        the exact same -Credential resolves the same name fine on its own (see Get-ADGroupSID, and
        Test-NPSServerRegistered's already-working Get-ADComputer-object-first pattern). Fixed the
        same way both of those already do it: resolve to a real AD object via Get-ADGroup first, THEN
        query membership on that object - never hand a bare string to
        Get-ADPrincipalGroupMembership -Identity when a credential is in play.
    #>
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    if (-not (Test-RSATAvailable)) {
        throw "The ActiveDirectory module (RSAT) is not available on this machine - run this from a DC or a machine with RSAT installed (or use Install-RSATActiveDirectoryModule to install it)."
    }
    Import-NPSActiveDirectoryModule

    $adParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $adParams['Server'] = $Server }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $seen  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[string]]::new()
    [void]$seen.Add($GroupName)
    $queue.Enqueue($GroupName)

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        try {
            # Resolve to a real object first (see .PARAMETER Credential above) - a bare name string
            # handed straight to Get-ADPrincipalGroupMembership -Identity is what broke under
            # -Credential, not this cmdlet itself.
            $currentGroup = Get-ADGroup -Identity $current @adParams
            $memberOf = Get-ADPrincipalGroupMembership -Identity $currentGroup @adParams
        } catch {
            # An auth-looking failure (see Test-NPSADAuthError) means the CREDENTIAL itself is bad -
            # every remaining item in the queue will fail the exact same way, so swallowing this and
            # continuing would just silently return an incomplete/empty result with nothing but an
            # easy-to-miss Write-Warning to explain why. Confirmed live (the maintainer): this is exactly what
            # let a genuinely broken credential slip past Get-VsaNamesForSide's own fallback-retry
            # logic undetected - that logic can only trigger on a THROWN exception, and this function
            # was never throwing one for this case. Re-throw here instead, so the caller's fallback
            # actually gets a chance to run. A non-auth failure (deleted/renamed group, etc.) is a
            # per-item problem, not a whole-session one - that case keeps the original skip-and-
            # continue behavior, since the rest of the queue is still worth walking.
            if (Test-NPSADAuthError -ErrorRecord $_) { throw }
            Write-Warning "Could not resolve group membership for '$current' - $($_.Exception.Message). Skipping its parents."
            continue
        }
        foreach ($parent in $memberOf) {
            if ($seen.Add($parent.Name)) {
                $results.Add([pscustomobject]@{ Name = $parent.Name; SID = $parent.SID.Value })
                $queue.Enqueue($parent.Name)
            }
        }
    }

    # @() wrap - same defensive reasoning applied everywhere else in this module: an empty
    # List[pscustomobject] returned bare can come back to the caller as $null instead of a real
    # empty collection (harmless for every current caller's `foreach`, which handles $null fine, but
    # inconsistent with this module's own established convention - see Get-NPSPolicySummary etc.).
    return @($results)
}

# ---------------------------------------------------------------------------
function Get-ADGroupSID {
    <#
    .SYNOPSIS
        Resolves a group name to its SID. Passes an already-SID-shaped string straight through
        unchanged, so callers can freely mix real group names and known SIDs in the same input list.

    .PARAMETER Server
        Optional - see Resolve-NestedADGroups's -Server notes. Passed straight through to Get-ADGroup.

    .PARAMETER Credential
        Optional - see Resolve-NestedADGroups's -Credential notes. Passed straight through to
        Get-ADGroup.
    #>
    param(
        [Parameter(Mandatory)][string]$GroupNameOrSID,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($GroupNameOrSID -match '^S-1-5-\d+(-\d+)+$') { return $GroupNameOrSID }

    if (-not (Test-RSATAvailable)) {
        throw "The ActiveDirectory module (RSAT) is not available on this machine - run this from a DC or a machine with RSAT installed (or use Install-RSATActiveDirectoryModule to install it)."
    }
    Import-NPSActiveDirectoryModule

    $adParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $adParams['Server'] = $Server }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $group = Get-ADGroup -Identity $GroupNameOrSID @adParams
    return $group.SID.Value
}

# ---------------------------------------------------------------------------
function Resolve-NPSGroupNameFromSid {
    <#
    .SYNOPSIS
        Resolves a SID back to its group's current display Name - the reverse of Get-ADGroupSID.
        Get-ADGroup -Identity already accepts a SID directly (the same underlying AD cmdlet
        capability Get-ADGroupSID's own pass-through case relies on), so this is a thin wrapper, not
        a new resolution mechanism. Used by Invoke-ReprocessNPSVsaWizard to turn an existing policy's
        already-recorded USERNTGROUPS SID(s) back into names Resolve-NestedADGroups can walk.
    #>
    param(
        [Parameter(Mandatory)][string]$Sid,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    if (-not (Test-RSATAvailable)) {
        throw "The ActiveDirectory module (RSAT) is not available on this machine - run this from a DC or a machine with RSAT installed (or use Install-RSATActiveDirectoryModule to install it)."
    }
    Import-NPSActiveDirectoryModule

    $adParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $adParams['Server'] = $Server }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $group = Get-ADGroup -Identity $Sid @adParams
    return $group.Name
}

# ---------------------------------------------------------------------------
function Get-NPSADOrganizationalUnitChildren {
    <#
    .SYNOPSIS
        Lists the immediate child OUs directly under -SearchBase (one level only, not recursive) -
        the fetch primitive Select-NPSADOrganizationalUnit's interactive browser calls fresh on every
        screen. Blank -SearchBase means the domain root itself.

    .PARAMETER Server
        Optional - see Resolve-NestedADGroups's -Server notes. Passed straight through to
        Get-ADOrganizationalUnit/Get-ADDomain.

    .PARAMETER Credential
        Optional - see Resolve-NestedADGroups's -Credential notes. Passed straight through to
        Get-ADOrganizationalUnit/Get-ADDomain.
    #>
    param(
        [string]$SearchBase,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    if (-not (Test-RSATAvailable)) {
        throw "The ActiveDirectory module (RSAT) is not available on this machine - run this from a DC or a machine with RSAT installed (or use Install-RSATActiveDirectoryModule to install it)."
    }
    Import-NPSActiveDirectoryModule

    $adParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $adParams['Server'] = $Server }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $base = if ($SearchBase) { $SearchBase } else { (Get-ADDomain @adParams).DistinguishedName }
    $children = @(Get-ADOrganizationalUnit -SearchBase $base -SearchScope OneLevel -Filter * @adParams | Sort-Object -Property Name)
    return [pscustomobject]@{ SearchBase = $base; Children = $children }
}

# ---------------------------------------------------------------------------
function Select-NPSADOrganizationalUnit {
    <#
    .SYNOPSIS
        Interactive text-based OU picker - navigate the domain's OU tree one level at a time (expand
        into a child, or go back up) and return the distinguishedName of whichever OU the tech lands
        on and confirms. Used by Read-ANDConditionGroups' "create this group" path to let the tech
        choose where a new AD group actually gets created, without needing a GUI OU picker (ADUC) or
        already knowing the target OU's full DN by heart.

    .DESCRIPTION
        Lazily fetches only the CURRENT level's children on each screen
        (Get-NPSADOrganizationalUnitChildren, SearchScope OneLevel) rather than walking the whole
        domain upfront - a real domain's OU tree can be deep and wide, and eagerly enumerating all of
        it just to pick one target would be slow and mostly wasted work. "Expand" is picking a
        numbered child; "collapse"/go back is 'B'; the CURRENT level (wherever navigation has landed,
        including the very first screen showing the domain root) is always selectable via 'S' -
        creating directly at the root is a legitimate, if unusual, choice and isn't blocked.

    .PARAMETER StartingDN
        Where to start browsing. Blank (the default) starts at the domain root.
    #>
    param(
        [string]$StartingDN,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $currentDN = $StartingDN
    # Stack of DNs visited on the way down, for 'B' (back up one level) - NOT a re-derivation from
    # $currentDN's own DN string (which would break for an OU whose name contains a comma, a legal
    # DN character escaped as "\," that a naive split-on-comma would mishandle).
    $history = [System.Collections.Generic.List[string]]::new()

    while ($true) {
        try {
            $level = Get-NPSADOrganizationalUnitChildren -SearchBase $currentDN -Server $Server -Credential $Credential
        } catch {
            Write-Host "Could not list child OUs under '$currentDN' - $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
        $currentDN = $level.SearchBase   # resolves blank -> the real domain-root DN, first time through
        $children = $level.Children

        Write-Host ""
        Write-Host "Current OU: $currentDN" -ForegroundColor Cyan
        if ($children.Count -eq 0) {
            Write-Host "    (no child OUs here)" -ForegroundColor Gray
        } else {
            for ($i = 0; $i -lt $children.Count; $i++) {
                Write-Host ("    {0}. {1}" -f ($i + 1), $children[$i].Name)
            }
        }
        Write-Host ""
        Write-Host "  S. Use THIS OU"
        if ($history.Count -gt 0) { Write-Host "  B. Back up one level" }
        Write-Host "  Q. Cancel"
        $sel = Read-Host "Select a number to browse into a child OU, or a letter"

        switch -Regex ($sel.Trim()) {
            '^[Ss]$' { return $currentDN }
            '^[Qq]$' { return $null }
            '^[Bb]$' {
                if ($history.Count -gt 0) {
                    $currentDN = $history[$history.Count - 1]
                    $history.RemoveAt($history.Count - 1)
                } else {
                    Write-Host "Already at the top." -ForegroundColor Yellow
                }
            }
            default {
                $idx = ($sel -as [int]) - 1
                if ($idx -ge 0 -and $idx -lt $children.Count) {
                    $history.Add($currentDN)
                    $currentDN = $children[$idx].DistinguishedName
                } else {
                    Write-Host "Invalid selection." -ForegroundColor Yellow
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
function New-NPSADGroup {
    <#
    .SYNOPSIS
        Creates a new AD security group (GlobalScope, Security category - the standard shape for a
        RADIUS/NPS access-gating group in this framework) in a chosen OU. Used when
        Read-ANDConditionGroups' wildcard search for a required group comes up with zero matches and
        the tech confirms it genuinely doesn't exist yet, rather than being a typo.

        See also: PushableTools\ADManager\ - if what's actually missing is a whole client's VPN group/
        OU structure (the main group + the shared VPNFW purpose groups), not just one RADIUS-condition
        group, AD-Manager's own scaffold (menu 2) + nesting (menu 3) is the fuller tool for that. This
        function stays the quick "one bare group, right here" path for a single condition term.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,   # target OU's distinguishedName
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )
    if (-not (Test-RSATAvailable)) {
        throw "The ActiveDirectory module (RSAT) is not available on this machine - run this from a DC or a machine with RSAT installed (or use Install-RSATActiveDirectoryModule to install it)."
    }
    Import-NPSActiveDirectoryModule

    $adParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $adParams['Server'] = $Server }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $group = New-ADGroup -Name $Name -Path $Path -GroupScope Global -GroupCategory Security -PassThru @adParams
    return $group
}

# ---------------------------------------------------------------------------
function Get-NPSRequiredGroupSidsFromConstraints {
    <#
    .SYNOPSIS
        Extracts every SID referenced by USERNTGROUPS(...) conditions in a policy's Constraints
        array (see Get-NPSPolicySummary) - flattened and deduplicated across every AND'd/OR'd entry.
        Feeds Invoke-ReprocessNPSVsaWizard, which doesn't care about the original AND/OR structure,
        only "which groups actually matter for this rule's VSAs".
    #>
    param([AllowEmptyCollection()][string[]]$Constraints = @())

    $sids = [System.Collections.Generic.List[string]]::new()
    foreach ($c in $Constraints) {
        $m = [regex]::Match($c, '^USERNTGROUPS\((.*)\)$')
        if (-not $m.Success) { continue }
        foreach ($quoted in [regex]::Matches($m.Groups[1].Value, '"([^"]*)"')) {
            $sid = $quoted.Groups[1].Value
            if ($sid -and ($sids -notcontains $sid)) { $sids.Add($sid) }
        }
    }
    return @($sids)
}

# ---------------------------------------------------------------------------
function Get-NPSProfileVsaGroupNames {
    <#
    .SYNOPSIS
        Reads the current Fortinet-Group-Name VSA list off a policy's matching RADIUS Profile entry
        (same display-name tag convention used everywhere else in this module), decoding each
        msRADIUSAnyVSA hex value back to its literal ASCII group name - see module NOTES' "HEX HASH"
        field format, the exact reverse of New-FortinetGroupVSA's encoding.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PolicyName
    )
    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $PolicyName
    $profiles = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.RadiusProfiles.Children
    $node = if ($profiles) { $profiles.$tag } else { $null }
    if (-not $node) { throw "No RADIUS Profile named '$PolicyName' found - this policy may not have one (e.g. it was created without VSAs)." }

    # @() wrap - same defensive reasoning already applied to msNPConstraint elsewhere in this module
    # (Get-NPSPolicySummary): PowerShell's XML adapter can collapse a SINGLE matching element down to
    # a bare scalar instead of a 1-item array, which would otherwise silently only process one VSA.
    $vsaValues = @($node.Properties.msRADIUSAnyVSA) | ForEach-Object { $_.'#text' } | Where-Object { $_ }
    $names = foreach ($hex in $vsaValues) {
        # Fixed 14-hex-char prefix (7 bytes: 01 + FortinetVendorHex(4 bytes) + 01 + length-byte) -
        # everything after it is the literal ASCII group name, unmodified.
        if ($hex.Length -gt 14) { $hex.Substring(14) } else { $hex }
    }
    return @($names)
}

# ---------------------------------------------------------------------------
function Set-NPSProfileVsaGroupNames {
    <#
    .SYNOPSIS
        Replaces a policy's matching RADIUS Profile's ENTIRE Fortinet-Group-Name VSA list with
        -VsaGroupNames - a wholesale replace, not a diff/merge, matching "re-process VSAs" semantics:
        recompute the full set fresh from current AD group nesting rather than trying to reconcile
        against whatever was there before.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PolicyName,
        [AllowEmptyCollection()][string[]]$VsaGroupNames = @(),
        [switch]$WhatIf
    )
    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $PolicyName
    $profiles = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.RadiusProfiles.Children
    $node = if ($profiles) { $profiles.$tag } else { $null }
    if (-not $node) { throw "No RADIUS Profile named '$PolicyName' found - nothing to update." }

    $newVsaFragments = ($VsaGroupNames | ForEach-Object { "<msRADIUSAnyVSA $script:XmlDtNs dt:dt=`"string`">$(New-FortinetGroupVSA -GroupName $_)</msRADIUSAnyVSA>" }) -join ''

    # Container-scoped to RadiusProfiles (see Set-NPSContainerRawText) for the same cross-container-
    # safety reason every other tag-scoped edit in this module is, even though a RadiusProfiles tag
    # can't collide with a NetworkPolicy/Proxy_Policies one in practice - consistency, not caution
    # this specific call strictly needs.
    $rawContent = Set-NPSContainerRawText -RawContent $config.RawContent -ContainerTag 'RadiusProfiles' -Transform {
        param($spanText)
        $tagPattern = "(<$([regex]::Escape($tag))\b[^>]*>.*?</$([regex]::Escape($tag))>)"
        # MUST be explicit MatchEvaluator casts (not -replace with an interpolated replacement
        # string) - a Fortinet group name is validated ASCII but CAN legally contain a literal '$',
        # which -replace's own replacement-pattern parser would otherwise misread as a backreference.
        # Same discipline already enforced elsewhere in this module (see
        # Set-NPSPolicySequenceInRawText's identical note) - do not "simplify" this to -replace.
        $blockEvaluator = [System.Text.RegularExpressions.MatchEvaluator]{
            param($m)
            $block = [regex]::Replace($m.Value, '<msRADIUSAnyVSA\b[^>]*>.*?</msRADIUSAnyVSA>', '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            # Insert the new set right before msRADIUSFramedProtocol - confirmed against real
            # production sample data that this element always immediately follows the VSA list, the same order
            # New-NPSProfileXmlFragment already builds fresh profiles in. Always present regardless
            # of whether any VSAs exist, so this anchor works even when adding VSAs to a rule that
            # had none before.
            $anchorEvaluator = [System.Text.RegularExpressions.MatchEvaluator]{
                param($am)
                "$newVsaFragments$($am.Value)"
            }
            [regex]::Replace($block, '<msRADIUSFramedProtocol\b', $anchorEvaluator)
        }
        [regex]::Replace($spanText, $tagPattern, $blockEvaluator, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    }

    if ($WhatIf) {
        return [pscustomobject]@{ PolicyName = $PolicyName; VsaGroupNames = $VsaGroupNames; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ PolicyName = $PolicyName; VsaGroupNames = $VsaGroupNames; BackupPath = $backupPath }
}

# ---------------------------------------------------------------------------
function Set-NPSPolicyConditions {
    <#
    .SYNOPSIS
        Replaces a policy's ENTIRE msNPConstraint condition list with -Conditions, within
        -PolicyType's own container - a wholesale replace, not a diff/merge, matching the same
        "recompute the full set fresh" semantics already established for VSA re-processing
        (Set-NPSProfileVsaGroupNames). Works for either policy universe (Network Policy or Connection
        Request Policy - identical schema, see module NOTES), since -Conditions is already a plain
        list of fully-formed msNPConstraint strings regardless of which condition-collection UI built
        it (New-NPSGroupConditionList for a Network Policy, Read-NPSConnectionRequestConditions for a
        Connection Request Policy).

    .DESCRIPTION
        Editing a Network Policy's conditions can change which groups actually matter for its VSAs -
        this function does NOT touch the RADIUS Profile at all; re-processing VSAs afterward (see
        Invoke-ReprocessNPSVsaWizard) is a deliberately separate, explicit step, not auto-chained here.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PolicyName,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType,
        [Parameter(Mandatory)][string[]]$Conditions,
        [switch]$WhatIf
    )
    if ($Conditions.Count -eq 0) { throw "At least one condition is required - a policy with zero conditions would match every request, which is never actually intended here." }

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $PolicyName
    $containerTag = Get-NPSPolicyContainerTag -PolicyType $PolicyType
    $np = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.$containerTag.Children
    if (-not ($np -and $np.$tag)) { throw "No policy named '$PolicyName' found." }

    $newConstraintFragments = ($Conditions | ForEach-Object { "<msNPConstraint $script:XmlDtNs dt:dt=`"string`">$(ConvertTo-NPSXmlText $_)</msNPConstraint>" }) -join ''

    $rawContent = Set-NPSContainerRawText -RawContent $config.RawContent -ContainerTag $containerTag -Transform {
        param($spanText)
        $tagPattern = "(<$([regex]::Escape($tag))\b[^>]*>.*?</$([regex]::Escape($tag))>)"
        # MUST be explicit MatchEvaluator casts (not -replace with an interpolated replacement
        # string) - a condition value could legally contain a literal '$' (e.g. a Client-Friendly-
        # Name regex pattern), which -replace's own replacement-pattern parser would otherwise
        # misread as a backreference. Same discipline as Set-NPSProfileVsaGroupNames.
        $blockEvaluator = [System.Text.RegularExpressions.MatchEvaluator]{
            param($m)
            $block = [regex]::Replace($m.Value, '<msNPConstraint\b[^>]*>.*?</msNPConstraint>', '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            # Insert the new set right before msNPSequence - confirmed against real production sample
            # data (both containers) that this element always immediately follows the constraint
            # list, the same order New-NPSPolicyRecordXmlFragment already builds fresh policies in.
            $anchorEvaluator = [System.Text.RegularExpressions.MatchEvaluator]{
                param($am)
                "$newConstraintFragments$($am.Value)"
            }
            [regex]::Replace($block, '<msNPSequence\b', $anchorEvaluator)
        }
        [regex]::Replace($spanText, $tagPattern, $blockEvaluator, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    }

    if ($WhatIf) {
        return [pscustomobject]@{ PolicyName = $PolicyName; Conditions = $Conditions; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ PolicyName = $PolicyName; Conditions = $Conditions; BackupPath = $backupPath }
}

# ---------------------------------------------------------------------------
function Find-NPSADGroupsByWildcard {
    <#
    .SYNOPSIS
        Wildcard-searches AD for groups whose Name contains SearchTerm (case-insensitive "contains",
        via -Filter "Name -like '*term*'") - lets the rule builder work off a partial name instead of
        requiring the tech to already know/type a group's exact full name.

    .PARAMETER Server
        Optional - see Resolve-NestedADGroups's -Server notes. Passed straight through to Get-ADGroup.

    .PARAMETER Credential
        Optional - see Resolve-NestedADGroups's -Credential notes. Passed straight through to
        Get-ADGroup. Confirmed live (the maintainer) against the exact command shape this function builds:
        Get-ADGroup -Filter "Name -like '*term*'" -Server <dc> -Credential $cred.
    #>
    param(
        [Parameter(Mandatory)][string]$SearchTerm,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    if (-not (Test-RSATAvailable)) {
        throw "The ActiveDirectory module (RSAT) is not available on this machine - run this from a DC or a machine with RSAT installed (or use Install-RSATActiveDirectoryModule to install it)."
    }
    $null = Import-NPSActiveDirectoryModule

    $adParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $adParams['Server'] = $Server }
    if ($Credential) { $adParams['Credential'] = $Credential }

    # AD's -Filter is its own PowerShell-like expression syntax, not a literal string comparison -
    # a single quote inside SearchTerm would otherwise terminate the quoted value early and either
    # error or (worse) silently change what's being matched. Doubling it is the AD filter engine's
    # own escape convention for an embedded literal quote (same as T-SQL), not something invented here.
    $escaped = $SearchTerm.Replace("'", "''")
    # $foundGroups (not $matches - that's a PowerShell automatic variable populated by -match/-cmatch;
    # assigning to it directly risks corrupting whatever the CALLER's own -match state was relying on).
    # Materializing into a real array BEFORE Sort-Object, rather than piping Get-ADGroup straight into
    # it, guards against the exact-one-result case: PowerShell's own pipeline/array-unwrapping can
    # still collapse a length-1 result back to a bare scalar object by the time a caller captures this
    # function's return value, even though this function's own `return @(...)` wraps it correctly - a
    # well-documented, classic PowerShell gotcha, and exactly what a live "search matched exactly 1
    # group" case just hit here (the maintainer, live: confirmed it broke specifically when the search matched
    # only one group). Read-ANDConditionGroups' own $found = @(...) wrap is the other, caller-side half
    # of this same defense - belt-and-suspenders on both ends of the same call.
    $foundGroups = @(Get-ADGroup -Filter "Name -like '*$escaped*'" @adParams)
    return @($foundGroups | Sort-Object -Property Name)
}

# ---------------------------------------------------------------------------
function Resolve-NPSGroupInteractive {
    <#
    .SYNOPSIS
        Resolves ONE group name/SID to a real AD group - tries the exact name first (Get-ADGroupSID),
        and on failure kicks over to Find-NPSADGroupsByWildcard's search so a tech isn't stuck just
        because the imported/typed name doesn't exactly match the group's real current name (a typo,
        a rename since the name was captured, different capitalization, etc.). Confirmed live
        (the maintainer, 2026-08-18): Invoke-ImportKickstartDefinitions used to just fail and skip the whole
        pair on an exact-match miss, forcing a trip to Option 5 to fix by hand even when the group was
        genuinely findable by a partial-name search.

    .DESCRIPTION
        Same 0/1/many-hit search UX Read-ANDConditionGroups already established (auto-pick on exactly
        one hit, numbered pick-list on multiple, Create/Skip on zero) - built as its own function
        rather than extracted out of Read-ANDConditionGroups' own inline loop, so its already-working,
        heavily-exercised condition-building flow isn't put at risk for this second, structurally
        different consumer (resolving ONE already-known name, not building AND/OR condition sets).

        An already-SID-shaped input that fails exact resolution is NOT searched (a SID isn't a
        wildcard search term - if a stored SID doesn't resolve, the group was deleted/the SID is
        stale, and a name search can't fix that) - reported as unresolved directly.

        A wildcard-search failure that looks like a credentials problem (Test-NPSADAuthError) offers
        the same Invoke-NPSADFallbackPrompt "connect to a specific DC directly" recovery every other
        AD-touching spot in this dashboard offers - same as Read-ANDConditionGroups' own handling.
    #>
    param(
        [Parameter(Mandatory)][string]$GroupNameOrSID,
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential,
        [string]$ShimPath
    )

    try {
        $sid = Get-ADGroupSID -GroupNameOrSID $GroupNameOrSID -Server $ADServer -Credential $ADCredential
        return [pscustomobject]@{ Resolved = $true; Name = $GroupNameOrSID; SID = $sid; ADServer = $ADServer; ADCredential = $ADCredential }
    } catch {
        $exactError = $_.Exception.Message
    }

    if ($GroupNameOrSID -match '^S-1-5-\d+(-\d+)+$') {
        Write-Host "  '$GroupNameOrSID' looks like a SID and didn't resolve - $exactError" -ForegroundColor Red
        return [pscustomobject]@{ Resolved = $false; Name = $null; SID = $null; ADServer = $ADServer; ADCredential = $ADCredential }
    }

    Write-Host "  Exact match for '$GroupNameOrSID' failed ($exactError) - searching AD instead..." -ForegroundColor Yellow

    try {
        $found = @(Find-NPSADGroupsByWildcard -SearchTerm $GroupNameOrSID -Server $ADServer -Credential $ADCredential)
    } catch {
        if (Test-NPSADAuthError -ErrorRecord $_) {
            Write-Host "  This looks like a credentials problem, not a bad search term." -ForegroundColor Yellow
            $fallback = Invoke-NPSADFallbackPrompt -ShimPath $ShimPath
            if ($fallback -and $fallback.Credential) {
                $script:ADServer = $fallback.DCServer
                $script:ADCredential = $fallback.Credential
                $ADServer = $fallback.DCServer
                $ADCredential = $fallback.Credential
                try {
                    $found = @(Find-NPSADGroupsByWildcard -SearchTerm $GroupNameOrSID -Server $ADServer -Credential $ADCredential)
                } catch {
                    Write-Host "  Still could not search AD for '$GroupNameOrSID' - $($_.Exception.Message)" -ForegroundColor Red
                    return [pscustomobject]@{ Resolved = $false; Name = $null; SID = $null; ADServer = $ADServer; ADCredential = $ADCredential }
                }
            } else {
                return [pscustomobject]@{ Resolved = $false; Name = $null; SID = $null; ADServer = $ADServer; ADCredential = $ADCredential }
            }
        } else {
            Write-Host "  Could not search AD for '$GroupNameOrSID' - $($_.Exception.Message)" -ForegroundColor Red
            return [pscustomobject]@{ Resolved = $false; Name = $null; SID = $null; ADServer = $ADServer; ADCredential = $ADCredential }
        }
    }

    $foundCount = $found.Count
    $picked = $null

    if ($foundCount -eq 0) {
        Write-Host "  No AD groups found matching '*$GroupNameOrSID*'." -ForegroundColor Red
        Write-Host "    C. Create a new AD group named '$GroupNameOrSID'"
        Write-Host "    S. Skip - leave this unresolved"
        Write-Host "  Tip: 'C' here creates just this one bare group. If what's actually missing is a" -ForegroundColor DarkGray
        Write-Host "  whole client's VPN group/OU structure, AD-Manager (PushableTools\ADManager\," -ForegroundColor DarkGray
        Write-Host "  menu 2) is the fuller, OU-browsable tool for that." -ForegroundColor DarkGray
        $zeroChoice = Read-Host "  Select"
        if ($zeroChoice -match '^[Cc]') {
            Write-Host "  Pick the OU to create '$GroupNameOrSID' in:" -ForegroundColor Cyan
            $targetOU = Select-NPSADOrganizationalUnit -Server $ADServer -Credential $ADCredential
            if (-not $targetOU) {
                Write-Host "  Cancelled - no OU selected." -ForegroundColor Yellow
                return [pscustomobject]@{ Resolved = $false; Name = $null; SID = $null; ADServer = $ADServer; ADCredential = $ADCredential }
            }
            try {
                $picked = New-NPSADGroup -Name $GroupNameOrSID -Path $targetOU -Server $ADServer -Credential $ADCredential
                Write-Host "  Created AD group '$GroupNameOrSID' in $targetOU" -ForegroundColor Green
            } catch {
                Write-Host "  Could not create group '$GroupNameOrSID' - $($_.Exception.Message)" -ForegroundColor Red
                return [pscustomobject]@{ Resolved = $false; Name = $null; SID = $null; ADServer = $ADServer; ADCredential = $ADCredential }
            }
        } else {
            return [pscustomobject]@{ Resolved = $false; Name = $null; SID = $null; ADServer = $ADServer; ADCredential = $ADCredential }
        }
    } elseif ($foundCount -eq 1) {
        $picked = $found[0]
        Write-Host "  '$GroupNameOrSID' matched exactly one group: $($picked.Name)" -ForegroundColor Green
    } else {
        Write-Host "  '$GroupNameOrSID' matched $foundCount groups:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $foundCount; $i++) {
            Write-Host ("    {0}. {1}" -f ($i + 1), $found[$i].Name)
        }
        $sel = Read-Host "  Select a number (blank to skip)"
        $idx = ($sel -as [int]) - 1
        if ($idx -ge 0 -and $idx -lt $foundCount) {
            $picked = $found[$idx]
        } else {
            Write-Host "  Skipped - no selection made." -ForegroundColor Yellow
            return [pscustomobject]@{ Resolved = $false; Name = $null; SID = $null; ADServer = $ADServer; ADCredential = $ADCredential }
        }
    }

    Write-Host "  Resolved '$GroupNameOrSID' -> '$($picked.Name)' -> $($picked.SID.Value)" -ForegroundColor Green
    return [pscustomobject]@{ Resolved = $true; Name = $picked.Name; SID = $picked.SID.Value; ADServer = $ADServer; ADCredential = $ADCredential }
}

# ---------------------------------------------------------------------------
function ConvertTo-NPSXmlText {
    <#
    .SYNOPSIS
        Escapes a string for use as XML ELEMENT TEXT content (&, <, > only) - deliberately NOT
        [System.Security.SecurityElement]::Escape(), which also escapes quotes. Quotes don't need
        escaping in element text (only in attribute values), and NPS's own exporter leaves them
        literal there - e.g. msNPConstraint text like MATCH("Client-IP-Address=..."). Using the
        heavier attribute-safe escape here would still produce valid, correctly-parseable XML
        (&quot; decodes back to " identically), but it'd diverge from native NPS export style for no
        functional benefit, and this codebase already leans on byte-for-byte fidelity to real
        exports wherever practical. Reserve [System.Security.SecurityElement]::Escape() for actual
        attribute values (the name="..." on each policy/profile tag).
    #>
    param([string]$Text)
    return $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
}

# ---------------------------------------------------------------------------
function New-NPSPolicyRecordXmlFragment {
    <#
    .SYNOPSIS
        Builds the raw <Tag ...>...</Tag> XML text for one policy record (Network Policy OR
        Connection Request Policy - the schema is identical, see module NOTES) from an already-
        resolved, fully-formed list of msNPConstraint condition strings. Shared skeleton extracted
        out of New-NPSPolicyXmlFragment (which builds its own Client-IP + group-SID condition list
        and calls this) so Add-NPSConnectionRequestRule can build a fragment from freeform conditions
        (MATCH/TIMEOFDAY/USERNTGROUPS - whatever a CRP actually needs) without inheriting Network
        Policy's specific "always Client-IP + group SIDs" shape.
    #>
    param(
        [Parameter(Mandatory)] [string]$DisplayName,
        [Parameter(Mandatory)] [string[]]$Conditions,
        [Parameter(Mandatory)] [int]$Sequence,
        [string]$ActionText   # msNPAction text - defaults to $DisplayName if not given
    )

    $tag = ConvertTo-NPSXmlTagName -DisplayName $DisplayName
    if (-not $ActionText) { $ActionText = $DisplayName }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<$tag name=`"$([System.Security.SecurityElement]::Escape($DisplayName))`"><Properties>")
    [void]$sb.Append("<Opaque_Data $script:XmlDtNs dt:dt=`"string`"></Opaque_Data>")
    [void]$sb.Append("<Policy_Enabled $script:XmlDtNs dt:dt=`"boolean`">1</Policy_Enabled>")
    [void]$sb.Append("<Policy_SourceTag $script:XmlDtNs dt:dt=`"int`">0</Policy_SourceTag>")
    [void]$sb.Append("<Template_Guid $script:XmlDtNs dt:dt=`"string`">$script:ZeroGuid</Template_Guid>")
    [void]$sb.Append("<msNPAction $script:XmlDtNs dt:dt=`"string`">$(ConvertTo-NPSXmlText $ActionText)</msNPAction>")
    foreach ($c in $Conditions) {
        [void]$sb.Append("<msNPConstraint $script:XmlDtNs dt:dt=`"string`">$(ConvertTo-NPSXmlText $c)</msNPConstraint>")
    }
    [void]$sb.Append("<msNPSequence $script:XmlDtNs dt:dt=`"int`">$Sequence</msNPSequence>")
    [void]$sb.Append("</Properties></$tag>")

    return $sb.ToString()
}

# ---------------------------------------------------------------------------
function New-NPSGroupConditionList {
    <#
    .SYNOPSIS
        Builds the Network-Policy-style condition list (Client-IP-Address MATCH first, then one
        USERNTGROUPS entry per AND'd group-SID-set) as plain msNPConstraint strings - extracted out
        of New-NPSPolicyXmlFragment so Invoke-EditNPSPolicyConditions can build the exact same shape
        when re-collecting an existing Network Policy's conditions, without a second copy of this
        logic to keep in sync.

    .PARAMETER AndGroupSidSets
        Array of arrays. Each inner array is one msNPConstraint USERNTGROUPS(...) entry (its SIDs
        OR'd together); separate inner arrays AND together across entries. E.g.
        @(@('SID-A','SID-B'), @('SID-C')) means (A OR B) AND C.
    #>
    param(
        [Parameter(Mandatory)] [string]$ClientIPAddress,
        [Parameter(Mandatory)] [array]$AndGroupSidSets
    )

    $constraints = [System.Collections.Generic.List[string]]::new()
    $constraints.Add("MATCH(`"Client-IP-Address=$ClientIPAddress`")")
    foreach ($sidSet in $AndGroupSidSets) {
        $quoted = ($sidSet | ForEach-Object { "`"$_`"" }) -join ','
        $constraints.Add("USERNTGROUPS($quoted)")
    }
    return @($constraints)
}

# ---------------------------------------------------------------------------
function New-NPSPolicyXmlFragment {
    <#
    .SYNOPSIS
        Builds the raw <Tag ...>...</Tag> XML text for one Network Policy entry - the access-grant
        shape (Client-IP-Address + AND/OR group SIDs). Thin wrapper: builds this specific condition
        list via New-NPSGroupConditionList, then delegates the actual fragment assembly to
        New-NPSPolicyRecordXmlFragment - a pure internal refactor, zero behavior change from before.
    #>
    param(
        [Parameter(Mandatory)] [string]$DisplayName,
        [Parameter(Mandatory)] [string]$ClientIPAddress,
        [Parameter(Mandatory)] [array]$AndGroupSidSets,
        [Parameter(Mandatory)] [int]$Sequence,
        [string]$ActionText   # msNPAction text - defaults to $DisplayName if not given
    )

    $constraints = New-NPSGroupConditionList -ClientIPAddress $ClientIPAddress -AndGroupSidSets $AndGroupSidSets
    return New-NPSPolicyRecordXmlFragment -DisplayName $DisplayName -Conditions $constraints -Sequence $Sequence -ActionText $ActionText
}

# ---------------------------------------------------------------------------
function New-NPSProfileXmlFragment {
    <#
    .SYNOPSIS
        Builds the raw <Tag ...>...</Tag> XML text for one RADIUS Profile entry, matching a real
        production baseline's exact per-Kind attribute set (see module header NOTES on the Combined/IPSecOnly vs
        SSLVPNOnly asymmetry).

    .PARAMETER Kind
        Combined - has both VSAs, includes msIgnoreUserDialinProperties + BapLinedn fields.
        IPSecOnly - IKEv2-only VSA, includes the same extra fields as Combined.
        SSLVPNOnly - SSLVPN-only VSA, OMITS msIgnoreUserDialinProperties + BapLinedn fields (matches
                     a real production "RADIUS - SSLVPN" profile exactly - not a simplification, a faithful
                     copy of an asymmetry that's actually there in the baseline).
        Single - for Add-NPSSingleRule (a standalone ad hoc rule, not part of the standard 3-policy
                 pattern). Includes the same fuller attribute set as Combined/IPSecOnly - there's no
                 baseline evidence either way for a rule outside that pattern, and the fuller set is
                 the safer/more broadly compatible default.
    #>
    param(
        [Parameter(Mandatory)] [string]$DisplayName,
        [Parameter(Mandatory)] [ValidateSet('Combined','IPSecOnly','SSLVPNOnly','Single')] [string]$Kind,
        [Parameter(Mandatory)] [string[]]$VsaGroupNames
    )

    $tag = ConvertTo-NPSXmlTagName -DisplayName $DisplayName
    $includeDialinExtras = $Kind -ne 'SSLVPNOnly'

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<$tag name=`"$([System.Security.SecurityElement]::Escape($DisplayName))`"><Properties>")
    [void]$sb.Append("<IP_Filter_Template_Guid $script:XmlDtNs dt:dt=`"string`">$script:ZeroGuid</IP_Filter_Template_Guid>")
    [void]$sb.Append("<Opaque_Data $script:XmlDtNs dt:dt=`"string`"></Opaque_Data>")
    [void]$sb.Append("<Template_Guid $script:XmlDtNs dt:dt=`"string`">$script:ZeroGuid</Template_Guid>")
    if ($includeDialinExtras) {
        [void]$sb.Append("<msIgnoreUserDialinProperties $script:XmlDtNs dt:dt=`"boolean`">1</msIgnoreUserDialinProperties>")
    }
    [void]$sb.Append("<msNPAllowDialin $script:XmlDtNs dt:dt=`"boolean`">1</msNPAllowDialin>")
    [void]$sb.Append("<msNPAllowedEapType $script:XmlDtNs dt:dt=`"bin.hex`">$script:PeapPolicyEapType</msNPAllowedEapType>")
    foreach ($authType in 5,4,10) {
        [void]$sb.Append("<msNPAuthenticationType2 $script:XmlDtNs dt:dt=`"int`">$authType</msNPAuthenticationType2>")
    }
    foreach ($groupName in $VsaGroupNames) {
        $vsa = New-FortinetGroupVSA -GroupName $groupName
        [void]$sb.Append("<msRADIUSAnyVSA $script:XmlDtNs dt:dt=`"string`">$vsa</msRADIUSAnyVSA>")
    }
    [void]$sb.Append("<msRADIUSFramedProtocol $script:XmlDtNs dt:dt=`"int`">1</msRADIUSFramedProtocol>")
    [void]$sb.Append("<msRADIUSServiceType $script:XmlDtNs dt:dt=`"int`">2</msRADIUSServiceType>")
    if ($includeDialinExtras) {
        [void]$sb.Append("<msRASBapLinednLimit $script:XmlDtNs dt:dt=`"int`">50</msRASBapLinednLimit>")
        [void]$sb.Append("<msRASBapLinednTime $script:XmlDtNs dt:dt=`"int`">120</msRASBapLinednTime>")
    }
    [void]$sb.Append("</Properties></$tag>")

    return $sb.ToString()
}

# ---------------------------------------------------------------------------
function Get-NPSExistingSequences {
    <#
    .SYNOPSIS
        Reads every real (non-999999/999998 built-in) msNPSequence value currently in -PolicyType's
        own container - Network Policies and Connection Request Policies each have their own,
        entirely separate msNPSequence numbering (both start at 1) - for computing where new policies
        should land.
    #>
    param(
        [Parameter(Mandatory)][xml]$ConfigXml,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType
    )

    $containerTag = Get-NPSPolicyContainerTag -PolicyType $PolicyType
    $np = $ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.$containerTag.Children
    $sequences = foreach ($node in $np.ChildNodes) {
        $seq = [int]$node.Properties.msNPSequence.'#text'
        if ($seq -lt 900000) { $seq }
    }
    return @($sequences | Sort-Object)
}

# ---------------------------------------------------------------------------
function Get-NPSConfigEncoding {
    <#
    .SYNOPSIS
        Detects the actual on-disk encoding of an ias.xml file (via its byte-order mark), so it can
        be preserved exactly on write.

    .DESCRIPTION
        The live ias.xml is UTF-16 LE with a BOM (legacy COM/IAS-era default) - NOT UTF-8, despite
        its <?xml version="1.0"?> declaration not stating an encoding at all. Get-Content
        auto-detects this fine on READ, but writing back with a hardcoded encoding (this module used
        to force UTF-8-no-BOM via New-Object System.Text.UTF8Encoding($false)) silently re-encodes
        the whole file into something IAS's own legacy COM-based loader can't parse. The failure
        doesn't show up until SERVICE START, as the maximally unhelpful "The Network Policy Server
        service terminated with the following error: The request is not supported." - not at the
        point of writing, and not from anything this module's own XML round-trip validation would
        catch (.NET's [xml] parses either encoding just fine).

        Confirmed against a real broken/backup pair from a live incident: the pre-edit backup was
        FF FE (UTF-16 LE BOM); the tool-written file that broke NPS was plain UTF-8 with no BOM at
        all. Never hardcode an encoding for this file again - always detect and reuse via this
        function, in both Add-NPSPolicySet's own write and anywhere else this file gets written.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $reader = New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::UTF8, $true)
    try {
        [void]$reader.Peek()   # forces the BOM-based detection to actually run before CurrentEncoding is reliable
        return $reader.CurrentEncoding
    } finally {
        $reader.Close()
    }
}

# ---------------------------------------------------------------------------
function Read-NPSConfig {
    <#
    .SYNOPSIS
        Reads an ias.xml file's raw text, parsed XML, and on-disk encoding in one call - the same
        three things almost every read/write function in this module needs before making an edit.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) { throw "'$Path' not found." }
    $encoding = Get-NPSConfigEncoding -Path $Path
    $raw = Get-Content -Path $Path -Raw
    [xml]$configXml = $raw
    return [pscustomobject]@{ Path = $Path; RawContent = $raw; ConfigXml = $configXml; Encoding = $encoding }
}

# ---------------------------------------------------------------------------
function Save-NPSConfig {
    <#
    .SYNOPSIS
        Backs up (Backup-NPSConfig), then writes $RawContent back to $Path using $Encoding - the
        write-side counterpart to Read-NPSConfig.

    .DESCRIPTION
        -Encoding MUST be the same Encoding object Read-NPSConfig originally detected for THIS file
        (its .Encoding property) - never a hardcoded one. See Get-NPSConfigEncoding's notes: a
        hardcoded UTF-8-no-BOM write once re-encoded a real UTF-16 LE ias.xml into something IAS's
        loader couldn't read, taking a live NPS service down with "The request is not supported" at
        next start. Cost a real outage once already.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RawContent,
        [Parameter(Mandatory)][System.Text.Encoding]$Encoding
    )
    $backupPath = Backup-NPSConfig -Path $Path
    [System.IO.File]::WriteAllText($Path, $RawContent, $Encoding)
    return $backupPath
}

# ---------------------------------------------------------------------------
function Get-NPSContainerSpan {
    <#
    .SYNOPSIS
        Locates the one `<ContainerTag name="ContainerTag">...</ContainerTag>` span in raw ias.xml
        text - each top-level container (NetworkPolicy, Proxy_Policies, RadiusProfiles, ...) appears
        exactly once in the file. Returns the [regex] Match (Index/Length/Value) so a caller can
        isolate, transform, and splice back just that one section.
    #>
    param(
        [Parameter(Mandatory)][string]$RawContent,
        [Parameter(Mandatory)][string]$ContainerTag
    )
    $pattern = "<$([regex]::Escape($ContainerTag))\s+name=`"$([regex]::Escape($ContainerTag))`">.*?</$([regex]::Escape($ContainerTag))>"
    $match = [regex]::Match($RawContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $match.Success) {
        throw "Could not find a <$ContainerTag> section in this ias.xml - unexpected file structure."
    }
    return $match
}

# ---------------------------------------------------------------------------
function Set-NPSContainerRawText {
    <#
    .SYNOPSIS
        Runs $Transform against ONLY one container's own span of raw ias.xml text (see
        Get-NPSContainerSpan), then splices the transformed result back into the full document.

    .DESCRIPTION
        THE container-scoping fix: every policy edit that locates a record by its XML TAG NAME
        (Set-NPSPolicySequenceInRawText, Remove-NPSFragmentFromRawText, Set-NPSPolicyEnabled) used to
        regex-match that tag name anywhere in the WHOLE raw file - harmless when only one container
        (NetworkPolicy) was ever edited (a same-named RadiusProfiles entry being caught by the same
        sweep was the deliberate, understood behavior - profiles share their policy's tag by design).
        Once Proxy_Policies (Connection Request Policies) is also editable, a Network Policy and a
        Connection Request Policy that happen to resolve to the SAME tag (e.g. a tech naming both
        "RADIUS from FortiGate") could otherwise corrupt/renumber/delete each other's entries via
        those unscoped regexes. Routing every tag-scoped edit through here closes that gap - the
        regex never sees text outside the one container it was told to operate on.
    #>
    param(
        [Parameter(Mandatory)][string]$RawContent,
        [Parameter(Mandatory)][string]$ContainerTag,
        [Parameter(Mandatory)][scriptblock]$Transform
    )
    $span = Get-NPSContainerSpan -RawContent $RawContent -ContainerTag $ContainerTag
    $newSpanText = & $Transform $span.Value
    return $RawContent.Substring(0, $span.Index) + $newSpanText + $RawContent.Substring($span.Index + $span.Length)
}

# ---------------------------------------------------------------------------
function Set-NPSPolicySequenceInRawText {
    <#
    .SYNOPSIS
        Atomically renumbers ONE policy's msNPSequence within raw ias.xml text, scoped to that
        policy's own <TagName>...</TagName> block WITHIN -ContainerTag's own span (see
        Set-NPSContainerRawText) - never a global string replace, since Proxy_Policies has its own,
        entirely separate msNPSequence numbering (its own policies are also numbered 1, 2, ...) that
        an unscoped replace could collide with - or, worse, could hit a same-tagged record in the
        OTHER container entirely.

        Because the replace is scoped by TAG NAME (not "whichever node currently holds value X"),
        it's safe to call this repeatedly with transient/temporary values still present elsewhere in
        the file - each call only ever touches its own named block, within its own container. Callers
        doing a multi-policy renumber (shift-to-make-room, close-a-gap-after-delete) are still
        responsible for choosing a safe processing ORDER among themselves (highest-first when shifting
        up, lowest-first when shifting down) so two DIFFERENT policies are never simultaneously left
        holding the same number as a resting state - not because this function needs it, but because
        Get-NPSExistingSequences/other readers expect current values to be unique at all times.
    #>
    param(
        [Parameter(Mandatory)][string]$RawContent,
        [Parameter(Mandatory)][string]$ContainerTag,
        [Parameter(Mandatory)][string]$TagName,
        [Parameter(Mandatory)][int]$OldSequence,
        [Parameter(Mandatory)][int]$NewSequence
    )
    $oldFragment = "<msNPSequence $($script:XmlDtNs) dt:dt=`"int`">$OldSequence</msNPSequence>"
    $newFragment = "<msNPSequence $($script:XmlDtNs) dt:dt=`"int`">$NewSequence</msNPSequence>"
    $tagPattern = "(<$([regex]::Escape($TagName))\b[^>]*>.*?</$([regex]::Escape($TagName))>)"
    # MUST be an explicit MatchEvaluator cast - a bare scriptblock here silently resolves to the
    # wrong [regex]::Replace overload and never actually invokes, leaving sequences unshifted. Cost
    # real debugging time once already (see Add-NPSPolicySet's git history) - do not "simplify" this.
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
        param($m)
        $m.Value.Replace($oldFragment, $newFragment)
    }
    return Set-NPSContainerRawText -RawContent $RawContent -ContainerTag $ContainerTag -Transform {
        param($spanText)
        [regex]::Replace($spanText, $tagPattern, $evaluator, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    }
}

# ---------------------------------------------------------------------------
function Add-NPSChildFragmentToRawContent {
    <#
    .SYNOPSIS
        Splices $Fragment in as a new child of -ContainerTag's own <Children> element, within raw
        ias.xml/iastemplates.xml text - the one place shared by every "add a new X" function in this
        module (Shared Secret Templates, RADIUS Client Templates, live Clients, Network/Connection
        Request Policies, RADIUS Profiles).

    .DESCRIPTION
        Handles BOTH shapes <Children> can take: the normal "already has at least one child"
        <Children>...</Children> form (insert just before its closing tag), AND the SELF-CLOSING
        <Children/> form NPS itself writes when a container is still genuinely empty - confirmed live
        against the real Samples\iastemplates.xml (RADIUS_Shared_Secrets_Templates renders as
        "<Children/>" with zero templates ever created). Every "add" function here used to regex-match
        ONLY the non-empty form and silently no-op (a zero-match [regex]::Replace just returns the
        input unchanged) whenever a container was still empty - reporting SUCCESS and a real backup,
        while actually adding nothing at all. Confirmed live, 2026-08-18: a fresh NPS server hit
        exactly this on its very first-ever Shared Secret Template, then again on the very next RADIUS
        Client Template - both containers start genuinely empty on a fresh box, so BOTH silently
        no-op'd, and the immediately-following lookup ("No Shared Secret Template named 'X' found")
        correctly reported that nothing had actually been added.

        Throws (rather than silently returning the content unchanged) if NEITHER shape is found, so a
        THIRD, still-unanticipated structure fails loudly instead of repeating this exact class of bug.
    #>
    param(
        [Parameter(Mandatory)][string]$RawContent,
        [Parameter(Mandatory)][string]$ContainerTag,
        [Parameter(Mandatory)][string]$Fragment
    )
    $closeTag = [regex]::Escape($ContainerTag)

    # Normal case: container already has at least one child - insert just before </Children>.
    $nonEmptyPattern = "</Children>(\s*)</$closeTag>"
    if ([regex]::IsMatch($RawContent, $nonEmptyPattern)) {
        return [regex]::Replace($RawContent, $nonEmptyPattern,
            [System.Text.RegularExpressions.MatchEvaluator]{ param($m) "$Fragment</Children>$($m.Groups[1].Value)</$ContainerTag>" })
    }

    # Empty case: NPS itself writes <Children/> (self-closing) when nothing has ever been added yet.
    $emptyPattern = "<Children\s*/>(\s*)</$closeTag>"
    if ([regex]::IsMatch($RawContent, $emptyPattern)) {
        return [regex]::Replace($RawContent, $emptyPattern,
            [System.Text.RegularExpressions.MatchEvaluator]{ param($m) "<Children>$Fragment</Children>$($m.Groups[1].Value)</$ContainerTag>" })
    }

    throw "Could not find a <Children> (or self-closing <Children/>) element inside <$ContainerTag> to add the new entry to - unexpected file structure."
}

# ---------------------------------------------------------------------------
function Add-NPSFragmentsToRawContent {
    <#
    .SYNOPSIS
        Splices policy fragments (into -PolicyContainer - "NetworkPolicy" or "Proxy_Policies") and/or
        RadiusProfiles fragments into raw ias.xml text, just before each section's own closing tag.
        Anchors on the full "...</NetworkPolicy>" / "...</Proxy_Policies>" / "...</RadiusProfiles>"
        tail rather than a bare "</Children>" - that closing tag isn't unique in the file (every
        section closes with it), but a CONTAINER's own closing tag IS unique (each top-level container
        appears exactly once) - so this anchor is already safe as-is, unlike the tag-NAME-scoped edits
        elsewhere in this module (see Set-NPSContainerRawText) which needed an actual scoping fix.
    #>
    param(
        [Parameter(Mandatory)][string]$RawContent,
        [ValidateSet('NetworkPolicy', 'Proxy_Policies')][string]$PolicyContainer = 'NetworkPolicy',
        [string[]]$PolicyFragments = @(),
        [string[]]$ProfileFragments = @()
    )
    if ($PolicyFragments.Count -gt 0) {
        $policyBlock = $PolicyFragments -join ''
        $RawContent = Add-NPSChildFragmentToRawContent -RawContent $RawContent -ContainerTag $PolicyContainer -Fragment $policyBlock
    }
    if ($ProfileFragments.Count -gt 0) {
        $profileBlock = $ProfileFragments -join ''
        $RawContent = Add-NPSChildFragmentToRawContent -RawContent $RawContent -ContainerTag 'RadiusProfiles' -Fragment $profileBlock
    }
    return $RawContent
}

# ---------------------------------------------------------------------------
function Remove-NPSFragmentFromRawText {
    <#
    .SYNOPSIS
        Removes one <TagName>...</TagName> block entirely from raw ias.xml text, scoped to
        -ContainerTag's own span (see Set-NPSContainerRawText). Internal helper for Remove-NPSPolicy,
        which uses it twice for EITHER policy type now - once for the policy entry itself
        (NetworkPolicy or Proxy_Policies), once for its matching paired profile (RadiusProfiles or
        Proxy_Profiles respectively - they share the same tag name, since a profile in this module is
        always created under the same display name as its policy). A CRP created before
        Add-NPSConnectionRequestRule started pairing a profile (2026-08-18) genuinely has none to
        remove - a no-match replace against Proxy_Profiles is a harmless no-op in that case, not an
        error.
    #>
    param(
        [Parameter(Mandatory)][string]$RawContent,
        [Parameter(Mandatory)][string]$ContainerTag,
        [Parameter(Mandatory)][string]$TagName
    )
    $tagPattern = "<$([regex]::Escape($TagName))\b[^>]*>.*?</$([regex]::Escape($TagName))>"
    return Set-NPSContainerRawText -RawContent $RawContent -ContainerTag $ContainerTag -Transform {
        param($spanText)
        [regex]::Replace($spanText, $tagPattern, '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    }
}

# ---------------------------------------------------------------------------
function Add-NPSPolicySet {
    <#
    .SYNOPSIS
        Adds the standard 3-policy set (Combined / IPSec-only / SSLVPN-only) - or a subset of it -
        to a live/target ias.xml, backing it up first, and saves.

    .DESCRIPTION
        Splices new <Tag>...</Tag> fragments directly into the raw file text just before the closing
        </Children> of NetworkPolicy and RadiusProfiles respectively (text splice, not DOM node
        creation - same reasoning MiscTools's GPP-editing code elsewhere in this framework already
        uses: full round-trip through [xml]/.Save() can reformat/reorder things NPS's own client can
        be picky about, a targeted text insert leaves everything else byte-for-byte untouched).

        New policies are always inserted as a contiguous block, Combined first, then IPSecOnly, then
        SSLVPNOnly (see module header NOTES on why that relative order matters), starting at
        -InsertAtSequence. Every existing REAL policy (not the 999999/999998 built-ins) at or after
        that sequence number is shifted back by the number of policies actually being added, so
        nothing collides. Defaults to inserting at the very top (sequence 1) if -InsertAtSequence
        isn't given - the most defensible default absent a specific instruction on where a new grant
        belongs relative to existing policies, but very much a "you may want to move this with the
        reorder tool afterward" default, not a claim that top is always correct.

    .PARAMETER IPSecGroupSidSets
        Array of arrays (AND/OR sets - see New-NPSPolicyXmlFragment) required for IPSec (IKEv2)
        access. Used ALONE as the condition for the IPSecOnly policy, and combined (AND'd) with
        -SSLVPNGroupSidSets for the Combined policy. NOT reused for SSLVPNOnly - verified against a
        real production baseline: its IPSec-only policy requires ONLY the IKEv2 group's SID, its
        SSLVPN-only policy requires ONLY the SSLVPN group's SID, and only the Combined policy
        requires both. Treating this as one shared condition set across all three (an earlier version
        of this function did) is wrong - it would let a user access IPSec-only via a group that
        should only grant SSLVPN, or vice versa.

    .PARAMETER SSLVPNGroupSidSets
        Same shape as -IPSecGroupSidSets, for SSLVPN access - used alone for SSLVPNOnly, AND'd with
        -IPSecGroupSidSets for Combined.

    .PARAMETER IPSecVsaGroupNames / SSLVPNVsaGroupNames
        Fortinet-Group-Name(s) to emit as msRADIUSAnyVSA - IPSec's own set goes on the IPSecOnly
        profile, SSLVPN's own set on SSLVPNOnly, and Combined gets both. The intent is that each set
        is normally the "rolled up" nested AD membership of that SIDE's own required group(s) (see
        Resolve-NestedADGroups) - i.e. whatever VPNFW_*-style firewall groups the IPSec-required
        group(s) belong to become the IPSec VSAs, and likewise for SSLVPN - not a shared/generic list.

    .PARAMETER Kinds
        Which of the three to actually create - defaults to all three. Restricting this does NOT
        change the relative sequence spacing reserved (still reserves 3 slots) unless -Kinds is
        also narrowed, keeping room to add the others later without a full renumber.
    #>
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$BaseName,
        [Parameter(Mandatory)] [string]$ClientIPAddress,
        [Parameter(Mandatory)] [array]$IPSecGroupSidSets,
        [Parameter(Mandatory)] [array]$SSLVPNGroupSidSets,
        [Parameter(Mandatory)] [string[]]$IPSecVsaGroupNames,
        [Parameter(Mandatory)] [string[]]$SSLVPNVsaGroupNames,
        [int]$InsertAtSequence,
        [ValidateSet('Combined','IPSecOnly','SSLVPNOnly')] [string[]]$Kinds = @('Combined','IPSecOnly','SSLVPNOnly'),
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $rawContent = $config.RawContent

    # Always NetworkPolicy - this whole function is specifically the standard-pattern access-grant set
    # (group SIDs + VSAs), which only makes semantic sense as a Network Policy. Not exposed as a
    # caller-set param - see Add-NPSConnectionRequestRule for the (deliberately much simpler,
    # no-profile) Connection Request Policy equivalent.
    $existingSequences = Get-NPSExistingSequences -ConfigXml $config.ConfigXml -PolicyType NetworkPolicy
    if (-not $InsertAtSequence) {
        $InsertAtSequence = 1
    }

    $slotCount = $Kinds.Count
    # Shift every real policy at/after the insertion point back by $slotCount, HIGHEST sequence first
    # - shifting low-to-high would briefly want two policies on the same number mid-batch; high-to-low
    # avoids that (each target value is already vacated by the previous step in this loop).
    $toShift = @($existingSequences | Where-Object { $_ -ge $InsertAtSequence } | Sort-Object -Descending)
    $shiftNeeded = $toShift.Count -gt 0

    if ($shiftNeeded) {
        # MUST be .LocalName, not .Name - PowerShell's [xml] adapter lets the "name" ATTRIBUTE (the
        # human-readable display name) shadow XmlElement's own real .Name property (the actual tag),
        # so $node.Name silently returns the wrong string here. Cost real debugging time once already.
        $np = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.NetworkPolicy.Children
        foreach ($oldSeq in $toShift) {
            $node = $np.ChildNodes | Where-Object { [int]$_.Properties.msNPSequence.'#text' -eq $oldSeq } | Select-Object -First 1
            if (-not $node) { continue }
            $rawContent = Set-NPSPolicySequenceInRawText -RawContent $rawContent -ContainerTag 'NetworkPolicy' -TagName $node.LocalName -OldSequence $oldSeq -NewSequence ($oldSeq + $slotCount)
        }
    }

    $policyFragments  = [System.Collections.Generic.List[string]]::new()
    $profileFragments = [System.Collections.Generic.List[string]]::new()
    $seq = $InsertAtSequence

    $kindOrder = @('Combined','IPSecOnly','SSLVPNOnly') | Where-Object { $_ -in $Kinds }
    foreach ($kind in $kindOrder) {
        $suffix = switch ($kind) { 'Combined' { 'IKEv2 & SSLVPN' } 'IPSecOnly' { 'IKEv2 VPN' } 'SSLVPNOnly' { 'SSLVPN' } }
        $displayName = "$BaseName - $suffix"
        # Condition sets are per-side, same split logic as the VSA names below - IPSecOnly matches
        # ONLY the IPSec-required group(s), SSLVPNOnly ONLY the SSLVPN-required group(s), Combined
        # requires both (AND'd together). See .PARAMETER notes above for why this must NOT be one
        # shared condition set reused across all three.
        $condSets = switch ($kind) {
            'Combined'   { @($IPSecGroupSidSets) + @($SSLVPNGroupSidSets) }
            'IPSecOnly'  { $IPSecGroupSidSets }
            'SSLVPNOnly' { $SSLVPNGroupSidSets }
        }
        $vsaNames = switch ($kind) {
            'Combined'   { @($IPSecVsaGroupNames) + @($SSLVPNVsaGroupNames) }
            'IPSecOnly'  { $IPSecVsaGroupNames }
            'SSLVPNOnly' { $SSLVPNVsaGroupNames }
        }
        $policyFragments.Add((New-NPSPolicyXmlFragment -DisplayName $displayName -ClientIPAddress $ClientIPAddress `
            -AndGroupSidSets $condSets -Sequence $seq))
        $profileFragments.Add((New-NPSProfileXmlFragment -DisplayName $displayName -Kind $kind -VsaGroupNames $vsaNames))
        $seq++
    }

    $rawContent = Add-NPSFragmentsToRawContent -RawContent $rawContent -PolicyFragments $policyFragments -ProfileFragments $profileFragments

    if ($WhatIf) {
        return [pscustomobject]@{
            WouldWriteTo      = $Path
            PolicyFragments   = $policyFragments
            ProfileFragments  = $profileFragments
            ShiftedSequences  = $shiftNeeded
            ResultingXml      = $rawContent
        }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    # (Save-NPSConfig backs up then writes using $config.Encoding - the source file's own detected
    # encoding, never a hardcoded one. See Get-NPSConfigEncoding's notes: a hardcoded UTF-8-no-BOM
    # write here previously re-encoded a real UTF-16 LE ias.xml into something IAS's loader couldn't
    # read, taking the live service down with "The request is not supported" at next start. Cost a real
    # outage once already - do not revert to a hardcoded encoding.)

    return [pscustomobject]@{
        BackupPath       = $backupPath
        PolicyFragments  = $policyFragments
        ProfileFragments = $profileFragments
    }
}

# ---------------------------------------------------------------------------
function Add-NPSSingleRule {
    <#
    .SYNOPSIS
        Adds ONE Network Policy + matching RADIUS Profile - not the standard 3-policy (Combined/IPSecOnly/
        SSLVPNOnly) pattern Add-NPSPolicySet builds. For a plain access grant that doesn't need the
        IPSec/SSLVPN split.

    .PARAMETER GroupSidSets
        Array of arrays (AND/OR sets) - see New-NPSPolicyXmlFragment's -AndGroupSidSets.
    #>
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$DisplayName,
        [Parameter(Mandatory)] [string]$ClientIPAddress,
        [Parameter(Mandatory)] [array]$GroupSidSets,
        [string[]]$VsaGroupNames = @(),
        [int]$InsertAtSequence,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $rawContent = $config.RawContent

    # Always NetworkPolicy - see Add-NPSPolicySet's identical note above.
    $existingSequences = Get-NPSExistingSequences -ConfigXml $config.ConfigXml -PolicyType NetworkPolicy
    if (-not $InsertAtSequence) { $InsertAtSequence = 1 }
    $toShift = @($existingSequences | Where-Object { $_ -ge $InsertAtSequence } | Sort-Object -Descending)

    if ($toShift.Count -gt 0) {
        $np = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.NetworkPolicy.Children
        foreach ($oldSeq in $toShift) {
            $node = $np.ChildNodes | Where-Object { [int]$_.Properties.msNPSequence.'#text' -eq $oldSeq } | Select-Object -First 1
            if (-not $node) { continue }
            $rawContent = Set-NPSPolicySequenceInRawText -RawContent $rawContent -ContainerTag 'NetworkPolicy' -TagName $node.LocalName -OldSequence $oldSeq -NewSequence ($oldSeq + 1)
        }
    }

    $policyFragment  = New-NPSPolicyXmlFragment -DisplayName $DisplayName -ClientIPAddress $ClientIPAddress -AndGroupSidSets $GroupSidSets -Sequence $InsertAtSequence
    $profileFragment = New-NPSProfileXmlFragment -DisplayName $DisplayName -Kind 'Single' -VsaGroupNames $VsaGroupNames

    $rawContent = Add-NPSFragmentsToRawContent -RawContent $rawContent -PolicyFragments @($policyFragment) -ProfileFragments @($profileFragment)

    if ($WhatIf) {
        return [pscustomobject]@{
            WouldWriteTo     = $Path
            PolicyFragment   = $policyFragment
            ProfileFragment  = $profileFragment
            ShiftedSequences = ($toShift.Count -gt 0)
            ResultingXml     = $rawContent
        }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ BackupPath = $backupPath; PolicyFragment = $policyFragment; ProfileFragment = $profileFragment }
}

# ---------------------------------------------------------------------------
function New-NPSConnectionRequestProfileXmlFragment {
    <#
    .SYNOPSIS
        Builds the raw <Tag ...>...</Tag> XML text for a Connection Request Policy's paired
        Proxy_Profiles entry - "authenticate requests matching this CRP locally via Windows
        Authentication" (msAuthProviderType=1). Property order/shape confirmed against a real,
        working "RADIUS from FortiGate" CRP+profile pair (a live client's own ias.xml, dropped in the
        repo root for inspection, 2026-08-18) - see Add-NPSConnectionRequestRule's own corrected
        notes for why this exists now.
    #>
    param([Parameter(Mandatory)][string]$DisplayName)
    $tag = ConvertTo-NPSXmlTagName -DisplayName $DisplayName
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<$tag name=`"$([System.Security.SecurityElement]::Escape($DisplayName))`"><Properties>")
    [void]$sb.Append("<IP_Filter_Template_Guid $script:XmlDtNs dt:dt=`"string`">$script:ZeroGuid</IP_Filter_Template_Guid>")
    [void]$sb.Append("<Opaque_Data $script:XmlDtNs dt:dt=`"string`"></Opaque_Data>")
    [void]$sb.Append("<Template_Guid $script:XmlDtNs dt:dt=`"string`">$script:ZeroGuid</Template_Guid>")
    [void]$sb.Append("<msAuthProviderType $script:XmlDtNs dt:dt=`"int`">1</msAuthProviderType>")
    [void]$sb.Append("<msOverrideRAPAuth $script:XmlDtNs dt:dt=`"boolean`">0</msOverrideRAPAuth>")
    [void]$sb.Append("</Properties></$tag>")
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
function Add-NPSConnectionRequestRule {
    <#
    .SYNOPSIS
        Adds ONE Connection Request Policy - the CRP equivalent of Add-NPSSingleRule, WITH its paired
        Proxy_Profiles entry (New-NPSConnectionRequestProfileXmlFragment, msAuthProviderType=1 -
        "authenticate locally"), and freeform -Conditions instead of Add-NPSSingleRule's fixed
        Client-IP + group-SID shape - real CRPs commonly use TIMEOFDAY(...), Client-Friendly-Name
        MATCH, and NAS-Port-Type MATCH, which that shape has no way to express at all.

    .DESCRIPTION
        CORRECTED, 2026-08-18: this used to deliberately skip the paired profile ("every real CRP
        sample seen routes/authenticates locally... so pairing one here would be inventing something
        this MSP's environments don't actually use") - that assumption was wrong. A real, working
        "RADIUS from FortiGate" CRP (a live client's own ias.xml) DOES have a paired Proxy_Profiles
        entry, and the maintainer confirmed he'd had to build a CRP by hand in the NPS console (recognizable
        as the "MANUAL - ..." entry in that same file) specifically because this function's
        auto-generated one was missing that piece and didn't work correctly without it. "Authenticates
        locally" describes WHAT the profile says (msAuthProviderType=1, not a RADIUS proxy target) -
        it never meant the profile itself could be omitted.

    .PARAMETER Conditions
        Fully-formed msNPConstraint strings, e.g. MATCH("Client-IP-Address=1.2.3.4"),
        MATCH("Client-Friendly-Name=.*pGINA"), TIMEOFDAY("..."), USERNTGROUPS("SID1","SID2") - see
        Invoke-AddNPSConnectionRequestPolicyWizard (NPSInteractive.ps1) for how these get built
        interactively.
    #>
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$DisplayName,
        [Parameter(Mandatory)] [string[]]$Conditions,
        [int]$InsertAtSequence,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $rawContent = $config.RawContent
    $containerTag = Get-NPSPolicyContainerTag -PolicyType ConnectionRequest

    $existingSequences = Get-NPSExistingSequences -ConfigXml $config.ConfigXml -PolicyType ConnectionRequest
    if (-not $InsertAtSequence) { $InsertAtSequence = 1 }
    $toShift = @($existingSequences | Where-Object { $_ -ge $InsertAtSequence } | Sort-Object -Descending)

    if ($toShift.Count -gt 0) {
        $crp = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.$containerTag.Children
        foreach ($oldSeq in $toShift) {
            $node = $crp.ChildNodes | Where-Object { [int]$_.Properties.msNPSequence.'#text' -eq $oldSeq } | Select-Object -First 1
            if (-not $node) { continue }
            $rawContent = Set-NPSPolicySequenceInRawText -RawContent $rawContent -ContainerTag $containerTag -TagName $node.LocalName -OldSequence $oldSeq -NewSequence ($oldSeq + 1)
        }
    }

    $policyFragment = New-NPSPolicyRecordXmlFragment -DisplayName $DisplayName -Conditions $Conditions -Sequence $InsertAtSequence
    $profileFragment = New-NPSConnectionRequestProfileXmlFragment -DisplayName $DisplayName

    $rawContent = Add-NPSFragmentsToRawContent -RawContent $rawContent -PolicyContainer $containerTag -PolicyFragments @($policyFragment)
    $rawContent = Add-NPSChildFragmentToRawContent -RawContent $rawContent -ContainerTag 'Proxy_Profiles' -Fragment $profileFragment

    if ($WhatIf) {
        return [pscustomobject]@{
            WouldWriteTo     = $Path
            PolicyFragment   = $policyFragment
            ProfileFragment  = $profileFragment
            ShiftedSequences = ($toShift.Count -gt 0)
            ResultingXml     = $rawContent
        }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ BackupPath = $backupPath; PolicyFragment = $policyFragment; ProfileFragment = $profileFragment }
}

# ---------------------------------------------------------------------------
function Get-NPSPolicySummary {
    <#
    .SYNOPSIS
        Friendly summary of every REAL policy (excludes the 999999/999998 built-ins) in -PolicyType's
        own container - Name, Tag, Sequence, Enabled, Constraints - for display or selection (status
        view, reorder/deactivate/delete pickers). Network Policies and Connection Request Policies are
        two entirely separate universes (see module NOTES) - always call this once per type, never
        assume one call covers both.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType
    )

    $config = Read-NPSConfig -Path $Path
    $containerTag = Get-NPSPolicyContainerTag -PolicyType $PolicyType
    $np = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.$containerTag.Children

    $results = foreach ($node in $np.ChildNodes) {
        $seq = [int]$node.Properties.msNPSequence.'#text'
        if ($seq -ge 900000) { continue }
        $enabledText = $node.Properties.Policy_Enabled.'#text'
        $constraints = @($node.Properties.msNPConstraint) | ForEach-Object { $_.'#text' }
        [pscustomobject]@{
            Name        = $node.name
            Tag         = $node.LocalName
            Sequence    = $seq
            Enabled     = ($enabledText -eq '1')
            Constraints = $constraints
        }
    }
    return @($results | Sort-Object Sequence)
}

# ---------------------------------------------------------------------------
function Get-NPSClients {
    <#
    .SYNOPSIS
        Reads every RADIUS client (Protocols\Microsoft Radius Protocol\Clients) from ias.xml - Name,
        IP address, shared secret, enabled/signature state - for display, editing, or picking a
        Client-IP-Address when adding a rule.

    .DESCRIPTION
        Returns SharedSecret in plain text (that's how NPS itself stores it in ias.xml - there's no
        more-protected form to return instead). Callers displaying this to a screen should mask it
        by default and only reveal on request - see NPS-Manager.ps1's client management menu for
        that convention. Not this function's job to decide UI treatment.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $config = Read-NPSConfig -Path $Path
    $clients = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.Protocols.Children.Microsoft_Radius_Protocol.Children.Clients.Children

    if (-not $clients) { return @() }

    $results = foreach ($node in $clients.ChildNodes) {
        [pscustomobject]@{
            Name                     = $node.name
            Tag                      = $node.LocalName
            IPAddress                = $node.Properties.IP_Address.'#text'
            SharedSecret             = $node.Properties.Shared_Secret.'#text'
            Enabled                  = ($node.Properties.Radius_Client_Enabled.'#text' -eq '1')
            RequireSignature         = ($node.Properties.Require_Signature.'#text' -eq '1')
            # Non-zero-GUID = this client's secret was originally copied from a Shared Secret
            # template (see Get-NPSSharedSecretTemplates / Resolve-NPSSharedSecretTemplateName to
            # resolve this to a name - NOT resolvable from ias.xml alone, confirmed live: templates
            # live in a separate file, iastemplates.xml). Verified live that this GUID can go STALE
            # (stays non-zero even after Set-NPSClientAttribute/Set-NpsRadiusClient overwrites the
            # client's own SharedSecret with an unrelated literal value) - its presence means "this
            # client WAS set up via a template at some point", not a live guarantee the two still match.
            ClientSecretTemplateGuid = $node.Properties.Client_Secret_Template_Guid.'#text'
            # A SEPARATE, distinct link from ClientSecretTemplateGuid above - this is a RADIUS Client
            # Template (a different template type than a Shared Secret Template; own container is
            # believed to be Radius_Clients_Templates, NOT yet confirmed live - see
            # Explore-NPSClientTemplates.ps1). Zero-GUID on every sample seen so far except reportedly
            # a real client's config, where a client can apparently be set up via a RADIUS Client
            # Template that itself references a Shared Secret Template - i.e. up to two levels of
            # template indirection above a client's literal Shared_Secret. Exposed here as raw data
            # only; no resolution/propagation behavior verified yet for this template type.
            ClientTemplateGuid       = $node.Properties.Template_Guid.'#text'
        }
    }
    return @($results)
}

# ---------------------------------------------------------------------------
function Get-NPSSharedSecretTemplates {
    <#
    .SYNOPSIS
        Reads every Shared Secret template directly from iastemplates.xml - Name, the literal secret
        value, and the template's own Template_Guid.

    .DESCRIPTION
        iastemplates.xml is a SEPARATE file from ias.xml (same directory, same UTF-16 LE encoding,
        same general schema conventions) - confirmed live against a real test template/client pair,
        not guessed. Templates are NOT stored anywhere inside ias.xml itself, despite ias.xml's own
        SDO_Schema section listing property names like "RADIUS_Shared_Secrets_Templates" - those are
        schema/property-definition metadata only, not a real data container.

        Deliberately reads the raw file directly rather than using the official
        Get-NpsSharedSecretTemplate cmdlet - that cmdlet only returns Name and SharedSecret, NOT the
        Template_Guid (confirmed via live testing), which is the one thing needed to resolve a
        client's own Client_Secret_Template_Guid back to a template name.
    #>
    param([string]$Path = "C:\Windows\System32\ias\iastemplates.xml")

    $config = Read-NPSConfig -Path $Path
    $templates = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Shared_Secrets_Templates.Children

    if (-not $templates) { return @() }

    $results = foreach ($node in $templates.ChildNodes) {
        [pscustomobject]@{
            Name         = $node.name
            Tag          = $node.LocalName
            SharedSecret = $node.Properties.RADIUS_Shared_Secret.'#text'
            TemplateGuid = $node.Properties.Template_Guid.'#text'
        }
    }
    return @($results)
}

# ---------------------------------------------------------------------------
function Resolve-NPSSharedSecretTemplateName {
    <#
    .SYNOPSIS
        Resolves a Client_Secret_Template_Guid value (from Get-NPSClients) to its template's display
        name, by cross-referencing Get-NPSSharedSecretTemplates' own Template_Guid values. Returns
        $null for a zero/empty GUID, a GUID that matches no known template (e.g. a stale reference
        left behind after a direct secret edit), or if iastemplates.xml can't be read at all
        (best-effort - a resolution failure here shouldn't block displaying/editing the client itself).
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Guid,
        [string]$TemplatesPath = "C:\Windows\System32\ias\iastemplates.xml"
    )
    if (-not $Guid -or $Guid -eq '{00000000-0000-0000-0000-000000000000}') { return $null }
    try {
        $templates = Get-NPSSharedSecretTemplates -Path $TemplatesPath
        $match = $templates | Where-Object { $_.TemplateGuid -eq $Guid } | Select-Object -First 1
        return $match.Name
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
function Get-NPSClientTemplates {
    <#
    .SYNOPSIS
        Reads every RADIUS Client Template directly from iastemplates.xml - a DIFFERENT template type
        than a Shared Secret Template (Get-NPSSharedSecretTemplates), confirmed live against a real
        a real multi-level client/template chain (the maintainer, direct inspection).

    .DESCRIPTION
        Lives under Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Clients_Templates
        in iastemplates.xml - a SIBLING container to RADIUS_Shared_Secrets_Templates, not nested inside
        it. NOTE the real tag is spelled RADIUS_Clients_Templates (all-caps RADIUS) - ias.xml's own
        schema-metadata RequiredProperties listing spells it "Radius_Clients_Templates" (mixed case),
        which cost a false negative in this session's own exploration tooling before being caught.

        Unlike a Shared Secret Template (which stores just Name/SharedSecret/TemplateGuid), a RADIUS
        Client Template is a full snapshot of an entire client configuration - it uses the EXACT SAME
        property schema as a live RADIUS Client entry (IP_Address, NAS_Manufacturer, Opaque_Data,
        Radius_Client_Enabled, Require_Signature, Shared_Secret, Template_Guid - its own identity -
        and, confirmed live, its OWN Client_Secret_Template_Guid pointing at a Shared Secret Template).
        That means a client's secret can be up to two levels removed from where the tech thinks they
        just edited it: Client -(Template_Guid)-> RADIUS Client Template
        -(Client_Secret_Template_Guid)-> Shared Secret Template - each level holding its own literal,
        independently-editable copy (same "copy, not live link" pattern already proven one level down
        for Client<->Shared Secret Template - propagation behavior for THIS additional level is not
        yet verified, see Test-NPSSecretPropagation.ps1 for the live-probe approach used for the
        one-level case).
    #>
    param([string]$Path = "C:\Windows\System32\ias\iastemplates.xml")

    $config = Read-NPSConfig -Path $Path
    $templates = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Clients_Templates.Children

    if (-not $templates) { return @() }

    $results = foreach ($node in $templates.ChildNodes) {
        [pscustomobject]@{
            Name                     = $node.name
            Tag                      = $node.LocalName
            IPAddress                = $node.Properties.IP_Address.'#text'
            SharedSecret             = $node.Properties.Shared_Secret.'#text'
            Enabled                  = ($node.Properties.Radius_Client_Enabled.'#text' -eq '1')
            RequireSignature         = ($node.Properties.Require_Signature.'#text' -eq '1')
            TemplateGuid             = $node.Properties.Template_Guid.'#text'
            ClientSecretTemplateGuid = $node.Properties.Client_Secret_Template_Guid.'#text'
        }
    }
    return @($results)
}

# ---------------------------------------------------------------------------
function Resolve-NPSClientTemplateName {
    <#
    .SYNOPSIS
        Resolves a client's ClientTemplateGuid value (from Get-NPSClients) to its RADIUS Client
        Template's display name, by cross-referencing Get-NPSClientTemplates' own TemplateGuid values.
        Same best-effort/$null-on-failure contract as Resolve-NPSSharedSecretTemplateName.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Guid,
        [string]$TemplatesPath = "C:\Windows\System32\ias\iastemplates.xml"
    )
    if (-not $Guid -or $Guid -eq '{00000000-0000-0000-0000-000000000000}') { return $null }
    try {
        $templates = Get-NPSClientTemplates -Path $TemplatesPath
        $match = $templates | Where-Object { $_.TemplateGuid -eq $Guid } | Select-Object -First 1
        return $match.Name
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
function Set-NPSSharedSecretTemplateValue {
    <#
    .SYNOPSIS
        Updates a Shared Secret template's stored secret value in iastemplates.xml, by template name -
        and CASCADES that new value to every linked RADIUS Client Template and every linked live
        Client (directly-linked, or linked via one of those RADIUS Client Templates), mirroring the
        native NPS console's own confirmed-live behavior (the maintainer, live test: editing a Shared Secret
        Template via the console propagated the new value all the way down through a RADIUS Client
        Template to an already-existing linked client's own Shared_Secret field, in one save).

    .DESCRIPTION
        Reuses the exact same safe primitives already proven against ias.xml (Read-NPSConfig,
        Save-NPSConfig/Backup-NPSConfig, ConvertTo-NPSXmlText/Tag) rather than new file-handling code
        - iastemplates.xml uses the same UTF-16 LE encoding and schema conventions, confirmed live.

        Touches up to TWO files in one call: iastemplates.xml always (the template itself, plus any
        linked RADIUS Client Templates - both live there), and ias.xml only if at least one live
        Client actually needs updating (skipped entirely, no backup taken, if none do).

        This is a WIDER blast radius than Set-NPSClientAttribute's single-client edit - every client
        sharing this template gets the new secret, not just one. Callers driving a UI should make that
        explicit before calling this (see NPS-Manager.ps1's Option 4 edit-client flow).

        NOT scoped to the RADIUS_Shared_Secrets_Templates/RADIUS_Clients_Templates container when
        matching a tag name for the text splice (same pattern already used elsewhere in this module) -
        relies on Shared Secret Templates and RADIUS Client Templates having distinct display names
        (true in every real sample seen, incl. The maintainer's own "-Secret" naming suffix convention) rather
        than fully container-scoped matching. Worth revisiting if that convention is ever not followed.
    #>
    param(
        [Parameter(Mandatory)][string]$TemplateName,
        [Parameter(Mandatory)][string]$NewSecret,
        [string]$Path = "C:\Windows\System32\ias\iastemplates.xml",
        [string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml",
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $TemplateName
    $templates = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Shared_Secrets_Templates.Children
    $node = if ($templates) { $templates.$tag } else { $null }
    if (-not $node) { throw "No Shared Secret template named '$TemplateName' found." }

    $currentValue = $node.Properties.RADIUS_Shared_Secret.'#text'
    $templateGuid = $node.Properties.Template_Guid.'#text'

    # MUST re-encode $currentValue the same way the raw file actually stores it before using it to
    # build a search fragment - $node.Properties.X.'#text' comes back XML-DECODED (e.g. "&amp;" -> "&")
    # from the parsed [xml], but $config.RawContent still has it encoded. A secret containing &, <, or
    # > (very plausible - this is exactly what a real captured secret had) would otherwise silently
    # never match, so .Replace() finds nothing, the file is "written" unchanged, and this still
    # reports Changed=true - caught via a live test against a real secret value, not synthetic data.
    $currentValueEscaped = ConvertTo-NPSXmlText $currentValue
    $newValueEscaped = ConvertTo-NPSXmlText $NewSecret

    $oldFragment = "<RADIUS_Shared_Secret $($script:XmlDtNs) dt:dt=`"string`">$currentValueEscaped</RADIUS_Shared_Secret>"
    $newFragment = "<RADIUS_Shared_Secret $($script:XmlDtNs) dt:dt=`"string`">$newValueEscaped</RADIUS_Shared_Secret>"

    if ($oldFragment -eq $newFragment) {
        return [pscustomobject]@{ Changed = $false; TemplateName = $TemplateName; CascadedClientTemplateNames = @(); CascadedClientNames = @() }
    }

    $tagPattern = "(<$([regex]::Escape($tag))\b[^>]*>.*?</$([regex]::Escape($tag))>)"
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
        param($m)
        $m.Value.Replace($oldFragment, $newFragment)
    }
    $rawContent = [regex]::Replace($config.RawContent, $tagPattern, $evaluator, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    # --- Cascade pass 1: every RADIUS Client Template linked to this Shared Secret Template - own
    # Shared_Secret property, SAME file/buffer as above. Reads from $config.ConfigXml (the ORIGINAL
    # parsed DOM, untouched by the text splice just performed above - safe, since that splice only
    # rewrote $rawContent, a separate string) so the lookup isn't affected by our own not-yet-saved edit.
    $cascadedClientTemplateNames = [System.Collections.Generic.List[string]]::new()
    $cascadedClientTemplateGuids = [System.Collections.Generic.List[string]]::new()
    $rctContainer = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Clients_Templates.Children
    if ($rctContainer) {
        foreach ($rctNode in @($rctContainer.ChildNodes)) {
            if ($rctNode.Properties.Client_Secret_Template_Guid.'#text' -ne $templateGuid) { continue }

            $rctCurrentValue = ConvertTo-NPSXmlText $rctNode.Properties.Shared_Secret.'#text'
            $rctOldFragment = "<Shared_Secret $($script:XmlDtNs) dt:dt=`"string`">$rctCurrentValue</Shared_Secret>"
            $rctNewFragment = "<Shared_Secret $($script:XmlDtNs) dt:dt=`"string`">$newValueEscaped</Shared_Secret>"
            if ($rctOldFragment -eq $rctNewFragment) { continue }

            $rctTagPattern = "(<$([regex]::Escape($rctNode.LocalName))\b[^>]*>.*?</$([regex]::Escape($rctNode.LocalName))>)"
            $rctEvaluator = [System.Text.RegularExpressions.MatchEvaluator]{
                param($m)
                $m.Value.Replace($rctOldFragment, $rctNewFragment)
            }
            $rawContent = [regex]::Replace($rawContent, $rctTagPattern, $rctEvaluator, [System.Text.RegularExpressions.RegexOptions]::Singleline)
            $cascadedClientTemplateNames.Add($rctNode.name)
            $cascadedClientTemplateGuids.Add($rctNode.Properties.Template_Guid.'#text')
        }
    }

    # --- Cascade pass 2: every live Client - DIFFERENT file (ias.xml), separate read/write pass -
    # linked either directly to this Shared Secret Template, or indirectly via a RADIUS Client
    # Template just updated above.
    $cascadedClientNames = [System.Collections.Generic.List[string]]::new()
    $iasRawContent = $null
    $iasConfig = $null
    try { $iasConfig = Read-NPSConfig -Path $IASConfigPath } catch { $iasConfig = $null }
    if ($iasConfig) {
        $iasRawContent = $iasConfig.RawContent
        $clientsContainer = $iasConfig.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.Protocols.Children.Microsoft_Radius_Protocol.Children.Clients.Children
        if ($clientsContainer) {
            foreach ($clientNode in @($clientsContainer.ChildNodes)) {
                $directLink = ($clientNode.Properties.Client_Secret_Template_Guid.'#text' -eq $templateGuid)
                $viaRctLink = ($cascadedClientTemplateGuids.Count -gt 0) -and ($clientNode.Properties.Template_Guid.'#text' -in $cascadedClientTemplateGuids)
                if (-not ($directLink -or $viaRctLink)) { continue }

                $clientCurrentValue = ConvertTo-NPSXmlText $clientNode.Properties.Shared_Secret.'#text'
                $clientOldFragment = "<Shared_Secret $($script:XmlDtNs) dt:dt=`"string`">$clientCurrentValue</Shared_Secret>"
                $clientNewFragment = "<Shared_Secret $($script:XmlDtNs) dt:dt=`"string`">$newValueEscaped</Shared_Secret>"
                if ($clientOldFragment -eq $clientNewFragment) { continue }

                $clientTagPattern = "(<$([regex]::Escape($clientNode.LocalName))\b[^>]*>.*?</$([regex]::Escape($clientNode.LocalName))>)"
                $clientEvaluator = [System.Text.RegularExpressions.MatchEvaluator]{
                    param($m)
                    $m.Value.Replace($clientOldFragment, $clientNewFragment)
                }
                $iasRawContent = [regex]::Replace($iasRawContent, $clientTagPattern, $clientEvaluator, [System.Text.RegularExpressions.RegexOptions]::Singleline)
                $cascadedClientNames.Add($clientNode.name)
            }
        }
    }

    if ($WhatIf) {
        return [pscustomobject]@{
            Changed = $true; TemplateName = $TemplateName; ResultingXml = $rawContent
            CascadedClientTemplateNames = @($cascadedClientTemplateNames); CascadedClientNames = @($cascadedClientNames)
            ResultingIASXml = $iasRawContent
        }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    $iasBackupPath = $null
    if ($cascadedClientNames.Count -gt 0) {
        $iasBackupPath = Save-NPSConfig -Path $IASConfigPath -RawContent $iasRawContent -Encoding $iasConfig.Encoding
    }
    return [pscustomobject]@{
        Changed = $true; TemplateName = $TemplateName; BackupPath = $backupPath
        CascadedClientTemplateNames = @($cascadedClientTemplateNames); CascadedClientNames = @($cascadedClientNames)
        IASBackupPath = $iasBackupPath
    }
}

# ---------------------------------------------------------------------------
function New-NPSSharedSecretTemplateXmlFragment {
    <#
    .SYNOPSIS
        Builds the raw <Tag ...>...</Tag> XML text for one Shared Secret Template entry - property
        order (RADIUS_Shared_Secret, then Template_Guid) verified against a real sample
        (Samples\iastemplates.xml, "SC-FortiGate-Secret").
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$SharedSecret,
        [Parameter(Mandatory)][string]$TemplateGuid
    )
    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<$tag name=`"$([System.Security.SecurityElement]::Escape($Name))`"><Properties>")
    [void]$sb.Append("<RADIUS_Shared_Secret $script:XmlDtNs dt:dt=`"string`">$(ConvertTo-NPSXmlText $SharedSecret)</RADIUS_Shared_Secret>")
    [void]$sb.Append("<Template_Guid $script:XmlDtNs dt:dt=`"string`">$TemplateGuid</Template_Guid>")
    [void]$sb.Append("</Properties></$tag>")
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
function New-NPSSharedSecretTemplate {
    <#
    .SYNOPSIS
        Creates a new Shared Secret Template in iastemplates.xml - splices in just before
        RADIUS_Shared_Secrets_Templates's own closing tag (confirmed unique in the file, unlike
        ias.xml's "</Clients>" collision - see Add-NPSClient's notes for that different case).
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$SharedSecret,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name
    $existing = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Shared_Secrets_Templates.Children
    if ($existing -and $existing.$tag) {
        throw "A Shared Secret Template named '$Name' already exists."
    }

    # Real GUID, not the zero placeholder - THIS is the template's own identity, what clients/RADIUS
    # Client Templates link to via their own Client_Secret_Template_Guid. Braced-uppercase to match
    # every real Template_Guid value seen (e.g. "{7F9A8CF3-8002-4A6E-8EAB-8B04591321F8}").
    $newGuid = ([guid]::NewGuid().ToString('B')).ToUpper()
    $fragment = New-NPSSharedSecretTemplateXmlFragment -Name $Name -SharedSecret $SharedSecret -TemplateGuid $newGuid
    $rawContent = Add-NPSChildFragmentToRawContent -RawContent $config.RawContent -ContainerTag 'RADIUS_Shared_Secrets_Templates' -Fragment $fragment

    if ($WhatIf) {
        return [pscustomobject]@{ WouldWriteTo = $Path; Fragment = $fragment; TemplateGuid = $newGuid; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ BackupPath = $backupPath; TemplateName = $Name; TemplateGuid = $newGuid }
}

# ---------------------------------------------------------------------------
function Get-NPSSharedSecretTemplateUsage {
    <#
    .SYNOPSIS
        Read-only: what currently links to a given Shared Secret Template, by name - every RADIUS
        Client Template and every live Client whose own Client_Secret_Template_Guid matches it. For
        showing a tech what deleting/editing a template will actually affect BEFORE they confirm -
        deleting doesn't clean up these references (same "dangling GUID" precedent already
        established for a direct client-secret edit - see Set-NPSClientAttribute's own notes), so a
        tech should see the blast radius up front rather than discover it later.
    #>
    param(
        [Parameter(Mandatory)][string]$TemplateName,
        [string]$TemplatesPath = "C:\Windows\System32\ias\iastemplates.xml",
        [string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml"
    )

    $templates = Get-NPSSharedSecretTemplates -Path $TemplatesPath
    $template = $templates | Where-Object { $_.Name -eq $TemplateName } | Select-Object -First 1
    if (-not $template) { throw "No Shared Secret Template named '$TemplateName' found." }

    $clientTemplateNames = @(
        (Get-NPSClientTemplates -Path $TemplatesPath) |
        Where-Object { $_.ClientSecretTemplateGuid -eq $template.TemplateGuid } |
        Select-Object -ExpandProperty Name
    )
    $clientNames = @()
    try {
        $clientNames = @(
            (Get-NPSClients -Path $IASConfigPath) |
            Where-Object { $_.ClientSecretTemplateGuid -eq $template.TemplateGuid } |
            Select-Object -ExpandProperty Name
        )
    } catch {}

    return [pscustomobject]@{
        TemplateName          = $TemplateName
        LinkedClientTemplates = $clientTemplateNames
        LinkedClients          = $clientNames
    }
}

# ---------------------------------------------------------------------------
function Remove-NPSSharedSecretTemplate {
    <#
    .SYNOPSIS
        Deletes a Shared Secret Template entirely. Does NOT clean up anything that references it (see
        Get-NPSSharedSecretTemplateUsage - call that first to show the tech what's linked before they
        confirm) - matches this codebase's existing precedent of leaving a dangling GUID behind rather
        than silently rewriting other records as a side effect of an unrelated delete.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name
    $templates = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Shared_Secrets_Templates.Children
    $node = if ($templates) { $templates.$tag } else { $null }
    if (-not $node) { throw "No Shared Secret Template named '$Name' found." }

    $rawContent = Remove-NPSFragmentFromRawText -RawContent $config.RawContent -TagName $tag

    if ($WhatIf) {
        return [pscustomobject]@{ DeletedTemplate = $Name; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ BackupPath = $backupPath; DeletedTemplate = $Name }
}

# ---------------------------------------------------------------------------
function New-NPSClientXmlFragment {
    <#
    .SYNOPSIS
        Builds the raw <Tag ...>...</Tag> XML text for one RADIUS Client entry, matching the exact
        property order/shape verified against a real production site's own FortiGate and "Self" client entries:
        Client_Secret_Template_Guid, IP_Address, NAS_Manufacturer, Opaque_Data,
        Radius_Client_Enabled, Require_Signature, Shared_Secret, Template_Guid.

    .PARAMETER TemplateGuid
        Which RADIUS Client Template this client was "created from" - zero-GUID (default) for a
        plain client with no template lineage. Set by Add-NPSClientFromTemplate when provisioning a
        client from an existing RADIUS Client Template - see its own notes for why both GUIDs get
        copied from the template rather than left zero.

    .PARAMETER ClientSecretTemplateGuid
        Which Shared Secret Template this client's secret is linked to - zero-GUID (default) for a
        plain literal secret with no template link. Same "copy, not live link" semantics as every
        other template reference in this schema (see Get-NPSClientTemplates' own notes) - the literal
        SharedSecret value is ALWAYS what's actually used/stored; this GUID is purely a "where did
        this value come from" breadcrumb NPS itself also keeps.
    #>
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$IPAddress,
        [Parameter(Mandatory)] [string]$SharedSecret,
        [bool]$Enabled = $true,
        [bool]$RequireSignature = $false,
        [string]$TemplateGuid = $script:ZeroGuid,
        [string]$ClientSecretTemplateGuid = $script:ZeroGuid
    )

    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<$tag name=`"$([System.Security.SecurityElement]::Escape($Name))`"><Properties>")
    [void]$sb.Append("<Client_Secret_Template_Guid $script:XmlDtNs dt:dt=`"string`">$ClientSecretTemplateGuid</Client_Secret_Template_Guid>")
    [void]$sb.Append("<IP_Address $script:XmlDtNs dt:dt=`"string`">$(ConvertTo-NPSXmlText $IPAddress)</IP_Address>")
    [void]$sb.Append("<NAS_Manufacturer $script:XmlDtNs dt:dt=`"int`">0</NAS_Manufacturer>")
    [void]$sb.Append("<Opaque_Data $script:XmlDtNs dt:dt=`"string`"></Opaque_Data>")
    [void]$sb.Append("<Radius_Client_Enabled $script:XmlDtNs dt:dt=`"boolean`">$(if ($Enabled) { '1' } else { '0' })</Radius_Client_Enabled>")
    [void]$sb.Append("<Require_Signature $script:XmlDtNs dt:dt=`"boolean`">$(if ($RequireSignature) { '1' } else { '0' })</Require_Signature>")
    [void]$sb.Append("<Shared_Secret $script:XmlDtNs dt:dt=`"string`">$(ConvertTo-NPSXmlText $SharedSecret)</Shared_Secret>")
    [void]$sb.Append("<Template_Guid $script:XmlDtNs dt:dt=`"string`">$TemplateGuid</Template_Guid>")
    [void]$sb.Append("</Properties></$tag>")

    return $sb.ToString()
}

# ---------------------------------------------------------------------------
function Add-NPSClient {
    <#
    .SYNOPSIS
        Adds a new RADIUS client (Protocols\Microsoft Radius Protocol\Clients) to ias.xml.

    .DESCRIPTION
        Splices in just before the section's own closing tag, anchored on "</Children></Clients>" -
        NOT bare "</Clients>", which is NOT unique in the file (a schema-attribute-definition section
        elsewhere in ias.xml also has its own unrelated <Clients name="Clients"> element, which
        closes "</Properties></Clients>" instead - confirmed by direct inspection of both real
        samples before trusting this anchor; a naive bare "</Clients>" replace would have spliced
        into - and corrupted - that schema section too).
    #>
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$IPAddress,
        [Parameter(Mandatory)] [string]$SharedSecret,
        [bool]$Enabled = $true,
        [bool]$RequireSignature = $false,
        # See New-NPSClientXmlFragment's own notes - both default to zero-GUID (a plain client, no
        # template lineage), populated only by Add-NPSClientFromTemplate.
        [string]$TemplateGuid = $script:ZeroGuid,
        [string]$ClientSecretTemplateGuid = $script:ZeroGuid,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name
    $existingClients = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.Protocols.Children.Microsoft_Radius_Protocol.Children.Clients.Children
    if ($existingClients -and $existingClients.$tag) {
        throw "A RADIUS client named '$Name' already exists."
    }

    $fragment = New-NPSClientXmlFragment -Name $Name -IPAddress $IPAddress -SharedSecret $SharedSecret -Enabled $Enabled -RequireSignature $RequireSignature -TemplateGuid $TemplateGuid -ClientSecretTemplateGuid $ClientSecretTemplateGuid
    $rawContent = Add-NPSChildFragmentToRawContent -RawContent $config.RawContent -ContainerTag 'Clients' -Fragment $fragment

    if ($WhatIf) {
        return [pscustomobject]@{ WouldWriteTo = $Path; Fragment = $fragment; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ BackupPath = $backupPath; Fragment = $fragment }
}

# ---------------------------------------------------------------------------
function New-NPSClientTemplate {
    <#
    .SYNOPSIS
        Creates a new RADIUS Client Template in iastemplates.xml - reuses New-NPSClientXmlFragment
        (a RADIUS Client Template uses the EXACT SAME property schema as a live Client, confirmed
        live - see Get-NPSClientTemplates' own notes), just spliced into
        RADIUS_Clients_Templates instead of ias.xml's Clients container, and with a REAL Template_Guid
        (its own identity) instead of the zero placeholder a plain client gets.

    .PARAMETER SharedSecretTemplateName
        Optional - links this Client Template's Client_Secret_Template_Guid to an existing Shared
        Secret Template (resolved by name via Get-NPSSharedSecretTemplates). -SharedSecret is still
        REQUIRED and stored literally regardless (same "copy, not live link" semantics as everywhere
        else in this schema) - this link is a breadcrumb NPS itself also keeps, not a substitute for
        the literal value.

    .PARAMETER RequireSignature
        Maps to the NPS console's own "Client must always send the message authenticator in the
        request" checkbox (Require_Signature in the XML). Defaults to $true (2026-08-27 per the maintainer:
        "the default template should include the 'Requires message authenticator' item checked") -
        was $false. Invoke-AddClientTemplate (NPS-Manager.ps1) never explicitly prompts for or sets
        this, so every new Client Template created through the wizard gets whatever this default is;
        flipping it here is what actually changes that behavior. Add-NPSClientFromTemplate copies a
        template's own RequireSignature value onto every client provisioned from it, so this default
        cascades there for free - no separate change needed. Add-NPSClient's own default (a plain,
        non-templated client) is intentionally untouched - The maintainer's ask was specifically about client
        templates.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$IPAddress,
        [Parameter(Mandatory)][string]$SharedSecret,
        [bool]$Enabled = $true,
        [bool]$RequireSignature = $true,
        [string]$SharedSecretTemplateName,
        [string]$TemplatesPath = "C:\Windows\System32\ias\iastemplates.xml",
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name
    $existing = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Clients_Templates.Children
    if ($existing -and $existing.$tag) {
        throw "A RADIUS Client Template named '$Name' already exists."
    }

    $secretTemplateGuid = $script:ZeroGuid
    if ($SharedSecretTemplateName) {
        $sst = Get-NPSSharedSecretTemplates -Path $TemplatesPath | Where-Object { $_.Name -eq $SharedSecretTemplateName } | Select-Object -First 1
        if (-not $sst) { throw "No Shared Secret Template named '$SharedSecretTemplateName' found." }
        $secretTemplateGuid = $sst.TemplateGuid
    }

    $newGuid = ([guid]::NewGuid().ToString('B')).ToUpper()
    $fragment = New-NPSClientXmlFragment -Name $Name -IPAddress $IPAddress -SharedSecret $SharedSecret -Enabled $Enabled -RequireSignature $RequireSignature -TemplateGuid $newGuid -ClientSecretTemplateGuid $secretTemplateGuid
    $rawContent = Add-NPSChildFragmentToRawContent -RawContent $config.RawContent -ContainerTag 'RADIUS_Clients_Templates' -Fragment $fragment

    if ($WhatIf) {
        return [pscustomobject]@{ WouldWriteTo = $Path; Fragment = $fragment; TemplateGuid = $newGuid; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ BackupPath = $backupPath; TemplateName = $Name; TemplateGuid = $newGuid }
}

# ---------------------------------------------------------------------------
function Get-NPSClientTemplateUsage {
    <#
    .SYNOPSIS
        Read-only: every live Client whose own Template_Guid matches this RADIUS Client Template -
        i.e. every client "created from" it (see Add-NPSClientFromTemplate). Same "show the blast
        radius before deleting" purpose as Get-NPSSharedSecretTemplateUsage.
    #>
    param(
        [Parameter(Mandatory)][string]$TemplateName,
        [string]$TemplatesPath = "C:\Windows\System32\ias\iastemplates.xml",
        [string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml"
    )

    $templates = Get-NPSClientTemplates -Path $TemplatesPath
    $template = $templates | Where-Object { $_.Name -eq $TemplateName } | Select-Object -First 1
    if (-not $template) { throw "No RADIUS Client Template named '$TemplateName' found." }

    $clientNames = @()
    try {
        $clientNames = @(
            (Get-NPSClients -Path $IASConfigPath) |
            Where-Object { $_.ClientTemplateGuid -eq $template.TemplateGuid } |
            Select-Object -ExpandProperty Name
        )
    } catch {}

    return [pscustomobject]@{ TemplateName = $TemplateName; LinkedClients = $clientNames }
}

# ---------------------------------------------------------------------------
function Remove-NPSClientTemplate {
    <#
    .SYNOPSIS
        Deletes a RADIUS Client Template entirely. Does NOT clean up anything that references it (see
        Get-NPSClientTemplateUsage) - same dangling-GUID precedent as Remove-NPSSharedSecretTemplate.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name
    $templates = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Clients_Templates.Children
    $node = if ($templates) { $templates.$tag } else { $null }
    if (-not $node) { throw "No RADIUS Client Template named '$Name' found." }

    $rawContent = Remove-NPSFragmentFromRawText -RawContent $config.RawContent -TagName $tag

    if ($WhatIf) {
        return [pscustomobject]@{ DeletedTemplate = $Name; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ BackupPath = $backupPath; DeletedTemplate = $Name }
}

# ---------------------------------------------------------------------------
function Set-NPSClientTemplateAttribute {
    <#
    .SYNOPSIS
        Updates ONE attribute on an existing RADIUS Client Template (IPAddress, SharedSecret,
        Enabled, or RequireSignature) - the RADIUS_Clients_Templates equivalent of
        Set-NPSClientAttribute, same decouple-on-direct-secret-edit behavior (a SharedSecret edit
        breaks the template's OWN Client_Secret_Template_Guid link, if it had one - directly editing
        the value is a deliberate divergence from whatever Shared Secret Template it came from).
        Does NOT touch the template's own Template_Guid - that's its identity, not a lineage
        reference, unlike a live Client's Template_Guid (which Set-NPSClientAttribute does reset).
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('IPAddress','SharedSecret','Enabled','RequireSignature')][string]$Attribute,
        [Parameter(Mandatory)]$Value,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name
    $templates = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service_Templates.Children.RADIUS_Clients_Templates.Children
    $node = if ($templates) { $templates.$tag } else { $null }
    if (-not $node) { throw "No RADIUS Client Template named '$Name' found." }

    $propMap = @{
        IPAddress        = @{ Xml = 'IP_Address';           Type = 'string'  }
        SharedSecret      = @{ Xml = 'Shared_Secret';         Type = 'string'  }
        Enabled           = @{ Xml = 'Radius_Client_Enabled'; Type = 'boolean' }
        RequireSignature  = @{ Xml = 'Require_Signature';     Type = 'boolean' }
    }
    $prop = $propMap[$Attribute]
    $currentValue = $node.Properties.($prop.Xml).'#text'
    $currentValueEscaped = ConvertTo-NPSXmlText ([string]$currentValue)
    $newValueText = if ($prop.Type -eq 'boolean') { if ([bool]$Value) { '1' } else { '0' } } else { ConvertTo-NPSXmlText ([string]$Value) }

    $oldFragment = "<$($prop.Xml) $($script:XmlDtNs) dt:dt=`"$($prop.Type)`">$currentValueEscaped</$($prop.Xml)>"
    $newFragment = "<$($prop.Xml) $($script:XmlDtNs) dt:dt=`"$($prop.Type)`">$newValueText</$($prop.Xml)>"

    $currentSecretTemplateGuid = $node.Properties.Client_Secret_Template_Guid.'#text'
    $willDecouple = ($Attribute -eq 'SharedSecret') -and ($oldFragment -ne $newFragment) -and
        ($currentSecretTemplateGuid -and $currentSecretTemplateGuid -ne $script:ZeroGuid)

    if ($oldFragment -eq $newFragment) {
        return [pscustomobject]@{ Changed = $false; TemplateName = $Name; Attribute = $Attribute; Decoupled = $false }
    }

    $tagPattern = "(<$([regex]::Escape($tag))\b[^>]*>.*?</$([regex]::Escape($tag))>)"
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
        param($m)
        $updated = $m.Value.Replace($oldFragment, $newFragment)
        if ($willDecouple) {
            $updated = $updated.Replace(
                "<Client_Secret_Template_Guid $($script:XmlDtNs) dt:dt=`"string`">$currentSecretTemplateGuid</Client_Secret_Template_Guid>",
                "<Client_Secret_Template_Guid $($script:XmlDtNs) dt:dt=`"string`">$($script:ZeroGuid)</Client_Secret_Template_Guid>")
        }
        return $updated
    }
    $rawContent = [regex]::Replace($config.RawContent, $tagPattern, $evaluator, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if ($WhatIf) {
        return [pscustomobject]@{ Changed = $true; TemplateName = $Name; Attribute = $Attribute; Decoupled = [bool]$willDecouple; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ Changed = $true; TemplateName = $Name; Attribute = $Attribute; Decoupled = [bool]$willDecouple; BackupPath = $backupPath }
}

# ---------------------------------------------------------------------------
function Add-NPSClientFromTemplate {
    <#
    .SYNOPSIS
        Provisions a new live RADIUS Client from an existing RADIUS Client Template - the
        "assignment" workflow: copies the template's SharedSecret/Enabled/RequireSignature and its
        Client_Secret_Template_Guid link (preserving the Shared-Secret-Template chain, if any) onto
        the new client, and sets the new client's own Template_Guid to the Client Template's
        TemplateGuid (marking "created from this template", mirroring what NPS's own console does
        when you create a client from a template - confirmed live pattern already established for
        the one-level Client<->Shared-Secret-Template case, extended here for the Client Template
        level per the SAME schema shape).

    .PARAMETER IPAddress
        Optional override - if omitted, uses the template's own IP address. Almost always wanted, in
        practice, since a template's whole point is one canonical config reused for MULTIPLE distinct
        clients with (usually) different IPs.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ClientTemplateName,
        [Parameter(Mandatory)][string]$NewClientName,
        [string]$IPAddress,
        [string]$TemplatesPath = "C:\Windows\System32\ias\iastemplates.xml",
        [switch]$WhatIf
    )

    $template = Get-NPSClientTemplates -Path $TemplatesPath | Where-Object { $_.Name -eq $ClientTemplateName } | Select-Object -First 1
    if (-not $template) { throw "No RADIUS Client Template named '$ClientTemplateName' found." }

    $effectiveIP = if ($IPAddress) { $IPAddress } else { $template.IPAddress }

    $addParams = @{
        Path                      = $Path
        Name                      = $NewClientName
        IPAddress                 = $effectiveIP
        SharedSecret              = $template.SharedSecret
        Enabled                   = $template.Enabled
        RequireSignature          = $template.RequireSignature
        TemplateGuid              = $template.TemplateGuid
        ClientSecretTemplateGuid  = $template.ClientSecretTemplateGuid
        WhatIf                    = $WhatIf
    }
    return Add-NPSClient @addParams
}

# ---------------------------------------------------------------------------
function Remove-NPSClient {
    <#
    .SYNOPSIS
        Deletes a RADIUS client (by display name) entirely.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name
    $clients = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.Protocols.Children.Microsoft_Radius_Protocol.Children.Clients.Children
    $node = if ($clients) { $clients.$tag } else { $null }
    if (-not $node) { throw "No RADIUS client named '$Name' found." }

    $rawContent = Remove-NPSFragmentFromRawText -RawContent $config.RawContent -TagName $tag

    if ($WhatIf) {
        return [pscustomobject]@{ DeletedClient = $Name; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ DeletedClient = $Name; BackupPath = $backupPath }
}

# ---------------------------------------------------------------------------
function Set-NPSClientAttribute {
    <#
    .SYNOPSIS
        Updates ONE attribute on an existing RADIUS client (IPAddress, SharedSecret, Enabled, or
        RequireSignature) without touching anything else about it.

    .DESCRIPTION
        Like Set-NPSPolicyEnabled, this compares old vs. new fragment text and reports Changed=false
        as a no-op if the value is already what was asked for. Old-value fragments are built from the
        PARSED (decoded) XML text, then re-escaped the same way New-NPSClientXmlFragment escapes on
        write (ConvertTo-NPSXmlText) - required for any value containing &/</>, not just plain ASCII
        (a real captured secret had one; caught live, see Set-NPSSharedSecretTemplateValue's notes).

        SharedSecret edits also BREAK the client's link to any template (Client_Secret_Template_Guid
        AND Template_Guid both reset to the zero-GUID, if either was set) - directly editing a
        client's own secret is a deliberate divergence from whatever template it came from, so the
        data shouldn't keep claiming a link that's no longer accurate (this was the "stale GUID"
        pattern flagged since Get-NPSClients was first built; per the maintainer, changing JUST the client
        should now actively clear the link rather than silently go stale). If you want the change to
        stay template-driven and cascade to every client that shares it, use
        Set-NPSSharedSecretTemplateValue instead - that intentionally KEEPS links intact.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('IPAddress','SharedSecret','Enabled','RequireSignature')][string]$Attribute,
        [Parameter(Mandatory)]$Value,
        [switch]$WhatIf
    )

    $zeroGuid = '{00000000-0000-0000-0000-000000000000}'

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $Name
    $clients = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.Protocols.Children.Microsoft_Radius_Protocol.Children.Clients.Children
    $node = if ($clients) { $clients.$tag } else { $null }
    if (-not $node) { throw "No RADIUS client named '$Name' found." }

    $propMap = @{
        IPAddress        = @{ Xml = 'IP_Address';           Type = 'string'  }
        SharedSecret      = @{ Xml = 'Shared_Secret';         Type = 'string'  }
        Enabled           = @{ Xml = 'Radius_Client_Enabled'; Type = 'boolean' }
        RequireSignature  = @{ Xml = 'Require_Signature';     Type = 'boolean' }
    }
    $prop = $propMap[$Attribute]
    $currentValue = $node.Properties.($prop.Xml).'#text'

    # MUST re-encode $currentValue the same way the raw file actually stores it before using it to
    # build a search fragment - $node.Properties.X.'#text' comes back XML-DECODED (e.g. "&amp;" -> "&")
    # from the parsed [xml], but $config.RawContent still has it encoded. A shared secret containing
    # &, <, or > (very plausible - a real captured secret had one) would otherwise silently never
    # match, so .Replace() finds nothing, the file is "written" unchanged, and this still reports
    # Changed=true. Booleans are always '0'/'1' so escaping is a harmless no-op for them; same fix as
    # Set-NPSSharedSecretTemplateValue.
    $currentValueEscaped = ConvertTo-NPSXmlText ([string]$currentValue)

    $newValueText = if ($prop.Type -eq 'boolean') { if ([bool]$Value) { '1' } else { '0' } } else { ConvertTo-NPSXmlText ([string]$Value) }

    $oldFragment = "<$($prop.Xml) $($script:XmlDtNs) dt:dt=`"$($prop.Type)`">$currentValueEscaped</$($prop.Xml)>"
    $newFragment = "<$($prop.Xml) $($script:XmlDtNs) dt:dt=`"$($prop.Type)`">$newValueText</$($prop.Xml)>"

    # Decoupling only applies to a SharedSecret edit that's actually changing the value - IPAddress/
    # Enabled/RequireSignature edits never touch the template link, and a no-op SharedSecret "change"
    # (setting it to what it already is) shouldn't silently unlink an otherwise-untouched client.
    $currentSecretTemplateGuid = $node.Properties.Client_Secret_Template_Guid.'#text'
    $currentClientTemplateGuid = $node.Properties.Template_Guid.'#text'
    $willDecouple = ($Attribute -eq 'SharedSecret') -and ($oldFragment -ne $newFragment) -and (
        ($currentSecretTemplateGuid -and $currentSecretTemplateGuid -ne $zeroGuid) -or
        ($currentClientTemplateGuid -and $currentClientTemplateGuid -ne $zeroGuid)
    )

    if ($oldFragment -eq $newFragment) {
        return [pscustomobject]@{ Changed = $false; ClientName = $Name; Attribute = $Attribute; Decoupled = $false }
    }

    $tagPattern = "(<$([regex]::Escape($tag))\b[^>]*>.*?</$([regex]::Escape($tag))>)"
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
        param($m)
        $updated = $m.Value.Replace($oldFragment, $newFragment)
        if ($willDecouple) {
            if ($currentSecretTemplateGuid -and $currentSecretTemplateGuid -ne $zeroGuid) {
                $updated = $updated.Replace(
                    "<Client_Secret_Template_Guid $($script:XmlDtNs) dt:dt=`"string`">$currentSecretTemplateGuid</Client_Secret_Template_Guid>",
                    "<Client_Secret_Template_Guid $($script:XmlDtNs) dt:dt=`"string`">$zeroGuid</Client_Secret_Template_Guid>")
            }
            if ($currentClientTemplateGuid -and $currentClientTemplateGuid -ne $zeroGuid) {
                $updated = $updated.Replace(
                    "<Template_Guid $($script:XmlDtNs) dt:dt=`"string`">$currentClientTemplateGuid</Template_Guid>",
                    "<Template_Guid $($script:XmlDtNs) dt:dt=`"string`">$zeroGuid</Template_Guid>")
            }
        }
        return $updated
    }
    $rawContent = [regex]::Replace($config.RawContent, $tagPattern, $evaluator, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if ($WhatIf) {
        return [pscustomobject]@{ Changed = $true; ClientName = $Name; Attribute = $Attribute; Decoupled = $willDecouple; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ Changed = $true; ClientName = $Name; Attribute = $Attribute; Decoupled = $willDecouple; BackupPath = $backupPath }
}

# ---------------------------------------------------------------------------
function Set-NPSPolicyEnabled {
    <#
    .SYNOPSIS
        Enables or disables one policy (Policy_Enabled 1/0) by display name, within -PolicyType's own
        container, without touching anything else about it - the "deactivate rule" operation.
        Reversible by calling again with the opposite value - nothing about the policy's conditions,
        VSAs, or sequence changes.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PolicyName,
        [Parameter(Mandatory)][bool]$Enabled,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $PolicyName
    $containerTag = Get-NPSPolicyContainerTag -PolicyType $PolicyType
    $np = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.$containerTag.Children
    $node = $np.$tag
    if (-not $node) { throw "No policy named '$PolicyName' found." }

    $currentValue = $node.Properties.Policy_Enabled.'#text'
    $newValue = if ($Enabled) { '1' } else { '0' }
    if ($currentValue -eq $newValue) {
        return [pscustomobject]@{ Changed = $false; PolicyName = $PolicyName; Enabled = $Enabled }
    }

    $oldFragment = "<Policy_Enabled $($script:XmlDtNs) dt:dt=`"boolean`">$currentValue</Policy_Enabled>"
    $newFragment = "<Policy_Enabled $($script:XmlDtNs) dt:dt=`"boolean`">$newValue</Policy_Enabled>"
    $tagPattern = "(<$([regex]::Escape($tag))\b[^>]*>.*?</$([regex]::Escape($tag))>)"
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
        param($m)
        $m.Value.Replace($oldFragment, $newFragment)
    }
    $rawContent = Set-NPSContainerRawText -RawContent $config.RawContent -ContainerTag $containerTag -Transform {
        param($spanText)
        [regex]::Replace($spanText, $tagPattern, $evaluator, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    }

    if ($WhatIf) {
        return [pscustomobject]@{ Changed = $true; PolicyName = $PolicyName; Enabled = $Enabled; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ Changed = $true; PolicyName = $PolicyName; Enabled = $Enabled; BackupPath = $backupPath }
}

# ---------------------------------------------------------------------------
function Remove-NPSPolicy {
    <#
    .SYNOPSIS
        Deletes a policy (by display name) from -PolicyType's own container, along with its matching
        paired profile entry (RadiusProfiles for a Network Policy, Proxy_Profiles for a Connection
        Request Policy - same tag either way, since a profile in this module is always created under
        the same display name as its policy - see Add-NPSConnectionRequestRule's own corrected notes,
        2026-08-18, on why CRPs get one too now). A CRP created before that fix has no paired profile
        to remove - the removal call is a harmless no-op in that case (see
        Remove-NPSFragmentFromRawText's own notes) - then closes the sequence gap left behind so
        remaining real policies in that SAME container stay contiguous, matching what the native NPS
        GUI does on delete.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PolicyName,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $tag = ConvertTo-NPSXmlTagName -DisplayName $PolicyName
    $containerTag = Get-NPSPolicyContainerTag -PolicyType $PolicyType
    $np = $config.ConfigXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.$containerTag.Children
    $node = $np.$tag
    if (-not $node) { throw "No policy named '$PolicyName' found." }
    $deletedSeq = [int]$node.Properties.msNPSequence.'#text'

    $rawContent = Remove-NPSFragmentFromRawText -RawContent $config.RawContent -ContainerTag $containerTag -TagName $tag
    $profileContainerTag = if ($PolicyType -eq 'NetworkPolicy') { 'RadiusProfiles' } else { 'Proxy_Profiles' }
    $rawContent = Remove-NPSFragmentFromRawText -RawContent $rawContent -ContainerTag $profileContainerTag -TagName $tag   # matching profile entry, same tag

    # Close the gap - every real policy after the deleted one, in this SAME container, shifts down by
    # 1, lowest-first (the opposite direction from Add-NPSPolicySet's insert-shift, and for the
    # mirror-image reason: each step's target value was already vacated by the PREVIOUS step when
    # moving downward).
    $existingSequences = Get-NPSExistingSequences -ConfigXml $config.ConfigXml -PolicyType $PolicyType
    $toShift = @($existingSequences | Where-Object { $_ -gt $deletedSeq } | Sort-Object)
    foreach ($oldSeq in $toShift) {
        $shiftNode = $np.ChildNodes | Where-Object { [int]$_.Properties.msNPSequence.'#text' -eq $oldSeq } | Select-Object -First 1
        if (-not $shiftNode) { continue }
        $rawContent = Set-NPSPolicySequenceInRawText -RawContent $rawContent -ContainerTag $containerTag -TagName $shiftNode.LocalName -OldSequence $oldSeq -NewSequence ($oldSeq - 1)
    }

    if ($WhatIf) {
        return [pscustomobject]@{ DeletedPolicy = $PolicyName; DeletedSequence = $deletedSeq; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ DeletedPolicy = $PolicyName; DeletedSequence = $deletedSeq; BackupPath = $backupPath }
}

# ---------------------------------------------------------------------------
function Move-NPSPolicy {
    <#
    .SYNOPSIS
        Moves one policy up or down within -PolicyType's own container by swapping msNPSequence
        values with its immediate neighbor, repeated -Steps times - the same "Move Up"/"Move Down"
        semantics the native NPS GUI uses. To move several selected policies, call this once per
        policy (in whatever order preserves their relative order, e.g. top-to-bottom for
        -Direction Up) - see NPSInteractive.ps1's reorder wizard for how the dashboard drives
        multi-select this way.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PolicyName,
        [Parameter(Mandatory)][ValidateSet('Up','Down')][string]$Direction,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType,
        [int]$Steps = 1,
        [switch]$WhatIf
    )

    $config = Read-NPSConfig -Path $Path
    $rawContent = $config.RawContent
    $tag = ConvertTo-NPSXmlTagName -DisplayName $PolicyName
    $containerTag = Get-NPSPolicyContainerTag -PolicyType $PolicyType
    $stepsTaken = 0

    for ($i = 0; $i -lt $Steps; $i++) {
        # Re-parse fresh each step from the ACCUMULATING rawContent - can't rely on the original
        # $config.ConfigXml snapshot past the first step, since prior swaps in this loop have already
        # changed what's actually at each sequence number.
        [xml]$currentXml = $rawContent
        $np = $currentXml.Root.Children.Microsoft_Internet_Authentication_Service.Children.$containerTag.Children
        $node = $np.$tag
        if (-not $node) { throw "No policy named '$PolicyName' found." }
        $mySeq = [int]$node.Properties.msNPSequence.'#text'

        $neighborSeq = if ($Direction -eq 'Up') { $mySeq - 1 } else { $mySeq + 1 }
        $neighborNode = $np.ChildNodes | Where-Object { [int]$_.Properties.msNPSequence.'#text' -eq $neighborSeq } | Select-Object -First 1
        if (-not $neighborNode -or $neighborSeq -ge 900000) {
            Write-Warning "'$PolicyName' is already at the $(if ($Direction -eq 'Up') { 'top' } else { 'bottom' }) - stopping after $i of $Steps step(s)."
            break
        }

        # Each Set-NPSPolicySequenceInRawText call is scoped by TAG NAME within -ContainerTag's own
        # span, not "whichever node currently holds value X" - so these two swaps can run directly, no
        # intermediate placeholder value needed to dodge a transient collision (there isn't one to
        # dodge).
        $rawContent = Set-NPSPolicySequenceInRawText -RawContent $rawContent -ContainerTag $containerTag -TagName $node.LocalName -OldSequence $mySeq -NewSequence $neighborSeq
        $rawContent = Set-NPSPolicySequenceInRawText -RawContent $rawContent -ContainerTag $containerTag -TagName $neighborNode.LocalName -OldSequence $neighborSeq -NewSequence $mySeq
        $stepsTaken++
    }

    if ($WhatIf) {
        return [pscustomobject]@{ PolicyName = $PolicyName; StepsTaken = $stepsTaken; ResultingXml = $rawContent }
    }

    $backupPath = Save-NPSConfig -Path $Path -RawContent $rawContent -Encoding $config.Encoding
    return [pscustomobject]@{ PolicyName = $PolicyName; StepsTaken = $stepsTaken; BackupPath = $backupPath }
}

# ---------------------------------------------------------------------------
function Install-NPSRole {
    <#
    .SYNOPSIS
        Installs the Network Policy and Access Services (NPAS) Windows feature - the modern feature
        name for Server 2016+. Verified via search: the older "NPAS-Policy-Server" sub-feature name
        that some older guides use now errors out on current Windows Server versions - "NPAS" is the
        correct name going forward, not a shortcut/alias for it.
    #>
    param([switch]$WhatIf)

    if (-not (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
        throw "Install-WindowsFeature is not available - this must be run on Windows Server (with the ServerManager module), not a client OS."
    }

    $existing = Get-WindowsFeature -Name NPAS -ErrorAction SilentlyContinue
    if ($existing -and $existing.InstallState -eq 'Installed') {
        return [pscustomobject]@{ AlreadyInstalled = $true; Success = $true; RestartNeeded = $false }
    }

    if ($WhatIf) {
        return [pscustomobject]@{ AlreadyInstalled = $false; WouldInstall = $true }
    }

    $result = Install-WindowsFeature -Name NPAS -IncludeManagementTools
    return [pscustomobject]@{
        AlreadyInstalled = $false
        Success          = $result.Success
        RestartNeeded    = ($result.RestartNeeded -eq 'Yes')
    }
}

# ---------------------------------------------------------------------------
# Session-lifetime cache, same pattern/reasoning as Get-NPSExtensionUninstallInfo's
# (Modules\NPSExtension.ps1) - confirmed live (the maintainer) that flaky AD Web Services at one client made
# this call itself slow, and Get-NPSStatus calls it on EVERY status computation (every dashboard menu
# redraw). Unlike the uninstall-info case, there's no faster underlying query to substitute here -
# Get-ADComputer/Get-ADPrincipalGroupMembership are already the correct, standard cmdlets; the latency
# is inherent to that client's ADWS, not an inefficient query. Caching still fixes the real-world
# problem: a slow/flaky AD round-trip becomes a ONE-TIME cost per session instead of repeating on
# every single redraw. Failures are cached too (not just successes) - a flaky/unreachable ADWS
# throwing a timeout is exactly the case that must NOT keep re-attempting on every redraw, or the
# dashboard stays just as hung as before. -Force / Clear-NPSServerRegisteredCache exist for after
# Register-NPSServerInAD actually changes the answer.
$script:NPSServerRegisteredCache = $null
$script:NPSServerRegisteredCached = $false
$script:NPSServerRegisteredCacheError = $null
# Which -Server value the cached result/error actually came from - a cached FAILURE from unqualified
# auto-discovery must NOT shadow a later retry against an explicit DC (the whole point of the Option 1
# fallback below), so the cache is only trusted when the requested -Server matches what produced it.
$script:NPSServerRegisteredCacheServer = $null

function Test-NPSServerRegistered {
    <#
    .SYNOPSIS
        Checks whether this server is registered in AD - i.e. a member of the "RAS and IAS Servers"
        domain security group, required for NPS to read users' dial-in properties during
        authorization. Verified against Microsoft's own docs (nps-manage-register): registration IS
        exactly this group membership, nothing more/hidden elsewhere.

        Cached for the session by default (success OR failure - see module-scoped cache notes above).
        Pass -Force to bypass the cache and re-check.

    .PARAMETER TimeoutSeconds
        Bounds the AD round-trip itself, not just repeats of it - confirmed live (the maintainer) that a
        flaky ADWS at one client can hang this call badly enough to freeze the WHOLE dashboard on
        its very first draw, before the session cache above has anything to serve yet (caching only
        helps every redraw AFTER the first). Runs the actual Get-ADComputer /
        Get-ADPrincipalGroupMembership pair in a background job specifically so a genuinely hung
        network call can be abandoned (Stop-Job/Remove-Job -Force) without leaving the dashboard
        itself blocked waiting on it - a plain foreground call has no way to be un-stuck once a
        Win32/RPC layer underneath it is the thing not responding.

        ONLY applies when -Credential is NOT given (the passive/automatic auto-discovery path used by
        Get-NPSStatus on every redraw - never carries a credential, exactly where hang protection
        actually matters). When -Credential IS given (the interactive Option 1 / Troubleshooting
        fallback path, see Invoke-NPSADFallbackPrompt), this runs INLINE instead - confirmed live
        (the maintainer) that Get-ADGroup with an explicit -Credential works fine run directly, but the
        SAME credential passed into a Start-Job here produced a mangled, cmdlet-less
        "not authenticated" RuntimeException that Get-ADComputer/-ADPrincipalGroupMembership never
        produce on their own - something about marshaling a real interactively-entered PSCredential
        across this specific job boundary breaks it (a synthetic ConvertTo-SecureString-built
        credential DID survive an isolated Start-Job test earlier this session, so it's specific to
        this real-world case, not a blanket "PSCredential can't cross a job boundary" rule). The
        interactive fallback path is already attended (a tech is watching it, unlike the passive
        status-screen path), so losing timeout protection there is an acceptable trade for it
        actually working.
    #>
    param(
        [string]$Server,
        [string]$ComputerName = $env:COMPUTERNAME,
        [switch]$Force,
        [int]$TimeoutSeconds = 10,
        # Confirmed live (the maintainer) that a direct-DC attempt can fail on credentials alone ("The server
        # has rejected the client credentials") - session-only, never persisted anywhere (unlike the
        # DC hostname itself, which Set-NPSShimADServer does save into the shim).
        [System.Management.Automation.PSCredential]$Credential
    )

    if ($script:NPSServerRegisteredCached -and -not $Force -and $script:NPSServerRegisteredCacheServer -eq $Server) {
        if ($script:NPSServerRegisteredCacheError) { throw $script:NPSServerRegisteredCacheError }
        return $script:NPSServerRegisteredCache
    }

    if (-not (Test-RSATAvailable)) {
        # Not cached - a static capability check (is RSAT installed), cheap to re-check every time
        # and not the kind of thing that's ever mid-session flaky the way an AD round-trip can be.
        throw "The ActiveDirectory module (RSAT) is not available - can't check AD group membership without it (or use Install-RSATActiveDirectoryModule)."
    }

    if ($Credential) {
        # Inline path - see .PARAMETER TimeoutSeconds above for why. Mirrors the job's own logic
        # exactly, just without the process boundary that broke it for a real interactive credential.
        try {
            $Env:ADPS_LoadDefaultDrive = 0
            Import-Module ActiveDirectory -ErrorAction Stop
            $adParams = @{ ErrorAction = 'Stop'; Credential = $Credential }
            if ($Server) { $adParams['Server'] = $Server }
            $computer = Get-ADComputer -Identity $ComputerName @adParams
            $groups = Get-ADPrincipalGroupMembership -Identity $computer @adParams
            $boolResult = [bool]($groups | Where-Object { $_.Name -eq 'RAS and IAS Servers' })
        } catch {
            $script:NPSServerRegisteredCached = $true
            $script:NPSServerRegisteredCacheError = $_.Exception.Message
            $script:NPSServerRegisteredCacheServer = $Server
            throw
        }
        $script:NPSServerRegisteredCache = $boolResult
        $script:NPSServerRegisteredCached = $true
        $script:NPSServerRegisteredCacheServer = $Server
        $script:NPSServerRegisteredCacheError = $null
        return $boolResult
    }

    $job = Start-Job -ScriptBlock {
        param($ComputerName, $Server)
        $Env:ADPS_LoadDefaultDrive = 0
        Import-Module ActiveDirectory -ErrorAction Stop
        $adParams = @{ ErrorAction = 'Stop' }
        if ($Server) { $adParams['Server'] = $Server }
        $computer = Get-ADComputer -Identity $ComputerName @adParams
        $groups = Get-ADPrincipalGroupMembership -Identity $computer @adParams
        [bool]($groups | Where-Object { $_.Name -eq 'RAS and IAS Servers' })
    } -ArgumentList $ComputerName, $Server

    $completedInTime = Wait-Job -Job $job -Timeout $TimeoutSeconds
    if (-not $completedInTime) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        $timeoutMsg = "AD registration check timed out after $TimeoutSeconds seconds - AD/ADWS appears slow or unreachable at this site."
        $script:NPSServerRegisteredCached = $true
        $script:NPSServerRegisteredCacheError = $timeoutMsg
        $script:NPSServerRegisteredCacheServer = $Server
        throw $timeoutMsg
    }

    $jobErrors = $null
    $result = Receive-Job -Job $job -ErrorAction SilentlyContinue -ErrorVariable jobErrors
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

    if ($jobErrors) {
        # Cache the failure itself, not just successes - this is the case that most needs caching
        # (a slow/flaky ADWS timeout is exactly what shouldn't keep re-attempting on every redraw).
        $msg = $jobErrors[0].Exception.Message
        $script:NPSServerRegisteredCached = $true
        $script:NPSServerRegisteredCacheError = $msg
        $script:NPSServerRegisteredCacheServer = $Server
        throw $msg
    }

    $boolResult = [bool]$result
    $script:NPSServerRegisteredCache = $boolResult
    $script:NPSServerRegisteredCached = $true
    $script:NPSServerRegisteredCacheServer = $Server
    $script:NPSServerRegisteredCacheError = $null
    return $boolResult
}

# ---------------------------------------------------------------------------
function Clear-NPSServerRegisteredCache {
    <#
    .SYNOPSIS
        Invalidates Test-NPSServerRegistered's session cache - call after Register-NPSServerInAD
        actually runs, since that's the only action that could change the answer mid-session.
    #>
    $script:NPSServerRegisteredCached = $false
    $script:NPSServerRegisteredCache = $null
    $script:NPSServerRegisteredCacheServer = $null
}

# ---------------------------------------------------------------------------
function Register-NPSServerInAD {
    <#
    .SYNOPSIS
        Registers this server in Active Directory (adds it to the "RAS and IAS Servers" domain
        security group) via netsh - the same operation NPS's own MMC console "Register Server in
        Active Directory" action performs.

    .DESCRIPTION
        Command is "netsh ras add registeredserver", NOT "netsh nps add registeredserver" - the
        latter was this function's first version, sourced from Microsoft's own nps-manage-register
        docs page, which turned out to itself have the wrong netsh context (an older, apparently
        uncorrected doc bug that's been copied forward by several secondary sources). Re-verified
        against the actively-maintained netsh-ras reference page (updated Oct 2025), which
        explicitly lists `add registeredserver`, `show registeredserver`, and
        `delete registeredserver` all under the `ras` context, and never mentions an `nps` context
        at all. "nps" is not a real netsh top-level context. No PowerShell-native cmdlet for this is
        documented by Microsoft either; netsh is the supported path (do not substitute an unverified
        "Register-NpsServer" cmdlet name seen in some third-party summaries - not in any Microsoft
        reference actually checked).

    .PARAMETER Domain
        DNS domain name to register in. Defaults to this machine's own domain
        ($env:USERDNSDOMAIN) - the "register in its default domain" case (minimum permission: local
        Administrators, per Microsoft's docs). Pass a different domain for the "register in another
        domain" case (an NPS reading dial-in properties for accounts in a domain it isn't a member
        of) - that case needs rights in the TARGET domain, not just local admin on this server.
    #>
    param(
        [string]$Domain = $env:USERDNSDOMAIN,
        [string]$ServerName = $env:COMPUTERNAME,
        [switch]$WhatIf
    )

    if (-not $Domain) {
        throw "Could not determine a domain to register in (`$env:USERDNSDOMAIN was empty) - this machine may not be domain-joined, or pass -Domain explicitly."
    }

    $cmd = "netsh ras add registeredserver domain=`"$Domain`" server=`"$ServerName`""
    if ($WhatIf) {
        return [pscustomobject]@{ WouldRun = $cmd }
    }

    $output = cmd /c $cmd 2>&1
    return [pscustomobject]@{ Command = $cmd; Output = ($output -join "`n"); ExitCode = $LASTEXITCODE }
}

# ---------------------------------------------------------------------------
function Initialize-IASConfigFile {
    <#
    .SYNOPSIS
        Forces ias.xml into existence on a brand-new NPS install, without needing a GUI edit first.

    .DESCRIPTION
        Confirmed live, 2026-09-03 (the maintainer, from a second tech's real run-through): on a fresh install,
        starting the IAS service alone does NOT reliably create ias.xml - Windows applies its built-in
        default configuration (the standard "Connections to other access servers"/"Use Windows
        authentication for all users" policies, the Protocols/Vendors block, etc. - see this module's
        own Samples\ias.xml for what a populated one looks like) purely in memory, from a template, and
        only actually WRITES it to disk the first time a real config-changing operation happens - which
        up to now has meant opening the NPS MMC console and touching ANYTHING, even something trivial.
        "Completely synthesized until you add SOMETHING to the config via the GUI," per the maintainer.

        `netsh nps export` is the supported, official command for serializing IAS's CURRENT live config
        out to an XML file (this module's own header already reverse-engineers its schema from real
        "netsh nps export" output - see NPSCore.ps1's .SYNOPSIS). Pointing that export straight at the
        live config path itself has the same practical effect as the GUI edit the maintainer describes - it
        forces IAS to flush its current (still-default, still-empty-of-clients/policies) config to disk
        - without a tech ever having to open the MMC snap-in. Purely a "make the file exist" helper,
        never destructive to an ias.xml that's already there (the caller is expected to Test-Path
        first, same as every other ias.xml-touching call site in this module).

        NOT yet confirmed against a genuinely fresh NPS install in the field - built from the same
        already-verified "netsh nps export" command this module's own schema notes are built from, but
        this specific "export back onto the live path to force its first write" use of it is new and
        wants a live pass before being fully trusted.

    .PARAMETER IASConfigPath
        Where ias.xml should end up. Defaults to the real live NPS config path.

    .PARAMETER WhatIf
        Returns the command that would run instead of running it - matches Register-NPSServerInAD's
        own -WhatIf convention (same netsh-wrapper shape, right above this function).
    #>
    param(
        [string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml",
        [switch]$WhatIf
    )

    $cmd = "netsh nps export filename=`"$IASConfigPath`" exportPSK=YES"
    if ($WhatIf) {
        return [pscustomobject]@{ WouldRun = $cmd }
    }

    $iasDir = Split-Path -Path $IASConfigPath -Parent
    if ($iasDir -and -not (Test-Path $iasDir)) {
        New-Item -ItemType Directory -Path $iasDir -Force | Out-Null
    }

    $output = cmd /c $cmd 2>&1
    $succeeded = ($LASTEXITCODE -eq 0) -and (Test-Path $IASConfigPath)
    return [pscustomobject]@{ Command = $cmd; Output = ($output -join "`n"); ExitCode = $LASTEXITCODE; Succeeded = $succeeded }
}

# ---------------------------------------------------------------------------
function Test-ADConnectivityViaExplicitDC {
    <#
    .SYNOPSIS
        Fallback for sites where normal AD site/DC auto-discovery is broken but a DIRECT connection
        to a known-good DC works fine - confirms with a bare Get-ADGroup -Filter -Server before
        reporting success.

    .DESCRIPTION
        Three successive "improvements" attempted and ruled out here, each confirmed LIVE (the maintainer) to
        make no difference (or worse) to the actual failure - documented so the next person doesn't
        retry the same dead ends:
          1. Explicitly creating an "AD:" PSDrive before checking. Removed - not needed (nothing
             elsewhere in this module references "AD:\" paths) and not the cause.
          2. Get-ADDomain -> Get-ADGroup -Filter as the check itself, on the theory Get-ADDomain's
             domain-context resolution behaved differently under -Credential. Not the cause either -
             The maintainer's manual "$cred = Get-Credential; Get-ADDomain -Server ... -Credential $cred"
             worked fine, so the cmdlet choice was never it. (Kept Get-ADGroup anyway since it's the
             exact cmdlet his working manual test used.)
          3. Wrapping the call in Start-Job for process isolation, on the theory the AD module's
             cached ADWS/WCF connection state was getting poisoned by an in-process retry. DISPROVEN
             live - running each attempt in a genuinely fresh, separate process produced the EXACT
             SAME failure, unchanged. Removed.
          4. Removing $Env:ADPS_LoadDefaultDrive = 0 entirely (part of the "strip back to the maintainer's
             literal manual sequence" pass, since his commands never set it). WRONG MOVE - this
             brought back a real, DIFFERENT problem: an explicit Import-Module ActiveDirectory
             (unlike auto-loading, which is what his manual test relied on by never calling
             Import-Module at all) tries to auto-create the module's default "AD:" drive using the
             CURRENT identity - confirmed live via the resulting "WARNING: Error initializing default
             drive: 'The server has rejected the client credentials.'" appearing right before the
             real failure. That failed drive-creation attempt, using the WRONG identity, plausibly
             leaves the AD provider itself in a faulted state for the rest of the process - a
             different, uglier failure mode than a clean per-call auth error, and a good candidate
             for why the SECOND (credentialed) attempt was producing that mangled, cmdlet-less
             RuntimeException. $Env:ADPS_LoadDefaultDrive = 0 is restored below - it doesn't touch
             auth at all, only suppresses this unrelated auto-connect side effect, so keeping it
             doesn't reintroduce any divergence from the maintainer's actual auth flow.

    .PARAMETER Credential
        Optional - confirmed live (the maintainer) that a direct connection can fail purely on credentials
        ("The server has rejected the client credentials") even when the DC itself is reachable, e.g.
        the account this session is running as isn't valid/trusted against that specific DC. When
        given, passed straight through to Get-ADGroup - NEVER written to disk anywhere in this
        codebase (unlike the learned DC hostname, which Set-NPSShimADServer does persist -
        credentials are session-only, by design).
    #>
    param(
        [Parameter(Mandatory)][string]$DCServer,
        [System.Management.Automation.PSCredential]$Credential
    )

    # Suppresses the module's own default-"AD:"-drive auto-connect attempt (which uses the CURRENT
    # identity, not -Credential) - unrelated to auth itself, just stops an unrelated side effect from
    # firing and potentially leaving the AD provider in a bad state. See .DESCRIPTION history above.
    $Env:ADPS_LoadDefaultDrive = 0
    Import-Module ActiveDirectory -ErrorAction Stop

    # -Filter "Name -like '*'" + -ResultSetSize 1: cheapest possible real query that still exercises
    # the exact same bind/search path as the maintainer's confirmed-working manual test, without pulling back
    # this domain's whole group list just to prove connectivity.
    $groupParams = @{ Filter = "Name -like '*'"; Server = $DCServer; ResultSetSize = 1; ErrorAction = 'Stop' }
    if ($Credential) { $groupParams['Credential'] = $Credential }
    Get-ADGroup @groupParams | Out-Null
}

# ---------------------------------------------------------------------------
function Set-NPSShimADServer {
    <#
    .SYNOPSIS
        Rewrites a staged NPS-Manager_Shim.ps1 copy's own $NPSADServer anchor line in place, so a
        DC hostname that a tech had to discover by hand (see Test-ADConnectivityViaExplicitDC /
        Invoke-NPSADFallbackPrompt) is used automatically on every future launch instead of
        re-hitting the same broken auto-discovery and re-prompting every time.

    .DESCRIPTION
        The shim re-extracts NPSManager.zip with -Force and rewrites NPSAnswers.json from its OWN
        embedded data on EVERY run (see NPS-Manager_Shim.ps1) - so persisting a learned DC hostname
        anywhere except the shim file itself would just get silently clobbered the next time the tech
        runs it. Self-mutating the shim on disk is the only persistence layer that actually survives
        that.
    #>
    param(
        [Parameter(Mandatory)][string]$ShimPath,
        [Parameter(Mandatory)][string]$DCServer
    )

    # Basic hostname shape check - this value gets spliced back into a live .ps1 file as a literal
    # single-quoted string; refusing anything outside DNS-hostname characters rules out a stray quote
    # or backtick corrupting the shim, same defensive spirit as the JSON-anchor validation
    # Complete-ClientStaging already does at staging time (just for a different anchor).
    if ($DCServer -notmatch '^[A-Za-z0-9][A-Za-z0-9\-\.]*$') {
        throw "'$DCServer' doesn't look like a valid hostname - refusing to write it into the shim."
    }
    # NSP.NPS: -ShimPath is the work folder's Answers.json - save the field there instead.
    if ($ShimPath -like '*.json') { Set-NPSToolAnswerField -Path $ShimPath -Field 'NPSADServer' -Value $DCServer; return }
    if (-not (Test-Path $ShimPath)) {
        throw "Shim not found at $ShimPath."
    }

    $lines = Get-Content -Path $ShimPath
    $anchorIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\`$NPSADServer\s*=\s*'[^']*'\s*$") { $anchorIdx = $i; break }
    }
    if ($anchorIdx -lt 0) {
        throw "Could not find the `$NPSADServer anchor line in $ShimPath - this shim may be an older version that doesn't support saving it yet (re-download NPS-Manager_Shim.ps1's current version)."
    }

    # Direct array-element replacement, not a regex Replace() on the content string - avoids .NET
    # regex replacement-string $-substitution parsing entirely (the hostname itself can't contain a
    # literal $, but this sidesteps that whole class of bug for free rather than relying on it never
    # coming up).
    $lines[$anchorIdx] = "`$NPSADServer = '$DCServer'"
    Set-Content -Path $ShimPath -Value $lines -Encoding UTF8
}

# ---------------------------------------------------------------------------
function Set-NPSShimADUsername {
    <#
    .SYNOPSIS
        Rewrites a staged NPS-Manager_Shim.ps1 copy's own $NPSADUsername anchor line in place, so
        the LAST username that successfully authenticated an explicit AD credential at this site is
        pre-filled into future Get-Credential prompts instead of starting blank every launch.

    .DESCRIPTION
        Same self-mutation approach as Set-NPSShimADServer, for the same reason (the shim re-extracts
        NPSManager.zip and rewrites NPSAnswers.json from its own embedded data on every run, so this
        is the only persistence layer that survives that). This NEVER writes a password - only the
        username, which is not a secret. The password is still asked for fresh on every single launch.

        Per the "anchor age matters" note in NPS-Manager_Shim.ps1's Merge-NPSShimTemplate docstring,
        $NPSADUsername was added in shim v2 - a v1 shim on disk won't have this anchor line yet and
        this function throws in that case (same as Set-NPSShimADServer would for a missing anchor).
        That's fine here: the shim self-updates to the current template (which DOES have the anchor)
        before the dashboard - and therefore this function - ever runs against it.
    #>
    param(
        [Parameter(Mandatory)][string]$ShimPath,
        [Parameter(Mandatory)][string]$Username
    )

    # Same defensive spirit as Set-NPSShimADServer's hostname check - this gets spliced back into a
    # live .ps1 file as a literal single-quoted string. Allow-list covers every shape an AD username
    # legitimately takes (DOMAIN\user, user@domain.com, plain sAMAccountName) while ruling out a stray
    # quote/backtick corrupting the shim.
    if ($Username -notmatch '^[A-Za-z0-9][A-Za-z0-9\-\.\\@_]*$') {
        throw "'$Username' doesn't look like a valid username - refusing to write it into the shim."
    }
    # NSP.NPS: -ShimPath is the work folder's Answers.json - save the field there instead.
    if ($ShimPath -like '*.json') { Set-NPSToolAnswerField -Path $ShimPath -Field 'NPSADUsername' -Value $Username; return }
    if (-not (Test-Path $ShimPath)) {
        throw "Shim not found at $ShimPath."
    }

    $lines = Get-Content -Path $ShimPath
    $anchorIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\`$NPSADUsername\s*=\s*'[^']*'\s*$") { $anchorIdx = $i; break }
    }
    if ($anchorIdx -lt 0) {
        throw "Could not find the `$NPSADUsername anchor line in $ShimPath - this shim may be an older version that doesn't support saving it yet (re-download NPS-Manager_Shim.ps1's current version)."
    }

    # Direct array-element replacement, not a regex Replace() on the content string - same reasoning
    # as Set-NPSShimADServer (sidesteps .NET regex replacement-string $-substitution entirely).
    $lines[$anchorIdx] = "`$NPSADUsername = '$Username'"
    Set-Content -Path $ShimPath -Value $lines -Encoding UTF8
}

# ---------------------------------------------------------------------------
function Set-NPSShimRequiresExplicitADCredentials {
    <#
    .SYNOPSIS
        Rewrites a staged NPS-Manager_Shim.ps1 copy's own $NPSRequiresExplicitADCredentials anchor
        line in place - same self-mutation approach as Set-NPSShimADServer, for the exact same reason
        (the shim re-extracts NPSManager.zip and rewrites NPSAnswers.json from its OWN embedded data
        on EVERY run, so this flag has to live in the shim file itself to survive that). Exposed via
        the dashboard's Troubleshooting menu (see NPSTroubleshooting.ps1).

    .DESCRIPTION
        This is a yes/no flag only - NEVER a credential. Setting it $true just makes future launches
        of this shim proactively prompt for AD credentials at startup instead of waiting for normal
        auto-discovery to fail first (see NPS-Manager.ps1's -RequiresExplicitADCredentials param and
        Invoke-NPSRequiredCredentialsPrompt) - the credentials themselves are still asked for fresh
        every single launch, never written to disk anywhere in this codebase.
    #>
    param(
        [Parameter(Mandatory)][string]$ShimPath,
        [Parameter(Mandatory)][bool]$RequiresExplicitCredentials
    )

    # NSP.NPS: -ShimPath is the work folder's Answers.json - save the field there instead.
    if ($ShimPath -like '*.json') { Set-NPSToolAnswerField -Path $ShimPath -Field 'NPSRequiresExplicitADCredentials' -Value $RequiresExplicitCredentials; return }
    if (-not (Test-Path $ShimPath)) {
        throw "Shim not found at $ShimPath."
    }

    $lines = Get-Content -Path $ShimPath
    $anchorIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\$NPSRequiresExplicitADCredentials\s*=\s*\$(true|false)\s*$') { $anchorIdx = $i; break }
    }
    if ($anchorIdx -lt 0) {
        throw "Could not find the `$NPSRequiresExplicitADCredentials anchor line in $ShimPath - this shim may be an older version that doesn't support this flag yet (re-stage from Master Orchestrator to pick up the current shim template)."
    }

    $lines[$anchorIdx] = "`$NPSRequiresExplicitADCredentials = `$$($RequiresExplicitCredentials.ToString().ToLower())"
    Set-Content -Path $ShimPath -Value $lines -Encoding UTF8
}

# ---------------------------------------------------------------------------
function Get-NPSStatus {
    <#
    .SYNOPSIS
        One-shot snapshot of this machine's NPS setup for the dashboard's status view: role
        installed?, registered in AD?, ias.xml policy/client counts, extension installed?, extension
        cert + expiry, current OVERRIDE_NUMBER_MATCHING_WITH_OTP value.

    .DESCRIPTION
        Registry paths and cert-location logic verified against Microsoft's own NPS extension docs
        (howto-mfa-nps-extension.md), not guessed:
          - HKLM:\SOFTWARE\Microsoft\AzureMfa - OVERRIDE_NUMBER_MATCHING_WITH_OTP,
            CLIENT_CERT_IDENTIFIER (cert thumbprint, extension 1.2.2893.1+ only).
          - Cert lives in Cert:\LocalMachine\My. Pre-1.2.2893.1 extension versions don't write
            CLIENT_CERT_IDENTIFIER, so falls back to subject pattern "OU=Microsoft NPS Extension"
            (documented subject format: CN=<TenantID>,OU=Microsoft NPS Extension) - picks the
            latest-expiring match if more than one is found (e.g. an overlapping renewal).
          - Cert is valid 2 years per Microsoft's docs - included here so DaysLeft is meaningful at a
            glance without the reader needing to know that separately.
    #>
    param(
        [string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml",
        # Passed straight through to Test-NPSServerRegistered - once a working DC is known (CLI
        # override, or learned via the Option 1 fallback and saved into the shim - see
        # Set-NPSShimADServer), the status screen should use it too instead of hitting the same
        # broken auto-discovery on every single redraw.
        [string]$ADServer,
        # Same reasoning as $ADServer above, for the credential learned alongside it (see
        # NPS-Manager.ps1's $script:ADCredential) - never persisted, session-only.
        [System.Management.Automation.PSCredential]$ADCredential
    )

    $status = [pscustomobject]@{
        NPSRoleInstalled        = $false
        ADRegistered            = $null   # $null = couldn't check (no RSAT, or an AD error) - NOT the same as $false (checked, confirmed not registered)
        IASConfigExists         = $false
        IASConfigPath           = $IASConfigPath
        PolicyCount             = $null   # Network Policies only - see ConnectionRequestPolicyCount for the other, separate universe
        ConnectionRequestPolicyCount = $null
        ClientCount             = $null
        ExtensionInstalled      = $false
        # $true when HKLM:\SOFTWARE\Microsoft\AzureMfa exists but Programs-and-Features does NOT
        # show the extension installed - confirmed live (the maintainer) that the extension's uninstaller
        # can leave this registry key (or values under it) behind without removing it, which
        # previously made ExtensionInstalled silently WRONG (reported "Installed" for a machine that
        # had genuinely been uninstalled). See the ExtensionInstalled determination below.
        ExtensionOrphanedConfig = $false
        ExtensionCertThumbprint = $null
        ExtensionCertExpires    = $null
        ExtensionCertDaysLeft   = $null
        OverrideNumberMatching  = $null
    }

    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $feature = Get-WindowsFeature -Name NPAS -ErrorAction SilentlyContinue
            $status.NPSRoleInstalled = [bool]($feature -and $feature.InstallState -eq 'Installed')
        }
    } catch {}

    if ($status.NPSRoleInstalled -and (Test-RSATAvailable)) {
        try { $status.ADRegistered = Test-NPSServerRegistered -Server $ADServer -Credential $ADCredential } catch {}
    }

    if (Test-Path $IASConfigPath) {
        $status.IASConfigExists = $true
        try { $status.PolicyCount = @(Get-NPSPolicySummary -Path $IASConfigPath -PolicyType NetworkPolicy).Count } catch {}
        try { $status.ConnectionRequestPolicyCount = @(Get-NPSPolicySummary -Path $IASConfigPath -PolicyType ConnectionRequest).Count } catch {}
        try { $status.ClientCount = @(Get-NPSClients -Path $IASConfigPath).Count } catch {}
    }

    $azureMfaRegPath = 'HKLM:\SOFTWARE\Microsoft\AzureMfa'
    $azureMfaRegExists = Test-Path $azureMfaRegPath
    if ($azureMfaRegExists) {
        # The registry key alone is NOT authoritative for "is the extension actually installed" -
        # confirmed live that the uninstaller can leave it (or values under it) behind. Programs-
        # and-Features (Get-NPSExtensionUninstallInfo, Modules\NPSExtension.ps1) is the real signal
        # when it's available; only fall back to registry-key-only if that function isn't loaded in
        # this session (e.g. a caller that dot-sources NPSCore.ps1 without NPSExtension.ps1) - a
        # guarded Get-Command check rather than a hard dependency, since NPSCore.ps1 is meant to
        # stay the lower-level foundational module.
        if (Get-Command Get-NPSExtensionUninstallInfo -ErrorAction SilentlyContinue) {
            $realUninstallEntry = Get-NPSExtensionUninstallInfo
            if ($realUninstallEntry) {
                $status.ExtensionInstalled = $true
            } else {
                $status.ExtensionInstalled = $false
                $status.ExtensionOrphanedConfig = $true
            }
        } else {
            $status.ExtensionInstalled = $true
        }
    }

    if ($status.ExtensionInstalled -or $status.ExtensionOrphanedConfig) {
        $overrideVal = (Get-ItemProperty -Path $azureMfaRegPath -Name 'OVERRIDE_NUMBER_MATCHING_WITH_OTP' -ErrorAction SilentlyContinue).OVERRIDE_NUMBER_MATCHING_WITH_OTP
        $status.OverrideNumberMatching = if ($null -ne $overrideVal) { $overrideVal } else { 'Not set (default: number matching required)' }

        $thumbprint = (Get-ItemProperty -Path $azureMfaRegPath -Name 'CLIENT_CERT_IDENTIFIER' -ErrorAction SilentlyContinue).CLIENT_CERT_IDENTIFIER
        $cert = $null
        if ($thumbprint) {
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumbprint }
        }
        if (-not $cert) {
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -like "*OU=Microsoft NPS Extension*" } |
                Sort-Object NotAfter -Descending | Select-Object -First 1
        }
        if ($cert) {
            $status.ExtensionCertThumbprint = $cert.Thumbprint
            $status.ExtensionCertExpires    = $cert.NotAfter
            $status.ExtensionCertDaysLeft   = [int]([datetime]$cert.NotAfter - (Get-Date)).TotalDays
        }
    }

    return $status
}
