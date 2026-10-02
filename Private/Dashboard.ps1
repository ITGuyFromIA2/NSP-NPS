<#
    Dashboard.ps1 - NPS Manager's menu actions and screens, moved verbatim from the zip-era
    NPS-Manager.ps1 (everything between its startup block and its main menu loop). The startup block and
    the main loop are now Start-NSPNpsManager (Public).
#>
# ---------------------------------------------------------------------------
function Show-NPSStatus {
    param([Parameter(Mandatory)]$Status)

    $roleColor = if ($Status.NPSRoleInstalled) { 'Green' } else { 'Yellow' }
    Write-Host "NPS Role Installed:        $(if ($Status.NPSRoleInstalled) { 'Yes' } else { 'No / Unknown' })" -ForegroundColor $roleColor

    if ($Status.NPSRoleInstalled) {
        $adColor = switch ($Status.ADRegistered) { $true { 'Green' } $false { 'Yellow' } default { 'Gray' } }
        $adText  = switch ($Status.ADRegistered) { $true { 'Yes' } $false { 'No' } default { 'Unknown (check failed/timed out - see Option 1 to check/fix)' } }
        Write-Host "Registered in AD:          $adText" -ForegroundColor $adColor
    }

    if ($Status.IASConfigExists) {
        Write-Host "ias.xml:                   Found - $($Status.ConnectionRequestPolicyCount) Connection Request Polic$(if ($Status.ConnectionRequestPolicyCount -eq 1) { 'y' } else { 'ies' }), $($Status.PolicyCount) Network Polic$(if ($Status.PolicyCount -eq 1) { 'y' } else { 'ies' }), $($Status.ClientCount) RADIUS client(s)" -ForegroundColor Green
        Write-Host "  Path:                    $($Status.IASConfigPath)" -ForegroundColor Gray
    } else {
        Write-Host "ias.xml:                   NOT FOUND at $($Status.IASConfigPath)" -ForegroundColor Red
    }

    if ($Status.ExtensionInstalled) {
        Write-Host "NPS Extension (Azure MFA): Installed" -ForegroundColor Green
        if ($Status.ExtensionCertThumbprint) {
            $certColor = if ($Status.ExtensionCertDaysLeft -lt 30) { 'Red' } elseif ($Status.ExtensionCertDaysLeft -lt 60) { 'Yellow' } else { 'Green' }
            Write-Host ("  Certificate:             {0}" -f $Status.ExtensionCertThumbprint) -ForegroundColor $certColor
            Write-Host ("  Expires:                 {0:yyyy-MM-dd}  ({1} days left)" -f $Status.ExtensionCertExpires, $Status.ExtensionCertDaysLeft) -ForegroundColor $certColor
        } else {
            Write-Host "  Certificate:             Not found - extension may be misconfigured" -ForegroundColor Yellow
        }
        Write-Host "  Number Matching Override: $($Status.OverrideNumberMatching)" -ForegroundColor Gray
    } elseif ($Status.ExtensionOrphanedConfig) {
        Write-Host "NPS Extension (Azure MFA): NOT installed - but leftover registry config found" -ForegroundColor Yellow
        Write-Host "  (HKLM:\SOFTWARE\Microsoft\AzureMfa exists, but Programs and Features shows it" -ForegroundColor Yellow
        Write-Host "  uninstalled - the uninstaller left this behind. See Option 2 to clean it up.)" -ForegroundColor Yellow
    } else {
        Write-Host "NPS Extension (Azure MFA): Not installed" -ForegroundColor Yellow
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
function Invoke-NotYetBuilt {
    param([Parameter(Mandatory)][string]$OptionName)
    Write-NPSHeader $OptionName
    Write-Host "Not built yet - a later NPSManager update covers this." -ForegroundColor Yellow
    Read-Host "Press Enter to return to the menu"
}

# ---------------------------------------------------------------------------
function Invoke-InstallAuthorizeNPS {
    <#
    .SYNOPSIS
        Option 1 - installs the NPAS Windows feature if missing, then offers to register this
        server in Active Directory (add it to the "RAS and IAS Servers" domain group) if it isn't
        already. Two independent, individually-confirmed steps - a tech might legitimately want one
        without the other (e.g. role already installed by someone else, just needs registering).

        If the AD registration CHECK fails (flaky ADWS auto-discovery at some sites - confirmed
        live), offers Invoke-NPSADFallbackPrompt's "connect to a specific DC directly" workaround.
        On success this updates $script:ADServer AND $script:ADCredential for the rest of THIS
        session (so the main status screen and every other AD-touching option pick both up
        immediately too, not just this one check) and, if the tech opts in, saves the DC hostname
        (never the credential) into the staged shim for future launches.
    #>
    param([string]$ADServer, [string]$ShimPath, [System.Management.Automation.PSCredential]$ADCredential, [string]$ADUsername)

    Write-NPSHeader "Install / Authorize the NPS Server"

    # --- Role install ---
    try {
        $existing = Get-WindowsFeature -Name NPAS -ErrorAction SilentlyContinue
        if ($existing -and $existing.InstallState -eq 'Installed') {
            Write-Host "NPS role (NPAS) is already installed." -ForegroundColor Green
        } else {
            $confirm = Read-Host "NPS role (NPAS) is not installed. Install it now? (Y/N)"
            if ($confirm -match '^[Yy]') {
                Write-Host "Installing NPAS (Network Policy and Access Services)..." -ForegroundColor Cyan
                $roleResult = Install-NPSRole
                if ($roleResult.Success) {
                    Write-Host "Installed." -ForegroundColor Green
                    if ($roleResult.RestartNeeded) {
                        Write-Host "A RESTART is required before NPS can be used." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "Install reported failure - check Windows Server logs (Get-WindowsFeature / Server Manager)." -ForegroundColor Red
                }
            } else {
                Write-Host "Skipped role install." -ForegroundColor Gray
            }
        }
    } catch {
        Write-Host "Could not check/install the NPS role - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "(This needs to run on Windows Server, with the ServerManager module available.)" -ForegroundColor Gray
    }

    Write-Host ""

    # --- AD registration ---
    try {
        if (-not (Test-RSATAvailable)) {
            Write-Host "The ActiveDirectory module (RSAT) isn't available - needed to check/set AD registration." -ForegroundColor Yellow
            $installRSAT = Read-Host "Install it now? (Y/N)"
            if ($installRSAT -match '^[Yy]') {
                Install-RSATActiveDirectoryModule | Out-Null
            }
        }

        $isRegistered = $null
        try {
            $isRegistered = Test-NPSServerRegistered -Server $ADServer -Credential $ADCredential
        } catch {
            Write-Host "Could not check AD registration status - $($_.Exception.Message)" -ForegroundColor Yellow
            $fallback = Invoke-NPSADFallbackPrompt -ShimPath $ShimPath -ADUsername $ADUsername
            if ($fallback) {
                $isRegistered = $fallback.Registered
                # Applies for the rest of THIS session too, not just this one check - the main status
                # screen and Options 3/5 all read this same $ADServer/$ADCredential on their next AD call.
                $script:ADServer = $fallback.DCServer
                $script:ADCredential = $fallback.Credential
                if ($fallback.Username) { $script:ADUsername = $fallback.Username }
            }
        }

        if ($isRegistered -eq $true) {
            Write-Host "This server is already registered in AD (member of 'RAS and IAS Servers')." -ForegroundColor Green
        } else {
            $defaultDomain = $env:USERDNSDOMAIN
            $domainPrompt = if ($defaultDomain) { "Register this server in Active Directory now? Domain [Enter for '$defaultDomain'], or type a different domain, or N to skip" }
                            else { "Register this server in Active Directory now? Type the domain name, or N to skip (this machine doesn't appear to be domain-joined)" }
            $domainInput = Read-Host $domainPrompt
            if ($domainInput -match '^[Nn]$') {
                Write-Host "Skipped AD registration." -ForegroundColor Gray
            } else {
                $domain = if ([string]::IsNullOrWhiteSpace($domainInput)) { $defaultDomain } else { $domainInput }
                if (-not $domain) {
                    Write-Host "No domain given - skipped." -ForegroundColor Yellow
                } else {
                    # Show the real command via -WhatIf rather than a separately-hardcoded display
                    # string, so this can never drift out of sync with what Register-NPSServerInAD
                    # actually runs.
                    $preview = Register-NPSServerInAD -Domain $domain -WhatIf
                    Write-Host "Running: $($preview.WouldRun)" -ForegroundColor Cyan
                    $result = Register-NPSServerInAD -Domain $domain
                    if ($result.Output) { Write-Host $result.Output }
                    if ($result.ExitCode -eq 0) {
                        Write-Host "Registered (added to 'RAS and IAS Servers' in $domain)." -ForegroundColor Green
                    } else {
                        Write-Host "netsh reported a non-zero exit code ($($result.ExitCode)) - see output above." -ForegroundColor Red
                    }
                    # This is the one action that could actually change the answer mid-session -
                    # next status check should see it fresh, not whatever was cached before this ran
                    # (including a cached FAILURE from before registration existed to check against).
                    Clear-NPSServerRegisteredCache
                }
            }
        }
    } catch {
        Write-Host "Error during AD registration - $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""

    # --- ias.xml existence (the actual chicken/egg) ---
    # Confirmed live, 2026-08-18: role install + AD registration alone do NOT create ias.xml - a
    # fresh NPS with both of those already done can still have no config file at all, which blocks
    # every other option in this dashboard (Import Kickstart Definitions, Manage Clients/Rules, etc.
    # all Test-Path $IASConfigPath and refuse to run without it). Windows creates the default
    # ias.xml the FIRST TIME the actual "Network Policy Server" (IAS) service starts and initializes
    # its config store - not at role-install time, not at AD-registration time. So make that
    # actually happen here, in the one place a tech would reasonably expect "install/authorize" to
    # leave NPS in a working state.
    if (Test-Path $IASConfigPath) {
        Write-Host "ias.xml already exists at $IASConfigPath." -ForegroundColor Green
    } else {
        Write-Host "ias.xml not found at $IASConfigPath yet." -ForegroundColor Yellow
        try {
            $iasSvc = Get-Service -Name IAS -ErrorAction Stop
            if ($iasSvc.Status -eq 'Running') {
                # Already running but still no ias.xml - not the normal first-start case. Confirmed
                # live, 2026-09-03 (the maintainer): even a running IAS service can leave its config
                # "completely synthesized" in memory only, never flushed to disk, until an actual
                # config-changing operation happens - same underlying issue as the never-started
                # branch below, just already past the service-start step. Same shortcut applies.
                Write-Host "The IAS (Network Policy Server) service is already running, but ias.xml still" -ForegroundColor Yellow
                Write-Host "isn't there yet." -ForegroundColor Yellow
                Invoke-IASConfigBootstrapPrompt -IASConfigPath $IASConfigPath
            } else {
                $startConfirm = Read-Host "The IAS (Network Policy Server) service has never started - starting it creates ias.xml. Start it now? (Y/N)"
                if ($startConfirm -match '^[Yy]') {
                    try {
                        Start-Service -Name IAS -ErrorAction Stop
                        # Give it a moment to actually write the file before checking - not
                        # instantaneous even on success.
                        Start-Sleep -Seconds 2
                        if (Test-Path $IASConfigPath) {
                            Write-Host "Started - ias.xml now exists." -ForegroundColor Green
                        } else {
                            # Confirmed live, 2026-09-03 (the maintainer): starting the service isn't always
                            # enough by itself - a fresh install can leave ias.xml missing until an
                            # actual config-changing operation happens (previously that meant opening
                            # the NPS MMC console and touching ANYTHING). Try the forced-write shortcut
                            # right here instead of just telling the tech to wait or dig into GUI.
                            Write-Host "Service started, but ias.xml still isn't there yet." -ForegroundColor Yellow
                            Invoke-IASConfigBootstrapPrompt -IASConfigPath $IASConfigPath
                        }
                    } catch {
                        Write-Host "Could not start the IAS service - $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host "(If the NPAS role install above reported a restart is needed, that restart has to happen first.)" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "Skipped - ias.xml won't exist until the IAS service starts at least once." -ForegroundColor Gray
                }
            }
        } catch {
            Write-Host "Could not query the IAS service - $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "(This usually means the NPAS role isn't fully installed yet - see the role-install step above.)" -ForegroundColor Gray
        }
    }

    Read-Host "Press Enter to return to the menu"
}

# ---------------------------------------------------------------------------
function Invoke-ManageNPSExtension {
    <#
    .SYNOPSIS
        Option 2 - "Manage NPS Extension": everything about the NPS Extension for Azure MFA in one
        place - prereq check, install/update, the OVERRIDE_NUMBER_MATCHING_WITH_OTP registry setting
        (folded in from the former standalone Option 4 - it's the same HKLM:\SOFTWARE\Microsoft\AzureMfa
        hive this menu already reads for cert/status, so it belongs here rather than as its own
        top-level item), and uninstall. Cert/status display stays on the main dashboard (Get-NPSStatus).

        The AuthSrv\Parameters DLL-disablement registry item (temporarily disabling the extension for
        troubleshooting) deliberately stays under Option 6/Troubleshooting, NOT here - that's a
        diagnostic action on a running install, not an install/config/lifecycle action.

        See Modules\NPSExtension.ps1's header for the verified (not guessed) install/uninstall details
        this is built from.
    #>
    param([string]$IASConfigPath)

    :ExtensionMenu while ($true) {
        Write-NPSHeader "Manage NPS Extension"

        $status = Get-NPSStatus -IASConfigPath $IASConfigPath
        if ($status.ExtensionInstalled) {
            Write-Host "Status: INSTALLED" -ForegroundColor Green
            if ($status.ExtensionCertThumbprint) {
                Write-Host "  Certificate: $($status.ExtensionCertThumbprint)  (expires $($status.ExtensionCertExpires.ToString('yyyy-MM-dd')), $($status.ExtensionCertDaysLeft) days left)"
            } else {
                Write-Host "  Certificate: not found - extension may be misconfigured" -ForegroundColor Yellow
            }
            Write-Host "  Number matching override: $($status.OverrideNumberMatching)"
        } elseif ($status.ExtensionOrphanedConfig) {
            Write-Host "Status: NOT installed - but leftover registry config found" -ForegroundColor Yellow
            Write-Host "  HKLM:\SOFTWARE\Microsoft\AzureMfa exists, but Programs and Features shows no" -ForegroundColor Yellow
            Write-Host "  matching entry - a previous uninstall left this behind. Use option 6 below to clean it up." -ForegroundColor Yellow
        } else {
            Write-Host "Status: NOT installed (HKLM:\SOFTWARE\Microsoft\AzureMfa not present)" -ForegroundColor Yellow
        }

        Write-Host ""
        Write-Host "  1. Check prerequisites (.NET 4.7.2+, PowerShell 5.1+)"
        Write-Host "  2. Install or Update the NPS Extension"
        Write-Host "  3. Run the NPS Extension configuration script (register/reconfigure tenant, rotate cert)"
        Write-Host "  4. Set OVERRIDE_NUMBER_MATCHING_WITH_OTP (push approve/deny fallback)"
        Write-Host "  5. Uninstall the NPS Extension"
        if ($status.ExtensionOrphanedConfig) {
            Write-Host "  6. Clean up leftover registry config (no matching install found)" -ForegroundColor Yellow
        }
        Write-Host "  M. Return to main menu"
        Write-Host ""
        $choice = Read-Host "Select an option"

        switch -Regex ($choice) {
            '^1$' {
                $prereqs = Test-NPSExtensionPrereqs
                Write-Host ""
                Write-Host "  .NET Framework:  $($prereqs.DotNetLabel)" -ForegroundColor $(if ($prereqs.DotNetOk) { 'Green' } else { 'Red' })
                Write-Host "  PowerShell:      $($prereqs.PSVersion)  $(if ($prereqs.PSOk) { '(OK - 5.1+)' } else { '(BELOW 5.1)' })" -ForegroundColor $(if ($prereqs.PSOk) { 'Green' } else { 'Red' })
                if (-not $prereqs.AllOk) {
                    Write-Host "  Resolve the above before installing the extension." -ForegroundColor Yellow
                }

                Write-Host ""
                $autoCap = Test-NPSExtensionAutoDownloadCapability
                Write-Host "  Automated headless download:  $(if ($autoCap.Available) { 'Available' } else { "Not available - $($autoCap.Reason)" })" -ForegroundColor $(if ($autoCap.Available) { 'Green' } else { 'Yellow' })
                Write-Host "  (optional - the manual 'open the download page' flow always works regardless)" -ForegroundColor Gray
                if (-not $autoCap.Available) {
                    $tryInstall = Read-Host "`nInstall the Selenium module + a matching Edge driver now? (Y/N)"
                    if ($tryInstall -match '^[Yy]') {
                        $installResult = Install-NPSExtensionAutoDownloadPrereqs
                        if ($installResult.Errors.Count -gt 0) {
                            foreach ($e in $installResult.Errors) { Write-Host "  $e" -ForegroundColor Red }
                        }
                        $reCheck = Test-NPSExtensionAutoDownloadCapability
                        Write-Host "  Result: $(if ($reCheck.Available) { 'Available now' } else { "Still not available - $($reCheck.Reason)" })" -ForegroundColor $(if ($reCheck.Available) { 'Green' } else { 'Yellow' })
                    }
                }
                Read-Host "`nPress Enter to continue"
            }
            '^2$' {
                # Install and Update are the same flow - the installer/config script are idempotent
                # (re-running them is how Microsoft documents refreshing an existing install too), so
                # there's no separate "update" code path to maintain.
                Write-NPSHeader "Step 1 of 2: Download / Install"
                $autoCapability = Test-NPSExtensionAutoDownloadCapability
                if (-not $autoCapability.Available) {
                    Write-Host "Automated headless download isn't available yet: $($autoCapability.Reason)" -ForegroundColor Yellow
                    $tryInstall = Read-Host "Try installing the Selenium module + a matching Edge driver now? (Y/N)"
                    if ($tryInstall -match '^[Yy]') {
                        $installResult = Install-NPSExtensionAutoDownloadPrereqs
                        if ($installResult.Errors.Count -gt 0) {
                            foreach ($e in $installResult.Errors) { Write-Host "  $e" -ForegroundColor Red }
                        }
                        if ($installResult.ModuleInstalled -and $installResult.DriverInstalled) {
                            Write-Host "Prereqs installed - re-checking..." -ForegroundColor Green
                            $autoCapability = Test-NPSExtensionAutoDownloadCapability
                        } else {
                            Write-Host "Prereqs not fully installed - falling back to the manual download page." -ForegroundColor Yellow
                        }
                    }
                }
                $downloadedPath = $null
                if ($autoCapability.Available) {
                    $tryAuto = Read-Host "Automated headless download is available - use it instead of opening a browser? (Y/N)"
                    if ($tryAuto -match '^[Yy]') {
                        $autoDestDir = Join-Path $env:TEMP "NPSExtensionDownload"
                        $autoDest = Join-Path $autoDestDir "NpsExtnForAzureMfaInstaller.exe"
                        try {
                            Write-Host "Downloading (headless) - this takes ~15-20 seconds..." -ForegroundColor Cyan
                            $autoResult = Invoke-NPSExtensionAutoDownload -DestinationPath $autoDest
                            $downloadedPath = $autoResult.DestinationPath
                            Write-Host "Downloaded to $downloadedPath - installing silently (no clicks needed)..." -ForegroundColor Green
                            $installLog = Join-Path $autoDestDir "NpsExtnInstall.log"
                            # NpsExtnForAzureMfaInstaller.exe is a WiX-Burn-style bootstrapper, same family
                            # as most other single-purpose Microsoft installers (.NET, VC++ redist, etc.) -
                            # /quiet + /norestart is the standard convention for that installer family: no
                            # UI, no prompts, no reboot kicked off out from under the tech. /log captures a
                            # verbatim record so a failure can be diagnosed without having to repro it
                            # interactively.
                            $installProc = Start-Process -FilePath $downloadedPath -ArgumentList "/quiet", "/norestart", "/log", "`"$installLog`"" -Wait -PassThru
                            if ($installProc.ExitCode -eq 0) {
                                Write-Host "Installer finished silently (exit code 0)." -ForegroundColor Green
                            } else {
                                Write-Host "Installer exited with code $($installProc.ExitCode) - it may not have completed." -ForegroundColor Red
                                Write-Host "Log: $installLog" -ForegroundColor Yellow
                                Write-Host "If Step 2 below can't find the config script, re-run '$downloadedPath' without arguments to install interactively and see what it's waiting on." -ForegroundColor Yellow
                            }
                        } catch {
                            Write-Host "Auto-download failed: $($_.Exception.Message)" -ForegroundColor Red
                            Write-Host "Falling back to the manual download page." -ForegroundColor Yellow
                            $downloadedPath = $null
                        }
                    }
                }
                if (-not $downloadedPath) {
                    Open-NPSExtensionDownloadPage
                    Read-Host "Press Enter once you've downloaded and run NpsExtnForAzureMfaInstaller.exe, to continue"
                }

                Write-NPSHeader "Step 2 of 2: Configure"
                Invoke-NPSExtensionConfigScript
                Read-Host "`nPress Enter to continue"
            }
            '^3$' {
                Write-NPSHeader "Run NPS Extension Configuration Script"
                Invoke-NPSExtensionConfigScript
                Read-Host "`nPress Enter to continue"
            }
            '^4$' { Invoke-SetNumberMatchingOverride }
            '^5$' {
                # -Force: want the true current state right before offering to uninstall, not
                # whatever was cached at dashboard startup or last redraw.
                $uninstallInfo = Get-NPSExtensionUninstallInfo -Force
                if (-not $uninstallInfo) {
                    Write-Host "Could not find an NPS Extension entry in Programs and Features - nothing to uninstall" -ForegroundColor Yellow
                    Write-Host "via this path (it may have been installed/removed differently)." -ForegroundColor Yellow
                } else {
                    Write-Host ""
                    Write-Host "Found: $($uninstallInfo.DisplayName) (version $($uninstallInfo.DisplayVersion))" -ForegroundColor Cyan
                    Write-Host "Uninstall command: $(if ($uninstallInfo.QuietUninstallString) { $uninstallInfo.QuietUninstallString } else { $uninstallInfo.UninstallString })" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "This will remove the NPS Extension - RADIUS clients relying on Azure MFA will fall" -ForegroundColor Yellow
                    Write-Host "back to primary (AD) authentication only until it's reinstalled." -ForegroundColor Yellow
                    $confirm = Read-Host "Type UNINSTALL to confirm"
                    if ($confirm -eq 'UNINSTALL') {
                        Write-Host "Running uninstall..." -ForegroundColor Cyan
                        $uninstallResult = Invoke-NPSExtensionUninstall -UninstallInfo $uninstallInfo
                        if ($uninstallResult.Error) {
                            Write-Host "ERROR running uninstall: $($uninstallResult.Error)" -ForegroundColor Red
                        } elseif ($uninstallResult.Verified) {
                            Write-Host "Uninstall verified - Programs and Features no longer lists it (exit code $($uninstallResult.ExitCode))." -ForegroundColor Green
                        } else {
                            Write-Host "Uninstall process exited (code $($uninstallResult.ExitCode)) but Programs and Features STILL shows it" -ForegroundColor Red
                            Write-Host "installed - the uninstall did NOT actually complete. Try running it interactively (without" -ForegroundColor Red
                            Write-Host "/qn) via Programs and Features directly to see what it's waiting on or failing on." -ForegroundColor Red
                        }
                    } else {
                        Write-Host "Cancelled." -ForegroundColor Gray
                    }
                }
                Read-Host "`nPress Enter to continue"
            }
            '^6$' {
                if (-not $status.ExtensionOrphanedConfig) {
                    Write-Host "Invalid selection." -ForegroundColor Yellow
                } else {
                    Write-Host "This removes HKLM:\SOFTWARE\Microsoft\AzureMfa - leftover config from a previous" -ForegroundColor Yellow
                    Write-Host "uninstall (Programs and Features confirms no extension is currently installed)." -ForegroundColor Yellow
                    $confirm = Read-Host "Remove it now? (Y/N)"
                    if ($confirm -match '^[Yy]') {
                        try {
                            $cleanupResult = Remove-NPSExtensionOrphanedConfig
                            if ($cleanupResult.Removed) {
                                Write-Host "Removed." -ForegroundColor Green
                            } else {
                                Write-Host "Already gone - nothing to do." -ForegroundColor Gray
                            }
                        } catch {
                            Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "Cancelled." -ForegroundColor Gray
                    }
                }
                Read-Host "`nPress Enter to continue"
            }
            '^[Mm]$' { return }
            default  { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
function Invoke-NPSExtensionConfigScript {
    <#
    .SYNOPSIS
        Runs (or offers to run) AzureMfaNpsExtnConfigSetup.ps1 - the script the installer drops at
        C:\Program Files\Microsoft\AzureMfa\Config, which prompts for the Azure AD Tenant ID and
        registers/reconfigures the NPS Extension against it (creates/reuses the Azure AD app
        registration, writes the client cert, sets registry values under
        HKLM:\SOFTWARE\Microsoft\AzureMfa). Per Microsoft's own docs this is also how you rotate an
        expiring cert or re-point at a different tenant - it's not a one-time install-only step, so
        this is broken out as its own reusable action (called both right after a fresh install/update,
        and standalone from the menu for a later re-run) rather than being buried inline in the
        install flow only.
    #>
    $configScript = 'C:\Program Files\Microsoft\AzureMfa\Config\AzureMfaNpsExtnConfigSetup.ps1'
    if (-not (Test-Path $configScript)) {
        Write-Host "Config script not found at $configScript - the NPS Extension may not be installed." -ForegroundColor Red
        return
    }

    Write-Host "This script prompts for your Azure AD Tenant ID and registers/configures the NPS" -ForegroundColor Cyan
    Write-Host "Extension against your tenant (creates/reuses an Azure AD app registration, writes" -ForegroundColor Cyan
    Write-Host "the client cert, sets registry values under HKLM:\SOFTWARE\Microsoft\AzureMfa)." -ForegroundColor Cyan
    Write-Host "Also used to rotate an expiring cert or re-point at a different tenant - safe to re-run." -ForegroundColor Cyan
    $confirm = Read-Host "Run '$configScript' now? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Skipped." -ForegroundColor Gray
        return
    }

    # TLS 1.2 required for the Azure AD calls this script makes - documented prereq, applied here
    # (process-scoped) rather than assuming the OS default already covers it.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    & $configScript
    # Reconfigure could plausibly change the Programs-and-Features entry (e.g. a version bump) -
    # next status check should see it fresh, not cached.
    Clear-NPSExtensionUninstallInfoCache
}

# ---------------------------------------------------------------------------
function Invoke-SetNumberMatchingOverride {
    <#
    .SYNOPSIS
        Sets/clears OVERRIDE_NUMBER_MATCHING_WITH_OTP under HKLM:\SOFTWARE\Microsoft\AzureMfa -
        registry path and TRUE/FALSE semantics verified against Microsoft's own NPS extension docs
        (not guessed). FALSE = allow fallback to Approve/Deny push; TRUE = enforce OTP instead of
        number matching (extension 1.0.1.40+, Authenticator-registered users only); unset/removed =
        Microsoft's default (number matching required, no fallback).
    #>
    Write-NPSHeader "Number Matching Override"
    $regPath = 'HKLM:\SOFTWARE\Microsoft\AzureMfa'
    if (-not (Test-Path $regPath)) {
        Write-Host "The NPS Extension for Azure MFA doesn't appear to be installed on this machine" -ForegroundColor Red
        Write-Host "($regPath not found) - install it first (Option 2)." -ForegroundColor Red
        Read-Host "Press Enter to return to the menu"
        return
    }

    $current = (Get-ItemProperty -Path $regPath -Name 'OVERRIDE_NUMBER_MATCHING_WITH_OTP' -ErrorAction SilentlyContinue).OVERRIDE_NUMBER_MATCHING_WITH_OTP
    Write-Host "Current value: $(if ($null -ne $current) { $current } else { '(not set - number matching required, no fallback)' })"
    Write-Host ""
    Write-Host "  F - FALSE: allow fallback to Approve/Deny push notifications"
    Write-Host "  T - TRUE:  enforce OTP instead of number matching"
    Write-Host "  R - Remove the override entirely (back to Microsoft's default)"
    Write-Host "  C - Cancel"
    $choice = Read-Host "Select an option"
    switch -Regex ($choice) {
        '^[Ff]' {
            New-ItemProperty -Path $regPath -Name 'OVERRIDE_NUMBER_MATCHING_WITH_OTP' -Value 'FALSE' -PropertyType String -Force | Out-Null
            Write-Host "Set to FALSE." -ForegroundColor Green
        }
        '^[Tt]' {
            New-ItemProperty -Path $regPath -Name 'OVERRIDE_NUMBER_MATCHING_WITH_OTP' -Value 'TRUE' -PropertyType String -Force | Out-Null
            Write-Host "Set to TRUE." -ForegroundColor Green
        }
        '^[Rr]' {
            Remove-ItemProperty -Path $regPath -Name 'OVERRIDE_NUMBER_MATCHING_WITH_OTP' -ErrorAction SilentlyContinue
            Write-Host "Override removed - back to Microsoft's default (number matching required)." -ForegroundColor Green
        }
        default { Write-Host "Cancelled." -ForegroundColor Gray }
    }
    Read-Host "Press Enter to return to the menu"
}

# ---------------------------------------------------------------------------
function Select-NPSClientFromList {
    param(
        [Parameter(Mandatory)][array]$Clients,
        [string]$Prompt = "Select a client by number"
    )
    if ($Clients.Count -eq 0) { Write-Host "No RADIUS clients to select from." -ForegroundColor Yellow; return $null }
    for ($i = 0; $i -lt $Clients.Count; $i++) {
        $c = $Clients[$i]
        $stateTag = if ($c.Enabled) { '' } else { ' [DISABLED]' }
        Write-Host ("    {0}. {1}  ({2}){3}" -f ($i + 1), $c.Name, $c.IPAddress, $stateTag)
    }
    $sel = Read-Host $Prompt
    $idx = ($sel -as [int]) - 1
    if ($idx -ge 0 -and $idx -lt $Clients.Count) { return $Clients[$idx] }
    Write-Host "Invalid selection." -ForegroundColor Yellow
    return $null
}

# ---------------------------------------------------------------------------
function Select-NPSTemplateFromList {
    <#
    .SYNOPSIS
        Name-only picker for Shared Secret Templates (Get-NPSSharedSecretTemplates) - no IP/Enabled
        state to show, unlike a Client (Select-NPSClientFromList, also reused as-is for RADIUS Client
        Templates - Get-NPSClientTemplates returns the exact same Name/IPAddress/Enabled shape).
    #>
    param(
        [Parameter(Mandatory)][array]$Templates,
        [string]$Prompt = "Select a template by number"
    )
    if ($Templates.Count -eq 0) { Write-Host "No Shared Secret Templates to select from." -ForegroundColor Yellow; return $null }
    for ($i = 0; $i -lt $Templates.Count; $i++) {
        Write-Host ("    {0}. {1}" -f ($i + 1), $Templates[$i].Name)
    }
    $sel = Read-Host $Prompt
    $idx = ($sel -as [int]) - 1
    if ($idx -ge 0 -and $idx -lt $Templates.Count) { return $Templates[$idx] }
    Write-Host "Invalid selection." -ForegroundColor Yellow
    return $null
}

# ---------------------------------------------------------------------------
function Get-NPSTemplatesPathFor {
    <#
    .SYNOPSIS
        Derives iastemplates.xml's path as the sibling of a given ias.xml path, rather than
        hardcoding the live "C:\Windows\System32\ias\..." location a second time here - keeps this
        working when $IASConfigPath is overridden (e.g. testing against a copy).
    #>
    param([Parameter(Mandatory)][string]$IASConfigPath)
    return Join-Path -Path (Split-Path -Path $IASConfigPath -Parent) -ChildPath "iastemplates.xml"
}

# ---------------------------------------------------------------------------
function Resolve-NPSEffectiveSharedSecretTemplateName {
    <#
    .SYNOPSIS
        Resolves the Shared Secret Template that actually governs a client's secret - checking BOTH
        levels of the chain confirmed live this session (the maintainer, a multi-level template setup): a client can
        link to a Shared Secret Template directly (ClientSecretTemplateGuid), or indirectly via a
        RADIUS Client Template (ClientTemplateGuid) that itself links to one. Direct link wins if
        both are somehow set to different chains (shouldn't normally happen - every real sample seen
        has a client created "from a template" carrying both links to the SAME chain).
    #>
    param(
        [Parameter(Mandatory)]$Client,
        [Parameter(Mandatory)][string]$TemplatesPath
    )
    $direct = Resolve-NPSSharedSecretTemplateName -Guid $Client.ClientSecretTemplateGuid -TemplatesPath $TemplatesPath
    if ($direct) { return $direct }

    $clientTemplateName = Resolve-NPSClientTemplateName -Guid $Client.ClientTemplateGuid -TemplatesPath $TemplatesPath
    if (-not $clientTemplateName) { return $null }
    $clientTemplate = Get-NPSClientTemplates -Path $TemplatesPath | Where-Object Name -eq $clientTemplateName
    if (-not $clientTemplate) { return $null }
    return Resolve-NPSSharedSecretTemplateName -Guid $clientTemplate.ClientSecretTemplateGuid -TemplatesPath $TemplatesPath
}

# ---------------------------------------------------------------------------
function New-NPSRandomSecret {
    <#
    .SYNOPSIS
        Generates a cryptographically random shared-secret-shaped string - mixed-case letters,
        digits, and a curated symbol set that avoids characters known to cause trouble when the same
        value has to be re-typed somewhere else (backtick, double-quote, backslash - classic
        shell/CLI escaping hazards on the FortiGate side). Everything else in the set is already
        proven safe end-to-end in THIS codebase - real captured secrets containing &, <, >, #, etc.
        all round-trip correctly through ConvertTo-NPSXmlText.

    .DESCRIPTION
        Uses RandomNumberGenerator.Create()+GetBytes (NOT the newer static .Fill() overload) -
        deliberately the older, more broadly-compatible API shape, since this needs to run under
        Windows PowerShell 5.1 / .NET Framework on the actual target machines (confirmed live,
        The maintainer: "only powershell 5.1 is available on these machines"), not just this sandbox's pwsh.

        Selection is a simple byte % charset.Length - a tiny, well-known modulo bias toward the
        charset's first few characters (here: ~1.19% vs ~1.17% per character, since 256 isn't evenly
        divisible by the charset size) that's irrelevant at this length/purpose (a RADIUS shared
        secret, not a cryptographic key in its own right) - not worth the complexity of rejection
        sampling for what this is actually used for.
    #>
    param([int]$Length = 32)

    $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.?'
    $bytes = [byte[]]::new($Length)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $sb = [System.Text.StringBuilder]::new()
    foreach ($b in $bytes) { [void]$sb.Append($charset[$b % $charset.Length]) }
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
function Read-NPSSharedSecret {
    <#
    .SYNOPSIS
        Prompts for a shared secret without echoing it to the console/scrollback
        (Read-Host -AsSecureString), then converts back to plain text for writing into ias.xml -
        NPS stores it there in plaintext regardless (same as every real client entry in the sample
        files), so this doesn't add protection at rest, just avoids it echoing on entry when it
        doesn't have to.

        Also offers to auto-generate a strong random secret instead of typing one - type 'GEN' at
        the prompt (case-insensitive, since it's the plaintext behind a masked SecureString prompt -
        the tech can't see what they typed to self-correct casing). Every shared-secret entry point
        in this tool (Add/Edit Client, Add/Edit Shared Secret Template, Add/Edit RADIUS Client
        Template, the Import Kickstart Definitions fallback) goes through this ONE function, so
        adding it here covers all of them at once rather than needing a change at each call site.

        The generated value IS shown on screen afterward (unlike a typed secret, which stays hidden
        because the tech already knows what they typed) - there's no way around that for a freshly-
        generated value nobody has seen yet; it has to be visible so the tech can copy it into the
        matching config on the other end (the FortiGate, or wherever else this secret needs to match).
    #>
    param(
        [string]$Prompt = "Shared secret",
        [int]$GeneratedLength = 32
    )
    while ($true) {
        $secure = Read-Host -Prompt "$Prompt [or type GEN to auto-generate one]" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }

        if ($plain -ne 'GEN') { return $plain }

        $generated = New-NPSRandomSecret -Length $GeneratedLength
        Write-Host "Generated: $generated" -ForegroundColor Yellow
        Write-Host "(copy this now - you'll need to enter the SAME value on the other end, e.g. the FortiGate)" -ForegroundColor Gray
        $useIt = Read-Host "Use this generated secret? (Y/N, N to generate a different one or type your own)"
        if ($useIt -match '^[Yy]') { return $generated }
        # Falls through to the top of the loop - re-prompts fresh (type GEN again for a new roll, or
        # type a real secret manually this time).
    }
}

# ---------------------------------------------------------------------------
function Invoke-AddClient {
    param([Parameter(Mandatory)][string]$IASConfigPath)

    Write-NPSHeader "Add RADIUS Client"
    $name = Read-Host "Client name (e.g. the FortiGate's hostname)"
    while ([string]::IsNullOrWhiteSpace($name)) { $name = Read-Host "A name is required" }

    $ip = Read-Host "Client IP address"
    while ([string]::IsNullOrWhiteSpace($ip)) { $ip = Read-Host "An IP address is required" }

    $secret = Read-NPSSharedSecret -Prompt "Shared secret (must match what's configured on the FortiGate)"
    while ([string]::IsNullOrWhiteSpace($secret)) { $secret = Read-NPSSharedSecret -Prompt "A shared secret is required" }

    $enabledInput = Read-Host "Enabled? [Enter for Yes] (Y/N)"
    $enabled = -not ($enabledInput -match '^[Nn]')

    try {
        $result = Add-NPSClient -Path $IASConfigPath -Name $name -IPAddress $ip -SharedSecret $secret -Enabled $enabled
        Write-Host "Added '$name' ($ip)." -ForegroundColor Green
        Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
function Invoke-EditClient {
    param([Parameter(Mandatory)][string]$IASConfigPath)

    Write-NPSHeader "Edit RADIUS Client"
    $clients = Get-NPSClients -Path $IASConfigPath
    $picked = Select-NPSClientFromList -Clients $clients -Prompt "Select a client to edit, by number"
    if (-not $picked) { return }

    # Best-effort - Resolve-NPSEffectiveSharedSecretTemplateName's own calls swallow their errors
    # (missing iastemplates.xml, zero GUID, etc.) and return $null, so this is safe unconditionally.
    $linkedTemplateName = Resolve-NPSEffectiveSharedSecretTemplateName -Client $picked -TemplatesPath (Get-NPSTemplatesPathFor -IASConfigPath $IASConfigPath)
    $secretLine = if ($linkedTemplateName) { "current: hidden - linked to template '$linkedTemplateName'" } else { "current: hidden - select to reveal or change" }

    Write-Host ""
    Write-Host "Editing '$($picked.Name)':" -ForegroundColor Cyan
    Write-Host "  I. IP Address        (current: $($picked.IPAddress))"
    Write-Host "  S. Shared Secret     ($secretLine)"
    Write-Host "  E. Enabled           (current: $($picked.Enabled))"
    Write-Host "  R. Require Signature (current: $($picked.RequireSignature))"
    Write-Host "  M. Back"
    $attrChoice = Read-Host "Select an attribute to change"

    $result = $null
    switch -Regex ($attrChoice) {
        '^[Ii]$' {
            $newIp = Read-Host "New IP address [Enter to cancel]"
            if ([string]::IsNullOrWhiteSpace($newIp)) { Write-Host "Cancelled." -ForegroundColor Gray; return }
            $result = Set-NPSClientAttribute -Path $IASConfigPath -Name $picked.Name -Attribute IPAddress -Value $newIp
        }
        '^[Ss]$' {
            $reveal = Read-Host "Reveal current secret first? (Y/N)"
            if ($reveal -match '^[Yy]') { Write-Host "Current secret: $($picked.SharedSecret)" -ForegroundColor Yellow }

            # $linkedTemplateName was already resolved above to build the menu's "current:" line.
            # Confirmed live (the maintainer, a multi-level chain test): Set-NPSSharedSecretTemplateValue
            # CASCADES to every linked RADIUS Client Template and every linked client, matching the
            # NPS console's own behavior - so there's no longer a "Both" option distinct from
            # "Template" (Template already keeps this client, and every other client sharing it, in
            # sync). The two remaining choices are genuinely different actions, not two paths to the
            # same result - pick based on WHO should be affected.
            $editTemplate = $false
            if ($linkedTemplateName) {
                Write-Host "'$($picked.Name)' is linked to Shared Secret template '$linkedTemplateName'." -ForegroundColor Yellow
                Write-Host "  T. Edit the template - updates '$linkedTemplateName' AND cascades the new value to" -ForegroundColor Yellow
                Write-Host "                     EVERY client (and RADIUS Client Template) linked to it, not just" -ForegroundColor Yellow
                Write-Host "                     '$($picked.Name)' - confirmed live to match the NPS console's own behavior." -ForegroundColor Yellow
                Write-Host "  C. Edit just this client - only '$($picked.Name)' changes; this BREAKS its link to" -ForegroundColor Yellow
                Write-Host "                     '$linkedTemplateName' (the template itself is left untouched)." -ForegroundColor Yellow
                $destChoice = Read-Host "Edit the [T]emplate (affects every linked client) or just [C]lient? [Enter to cancel]"
                switch -Regex ($destChoice) {
                    '^[Tt]$' { $editTemplate = $true }
                    '^[Cc]$' { $editTemplate = $false }
                    default  { Write-Host "Cancelled." -ForegroundColor Gray; return }
                }
            }

            $newSecret = Read-NPSSharedSecret -Prompt "New shared secret [blank to cancel]"
            if ([string]::IsNullOrWhiteSpace($newSecret)) { Write-Host "Cancelled." -ForegroundColor Gray; return }

            if ($editTemplate) {
                try {
                    $templateResult = Set-NPSSharedSecretTemplateValue -TemplateName $linkedTemplateName -NewSecret $newSecret -Path (Get-NPSTemplatesPathFor -IASConfigPath $IASConfigPath) -IASConfigPath $IASConfigPath
                    if ($templateResult.Changed) {
                        Write-Host "Template '$linkedTemplateName' updated." -ForegroundColor Green
                        Write-Host "Backup: $($templateResult.BackupPath)" -ForegroundColor Green
                        if ($templateResult.CascadedClientTemplateNames.Count -gt 0) {
                            Write-Host "Also updated RADIUS Client Template(s): $($templateResult.CascadedClientTemplateNames -join ', ')" -ForegroundColor Green
                        }
                        if ($templateResult.CascadedClientNames.Count -gt 0) {
                            Write-Host "Also updated live client(s): $($templateResult.CascadedClientNames -join ', ')" -ForegroundColor Green
                            Write-Host "Backup: $($templateResult.IASBackupPath)" -ForegroundColor Green
                        }
                    } else {
                        Write-Host "Template: no change needed - value was already what was asked for." -ForegroundColor Gray
                    }
                } catch {
                    Write-Host "ERROR updating template: $($_.Exception.Message)" -ForegroundColor Red
                }
                # Template path already reported above and doesn't go through the generic $result
                # handling below (that's written in terms of a single CLIENT attribute update).
                return
            }
            $result = Set-NPSClientAttribute -Path $IASConfigPath -Name $picked.Name -Attribute SharedSecret -Value $newSecret
            if ($result.Decoupled) {
                Write-Host "Note: '$($picked.Name)' is no longer linked to '$linkedTemplateName' - its secret is now independent." -ForegroundColor Yellow
            }
        }
        '^[Ee]$' {
            $newEnabled = -not $picked.Enabled
            $confirm = Read-Host "Set Enabled to ${newEnabled}? (Y/N)"
            if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled." -ForegroundColor Gray; return }
            $result = Set-NPSClientAttribute -Path $IASConfigPath -Name $picked.Name -Attribute Enabled -Value $newEnabled
        }
        '^[Rr]$' {
            $newRequireSig = -not $picked.RequireSignature
            $confirm = Read-Host "Set Require Signature to ${newRequireSig}? (Y/N)"
            if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled." -ForegroundColor Gray; return }
            $result = Set-NPSClientAttribute -Path $IASConfigPath -Name $picked.Name -Attribute RequireSignature -Value $newRequireSig
        }
        default { Write-Host "Cancelled." -ForegroundColor Gray; return }
    }

    if ($result.Changed) {
        Write-Host "Updated." -ForegroundColor Green
        Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
    } else {
        Write-Host "No change needed - value was already what was asked for." -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
function Invoke-DeleteClient {
    param([Parameter(Mandatory)][string]$IASConfigPath)

    Write-NPSHeader "Delete RADIUS Client"
    Write-Host "This permanently removes the client entry - not reversible except by restoring the" -ForegroundColor Yellow
    Write-Host "backup this creates. Any rules whose Client-IP-Address condition matches this client" -ForegroundColor Yellow
    Write-Host "will keep that IP as a literal condition value - they are NOT automatically updated." -ForegroundColor Yellow
    $clients = Get-NPSClients -Path $IASConfigPath
    $picked = Select-NPSClientFromList -Clients $clients -Prompt "Select a client to DELETE, by number"
    if (-not $picked) { return }

    $confirm = Read-Host "Type the client's exact name to confirm permanent deletion: '$($picked.Name)'"
    if ($confirm -ne $picked.Name) { Write-Host "Name did not match - cancelled." -ForegroundColor Gray; return }

    $result = Remove-NPSClient -Path $IASConfigPath -Name $picked.Name
    Write-Host "Deleted '$($picked.Name)'." -ForegroundColor Green
    Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
function Invoke-AddSharedSecretTemplate {
    param([Parameter(Mandatory)][string]$TemplatesPath)

    Write-NPSHeader "Add Shared Secret Template"
    $name = Read-Host "Template name (e.g. 'SC-FortiGate-Secret')"
    while ([string]::IsNullOrWhiteSpace($name)) { $name = Read-Host "A name is required" }

    $secret = Read-NPSSharedSecret -Prompt "Shared secret value"
    while ([string]::IsNullOrWhiteSpace($secret)) { $secret = Read-NPSSharedSecret -Prompt "A shared secret is required" }

    try {
        $result = New-NPSSharedSecretTemplate -Path $TemplatesPath -Name $name -SharedSecret $secret
        Write-Host "Added '$name'." -ForegroundColor Green
        Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
function Invoke-EditSharedSecretTemplate {
    param([Parameter(Mandatory)][string]$TemplatesPath, [Parameter(Mandatory)][string]$IASConfigPath)

    Write-NPSHeader "Edit Shared Secret Template"
    $templates = Get-NPSSharedSecretTemplates -Path $TemplatesPath
    $picked = Select-NPSTemplateFromList -Templates $templates -Prompt "Select a template to edit, by number"
    if (-not $picked) { return }

    Write-Host "This CASCADES to every linked RADIUS Client Template and every linked live Client -" -ForegroundColor Yellow
    Write-Host "matching the NPS console's own behavior, not just this one template record." -ForegroundColor Yellow
    $reveal = Read-Host "Reveal current secret first? (Y/N)"
    if ($reveal -match '^[Yy]') { Write-Host "Current secret: $($picked.SharedSecret)" -ForegroundColor Yellow }

    $newSecret = Read-NPSSharedSecret -Prompt "New shared secret [blank to cancel]"
    if ([string]::IsNullOrWhiteSpace($newSecret)) { Write-Host "Cancelled." -ForegroundColor Gray; return }

    try {
        $result = Set-NPSSharedSecretTemplateValue -TemplateName $picked.Name -NewSecret $newSecret -Path $TemplatesPath -IASConfigPath $IASConfigPath
        if ($result.Changed) {
            Write-Host "Template '$($picked.Name)' updated." -ForegroundColor Green
            Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
            if ($result.CascadedClientTemplateNames.Count -gt 0) {
                Write-Host "Also updated RADIUS Client Template(s): $($result.CascadedClientTemplateNames -join ', ')" -ForegroundColor Green
            }
            if ($result.CascadedClientNames.Count -gt 0) {
                Write-Host "Also updated live client(s): $($result.CascadedClientNames -join ', ')" -ForegroundColor Green
                Write-Host "Backup: $($result.IASBackupPath)" -ForegroundColor Green
            }
        } else {
            Write-Host "No change needed - value was already what was asked for." -ForegroundColor Gray
        }
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
function Invoke-DeleteSharedSecretTemplate {
    param([Parameter(Mandatory)][string]$TemplatesPath, [Parameter(Mandatory)][string]$IASConfigPath)

    Write-NPSHeader "Delete Shared Secret Template"
    $templates = Get-NPSSharedSecretTemplates -Path $TemplatesPath
    $picked = Select-NPSTemplateFromList -Templates $templates -Prompt "Select a template to DELETE, by number"
    if (-not $picked) { return }

    try {
        $usage = Get-NPSSharedSecretTemplateUsage -TemplateName $picked.Name -TemplatesPath $TemplatesPath -IASConfigPath $IASConfigPath
        if ($usage.LinkedClientTemplates.Count -gt 0 -or $usage.LinkedClients.Count -gt 0) {
            Write-Host "WARNING: this template is still referenced by:" -ForegroundColor Yellow
            if ($usage.LinkedClientTemplates.Count -gt 0) { Write-Host "  RADIUS Client Template(s): $($usage.LinkedClientTemplates -join ', ')" -ForegroundColor Yellow }
            if ($usage.LinkedClients.Count -gt 0) { Write-Host "  Live Client(s): $($usage.LinkedClients -join ', ')" -ForegroundColor Yellow }
            Write-Host "Deleting does NOT update those - they'll keep a reference to a template that no longer exists." -ForegroundColor Yellow
        }
    } catch {}

    $confirm = Read-Host "Type the template's exact name to confirm permanent deletion: '$($picked.Name)'"
    if ($confirm -ne $picked.Name) { Write-Host "Name did not match - cancelled." -ForegroundColor Gray; return }

    $result = Remove-NPSSharedSecretTemplate -Path $TemplatesPath -Name $picked.Name
    Write-Host "Deleted '$($picked.Name)'." -ForegroundColor Green
    Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
function Invoke-AddClientTemplate {
    param([Parameter(Mandatory)][string]$TemplatesPath)

    Write-NPSHeader "Add RADIUS Client Template"
    $name = Read-Host "Template name (e.g. 'SC-FortiGate')"
    while ([string]::IsNullOrWhiteSpace($name)) { $name = Read-Host "A name is required" }

    $ip = Read-Host "IP address (used when a client is provisioned from this template without an override)"
    while ([string]::IsNullOrWhiteSpace($ip)) { $ip = Read-Host "An IP address is required" }

    $sstNames = @(Get-NPSSharedSecretTemplates -Path $TemplatesPath | Select-Object -ExpandProperty Name)
    $sstLink = $null
    if ($sstNames.Count -gt 0) {
        Write-Host "Existing Shared Secret Templates: $($sstNames -join ', ')" -ForegroundColor Gray
        $sstInput = Read-Host "Link to one of these by name for the secret [Enter to type a literal secret instead]"
        if ($sstInput -and ($sstNames -contains $sstInput)) { $sstLink = $sstInput }
        elseif ($sstInput) { Write-Host "'$sstInput' not found - falling back to a literal secret." -ForegroundColor Yellow }
    }

    $secret = if ($sstLink) {
        (Get-NPSSharedSecretTemplates -Path $TemplatesPath | Where-Object Name -eq $sstLink).SharedSecret
    } else {
        Read-NPSSharedSecret -Prompt "Shared secret value"
    }
    while ([string]::IsNullOrWhiteSpace($secret)) { $secret = Read-NPSSharedSecret -Prompt "A shared secret is required" }

    $enabledInput = Read-Host "Enabled? [Enter for Yes] (Y/N)"
    $enabled = -not ($enabledInput -match '^[Nn]')

    # Defaults to Yes/checked (2026-08-27 per the maintainer: "the default template should include the
    # 'Requires message authenticator' item checked") - matches the NPS console's own "Client must
    # always send the message authenticator in the request" checkbox. Same [Enter for Yes] shape as
    # Enabled just above, so it's visible and still overridable per-template, not a silent default.
    $reqSigInput = Read-Host "Require message authenticator in every request? [Enter for Yes] (Y/N)"
    $requireSig = -not ($reqSigInput -match '^[Nn]')

    try {
        $params = @{ Path = $TemplatesPath; Name = $name; IPAddress = $ip; SharedSecret = $secret; Enabled = $enabled; RequireSignature = $requireSig; TemplatesPath = $TemplatesPath }
        if ($sstLink) { $params['SharedSecretTemplateName'] = $sstLink }
        $result = New-NPSClientTemplate @params
        Write-Host "Added '$name'." -ForegroundColor Green
        Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
function Invoke-EditClientTemplate {
    param([Parameter(Mandatory)][string]$TemplatesPath)

    Write-NPSHeader "Edit RADIUS Client Template"
    $templates = Get-NPSClientTemplates -Path $TemplatesPath
    $picked = Select-NPSClientFromList -Clients $templates -Prompt "Select a template to edit, by number"
    if (-not $picked) { return }

    $linkedName = Resolve-NPSSharedSecretTemplateName -Guid $picked.ClientSecretTemplateGuid -TemplatesPath $TemplatesPath
    $secretLine = if ($linkedName) { "current: hidden - linked to Shared Secret Template '$linkedName'" } else { "current: hidden - select to reveal or change" }

    Write-Host ""
    Write-Host "Editing '$($picked.Name)':" -ForegroundColor Cyan
    Write-Host "  I. IP Address        (current: $($picked.IPAddress))"
    Write-Host "  S. Shared Secret     ($secretLine)"
    Write-Host "  E. Enabled           (current: $($picked.Enabled))"
    Write-Host "  R. Require Signature (current: $($picked.RequireSignature))"
    Write-Host "  M. Back"
    $attrChoice = Read-Host "Select an attribute to change"

    $result = $null
    switch -Regex ($attrChoice) {
        '^[Ii]$' {
            $newIp = Read-Host "New IP address [Enter to cancel]"
            if ([string]::IsNullOrWhiteSpace($newIp)) { Write-Host "Cancelled." -ForegroundColor Gray; return }
            $result = Set-NPSClientTemplateAttribute -Path $TemplatesPath -Name $picked.Name -Attribute IPAddress -Value $newIp
        }
        '^[Ss]$' {
            $reveal = Read-Host "Reveal current secret first? (Y/N)"
            if ($reveal -match '^[Yy]') { Write-Host "Current secret: $($picked.SharedSecret)" -ForegroundColor Yellow }
            if ($linkedName) {
                Write-Host "Editing this directly BREAKS its link to Shared Secret Template '$linkedName'." -ForegroundColor Yellow
                Write-Host "To change the value for every linked record instead, edit the Shared Secret Template itself." -ForegroundColor Yellow
            }
            $newSecret = Read-NPSSharedSecret -Prompt "New shared secret [blank to cancel]"
            if ([string]::IsNullOrWhiteSpace($newSecret)) { Write-Host "Cancelled." -ForegroundColor Gray; return }
            $result = Set-NPSClientTemplateAttribute -Path $TemplatesPath -Name $picked.Name -Attribute SharedSecret -Value $newSecret
            if ($result.Decoupled) {
                Write-Host "Note: '$($picked.Name)' is no longer linked to '$linkedName' - its secret is now independent." -ForegroundColor Yellow
            }
        }
        '^[Ee]$' {
            $newEnabled = -not $picked.Enabled
            $confirm = Read-Host "Set Enabled to ${newEnabled}? (Y/N)"
            if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled." -ForegroundColor Gray; return }
            $result = Set-NPSClientTemplateAttribute -Path $TemplatesPath -Name $picked.Name -Attribute Enabled -Value $newEnabled
        }
        '^[Rr]$' {
            $newRequireSig = -not $picked.RequireSignature
            $confirm = Read-Host "Set Require Signature to ${newRequireSig}? (Y/N)"
            if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled." -ForegroundColor Gray; return }
            $result = Set-NPSClientTemplateAttribute -Path $TemplatesPath -Name $picked.Name -Attribute RequireSignature -Value $newRequireSig
        }
        default { Write-Host "Cancelled." -ForegroundColor Gray; return }
    }

    if ($result.Changed) {
        Write-Host "Updated." -ForegroundColor Green
        Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
    } else {
        Write-Host "No change needed - value was already what was asked for." -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
function Invoke-DeleteClientTemplate {
    param([Parameter(Mandatory)][string]$TemplatesPath, [Parameter(Mandatory)][string]$IASConfigPath)

    Write-NPSHeader "Delete RADIUS Client Template"
    $templates = Get-NPSClientTemplates -Path $TemplatesPath
    $picked = Select-NPSClientFromList -Clients $templates -Prompt "Select a template to DELETE, by number"
    if (-not $picked) { return }

    try {
        $usage = Get-NPSClientTemplateUsage -TemplateName $picked.Name -TemplatesPath $TemplatesPath -IASConfigPath $IASConfigPath
        if ($usage.LinkedClients.Count -gt 0) {
            Write-Host "WARNING: live client(s) were created from this template: $($usage.LinkedClients -join ', ')" -ForegroundColor Yellow
            Write-Host "Deleting does NOT update those - they'll keep a reference to a template that no longer exists." -ForegroundColor Yellow
        }
    } catch {}

    $confirm = Read-Host "Type the template's exact name to confirm permanent deletion: '$($picked.Name)'"
    if ($confirm -ne $picked.Name) { Write-Host "Name did not match - cancelled." -ForegroundColor Gray; return }

    $result = Remove-NPSClientTemplate -Path $TemplatesPath -Name $picked.Name
    Write-Host "Deleted '$($picked.Name)'." -ForegroundColor Green
    Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
function Invoke-AddClientFromTemplate {
    param([Parameter(Mandatory)][string]$IASConfigPath, [Parameter(Mandatory)][string]$TemplatesPath)

    Write-NPSHeader "Add a RADIUS Client From a Template"
    $templates = Get-NPSClientTemplates -Path $TemplatesPath
    $picked = Select-NPSClientFromList -Clients $templates -Prompt "Select a RADIUS Client Template to provision from, by number"
    if (-not $picked) { return }

    $name = Read-Host "New client's name"
    while ([string]::IsNullOrWhiteSpace($name)) { $name = Read-Host "A name is required" }

    $ip = Read-Host "New client's IP address [Enter to use the template's own IP, $($picked.IPAddress)]"

    try {
        $params = @{ Path = $IASConfigPath; ClientTemplateName = $picked.Name; NewClientName = $name; TemplatesPath = $TemplatesPath }
        if (-not [string]::IsNullOrWhiteSpace($ip)) { $params['IPAddress'] = $ip }
        $result = Add-NPSClientFromTemplate @params
        Write-Host "Added '$name', provisioned from template '$($picked.Name)'." -ForegroundColor Green
        Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
function Invoke-ManageNPSClientsMenu {
    <#
    .SYNOPSIS
        Option 4 - one-stop management for RADIUS Clients AND both template types (Shared Secret
        Templates, RADIUS Client Templates), plus the "assignment" workflow (provisioning a new live
        Client directly from an existing RADIUS Client Template). Originally two separate screens (a
        plain client list here, with a "T" hop to a richer templates-plus-duplicated-client-CRUD
        screen) - consolidated into this single screen per the maintainer's request, since the old split just
        meant the SAME client Add/Edit/Delete existed in two places and a tech had to guess which one
        to use to see template linkage.

    .DESCRIPTION
        The three-column overview (Clients / RADIUS Client Templates / Shared Secret Templates) shows
        each item's link to the next level up (Resolve-NPSClientTemplateName /
        Resolve-NPSSharedSecretTemplateName) and flags templates NOTHING currently references
        ([UNUSED] - via Get-NPSClientTemplateUsage / Get-NPSSharedSecretTemplateUsage) - the same
        "what's linked to this" question those two functions already answer before a delete, surfaced
        proactively here instead of only at delete-confirmation time.
    #>
    param([Parameter(Mandatory)][string]$IASConfigPath)
    $templatesPath = Get-NPSTemplatesPathFor -IASConfigPath $IASConfigPath

    :ClientsMenu while ($true) {
        Write-NPSHeader "Manage NPS Clients & Templates"

        $clients = @()
        $sst = @()
        $rct = @()
        try { $clients = Get-NPSClients -Path $IASConfigPath } catch {}
        try { $sst = Get-NPSSharedSecretTemplates -Path $templatesPath } catch {}
        try { $rct = Get-NPSClientTemplates -Path $templatesPath } catch {}

        # Stacked (one section per row) layout, not side-by-side columns - per the maintainer, easier to read
        # than the old 3-column table once names/IPs run long. Each section: name/IP, [DISABLED] if
        # applicable, then its link to the next level up quoted and labeled (e.g. "-> 'X' (Client
        # Template)") so it's unambiguous which kind of thing it's pointing at.

        # --- Section 1: live Clients, each showing which RADIUS Client Template (if any) it was
        # provisioned from. ---
        Write-Host "Current RADIUS Clients:" -ForegroundColor Cyan
        if ($clients.Count -eq 0) {
            Write-Host "   (none)"
        } else {
            foreach ($c in $clients) {
                $line = "   {0}  ({1})" -f $c.Name, $c.IPAddress
                if (-not $c.Enabled) { $line += "  [DISABLED]" }
                $tplName = Resolve-NPSClientTemplateName -Guid $c.ClientTemplateGuid -TemplatesPath $templatesPath
                if ($tplName) { $line += "  -> '$tplName' (Client Template)" }
                Write-Host $line
            }
        }

        Write-Host ""
        Write-Host "RADIUS Client Templates:" -ForegroundColor Cyan
        if ($rct.Count -eq 0) {
            Write-Host "   (none)"
        } else {
            foreach ($t in $rct) {
                $line = "   {0}  ({1})" -f $t.Name, $t.IPAddress
                if (-not $t.Enabled) { $line += "  [DISABLED]" }
                $sstName = Resolve-NPSSharedSecretTemplateName -Guid $t.ClientSecretTemplateGuid -TemplatesPath $templatesPath
                $line += if ($sstName) { "  -> '$sstName' (Secret Template)" } else { "  (literal secret, no template link)" }
                try {
                    $rctUsage = Get-NPSClientTemplateUsage -TemplateName $t.Name -TemplatesPath $templatesPath -IASConfigPath $IASConfigPath
                    if ($rctUsage.LinkedClients.Count -eq 0) { $line += "  [UNUSED]" }
                } catch {}
                Write-Host $line
            }
        }

        Write-Host ""
        Write-Host "Shared Secret Templates:" -ForegroundColor Cyan
        if ($sst.Count -eq 0) {
            Write-Host "   (none)"
        } else {
            foreach ($s in $sst) {
                $line = "   $($s.Name)"
                try {
                    $sstUsage = Get-NPSSharedSecretTemplateUsage -TemplateName $s.Name -TemplatesPath $templatesPath -IASConfigPath $IASConfigPath
                    if ($sstUsage.LinkedClientTemplates.Count -eq 0 -and $sstUsage.LinkedClients.Count -eq 0) { $line += "  [UNUSED]" }
                } catch {}
                Write-Host $line
            }
        }

        # Menu sections ordered to match the table above (RADIUS Clients / RADIUS Client Templates /
        # Shared Secret Templates, left to right) - was reversed before (Secret Templates listed
        # first), which didn't match what a tech was just looking at above it.
        Write-Host ""
        Write-Host "RADIUS Clients" -ForegroundColor Cyan
        Write-Host "  1. Add a RADIUS Client from a template"
        Write-Host "  2. Add a RADIUS Client WITHOUT a template"
        Write-Host "  3. Edit a client's attributes"
        Write-Host "  4. Delete a client"
        Write-Host ""
        Write-Host "RADIUS Client Templates" -ForegroundColor Cyan
        Write-Host "  5. Add"
        Write-Host "  6. Edit"
        Write-Host "  7. Delete"
        Write-Host ""
        Write-Host "Shared Secret Templates:" -ForegroundColor Cyan
        Write-Host "  8. Add"
        Write-Host "  9. Edit (cascades to linked Client Templates/Clients)"
        Write-Host "  10. Delete"
        Write-Host ""
        Write-Host "  M. Return to main menu"
        Write-Host ""
        $choice = Read-Host "Select an option"

        switch -Regex ($choice) {
            '^1$'  { Invoke-AddClientFromTemplate -IASConfigPath $IASConfigPath -TemplatesPath $templatesPath; Read-Host "`nPress Enter to continue" }
            '^2$'  { Invoke-AddClient -IASConfigPath $IASConfigPath; Read-Host "`nPress Enter to continue" }
            '^3$'  { Invoke-EditClient -IASConfigPath $IASConfigPath; Read-Host "`nPress Enter to continue" }
            '^4$'  { Invoke-DeleteClient -IASConfigPath $IASConfigPath; Read-Host "`nPress Enter to continue" }
            '^5$'  { Invoke-AddClientTemplate -TemplatesPath $templatesPath; Read-Host "`nPress Enter to continue" }
            '^6$'  { Invoke-EditClientTemplate -TemplatesPath $templatesPath; Read-Host "`nPress Enter to continue" }
            '^7$'  { Invoke-DeleteClientTemplate -TemplatesPath $templatesPath -IASConfigPath $IASConfigPath; Read-Host "`nPress Enter to continue" }
            '^8$'  { Invoke-AddSharedSecretTemplate -TemplatesPath $templatesPath; Read-Host "`nPress Enter to continue" }
            '^9$'  { Invoke-EditSharedSecretTemplate -TemplatesPath $templatesPath -IASConfigPath $IASConfigPath; Read-Host "`nPress Enter to continue" }
            '^10$' { Invoke-DeleteSharedSecretTemplate -TemplatesPath $templatesPath -IASConfigPath $IASConfigPath; Read-Host "`nPress Enter to continue" }
            '^[Mm]$' { return }
            default  { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
function Select-NPSPolicyFromSummary {
    param(
        [Parameter(Mandatory)][array]$Summary,
        [string]$Prompt = "Select a rule by number"
    )
    if ($Summary.Count -eq 0) { Write-Host "No rules to select from." -ForegroundColor Yellow; return $null }
    for ($i = 0; $i -lt $Summary.Count; $i++) {
        $p = $Summary[$i]
        $stateTag = if ($p.Enabled) { '' } else { ' [DISABLED]' }
        Write-Host ("    {0}. [seq {1}] {2}{3}" -f ($i + 1), $p.Sequence, $p.Name, $stateTag)
    }
    $sel = Read-Host $Prompt
    $idx = ($sel -as [int]) - 1
    if ($idx -ge 0 -and $idx -lt $Summary.Count) { return $Summary[$idx] }
    Write-Host "Invalid selection." -ForegroundColor Yellow
    return $null
}

# ---------------------------------------------------------------------------
function Invoke-ReorderRule {
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType
    )

    do {
        Write-NPSHeader "Reorder Rule"
        $summary = Get-NPSPolicySummary -Path $IASConfigPath -PolicyType $PolicyType
        $picked = Select-NPSPolicyFromSummary -Summary $summary -Prompt "Select the rule to move, by number"
        if (-not $picked) { return }

        $dirInput = Read-Host "Move [U]p or [D]own"
        $direction = if ($dirInput -match '^[Uu]') { 'Up' } elseif ($dirInput -match '^[Dd]') { 'Down' } else { $null }
        if (-not $direction) { Write-Host "Cancelled." -ForegroundColor Gray; return }

        $stepsInput = Read-Host "How many positions? [Enter for 1]"
        $steps = if ([string]::IsNullOrWhiteSpace($stepsInput)) { 1 } else { [int]$stepsInput }

        $result = Move-NPSPolicy -Path $IASConfigPath -PolicyName $picked.Name -Direction $direction -Steps $steps -PolicyType $PolicyType
        Write-Host "Moved '$($picked.Name)' $direction by $($result.StepsTaken) step(s)." -ForegroundColor Green
        Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green

        $again = Read-Host "Move another rule? (Y/N)"
    } while ($again -match '^[Yy]')
}

# ---------------------------------------------------------------------------
function Invoke-ToggleRuleEnabled {
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType
    )

    Write-NPSHeader "Deactivate / Reactivate Rule"
    $summary = Get-NPSPolicySummary -Path $IASConfigPath -PolicyType $PolicyType
    $picked = Select-NPSPolicyFromSummary -Summary $summary -Prompt "Select a rule to toggle, by number"
    if (-not $picked) { return }

    $newState = -not $picked.Enabled
    $verb = if ($newState) { 'reactivate' } else { 'deactivate' }
    $currentState = if ($picked.Enabled) { 'ENABLED' } else { 'DISABLED' }
    $confirm = Read-Host "'$($picked.Name)' is currently $currentState - $verb it? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled." -ForegroundColor Gray; return }

    $result = Set-NPSPolicyEnabled -Path $IASConfigPath -PolicyName $picked.Name -Enabled $newState -PolicyType $PolicyType
    Write-Host "'$($picked.Name)' is now $(if ($newState) { 'ENABLED' } else { 'DISABLED' })." -ForegroundColor Green
    Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
function Invoke-DeleteRule {
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType
    )

    Write-NPSHeader "Delete Rule"
    if ($PolicyType -eq 'NetworkPolicy') {
        Write-Host "This permanently removes the rule AND its matching RADIUS profile - not reversible" -ForegroundColor Yellow
        Write-Host "except by restoring the backup this creates." -ForegroundColor Yellow
    } else {
        Write-Host "This permanently removes the Connection Request Policy - not reversible except by" -ForegroundColor Yellow
        Write-Host "restoring the backup this creates." -ForegroundColor Yellow
    }
    $summary = Get-NPSPolicySummary -Path $IASConfigPath -PolicyType $PolicyType
    $picked = Select-NPSPolicyFromSummary -Summary $summary -Prompt "Select a rule to DELETE, by number"
    if (-not $picked) { return }

    # Confirm by the SAME list number the tech just typed to pick it (not the internal [seq N] value
    # shown alongside it - that's a different number and not what they'd have front-of-mind here) -
    # per the maintainer's request, "type 'del x'" instead of the rule's exact name.
    $displayNum = [array]::IndexOf($summary, $picked) + 1
    $expectedConfirm = "del $displayNum"
    $confirm = Read-Host "Type '$expectedConfirm' to confirm permanent deletion of rule $displayNum ('$($picked.Name)')"
    if ($confirm -ne $expectedConfirm) { Write-Host "Confirmation did not match - cancelled." -ForegroundColor Gray; return }

    $result = Remove-NPSPolicy -Path $IASConfigPath -PolicyName $picked.Name -PolicyType $PolicyType
    Write-Host "Deleted '$($picked.Name)'." -ForegroundColor Green
    Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
function Invoke-ManageNetworkPoliciesMenu {
    <#
    .SYNOPSIS
        Full add/reorder/deactivate/delete menu for Network Policies (access/authorization - WHO gets
        in and WHAT they receive). Body is the former Invoke-ManageNPSRulesMenu, unchanged apart from
        now explicitly passing -PolicyType NetworkPolicy through every call - see
        Invoke-ManageConnectionRequestPoliciesMenu for the CRP counterpart, and Invoke-ManageNPSRulesMenu
        for the parent dispatcher between the two.
    #>
    param([Parameter(Mandatory)][string]$IASConfigPath, [string]$ADServer, [string]$ShimPath, [System.Management.Automation.PSCredential]$ADCredential)

    :RulesMenu while ($true) {
        Write-NPSHeader "Manage Network Policies"
        $summary = @()
        try {
            $summary = Get-NPSPolicySummary -Path $IASConfigPath -PolicyType NetworkPolicy
        } catch {
            Write-Host "Could not read policies from $IASConfigPath - $($_.Exception.Message)" -ForegroundColor Red
            Read-Host "Press Enter to return to the main menu"
            return
        }

        if ($summary.Count -eq 0) {
            Write-Host "No real Network Policies found yet." -ForegroundColor Gray
        } else {
            Write-Host "Current Network Policies (evaluated top to bottom, first match wins):" -ForegroundColor Cyan
            foreach ($p in $summary) {
                $stateTag = if ($p.Enabled) { '' } else { ' [DISABLED]' }
                Write-Host ("    {0,3}. {1}{2}" -f $p.Sequence, $p.Name, $stateTag)
            }
        }
        Write-Host ""
        Write-Host "  A. Add a rule (single, or IPSec/SSLVPN/Both triplicate)"
        Write-Host "  E. Edit conditions for a rule"
        Write-Host "  O. Reorder a rule (move up/down)"
        Write-Host "  D. Deactivate/reactivate a rule"
        Write-Host "  X. Delete a rule"
        Write-Host "  R. Re-process VSAs for a rule (refresh nested AD group membership)"
        Write-Host "  M. Return to main menu"
        Write-Host ""
        $choice = Read-Host "Select an option"

        switch -Regex ($choice) {
            '^[Aa]$' { Invoke-AddNPSRuleWizard -IASConfigPath $IASConfigPath -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath }
            '^[Ee]$' { Invoke-EditNPSPolicyConditions -IASConfigPath $IASConfigPath -PolicyType NetworkPolicy -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath }
            '^[Oo]$' { Invoke-ReorderRule -IASConfigPath $IASConfigPath -PolicyType NetworkPolicy }
            '^[Dd]$' { Invoke-ToggleRuleEnabled -IASConfigPath $IASConfigPath -PolicyType NetworkPolicy }
            '^[Xx]$' { Invoke-DeleteRule -IASConfigPath $IASConfigPath -PolicyType NetworkPolicy }
            '^[Rr]$' { Invoke-ReprocessNPSVsaWizard -IASConfigPath $IASConfigPath -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath }
            '^[Mm]$' { return }
            default  { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
function Invoke-ManageConnectionRequestPoliciesMenu {
    <#
    .SYNOPSIS
        Full add/reorder/deactivate/delete menu for Connection Request Policies (routing - WHERE/HOW
        a request gets authenticated) - structurally identical to Invoke-ManageNetworkPoliciesMenu,
        just against -PolicyType ConnectionRequest throughout, and "A. Add" uses the CRP-specific
        wizard (freeform conditions, no VSA/profile step) instead.
    #>
    param([Parameter(Mandatory)][string]$IASConfigPath, [string]$ADServer, [string]$ShimPath, [System.Management.Automation.PSCredential]$ADCredential)

    :RulesMenu while ($true) {
        Write-NPSHeader "Manage Connection Request Policies"
        $summary = @()
        try {
            $summary = Get-NPSPolicySummary -Path $IASConfigPath -PolicyType ConnectionRequest
        } catch {
            Write-Host "Could not read policies from $IASConfigPath - $($_.Exception.Message)" -ForegroundColor Red
            Read-Host "Press Enter to return to the main menu"
            return
        }

        if ($summary.Count -eq 0) {
            Write-Host "No real Connection Request Policies found yet." -ForegroundColor Gray
        } else {
            Write-Host "Current Connection Request Policies (evaluated top to bottom, first match wins):" -ForegroundColor Cyan
            foreach ($p in $summary) {
                $stateTag = if ($p.Enabled) { '' } else { ' [DISABLED]' }
                Write-Host ("    {0,3}. {1}{2}" -f $p.Sequence, $p.Name, $stateTag)
            }
        }
        Write-Host ""
        Write-Host "  A. Add a policy"
        Write-Host "  E. Edit conditions for a policy"
        Write-Host "  O. Reorder a policy (move up/down)"
        Write-Host "  D. Deactivate/reactivate a policy"
        Write-Host "  X. Delete a policy"
        Write-Host "  M. Return to main menu"
        Write-Host ""
        $choice = Read-Host "Select an option"

        switch -Regex ($choice) {
            '^[Aa]$' { Invoke-AddNPSConnectionRequestPolicyWizard -IASConfigPath $IASConfigPath -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath }
            '^[Ee]$' { Invoke-EditNPSPolicyConditions -IASConfigPath $IASConfigPath -PolicyType ConnectionRequest -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath }
            '^[Oo]$' { Invoke-ReorderRule -IASConfigPath $IASConfigPath -PolicyType ConnectionRequest }
            '^[Dd]$' { Invoke-ToggleRuleEnabled -IASConfigPath $IASConfigPath -PolicyType ConnectionRequest }
            '^[Xx]$' { Invoke-DeleteRule -IASConfigPath $IASConfigPath -PolicyType ConnectionRequest }
            '^[Mm]$' { return }
            default  { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
function Invoke-ManageNPSRulesMenu {
    <#
    .SYNOPSIS
        Option 5's parent dispatcher - the explicit, unmistakable differentiation point between the
        two entirely separate policy universes ias.xml holds (see module NOTES): Network Policies
        (access/authorization) vs. Connection Request Policies (routing - where/how to authenticate).
        Never an ambiguous shared list - the tech always picks which universe they're editing first.
    #>
    param([Parameter(Mandatory)][string]$IASConfigPath, [string]$ADServer, [string]$ShimPath, [System.Management.Automation.PSCredential]$ADCredential)

    :PolicyTypeMenu while ($true) {
        Write-NPSHeader "Manage NPS Policies"
        # Connection Request Policies listed above Network Policies - mirrors the native NPS console's
        # own tree layout (per the maintainer).
        Write-Host "  C. Connection Request Policies - routing: WHERE/HOW a request gets authenticated"
        Write-Host "  N. Network Policies       - access/authorization: WHO gets in, WHAT they receive (VSAs)"
        Write-Host "  M. Return to main menu"
        Write-Host ""
        $choice = Read-Host "Select an option"

        switch -Regex ($choice) {
            '^[Nn]$' { Invoke-ManageNetworkPoliciesMenu -IASConfigPath $IASConfigPath -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath }
            '^[Cc]$' { Invoke-ManageConnectionRequestPoliciesMenu -IASConfigPath $IASConfigPath -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath }
            '^[Mm]$' { return }
            default  { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
function Invoke-TroubleshootingAction {
    <#
    .SYNOPSIS
        The actual work behind every troubleshooting-menu action, keyed by a stable semantic
        -ActionId (not a raw menu number) - 2026-09-03, per the maintainer: "streamline the NPS Manager
        troubleshooting screen... add a service restart option to it." Extracted out of what used to
        be ONE big numbered switch inside a single flat menu function, so the SAME action bodies can be
        called from two independently-numbered menu presentations (Invoke-TroubleshootingMenu's flat,
        all-categories list from the dashboard's bare "6"; Invoke-TroubleshootingCategoryMenu's single-
        category view from "6a"-"6e", directly reachable from the dashboard itself - see
        Show-TroubleshootingCategoryLinks) without duplicating any of this logic - "no duplicate
        embedded functions" is the whole reason this got pulled out, not just renumbered in place.

    .DESCRIPTION
        Every case body here is otherwise UNCHANGED from the original flat menu's own numbered switch -
        this is a mechanical extraction (numeric '^N$' patterns -> semantic ActionId string matches),
        not a rewrite of what any of them actually do. 'RestartService' and 'ForceIASConfigWrite' are
        the two genuinely NEW cases added since the extraction (both Modules\NPSTroubleshooting.ps1 -
        Invoke-NPSServiceRestartAction and Invoke-IASConfigBootstrapPrompt respectively), the latter
        being the item 7 "ias.xml chicken/egg, take 2" shortcut, same 2026-09-03 punch list.
    #>
    param(
        [Parameter(Mandatory)][string]$ActionId,
        [string]$IASConfigPath,
        [string]$ADServer,
        [string]$ShimPath,
        [System.Management.Automation.PSCredential]$ADCredential,
        [string]$ADUsername
    )

    switch ($ActionId) {
        'MFATroubleshooter' { Invoke-DownloadAndReviewMFATroubleshooter; Read-Host "`nPress Enter to continue" }
        'ToggleExtension' { Invoke-ToggleNPSExtensionRegistry; Read-Host "`nPress Enter to continue" }
        'ReadLogs' { Invoke-ReadRadiusLogsMenu -IASConfigPath $IASConfigPath }
        'RestartService' {
            Write-NPSHeader "Restart Network Policy Server Service"
            Invoke-NPSServiceRestartAction
            Read-Host "`nPress Enter to continue"
        }
        'ForceIASConfigWrite' {
            Write-NPSHeader "Force Initial ias.xml Write"
            Invoke-IASConfigBootstrapPrompt -IASConfigPath $IASConfigPath
            Read-Host "`nPress Enter to continue"
        }
        'PrereqCheck' {
            Write-NPSHeader "NPS Extension Prerequisite Check"
            Show-NPSExtensionPrereqCheck
            Read-Host "`nPress Enter to continue"
        }
        'RSAT' {
            Write-NPSHeader "RSAT (ActiveDirectory Module)"
            $available = Test-RSATAvailable
            Write-Host "Current status: $(if ($available) { 'Installed' } else { 'Not installed' })" -ForegroundColor $(if ($available) { 'Green' } else { 'Yellow' })
            Write-Host ""
            if ($available) {
                $action = Read-Host "U to uninstall it, or Enter to go back"
                if ($action -match '^[Uu]$') { Uninstall-RSATActiveDirectoryModule | Out-Null }
            } else {
                $action = Read-Host "I to install it, or Enter to go back"
                if ($action -match '^[Ii]$') { Install-RSATActiveDirectoryModule | Out-Null }
            }
            Read-Host "`nPress Enter to continue"
        }
        'ADConnectivity' {
            Write-NPSHeader "Test AD Connectivity"
            try {
                $regResult = Test-NPSServerRegistered -Server $ADServer -Credential $ADCredential -Force
                $regLabel = if ($regResult) { 'registered' } else { 'NOT registered' }
                Write-Host "AD check succeeded - this server is $regLabel in AD ('RAS and IAS Servers')." -ForegroundColor $(if ($regResult) { 'Green' } else { 'Yellow' })
            } catch {
                Write-Host "AD check failed - $($_.Exception.Message)" -ForegroundColor Red
                $fallback = Invoke-NPSADFallbackPrompt -ShimPath $ShimPath -ADUsername $ADUsername
                if ($fallback) {
                    # Applies for the rest of THIS session too - see Invoke-InstallAuthorizeNPS's
                    # identical use of this same fallback for why.
                    $script:ADServer = $fallback.DCServer
                    $script:ADCredential = $fallback.Credential
                    if ($fallback.Username) { $script:ADUsername = $fallback.Username }
                    Write-Host "Now using '$($fallback.DCServer)' for AD checks for the rest of this session." -ForegroundColor Green
                }
            }
            Read-Host "`nPress Enter to continue"
        }
        'BackupIAS' {
            Write-NPSHeader "Back Up ias.xml"
            if (-not (Test-Path $IASConfigPath)) {
                Write-Host "ias.xml not found at $IASConfigPath - nothing to back up." -ForegroundColor Red
            } else {
                try {
                    $backupPath = Backup-NPSConfig -Path $IASConfigPath
                    Write-Host "Backed up to: $backupPath" -ForegroundColor Green
                } catch {
                    Write-Host "Backup failed - $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            Read-Host "`nPress Enter to continue"
        }
        'RestoreIAS' {
            Write-NPSHeader "Restore ias.xml From a Backup"
            if (-not (Test-Path $IASConfigPath)) {
                Write-Host "ias.xml not found at $IASConfigPath." -ForegroundColor Red
            } else {
                $backups = Get-NPSConfigBackups -Path $IASConfigPath
                if ($backups.Count -eq 0) {
                    Write-Host "No backups found next to $IASConfigPath." -ForegroundColor Yellow
                } else {
                    $showCount = [Math]::Min(15, $backups.Count)
                    $moreNote = if ($backups.Count -gt $showCount) { " (showing $showCount of $($backups.Count), newest first)" } else { " (newest first)" }
                    Write-Host "Most recent backups$moreNote`:" -ForegroundColor Cyan
                    for ($i = 0; $i -lt $showCount; $i++) {
                        Write-Host ("    {0}. {1}  ({2:yyyy-MM-dd HH:mm:ss})" -f ($i + 1), $backups[$i].Name, $backups[$i].LastWriteTime)
                    }
                    $sel = Read-Host "Pick a backup by number to restore, or Enter to cancel"
                    $idx = ($sel -as [int]) - 1
                    if ($idx -ge 0 -and $idx -lt $showCount) {
                        $picked = $backups[$idx]
                        Write-Host ""
                        Write-Host "This will OVERWRITE the live ias.xml with '$($picked.Name)'." -ForegroundColor Yellow
                        Write-Host "(the current live config is backed up first too - this itself is undoable)" -ForegroundColor Gray
                        $confirm = Read-Host "Type RESTORE to confirm"
                        if ($confirm -eq 'RESTORE') {
                            try {
                                $result = Restore-NPSConfigFromBackup -Path $IASConfigPath -BackupPath $picked.FullName
                                Write-Host "Restored from $($result.RestoredFrom)." -ForegroundColor Green
                                if ($result.PreRestoreBackup) { Write-Host "Pre-restore state backed up to: $($result.PreRestoreBackup)" -ForegroundColor Green }
                            } catch {
                                Write-Host "Restore failed - $($_.Exception.Message)" -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Cancelled." -ForegroundColor Gray
                        }
                    } else {
                        Write-Host "Cancelled." -ForegroundColor Gray
                    }
                }
            }
            Read-Host "`nPress Enter to continue"
        }
        'ConfigSummary' {
            Write-NPSHeader "Full Config Summary"
            if (-not (Test-Path $IASConfigPath)) {
                Write-Host "ias.xml not found at $IASConfigPath." -ForegroundColor Red
            } else {
                Show-NPSConfigSummary -IASConfigPath $IASConfigPath
            }
            Read-Host "`nPress Enter to continue"
        }
        'ADCredsToggle' {
            Write-NPSHeader "Requires Explicit AD Credentials"
            Write-Host "Currently: $(if ($script:RequiresExplicitADCredentials) { 'YES - prompts for a DC + credentials at every launch' } else { 'No - normal auto-discovery first, this fallback only offered on failure' })" -ForegroundColor Cyan
            if (-not $ShimPath -or -not (Test-Path $ShimPath)) {
                Write-Host "Not running from a staged shim (or its path wasn't provided) - can't save this setting." -ForegroundColor Yellow
                Read-Host "`nPress Enter to continue"
            } else {
                $newValue = -not $script:RequiresExplicitADCredentials
                $toggleConfirm = Read-Host "Set to $(if ($newValue) { 'YES' } else { 'No' })? (Y/N)"
                if ($toggleConfirm -match '^[Yy]') {
                    try {
                        Set-NPSShimRequiresExplicitADCredentials -ShimPath $ShimPath -RequiresExplicitCredentials $newValue
                        $script:RequiresExplicitADCredentials = $newValue
                        Write-Host "Saved into the shim at $ShimPath." -ForegroundColor Green
                        if ($newValue) {
                            $promptNow = Read-Host "Run the credential prompt now, so the rest of THIS session benefits too? (Y/N)"
                            if ($promptNow -match '^[Yy]') {
                                $requiredCredsResult = Invoke-NPSRequiredCredentialsPrompt -ADServer $ADServer -ShimPath $ShimPath -ADUsername $ADUsername
                                if ($requiredCredsResult) {
                                    $script:ADServer = $requiredCredsResult.DCServer
                                    $script:ADCredential = $requiredCredsResult.Credential
                                    if ($requiredCredsResult.Username) { $script:ADUsername = $requiredCredsResult.Username }
                                }
                            }
                        } else {
                            Write-Host "Any credential already cached this session is left as-is - future launches just won't prompt proactively." -ForegroundColor Gray
                        }
                    } catch {
                        Write-Host "Could not save into the shim - $($_.Exception.Message)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Cancelled." -ForegroundColor Gray
                }
                Read-Host "`nPress Enter to continue"
            }
        }
        'NTLMv2Check' {
            Write-NPSHeader "Enable NTLMv2 Compatibility"
            Invoke-NPSNtlmv2CompatibilityCheck
            Read-Host "`nPress Enter to continue"
        }
        'TimestampSync' {
            Write-NPSHeader "TemplatesTimestamp Sync Check"
            if (-not (Test-Path $IASConfigPath)) {
                Write-Host "ias.xml not found at $IASConfigPath." -ForegroundColor Red
            } else {
                Invoke-NPSTemplatesTimestampCheck -IASConfigPath $IASConfigPath
            }
            Read-Host "`nPress Enter to continue"
        }
        'StartFailureReport' {
            Write-NPSHeader "Why Won't NPS Start - Report"
            Invoke-NPSServiceStartFailureReport | Out-Null
            Read-Host "`nPress Enter to continue"
        }
        'HardeningReport' {
            Write-NPSHeader "NTLM / Kerberos Hardening Report"
            Show-NPSNtlmKerberosHardeningReport
            Read-Host "`nPress Enter to continue"
        }
        'ClockSkew' {
            Write-NPSHeader "Clock Skew Check"
            Invoke-NPSClockSkewCheck -TargetServer $ADServer
            Read-Host "`nPress Enter to continue"
        }
        'WindowsUpdates' {
            Write-NPSHeader "Recent Windows Updates"
            Invoke-NPSRecentWindowsUpdatesCheck
            Read-Host "`nPress Enter to continue"
        }
        'ServerCerts' {
            Write-NPSHeader "Server Certificates (PEAP / EAP-TLS)"
            Show-NPSServerCertificateReport
            Read-Host "`nPress Enter to continue"
        }
        'AuthCorrelation' {
            Write-NPSHeader "Correlate Auth Failure Across Logs"
            Show-NPSAuthFailureCorrelation -IASConfigPath $IASConfigPath
            Read-Host "`nPress Enter to continue"
        }
        default { Write-Host "Invalid selection." -ForegroundColor Yellow }
    }
}

# Ordered action list shared by BOTH menu presentations - one source of truth for the
# number/label/category/ActionId of every troubleshooting action, so T1's flat numbering and T2's
# per-category numbering can never drift out of sync with each other or with Invoke-TroubleshootingAction
# above. Category "Settings" is a 2026-09-03 fix, not just a rename - the original flat menu filed the
# AD-credentials toggle (ActionId ADCredsToggle) under "Backup / Restore NPS Configuration" purely
# because it happened to print right after option 9, not because it has anything to do with backup/
# restore; it gets its own honest category now that T2 actually groups by category for real.
function Get-NPSTroubleshootingActions {
    return @(
        [pscustomobject]@{ ActionId = 'MFATroubleshooter'; Category = 'Troubleshooters / Debugging'; Label = "Download & run Microsoft's MFA_NPS_Troubleshooter"; Detail = "MFA prompts not reaching users, or auth succeeds on the FortiGate but fails in NPS." }
        [pscustomobject]@{ ActionId = 'ToggleExtension'; Category = 'Troubleshooters / Debugging'; Label = "Temporarily disable/restore the NPS Extension (registry)"; Detail = "Isolate whether the extension itself is the problem." }
        [pscustomobject]@{ ActionId = 'ReadLogs'; Category = 'Troubleshooters / Debugging'; Label = "Read RADIUS logs"; Detail = "See the actual accept/reject reason for a failed login, filterable by user." }
        [pscustomobject]@{ ActionId = 'RestartService'; Category = 'Troubleshooters / Debugging'; Label = "Restart the Network Policy Server service"; Detail = "Common first troubleshooting step - confirmed before acting, never silent." }
        [pscustomobject]@{ ActionId = 'ForceIASConfigWrite'; Category = 'Troubleshooters / Debugging'; Label = "Force the initial ias.xml write"; Detail = "Fresh install has no ias.xml and starting the service alone didn't create it - forces it via netsh nps export instead of needing a GUI edit." }
        [pscustomobject]@{ ActionId = 'PrereqCheck'; Category = 'Prerequisites / Script Troubleshooters'; Label = "Check NPS Extension prerequisites (read-only)"; Detail = "Run before installing/updating the extension if something's not working right." }
        [pscustomobject]@{ ActionId = 'RSAT'; Category = 'Prerequisites / Script Troubleshooters'; Label = "Check / install / uninstall RSAT (ActiveDirectory module)"; Detail = "Use when AD group lookups or the registration check fail with 'module not available'." }
        [pscustomobject]@{ ActionId = 'ADConnectivity'; Category = 'Prerequisites / Script Troubleshooters'; Label = "Test AD connectivity (specific DC + credentials fallback)"; Detail = "Use when the dashboard's own AD check keeps failing on launch." }
        [pscustomobject]@{ ActionId = 'BackupIAS'; Category = 'Backup / Restore NPS Configuration'; Label = "Back up ias.xml now"; Detail = "" }
        [pscustomobject]@{ ActionId = 'RestoreIAS'; Category = 'Backup / Restore NPS Configuration'; Label = "Restore ias.xml from a backup"; Detail = "" }
        [pscustomobject]@{ ActionId = 'ConfigSummary'; Category = 'Backup / Restore NPS Configuration'; Label = "Show full config summary (rules, clients, templates)"; Detail = "" }
        [pscustomobject]@{ ActionId = 'ADCredsToggle'; Category = 'Settings'; Label = "Toggle 'require explicit AD credentials every launch'"; Detail = "For a site where normal AD/ADWS auto-discovery never works." }
        [pscustomobject]@{ ActionId = 'NTLMv2Check'; Category = 'AD / Hardening Diagnostics'; Label = "Check / fix 'Enable NTLMv2 Compatibility'"; Detail = "Fixes DC Event 4776 wrong-password errors at NTLMv2-only-hardened sites." }
        [pscustomobject]@{ ActionId = 'TimestampSync'; Category = 'AD / Hardening Diagnostics'; Label = "Check / fix ias.xml <-> iastemplates.xml TemplatesTimestamp sync"; Detail = "Cheap integrity check for a real drift this tool can cause and correct." }
        [pscustomobject]@{ ActionId = 'StartFailureReport'; Category = 'AD / Hardening Diagnostics'; Label = "Generate 'Why won't NPS start' report"; Detail = "Use when the Network Policy Server service won't start." }
        [pscustomobject]@{ ActionId = 'HardeningReport'; Category = 'AD / Hardening Diagnostics'; Label = "NTLM / Kerberos hardening report (read-only)"; Detail = "GPO-driven settings - Restart NTLMv2 Compatibility is the actual fix." }
        [pscustomobject]@{ ActionId = 'ClockSkew'; Category = 'AD / Hardening Diagnostics'; Label = "Check clock skew against a Domain Controller"; Detail = "Kerberos breaks past 5 minutes of skew, regardless of credential correctness." }
        [pscustomobject]@{ ActionId = 'WindowsUpdates'; Category = 'AD / Hardening Diagnostics'; Label = "Show recent Windows Updates (optionally highlight against a date)"; Detail = "Cheap first check when something broke around a reboot." }
        [pscustomobject]@{ ActionId = 'ServerCerts'; Category = 'AD / Hardening Diagnostics'; Label = "Check server certificates (PEAP / EAP-TLS)"; Detail = "Flags expired/expiring/no-private-key certs in LocalMachine\My." }
        [pscustomobject]@{ ActionId = 'AuthCorrelation'; Category = 'AD / Hardening Diagnostics'; Label = "Correlate an auth failure across RADIUS log / NTLM logs / DC 4776"; Detail = "Given a timestamp, pulls all three side by side." }
    )
}

function Show-TroubleshootingCategoryLinks {
    <#
    .SYNOPSIS
        The "6a. Debugging   6b. Prerequisites / Script Troubleshooters" quick-link row(s) printed
        right under the main dashboard's "6. Troubleshooting Tools" (2026-09-03, per the maintainer: "make the
        grouped troubleshooting tools categories directly hittable from the NPS Manager dashboard").

    .DESCRIPTION
        Letters are derived the SAME way the main menu loop's own "6<letter>" dispatch derives them
        (Get-NPSTroubleshootingActions, first-seen category order) - never hand-typed here, so a
        category being added/removed/reordered can't silently drift this row out of sync with what
        actually gets accepted at the prompt.

        Only "Troubleshooters / Debugging" gets a shortened dashboard label ("Debugging") -
        "Troubleshooters" reads as redundant right under a "Troubleshooting Tools" heading; the other 4
        category names are already dashboard-width. The FULL category name is still what's shown once
        you're actually inside it (Invoke-TroubleshootingCategoryMenu's own header).
    #>
    $categories = @(Get-NPSTroubleshootingActions | Select-Object -ExpandProperty Category -Unique)
    $dashboardLabel = @{ 'Troubleshooters / Debugging' = 'Debugging' }
    $cellWidth = 46

    for ($i = 0; $i -lt $categories.Count; $i += 2) {
        $letterA = [string][char](97 + $i)
        $labelA = if ($dashboardLabel.ContainsKey($categories[$i])) { $dashboardLabel[$categories[$i]] } else { $categories[$i] }
        Write-Host "     6$letterA." -NoNewline -ForegroundColor Yellow
        if ($i + 1 -lt $categories.Count) {
            $letterB = [string][char](97 + $i + 1)
            $labelB = if ($dashboardLabel.ContainsKey($categories[$i + 1])) { $dashboardLabel[$categories[$i + 1]] } else { $categories[$i + 1] }
            $leftCell = (" {0}" -f $labelA).PadRight($cellWidth)
            Write-Host $leftCell -NoNewline
            Write-Host "6$letterB." -NoNewline -ForegroundColor Yellow
            Write-Host " $labelB"
        } else {
            Write-Host " $labelA"
        }
    }
}

function Invoke-TroubleshootingCategoryMenu {
    <#
    .SYNOPSIS
        One category's own action list - directly reachable from the main dashboard as "6<letter>"
        (2026-09-03, per the maintainer: "make the grouped troubleshooting tools categories directly hittable
        from the NPS Manager dashboard"). Replaces the old two-hop "6 -> pick a category -> pick an
        action" flow - the category is now picked AT the dashboard itself (see
        Show-TroubleshootingCategoryLinks), so this only ever needs to render ONE category's actions.

    .DESCRIPTION
        Full "label, then an indented '-detail' line below it" format (2026-09-03, per the maintainer: "Go back
        to the more verbose descriptions. Descriptions should always go on a new, indented line after
        the 'entry'") - the condensed single-line "Label - Detail" form from the short-lived T1/T2 A/B
        comparison is gone now that the maintainer's picked how this should actually look. Option numbers are
        colorized (Yellow) so they stand out from the label text, also per the maintainer's request. An action
        with no Detail text (a few of the Backup/Restore ones are self-explanatory) just skips the
        detail line rather than printing an empty one.
    #>
    param(
        [Parameter(Mandatory)][string]$Category,
        [string]$IASConfigPath, [string]$ADServer, [string]$ShimPath,
        [System.Management.Automation.PSCredential]$ADCredential, [string]$ADUsername
    )

    $catActions = @(Get-NPSTroubleshootingActions | Where-Object { $_.Category -eq $Category })

    :TroubleshootCategoryMenu while ($true) {
        Write-NPSHeader $Category
        for ($ai = 0; $ai -lt $catActions.Count; $ai++) {
            Write-Host ("  {0,2}." -f ($ai + 1)) -NoNewline -ForegroundColor Yellow
            Write-Host " $($catActions[$ai].Label)"
            if ($catActions[$ai].Detail) {
                Write-Host "            -$($catActions[$ai].Detail)" -ForegroundColor Gray
            }
            Write-Host ""
        }
        Write-Host "  M." -NoNewline -ForegroundColor Yellow
        Write-Host " Return to main menu"
        Write-Host ""
        $actChoice = Read-Host "Select an option"

        if ($actChoice -match '^[Mm]$') { return }
        $actIdx = ($actChoice -as [int]) - 1
        if ($actIdx -ge 0 -and $actIdx -lt $catActions.Count) {
            Invoke-TroubleshootingAction -ActionId $catActions[$actIdx].ActionId -IASConfigPath $IASConfigPath -ADServer $ADServer -ShimPath $ShimPath -ADCredential $ADCredential -ADUsername $ADUsername
        } else {
            Write-Host "Invalid selection." -ForegroundColor Yellow
        }
    }
}

function Invoke-TroubleshootingMenu {
    <#
    .SYNOPSIS
        Flat, ALL-categories view - the main dashboard's bare "6" (as opposed to "6<letter>", which
        goes straight to Invoke-TroubleshootingCategoryMenu for just one category). The "I don't know
        which category this is" catch-all - every action, still grouped under its category header, one
        screen, no hop.

    .DESCRIPTION
        Same verbose "label + indented detail line" format and Yellow-numbered options as
        Invoke-TroubleshootingCategoryMenu - the two used to be genuinely different presentations (T1
        flat/condensed vs T2 categorized/condensed) while the maintainer was comparing them live; now that he's
        picked "categories directly on the dashboard, verbose descriptions," this is just that same
        rendering applied to the full action list instead of one category's slice of it - not a
        separate style to maintain.
    #>
    param([string]$IASConfigPath, [string]$ADServer, [string]$ShimPath, [System.Management.Automation.PSCredential]$ADCredential, [string]$ADUsername)

    $actions = @(Get-NPSTroubleshootingActions)

    :TroubleshootMenuAll while ($true) {
        Write-NPSHeader "Troubleshooting Tools (all categories)"
        $num = 0
        $lastCategory = $null
        foreach ($a in $actions) {
            if ($a.Category -ne $lastCategory) {
                if ($lastCategory) { Write-Host "" }
                Write-Host $a.Category -ForegroundColor Cyan
                $lastCategory = $a.Category
            }
            $num++
            Write-Host ("  {0,2}." -f $num) -NoNewline -ForegroundColor Yellow
            Write-Host " $($a.Label)"
            if ($a.Detail) {
                Write-Host "            -$($a.Detail)" -ForegroundColor Gray
            }
            Write-Host ""
        }
        Write-Host "  M." -NoNewline -ForegroundColor Yellow
        Write-Host " Return to main menu"
        Write-Host ""
        $choice = Read-Host "Select an option"

        if ($choice -match '^[Mm]$') { return }
        $idx = ($choice -as [int]) - 1
        if ($idx -ge 0 -and $idx -lt $actions.Count) {
            Invoke-TroubleshootingAction -ActionId $actions[$idx].ActionId -IASConfigPath $IASConfigPath -ADServer $ADServer -ShimPath $ShimPath -ADCredential $ADCredential -ADUsername $ADUsername
        } else {
            Write-Host "Invalid selection." -ForegroundColor Yellow
        }
    }
}

