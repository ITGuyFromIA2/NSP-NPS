<#
.SYNOPSIS
    Shared interactive (Read-Host-driven) wizards for NPSManager - the "add a rule" flow, group
    condition collection, VSA resolution, and RADIUS client picking. Dot-sourced by BOTH
    Add-NPSNetworkPolicy.ps1 (standalone) and NPS-Manager.ps1 (the dashboard's Option 5), so a fix
    or UX change here lands in both places at once instead of needing to be copied twice - exactly
    the kind of duplication that already caused a real bug once in this repo's Master Orchestrator
    (see its own "Build-AndStageClient" refactor history).

.DESCRIPTION
    Requires Modules\NPSCore.ps1 to already be dot-sourced (uses Get-ADGroupSID,
    Resolve-NestedADGroups, Get-NPSExistingSequences, Add-NPSPolicySet, Add-NPSSingleRule,
    Get-NPSClients, Test-ADConnectivityViaExplicitDC, Set-NPSShimADServer, Set-NPSShimADUsername,
    Test-NPSServerRegistered, Test-NPSADAuthError).
#>

function Write-NPSHeader {
    <#
    .SYNOPSIS
        Draws the "====" banner used at the top of every screen/menu in this tool - and, per the maintainer's
        request, clears the screen first so scrollback from the PREVIOUS screen doesn't pile up
        between menu transitions. Called at the start of essentially every screen redraw across this
        whole app, so this one change gives a "clear between screens" effect everywhere for free.

    .DESCRIPTION
        Clear-Host wrapped in try/catch, not called bare - it can throw in a handful of non-console
        hosts (e.g. some CI/automation runners with no real console buffer). This app is always run
        in a real interactive elevated console window by design, so that's not expected to actually
        happen here, but silently no-op'ing instead of crashing the entire dashboard over a cosmetic
        failure is the correct trade-off regardless.
    #>
    param([string]$Title)
    try { Clear-Host } catch {}
    Write-Host ""
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ---------------------------------------------------------------------------
function Write-NPSADErrorDiagnostics {
    <#
    .SYNOPSIS
        Shared error-detail dump for AD connectivity/registration failures - CategoryInfo/
        FullyQualifiedErrorId/InnerException chain. Promoted to a top-level function (was originally
        nested inside Invoke-NPSADFallbackPrompt) so Connect-NPSADWithRetry can use it too without
        duplicating it - confirmed live (the maintainer) that this level of detail matters for telling apart
        genuinely different failures; a run of "fixes" to Test-ADConnectivityViaExplicitDC once kept
        not changing an error that, in hindsight, may have actually been coming from the OTHER call
        (Test-NPSServerRegistered) the whole time, back when both calls shared one try/catch with no
        way to tell which one actually failed.
    #>
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    Write-Host "  Exception type:  $($ErrorRecord.Exception.GetType().FullName)" -ForegroundColor DarkGray
    Write-Host "  CategoryInfo:    $($ErrorRecord.CategoryInfo)" -ForegroundColor DarkGray
    Write-Host "  FullyQualifiedErrorId: $($ErrorRecord.FullyQualifiedErrorId)" -ForegroundColor DarkGray
    $inner = $ErrorRecord.Exception.InnerException
    $depth = 1
    while ($inner) {
        Write-Host "  InnerException($depth): $($inner.GetType().FullName): $($inner.Message)" -ForegroundColor DarkGray
        $inner = $inner.InnerException
        $depth++
    }
}

# ---------------------------------------------------------------------------
function Connect-NPSADWithRetry {
    <#
    .SYNOPSIS
        Shared "prove connectivity + credentials work against a specific DC" retry loop -
        Test-ADConnectivityViaExplicitDC, up to $MaxAttempts tries, offering Get-Credential between
        failures. Factored out of Invoke-NPSADFallbackPrompt so Invoke-NPSRequiredCredentialsPrompt
        (the PROACTIVE version, for a client flagged as always needing explicit credentials - see
        $NPSRequiresExplicitADCredentials) doesn't duplicate it - same "one copy, not two that can
        drift apart" reasoning this codebase already applies elsewhere (e.g. Complete-ClientStaging's
        shared Kickstart-splicing logic).

    .DESCRIPTION
        Credentials are session-only here too - NEVER written to disk, same as every other credential
        prompt in this codebase.

    .PARAMETER Username
        Last-known-good username for this site (see $NPSADUsername / Set-NPSShimADUsername), if any -
        pre-fills the Get-Credential prompt so the tech doesn't have to retype it every launch. Never
        a password - just the username. Blank is fine (Get-Credential just starts empty, as before).

    .OUTPUTS
        $null if every attempt failed or the tech declined to retry. Otherwise a pscustomobject with
        Credential (the PSCredential that actually worked, or $null if the default identity worked
        without one).
    #>
    param(
        [Parameter(Mandatory)][string]$DCServer,
        [string]$Username,
        [int]$MaxAttempts = 3
    )

    $credential = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $asWhom = if ($credential) { " as '$($credential.UserName)'" } else { "" }
            Write-Host "Connecting directly to '$DCServer'$asWhom..." -ForegroundColor Cyan
            Test-ADConnectivityViaExplicitDC -DCServer $DCServer -Credential $credential
            Write-Host "Connected successfully via '$DCServer'." -ForegroundColor Green
            return [pscustomobject]@{ Credential = $credential }
        } catch {
            Write-Host "Connection to '$DCServer' failed - $($_.Exception.Message)" -ForegroundColor Red
            Write-NPSADErrorDiagnostics -ErrorRecord $_
            if ($attempt -ge $MaxAttempts) {
                Write-Host "Giving up after $MaxAttempts attempt(s)." -ForegroundColor Yellow
                return $null
            }
            $tryCreds = Read-Host "Try again with different credentials? (Y/N)"
            if ($tryCreds -notmatch '^[Yy]') { return $null }
            # Pre-fill with the last-known-good username for this site, if any - the tech can still
            # overwrite it in the Get-Credential dialog; this just saves retyping it every launch.
            if ($Username) {
                $credential = Get-Credential -UserName $Username -Message "Credentials with AD access on '$DCServer'"
            } else {
                $credential = Get-Credential -Message "Credentials with AD access on '$DCServer' (e.g. DOMAIN\username)"
            }
            if (-not $credential) {
                Write-Host "No credentials entered - skipped." -ForegroundColor Gray
                return $null
            }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
function Invoke-NPSADFallbackPrompt {
    <#
    .SYNOPSIS
        Offers the "connect to a specific DC directly" fallback after a normal AD check has failed -
        confirmed live (the maintainer) as the actual fix at a site where normal AD/ADWS auto-discovery is
        broken but a direct connection to a known-good DC works. On success, offers to persist the
        DC hostname into the staged shim (-ShimPath) so future launches use it automatically instead
        of hitting the same failure/prompt again.

        REACTIVE - only offered after a normal check has already failed. For a client already known
        to always need this (see $NPSRequiresExplicitADCredentials), see the PROACTIVE counterpart
        Invoke-NPSRequiredCredentialsPrompt instead, which skips straight to this without waiting for
        a failure first.

    .DESCRIPTION
        A direct connection can still fail on CREDENTIALS alone even once the right DC is named -
        confirmed live ("The server has rejected the client credentials") when the account this
        session is running as isn't valid/trusted against that specific DC. Connect-NPSADWithRetry
        offers Get-Credential to supply different ones across up to 3 attempts - session-only; NEVER
        written to disk anywhere in this codebase (unlike the DC hostname itself, which the "save for
        next time" step below does persist into the shim - a hostname and a password are not the same
        kind of secret).

        A working credential IS returned to the caller (see .OUTPUTS) - confirmed live (the maintainer) that
        the SAME credential is needed again for other AD-touching operations in the same session
        (the rule builder's wildcard group search, nested-group resolution), not just this one
        registration check - re-prompting separately for every single AD call would be needlessly
        painful. The caller is expected to cache it for the rest of the session (see
        NPS-Manager.ps1's $script:ADCredential) and pass it to those other calls too - still never
        written to disk, same as here.

    .PARAMETER ShimPath
        Path to the staged NPS-Manager_Shim.ps1 copy that launched this session (see
        NPS-Manager.ps1's -ShimPath param), if any - only known when running via the staged shim,
        not a standalone/manual copy of the dashboard. Passed to Set-NPSShimADServer for the "save
        for next time" step; when blank, that step is offered as a manual "-ADServer" note instead.

    .PARAMETER ADUsername
        Last-known-good username for this site (see $NPSADUsername / Set-NPSShimADUsername), if any -
        passed straight through to Connect-NPSADWithRetry to pre-fill its Get-Credential prompt.

    .OUTPUTS
        $null if skipped or every connection attempt failed. Otherwise a pscustomobject with
        DCServer, Registered (the actual Test-NPSServerRegistered result via that DC), Credential
        (the PSCredential that actually worked, or $null if the default identity worked without one),
        and Username (that credential's UserName, or $null) - the caller should apply DCServer,
        Credential, AND Username as this session's AD context going forward (see NPS-Manager.ps1's
        Invoke-InstallAuthorizeNPS), not just for this one check.
    #>
    param([string]$ShimPath, [string]$ADUsername)

    Write-Host ""
    Write-Host "The normal AD check failed - this can happen at sites with flaky AD/ADWS auto-discovery." -ForegroundColor Yellow
    $dcServer = Read-Host "Try connecting to a specific Domain Controller directly? Enter its FQDN (e.g. dc1.contoso.local), or blank to skip"
    if ([string]::IsNullOrWhiteSpace($dcServer)) {
        Write-Host "Skipped." -ForegroundColor Gray
        return $null
    }
    if ($dcServer -notmatch '\.') {
        # Confirmed live (the maintainer): a bare short hostname (no domain suffix) hit a DIFFERENT failure
        # than the exact same DC's FQDN did with the exact same credential - Kerberos SPN resolution
        # is picky about short-name vs FQDN in a way that can silently change which auth path gets
        # used. Not blocking the short name (it might still work at some sites), just flagging it.
        Write-Host "'$dcServer' looks like a short hostname, not a full FQDN - if this fails, try the" -ForegroundColor Yellow
        Write-Host "full FQDN instead (e.g. '$dcServer.yourdomain.tld') - Kerberos can behave differently" -ForegroundColor Yellow
        Write-Host "for a short name vs. the FQDN of the exact same DC." -ForegroundColor Yellow
    }

    $connectResult = Connect-NPSADWithRetry -DCServer $dcServer -Username $ADUsername
    if (-not $connectResult) { return $null }
    $credential = $connectResult.Credential

    # --- The actual registration check, SEPARATELY - a failure here is never confused with a
    # connectivity/credential failure above, since it has its own try/catch. ---
    $registered = $null
    try {
        Write-Host "Checking AD registration via '$dcServer'..." -ForegroundColor Cyan
        $registered = Test-NPSServerRegistered -Server $dcServer -Credential $credential -Force
    } catch {
        # Confirmed live (the maintainer): the connectivity check above can succeed under the DEFAULT identity
        # (no -Credential) while THIS check still fails on auth - Test-NPSServerRegistered runs its
        # own no-credential path in a background job (see its own TimeoutSeconds notes), and that job
        # boundary doesn't always carry the same Kerberos context the foreground connectivity check
        # just proved works. Without this branch, a tech in exactly that situation never sees a
        # credential prompt at all - "connected successfully" already printed, so there was nothing
        # left in the old flow that would ever call Get-Credential. Only offered when no credential
        # was already tried (retrying with the SAME credential that just failed would just fail the
        # same way) and the failure actually looks auth-related (Test-NPSADAuthError) - a genuinely
        # different failure (e.g. the group not existing) isn't something a credential retry can fix.
        if (-not $credential -and (Test-NPSADAuthError -ErrorRecord $_)) {
            Write-Host "Connected to '$dcServer' fine, but the registration check itself hit an auth error - $($_.Exception.Message)" -ForegroundColor Yellow
            Write-NPSADErrorDiagnostics -ErrorRecord $_
            $retryWithCreds = Read-Host "Try the registration check again with explicit credentials? (Y/N)"
            if ($retryWithCreds -match '^[Yy]') {
                $retryCred = if ($ADUsername) { Get-Credential -UserName $ADUsername -Message "Credentials with AD access on '$dcServer'" } else { Get-Credential -Message "Credentials with AD access on '$dcServer' (e.g. DOMAIN\username)" }
                if ($retryCred) {
                    try {
                        $registered = Test-NPSServerRegistered -Server $dcServer -Credential $retryCred -Force
                        $credential = $retryCred
                        Write-Host "Registration check succeeded with explicit credentials." -ForegroundColor Green
                    } catch {
                        Write-Host "Still failed with explicit credentials - $($_.Exception.Message)" -ForegroundColor Red
                        Write-NPSADErrorDiagnostics -ErrorRecord $_
                        Write-Host "Continuing anyway - '$dcServer' is confirmed reachable; just couldn't verify registration status." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "No credentials entered - skipped." -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "Connected to '$dcServer' successfully, but the registration check itself failed - $($_.Exception.Message)" -ForegroundColor Red
            Write-NPSADErrorDiagnostics -ErrorRecord $_
            Write-Host "Continuing anyway - '$dcServer' is confirmed reachable with these credentials; just couldn't verify" -ForegroundColor Yellow
            Write-Host "registration status this specific way. Saving below still applies this DC to the rest of the session." -ForegroundColor Yellow
        }
    }

    $save = Read-Host "Save '$dcServer' so future launches use it automatically, no re-prompting? (Y/N)"
    if ($save -match '^[Yy]') {
        if ($ShimPath -and (Test-Path $ShimPath)) {
            try {
                Set-NPSShimADServer -ShimPath $ShimPath -DCServer $dcServer
                Write-Host "Saved '$dcServer' into the shim at $ShimPath - future runs will use it automatically." -ForegroundColor Green
            } catch {
                Write-Host "Could not save into the shim - $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "You can still pass it manually next time: -ADServer '$dcServer'" -ForegroundColor Yellow
            }
            # Username too, if an explicit credential was actually entered (not the default identity)
            # - NEVER the password, just the username, so future Get-Credential prompts are pre-filled
            # instead of starting blank every launch (confirmed live: "I also needed to use a
            # different admin account").
            if ($credential -and $credential.UserName) {
                try {
                    Set-NPSShimADUsername -ShimPath $ShimPath -Username $credential.UserName
                    Write-Host "Saved username '$($credential.UserName)' into the shim too." -ForegroundColor Green
                } catch {
                    Write-Host "Could not save the username into the shim - $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            # CORRECTED, 2026-08-18: saving the DC hostname alone does NOT deliver on "future launches
            # use it automatically" - confirmed live (the maintainer): the save reported success, but a fresh
            # relaunch went right back to the normal (REACTIVE) flow, hit the same auto-discovery
            # failure again, and re-prompted for the DC from scratch anyway (this function has no
            # pre-fill from an already-known $ADServer at all). Without also flipping
            # $NPSRequiresExplicitADCredentials, NOTHING at startup ever tells the dashboard to call
            # the PROACTIVE Invoke-NPSRequiredCredentialsPrompt instead - which IS the one that reuses
            # a saved DC without re-asking (see its own notes) - so the saved value just sat in the
            # shim, unused, until a tech separately found and flipped the Troubleshooting toggle by
            # hand. Setting it here is what the "Y" answer to THIS prompt already promises.
            try {
                Set-NPSShimRequiresExplicitADCredentials -ShimPath $ShimPath -RequiresExplicitCredentials $true
                Write-Host "Future launches will also skip straight to asking for the DC/credentials up front." -ForegroundColor Green
            } catch {
                Write-Host "Could not enable proactive AD credential prompting - $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "The DC is still saved, but future launches may hit the same auto-discovery failure" -ForegroundColor Yellow
                Write-Host "before falling back to it - toggle it on manually via Troubleshooting Tools instead." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Not running from a staged shim (or its path wasn't provided) - can't auto-save." -ForegroundColor Yellow
            Write-Host "Pass it manually next time: -ADServer '$dcServer'" -ForegroundColor Yellow
        }
    }

    return [pscustomobject]@{ DCServer = $dcServer; Registered = $registered; Credential = $credential; Username = $(if ($credential) { $credential.UserName } else { $null }) }
}

# ---------------------------------------------------------------------------
function Invoke-NPSRequiredCredentialsPrompt {
    <#
    .SYNOPSIS
        PROACTIVE counterpart to Invoke-NPSADFallbackPrompt, for a client flagged (via
        $NPSRequiresExplicitADCredentials in its staged shim - see
        Set-NPSShimRequiresExplicitADCredentials and NPSTroubleshooting.ps1's toggle) as always
        needing an explicit DC + credentials, rather than reactively offering this only after a
        normal auto-discovery check has already failed. Called once at dashboard startup (see
        NPS-Manager.ps1) when that flag is set, BEFORE the first status check even runs, so the
        very first screen the tech sees already reflects reality instead of showing "Unknown" until
        they happen to visit Option 1 or Troubleshooting's "Test AD connectivity".

    .DESCRIPTION
        If $ADServer is already known (a prior session already saved a DC hostname into the shim via
        Set-NPSShimADServer), it's reused as-is and only credentials are asked for - the DC hostname
        itself is never re-prompted for once saved. Otherwise this asks for the DC FQDN too, same as
        Invoke-NPSADFallbackPrompt does reactively. Credentials themselves are NEVER persisted - this
        flag only controls whether the tech is asked proactively vs. reactively, not whether the
        answer is remembered (confirmed live: "we need to ask for it every time it's launched if we
        don't save credentials").

    .PARAMETER ADUsername
        Last-known-good username for this site (see $NPSADUsername / Set-NPSShimADUsername), if any -
        passed straight through to Connect-NPSADWithRetry to pre-fill its Get-Credential prompt.

    .OUTPUTS
        Same shape as Invoke-NPSADFallbackPrompt - $null if skipped/failed, otherwise a
        pscustomobject with DCServer, Registered, Credential, and Username.
    #>
    param([string]$ADServer, [string]$ShimPath, [string]$ADUsername)

    Write-Host ""
    Write-Host "This client is flagged as always needing explicit AD credentials (auto-discovery isn't" -ForegroundColor Yellow
    Write-Host "reliable here) - see Troubleshooting Tools to turn this off if that's changed." -ForegroundColor Yellow

    $dcServer = $ADServer
    if ([string]::IsNullOrWhiteSpace($dcServer)) {
        $dcServer = Read-Host "Domain Controller FQDN (e.g. dc1.contoso.local), or blank to skip"
        if ([string]::IsNullOrWhiteSpace($dcServer)) {
            Write-Host "Skipped - AD-dependent features will not work this session." -ForegroundColor Gray
            return $null
        }
    } else {
        Write-Host "Using previously-saved Domain Controller: $dcServer" -ForegroundColor Cyan
    }

    $connectResult = Connect-NPSADWithRetry -DCServer $dcServer -Username $ADUsername
    if (-not $connectResult) { return $null }
    $credential = $connectResult.Credential

    $registered = $null
    try {
        $registered = Test-NPSServerRegistered -Server $dcServer -Credential $credential -Force
    } catch {
        # Same job-boundary auth quirk as Invoke-NPSADFallbackPrompt hits (see its own notes on this
        # branch) - the default identity can pass the connectivity check above yet still fail THIS
        # check's own no-credential background-job path. Only offered when no credential was already
        # tried and the failure looks auth-related, same guard reasoning as the other function.
        if (-not $credential -and (Test-NPSADAuthError -ErrorRecord $_)) {
            Write-Host "Connected to '$dcServer' fine, but the registration check itself hit an auth error - $($_.Exception.Message)" -ForegroundColor Yellow
            Write-NPSADErrorDiagnostics -ErrorRecord $_
            $retryWithCreds = Read-Host "Try the registration check again with explicit credentials? (Y/N)"
            if ($retryWithCreds -match '^[Yy]') {
                $retryCred = if ($ADUsername) { Get-Credential -UserName $ADUsername -Message "Credentials with AD access on '$dcServer'" } else { Get-Credential -Message "Credentials with AD access on '$dcServer' (e.g. DOMAIN\username)" }
                if ($retryCred) {
                    try {
                        $registered = Test-NPSServerRegistered -Server $dcServer -Credential $retryCred -Force
                        $credential = $retryCred
                        Write-Host "Registration check succeeded with explicit credentials." -ForegroundColor Green
                    } catch {
                        Write-Host "Still failed with explicit credentials - $($_.Exception.Message)" -ForegroundColor Red
                        Write-NPSADErrorDiagnostics -ErrorRecord $_
                    }
                } else {
                    Write-Host "No credentials entered - skipped." -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "Connected to '$dcServer' successfully, but the registration check itself failed - $($_.Exception.Message)" -ForegroundColor Red
            Write-NPSADErrorDiagnostics -ErrorRecord $_
        }
    }

    # Offer to save whatever actually changed - the DC only if it wasn't already known, the username
    # only if a credential was actually entered AND it differs from what's already saved (skips a
    # needless re-prompt/rewrite on a launch where nothing new happened).
    $dcChanged = ($ADServer -ne $dcServer)
    $usernameChanged = ($credential -and $credential.UserName -and $credential.UserName -ne $ADUsername)
    if ($dcChanged -or $usernameChanged) {
        $save = Read-Host "Save these to the shim so future launches use them automatically? (Y/N)"
        if ($save -match '^[Yy]') {
            if ($ShimPath -and (Test-Path $ShimPath)) {
                if ($dcChanged) {
                    try {
                        Set-NPSShimADServer -ShimPath $ShimPath -DCServer $dcServer
                        Write-Host "Saved '$dcServer' into the shim at $ShimPath." -ForegroundColor Green
                    } catch {
                        Write-Host "Could not save the DC into the shim - $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
                if ($usernameChanged) {
                    try {
                        Set-NPSShimADUsername -ShimPath $ShimPath -Username $credential.UserName
                        Write-Host "Saved username '$($credential.UserName)' into the shim." -ForegroundColor Green
                    } catch {
                        Write-Host "Could not save the username into the shim - $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "Not running from a staged shim - can't auto-save." -ForegroundColor Yellow
            }
        }
    }

    return [pscustomobject]@{ DCServer = $dcServer; Registered = $registered; Credential = $credential; Username = $(if ($credential) { $credential.UserName } else { $null }) }
}

# ---------------------------------------------------------------------------
function Read-ANDConditionGroups {
    <#
    .SYNOPSIS
        Collects AND/OR group-membership conditions for one "side" (IPSec, SSLVPN, or a plain
        single rule's "Access" side) - each condition entered is AND'd with the others; multiple
        comma-separated search terms within ONE condition are OR'd.

    .DESCRIPTION
        Each comma-separated entry is a WILDCARD SEARCH TERM, not a required exact group name -
        resolved via Find-NPSADGroupsByWildcard ("contains" match). Exactly one AD hit auto-selects;
        multiple hits show a numbered pick-list so the tech doesn't need to already know the group's
        full exact name. An already-SID-shaped entry is still passed straight through unchanged
        (same as Get-ADGroupSID always did), since a SID isn't something to wildcard-search for.

        ZERO hits offers Create/Retype/Skip instead of just failing the term - Create prompts for a
        target OU via Select-NPSADOrganizationalUnit's text browser, then provisions the group
        (New-NPSADGroup) and resolves it exactly like a real search hit would. Retype/Skip both fall
        through to the existing "re-enter the whole condition" behavior, which already handles "fix a
        typo" without needing a separate single-term retry path.
    #>
    param(
        [Parameter(Mandatory)][string]$SideLabel,
        [string]$ADServer,
        # Optional - see Invoke-NPSADFallbackPrompt's -Credential notes. Confirmed live (the maintainer)
        # this is needed alongside -ADServer at some sites, for the exact wildcard-search call this
        # function makes.
        [System.Management.Automation.PSCredential]$ADCredential,
        # Passed straight through to Invoke-NPSADFallbackPrompt if a group search fails on what looks
        # like a credentials problem (see Test-NPSADAuthError) - lets the "save for next time" step
        # work from here too, not just the top-level status check.
        [string]$ShimPath
    )

    Write-Host "Building the $SideLabel required-group condition:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  - Each condition you add is AND'd with the others (a user must satisfy ALL of them)." -ForegroundColor Cyan
    Write-Host "  - Within ONE condition, list multiple search terms separated by commas - those are" -ForegroundColor Cyan
    Write-Host "    OR'd (a user needs to match ANY ONE of them to satisfy that condition)." -ForegroundColor Cyan
    Write-Host "  - Terms don't need to be exact - a partial name searches AD and you pick from matches." -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-RSATAvailable)) {
        Write-Host "The ActiveDirectory module (RSAT) isn't available - needed to search AD for group names." -ForegroundColor Yellow
        $installRSAT = Read-Host "Install it now? (Y/N)"
        if ($installRSAT -match '^[Yy]') {
            Install-RSATActiveDirectoryModule | Out-Null
        }
    }

    $sidSets = [System.Collections.Generic.List[string[]]]::new()
    $names   = [System.Collections.Generic.List[string]]::new()
    $conditionNum = 1
    while ($true) {
        $entry = Read-Host "$SideLabel AND-condition #${conditionNum}: group search term(s), comma-separated for OR (blank to finish, need at least 1)"
        if ([string]::IsNullOrWhiteSpace($entry)) {
            if ($sidSets.Count -eq 0) { Write-Host "At least one condition is required." -ForegroundColor Yellow; continue }
            break
        }
        $entryTerms = $entry.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $sids = [System.Collections.Generic.List[string]]::new()
        $ok = $true
        foreach ($term in $entryTerms) {
            $picked = $null
            if ($term -match '^S-1-5-\d+(-\d+)+$') {
                $sids.Add($term)
                $names.Add($term)
                Write-Host "  Using SID directly: $term" -ForegroundColor Green
                continue
            }

            try {
                # Proactively wrapped in @() - Find-NPSADGroupsByWildcard already wraps its OWN return
                # value the same way, but PowerShell's pipeline/array-unwrapping can still collapse a
                # length-1 result back to a bare scalar object by the time it's captured here (a
                # well-documented gotcha, confirmed live: this exact assignment broke specifically when
                # the search matched only one group, leaving $found.Count reading blank/failing on the
                # numeric comparisons below instead of behaving like a real 1-element array).
                $found = @(Find-NPSADGroupsByWildcard -SearchTerm $term -Server $ADServer -Credential $ADCredential)
            } catch {
                Write-Host "  Could not search AD for '$term' - $($_.Exception.Message)" -ForegroundColor Red
                # A site where the default identity partially works (e.g. the earlier status check
                # succeeded) can still fail HERE on a real query - confirmed live (the maintainer). Offer the
                # same fallback the top-level check would, right here, rather than just warning and
                # leaving the tech stuck mid-wizard.
                if (Test-NPSADAuthError -ErrorRecord $_) {
                    Write-Host "  This looks like a credentials problem, not a bad search term." -ForegroundColor Yellow
                    $fallback = Invoke-NPSADFallbackPrompt -ShimPath $ShimPath
                    if ($fallback -and $fallback.Credential) {
                        # Applies for the REST of this session too, same as the top-level fallback -
                        # every AD call after this one (including the rest of THIS loop) picks it up.
                        $script:ADServer = $fallback.DCServer
                        $script:ADCredential = $fallback.Credential
                        $ADServer = $fallback.DCServer
                        $ADCredential = $fallback.Credential
                        try {
                            $found = @(Find-NPSADGroupsByWildcard -SearchTerm $term -Server $ADServer -Credential $ADCredential)
                        } catch {
                            Write-Host "  Still could not search AD for '$term' - $($_.Exception.Message)" -ForegroundColor Red
                            $ok = $false
                            continue
                        }
                    } else {
                        $ok = $false
                        continue
                    }
                } else {
                    $ok = $false
                    continue
                }
            }

            # Computed once into a real [int] rather than repeatedly re-reading $found.Count below -
            # belt-and-suspenders against the same class of surprise recurring on a later access.
            $foundCount = $found.Count

            if ($foundCount -eq 0) {
                Write-Host "  No AD groups found matching '*$term*'." -ForegroundColor Red
                Write-Host "    C. Create a new AD group named '$term'"
                Write-Host "    R. Retype this term (maybe a typo)"
                Write-Host "    S. Skip this term"
                Write-Host "  Tip: 'C' here creates just this one bare group. If what's actually missing is" -ForegroundColor DarkGray
                Write-Host "  a whole client's VPN group/OU structure, AD-Manager (PushableTools\ADManager\," -ForegroundColor DarkGray
                Write-Host "  menu 2) is the fuller, OU-browsable tool for that." -ForegroundColor DarkGray
                $zeroChoice = Read-Host "  Select"
                if ($zeroChoice -match '^[Cc]') {
                    Write-Host "  Pick the OU to create '$term' in:" -ForegroundColor Cyan
                    $targetOU = Select-NPSADOrganizationalUnit -Server $ADServer -Credential $ADCredential
                    if (-not $targetOU) {
                        Write-Host "  Cancelled - no OU selected." -ForegroundColor Yellow
                        $ok = $false
                        continue
                    }
                    try {
                        $picked = New-NPSADGroup -Name $term -Path $targetOU -Server $ADServer -Credential $ADCredential
                        Write-Host "  Created AD group '$term' in $targetOU" -ForegroundColor Green
                        # Falls through to the shared $sids/$names.Add(...) tail below, same as a
                        # normal search hit - a freshly-created group is resolved exactly the same way.
                    } catch {
                        Write-Host "  Could not create group '$term' - $($_.Exception.Message)" -ForegroundColor Red
                        $ok = $false
                        continue
                    }
                } else {
                    # 'R' (retype) and 'S' (skip) both land here - either way, forcing the WHOLE
                    # condition line to be re-entered is the existing, established behavior for any
                    # unresolved term in this loop (see the "Skipped '$term'" case below), and it
                    # naturally handles "fix a typo" too since the tech just retypes the corrected
                    # term next time instead of this function needing a separate single-term retry path.
                    $ok = $false
                    continue
                }
            }

            if (-not $picked) {
                if ($foundCount -eq 1) {
                    $picked = $found[0]
                    Write-Host "  '$term' matched exactly one group: $($picked.Name)" -ForegroundColor Green
                } else {
                    Write-Host "  '$term' matched $foundCount groups:" -ForegroundColor Cyan
                    for ($i = 0; $i -lt $foundCount; $i++) {
                        Write-Host ("    {0}. {1}" -f ($i + 1), $found[$i].Name)
                    }
                    $sel = Read-Host "  Select a number (blank to skip this term)"
                    $idx = ($sel -as [int]) - 1
                    if ($idx -ge 0 -and $idx -lt $foundCount) {
                        $picked = $found[$idx]
                    } else {
                        Write-Host "  Skipped '$term' - no selection made." -ForegroundColor Yellow
                        $ok = $false
                        continue
                    }
                }
            }

            $sids.Add($picked.SID.Value)
            $names.Add($picked.Name)
            Write-Host "  Resolved '$term' -> '$($picked.Name)' -> $($picked.SID.Value)" -ForegroundColor Green
        }
        if (-not $ok) {
            Write-Host "Condition #${conditionNum} had unresolved/skipped term(s) - re-enter it." -ForegroundColor Yellow
            continue
        }
        $sidSets.Add($sids.ToArray())
        $conditionNum++
    }
    return [pscustomobject]@{ SidSets = $sidSets.ToArray(); RequiredNames = @($names | Select-Object -Unique) }
}

# ---------------------------------------------------------------------------
function Get-VsaNamesForSide {
    <#
    .SYNOPSIS
        Collects Fortinet-Group-Name VSA candidates for one side - offers to auto-resolve nested AD
        membership of the required group(s) (PLUS the required group(s) themselves - a client's
        FortiGate group can be scoped directly to the same group used for the condition match just
        as easily as to something it's nested under), or falls back to manual entry.

    .DESCRIPTION
        Nested membership resolves into ONE combined candidate list (required group(s) + everything
        found nested under them, deduped) shown ONCE as a numbered pick-list - not a separate (Y/N)
        prompt per group like this used to be. A required group with a dozen nested groups used to
        mean a dozen-plus individual confirmations here; now it's one list + one selection line
        (numbers comma-separated, 'A' for all, or blank for none) - same numbered-pick-list pattern
        already used elsewhere in this wizard (Read-ANDConditionGroups' AD search disambiguation,
        Select-NPSClientIP), not a new UX invented just for this.
    #>
    param(
        [Parameter(Mandatory)][string]$SideLabel,
        [string[]]$RequiredNames,
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential,
        # Passed straight through to Invoke-NPSADFallbackPrompt if a nested-membership resolve fails
        # on what looks like a credentials problem (see Test-NPSADAuthError).
        [string]$ShimPath
    )

    $vsaNames = [System.Collections.Generic.List[string]]::new()
    if ($RequiredNames.Count -gt 0) {
        if (-not (Test-RSATAvailable)) {
            Write-Host "The ActiveDirectory module (RSAT) isn't available - needed to auto-resolve nested AD group membership." -ForegroundColor Yellow
            $installRSAT = Read-Host "Install it now? (Y/N, N to skip straight to manual VSA entry)"
            if ($installRSAT -match '^[Yy]') {
                Install-RSATActiveDirectoryModule | Out-Null
            }
        }
        # Defaults to Yes (2026-08-31 per the maintainer) - blank/Enter now auto-resolves, same [Enter for Yes]
        # shape this codebase already uses elsewhere for a defaulted Y/N. Saying N explicitly still
        # skips straight to manual VSA entry below.
        $autoResolve = Read-Host "Auto-resolve nested AD group membership for the $SideLabel required group(s) ($($RequiredNames -join ', ')) and pick VSAs from those? [Enter for Yes] (Y/N)`n  (requires the ActiveDirectory module/RSAT - say N to type VSA group names directly instead)"
        if ([string]::IsNullOrWhiteSpace($autoResolve) -or $autoResolve -match '^[Yy]') {
            # Resolve AD FIRST, ask the tech ONCE at the end - build one combined, deduped candidate
            # list (required group(s) + everything nested under them, in discovery order) instead of
            # interleaving a live AD call with a Y/N prompt per group.
            #
            # Lowercased at the point of collection (not just deep inside New-FortinetGroupVSA's own
            # hex-encoding) so what the wizard's PREVIEW shows the tech is exactly what ends up written
            # into the VSA - FortiGate's Fortinet-Group-Name matching is case-sensitive (confirmed
            # live, the maintainer), so a display/actual case mismatch here would be exactly the kind of silent
            # "auth works, group assignment doesn't" failure this is meant to avoid.
            $candidates = [System.Collections.Generic.List[string]]::new()
            foreach ($reqName in $RequiredNames) {
                $reqNameLower = $reqName.ToLowerInvariant()
                if ($candidates -notcontains $reqNameLower) { $candidates.Add($reqNameLower) }

                Write-Host "Resolving nested membership for '$reqName'..." -ForegroundColor Gray
                # Local closure so the retry-after-fallback path below can reuse the exact same
                # "walk $nested, add each to the candidate list" logic without duplicating it.
                $addNestedGroups = {
                    param($NestedGroups)
                    foreach ($n in $NestedGroups) {
                        $nameLower = $n.Name.ToLowerInvariant()
                        if ($candidates -notcontains $nameLower) { $candidates.Add($nameLower) }
                    }
                }
                try {
                    $nested = Resolve-NestedADGroups -GroupName $reqName -Server $ADServer -Credential $ADCredential
                    & $addNestedGroups $nested
                } catch {
                    Write-Host "  Could not resolve nested membership for '$reqName' - $($_.Exception.Message)" -ForegroundColor Red
                    # A site where the default identity partially works (e.g. the earlier status check
                    # succeeded) can still fail HERE on a real query - confirmed live (the maintainer). Offer
                    # the same fallback the top-level check would, right here, rather than just
                    # warning and leaving the tech stuck mid-wizard.
                    if (Test-NPSADAuthError -ErrorRecord $_) {
                        Write-Host "  This looks like a credentials problem, not a bad group name." -ForegroundColor Yellow
                        $fallback = Invoke-NPSADFallbackPrompt -ShimPath $ShimPath
                        if ($fallback -and $fallback.Credential) {
                            # Applies for the REST of this session too - every AD call after this one
                            # (including the rest of THIS loop, and the OTHER side's resolve pass)
                            # picks it up immediately.
                            $script:ADServer = $fallback.DCServer
                            $script:ADCredential = $fallback.Credential
                            $ADServer = $fallback.DCServer
                            $ADCredential = $fallback.Credential
                            try {
                                $nested = Resolve-NestedADGroups -GroupName $reqName -Server $ADServer -Credential $ADCredential
                                & $addNestedGroups $nested
                            } catch {
                                Write-Host "  Still could not resolve nested membership for '$reqName' - $($_.Exception.Message)" -ForegroundColor Red
                            }
                        }
                    }
                }
            }

            if ($candidates.Count -eq 0) {
                Write-Host "No groups found - you'll need to enter $SideLabel VSA group names directly." -ForegroundColor Yellow
            } else {
                Write-Host ""
                Write-Host "$SideLabel VSA candidates (required group(s) + everything nested under them):" -ForegroundColor Cyan
                for ($i = 0; $i -lt $candidates.Count; $i++) {
                    Write-Host ("    {0}. {1}" -f ($i + 1), $candidates[$i])
                }
                Write-Host ""
                # Blank now defaults to ALL (2026-08-31 per the maintainer, live: "let's make this screen a
                # 'blank for all, comma separated or n for none'") - was blank=none/'A'=all, which
                # meant the common case (take everything nested under the required group) needed an
                # extra keystroke every time. 'N' is the new explicit way to say none, since blank no
                # longer means that; 'A' still works too, for anyone used to typing it.
                $sel = Read-Host "Include which as $SideLabel VSAs? [Enter for all] Numbers comma-separated, or N for none"
                if ([string]::IsNullOrWhiteSpace($sel) -or $sel -match '^[Aa]$') {
                    foreach ($c in $candidates) { $vsaNames.Add($c) }
                } elseif ($sel -match '^[Nn]$') {
                    # None - $vsaNames stays empty.
                } else {
                    foreach ($token in ($sel.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                        $idx = ($token -as [int]) - 1
                        if ($idx -ge 0 -and $idx -lt $candidates.Count) {
                            $vsaNames.Add($candidates[$idx])
                        } else {
                            Write-Host "  Skipped invalid selection '$token'." -ForegroundColor Yellow
                        }
                    }
                }
                if ($vsaNames.Count -gt 0) {
                    Write-Host "Selected: $($vsaNames -join ', ')" -ForegroundColor Green
                } else {
                    Write-Host "No groups selected - you'll need to enter $SideLabel VSA group names directly." -ForegroundColor Yellow
                }
            }
        }
    }
    if ($vsaNames.Count -eq 0) {
        $entry = Read-Host "$SideLabel VSA group name(s), comma-separated (e.g. 'azuremfa_ikev2' / 'azuremfa_sslvpn_group') - leave blank for none"
        foreach ($n in ($entry.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { $vsaNames.Add($n.ToLowerInvariant()) }
    }
    return @($vsaNames)
}

# ---------------------------------------------------------------------------
function Invoke-ReprocessNPSVsaWizard {
    <#
    .SYNOPSIS
        Re-runs nested AD group membership resolution for an EXISTING Network Policy's already-
        configured required group(s), so its RADIUS Profile's Fortinet-Group-Name VSAs can be
        refreshed after AD group nesting changes (e.g. a new firewall group added to a role group) -
        without deleting and recreating the whole rule.

    .DESCRIPTION
        Pulls the SID(s) straight off the picked policy's own USERNTGROUPS condition(s) (see
        Get-NPSRequiredGroupSidsFromConstraints), resolves each back to its current name
        (Resolve-NPSGroupNameFromSid - same credentials-fallback handling as everywhere else AD gets
        touched in this wizard flow), then reuses Get-VsaNamesForSide - the EXACT same interactive
        nested-resolve UX Invoke-AddNPSRuleWizard already uses - rather than a second, parallel copy
        of that flow. Shows current vs. proposed VSAs (added/removed/unchanged) before writing.
    #>
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential,
        [string]$ShimPath
    )

    Write-NPSHeader "Re-process VSAs for a Rule"
    $summary = Get-NPSPolicySummary -Path $IASConfigPath -PolicyType NetworkPolicy
    $picked = Select-NPSPolicyFromSummary -Summary $summary -Prompt "Select a rule to re-process VSAs for, by number"
    if (-not $picked) { return }

    $sids = Get-NPSRequiredGroupSidsFromConstraints -Constraints $picked.Constraints
    if ($sids.Count -eq 0) {
        Write-Host "'$($picked.Name)' has no required-group-membership (USERNTGROUPS) condition to re-process VSAs from." -ForegroundColor Yellow
        Write-Host "(Only rules built with a group-membership condition have anything to re-resolve here.)" -ForegroundColor Yellow
        Read-Host "Press Enter to continue"
        return
    }

    Write-Host "Resolving current group name(s) for this rule's required SID(s)..." -ForegroundColor Gray
    $requiredNames = [System.Collections.Generic.List[string]]::new()
    foreach ($sid in $sids) {
        try {
            $name = Resolve-NPSGroupNameFromSid -Sid $sid -Server $ADServer -Credential $ADCredential
            $requiredNames.Add($name)
            Write-Host "  $sid -> $name" -ForegroundColor Green
        } catch {
            Write-Host "  Could not resolve $sid - $($_.Exception.Message)" -ForegroundColor Red
            # Same reactive AD-credential fallback as everywhere else this wizard touches AD - see
            # Test-NPSADAuthError.
            if (Test-NPSADAuthError -ErrorRecord $_) {
                Write-Host "  This looks like a credentials problem." -ForegroundColor Yellow
                $fallback = Invoke-NPSADFallbackPrompt -ShimPath $ShimPath
                if ($fallback -and $fallback.Credential) {
                    $script:ADServer = $fallback.DCServer
                    $script:ADCredential = $fallback.Credential
                    $ADServer = $fallback.DCServer
                    $ADCredential = $fallback.Credential
                    try {
                        $name = Resolve-NPSGroupNameFromSid -Sid $sid -Server $ADServer -Credential $ADCredential
                        $requiredNames.Add($name)
                        Write-Host "  $sid -> $name" -ForegroundColor Green
                    } catch {
                        Write-Host "  Still could not resolve $sid - skipping it (may have been deleted)." -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "  Skipping $sid (may have been deleted from AD)." -ForegroundColor Yellow
            }
        }
    }
    if ($requiredNames.Count -eq 0) {
        Write-Host "Could not resolve any of this rule's required group(s) - nothing to re-process." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }

    $currentVsas = @()
    try {
        $currentVsas = @(Get-NPSProfileVsaGroupNames -Path $IASConfigPath -PolicyName $picked.Name)
    } catch {
        Write-Host "Could not read the current VSA list - $($_.Exception.Message)" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    Write-Host ""
    Write-Host "Current VSAs on '$($picked.Name)': $(if ($currentVsas.Count -gt 0) { $currentVsas -join ', ' } else { '(none)' })" -ForegroundColor Cyan
    Write-Host ""

    Write-NPSHeader "RADIUS Attributes (Fortinet-Group-Name VSAs)"
    $newVsas = @(Get-VsaNamesForSide -SideLabel $picked.Name -RequiredNames @($requiredNames) -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath)

    $added = @($newVsas | Where-Object { $currentVsas -notcontains $_ })
    $removed = @($currentVsas | Where-Object { $newVsas -notcontains $_ })
    $unchanged = @($newVsas | Where-Object { $currentVsas -contains $_ })

    Write-Host ""
    Write-Host "Proposed VSAs for '$($picked.Name)': $(if ($newVsas.Count -gt 0) { $newVsas -join ', ' } else { '(none)' })" -ForegroundColor Cyan
    if ($added.Count -gt 0) { Write-Host "  + Added:     $($added -join ', ')" -ForegroundColor Green }
    if ($removed.Count -gt 0) { Write-Host "  - Removed:   $($removed -join ', ')" -ForegroundColor Red }
    if ($unchanged.Count -gt 0) { Write-Host "  = Unchanged: $($unchanged -join ', ')" -ForegroundColor Gray }
    if ($added.Count -eq 0 -and $removed.Count -eq 0) {
        Write-Host "No change - the resolved VSA set is identical to what's already there." -ForegroundColor Gray
        Read-Host "Press Enter to continue"
        return
    }
    Write-Host ""

    $confirm = Read-Host "Apply this to $IASConfigPath now? A timestamped backup will be made first. (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled - nothing changed." -ForegroundColor Gray; return }

    $result = Set-NPSProfileVsaGroupNames -Path $IASConfigPath -PolicyName $picked.Name -VsaGroupNames @($newVsas)
    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
    Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
    Write-Host "NPS/IAS watches ias.xml and picks up the change on its own - no service restart needed." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
function Select-NPSClientIP {
    <#
    .SYNOPSIS
        Picks a Client-IP-Address for a new policy's Client-IP-Address condition - offers a numbered
        list of existing RADIUS Clients (Get-NPSClients) to choose from, or manual entry (always
        available, including when no clients exist yet).

    .DESCRIPTION
        A "0 RADIUS Clients registered" result is a real, valid state to land in even when
        Invoke-AddNPSRuleWizard just showed IPs already referenced elsewhere in ias.xml - those come
        from a DIFFERENT section (existing NetworkPolicy conditions' literal Client-IP-Address
        values) than this one (Protocols\Microsoft Radius Protocol\Clients, the actual registered
        RADIUS Client objects - see Get-NPSClients). A policy CAN condition on an IP that was never
        registered as a formal Client, so seeing IPs in one list and none in the other isn't a
        contradiction - always shows an explicit "(none found)" line for that case rather than
        silently rendering a header with nothing under it, which read as a blank/broken list.
    #>
    param([Parameter(Mandatory)][string]$IASConfigPath)

    $clients = @()
    try { $clients = @(Get-NPSClients -Path $IASConfigPath) } catch {}

    Write-Host "Existing RADIUS Clients:" -ForegroundColor Cyan
    if ($clients.Count -eq 0) {
        Write-Host "    (none found in ias.xml - see Option 4, Manage NPS Clients, to register one)" -ForegroundColor Gray
    } else {
        for ($i = 0; $i -lt $clients.Count; $i++) {
            $c = $clients[$i]
            $flag = if (-not $c.Enabled) { '  [DISABLED]' } else { '' }
            Write-Host ("    {0}. {1}  ({2}){3}" -f ($i + 1), $c.Name, $c.IPAddress, $flag)
        }
    }
    Write-Host "    M. Enter a Client-IP-Address manually instead"
    $sel = Read-Host "Pick a client by number, or M to enter manually"
    if ($sel -match '^[Mm]$') {
        return Read-Host "Client-IP-Address for the FortiGate NAS"
    }
    $idx = ($sel -as [int]) - 1
    if ($idx -ge 0 -and $idx -lt $clients.Count) {
        return $clients[$idx].IPAddress
    }
    Write-Host "Invalid selection - enter manually instead." -ForegroundColor Yellow
    return Read-Host "Client-IP-Address for the FortiGate NAS"
}

# ---------------------------------------------------------------------------
function Format-NPSCondText {
    param([array]$SidSets)
    return ($SidSets | ForEach-Object { '(' + ($_ -join ' OR ') + ')' }) -join ' AND '
}

# ---------------------------------------------------------------------------
function Invoke-AddNPSRuleWizard {
    <#
    .SYNOPSIS
        The full interactive "add a rule" flow - asks whether this needs the standard 3-policy
        set (Combined/IPSec-only/SSLVPN-only) or a single standalone rule, then drives the rest of
        the flow (naming, Client-IP, AND/OR conditions, VSA resolution, sequence placement, preview,
        confirm, apply) accordingly. Called from both Add-NPSNetworkPolicy.ps1 (standalone) and
        NPS-Manager.ps1 (dashboard Option 5 -> Add).
    #>
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential,
        # Passed straight through to Read-ANDConditionGroups/Get-VsaNamesForSide, in turn to
        # Invoke-NPSADFallbackPrompt if either hits what looks like a credentials problem mid-flow.
        [string]$ShimPath
    )

    Write-NPSHeader "Add NPS Rule"

    Write-Host "Does this rule need to simultaneously support SSLVPN AND IPSec through RADIUS?" -ForegroundColor Cyan
    Write-Host "  Y = builds the 3-policy set (Combined / IPSec-only / SSLVPN-only)" -ForegroundColor Cyan
    Write-Host "  N = a single standalone rule" -ForegroundColor Cyan
    $simulSupport = Read-Host "(Y/N)"
    $isTriplicate = $simulSupport -match '^[Yy]'

    Write-NPSHeader "Policy Naming"
    if ($isTriplicate) {
        $baseName = Read-Host "Base name for this policy set (e.g. 'RADIUS - Accounting')`n  Three policies will be created: '<name> - IKEv2 & SSLVPN', '<name> - IKEv2 VPN', '<name> - SSLVPN'"
    } else {
        $baseName = Read-Host "Display name for this rule (e.g. 'RADIUS - VendorAccess')"
    }
    while ([string]::IsNullOrWhiteSpace($baseName)) { $baseName = Read-Host "A name is required" }

    [xml]$currentConfig = Get-Content -Path $IASConfigPath -Raw
    $existingClientIPs = @($currentConfig.Root.Children.Microsoft_Internet_Authentication_Service.Children.NetworkPolicy.Children.ChildNodes |
        ForEach-Object {
            $c = @($_.Properties.msNPConstraint) | Where-Object { $_ -and $_.'#text' -match 'Client-IP-Address=([\d.]+)' }
            if ($c) { $Matches[1] }
        } | Select-Object -Unique)
    if ($existingClientIPs) {
        Write-Host "Client-IP-Address values already in use in this config: $($existingClientIPs -join ', ')" -ForegroundColor Gray
    }
    $clientIP = Select-NPSClientIP -IASConfigPath $IASConfigPath
    while ([string]::IsNullOrWhiteSpace($clientIP)) { $clientIP = Read-Host "A Client-IP-Address is required" }

    if ($isTriplicate) {
        Write-NPSHeader "IPSec (IKEv2) Access - Required Group Membership"
        Write-Host "Who gets IPSec/IKEv2 access - AD group condition(s) below." -ForegroundColor Gray
        Write-Host ""
        $ipsecReq = Read-ANDConditionGroups -SideLabel "IPSec" -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath

        Write-NPSHeader "SSLVPN Access - Required Group Membership"
        Write-Host "Who gets SSLVPN access - a SEPARATE condition from IPSec above (same group(s) or" -ForegroundColor Gray
        Write-Host "different ones, your call)." -ForegroundColor Gray
        Write-Host ""
        $sslvpnReq = Read-ANDConditionGroups -SideLabel "SSLVPN" -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath

        Write-NPSHeader "RADIUS Attributes (Fortinet-Group-Name VSAs)"
        Write-Host "These become msRADIUSAnyVSA entries in the RADIUS Profile - they tell the FortiGate" -ForegroundColor Cyan
        Write-Host "which local group(s) to place the user into once authenticated." -ForegroundColor Cyan
        Write-Host ""

        Write-Host "-- IPSec side --" -ForegroundColor Cyan
        $ikeVsaNames = Get-VsaNamesForSide -SideLabel "IPSec" -RequiredNames $ipsecReq.RequiredNames -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath

        Write-Host ""
        Write-Host "-- SSLVPN side --" -ForegroundColor Cyan
        $sslVsaNames = Get-VsaNamesForSide -SideLabel "SSLVPN" -RequiredNames $sslvpnReq.RequiredNames -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath

        if ($ikeVsaNames.Count -eq 0 -or $sslVsaNames.Count -eq 0) {
            Write-Host "ERROR: At least one VSA group name is required for both IPSec and SSLVPN." -ForegroundColor Red
            return
        }

        Write-NPSHeader "Policy Order"
        # Shows Name alongside Sequence (2026-08-31 per the maintainer: "can we show the list of policy names
        # so we can pick the right one, similar to how it's shown on the first page of NPS Manager") -
        # same rendering NPS-Manager.ps1's own "Current Network Policies" status view (Option 1's
        # dashboard) already uses.
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
        Write-Host "New policies always land as a contiguous 3-slot block, Combined first (must be evaluated" -ForegroundColor Gray
        Write-Host "before the narrower IPSec-only/SSLVPN-only ones, or a dual-qualified user could get caught" -ForegroundColor Gray
        Write-Host "by the narrower policy first and only receive one VSA)." -ForegroundColor Gray
        $seqInput = Read-Host "Insert at sequence number [Enter for 1 = top priority]"
        $insertAt = if ([string]::IsNullOrWhiteSpace($seqInput)) { 1 } else { [int]$seqInput }

        Write-NPSHeader "Preview"
        $preview = Add-NPSPolicySet -Path $IASConfigPath -BaseName $baseName -ClientIPAddress $clientIP `
            -IPSecGroupSidSets $ipsecReq.SidSets -SSLVPNGroupSidSets $sslvpnReq.SidSets `
            -IPSecVsaGroupNames $ikeVsaNames -SSLVPNVsaGroupNames $sslVsaNames `
            -InsertAtSequence $insertAt -WhatIf

        $ipsecCondText = Format-NPSCondText $ipsecReq.SidSets
        $sslCondText   = Format-NPSCondText $sslvpnReq.SidSets

        Write-Host "Would create 3 policies starting at sequence $insertAt`:"
        Write-Host "  1. $baseName - IKEv2 & SSLVPN  (requires IPSec: $ipsecCondText  AND  SSLVPN: $sslCondText)"
        Write-Host "     VSAs: $(($ikeVsaNames + $sslVsaNames | Select-Object -Unique) -join ', ')"
        Write-Host "  2. $baseName - IKEv2 VPN       (requires: $ipsecCondText)"
        Write-Host "     VSAs: $($ikeVsaNames -join ', ')"
        Write-Host "  3. $baseName - SSLVPN          (requires: $sslCondText)"
        Write-Host "     VSAs: $($sslVsaNames -join ', ')"
        Write-Host ""
        if ($preview.ShiftedSequences) {
            Write-Host "Existing policies at sequence $insertAt and above will be shifted back by 3 to make room." -ForegroundColor Yellow
        }
        Write-Host ""

        $confirm = Read-Host "Apply this to $IASConfigPath now? A timestamped backup will be made first. (Y/N)"
        if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled - nothing changed." -ForegroundColor Gray; return }

        $result = Add-NPSPolicySet -Path $IASConfigPath -BaseName $baseName -ClientIPAddress $clientIP `
            -IPSecGroupSidSets $ipsecReq.SidSets -SSLVPNGroupSidSets $sslvpnReq.SidSets `
            -IPSecVsaGroupNames $ikeVsaNames -SSLVPNVsaGroupNames $sslVsaNames `
            -InsertAtSequence $insertAt

        Write-Host ""
        Write-Host "Done." -ForegroundColor Green
        Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
        Write-Host "NPS/IAS watches ias.xml and picks up the change on its own - no service restart needed." -ForegroundColor Green
    } else {
        Write-NPSHeader "Required Group Membership (AND / OR)"
        Write-Host "Who this rule applies to - AD group condition(s) below." -ForegroundColor Gray
        Write-Host ""
        $req = Read-ANDConditionGroups -SideLabel "Access" -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath

        Write-NPSHeader "RADIUS Attributes (Fortinet-Group-Name VSAs)"
        Write-Host "Optional for a single rule - leave blank if this rule doesn't need to assign a" -ForegroundColor Cyan
        Write-Host "specific FortiGate group." -ForegroundColor Cyan
        Write-Host ""
        $vsaNames = Get-VsaNamesForSide -SideLabel "Access" -RequiredNames $req.RequiredNames -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath

        Write-NPSHeader "Policy Order"
        # Shows Name alongside Sequence (2026-08-31 per the maintainer) - same rendering as the other two
        # "Policy Order" spots in this file/OrchestratorImport.ps1, see their own comments.
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
        $seqInput = Read-Host "Insert at sequence number [Enter for 1 = top priority]"
        $insertAt = if ([string]::IsNullOrWhiteSpace($seqInput)) { 1 } else { [int]$seqInput }

        Write-NPSHeader "Preview"
        $preview = Add-NPSSingleRule -Path $IASConfigPath -DisplayName $baseName -ClientIPAddress $clientIP `
            -GroupSidSets $req.SidSets -VsaGroupNames $vsaNames -InsertAtSequence $insertAt -WhatIf

        Write-Host "Would create 1 policy at sequence $insertAt`:"
        Write-Host "  $baseName  (requires: $(Format-NPSCondText $req.SidSets))"
        Write-Host "  VSAs: $(if ($vsaNames.Count -gt 0) { $vsaNames -join ', ' } else { '(none)' })"
        Write-Host ""
        if ($preview.ShiftedSequences) {
            Write-Host "Existing policies at sequence $insertAt and above will be shifted back by 1 to make room." -ForegroundColor Yellow
        }
        Write-Host ""

        $confirm = Read-Host "Apply this to $IASConfigPath now? A timestamped backup will be made first. (Y/N)"
        if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled - nothing changed." -ForegroundColor Gray; return }

        $result = Add-NPSSingleRule -Path $IASConfigPath -DisplayName $baseName -ClientIPAddress $clientIP `
            -GroupSidSets $req.SidSets -VsaGroupNames $vsaNames -InsertAtSequence $insertAt

        Write-Host ""
        Write-Host "Done." -ForegroundColor Green
        Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
        Write-Host "NPS/IAS watches ias.xml and picks up the change on its own - no service restart needed." -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
function Read-NPSConnectionRequestConditions {
    <#
    .SYNOPSIS
        The interactive condition-collection loop for a Connection Request Policy - factored out of
        Invoke-AddNPSConnectionRequestPolicyWizard so Invoke-EditNPSPolicyConditions can reuse the
        EXACT same loop (condition kinds, wording, validation) instead of a second, parallel copy
        that could drift out of sync with the add flow.

    .DESCRIPTION
        Offers the condition kinds actually seen in real CRP data (Client-IP-Address, Client-
        Friendly-Name, NAS-Port-Type, TIMEOFDAY), required AD group membership (reuses
        Read-ANDConditionGroups as-is), and a free-text "other attribute" fallback so an uncommon
        condition is never a hard blocker.

    .PARAMETER StartingConditions
        Pre-seeds the list (used by the edit flow, which starts from the policy's CURRENT conditions
        rather than empty) - each entry is shown as already-added before the tech adds/removes
        anything further. Add-only per pass (this loop has no "remove" option - matches the wholesale-
        recompute semantics already established for VSA re-processing: start over with what you want,
        don't try to surgically edit one entry among many).
    #>
    param(
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential,
        [string]$ShimPath,
        [string[]]$StartingConditions = @()
    )

    # MUST be an explicit [string[]] cast, not a bare @() wrap - List[string]::new() has no overload
    # for a plain object[] (what @() alone produces), since .NET generics don't treat
    # IEnumerable<object> as assignable to IEnumerable<string> - confirmed live, this exact call threw
    # "Cannot find an overload for 'new' and the argument count: 1" without the cast.
    $conditions = [System.Collections.Generic.List[string]]::new([string[]]@($StartingConditions))
    Write-Host "Add one or more conditions - ALL of them must match for this policy to apply." -ForegroundColor Cyan
    if ($conditions.Count -gt 0) {
        Write-Host "Starting from $($conditions.Count) existing condition(s):" -ForegroundColor Gray
        foreach ($c in $conditions) { Write-Host "    - $c" -ForegroundColor Gray }
    }
    Write-Host ""
    :ConditionLoop while ($true) {
        Write-Host "  1. Client IP Address"
        Write-Host "  2. Client Friendly Name (supports a regex pattern, e.g. '.*pGINA')"
        Write-Host "  3. NAS Port Type (numeric code, e.g. real samples use '^5$' - RD Gateway)"
        Write-Host "  4. Time of Day (Always = all days/times, or type a custom schedule)"
        Write-Host "  5. Required AD group membership (AND/OR - same wizard the access-grant flow uses)"
        Write-Host "  6. Other RADIUS attribute (free-text name + value)"
        Write-Host "  F. Finish$(if ($conditions.Count -eq 0) { ' (need at least 1 condition first)' } else { " ($($conditions.Count) condition(s) so far)" })"
        $choice = Read-Host "Select an option"

        switch -Regex ($choice) {
            '^1$' {
                $ip = Read-Host "Client IP Address"
                if (-not [string]::IsNullOrWhiteSpace($ip)) {
                    $conditions.Add("MATCH(`"Client-IP-Address=$ip`")")
                    Write-Host "  Added." -ForegroundColor Green
                }
            }
            '^2$' {
                $pattern = Read-Host "Client Friendly Name (exact value or regex pattern)"
                if (-not [string]::IsNullOrWhiteSpace($pattern)) {
                    $conditions.Add("MATCH(`"Client-Friendly-Name=$pattern`")")
                    Write-Host "  Added." -ForegroundColor Green
                }
            }
            '^3$' {
                $portType = Read-Host "NAS Port Type value/pattern"
                if (-not [string]::IsNullOrWhiteSpace($portType)) {
                    $conditions.Add("MATCH(`"NAS-Port-Type=$portType`")")
                    Write-Host "  Added." -ForegroundColor Green
                }
            }
            '^4$' {
                $todChoice = Read-Host "  A for Always (all days, all times), or C for a Custom TIMEOFDAY value"
                if ($todChoice -match '^[Aa]') {
                    # Exact convention seen in every real "always" CRP sample seen in the field - all 7 days, 00:00-24:00.
                    $conditions.Add('TIMEOFDAY("0 00:00-24:00; 1 00:00-24:00; 2 00:00-24:00; 3 00:00-24:00; 4 00:00-24:00; 5 00:00-24:00; 6 00:00-24:00")')
                    Write-Host "  Added." -ForegroundColor Green
                } elseif ($todChoice -match '^[Cc]') {
                    $custom = Read-Host "  Custom TIMEOFDAY value (the content that goes inside TIMEOFDAY(`"...`"))"
                    if (-not [string]::IsNullOrWhiteSpace($custom)) {
                        $conditions.Add("TIMEOFDAY(`"$custom`")")
                        Write-Host "  Added." -ForegroundColor Green
                    }
                } else {
                    Write-Host "  Cancelled." -ForegroundColor Gray
                }
            }
            '^5$' {
                $req = Read-ANDConditionGroups -SideLabel "Group membership" -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath
                foreach ($sidSet in $req.SidSets) {
                    $quoted = ($sidSet | ForEach-Object { "`"$_`"" }) -join ','
                    $conditions.Add("USERNTGROUPS($quoted)")
                }
                if ($req.SidSets.Count -gt 0) { Write-Host "  Added $($req.SidSets.Count) condition(s)." -ForegroundColor Green }
            }
            '^6$' {
                $attrName = Read-Host "  RADIUS attribute name (e.g. 'Called-Station-Id')"
                if (-not [string]::IsNullOrWhiteSpace($attrName)) {
                    $attrValue = Read-Host "  Value/pattern for '$attrName'"
                    if (-not [string]::IsNullOrWhiteSpace($attrValue)) {
                        $conditions.Add("MATCH(`"$attrName=$attrValue`")")
                        Write-Host "  Added." -ForegroundColor Green
                    }
                }
            }
            '^[Ff]$' {
                if ($conditions.Count -eq 0) {
                    Write-Host "At least one condition is required before finishing." -ForegroundColor Yellow
                } else {
                    break ConditionLoop
                }
            }
            default { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
        Write-Host ""
    }
    return @($conditions)
}

# ---------------------------------------------------------------------------
function Invoke-AddNPSConnectionRequestPolicyWizard {
    <#
    .SYNOPSIS
        The full interactive "add a Connection Request Policy" flow - deliberately NOT a reuse of
        Invoke-AddNPSRuleWizard, which is inherently about access grants (group SIDs + VSAs); that
        model is semantically wrong for a CRP, which decides WHERE/HOW a request gets authenticated,
        not who gets access to what. No VSA/profile step at all - confirmed with the maintainer, every real
        CRP sample seen in the field routes/authenticates locally rather than granting VSA-bearing
        access.

    .DESCRIPTION
        Condition collection itself is Read-NPSConnectionRequestConditions (shared with
        Invoke-EditNPSPolicyConditions) - the real ones seen in live CRP data (Client-IP-Address,
        Client-Friendly-Name, NAS-Port-Type, TIMEOFDAY), required AD group membership (reuses
        Read-ANDConditionGroups as-is), and a free-text "other attribute" fallback so an uncommon
        condition is never a hard blocker. Same sequence-placement/preview/confirm/apply pattern as
        Invoke-AddNPSRuleWizard, just against Add-NPSConnectionRequestRule instead.
    #>
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential,
        # Passed straight through to Read-ANDConditionGroups, in turn to Invoke-NPSADFallbackPrompt if
        # it hits what looks like a credentials problem mid-flow.
        [string]$ShimPath
    )

    Write-NPSHeader "Add Connection Request Policy"

    $displayName = Read-Host "Display name for this policy (e.g. 'RADIUS from FortiGate')"
    while ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = Read-Host "A name is required" }

    Write-NPSHeader "Conditions"
    $conditions = Read-NPSConnectionRequestConditions -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath

    Write-NPSHeader "Policy Order"
    [xml]$currentConfig = Get-Content -Path $IASConfigPath -Raw
    $existingSeqs = Get-NPSExistingSequences -ConfigXml $currentConfig -PolicyType ConnectionRequest
    Write-Host "Existing real Connection Request Policy sequence numbers: $($existingSeqs -join ', ')" -ForegroundColor Gray
    $seqInput = Read-Host "Insert at sequence number [Enter for 1 = top priority]"
    $insertAt = if ([string]::IsNullOrWhiteSpace($seqInput)) { 1 } else { [int]$seqInput }

    Write-NPSHeader "Preview"
    $preview = Add-NPSConnectionRequestRule -Path $IASConfigPath -DisplayName $displayName -Conditions @($conditions) -InsertAtSequence $insertAt -WhatIf

    Write-Host "Would create 1 Connection Request Policy at sequence $insertAt`:"
    Write-Host "  $displayName"
    foreach ($c in $conditions) { Write-Host "    - $c" -ForegroundColor Gray }
    Write-Host "  (no RADIUS Profile/VSAs - Connection Request Policies in this environment don't use them)" -ForegroundColor Gray
    Write-Host ""
    if ($preview.ShiftedSequences) {
        Write-Host "Existing Connection Request Policies at sequence $insertAt and above will be shifted back by 1 to make room." -ForegroundColor Yellow
    }
    Write-Host ""

    $confirm = Read-Host "Apply this to $IASConfigPath now? A timestamped backup will be made first. (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled - nothing changed." -ForegroundColor Gray; return }

    $result = Add-NPSConnectionRequestRule -Path $IASConfigPath -DisplayName $displayName -Conditions @($conditions) -InsertAtSequence $insertAt

    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
    Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
    Write-Host "NPS/IAS watches ias.xml and picks up the change on its own - no service restart needed." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
function Invoke-EditNPSPolicyConditions {
    <#
    .SYNOPSIS
        Edits an EXISTING policy's conditions - Network Policy or Connection Request Policy, per
        -PolicyType (identical record schema, see NPSCore.ps1 module NOTES) - previously the only way
        to change a policy's conditions was delete + recreate. Wholesale replace (Set-NPSPolicyConditions),
        matching the same "recompute the full set" semantics already established for VSA
        re-processing, not a surgical single-condition edit.

    .DESCRIPTION
        Connection Request Policy conditions reuse Read-NPSConnectionRequestConditions - the EXACT
        same condition-collection loop the add wizard uses - pre-seeded with the policy's current
        conditions (add-only from there; start over with what you want, matching the wholesale-
        recompute philosophy rather than a per-entry add/remove UI).

        Network Policy conditions are structurally two distinct pieces (Client-IP-Address + AND/OR
        group SIDs, see New-NPSGroupConditionList) rather than one flat freeform list, so there's no
        equivalent single pre-seeded builder to reuse - the tech keeps or changes the Client-IP-
        Address, then re-enters the group-membership conditions fresh via Read-ANDConditionGroups
        (current ones are shown first for reference) - the same as a tech would re-derive them when
        adding a rule in the first place, just re-confirmed rather than assumed unchanged.

        Does NOT touch the RADIUS Profile/VSAs at all, even for a Network Policy whose group
        conditions changed - re-processing VSAs afterward (Invoke-ReprocessNPSVsaWizard) is a
        deliberately separate, explicit step, not auto-chained here.
    #>
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [Parameter(Mandatory)][ValidateSet('NetworkPolicy', 'ConnectionRequest')][string]$PolicyType,
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential,
        [string]$ShimPath
    )

    Write-NPSHeader "Edit Conditions"
    $summary = Get-NPSPolicySummary -Path $IASConfigPath -PolicyType $PolicyType
    $picked = Select-NPSPolicyFromSummary -Summary $summary -Prompt "Select a policy to edit conditions for, by number"
    if (-not $picked) { return }

    Write-Host ""
    Write-Host "Current conditions on '$($picked.Name)':" -ForegroundColor Cyan
    foreach ($c in $picked.Constraints) { Write-Host "  - $c" -ForegroundColor Gray }
    Write-Host ""

    if ($PolicyType -eq 'ConnectionRequest') {
        Write-NPSHeader "Conditions"
        $newConditions = Read-NPSConnectionRequestConditions -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath -StartingConditions $picked.Constraints
    } else {
        Write-NPSHeader "Client IP Address"
        $currentIpMatch = $picked.Constraints | Where-Object { $_ -match 'Client-IP-Address=([^"]+)' } | Select-Object -First 1
        $currentIp = if ($currentIpMatch -and $currentIpMatch -match 'Client-IP-Address=([^"]+)') { $Matches[1] } else { $null }
        $clientIP = $null
        if ($currentIp) {
            $keepIp = Read-Host "Keep the current Client-IP-Address ($currentIp)? (Y/N)"
            if ($keepIp -match '^[Yy]' -or [string]::IsNullOrWhiteSpace($keepIp)) { $clientIP = $currentIp }
        }
        if (-not $clientIP) { $clientIP = Select-NPSClientIP -IASConfigPath $IASConfigPath }
        while ([string]::IsNullOrWhiteSpace($clientIP)) { $clientIP = Read-Host "A Client-IP-Address is required" }

        Write-NPSHeader "Required Group Membership (AND / OR)"
        Write-Host "Re-enter the required group-membership condition(s) for this policy - shown above for reference." -ForegroundColor Cyan
        $req = Read-ANDConditionGroups -SideLabel "Access" -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath
        $newConditions = New-NPSGroupConditionList -ClientIPAddress $clientIP -AndGroupSidSets $req.SidSets
    }

    $added = @($newConditions | Where-Object { $picked.Constraints -notcontains $_ })
    $removed = @($picked.Constraints | Where-Object { $newConditions -notcontains $_ })
    $unchanged = @($newConditions | Where-Object { $picked.Constraints -contains $_ })

    Write-NPSHeader "Preview"
    $preview = Set-NPSPolicyConditions -Path $IASConfigPath -PolicyName $picked.Name -PolicyType $PolicyType -Conditions $newConditions -WhatIf

    Write-Host "Proposed conditions for '$($picked.Name)':"
    foreach ($c in $newConditions) { Write-Host "    - $c" -ForegroundColor Gray }
    Write-Host ""
    if ($added.Count -gt 0) { Write-Host "  + Added:     $($added -join ' | ')" -ForegroundColor Green }
    if ($removed.Count -gt 0) { Write-Host "  - Removed:   $($removed -join ' | ')" -ForegroundColor Red }
    if ($unchanged.Count -gt 0) { Write-Host "  = Unchanged: $($unchanged -join ' | ')" -ForegroundColor Gray }
    if ($added.Count -eq 0 -and $removed.Count -eq 0) {
        Write-Host "No change - the new condition set is identical to what's already there." -ForegroundColor Gray
        Read-Host "Press Enter to continue"
        return
    }
    if ($PolicyType -eq 'NetworkPolicy' -and $removed.Count -gt 0) {
        Write-Host ""
        Write-Host "Note: this rule's required group(s) changed - consider re-processing its VSAs" -ForegroundColor Yellow
        Write-Host "afterward (Option R) if the FortiGate group assignment should reflect this too." -ForegroundColor Yellow
    }
    Write-Host ""

    $confirm = Read-Host "Apply this to $IASConfigPath now? A timestamped backup will be made first. (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Cancelled - nothing changed." -ForegroundColor Gray; return }

    $result = Set-NPSPolicyConditions -Path $IASConfigPath -PolicyName $picked.Name -PolicyType $PolicyType -Conditions $newConditions
    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
    Write-Host "Backup: $($result.BackupPath)" -ForegroundColor Green
    Write-Host "NPS/IAS watches ias.xml and picks up the change on its own - no service restart needed." -ForegroundColor Green
}
