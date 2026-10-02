function Start-NSPNpsManager {
    <#
    .SYNOPSIS
        The NPS Manager dashboard: install/authorize NPS, the NPS Extension, importing a client's
        RADIUS definitions from the Orchestrator, RADIUS clients and templates, network and connection
        request policies, troubleshooting, and the hand-back to the Orchestrator.

    .DESCRIPTION
        Moved from the zip-era NPS-Manager.ps1; the menus are unchanged. Relaunches elevated if
        needed. Answers live in the NPS work folder (Get-NSPToolWorkPath -Tool NPS): a launcher's
        -SeedAnswersJson is merged there, and the AD server, AD username (never a password) and
        "always ask for AD credentials" flag that the zip-era tool wrote into its shim are saved
        there instead. The first start on a server offers to move the zip-era NPS-Manager's files
        into the work folder.

    .PARAMETER SeedAnswersJson
        Answers to merge in (plain JSON - see ConvertTo-NSPNpsAnswers - or an NPS Answers hand-off).

    .PARAMETER SeedOnly
        Merge -SeedAnswersJson and return without opening the dashboard.

    .PARAMETER IASConfigPath
        The live NPS configuration file.

    .PARAMETER ADServer
        A specific DC, for sites where AD auto-discovery is unreliable (defaults to the saved one).

    .PARAMETER ADUsername
        Pre-fills AD credential prompts (defaults to the saved one).

    .PARAMETER RequiresExplicitADCredentials
        Ask for AD credentials at startup (defaults to the saved setting).

    .PARAMETER NoElevate
        Do not relaunch elevated.

    .EXAMPLE
        Start-NSPNpsManager

    .EXAMPLE
        Start-NSPNpsManager -ADServer dc01.example.com
    #>
    [CmdletBinding()]
    param(
        [string]$SeedAnswersJson,
        [switch]$SeedOnly,
        [string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml",
        [string]$ADServer,
        [string]$ADUsername,
        [switch]$RequiresExplicitADCredentials,
        [switch]$NoElevate
    )

    Use-NSPNpsDependency

    if ($SeedOnly) {
        $null = Import-NSPToolSeedAnswers -Tool NPS -SeedAnswersJson $SeedAnswersJson
        return
    }

    if (-not $NoElevate) {
        $manifest = (Join-Path $script:ModuleRoot 'NSP.NPS.psd1').Replace("'", "''")
        $relaunch = "Import-Module '$manifest'; Start-NSPNpsManager"
        if ($PSBoundParameters.ContainsKey('IASConfigPath')) { $relaunch += " -IASConfigPath '$($IASConfigPath.Replace("'", "''"))'" }
        if ($PSBoundParameters.ContainsKey('ADServer')) { $relaunch += " -ADServer '$($ADServer.Replace("'", "''"))'" }
        if ($PSBoundParameters.ContainsKey('ADUsername')) { $relaunch += " -ADUsername '$($ADUsername.Replace("'", "''"))'" }
        if ($RequiresExplicitADCredentials) { $relaunch += ' -RequiresExplicitADCredentials' }
        if (Invoke-NSPElevated -Command $relaunch -NoExit) { return }
    }

    $saved = Import-NSPToolSeedAnswers -Tool NPS -SeedAnswersJson $SeedAnswersJson

    # First start on this server: offer to bring over what the zip-era NPS-Manager left behind.
    $marker = Join-Path (Get-NSPToolWorkPath -Tool NPS -Create) '.legacy-checked'
    if (-not (Test-Path -LiteralPath $marker)) {
        try {
            $summary = Move-NSPToolLegacyData -Tool NPS
            if ($summary.Found) { $saved = Get-NSPToolAnswers -Tool NPS; Read-Host "`nPress Enter to continue" | Out-Null }
        } catch { Write-Warning "Old NPS-Manager files could not be checked: $($_.Exception.Message)" }
        Set-Content -LiteralPath $marker -Value (Get-Date -Format 's')
    }

    # The zip-era script kept these as script-level variables that its functions read and update
    # ($script:ADServer = ...). Same here, in module scope: the parameters (or the saved answers) are
    # copied into $script:, then the locals are removed so every later $ADServer / $IASConfigPath /
    # ... below resolves to the module-scope value the functions update, exactly as before.
    $savedValue = { param($Name) if ($saved -and $saved.PSObject.Properties[$Name]) { $saved.$Name } else { $null } }
    if (-not $PSBoundParameters.ContainsKey('ADServer') -and (& $savedValue 'NPSADServer')) { $ADServer = [string](& $savedValue 'NPSADServer') }
    if (-not $PSBoundParameters.ContainsKey('ADUsername') -and (& $savedValue 'NPSADUsername')) { $ADUsername = [string](& $savedValue 'NPSADUsername') }
    if (-not $RequiresExplicitADCredentials -and (& $savedValue 'NPSRequiresExplicitADCredentials')) { $RequiresExplicitADCredentials = [switch]$true }

    # Answers.json stands in for the zip-era shim path: Set-NPSShim* write their fields into it.
    $answersDir = Get-NSPToolWorkPath -Tool NPS -Kind Answers -Create
    $answersFile = Join-Path $answersDir 'Answers.json'
    if (-not (Test-Path -LiteralPath $answersFile)) { [IO.File]::WriteAllText($answersFile, '{}') }

    $script:IASConfigPath = $IASConfigPath
    $script:ADServer = $ADServer
    $script:ShimPath = $answersFile
    $script:BaseDir = $answersDir
    $script:NPSManagerVersion = Get-NSPNpsModuleVersion
    $script:NPSManagerVersionLabel = (Get-NSPToolVersionStatus -ToolKey 'NSP.NPS' -Version $script:NPSManagerVersion).Label
    $script:ADUsername = $ADUsername
    $script:RequiresExplicitADCredentials = [bool]$RequiresExplicitADCredentials
    Remove-Variable -Name IASConfigPath, ADServer, ADUsername, RequiresExplicitADCredentials -Scope Local
    Set-ConsoleFullScreen

    # ----- zip-era NPS-Manager.ps1 startup block (verbatim) -----
    # Set once a tech successfully authenticates to a specific DC via Invoke-NPSADFallbackPrompt (Option
    # 1, or Troubleshooting's "Test AD connectivity") - confirmed live (the maintainer) that the SAME credential
    # is needed for every AD-touching operation this session, not just the one check that first surfaced
    # the problem (the rule builder's wildcard group search hits the identical auth failure). Deliberately
    # NOT a script parameter (no plaintext-password-on-the-command-line) and NEVER written to disk -
    # session-only, same as $ADServer is persisted (into the shim) while a credential never is.
    $script:ADCredential = $null

    # Mirrors the -RequiresExplicitADCredentials switch into a script-scoped variable so the
    # Troubleshooting menu's toggle (Set-NPSShimRequiresExplicitADCredentials) can flip it mid-session and
    # have the menu's own "currently: Yes/No" display and this session's proactive-prompt behavior both
    # see the change immediately, not just future launches.
    $script:RequiresExplicitADCredentials = [bool]$RequiresExplicitADCredentials

    # Last-known-good username for this site (see $NPSADUsername / Set-NPSShimADUsername) - NEVER the
    # password. Only ever used to pre-fill Get-Credential prompts; updated below whenever a fallback/
    # required-credentials prompt actually captures a (possibly different) username, same "session
    # variable, threaded explicitly through every function that needs it" pattern as $script:ADServer.
    $script:ADUsername = $ADUsername

    # Proactive AD credential prompt for a client flagged as always needing it (see
    # $RequiresExplicitADCredentials above / Invoke-NPSRequiredCredentialsPrompt) - runs BEFORE the main
    # menu loop's first Get-NPSStatus call, so that very first status screen already reflects reality
    # instead of showing "Unknown" until the tech happens to visit Option 1 or Troubleshooting Tools.
    # Credentials are never saved to disk, so this still runs every launch even though $ADServer itself
    # (once learned) is not re-prompted for - see the function's own header for why.
    if ($script:RequiresExplicitADCredentials) {
        $requiredCredsResult = Invoke-NPSRequiredCredentialsPrompt -ADServer $ADServer -ShimPath $ShimPath -ADUsername $script:ADUsername
        if ($requiredCredsResult) {
            $script:ADServer = $requiredCredsResult.DCServer
            $script:ADCredential = $requiredCredsResult.Credential
            if ($requiredCredsResult.Username) { $script:ADUsername = $requiredCredsResult.Username }
        }
    }

    # ----- zip-era NPS-Manager.ps1 main menu loop (verbatim; 'exit 0' -> 'return') -----
    :MainMenu while ($true) {
        Write-NPSHeader "NPS Manager Dashboard  $script:NPSManagerVersionLabel"

        $status = Get-NPSStatus -IASConfigPath $IASConfigPath -ADServer $ADServer -ADCredential $ADCredential
        Show-NPSStatus -Status $status

        if ($status.IASConfigExists) {
            # Compact form only - see Show-NPSConfigSummary's -Compact notes for why the full per-rule
            # detail stays reserved for Troubleshooting -> 9 instead of every single redraw here.
            Show-NPSConfigSummary -IASConfigPath $IASConfigPath -Compact
            Write-Host ""
        }

        Write-Host "  1." -NoNewline -ForegroundColor Yellow
        Write-Host " Install / authorize the NPS Server"
        Write-Host "  2." -NoNewline -ForegroundColor Yellow
        Write-Host " Manage NPS Extension (install/update, uninstall, number matching override)"
        Write-Host "  3." -NoNewline -ForegroundColor Yellow
        Write-Host " Import Kickstart Definitions from Master Orchestrator"
        Write-Host "  4." -NoNewline -ForegroundColor Yellow
        Write-Host " Manage NPS Clients & Templates"
        Write-Host "  5." -NoNewline -ForegroundColor Yellow
        Write-Host " Manage NPS Rules"
        Write-Host "  6." -NoNewline -ForegroundColor Yellow
        Write-Host " Troubleshooting Tools"
        Show-TroubleshootingCategoryLinks
        Write-Host "  7." -NoNewline -ForegroundColor Yellow
        Write-Host " Hand back to the Orchestrator (NPS facts + ias.xml, secrets removed)"
        Write-Host "  Q." -NoNewline -ForegroundColor Yellow
        Write-Host " Quit"
        Write-Host ""
        $choice = Read-Host "Select an option"

        switch -Regex ($choice) {
            '^1$'    { Invoke-InstallAuthorizeNPS -ADServer $ADServer -ShimPath $ShimPath -ADCredential $ADCredential -ADUsername $ADUsername }
            '^2$'    { Invoke-ManageNPSExtension -IASConfigPath $IASConfigPath }
            '^3$'    {
                if (-not (Test-Path $IASConfigPath)) {
                    Write-Host "ias.xml not found at $IASConfigPath - install/authorize NPS first (option 1)." -ForegroundColor Red
                    Read-Host "Press Enter to return to the menu"
                } else {
                    # Every error path Invoke-ImportKickstartDefinitions already anticipates pauses on
                    # its own (see OrchestratorImport.ps1) - this try/catch is the defense-in-depth net
                    # for anything that ISN'T anticipated: an uncaught exception used to print, then
                    # vanish instantly under this loop's own next Write-NPSHeader (Clear-Host) before a
                    # tech had any chance to read it. Confirmed live (the maintainer, 2026-08-18): "errors out,
                    # but it flashes so quick I can't see the error."
                    try {
                        Invoke-ImportKickstartDefinitions -IASConfigPath $IASConfigPath -ADServer $ADServer -ADCredential $ADCredential -ScriptRoot $script:BaseDir -ShimPath $ShimPath
                    } catch {
                        Write-Host "`nUNEXPECTED ERROR: $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
                        Read-Host "Press Enter to return to the menu"
                    }
                }
            }
            '^4$'    {
                if (-not (Test-Path $IASConfigPath)) {
                    Write-Host "ias.xml not found at $IASConfigPath - nothing to manage yet." -ForegroundColor Red
                    Read-Host "Press Enter to return to the menu"
                } else {
                    Invoke-ManageNPSClientsMenu -IASConfigPath $IASConfigPath
                }
            }
            '^5$'    {
                if (-not (Test-Path $IASConfigPath)) {
                    Write-Host "ias.xml not found at $IASConfigPath - nothing to manage yet." -ForegroundColor Red
                    Read-Host "Press Enter to return to the menu"
                } else {
                    Invoke-ManageNPSRulesMenu -IASConfigPath $IASConfigPath -ADServer $ADServer -ADCredential $ADCredential -ShimPath $ShimPath
                }
            }
            '^6$'    { Invoke-TroubleshootingMenu -IASConfigPath $IASConfigPath -ADServer $ADServer -ShimPath $ShimPath -ADCredential $ADCredential -ADUsername $ADUsername }
            '^6[A-Za-z]$' {
                # "6a"-"6e" etc, straight from Show-TroubleshootingCategoryLinks' own dashboard row - same
                # first-seen category order/letter derivation as that function uses, so the two can never
                # silently drift apart.
                $letterIdx = [int][char]($choice.Substring(1, 1).ToLower()) - 97
                $troubleshootCategories = @(Get-NPSTroubleshootingActions | Select-Object -ExpandProperty Category -Unique)
                if ($letterIdx -ge 0 -and $letterIdx -lt $troubleshootCategories.Count) {
                    Invoke-TroubleshootingCategoryMenu -Category $troubleshootCategories[$letterIdx] -IASConfigPath $IASConfigPath -ADServer $ADServer -ShimPath $ShimPath -ADCredential $ADCredential -ADUsername $ADUsername
                } else {
                    Write-Host "Invalid selection." -ForegroundColor Yellow
                }
            }
            '^7$'    { Invoke-NPSMenuHandoff -IASConfigPath $IASConfigPath -ScriptRoot $script:BaseDir -Status $status }
            '^[Qq]$' { Write-Host "Goodbye." -ForegroundColor Gray; return }
            default  { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    }
}
