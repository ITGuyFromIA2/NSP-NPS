<#
.SYNOPSIS
    Option 2 - download/install/configure/uninstall the NPS Extension for Azure MFA, plus prereq
    checks. Status display (installed?, cert, expiry) already lives in Get-NPSStatus/Show-NPSStatus
    (Modules\NPSCore.ps1 / NPS-Manager.ps1) - this module is the ACTION side (the maintainer's original
    spec, verified live against Microsoft's docs earlier this session, not re-guessed here):

        Download page (no stable direct-download URL - Download Center landing page only, confirmed
          live; Microsoft generates a single-use download.microsoft.com token URL via page JavaScript
          after the tech clicks through, so there's nothing fixed to hardcode):
          https://www.microsoft.com/en-us/download/details.aspx?id=54688
          -> click Download -> select "NpsExtnForAzureMfaInstaller.exe"
        The maintainer built a headless-Selenium automation (Samples\NPSExtension_FullyWorkable_Downloader.ps1)
        that drives that same click-through in a headless Edge/Chrome session, scrapes the generated
        token URL out of the resulting page source, then downloads natively via Invoke-WebRequest -
        adapted below (Invoke-NPSExtensionAutoDownload) as the preferred path when Selenium + a
        webdriver are available, falling back to Open-NPSExtensionDownloadPage's manual flow otherwise
        (or on any failure) - this remains inherently a bit fragile (depends on Microsoft's page
        structure/CSS selectors not changing), which is exactly why the manual fallback always stays
        available rather than being replaced outright.
        Prereqs: .NET Framework 4.7.2+, PowerShell 5.1+
        TLS: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Config script (installed by the .exe above):
          C:\Program Files\Microsoft\AzureMfa\Config\AzureMfaNpsExtnConfigSetup.ps1
        Uninstall: find + invoke the real UninstallString (confirmed design decision - not a
          hardcoded guess at the product's registry GUID, which could easily drift across extension
          versions; a wildcard DisplayName search is version-independent).

.DESCRIPTION
    Requires Modules\NPSCore.ps1 to already be dot-sourced (uses Get-NPSStatus).
#>

# ---------------------------------------------------------------------------
function Test-NPSExtensionPrereqs {
    <#
    .SYNOPSIS
        Checks the two documented prereqs for the NPS Extension installer: .NET Framework 4.7.2+ and
        PowerShell 5.1+.

    .DESCRIPTION
        .NET Framework version is read from the Release DWORD at
        HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full - 461808 is Microsoft's own documented
        minimum threshold for "4.7.2 or later" (461814 is the exact 4.7.2 release key; 461808 is the
        official comparison floor per Microsoft's version-detection docs, not a guessed number).
    #>
    $ndpPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    $release = $null
    if (Test-Path $ndpPath) {
        $release = (Get-ItemProperty -Path $ndpPath -Name Release -ErrorAction SilentlyContinue).Release
    }
    $dotNetOk = ($null -ne $release) -and ($release -ge 461808)

    $psOk = $PSVersionTable.PSVersion -ge [version]'5.1'

    return [pscustomobject]@{
        DotNetReleaseValue = $release
        DotNetOk           = $dotNetOk
        DotNetLabel        = if ($null -eq $release) { 'Not detected' } elseif ($dotNetOk) { ".NET 4.7.2+ (release $release)" } else { "Below 4.7.2 (release $release) - update required" }
        PSVersion           = $PSVersionTable.PSVersion
        PSOk                = $psOk
        AllOk               = $dotNetOk -and $psOk
    }
}

# ---------------------------------------------------------------------------
# Session-lifetime cache for Get-NPSExtensionUninstallInfo, ON TOP OF the fast-scan rewrite below -
# belt and suspenders: Get-NPSStatus calls this on every status computation, which runs on every
# dashboard menu redraw AND again inside Invoke-ManageNPSExtension's own redraw, so avoiding repeat
# work still matters even once each individual scan is fast. Only Clear-NPSExtensionUninstallInfoCache
# (called after install/uninstall actions that could actually change the answer) forces a fresh scan.
$script:NPSExtensionUninstallInfoCache = $null
$script:NPSExtensionUninstallInfoCached = $false

function Get-NPSExtensionUninstallInfo {
    <#
    .SYNOPSIS
        Finds the NPS Extension's real Programs-and-Features uninstall entry by DisplayName pattern
        (NOT a hardcoded product GUID, which could easily differ across extension versions/updates) -
        searches both the native and Wow6432Node Uninstall registry hives. Returns $null if not found
        (that's a normal, expected outcome - not an error - for a machine where it's simply not
        installed via MSI, e.g. if HKLM:\SOFTWARE\Microsoft\AzureMfa exists from a manual/partial setup).

        Uses raw Microsoft.Win32.Registry APIs (GetSubKeyNames + a single targeted GetValue per
        subkey), NOT Get-ItemProperty against a wildcarded path - confirmed live (the maintainer) that the
        wildcard-expansion approach (which reads EVERY property of EVERY installed program's
        Uninstall subkey through PowerShell's registry provider) measured 1.2-1.5 SECONDS on a
        machine with ~550 installed-software entries, and was still hanging the dashboard's very
        first status check on the maintainer's real server (session-caching alone doesn't help a cold first
        call). The raw-API rewrite measured 25x faster (~50ms) for the identical result on the same
        machine - reads only subkey names (cheap) plus one value (DisplayName) per subkey, versus
        every property PowerShell's provider round-trips for each entry.

        Cached for the session on top of that - see the module-scoped cache notes above. Pass -Force
        to bypass the cache and re-scan (e.g. right after an uninstall you just ran, before the cache
        would naturally be invalidated).
    #>
    param([switch]$Force)

    if ($script:NPSExtensionUninstallInfoCached -and -not $Force) {
        return $script:NPSExtensionUninstallInfoCache
    }

    $hives = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $result = $null
    foreach ($hivePath in $hives) {
        $hiveKey = $null
        try {
            $hiveKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($hivePath)
            if (-not $hiveKey) { continue }
            foreach ($subKeyName in $hiveKey.GetSubKeyNames()) {
                $subKey = $null
                try {
                    $subKey = $hiveKey.OpenSubKey($subKeyName)
                    if (-not $subKey) { continue }
                    $displayName = $subKey.GetValue('DisplayName')
                    if ($displayName -and ($displayName -like '*NPS Extension*' -or $displayName -like '*Azure Multi-Factor*Authentication*NPS*')) {
                        $result = [pscustomobject]@{
                            DisplayName          = $displayName
                            DisplayVersion       = $subKey.GetValue('DisplayVersion')
                            UninstallString      = $subKey.GetValue('UninstallString')
                            QuietUninstallString = $subKey.GetValue('QuietUninstallString')
                            RegistryPath         = "HKLM:\$hivePath\$subKeyName"
                        }
                        break
                    }
                } finally {
                    if ($subKey) { $subKey.Dispose() }
                }
            }
        } catch {
            # Best-effort, same as the old -ErrorAction SilentlyContinue behavior - a permission
            # issue or transient registry error on one hive shouldn't abort the whole lookup.
        } finally {
            if ($hiveKey) { $hiveKey.Dispose() }
        }
        if ($result) { break }
    }
    $script:NPSExtensionUninstallInfoCache = $result
    $script:NPSExtensionUninstallInfoCached = $true
    return $result
}

# ---------------------------------------------------------------------------
function Clear-NPSExtensionUninstallInfoCache {
    <#
    .SYNOPSIS
        Invalidates Get-NPSExtensionUninstallInfo's session cache - call after any action that could
        actually change whether/how the extension shows up in Programs and Features (install,
        update, uninstall). Cheap/safe to call even when nothing changed; the next
        Get-NPSExtensionUninstallInfo call just re-scans once.
    #>
    $script:NPSExtensionUninstallInfoCached = $false
    $script:NPSExtensionUninstallInfoCache = $null
}

# ---------------------------------------------------------------------------
function Invoke-NPSExtensionUninstall {
    <#
    .SYNOPSIS
        Actually runs the uninstall, and VERIFIES it worked afterward rather than assuming success
        from the invoking process merely exiting - confirmed live (the maintainer) that a naive
        "Start-Process cmd.exe /c $UninstallString" could report success without actually removing
        anything.

    .DESCRIPTION
        Two things fixed vs. the naive approach:
          - Runs the uninstaller DIRECTLY (Start-Process -FilePath <exe> -ArgumentList <args>), not
            wrapped in "cmd.exe /c <string>". Wrapping through cmd is fragile for exactly the strings
            these commonly are - an MSI UninstallString like 'MsiExec.exe /X{GUID}' or a quoted EXE
            path with its own arguments - Start-Process's own array-based -ArgumentList quoting can
            disagree with how cmd.exe re-parses a single already-quoted string handed to it, silently
            producing a no-op or a differently-scoped command than intended.
          - MSI-based UninstallStrings are detected (msiexec + a {GUID}) and run with /qn /norestart
            added explicitly (unattended - a UI-mode msiexec can otherwise block waiting for input
            that never comes in this context) and via msiexec.exe directly rather than parsing
            msiexec's own quoting.
          - QuietUninstallString is preferred over UninstallString when the registry entry provides
            one - already pre-built for unattended use by whoever authored the installer, more
            reliable than us guessing at silent flags for a generic EXE-based uninstaller.
          - After running, RE-CHECKS Get-NPSExtensionUninstallInfo (not just the exit code) and
            reports Verified=$true only if the Programs-and-Features entry is actually gone - the
            exit code alone isn't trustworthy enough to claim success against, given the above.
    #>
    param([Parameter(Mandatory)]$UninstallInfo)

    $commandString = if ($UninstallInfo.QuietUninstallString) { $UninstallInfo.QuietUninstallString } else { $UninstallInfo.UninstallString }
    $usedQuietVariant = [bool]$UninstallInfo.QuietUninstallString

    $msiMatch = [regex]::Match($commandString, 'msiexec(\.exe)?\b.*?(\{[0-9A-Fa-f\-]{36}\})', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $exitCode = $null
    try {
        if ($msiMatch.Success) {
            $productCode = $msiMatch.Groups[2].Value
            # Confirmed against Microsoft's own msiexec docs (e.g. their /fa example uses
            # "msiexec.exe /fa {GUID}") - /X and the product code are SEPARATE arguments joined by a
            # space, not one concatenated token. Concatenating them ("/X{GUID}") is malformed: msiexec
            # silently no-ops under /qn (all UI, including its own "invalid args" complaint, is
            # suppressed - so it reports exit 0 without touching anything) and shows the bare
            # usage/help screen under /passive instead (that screen is the command-line PARSER
            # failing, before /passive's install-progress UI even comes into play) - both confirmed
            # live (the maintainer) against this exact bug.
            $msiArgs = @("/X", $productCode, "/qn", "/norestart")
            Write-Host "Running: msiexec.exe $($msiArgs -join ' ')" -ForegroundColor Cyan
            $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
            $exitCode = $proc.ExitCode
        } else {
            # Split the leading executable (quoted or not) from its own arguments, rather than
            # re-quoting the whole string through cmd.exe.
            $parsed = [regex]::Match($commandString, '^\s*"([^"]+)"\s*(.*)$')
            if ($parsed.Success) {
                $exePath = $parsed.Groups[1].Value
                $exeArgs = $parsed.Groups[2].Value
            } else {
                $split = $commandString.Split(' ', 2)
                $exePath = $split[0]
                $exeArgs = if ($split.Count -gt 1) { $split[1] } else { '' }
            }
            Write-Host "Running: `"$exePath`" $exeArgs" -ForegroundColor Cyan
            $proc = if ($exeArgs) {
                Start-Process -FilePath $exePath -ArgumentList $exeArgs -Wait -PassThru -NoNewWindow
            } else {
                Start-Process -FilePath $exePath -Wait -PassThru -NoNewWindow
            }
            $exitCode = $proc.ExitCode
        }
    } catch {
        return [pscustomobject]@{ Verified = $false; ExitCode = $exitCode; UsedQuietVariant = $usedQuietVariant; Error = $_.Exception.Message }
    }

    Start-Sleep -Seconds 2   # Programs-and-Features registry cleanup can lag a moment behind the process exiting
    # -Force is NOT optional here - without it this would return the CACHED pre-uninstall result and
    # always report Verified=$false regardless of what actually happened, making this check useless.
    $stillPresent = Get-NPSExtensionUninstallInfo -Force
    return [pscustomobject]@{
        Verified          = ($null -eq $stillPresent)
        ExitCode          = $exitCode
        UsedQuietVariant  = $usedQuietVariant
        Error             = $null
    }
}

# ---------------------------------------------------------------------------
function Remove-NPSExtensionOrphanedConfig {
    <#
    .SYNOPSIS
        Removes HKLM:\SOFTWARE\Microsoft\AzureMfa when it's confirmed orphaned - the extension was
        genuinely uninstalled (no Programs-and-Features entry) but the uninstaller left this key
        behind, which otherwise makes Get-NPSStatus/this dashboard keep reporting stale
        installed/config state indefinitely. Refuses to touch it if Get-NPSExtensionUninstallInfo
        still finds a real install, so this can't be used to blow away a legitimately-installed
        extension's config by mistake.
    #>
    if (Get-NPSExtensionUninstallInfo) {
        throw "Refusing to remove HKLM:\SOFTWARE\Microsoft\AzureMfa - Programs and Features still shows the extension installed. Uninstall it properly first."
    }
    $path = 'HKLM:\SOFTWARE\Microsoft\AzureMfa'
    if (-not (Test-Path $path)) {
        return [pscustomobject]@{ Removed = $false; AlreadyAbsent = $true }
    }
    Remove-Item -Path $path -Recurse -Force
    return [pscustomobject]@{ Removed = $true; AlreadyAbsent = $false }
}

# ---------------------------------------------------------------------------
function Get-NPSInstalledEdgeVersion {
    <#
    .SYNOPSIS
        Reads the actually-installed Microsoft Edge browser's version from the exe's own file
        version info (Program Files or Program Files (x86)) - NOT
        HKLM:\SOFTWARE\Microsoft\Edge\BLBeacon's "version" value, which was confirmed EMPTY on a real
        test machine that otherwise has Edge installed (BLBeacon appears to only populate after Edge
        has actually run in a session - unreliable as a primary source). Returns $null if Edge isn't
        found at either standard path.
    #>
    $edgeExePaths = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    )
    $edgeExe = $edgeExePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $edgeExe) { return $null }
    return (Get-Item $edgeExe).VersionInfo.ProductVersion
}

# ---------------------------------------------------------------------------
function Test-NPSEdgeDriverVersionMatch {
    <#
    .SYNOPSIS
        Checks whether a webdriver executable's own reported version matches the installed Edge
        browser's MAJOR version - confirmed live (the maintainer) that a driver merely EXISTING isn't enough
        to trust: a stale driver (a leftover v79 - the very first Chromium-Edge release - was found
        sitting in a real Selenium assemblies folder) produced Selenium's own
        "session not created: Microsoft Edge version must be 79" failure, since it was never
        version-checked before being used, just detected as present.

        Runs "$DriverPath --version" and regex-extracts the version number, rather than trusting the
        driver file's own VersionInfo - confirmed live this works identically for both real
        msedgedriver.exe output ("Microsoft Edge WebDriver 151.0.4129.59 (...)") and a
        chromedriver.exe standing in for it ("ChromeDriver ..." - same numbering scheme, Chromium
        release cadence tracks closely enough between the two for automation purposes).

        Compares MAJOR version only (the first dot-segment) - that's the actual compatibility
        boundary Selenium's error message itself references ("version must be 79"), not an exact
        4-part match.
    #>
    param([Parameter(Mandatory)][string]$DriverPath)

    if (-not (Test-Path $DriverPath)) {
        return [pscustomobject]@{ Match = $false; Reason = "Driver not found at $DriverPath"; DriverVersion = $null; EdgeVersion = $null }
    }
    $edgeVersion = Get-NPSInstalledEdgeVersion
    if (-not $edgeVersion) {
        return [pscustomobject]@{ Match = $false; Reason = "Microsoft Edge not found - can't determine what version to compare against"; DriverVersion = $null; EdgeVersion = $null }
    }

    try {
        $versionOutput = & $DriverPath --version 2>&1 | Out-String
    } catch {
        return [pscustomobject]@{ Match = $false; Reason = "Could not run '$DriverPath --version' - $($_.Exception.Message)"; DriverVersion = $null; EdgeVersion = $edgeVersion }
    }
    $versionMatch = [regex]::Match($versionOutput, '\d+\.\d+\.\d+\.\d+')
    if (-not $versionMatch.Success) {
        return [pscustomobject]@{ Match = $false; Reason = "Could not parse a version number from driver output: $versionOutput"; DriverVersion = $null; EdgeVersion = $edgeVersion }
    }
    $driverVersion = $versionMatch.Value

    $driverMajor = $driverVersion.Split('.')[0]
    $edgeMajor = $edgeVersion.Split('.')[0]
    $isMatch = $driverMajor -eq $edgeMajor

    return [pscustomobject]@{
        Match          = $isMatch
        Reason         = if ($isMatch) { $null } else { "Driver is version $driverVersion (major $driverMajor), installed Edge is $edgeVersion (major $edgeMajor)" }
        DriverVersion  = $driverVersion
        EdgeVersion    = $edgeVersion
    }
}

# ---------------------------------------------------------------------------
function Test-NPSExtensionAutoDownloadCapability {
    <#
    .SYNOPSIS
        Checks whether headless auto-download (Invoke-NPSExtensionAutoDownload) has what it needs:
        the Selenium PowerShell module, and a webdriver executable (msedgedriver.exe or
        chromedriver.exe, the latter copy-renamed to stand in for the former - same trick
        NPSExtension_FullyWorkable_Downloader.ps1 uses) sitting in that module's assemblies folder
        AND actually version-matched to the installed Edge browser (see
        Test-NPSEdgeDriverVersionMatch - a driver merely existing isn't enough; a stale/mismatched
        one produces a cryptic Selenium "session not created" failure instead of a clear
        not-available result here). Informational/gating only - absence just means falling back to
        the manual download-page flow, never a hard failure.
    #>
    $seleniumModule = Get-Module -Name Selenium -ListAvailable | Select-Object -First 1
    if (-not $seleniumModule) {
        return [pscustomobject]@{ Available = $false; Reason = "Selenium PowerShell module not installed"; ModuleBase = $null; DriverPath = $null }
    }
    $assemblyFolder = Join-Path $seleniumModule.ModuleBase "assemblies"
    $driverPath = @(
        Join-Path $assemblyFolder "msedgedriver.exe"
        Join-Path $assemblyFolder "chromedriver.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $driverPath) {
        return [pscustomobject]@{ Available = $false; Reason = "No msedgedriver.exe/chromedriver.exe found in $assemblyFolder"; ModuleBase = $seleniumModule.ModuleBase; DriverPath = $null }
    }

    $versionCheck = Test-NPSEdgeDriverVersionMatch -DriverPath $driverPath
    if (-not $versionCheck.Match) {
        return [pscustomobject]@{ Available = $false; Reason = "Driver found but not usable: $($versionCheck.Reason)"; ModuleBase = $seleniumModule.ModuleBase; DriverPath = $driverPath }
    }
    return [pscustomobject]@{ Available = $true; Reason = $null; ModuleBase = $seleniumModule.ModuleBase; DriverPath = $driverPath }
}

# ---------------------------------------------------------------------------
function Install-NPSExtensionAutoDownloadPrereqs {
    <#
    .SYNOPSIS
        Installs whatever Test-NPSExtensionAutoDownloadCapability found missing: the Selenium
        PowerShell module (from PSGallery) and/or a matching msedgedriver.exe (from Microsoft's own
        versioned driver downloads). Best-effort throughout - every failure is collected and returned
        rather than thrown, since the caller's fallback (manual download-page flow) doesn't need
        either of these to exist.

    .DESCRIPTION
        Driver version matching: msedgedriver.exe versions are tied to a specific installed Edge
        build - downloading a mismatched one is a known way to get cryptic "session not created"
        failures at runtime, not a same-version-family free-for-all. This reads the ACTUAL installed
        Edge executable's file version (Program Files or Program Files (x86)) rather than assuming a
        specific location or trusting HKLM:\SOFTWARE\Microsoft\Edge\BLBeacon's "version" value - that
        registry value was confirmed EMPTY on a real test machine that otherwise has Edge installed
        (BLBeacon appears to only populate after Edge has actually run in a session, unreliable as a
        primary source) - so the exe's own VersionInfo.ProductVersion is used instead, confirmed
        reliable on the same machine.

        Download URL confirmed live against Microsoft's own WebDriver page, not guessed:
        https://msedgedriver.microsoft.com/{version}/edgedriver_win64.zip - NOTE this is a different
        host (msedgedriver.microsoft.com) than some third-party writeups suggest
        (msedgedriver.azureedge.net) - verified directly against the current page content.
    #>
    param()

    $result = [pscustomobject]@{
        ModuleInstalled = $false
        DriverInstalled = $false
        ModuleBase      = $null
        Errors          = [System.Collections.Generic.List[string]]::new()
    }

    # --- Selenium PowerShell module ---
    $existingModule = Get-Module -Name Selenium -ListAvailable | Select-Object -First 1
    if ($existingModule) {
        $result.ModuleInstalled = $true
        $result.ModuleBase = $existingModule.ModuleBase
    } else {
        try {
            Write-Host "Installing Selenium PowerShell module from PSGallery..." -ForegroundColor Cyan
            # NuGet provider is required by Install-Module and often isn't present yet on a fresh
            # server - bootstrap it first so this fails with a clear message here rather than a
            # confusing one deeper inside Install-Module.
            if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction Stop | Out-Null
            }
            if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            }
            Install-Module -Name Selenium -Scope AllUsers -Force -AllowClobber -ErrorAction Stop

            $installedModule = Get-Module -Name Selenium -ListAvailable | Select-Object -First 1
            $result.ModuleInstalled = [bool]$installedModule
            $result.ModuleBase = $installedModule.ModuleBase
            if ($result.ModuleInstalled) { Write-Host "Selenium module installed." -ForegroundColor Green }
        } catch {
            $result.Errors.Add("Selenium module install failed: $($_.Exception.Message)")
        }
    }

    # --- Matching msedgedriver.exe ---
    if ($result.ModuleBase) {
        $assemblyFolder = Join-Path $result.ModuleBase "assemblies"
        $existingDriver = @(
            Join-Path $assemblyFolder "msedgedriver.exe"
            Join-Path $assemblyFolder "chromedriver.exe"
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1

        # A driver merely EXISTING isn't enough - confirmed live (the maintainer) that a stale v79 driver
        # (the very first Chromium-Edge release) was already sitting in a real assemblies folder,
        # and got treated as "fine" here before this version check existed, producing Selenium's own
        # cryptic "session not created: Microsoft Edge version must be 79" failure at actual use time
        # instead of being caught and replaced here.
        $driverIsUsable = $false
        if ($existingDriver) {
            $versionCheck = Test-NPSEdgeDriverVersionMatch -DriverPath $existingDriver
            if ($versionCheck.Match) {
                $driverIsUsable = $true
            } else {
                Write-Host "Existing driver at $existingDriver is not usable: $($versionCheck.Reason) - replacing it." -ForegroundColor Yellow
            }
        }

        if ($driverIsUsable) {
            $result.DriverInstalled = $true
        } else {
            try {
                Write-Host "Downloading a matching msedgedriver.exe..." -ForegroundColor Cyan
                if (-not (Test-Path $assemblyFolder)) { New-Item -ItemType Directory -Path $assemblyFolder -Force | Out-Null }

                # A REPLACED driver's file lock can linger briefly after its process exits (e.g. the
                # --version check Test-NPSEdgeDriverVersionMatch just ran against it moments ago, or
                # AV/EDR scanning the just-executed file) - confirmed live (the maintainer) that the Copy-Item
                # below can otherwise fail with "being used by another process" even though nothing
                # is deliberately still running it. Same kill-then-wait pattern already used in
                # Invoke-NPSExtensionAutoDownload, applied here too before attempting to overwrite.
                Stop-Process -Name "msedgedriver" -Force -ErrorAction SilentlyContinue
                Stop-Process -Name "chromedriver" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1

                $edgeVersion = Get-NPSInstalledEdgeVersion
                if (-not $edgeVersion) { throw "Microsoft Edge not found at either standard install path - can't determine which driver version to fetch." }
                Write-Host "Detected installed Edge version: $edgeVersion" -ForegroundColor Cyan

                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $driverZipUrl = "https://msedgedriver.microsoft.com/$edgeVersion/edgedriver_win64.zip"
                $tempZip = Join-Path ([System.IO.Path]::GetTempPath()) ("edgedriver_" + [guid]::NewGuid().ToString('N') + ".zip")
                $tempExtract = Join-Path ([System.IO.Path]::GetTempPath()) ("edgedriver_" + [guid]::NewGuid().ToString('N'))
                try {
                    Invoke-WebRequest -Uri $driverZipUrl -OutFile $tempZip -UseBasicParsing -ErrorAction Stop
                    Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force
                    $driverExe = Get-ChildItem -Path $tempExtract -Filter "msedgedriver.exe" -Recurse | Select-Object -First 1
                    if (-not $driverExe) { throw "Downloaded driver zip did not contain msedgedriver.exe." }

                    # Retry the overwrite a few times - even after Stop-Process + a delay, a file
                    # lock release can still be a hair slower than expected on a loaded/AV-scanned
                    # system; this is cheap insurance against exactly the race just described.
                    $destPath = Join-Path $assemblyFolder "msedgedriver.exe"
                    $copySucceeded = $false
                    $lastCopyError = $null
                    for ($attempt = 1; $attempt -le 3; $attempt++) {
                        try {
                            Copy-Item -Path $driverExe.FullName -Destination $destPath -Force -ErrorAction Stop
                            $copySucceeded = $true
                            break
                        } catch {
                            $lastCopyError = $_
                            if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
                        }
                    }
                    if (-not $copySucceeded) { throw $lastCopyError }

                    $result.DriverInstalled = $true
                    Write-Host "Driver installed to $destPath" -ForegroundColor Green
                } finally {
                    Remove-Item -Path $tempZip, $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
                }
            } catch {
                $result.Errors.Add("Driver download failed: $($_.Exception.Message)")
            }
        }
    }

    return $result
}

# ---------------------------------------------------------------------------
function Invoke-NPSExtensionAutoDownload {
    <#
    .SYNOPSIS
        Headless-browser download of NpsExtnForAzureMfaInstaller.exe with no tech intervention -
        adapted from the maintainer's Samples\NPSExtension_FullyWorkable_Downloader.ps1 (same technique,
        parameterized rather than hardcoded, plus the safety/error-handling changes noted below).
        Throws on any failure - callers should catch and fall back to
        Open-NPSExtensionDownloadPage's manual flow, never treat this as the only path.

    .DESCRIPTION
        Changes from the original script (kept deliberately minimal - proven-working automation,
        not something to rewrite from scratch):
          - -DestinationPath parameterized instead of a hardcoded "C:\Downloads" - avoids assuming a
            path exists/is writable on every NPS server, and lets Invoke-ManageNPSExtension control it.
          - TLS 1.3 is opportunistic, not assumed: older .NET Framework builds on older Windows Server
            releases don't define [Net.SecurityProtocolType]::Tls13 in the enum at all, which throws
            on the bare reference the original script uses unconditionally - wrapped in try/catch so
            this still runs correctly (TLS 1.2 only) on a server where that enum member doesn't exist.
          - Selenium/driver availability is checked by the caller first
            (Test-NPSExtensionAutoDownloadCapability) rather than failing deep inside a Selenium call
            with a less obvious error message.
    #>
    param([Parameter(Mandatory)][string]$DestinationPath)

    $capability = Test-NPSExtensionAutoDownloadCapability
    if (-not $capability.Available) { throw "Auto-download not available: $($capability.Reason)" }

    # "Available" only means the module MANIFEST is discoverable (Get-Module -ListAvailable) - the
    # [OpenQA.Selenium...] .NET types below aren't actually loaded into this session until it's
    # imported. Caught by testing this cold rather than assuming a caller already ran Import-Module.
    Import-Module Selenium -ErrorAction Stop

    $destDir = Split-Path -Path $DestinationPath -Parent
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

    $assemblyFolder = Split-Path -Path $capability.DriverPath -Parent
    # chromedriver standing in for msedgedriver, same trick as the original script - Selenium's Edge
    # driver classes work against chromedriver's wire protocol since both are Chromium-based, as long
    # as a file literally named msedgedriver.exe exists in the assemblies folder.
    if ((Split-Path -Path $capability.DriverPath -Leaf) -eq 'chromedriver.exe' -and -not (Test-Path (Join-Path $assemblyFolder 'msedgedriver.exe'))) {
        Copy-Item -Path $capability.DriverPath -Destination (Join-Path $assemblyFolder 'msedgedriver.exe') -Force -ErrorAction SilentlyContinue
    }

    Stop-Process -Name "msedgedriver" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "chromedriver" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $driverInstance = $null
    try {
        $edgeOptions = [OpenQA.Selenium.Edge.EdgeOptions]::new()
        $edgeArgs = New-Object System.Collections.ArrayList
        [void]$edgeArgs.Add("--headless=old")
        [void]$edgeArgs.Add("--window-size=1920,1080")
        [void]$edgeArgs.Add("--disable-blink-features=AutomationControlled")
        [void]$edgeArgs.Add("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0")

        $edgeOptionsDict = [System.Collections.Generic.Dictionary[string, object]]::new()
        $edgeOptionsDict.Add("args", $edgeArgs)
        $edgeOptions.AddAdditionalCapability("ms:edgeOptions", $edgeOptionsDict)

        # Explicit driver filename (2-arg overload), NOT CreateDefaultService($assemblyFolder) alone -
        # confirmed live (the maintainer) that the single-arg overload can fail looking for
        # "MicrosoftWebDriver.exe" (the legacy pre-Chromium Edge driver name) even when
        # msedgedriver.exe is genuinely present in the folder - it apparently has its own internal
        # default-name logic that isn't reliably "msedgedriver.exe" across machines/Selenium builds.
        # By this point msedgedriver.exe is guaranteed to exist here (either natively, or copy-
        # renamed from chromedriver.exe above), so name it explicitly and remove the ambiguity.
        $driverService = [OpenQA.Selenium.Edge.EdgeDriverService]::CreateDefaultService($assemblyFolder, 'msedgedriver.exe')
        $driverService.HideCommandPromptWindow = $true
        $driverInstance = [OpenQA.Selenium.Edge.EdgeDriver]::new($driverService, $edgeOptions)

        $targetUrl = "https://www.microsoft.com/en-us/download/details.aspx?id=54688"
        Write-Host "Navigating to Microsoft Download Center..." -ForegroundColor Cyan
        $driverInstance.Navigate().GoToUrl($targetUrl)
        $driverInstance.Manage().Timeouts().ImplicitWait = [System.TimeSpan]::FromSeconds(15)
        Start-Sleep -Seconds 4

        Write-Host "Opening download selections..." -ForegroundColor Cyan
        $downloadButton = $driverInstance.FindElement([OpenQA.Selenium.By]::CssSelector("button.dlcdetail__download-btn"))
        $downloadButton.Click()
        Start-Sleep -Seconds 3

        Write-Host "Selecting NpsExtnForAzureMfaInstaller.exe..." -ForegroundColor Cyan
        $checkboxes = $driverInstance.FindElements([OpenQA.Selenium.By]::CssSelector("input[type='checkbox']"))
        foreach ($checkbox in $checkboxes) {
            $checkboxId = $checkbox.GetAttribute("id")
            if ($checkboxId -like "*NpsExtnForAzureMfaInstaller.exe*") {
                [void]$driverInstance.ExecuteScript("if(!arguments[0].checked) { arguments[0].click(); }", $checkbox)
            } else {
                [void]$driverInstance.ExecuteScript("if(arguments[0].checked) { arguments[0].click(); }", $checkbox)
            }
        }
        Start-Sleep -Seconds 2

        Write-Host "Submitting to generate the download link..." -ForegroundColor Cyan
        $submitSelector = "(//button[text()='Download']) | //*[contains(@class, 'dlc-multi-file-submit')]"
        $submitBtn = $driverInstance.FindElement([OpenQA.Selenium.By]::XPath($submitSelector))
        [void]$driverInstance.ExecuteScript("arguments[0].click();", $submitBtn)

        # Critical: Microsoft's JS needs a moment to compile and populate the page with the link token.
        Start-Sleep -Seconds 5

        $pageSource = $driverInstance.PageSource
        if ($pageSource -notmatch 'https://download\.microsoft\.com/[^"\x27]*NpsExtnForAzureMfaInstaller\.exe[^"\x27]*') {
            throw "Could not locate the generated download URL in the page source - Microsoft's page layout may have changed."
        }
        $extractedUrl = $Matches[0]
        Write-Host "Found download URL." -ForegroundColor Green

        $driverInstance.Quit()
        $driverInstance.Dispose()
        $driverInstance = $null

        # Opportunistic TLS 1.3 - see .DESCRIPTION on why this can't be assumed to exist in the enum.
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        } catch {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }

        Write-Host "Downloading to $DestinationPath ..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $extractedUrl -OutFile $DestinationPath -UseBasicParsing -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

        if (-not (Test-Path $DestinationPath)) { throw "Download reported success but $DestinationPath doesn't exist." }
        return [pscustomobject]@{ Success = $true; DestinationPath = $DestinationPath; SourceUrl = $extractedUrl }
    } finally {
        if ($null -ne $driverInstance) {
            try { $driverInstance.Quit(); $driverInstance.Dispose() } catch {}
        }
    }
}

# ---------------------------------------------------------------------------
function Open-NPSExtensionDownloadPage {
    <#
    .SYNOPSIS
        Opens the Microsoft Download Center landing page in the default browser - there is no stable
        direct-download URL for the installer itself (verified live earlier this session), so this
        can't be more automated than "open the page and tell the tech what to click."
    #>
    $url = 'https://www.microsoft.com/en-us/download/details.aspx?id=54688'
    Write-Host "Opening $url ..." -ForegroundColor Cyan
    Write-Host "On that page: click Download, then select 'NpsExtnForAzureMfaInstaller.exe'." -ForegroundColor Cyan
    try {
        Start-Process $url
    } catch {
        Write-Host "Could not open a browser automatically - navigate to the URL above manually." -ForegroundColor Yellow
    }
}
