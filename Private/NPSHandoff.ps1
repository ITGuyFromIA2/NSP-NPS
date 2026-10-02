<#
.SYNOPSIS
    NPS-Manager menu 7 - hand back to the Master Orchestrator (2026-09-30).

.DESCRIPTION
    Writes ONE file, <Company>_NPSResponse.json, for the tech to copy into the Orchestrator's
    Staging\<Abbrev>\ folder - the same one-file pattern as CA-Manager's <Company>_CAResponse.json.
    It carries this NPS server's facts (extension, number matching, RADIUS clients) and a copy of the
    live ias.xml for the Orchestrator's Resume Point D report (NSP.FortiGate -NpsConfig).

    The ias.xml copy has every secret removed first: RADIUS client shared secrets, remote RADIUS
    server authentication/accounting secrets, and any other *Secret / *Password / *Psk value. That's
    unconditional (the maintainer: "Remove the secrets"), and the written file is re-read and checked before
    menu 7 reports success. The report never reads those values, so nothing is lost.

    Read-only on this server: nothing in NPS is changed.

    Schema 1:
      SchemaVersion, Tool, ToolVersion, Generated, Company, ComputerName, Domain
      Nps           RoleInstalled, ExtensionInstalled, ExtensionVersion, NumberMatchingOverride,
                    NetworkPolicyCount, ConnectionRequestPolicyCount
      RadiusClients Name, Address, Enabled (no secrets)
      IasXml        FileName, LastWriteTime, SecretsRemoved, Sha256, ContentBase64
                    (the redacted file's exact bytes, in ias.xml's own encoding - UTF-16 LE + BOM)
#>

$script:NPSHandoffResponseSchema = 1

# Element names whose TEXT is a secret. Container elements of the same name (the schema section's
# <Accounting_Secret name=...><Properties>...) have child elements, not text, so they never match.
$script:NPSSecretElementPattern = '(?<open><(?<tag>[A-Za-z_]*(?:Secret|Password|Psk))\b[^>]*>)(?<value>[^<]*)(?<close></\k<tag>>)'
$script:NPSRedactedValue = '&lt;redacted&gt;'

# ---------------------------------------------------------------------------
function ConvertTo-NPSRedactedIasXml {
    <#
    .SYNOPSIS
        PURE. Replaces the text of every secret element in ias.xml content with <redacted>.
        Returns @{ Content; Count } - Count is how many non-empty secrets were removed.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RawContent)

    $count = @(Get-NPSUnredactedSecret -RawContent $RawContent).Count
    $content = [regex]::Replace($RawContent, $script:NPSSecretElementPattern, {
        param($m)
        $value = $m.Groups['value'].Value
        if ([string]::IsNullOrWhiteSpace($value) -or $value -eq $script:NPSRedactedValue) { return $m.Value }
        $m.Groups['open'].Value + $script:NPSRedactedValue + $m.Groups['close'].Value
    })
    [pscustomobject]@{ Content = $content; Count = $count }
}

# ---------------------------------------------------------------------------
function Get-NPSUnredactedSecret {
    <#
    .SYNOPSIS
        PURE. The element names that still hold a secret value (anything but blank or <redacted>).
        Empty when the content is clean. Names only - never the values.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RawContent)

    @(foreach ($m in [regex]::Matches($RawContent, $script:NPSSecretElementPattern)) {
        $value = $m.Groups['value'].Value
        if (-not [string]::IsNullOrWhiteSpace($value) -and $value -ne $script:NPSRedactedValue) { $m.Groups['tag'].Value }
    })
}

# ---------------------------------------------------------------------------
function New-NPSHandoffResponse {
    <#
    .SYNOPSIS
        Builds the Schema 1 hand-back object from an ias.xml path plus the dashboard's status facts.
        Throws if the redacted copy wouldn't parse or still holds a secret.
    .PARAMETER Status
        Get-NPSStatus output (optional - facts are left blank without it).
    .PARAMETER ExtensionVersion
        The NPS Extension's DisplayVersion (Get-NPSExtensionUninstallInfo), or blank.
    #>
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [Parameter(Mandatory)][string]$Company,
        $Status,
        [string]$ExtensionVersion,
        [string]$ToolVersion = $script:NPSManagerVersion,
        [datetime]$Now = (Get-Date)
    )

    $config = Read-NPSConfig -Path $IASConfigPath
    $redacted = ConvertTo-NPSRedactedIasXml -RawContent $config.RawContent
    $left = @(Get-NPSUnredactedSecret -RawContent $redacted.Content)
    if ($left.Count) { throw "Secrets still present after redaction ($(($left | Select-Object -Unique) -join ', ')) - nothing written." }
    try { [xml]$redacted.Content | Out-Null } catch { throw "The redacted ias.xml no longer parses - nothing written. $($_.Exception.Message)" }

    # Same encoding (and BOM) as the live file, so the copy is a normal ias.xml to any reader.
    [byte[]]$bytes = $config.Encoding.GetPreamble() + $config.Encoding.GetBytes($redacted.Content)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '') } finally { $sha.Dispose() }

    $clients = @(foreach ($c in @(Get-NPSClients -Path $IASConfigPath)) {
        [pscustomobject]@{ Name = "$($c.Name)"; Address = "$($c.IPAddress)"; Enabled = [bool]$c.Enabled }
    })

    $domain = try { [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name } catch { "$env:USERDNSDOMAIN" }
    [pscustomobject][ordered]@{
        SchemaVersion = $script:NPSHandoffResponseSchema
        Tool          = 'NPS-Manager'
        ToolVersion   = "$ToolVersion"
        Generated     = $Now.ToString('s')
        Company       = $Company
        ComputerName  = "$env:COMPUTERNAME"
        Domain        = $domain
        Nps           = [pscustomobject][ordered]@{
            RoleInstalled                = if ($Status) { [bool]$Status.NPSRoleInstalled } else { $null }
            ExtensionInstalled           = if ($Status) { [bool]$Status.ExtensionInstalled } else { $null }
            ExtensionVersion             = "$ExtensionVersion"
            NumberMatchingOverride       = if ($Status -and $null -ne $Status.OverrideNumberMatching) { "$($Status.OverrideNumberMatching)" } else { '' }
            NetworkPolicyCount           = if ($Status) { $Status.PolicyCount } else { $null }
            ConnectionRequestPolicyCount = if ($Status) { $Status.ConnectionRequestPolicyCount } else { $null }
        }
        RadiusClients = $clients
        IasXml        = [pscustomobject][ordered]@{
            FileName       = Split-Path $IASConfigPath -Leaf
            LastWriteTime  = (Get-Item -LiteralPath $IASConfigPath).LastWriteTime.ToString('s')
            SecretsRemoved = $redacted.Count
            Sha256         = $hash
            ContentBase64  = [Convert]::ToBase64String($bytes)
        }
    }
}

# ---------------------------------------------------------------------------
function Write-NPSHandoffFile {
    <#
    .SYNOPSIS
        Writes <stem>_NPSResponse.json into OutputDir, then re-reads it and confirms the embedded
        ias.xml decodes, matches its hash, and holds no secret. A file that fails is deleted and the
        function throws. Returns the path.
    #>
    param(
        [Parameter(Mandatory)]$Response,
        [Parameter(Mandatory)][string]$OutputDir
    )
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    # NSP.NPS: written as an NPS Response hand-off (NSP.Toolkit shared header, payload unchanged) -
    # <Company>_NPS_Response.json, for the Orchestrator's Staging\<Abbrev>\Inbox\. The zip-era
    # <stem>_NPSResponse.json is only written when NSP.Toolkit is unavailable.
    $useHandoff = [bool](Get-Command New-NSPHandoff -ErrorAction SilentlyContinue)
    if ($useHandoff) {
        $handoff = New-NSPHandoff -Kind Response -Tool NPS -Company "$($Response.Company)" -Payload $Response `
            -PayloadSchema ([int]$Response.SchemaVersion) -ToolVersion "$($Response.ToolVersion)" -GeneratedBy "NSP.NPS $($Response.ToolVersion)" `
            -ComputerName "$($Response.ComputerName)" -Domain "$($Response.Domain)"
        $path = (Export-NSPHandoff -Handoff $handoff -Directory $OutputDir).FullName
    } else {
        $stem = ("$($Response.Company)" -replace '[^A-Za-z0-9]', '')
        $path = Join-Path $OutputDir "${stem}_NPSResponse.json"
        $Response | ConvertTo-Json -Depth 6 | Set-Content -Path $path -Encoding UTF8
    }

    $problem = $null
    try {
        $check = if ($useHandoff) { (Import-NSPHandoff -Path $path -Tool NPS -Kind Response).Payload } else { Get-Content -Path $path -Raw | ConvertFrom-Json }
        [byte[]]$bytes = [Convert]::FromBase64String($check.IasXml.ContentBase64)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '') } finally { $sha.Dispose() }
        if ($hash -ne $check.IasXml.Sha256) { $problem = 'the embedded ias.xml does not match its hash' }
        else {
            $reader = New-Object System.IO.StreamReader((New-Object System.IO.MemoryStream(, $bytes)), [System.Text.Encoding]::UTF8, $true)
            try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
            $left = @(Get-NPSUnredactedSecret -RawContent $text)
            if ($left.Count) { $problem = "secrets still present ($(($left | Select-Object -Unique) -join ', '))" }
        }
    } catch { $problem = "it could not be read back: $($_.Exception.Message)" }

    if ($problem) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        throw "Hand-back check failed - $problem. The file was deleted."
    }
    $path
}

# ---------------------------------------------------------------------------
function Invoke-NPSMenuHandoff {
    <#
    .SYNOPSIS
        Menu 7. Asks the company (defaulting to the staged NPSAnswers.json) and output folder, writes
        the hand-back, and tells the tech where to copy it. Safe to re-run: the file is overwritten.
    #>
    param(
        [Parameter(Mandatory)][string]$IASConfigPath,
        [string]$ScriptRoot,
        $Status
    )
    Write-NPSHeader "Hand back to the Orchestrator"
    Write-Host "Writes <Company>_NPS_Response.json: this server's NPS facts and a copy of ias.xml with" -ForegroundColor Cyan
    Write-Host "every shared secret removed, for the Orchestrator's VPN access report (Resume Point D)." -ForegroundColor Cyan
    Write-Host "Nothing on this server is changed." -ForegroundColor Gray
    Write-Host ""

    if (-not (Test-Path -LiteralPath $IASConfigPath)) {
        Write-Host "ias.xml not found at $IASConfigPath - install/authorize NPS first (option 1)." -ForegroundColor Red
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    $baked = Get-NPSBakedInAnswers -ScriptRoot $ScriptRoot
    $defaultCompany = if ($baked -and $baked.CompanyName) { "$($baked.CompanyName)" } else { '' }
    $company = ''
    while (-not $company) {
        $prompt = if ($defaultCompany) { "Company name [$defaultCompany]" } else { "Company name (as in the Orchestrator)" }
        $company = ([string](Read-Host $prompt)).Trim()
        if (-not $company) { $company = $defaultCompany }
    }
    $stem = ($company -replace '[^A-Za-z0-9]', '')
    $defaultDir = if (Get-Command Get-NSPToolWorkPath -ErrorAction SilentlyContinue) { Get-NSPToolWorkPath -Tool NPS -Kind Responses } else { "C:\Admin\Handoff\$stem" }
    $outDir = ([string](Read-Host "Output folder [$defaultDir]")).Trim().Trim('"')
    if (-not $outDir) { $outDir = $defaultDir }

    try {
        if (-not $Status) { $Status = Get-NPSStatus -IASConfigPath $IASConfigPath }
        $ext = if (Get-Command Get-NPSExtensionUninstallInfo -ErrorAction SilentlyContinue) { Get-NPSExtensionUninstallInfo } else { $null }
        $response = New-NPSHandoffResponse -IASConfigPath $IASConfigPath -Company $company -Status $Status -ExtensionVersion $(if ($ext) { $ext.DisplayVersion } else { '' })
        $path = Write-NPSHandoffFile -Response $response -OutputDir $outDir
    } catch {
        Write-Host ""
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Read-Host "Press Enter to return to the menu" | Out-Null
        return
    }

    Write-Host ""
    Write-Host "Written: $path" -ForegroundColor Green
    Write-Host ("  ias.xml copy: {0} secret(s) removed, checked clean." -f $response.IasXml.SecretsRemoved) -ForegroundColor Gray
    Write-Host ("  RADIUS clients: {0}" -f (@($response.RadiusClients | ForEach-Object { "$($_.Name) ($($_.Address))" }) -join ', ')) -ForegroundColor Gray
    Write-Host ""
    Write-Host "Copy this one file to the Orchestrator machine, into Staging\<Abbrev>\Inbox\, then run" -ForegroundColor Cyan
    Write-Host "Resume Point D. Re-run this menu whenever the NPS policies change." -ForegroundColor Cyan
    Read-Host "Press Enter to return to the menu" | Out-Null
}
