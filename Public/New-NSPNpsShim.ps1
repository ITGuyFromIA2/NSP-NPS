function New-NSPNpsShim {
    <#
    .SYNOPSIS
        Writes a launcher script for NPS Manager - optionally carrying a client's RADIUS answers - to
        drop on the NPS server and run.

    .DESCRIPTION
        The launcher installs NSP.NPS (this version or newer) and the NSP modules it uses from the
        PowerShell Gallery, hands the answers to Start-NSPNpsManager once, blanks them from its own
        file (they include the RADIUS shared secret), and starts the dashboard. See New-NSPToolShim
        (NSP.ClientScripts).

    .PARAMETER Answers
        NPS answers (ConvertTo-NSPNpsAnswers output), a hashtable, or a JSON string. Optional.

    .PARAMETER ClientAnswers
        A ClientAnswers object or file instead of -Answers; converted with ConvertTo-NSPNpsAnswers.

    .PARAMETER Path
        Where to write the launcher (.ps1).

    .PARAMETER Company
        Shown in the launcher header; defaults to the answers' CompanyName.

    .PARAMETER GeneratedBy
        Shown in the launcher header, e.g. 'Orchestrator 4.1.0'.

    .PARAMETER Force
        Overwrite an existing file.

    .EXAMPLE
        New-NSPNpsShim -ClientAnswers 'C:\...\ClientAnswers\EXAMPLE.json' -Path C:\Temp\NPS-Manager.ps1
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Answers')]
    [OutputType([IO.FileInfo])]
    param(
        [Parameter(ParameterSetName = 'Answers')][object]$Answers,
        [Parameter(Mandatory, ParameterSetName = 'ClientAnswers')][object]$ClientAnswers,
        [Parameter(Mandatory)][string]$Path,
        [string]$Company,
        [string]$GeneratedBy,
        [switch]$Force
    )

    Import-NSPToolkitModule -Name NSP.ClientScripts -MinimumVersion 0.1.0
    if ($PSCmdlet.ParameterSetName -eq 'ClientAnswers') {
        $Answers = ConvertTo-NSPNpsAnswers -ClientAnswers $ClientAnswers
        if ($null -eq $Answers) { throw 'That client does not use RADIUS (AuthType is not RADIUS) - there is nothing for NPS Manager.' }
        if (-not $Answers.IsComplete) { Write-Warning 'These RADIUS answers are incomplete (placeholder FortiGate IP, or no secret or user group).' }
    }
    if ($Answers -is [string]) {
        try { $Answers = ConvertFrom-Json -InputObject $Answers -ErrorAction Stop }
        catch { throw "-Answers is not valid JSON: $($_.Exception.Message)" }
    }
    if (-not $Company -and $Answers) {
        $Company = if ($Answers -is [Collections.IDictionary]) { [string]$Answers['CompanyName'] } elseif ($Answers.PSObject.Properties['CompanyName']) { [string]$Answers.CompanyName } else { '' }
    }

    $version = Get-NSPNpsModuleVersion
    $shim = @{
        ToolName             = 'NPS Manager'
        ModuleName           = 'NSP.NPS'
        ModuleMinimumVersion = $version
        EntryFunction        = 'Start-NSPNpsManager'
        Modules              = @(
            @{ Name = 'NSP.Console'; MinimumVersion = '0.1.2' }
            @{ Name = 'NSP.Toolkit'; MinimumVersion = '0.1.0' }
            @{ Name = 'NSP.NPS'; MinimumVersion = $version }
        )
        Path                 = $Path
        Force                = $Force
    }
    if ($null -ne $Answers) { $shim['SeedAnswers'] = $Answers }
    if ($Company) { $shim['Company'] = $Company }
    if ($GeneratedBy) { $shim['GeneratedBy'] = $GeneratedBy }

    if ($PSCmdlet.ShouldProcess($Path, 'Write NPS Manager launcher')) {
        New-NSPToolShim @shim -Confirm:$false
    }
}
