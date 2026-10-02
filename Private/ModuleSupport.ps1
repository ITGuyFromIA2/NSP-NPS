<#
    ModuleSupport.ps1 - NSP.NPS glue between the zip-era NPS Manager code (the other Private files,
    moved with only small, marked edits) and the module world: the work-folder answers file that
    replaced writing into the shim, and the module version.
#>

function Set-NPSToolAnswerField {
    # Sets one field in the NPS work folder's Answers.json (what Set-NPSShimADServer / -ADUsername /
    # -RequiresExplicitADCredentials write to now that the launcher no longer carries them). Never a
    # password - those are asked for fresh every launch, as before.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Field, [AllowNull()]$Value)
    $answers = $null
    if (Test-Path -LiteralPath $Path) {
        $raw = [IO.File]::ReadAllText($Path)
        if (-not [string]::IsNullOrWhiteSpace($raw)) { $answers = ConvertFrom-Json -InputObject $raw }
    }
    if ($null -eq $answers) { $answers = New-Object psobject }
    $answers | Add-Member -NotePropertyName $Field -NotePropertyValue $Value -Force
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $answers -Depth 20), (New-Object Text.UTF8Encoding($false)))
}

function Get-NSPNpsModuleVersion {
    return [string]$ExecutionContext.SessionState.Module.Version
}
