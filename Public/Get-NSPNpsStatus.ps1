function Get-NSPNpsStatus {
    <#
    .SYNOPSIS
        A snapshot of this server's NPS setup - role installed, registered in AD, ias.xml policy and
        client counts, NPS Extension installed and its certificate, number-matching override - the
        same facts the NPS Manager dashboard shows at the top. Read-only; usable from RMM.

    .PARAMETER IASConfigPath
        The NPS configuration file.

    .PARAMETER ADServer
        A specific DC for the "registered in AD" check.

    .PARAMETER ADCredential
        Credentials for that check, where the session's own can't reach AD.

    .EXAMPLE
        Get-NSPNpsStatus | Select-Object NPSRoleInstalled, ExtensionInstalled, PolicyCount
    #>
    [CmdletBinding()]
    param(
        [string]$IASConfigPath = "C:\Windows\System32\ias\ias.xml",
        [string]$ADServer,
        [System.Management.Automation.PSCredential]$ADCredential
    )
    $statusArgs = @{ IASConfigPath = $IASConfigPath }
    if ($ADServer) { $statusArgs['ADServer'] = $ADServer }
    if ($ADCredential) { $statusArgs['ADCredential'] = $ADCredential }
    Get-NPSStatus @statusArgs
}
