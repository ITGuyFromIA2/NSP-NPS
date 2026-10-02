@{
    RootModule        = 'NSP.NPS.psm1'
    ModuleVersion     = '0.1.1'
    GUID              = 'ef6a0414-fdce-4f6f-9045-ca152c56c7a8'
    Author            = 'Network Systems Plus'
    CompanyName       = 'Network Systems Plus'
    Copyright         = '(c) Network Systems Plus. All rights reserved.'
    Description       = 'Windows NPS (RADIUS) for NSP VPN deployments: install/authorize, NPS Extension for Entra MFA, RADIUS clients and templates, network and connection request policies, troubleshooting, hand-off to the IPSec Orchestrator, and the NPS Manager dashboard (Start-NSPNpsManager). Windows PowerShell 5.1 compatible.'

    # 5.1 is the floor for every NSP toolkit, and the module must import on a bare 5.1 host -
    # sibling NSP modules are loaded on first use (Private\Import-NSPToolkitModule.ps1), never
    # declared as RequiredModules.
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'ConvertTo-NSPNpsAnswers'
        'Get-NSPNpsStatus'
        'New-NSPNpsShim'
        'Start-NSPNpsManager'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('NSP', 'NPS', 'RADIUS', 'NetworkPolicyServer', 'VPN', 'MFA')
            ProjectUri   = 'https://github.com/ITGuyFromIA2/NSP-NPS'
            LicenseUri   = 'https://github.com/ITGuyFromIA2/NSP-NPS/blob/main/LICENSE'
            ReleaseNotes = 'https://github.com/ITGuyFromIA2/NSP-NPS/blob/main/CHANGELOG.md'
        }
    }
}