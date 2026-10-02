<#
    Pester 5. The NSP.NPS module glue (the NPS engine itself is covered by Tests\Legacy). Sibling
    checkouts are loaded first; NSP_TOOLKIT_ROOT keeps the work folder in $TestDrive.
#>

BeforeAll {
    $toolkits = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path (Split-Path -Parent $toolkits) 'NSP-Bootstrap\NSP.Bootstrap.psd1') -Force -Global -ErrorAction Stop
    foreach ($m in 'NSP-Console\NSP.Console.psd1', 'NSP-Toolkit\NSP.Toolkit.psd1', 'NSP-ClientScripts\NSP.ClientScripts.psd1') {
        Import-Module (Join-Path $toolkits $m) -Force -Global -ErrorAction Stop
    }
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.NPS.psd1') -Force -ErrorAction Stop

    $script:Client = [pscustomobject]@{
        Company_Name = 'Example Co'; AuthType = 'RADIUS'; RADIUS_FGTInt_IP = '192.0.2.1'; RADIUS_Secret = 'not-a-real-secret'
        RADIUS_NPS_FGTName = 'EXAMPLE-FGT'; Auth_UserGroup_Name = 'IKEv2_Users'; Auth_UserGroup_Value = 'VPN_Staff'
        RadiusGroupPairs = @([pscustomobject]@{ Name = 'Staff' }); IPSecTunnelName = 'Example-IKEv2'
    }
}

AfterAll {
    Remove-Item Env:\NSP_TOOLKIT_ROOT -ErrorAction SilentlyContinue
    Remove-Module NSP.NPS -Force -ErrorAction SilentlyContinue
}

Describe 'NSP.NPS' {
    BeforeEach {
        $env:NSP_TOOLKIT_ROOT = Join-Path $TestDrive ('tk_' + [guid]::NewGuid().ToString('N'))
        Mock -ModuleName NSP.Toolkit Write-Host { }
        Mock -ModuleName NSP.NPS Write-Host { }
    }

    Context 'ConvertTo-NSPNpsAnswers' {
        It 'maps a RADIUS client and marks it complete' {
            $a = ConvertTo-NSPNpsAnswers -ClientAnswers $Client
            $a.CompanyName | Should -Be 'Example Co'
            $a.RADIUSFGTIntIP | Should -Be '192.0.2.1'
            $a.AuthUserGroupValue | Should -Be 'VPN_Staff'
            $a.IsComplete | Should -BeTrue
            @($a.PSObject.Properties.Name) | Should -Not -Contain 'FullPath'
        }
        It 'flags a placeholder IP as incomplete and ignores non-RADIUS clients' {
            $p = $Client.PSObject.Copy(); $p.RADIUS_FGTInt_IP = '10.x.x.1'
            (ConvertTo-NSPNpsAnswers -ClientAnswers $p).IsComplete | Should -BeFalse
            $l = $Client.PSObject.Copy(); $l.AuthType = 'Local'
            ConvertTo-NSPNpsAnswers -ClientAnswers $l | Should -BeNullOrEmpty
        }
        It 'reads a ClientAnswers file' {
            $f = Join-Path $TestDrive 'EXAMPLE.json'; $Client | ConvertTo-Json -Depth 5 | Set-Content $f
            (ConvertTo-NSPNpsAnswers -ClientAnswers $f).CompanyName | Should -Be 'Example Co'
        }
    }

    Context 'Launcher and seed answers' {
        It 'writes a launcher carrying the answers' {
            $p = Join-Path $TestDrive 'NPS-Manager.ps1'
            New-NSPNpsShim -ClientAnswers $Client -Path $p -GeneratedBy 'test' -Force | Should -BeOfType [IO.FileInfo]
            $text = Get-Content -LiteralPath $p -Raw
            $parseErrors = $null
            [Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$parseErrors) | Out-Null
            $parseErrors | Should -BeNullOrEmpty
            $text | Should -Match "EntryFunction\s+= 'Start-NSPNpsManager'"
            $text | Should -Match '"RADIUSFGTIntIP":\s+"192\.0\.2\.1"'
        }
        It 'refuses a non-RADIUS client' {
            $l = $Client.PSObject.Copy(); $l.AuthType = 'Local'
            { New-NSPNpsShim -ClientAnswers $l -Path (Join-Path $TestDrive 'x.ps1') } | Should -Throw '*does not use RADIUS*'
        }
        It 'merges seed answers with -SeedOnly, and the engine finds them' {
            $json = ConvertTo-NSPNpsAnswers -ClientAnswers $Client | ConvertTo-Json -Depth 5
            Start-NSPNpsManager -SeedAnswersJson $json -SeedOnly
            (Get-NSPToolAnswers -Tool NPS).RADIUSSecret | Should -Be 'not-a-real-secret'
            $dir = Get-NSPToolWorkPath -Tool NPS -Kind Answers
            InModuleScope NSP.NPS -Parameters @{ Dir = $dir } { param($Dir) (Get-NPSBakedInAnswers -ScriptRoot $Dir).CompanyName } | Should -Be 'Example Co'
        }
    }

    Context 'Settings the zip-era tool wrote into its shim' {
        It 'saves the AD server, username and credentials flag into Answers.json' {
            $file = Join-Path (Get-NSPToolWorkPath -Tool NPS -Kind Answers -Create) 'Answers.json'
            '{"CompanyName":"Example Co"}' | Set-Content $file
            InModuleScope NSP.NPS -Parameters @{ File = $file } {
                param($File)
                Set-NPSShimADServer -ShimPath $File -DCServer 'dc01.example.test'
                Set-NPSShimADUsername -ShimPath $File -Username 'EXAMPLE\tech'
                Set-NPSShimRequiresExplicitADCredentials -ShimPath $File -RequiresExplicitCredentials $true
            }
            $a = Get-NSPToolAnswers -Tool NPS
            $a.NPSADServer | Should -Be 'dc01.example.test'
            $a.NPSADUsername | Should -Be 'EXAMPLE\tech'
            $a.NPSRequiresExplicitADCredentials | Should -BeTrue
            $a.CompanyName | Should -Be 'Example Co'
        }
        It 'still refuses an unsafe DC name' {
            $file = Join-Path $TestDrive 'a.json'
            { InModuleScope NSP.NPS -Parameters @{ File = $file } { param($File) Set-NPSShimADServer -ShimPath $File -DCServer "dc'; rm" } } | Should -Throw '*valid hostname*'
        }
    }

    Context 'Hand-back' {
        It 'writes an NPS Response hand-off the Orchestrator Inbox can read' {
            $bytes = [Text.Encoding]::UTF8.GetBytes('<Root><Clients/></Root>')
            $sha = [Security.Cryptography.SHA256]::Create()
            $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', ''); $sha.Dispose()
            $response = [pscustomobject][ordered]@{
                SchemaVersion = 1; Tool = 'NPS-Manager'; ToolVersion = '0.1.0'; Generated = '2026-01-15T10:00:00'; Company = 'Example Co'
                ComputerName = 'EXAMPLE-NPS'; Domain = 'example.test'; RadiusClients = @()
                IasXml = [pscustomobject]@{ FileName = 'ias.xml'; SecretsRemoved = 0; Sha256 = $hash; ContentBase64 = [Convert]::ToBase64String($bytes) }
            }
            $out = Join-Path $TestDrive 'handoff'
            $path = InModuleScope NSP.NPS -Parameters @{ R = $response; O = $out } { param($R, $O) Write-NPSHandoffFile -Response $R -OutputDir $O }
            Split-Path -Leaf $path | Should -Be 'ExampleCo_NPS_Response.json'
            $h = Import-NSPHandoff -Path $path -Tool NPS -Kind Response
            $h.HashValid | Should -BeTrue
            $h.Payload.IasXml.Sha256 | Should -Be $hash
            $h.ComputerName | Should -Be 'EXAMPLE-NPS'
        }
    }
}

Describe 'Open-NSPOutputFolder' {
    BeforeEach {
        $script:SavedNoExplorer = $env:NSP_NO_EXPLORER
        $env:NSP_NO_EXPLORER = $null
        Mock -ModuleName NSP.NPS Start-Process { }
        Mock -ModuleName NSP.NPS Get-NSPDesktopUserSid { 'S-1-5-21-1-2-3-1001' }
        Mock -ModuleName NSP.NPS Grant-NSPFolderRead { }
        $script:Dir = Join-Path $TestDrive ('out_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $Dir | Out-Null
        $script:File = Join-Path $Dir 'Contoso_NPS_Response.json'
        '{}' | Set-Content -LiteralPath $File
    }
    AfterEach { $env:NSP_NO_EXPLORER = $script:SavedNoExplorer }

    It 'gives the desktop user read access, then opens Explorer on the hand-back folder' {
        InModuleScope NSP.NPS -Parameters @{ F = $File } { param($F) Open-NSPOutputFolder -Path $F }
        Should -Invoke -ModuleName NSP.NPS Grant-NSPFolderRead -Times 1 -Exactly -ParameterFilter { $Path -eq $Dir -and $Sid -eq 'S-1-5-21-1-2-3-1001' }
        Should -Invoke -ModuleName NSP.NPS Start-Process -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq 'explorer.exe' -and "$ArgumentList" -eq ('"{0}"' -f $Dir)
        }
    }
    It 'does nothing for a folder that was never written (dry run)' {
        InModuleScope NSP.NPS -Parameters @{ F = (Join-Path $TestDrive 'missing\x.json') } { param($F) Open-NSPOutputFolder -Path $F }
        Should -Invoke -ModuleName NSP.NPS Start-Process -Times 0
    }
    It 'does nothing with NSP_NO_EXPLORER=1' {
        $env:NSP_NO_EXPLORER = '1'
        InModuleScope NSP.NPS -Parameters @{ F = $File } { param($F) Open-NSPOutputFolder -Path $F }
        Should -Invoke -ModuleName NSP.NPS Start-Process -Times 0
    }
}

Describe 'Grant-NSPFolderRead' {
    It 'adds one read-only, inherited entry for that account (real ACL on a TestDrive folder)' {
        $dir = Join-Path $TestDrive ('acl_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        InModuleScope NSP.NPS -Parameters @{ D = $dir; S = $me } { param($D, $S) Grant-NSPFolderRead -Path $D -Sid $S }
        $ace = @((Get-Acl -LiteralPath $dir).Access | Where-Object { -not $_.IsInherited -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $me })
        $ace.Count | Should -Be 1
        "$($ace[0].FileSystemRights)" | Should -Match 'ReadAndExecute'
        "$($ace[0].FileSystemRights)" | Should -Not -Match 'Write|Modify|FullControl'
        "$($ace[0].InheritanceFlags)" | Should -Match 'ObjectInherit'
    }
    It 'warns instead of throwing when the folder is missing' {
        Mock -ModuleName NSP.NPS Write-Warning { }
        { InModuleScope NSP.NPS { Grant-NSPFolderRead -Path (Join-Path $TestDrive 'nope') -Sid 'S-1-5-18' } } | Should -Not -Throw
        Should -Invoke -ModuleName NSP.NPS Write-Warning -Times 1
    }
}