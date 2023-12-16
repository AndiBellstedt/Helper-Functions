Function Get-UserProcess {
    <#
    .SYNOPSIS
        Retrieves user processes from local or remote server/s

    .DESCRIPTION
        Retrieves user processes from local or remote server/s

    .PARAMETER ComputerName
        Name of computer to query against

    .PARAMETER Credential
        Credetial to use in query

    .NOTES
        Author: Andreas Bellstedt
        DateCreated: 03.04.2022

    .LINK
        https://github.com/AndiBellstedt/Helper-Functions

    .EXAMPLE
        Get-UserProcess -ComputerName "Server1"

        Will query all processes from currently logged in user sessions on 'server1'.
    #>
    [cmdletbinding(ConfirmImpact = 'low')]
    Param(
        [Parameter(
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            Position = 0
        )]
        [string[]]
        $ComputerName = $env:computername,

        [System.Management.Automation.PSCredential]
        $Credential
    )

    Begin {
        $queryScriptBlock = [ScriptBlock] {
            param (
                [string[]]
                $computer = $env:COMPUTERNAME,

                [System.Management.Automation.PSCredential]
                $Credential
            )

            $connectionParameter = @{}
            if ($computer -ne $env:computername) {
                $connectionParameter.Add("ComputerName", $computer)
                if ($Credential) { $connectionParameter.Add("Credential", $Credential) }
            }

            [Array]$processList = Get-WmiObject @connectionParameter -Query "SELECT * FROM win32_process where SessionId>0 AND NOT Name='csrss.exe' AND NOT Name='winlogon.exe' AND NOT Name='fontdrvhost.exe' AND NOT Name='LogonUI.exe' AND NOT Name='dwm.exe' AND NOT Name='conhost.exe'"
            $sys = Get-WmiObject @connectionParameter -Class Win32_OperatingSystem

            if ($processList) {
                foreach ($processGroup in ($processList | Group-Object SessionId)) {
                    $owner = $processGroup.group[0].GetOwner()
                    $ownerSID = $processGroup.group[0].GetOwnerSid()

                    foreach ($process in $processGroup.group) {
                        $outputObject = [PSCustomObject]@{
                            ComputerName                = $process.PSComputerName
                            SessionId                   = $process.SessionId
                            Name                        = $process.Name
                            UserName                    = $owner.User
                            Domain                      = $owner.Domain
                            UserSID                     = $ownerSID.Sid
                            Path                        = $process.Path
                            CommandLine                 = $process.CommandLine
                            Description                 = $process.Description
                            PhysicalMemoryUsedInMB      = [math]::Round( ($process.PrivatePageCount / 1MB), 1)
                            CreationDateTime            = $process.ConvertToDateTime($process.CreationDate)
                            Threads                     = $process.ThreadCount
                            Handles                     = $process.HandleCount
                            Priority                    = $process.Priority
                            ParentProcessId             = $process.ParentProcessId

                            SystemBootUpTime            = $sys.ConvertToDateTime($sys.LastBootUpTime)
                            OSName                      = $sys.Caption
                            OSArchitecture              = $sys.OSArchitecture
                            OSVersion                   = $sys.Version
                            PhysicalMemoryAvailableInMB = [math]::Round( ($sys.FreePhysicalMemory / 1MB), 1)
                        }
                        $outputObject
                    }
                }
            } elseif ($sys) {
                $outputObject = [PSCustomObject]@{
                    ComputerName                = $computer
                    SessionId                   = $null
                    Name                        = $null
                    UserName                    = $null
                    Domain                      = $null
                    UserSID                     = $null
                    Path                        = $null
                    CommandLine                 = $null
                    Description                 = $null
                    PhysicalMemoryUsedInMB      = $null
                    CreationDateTime            = $null
                    Threads                     = $null
                    Handles                     = $null
                    Priority                    = $null
                    ParentProcessId             = $null

                    SystemBootUpTime            = $sys.ConvertToDateTime($sys.LastBootUpTime)
                    OSName                      = $sys.Caption
                    OSArchitecture              = $sys.OSArchitecture
                    OSVersion                   = $sys.Version
                    PhysicalMemoryAvailableInMB = [math]::Round( ($sys.FreePhysicalMemory / 1MB), 1)
                }
                $outputObject
            } else {
                $outputObject = [PSCustomObject]@{
                    ComputerName                = $computer
                    SessionId                   = $null
                    Name                        = $null
                    UserName                    = $null
                    Domain                      = $null
                    UserSID                     = $null
                    Path                        = $null
                    CommandLine                 = $null
                    Description                 = $null
                    PhysicalMemoryUsedInMB      = $null
                    CreationDateTime            = $null
                    Threads                     = $null
                    Handles                     = $null
                    Priority                    = $null
                    ParentProcessId             = $null

                    SystemBootUpTime            = $null
                    OSName                      = $null
                    OSArchitecture              = $null
                    OSVersion                   = $null
                    PhysicalMemoryAvailableInMB = $null
                }
                $outputObject
            }
        }
    }

    Process {
        ForEach ($computer in $ComputerName) {
            $connectionParameter = @{ ComputerName = $computer }
            if ($Credential) { $parameter.Add("Credential", $Credential) }

            if ($computer -like $env:computername -or $computer -like "localhost" -or $computer -like ".") {

                $result = . $queryScriptBlock

            } else {

                if (-not (Resolve-DnsName -Name $computer)) {
                    Write-Error "Unable to resolve '$computer'"
                    continue
                }

                if (Test-NetConnection -ComputerName $computer -Port 5985 -InformationLevel Quiet -ErrorAction SilentlyContinue) {
                    # WSMAN/PowerShellRemoting
                    $result = Invoke-Command @connectionParameter -ScriptBlock $queryScriptBlock
                } else {
                    if (Test-NetConnection -ComputerName $computer -Port 135 -InformationLevel Quiet -ErrorAction SilentlyContinue) {
                        # use RPC/WMI
                        $result = . $queryScriptBlock
                    }
                }
            }

            if (-not $result) {
                Write-Warning "Unable to connect to '$computer'"
                $result = [PSCustomObject]@{
                    ComputerName                = $computer
                    SessionId                   = $null
                    Name                        = $null
                    UserName                    = $null
                    Domain                      = $null
                    UserSID                     = $null
                    Path                        = $null
                    CommandLine                 = $null
                    Description                 = $null
                    PhysicalMemoryUsedInMB      = $null
                    CreationDateTime            = $null
                    Threads                     = $null
                    Handles                     = $null
                    Priority                    = $null
                    ParentProcessId             = $null

                    SystemBootUpTime            = $null
                    OSName                      = $null
                    OSArchitecture              = $null
                    OSVersion                   = $null
                    PhysicalMemoryAvailableInMB = $null
                }
            }

            $result
        }
    }

    End {}
}
