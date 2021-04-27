function Get-WindowsOSBootCount {
    <#
    .SYNOPSIS
        Query the amount of system boots since installation of windows

    .DESCRIPTION
        Query the amount of system boots since installation of windows

    .PARAMETER ComputerName
        The name of the computer to query

    .PARAMETER Credential
        Explicit credential for connecting to computer

    .EXAMPLE
        PS C:\> Get-WindowsOSBootCount

        Return information from the local computer

    .EXAMPLE
        PS C:\> Get-WindowsOSBootCount -ComputerName SRV01

        Return information from the remote computer "SRV01"

    .EXAMPLE
        PS C:\> Get-WindowsOSBootCount -ComputerName SRV01 -Credential (Get-Credential)

        Return information from the remote computer "SRV01"

    #>
    [CmdletBinding(ConfirmImpact = 'Low', DefaultParameterSetName = 'Local')]
    param (
        [Parameter(ParameterSetName = 'Remoting', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [Alias('Host', "Hostname", "Computer", "Server", "ServerName")]
        [String[]]
        $ComputerName,

        [Parameter(ParameterSetName = 'Remoting')]
        [pscredential]
        $Credential
    )

    begin {
        $query = {
            $operatingsystem = Get-CimInstance -ClassName win32_operatingsystem
            [PSCustomObject]@{
                Name = $operatingsystem.CSName
                Caption = $operatingsystem.Caption
                BuildNumber = $operatingsystem.BuildNumber
                Version = $operatingsystem.Version
                InstallDate = $operatingsystem.InstallDate
                BootCount = [System.Runtime.InteropServices.Marshal]::ReadInt32(0x7ffe02C4)
            }
        }
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Local' {
                & $query
            }
            'Remoting' {
                foreach ($Computer in $ComputerName) {
                    $icmParam = @{
                        ComputerName = $ComputerName
                        ArgumentList = $query
                    }
                    if($Credential) { $icmParam.Add("Credential", $Credential)}
                    Invoke-Command @icmParam -ScriptBlock { [scriptblock]::Create($args[0]).Invoke() }
                }
            }
        }
    }

    end {
    }
}