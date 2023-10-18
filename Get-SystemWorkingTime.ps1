function Get-SystemWorkingTime {
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [Alias("gswt")]
    Param(
        [int]
        $DaysBack = 1,

        [string]
        $ComputerName,

        [pscredential]
        $Credential
    )

    $filterDate = [datetime]::Parse( (Get-Date).AddDays(-$DaysBack).ToLongDateString() )

    #hybernation
    [xml]$xmlFilter = @"
<QueryList>
    <Query Id="0" Path="System">
        <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Kernel-Power' or @Name='Microsoft-Windows-Power-Troubleshooter'] and (EventID=1 or EventID=42) and TimeCreated[timediff(@SystemTime) &lt;= 604800000]]]</Select>
    </Query>
</QueryList>
"@

    $params = @{
        "FilterXML"   = $xmlFilter
        "ErrorAction" = "SilentlyContinue "
    }
    if ($ComputerName) { $params.Add("ComputerName", $ComputerName) }
    if ($Credential) { $params.Add("Credential", $Credential) }

    $Events = Get-WinEvent @params

    #reboots
    [xml]$xmlFilter = @"
<QueryList>
    <Query Id="0" Path="System">
        <Select Path="System">*[System[(EventID=13 or EventID=12) and TimeCreated[timediff(@SystemTime) &lt;= 604800000]]]</Select>
    </Query>
</QueryList>
"@
    $params['FilterXML'] = $xmlFilter

    $Events += Get-WinEvent @params

    $Events | Where-Object TimeCreated -ge $filterDate | Sort-Object TimeCreated | Select-Object MachineName, TimeCreated, @{n = "Action"; e = {
            switch ($_.Id) {
                1 { "Stanby - Resume" }
                42 { "Stanby - Start Sleep" }
                13 { "Shutdown" }
                12 { "Bootup" }
                Default { "Unknown" }
            }
        }
    }
}