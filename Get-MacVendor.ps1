function Get-MacVendor {
    <#
    .Synopsis
        Resolve MacAddresses To Vendors

    .Description
        This Function Queries The MacVendors API With Supplied MacAdderess And Returns Manufacturer Information If A Match Is Found

    .Parameter MacAddress
        MacAddress To Be Resolved

    .Example
        Get-MacVendor

    .Example
        Get-MacVendor -MacAddress 00:00:00:00:00:00

    .Example
        Get-NetAdapter | Get-MacVendor

    .Example
        Get-DhcpServerv4Lease -ScopeId $ScopeId | Get-MacVendor

    .NOTES
        AUTHOR:     Andreas Bellstedt
        VERSION:    1.0.0
        DATE:       2023-11-18
        KEYWORDS:   Network, MacAddress, Vendor lookup

    .LINK
        https://github.com/AndiBellstedt

#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidatePattern("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")]
        [alias('Mac', "ClientId")]
        [string[]]
        $MacAddress,

        [switch]
        $NoWait
    )

    begin {
        $baseUri = "https://api.macvendors.com/"
    }

    process {
        foreach ($mac in $MacAddress) {
            try {
                Write-Verbose "Sending lookup request for '$($mac)' to '$($baseUri)'"

                $url = $baseUri + [System.Web.HttpUtility]::UrlEncode($mac)
                $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop -Verbose:$false

                foreach ($item in $response) {
                    [pscustomobject]@{
                        MacAddress = $Mac
                        Vendor     = $item
                    }
                }
            } catch {
                Write-Error -Message "$Mac, $_"
            }

            if(-not $NoWait) { Start-Sleep -Seconds 1 }
        }
    }

    end {}
}
