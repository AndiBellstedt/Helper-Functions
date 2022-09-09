function Compare-ConfigFolder {
    <#
    .Synopsis
        Compare-ConfigTextFile

    .DESCRIPTION
        Compares configuration folders, for example of a apache installation for diffs

    .PARAMETER ServerA
        First Server

    .PARAMETER ServerB
        Second Server

    .PARAMETER Filter
        File filter for gathering files on ServerA

    .PARAMETER Folder
        The path to the folder to compare.
        The path has to be specified in UNC notation, so please use something like c$\...

    .EXAMPLE
        Compare-ConfigFolder -ServerA "SRV01" -ServerB "SRV02" -Filter "*.conf" -Folder "d$\apache\conf\", "d$\apache\conf\extra"

    .NOTES
        Author: Andreas Bellstedt

    .LINK
        https://github.com/AndiBellstedt/Helper-Functions
#>
    [CmdletBinding(
        ConfirmImpact = "Low",
        SupportsShouldProcess = $false,
        PositionalBinding = $true
    )]
    param(
        [Parameter(Mandatory = $true)]
        [String]
        $ServerA,

        [Parameter(Mandatory = $true)]
        [String]
        $ServerB,

        [Parameter(Mandatory = $true)]
        [String[]]
        $Folder,

        [String]
        $Filter = "*.conf"
    )

    foreach ($configDir in $Folder) {
        foreach ($fileName in (Get-ChildItem "\\$ServerA\$configDir" -Filter $Filter -File).Name) {
            Write-Host "Checking for diffs from $($ServerA) to $($ServerB) on file: $($fileName)" -ForegroundColor Yellow
            $test = Get-Content "\\$ServerA\$configDir\$fileName"
            $prod = Get-Content "\\$ServerB\$configDir\$fileName"

            $diff = $null
            $diff = Compare-Object -ReferenceObject $test -DifferenceObject $prod -CaseSensitive
            if ($diff) {
                write-host "Found diff - in $fileName"  -ForegroundColor Red
                $diff | ForEach-Object {
                    if ($_.SideIndicator -like "=>") {
                        write-host "$($ServerB): $($_.InputObject)" -ForegroundColor DarkRed
                    } else {
                        write-host "$($ServerA): $($_.InputObject)" -ForegroundColor DarkRed
                    }
                }
            }
        }
    }
}