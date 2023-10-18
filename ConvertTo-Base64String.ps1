function ConvertTo-Base64String {
    <#
    .SYNOPSIS
        Convert plain text to base64 encoded string

    .DESCRIPTION
        Convert plain text to base64 encoded string

    .PARAMETER InputObject
        String to convert into base64

    .PARAMETER Encoding
        Encoding of the input string. Default is UTF8

    .NOTES
        Author: Andreas Bellstedt
        DateCreated: 2023-10-16

    .LINK
        https://github.com/AndiBellstedt/Helper-Functions

    .EXAMPLE
        ConvertTo-Base64String -InputObject "ConvertFrom-Base64String"

        Converts the string "ConvertFrom-Base64String" to "Q29udmVydEZyb20tQmFzZTY0U3RyaW5n"

    .EXAMPLE
        "ConvertFrom-Base64String" | ConvertFrom-Base64String -encoding UTF8

        Converts the string "ConvertFrom-Base64String" to "Q29udmVydEZyb20tQmFzZTY0U3RyaW5n"

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]]
        $InputObject,

        [Parameter(Mandatory = $false)]
        [ValidateSet("UTF8", "Unicode", "ASCII", "UTF32")]
        [String]
        $Encoding = "UTF8"
    )

    begin { }

    process {
        foreach ($string in $InputObject) {
            switch ($Encoding) {
                "UTF8" { [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($string)) }
                "Unicode" { [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($string)) }
                "ASCII" { [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($string)) }
                "UTF32" { [Convert]::ToBase64String([System.Text.Encoding]::UTF32.GetBytes($string)) }
            }
        }
    }

    end { }
}