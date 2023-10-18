function ConvertFrom-Base64String {
    <#
    .SYNOPSIS
        Convert Base64 encoded string to plain text

    .DESCRIPTION
        Convert Base64 encoded string to plain text

    .PARAMETER InputObject
        Base64 encoded string to convert

    .PARAMETER Encoding
        Encoding of the input string. Default is UTF8

    .NOTES
        AUTHOR: Andreas Bellstedt
        VERSION: 1.0.0
        DATE: 2023-10-16
        KEYWORDS: Encode, Decode, Text, Transformation, Algorith, Base64

    .LINK
        https://github.com/AndiBellstedt/Helper-Functions

    .EXAMPLE
        ConvertFrom-Base64String -InputObject "Q29udmVydEZyb20tQmFzZTY0U3RyaW5n"

        Converts the string "Q29udmVydEZyb20tQmFzZTY0U3RyaW5n" to "ConvertFrom-Base64String"

    .EXAMPLE
        "Q29udmVydEZyb20tQmFzZTY0U3RyaW5n" | ConvertFrom-Base64String -encoding UTF8

        Converts the string "Q29udmVydEZyb20tQmFzZTY0U3RyaW5n" to "ConvertFrom-Base64String"

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [string[]]
        $InputObject,

        [Parameter(Mandatory=$false)]
        [ValidateSet("UTF8", "Unicode", "ASCII", "UTF32")]
        [String]
        $Encoding = "UTF8"
    )

    begin { }

    process {
        foreach($string in $InputObject) {
            switch ($Encoding) {
                "UTF8" { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($string)) }
                "Unicode" { [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($string)) }
                "ASCII" { [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($string)) }
                "UTF32" { [System.Text.Encoding]::UTF32.GetString([System.Convert]::FromBase64String($string)) }
            }
        }
    }

    end { }
}