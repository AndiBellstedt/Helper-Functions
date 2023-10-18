function Get-Hash {
    <#
    .SYNOPSIS
        Process text to hashes

    .DESCRIPTION
        This function processes text/strings to hash values of various algorithms.

    .PARAMETER InputObject
        The text/string to be processed to a hash value

    .PARAMETER Algorithm
        The algorithm used, to process the hash value

    .PARAMETER ToLower
        Tells the function to output the hash value with lower characters.
        Instead of "A375B2C1..." the output will be "a375b2c1..."

    .EXAMPLE
        Get-Hash -InputObject "Text"

        Get a SHA512 hash with capital characters of string "Text"

    .EXAMPLE
        Get-Hash -Text "Text" -Algorithm SHA256 -ToLower

        Get a SHA256 hash with lower characters of string "Text"

    .Notes
        AUTHOR: Andreas Bellstedt
        VERSION: 1.0.0
        DATE: 2023-10-16
        KEYWORDS: Hash, Algorith, Encode, Text, Transformation

    .LINK
        https://github.com/AndiBellstedt/Helper-Functions

    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    Param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [Alias("Text", "String", "Input", "Name")]
        [string]
        $InputObject,

        [Parameter(Position = 2)]
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [String]
        $Algorithm = "SHA512",

        [switch]
        $ToLower
    )

    begin {}

    process {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
        $hash = $hashAlgorithm.ComputeHash( [System.Text.Encoding]::UTF8.GetBytes($InputObject) )
        $hashOutput = [System.BitConverter]::ToString($hash)
        $output = $hashOutput.Replace('-', '')
        if ($ToLower) { $output.ToLower() } else { $output }
    }

    end {}
}


