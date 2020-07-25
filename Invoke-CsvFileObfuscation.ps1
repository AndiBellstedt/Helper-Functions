﻿function Invoke-CsvFileObfuscation {
    <#
    .SYNOPSIS
        Invokes obfuscation on a csv file

    .DESCRIPTION
        Invokes obfuscation on a csv file

    .PARAMETER Fullname
        Full path of the csv file to obfuscate

    .PARAMETER ReplaceHash
        Hashtable with text to replace in the hole file
        The csv file is handled as plain text file in the first place
        and does property based obfuscation in the second place.

        Place all text in a hashtable in the following manner:
        "TextToReplace" = "TextToInsertInstead"

        Attention! Please use ordered hashtables as input objects!
        [ordered]@{
            "TextToReplace" = "TextToInsertInstead"
        }

        The hashtable is processed top to down. So order sequence matters if you want to replace concrete phrases and single words.
        For example:
            "SomeSpecialText" = "NoSpecString"
        has to come first if there is another
            "Text" = "SomeOther"

    .PARAMETER PropertyToObfuscate
        Properties in the csv file where all letters should be obfuscated

        Attention!
        Values from the ReplaceHash will not be obfuscated and remains untouched!

    .PARAMETER PropertyToClear
        Properties in the csv with should be completely cleared and replaced by the text specified in parameter ClearingText

    .PARAMETER ClearingText
        Text replacement in properties specified in parameter PropertyToClear

    .PARAMETER Delimiter
        The delimiting character for the csv file.

    .PARAMETER Encoding
        The encoding of the csv file.

    .PARAMETER OutFile
        If specified a file next to the file specified in paramter Fullname is written.
        Name will be include "_obfuscated" in the filename.

    .PARAMETER ShowProgress

    .EXAMPLE
        PS C:\> Invoke-CsvFileObfuscation -Fullname "C:\data.csv" -ReplaceHash $hash -PropertyToObfuscate @("Identity", "Mailaddress") -PropertyToClear "description" -ShowProgress

        Invokes obfuscation on file data.csv
        $hash = {}

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]
        $Fullname,

        $ReplaceHash = ([ordered]@{
                "§SomeVerySecretText§" = "NewText"
                "§MoreVerySecretText§" = "NewText"
        }),

        $PropertyToObfuscate = @("Identity"),

        $PropertyToClear = @("SID"),

        $ClearingText = "***REMOVED FOR DATA PRIVACY REASON***",

        $Delimiter = ";",

        $Encoding = "Default",

        [switch]$OutFile,

        [switch]$ShowProgress
    )

    process {
        #region calculate variables
        # new filename
        $path = Split-Path $Fullname
        $filename = [string]::Join(".", (Split-Path $Fullname -Leaf).split(".")[0 .. ((Split-Path $Fullname -Leaf).split(".").count - 2) ])
        $extension = (Split-Path $Fullname -Leaf).split(".")[-1]
        $newname = "$($path)\$($filename)_objuscated.$($extension)"
        #endregion calculate variables


        #region custom function for obfuscation on text
        function Invoke-FlipCharacter {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true,
                    Position = 0,
                    ValueFromPipeline = $true)]
                [string]$Text
            )
            begin {}
            process {
                $_resultarray = for ($i1 = 0; $i1 -lt ([string]$text.Length); $i1++) {
                    if ( [char]::IsLetter([string]$text[$i1]) ) {
                        $byte = [byte][char][string]$text[$i1]

                        #0-9
                        if ($byte -in (48..57)) {
                            if ($byte -eq 48) {
                                $byte = 57
                            } elseif ($byte -eq 57) {
                                $byte = 48
                            } else {
                                $byte = $byte - 1
                            }
                        }

                        #A-Z
                        if ($byte -in (65..90)) {
                            if ($byte -eq 65) {
                                $byte = 90
                            } elseif ($byte -eq 90) {
                                $byte = 65
                            } else {
                                $byte = $byte - 1
                            }
                        }

                        #A-Z
                        if ($byte -in (97..122)) {
                            if ($byte -eq 97) {
                                $byte = 122
                            } elseif ($byte -eq 122) {
                                $byte = 97
                            } else {
                                $byte = $byte - 1
                            }
                        }

                        [char][byte]$byte
                    } else {
                        [string]$text[$i1]
                    }
                }
                [string]::Join("", $_resultarray)
            }
            end {}
        }
        #endregion custom function for obfuscation on text


        #region Main script
        $records = Import-Csv -Path $Fullname -Delimiter $Delimiter -Encoding $Encoding

        # progress
        if ($ShowProgress) {
            if ($records.count -lt 100) { $refreshInterval = 1 } else { $refreshInterval = [math]::Round($records.count / 100) }
        }
        $output = New-Object -TypeName "System.Collections.ArrayList"
        $i = 0
        foreach ($record in $records) {
            $csv = $record | ConvertTo-Csv -Delimiter ";" -NoTypeInformation

            # general text replacement
            foreach ($item in $ReplaceHash.Keys) {
                $csv[1] = $csv[1] -replace $item, $ReplaceHash[$item]
            }

            $record = $csv | ConvertFrom-Csv -Delimiter ";"

            # property obfuscation
            foreach ($prop in $PropertyToObfuscate) {
                [array]$matched = foreach ($item in $ReplaceHash.Values) {
                    $result = ""
                    if ($record.$prop -like $item) { $result = "like" }
                    if (-not $result -and $record.$prop -match $item) { $result = $item } else { $result = "" }
                    if ($result) { $result }
                }
                if ($matched) {
                    $parts = ($record.$prop -replace $matched[0], "|$($matched[0])|").split("|")
                    $part = $parts[0]
                    $_resultParts = foreach ($part in $parts) {
                        if ($part -and $part -notlike $matched[0]) {
                            Invoke-FlipCharacter -Text $part
                        } elseif ($part -and $part -like $matched[0]) {
                            $part
                        }
                    }
                    $record.$prop = [string]::Join("", $_resultParts)
                } else {
                    if ($record.$prop) {
                        $record.$prop = Invoke-FlipCharacter -Text $record.$prop
                    }
                }
            }

            # property obfuscation
            foreach ($prop in $PropertyToClear) {
                $record.$prop = $ClearingText
            }

            $null = $output.Add($record)

            if (($i -eq 0 -or $i % $refreshInterval) -eq 0) {
                Write-Progress -Activity "Process record" -Status "($($i) / $($records.count))" -PercentComplete ($i / $records.count * 100)
            }
            $i = $i + 1
        }

        if($OutFile) {
            $output | Export-Csv -Path $newname -Delimiter $Delimiter -Encoding $Encoding -NoTypeInformation
        } else {
            $output | ForEach-Object { $_ }
        }
        #endregion Main script
    }
}