
function Get-WhoIs {
    <#
    .Synopsis
        Does a raw WHOIS query and returns the results

    .DESCRIPTION
        Does a raw WHOIS query and returns the results

    .Example
        PS C:\> Get-Whois github.com

        The simplest whois search

    .Example
        PS C:\> Get-Whois github.com -NoForward

        Returns the partial results you get when you don't follow forwarding to a new whois server

    .Example
        PS C:\> Get-Whois "domain google.com"

        Shows an example of sending a command as part of the search.
        This example does a search for an exact domain (the "domain" command works on crsnic.net for .com and .net domains)

        The google.com domain has a lot of look-alike domains, the least offensive ones are actually Google's domains (like "GOOGLE.COM.BR"), but in general, if you want to look up the actual "google.com" you need to search for the exact domain.

    .Example
        PS C:\> Get-Whois "129.21.1.82" -server whois.arin.net

        Does an ip lookup at arin.net

    .NOTES
        AUTHOR:     Andreas Bellstedt
        VERSION:    1.0.0
        DATE:       2023-11-18
        KEYWORDS:   WHOIS, domain lookup, ip lookup

        Future development should look at http://cvs.savannah.gnu.org/viewvc/jwhois/jwhois/example/jwhois.conf?view=markup

    .LINK
        https://github.com/AndiBellstedt

    #>
    [CmdletBinding()]
    [Alias("whois")]
    param(
        # The query to send to WHOIS servers
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("Domain", "Query", "Uri")]
        [string]
        $Name,

        # A specific whois server to search
        [Alias("Registry")]
        [string]
        $Server,

        # Disable forwarding to new whois servers
        [switch]
        $NoForward,

        # Return the raw results from the whois server instead of parsing the output into a powershell object
        [switch]
        $Raw

    )

    begin {
        [int]$maxRequery = 3

        if (-not $Server) { $Server = "whois.iana.org." }
    }

    process {
        foreach ($query in $Name) {
            $query = $query.Trim()

            # check for ip address as a query
            if ($query -match "(?:\d{1,3}\.){3}\d{1,3}" -or $query -match '^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$') {
                Write-Verbose "Query '$($query) is a IP lookup"

                if ($query -notmatch " ") {
                    $query = "n $query"
                }

                if (-not $Server) {
                    $Server = "whois.arin.net"
                    Write-Verbose "No server specified, using $($Server)"
                }
            }

            # do lookup
            do {
                Write-Verbose "Connecting to $($Server)"
                $tcpClient = [System.Net.Sockets.TcpClient]::new($Server, 43)

                if ($tcpClient) {
                    try {
                        $stream = $tcpClient.GetStream()

                        Write-Verbose "Sending Query: $query"
                        $data = [System.Text.Encoding]::Ascii.GetBytes( $query + "`r`n" )
                        $stream.Write($data, 0, $data.Length)

                        Write-Verbose "Reading Response:"
                        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII)

                        $result = $reader.ReadToEnd()

                        if ($result -match "(?i)whois:\s*(\S+)") {
                            $whoisServer = $Matches[1]
                            Write-Verbose "Recommended WHOIS server: $($whoisServer)"

                            if (-not $NoForward) {
                                Write-Verbose "Non-Authoritative results received from $($server), re-querying at $($whoisServer)"

                                # cache, in case we can't get an answer at the forwarder
                                if (-not $cachedResult) {
                                    $cachedResult = $result
                                    $cachedServer = $Server
                                }

                                $Server = $whoisServer
                                $query = ($query -split " ")[-1]

                                $maxRequery--
                            } else {
                                Write-Verbose "Non-Authoritative results received from '$($server)' but not going to forward to '$($whoisServer)' because -NoForward was specified"
                                $maxRequery = 0
                            }
                        } else {
                            $maxRequery = 0
                        }
                    } finally {
                        if ($stream) {
                            $stream.Close()
                            $stream.Dispose()
                        }
                        if ($tcpClient) {
                            $tcpClient.Close()
                            $tcpClient.Dispose()
                        }
                    }
                } else {
                    throw "No connection to $Server"
                }
            } while ($maxRequery -gt 0)

            if ($Raw) {
                $result

                if ($cachedResult) {
                    Write-Warning "Original Result from $($cachedServer):"
                    $cachedResult
                }
            } else {

                $outputHash = [ordered]@{}
                $outputHash.Add("Query", $query)
                $outputHash.Add("Server", $Server)

                $matchResults = [regex]::Matches($result, "(?'line'(.*):\s(.*))")
                foreach ($match in $matchResults) {
                    $name = $match.Groups[1].Value.trim('>').trim('<').trim()
                    $value = $match.Groups[2].Value.trim('>').trim('<').trim()

                    if ($outputHash.$name) {
                        $outputHash.$name = "$($outputHash.$name)`r`n$($value)"
                    } else {
                        $outputHash.add($name, $value)
                    }
                }

                $outputHash.Add("RawResult", $result)
                if ($cachedResult) {
                    $outputHash.Add("OriginalServer", $cachedServer)
                    $outputHash.Add("OriginalResult", $cachedResult)
                }

                [pscustomobject]$outputHash
            }
        }
    }

    end {

    }
}
