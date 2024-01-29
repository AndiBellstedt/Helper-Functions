function Test-SslProtocol {
    <#
    .DESCRIPTION
        Outputs the SSL protocols that the client is able to successfully use to connect to a server.

    .PARAMETER ComputerName
        The name of the remote computer to connect to.

    .PARAMETER Port
        The remote port to connect to. The default is 443.

    .PARAMETER Protocol
        Specifies the SSL protocols to test.

    .PARAMETER AcceptInvalidCertificates
        Specifies whether the client accepts invalid certificates from the server.
        For example, if the server certificate is self-signed or if the server certificate is not trusted by the client.
        This should be considered as a security risk and is not used by default.

    .PARAMETER DisableCheckCertificateRevocation
        Specifies whether the client checks the certificate revocation list (CRL) for the server certificate.
        This should be considered as a security risk and is not used by default.

    .PARAMETER OutputCertificate
        Specifies whether the certificate is output in the result.

    .PARAMETER CertificateOutputPath
        Specifies the path to which the certificate is saved.
        This is considered as a debug option and is not used by default.

    .PARAMETER ClientCertificate
        Specifies the client certificate to use for authentication.

    .EXAMPLE
        PS C:\> Test-SslProtocol -ComputerName "www.google.com"

        Output shows the SSL protocols that the client is able to successfully use to connect to the server.

    .EXAMPLE
        PS C:\> Test-SslProtocol -ComputerName "192.168.0.1" -Port 8443 -Protocol "Tls12" -AcceptInvalidCertificates

        Checks if the client is able to successfully use the TLS 1.2 protocol to connect to the server on port 8443.
        The client accepts invalid/ selfsigned certificates from the server.

    .EXAMPLE
        PS C:\> Test-SslProtocol -ComputerName "www.google.com" -OutputCertificate

        Output shows the SSL protocols that the client is able to successfully use to connect to the server.
        As an addition the certificate is output in the result.

    .EXAMPLE
        PS C:\> "192.168.0.1", "192.168.0.2" | Test-SslProtocol -AcceptInvalidCertificates

        Checks if the clients is able to successfully use the SSL protocols to connect to the servers "192.168.0.1" & "192.168.0.2".
        The client accepts invalid/ selfsigned certificates from the server.

    .EXAMPLE
        PS C:\> "443", "8443" | Test-SslProtocol "192.168.0.1" -AcceptInvalidCertificates

        Checks if the clients is able to successfully use the SSL protocols to connect via port 443 & 8443 to the servers "192.168.0.1".
        The client accepts invalid/ selfsigned certificates from the server.

    .NOTES
        AUTHOR:     Andreas Bellstedt
        VERSION:    1.0.0
        DATE:       2023-11-25
        KEYWORDS:   SSL, TLS, security, network, protocol check

        Function is derived from Chris Duck (http://blog.whatsupduck.net - Copyright 2014)

    .LINK
        https://github.com/AndiBellstedt

    #>
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
        )]
        [Alias("CN", "Server", "IPAddress", "IP", "Host", "Computer", "ServerName")]
        [string[]]
        $ComputerName,

        [Parameter(
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true
        )]
        [Alias("P")]
        [int]
        $Port = 443,

        [ValidateSet("Ssl2", "Ssl3", "Tls", "Tls11", "Tls12", "Tls13" )]
        [string[]]
        $Protocol = ([System.Enum]::GetNames([System.Security.Authentication.SslProtocols]) | Where-Object { $_ -notin @("Default", "None") }),

        [switch]
        $AcceptInvalidCertificates,

        [switch]
        $DisableCheckCertificateRevocation,

        [System.Security.Cryptography.X509Certificates.X509CertificateCollection]
        $ClientCertificate,

        [switch]
        $OutputCertificate,

        [string]
        $CertificateOutputPath
    )

    begin {
        if ($CertificateOutputPath ) {
            if (-not (Test-Path -Path $CertificateOutputPath -PathType Container)) {
                throw "CertificateOutputPath '$CertificateOutputPath' does not exist."
            }
        }

        if($DisableCheckCertificateRevocation) {
            $checkCertificateRevocation = $false
        } else {
            $checkCertificateRevocation = $true
        }
    }

    process {
        :computer foreach ($computer in $ComputerName) {
            #region Initialize variables
            $protocolStatus = [Ordered]@{
                "ComputerName"       = $computer
                "Port"               = $Port
                "DnsNameList"        = $null
                "KeySize"            = $null
                "KeyAlgorithm"       = $null
                "SignatureAlgorithm" = $null
                "EnhancedKeyUsage"   = $null
                "NotBefore"          = $null
                "NotAfter"           = $null
            }

            $remoteCertificate = $null
            #endregion Initialize variables



            #region Test ssl protocols
            :protocols foreach ($protocolName in $Protocol) {
                # Open connection to the remote computer


                try {
                    # Create inital tcp connection
                    $socket = [System.Net.Sockets.Socket]::new([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                    $socket.Connect($computer, $Port)

                    # Create network stream
                    $netStream = [System.Net.Sockets.NetworkStream]::new($socket, $true)

                    # Create ssl connection
                    if ($AcceptInvalidCertificates) {
                        $sslStream = [System.Net.Security.SslStream]::new($netStream, $true, [System.Net.Security.RemoteCertificateValidationCallback] { $true })
                    } else {
                        $sslStream = [System.Net.Security.SslStream]::new($netStream, $true)
                    }

                    # Authenticate as client within the ssl connection
                    if ($ClientCertificate) {
                        $sslStream.AuthenticateAsClient($computer, $ClientCertificate, $protocolName, $checkCertificateRevocation)
                    } else {
                        $sslStream.AuthenticateAsClient($computer, $null, $protocolName, $checkCertificateRevocation)
                    }

                    # Check if there is already a certificate available from previous connection attempts
                    if (-not $remoteCertificate) {
                        # Convert the certificate from the data stream to a qualified X509Certificate2 object
                        $remoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslStream.RemoteCertificate
                    }

                    # Add the protocol result to the output
                    $protocolStatus.Add($protocolName, $true)

                } catch {
                    $errorRecord = $_
                    # Error handling - Errors occure differently in PowerShell 5 and 7
                    switch ($PSVersionTable.PSVersion.Major) {
                        "5" {
                            if (
                                $errorRecord.Exception.InnerException.ErrorCode -eq -2147467259 -or
                                $errorRecord.Exception.InnerException.InnerException.ErrorCode -eq -2147467259
                            ) {
                                # SSL/TLS error: The client and server cannot communicate, because they do not possess a common algorithm
                                # -->  server does not support this protocol
                                $protocolStatus.Add($protocolName, $false)
                            } else {
                                # Any other error occured. Possibly a certificate error, service connection error, etc.
                                Write-Error -ErrorRecord $errorRecord

                                # Do not output a result, but continue with next computer
                                continue computer
                            }
                        }

                        "7" {
                            if ($errorRecord.Exception.InnerException.InnerException.ErrorCode -eq -2147467259) {
                                # SSL/TLS error: The client and server cannot communicate, because they do not possess a common algorithm
                                # -->  server does not support this protocol
                                $protocolStatus.Add($protocolName, $false)
                            } else {
                                # Any other error occured. Possibly a certificate error, service connection error, etc.
                                Write-Error -ErrorRecord $errorRecord

                                # Do not output a result, but continue with next computer
                                continue computer
                            }
                        }

                        Default {
                            throw "Unsupported PowerShell version detected. Only PowerShell 5 and 7 are supported."
                        }
                    }
                } finally {
                    # Close connection to the computer
                    if($sslStream) { $sslStream.Close() }
                    if($netStream) { $netStream.Close() }
                    #$socket.Close()
                }
            }
            #endregion Test ssl protocols



            #region Prepare output
            if ($remoteCertificate) {
                # Output the certificate to file if path is specified
                if ($CertificateOutputPath) {
                    $bytes = $remoteCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    $base64 = [System.Convert]::ToBase64String($bytes)
                    $base64Lines = $base64 -split '(?<=\G.{64})'
                    $pem = "-----BEGIN CERTIFICATE-----`n$($base64Lines)`n-----END CERTIFICATE-----"
                    $pem | Set-Content "$($computer).crt"
                }

                # Check the public key if RSA or ECC
                if ($remoteCertificate.PublicKey.Key.KeySize) {
                    # RSA Key
                    $protocolStatus["KeySize"] = $remoteCertificate.PublicKey.Key.KeySize
                    $protocolStatus["KeyAlgorithm"] = $remoteCertificate.PublicKey.EncodedParameters.Oid.FriendlyName #"RSA" #$remoteCertificate.PublicKey.Key.KeyExchangeAlgorithm
                } else {
                    # ECC Key
                    $publicKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($remoteCertificate)
                    $protocolStatus["KeySize"] = "$($remoteCertificate.PublicKey.EncodedParameters.Oid.FriendlyName) $($publicKey.key.KeySize)"
                    $protocolStatus["KeyAlgorithm"] = $publicKey.key.Algorithm
                }

                # Append the certificate details to the output
                $protocolStatus["SignatureAlgorithm"] = $remoteCertificate.SignatureAlgorithm.FriendlyName
                $protocolStatus["EnhancedKeyUsage"] = $remoteCertificate.EnhancedKeyUsageList
                $protocolStatus["DnsNameList"] = $remoteCertificate.DnsNameList
                $protocolStatus["NotBefore"] = $remoteCertificate.NotBefore
                $protocolStatus["NotAfter"] = $remoteCertificate.NotAfter

                # Append the certificate to the output
                if ($OutputCertificate) {
                    $protocolStatus["Certificate"] = $remoteCertificate
                }
            }

            # Output the final result
            [PSCustomObject]$protocolStatus
            #endregion Prepare output
        }
    }

    end {}
}
