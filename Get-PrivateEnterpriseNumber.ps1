function Get-PrivateEnterpriseNumber {
    <#
    .Synopsis
       Get private enterprise numbers from IANA website
    
    .DESCRIPTION
       Get private enterprise numbers from IANA website
    
    .NOTES
       Version: 1.0.0.0
       Author:  Andreas Bellstedt
       History: 2017-04-09 - First Version

    .LINK
       https://github.com/AndiBellstedt
    
    .EXAMPLE
       Get-PrivateEnterpriseNumber
       Returns all numbers
    
    .EXAMPLE
       Get-PrivateEnterpriseNumber -Name "Unix"
       Returns a company by name.
       (Wildcards are possibles in names)

       The parameter -Name has a alias of "organisation". 
       So -Organisation can also be used instead auf -Name.

    .EXAMPLE
       Get-PrivateEnterpriseNumber -ID 0
       Returns a company by it private enterprise numbers (PEN) ID.

       The parameter -ID has a alias of "number". 
       So -Number can also be used instead auf -ID.

    .EXAMPLE
       Get-PrivateEnterpriseNumber -Contact "Dave Jones"
       Search for a company by contact name.
       (Wildcards are possibles in names)

    .EXAMPLE
       Get-PrivateEnterpriseNumber -Email "davej&cisco.com"
       Search for a company by contact details.
       (Wildcards are possibles in names)

    .EXAMPLE
       1,2,3 | Get-PrivateEnterpriseNumber
       Pipeping is possible by "ID" and "Name". The example shows the first 3 
    
    .EXAMPLE       
       "Unix","Cisco*", "*IBM*" | Get-PrivateEnterpriseNumber
       Another example for piping, this time with names.

    #>
    #Requires -version 3
    [CmdletBinding(DefaultParameterSetName='ShowAll', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$true,
                  ConfirmImpact='Low')]
    [Alias("gpen")]
    [OutputType([PSCustomObject])]
    Param (
        # Search by Name of the organisation
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='ByName')]
        [Alias("Organisation")] 
            [String[]]$Name,
        
        # Search by Private enterprise number (PEN) of organisation
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='ByID')]
        [Alias("Number")] 
            [int[]]$ID,

        # Search by contact name in the organisation
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='ByContact')]
        [Alias("Person")] 
            [String[]]$Contact,

        # Search by email address, respectively "contact details"
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='ByEmail')]
        [Alias("ContactDetails", "Mail")] 
            [String[]]$Email
    )

    Begin {
        $Url = 'https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers'
        Write-Verbose "Catching data from $($Url)"
        $WebData = Invoke-WebRequest -Uri $Url -UseBasicParsing | Select-Object -ExpandProperty Content
        $AllLines = $WebData.Split(“`r`n”)
        $lastUpdate = [datetime]($AllLines[2] -replace '.*(?<date>\d{4}-\d{2}-\d{2}).*', '${date}')
        $Matches = Select-String -InputObject $WebData -Pattern '(?<number>\d+)\n(\s{2}(?<Organization>(.*|\n)*))(\s{5}(?<Contact>(.*|\n)*))(\s{7}(?<Email>.*))' -AllMatches
        $EntryCount = $Matches.Matches.count
        $Counter = 0
        $Company = foreach ($Match in $Matches.Matches) { 
            if(($Counter % 1024) -eq 0) {
                Write-Progress -Activity "Catching infos" -CurrentOperation "$($Counter)/$($EntryCount)" -PercentComplete (100/$EntryCount*$Counter)
            }
            $Object = [PSCustomObject]@{
                ID = [int32]$Match.Groups[6].Value
                Name = $Match.Groups[7].Value -replace '\n|\r|\n\r|\r\n',' '
                Contact = $Match.Groups[8].Value -replace '\n|\r|\n\r|\r\n',' '
                Email = $Match.Groups[9].Value -replace '\n|\r|\n\r|\r\n',' '
                LastUpdate = $lastUpdate
            }
            $Object.PSTypeNames.Insert(0,"IANA.Assignments.EnterpriseNumbers.Private")
            Write-Output $Object
            $counter++
        }
        Write-Progress -Activity "Catching infos" -Completed
    }
    Process {
        switch ($PsCmdlet.ParameterSetName) {
            'ByName'    { foreach($Filter in $Name   ) { $Company | Where-Object name    -like $Filter } }
            'ByID'      { foreach($Filter in $ID     ) { $Company | Where-Object ID      -eq   $Filter } }
            'ByContact' { foreach($Filter in $Contact) { $Company | Where-Object Contact -like $Filter } }
            'ByEmail'   { foreach($Filter in $Email  ) { $Company | Where-Object Email   -like $Filter } }
            Default     { $Company }
        }
    }
    End {
        Remove-Variable Url, WebData, AllLines, lastUpdate, Matches, EntryCount, counter, Match, Object, Company -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false -Verbose:$false -Debug:$false
    }
}

gpen -id 1,2,3,4

