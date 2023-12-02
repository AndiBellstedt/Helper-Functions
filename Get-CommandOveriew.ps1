function Get-CommandOveriew {
    <#
    .SYNOPSIS
        Retrieves an overview of commands from module(s)

    .DESCRIPTION
        The Get-CommandOveriew function retrieves an overview of commands from the specified module(s).
        It accepts one or more module names and returns an overview of the commands in those modules.

    .PARAMETER ModuleName
        Specifies the name(s) of the module(s) to retrieve commands from. This parameter accepts one or more strings.

    .PARAMETER Prefix
        Specifies a prefix to filter the commands by. Only commands that start with this prefix will be included in the overview.

    .EXAMPLE
        PS C:\> Get-CommandOveriew -ModuleName 'MyModule'

        This command retrieves an overview of the commands in the 'MyModule' module.

    .EXAMPLE
        PS C:\> Get-CommandOveriew -ModuleName 'MyModule', 'MyOtherModule'

        This command retrieves an overview of the commands in the 'MyModule' and 'MyOtherModule' modules.

    .EXAMPLE
        PS C:\> Get-CommandOveriew -ModuleName 'MyModule' -Prefix 'Get'

        This command retrieves an overview of the commands in the 'MyModule' module that start with 'Get'.

    .INPUTS
        System.String. You can pipe a string that contains the module name to Get-CommandOveriew.

    .OUTPUTS
        CommandOverview. This function returns an overview of the commands in the specified module(s).

    .NOTES
        AUTHOR:     Andreas Bellstedt
        VERSION:    1.0.0
        DATE:       2023-12-02
        KEYWORDS:   Command, overview, module overview, command without prefix in name

    .LINK
        https://github.com/AndiBellstedt

    #>
    #requires -version 5.0
    [cmdletbinding(
        DefaultParameterSetName = 'DefaultOrder',
        ConfirmImpact = 'Low',
        PositionalBinding = $true
    )]
    [Alias("gcmo")]
    [OutputType("CommandOverview")]
    param(
        [Parameter(
            parameterSetName = 'DefaultOrder',
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Parameter(
            parameterSetName = 'OrderByResolvedCommand',
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Name')]
        [string[]]
        $ModuleName,

        [Parameter(parameterSetName = 'DefaultOrder')]
        [alias('Prefix')]
        [string[]]
        $CmdPrefix,

        [Parameter(parameterSetName = 'OrderByResolvedCommand')]
        [switch]
        $OrderByResolvedCommand,

        [Parameter(parameterSetName = 'DefaultOrder')]
        [switch]
        $Unordered
    )

    begin {
        $commands = [System.Collections.ArrayList]@()
        Update-TypeData -TypeName 'CommandOverview' -DefaultDisplayPropertySet "ModuleName", "Version", "Verb", "NounNotPrefixed", "Type", "Name", "ResolvedCommand", "Synopsis", "Help", "Compatible", "PSVersion" -DefaultDisplayProperty ResolvedCommand -DefaultKeyPropertySet ResolvedCommand -Force
    }

    process {
        foreach ($moduleNameItem in $ModuleName) {

            Write-Verbose "Searching for module '$($moduleNameItem)' on the system"
            $module = Get-InstalledModule -Name $moduleNameItem -ErrorAction Ignore
            if (-not $module) {
                Write-Error "Module $($moduleNameItem) not found"
                continue
            }

            Write-Verbose "Gettings commands from module '$($moduleNameItem)'"
            $moduleCommands = Get-Command -Module $moduleNameItem -ErrorAction Ignore
            Write-Verbose "Found $($moduleCommands.count) in module '$($moduleNameItem)'"

            foreach ($command in $moduleCommands) {
                Write-Verbose "Processing command: $($command.Name)"

                # Get the verb
                if ($command.Verb) {
                    $verb = $command.Verb
                } else {
                    if ($command.Name -like "*-*") {
                        $verb = $command.Name.Split('-')[0]
                    } else {
                        $verb = ""
                        #$verb = $command.ResolvedCommand.Verb
                    }
                }

                # Get the noun
                if ($command.Noun) {
                    # handle cmdlets/functions
                    $noun = $command.Noun
                } else {
                    # handle aliases
                    if ($command.Name -like "*-*") {
                        $noun = $command.Name.Split('-')[1]
                    } else {
                        $noun = ""
                        #$noun = $command.ResolvedCommand.Noun
                    }
                }

                # Trim Prefixes from Noun
                $nounNotPrefixed = $noun
                foreach ($prefix in $CmdPrefix) {
                    if ($noun -like "$($prefix)*") {
                        $nounNotPrefixed = $nounNotPrefixed.replace($prefix, '')
                    }
                }


                if ($command.ResolvedCommand) {
                    $resolvedCommand = $command.ResolvedCommand.Name
                } else {
                    $resolvedCommand = $command.name
                }

                $output = [PSCustomObject]@{
                    PSTypeName      = "CommandOverview"
                    ModuleName      = $module.Name
                    Version         = $command.Version
                    Verb            = $verb
                    NounNotPrefixed = $nounNotPrefixed
                    Type            = $command.CommandType
                    Name            = $command.name
                    ResolvedCommand = $resolvedCommand
                    Synopsis        = (Get-Help $command.name).synopsis.trim()
                    Help            = $command.HelpUri
                    Compatible      = $module.CompatiblePSEditions
                    PSVersion       = $module.PowerShellVersion
                    Command         = $command
                }

                if ($Unordered) {
                    $output
                } else {
                    $null = $commands.Add($output)
                }
            }

        }
    }

    end {
        if ($OrderByResolvedCommand) {
            $commands | Sort-Object ResolvedCommand, NounNotPrefixed, Verb
        } else {
            $commands | Sort-Object NounNotPrefixed, Verb
        }
    }
}