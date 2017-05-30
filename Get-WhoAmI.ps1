function Get-WhoAmI {
    <#
    .Synopsis
       Shows extensive information about the current user

    .DESCRIPTION
       Get-WhoAmI is intended to be an extended equivalent to the cmd tool whoami.exe. There are nearly the same parameters but much more output.

    .NOTES
       Version:     1.0.0.1
       Author:      Andreas Bellstedt
       History:     28.05.2017 - First Version
                    30.05.2017 - Apply coding best practice. changing aliases to cmdlets

    .LINK
       https://github.com/AndiBellstedt/

    .EXAMPLE
       Get-WhoAmI
       This displays only user information.

    .EXAMPLE
       Get-WhoAmI -User
       Same as calling the cmdlet without parameter user... this displays only user information.

    .EXAMPLE
       Get-WhoAmI -Groups | Out-GridView
       Display extensive 

    .EXAMPLE
       Get-WhoAmI -Privileges | Format-Table
       Display the users privileges.

    .EXAMPLE
       Get-WhoAmI -All
       Comprehensive informations about the current user as object with deep hierarchy of objects

    #>
    [CmdletBinding(DefaultParameterSetName='User',
                   SupportsShouldProcess=$false,
                   PositionalBinding=$true,
                   ConfirmImpact='Low')]
    [Alias("WhoAmI")]
    Param(
        #Only display user information
        [Parameter(ParameterSetName='User')]
        [Alias("Usr")]
            [Switch]$User,

        #Only display groups information
        [Parameter(ParameterSetName='Groups')]
        [Alias("Grp")]
            [Switch]$Groups,

        #Only privileges of the user
        [Parameter(ParameterSetName='Privileges')]
        [Alias("Priv")]
            [Switch]$Privileges,

        #Only privileges of the user
        [Parameter(ParameterSetName='All')]
        [Alias("Everthing")]
            [Switch]$All
    )

    
    $CurrentUserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    #$LogonId = [System.Security.Principal.SecurityIdentifier]::new((whoami.exe /LOGONID))
    switch ($PsCmdlet.ParameterSetName) {
        { $_ -like 'User' -or $_ -like 'Groups' -or $_ -like 'All' } { 
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $CurrentUserAccount = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
        }

        { $_ -like 'Groups' -or $_ -like 'All' } {
            $GroupsFromUserIdentity = foreach ($Group in $CurrentUserIdentity.Groups) { 
                try {
                    $GroupFromUserIdentityName = $Group.Translate([System.Security.Principal.NTAccount]).Value            
                } catch {
                    $GroupFromUserIdentityName = ""
                }
                
                if($Group.AccountDomainSid) { 
                    $SearchContext = [System.DirectoryServices.AccountManagement.ContextType]::Domain 
                } else { 
                    $SearchContext = [System.DirectoryServices.AccountManagement.ContextType]::Machine 
                }

                if($GroupFromUserIdentityName ) {
                    $GroupFromUserIdentity = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($SearchContext, $GroupFromUserIdentityName)
                } else {
                    $GroupFromUserIdentity = [System.DirectoryServices.AccountManagement.GroupPrincipal]::new($SearchContext, "unknown SID $($Group.Value)")
                }
                Write-Output $GroupFromUserIdentity
            }
            Add-Member -InputObject $CurrentUserIdentity -MemberType NoteProperty -Name Groups -Value $GroupsFromUserIdentity -Force -ErrorAction Continue
            Add-Member -InputObject $CurrentUserAccount -MemberType NoteProperty -Name Groups -Value $CurrentUserAccount.GetGroups() -Force -ErrorAction Continue
            Add-Member -InputObject $CurrentUserAccount -MemberType NoteProperty -Name GroupsAuthorization -Value $CurrentUserAccount.GetAuthorizationGroups() -Force -ErrorAction Continue
        }

        { $_ -like 'Privileges' -or $_ -like 'All' } { 
            $CurrentUserPrivileges = whoami.exe /priv /FO CSV | ConvertFrom-Csv
        }
    }

    $OutputHash = [ordered]@{}
    switch ($PsCmdlet.ParameterSetName) {
        'User' { 
            $OutputHash.Name                     = $CurrentUserAccount.Name
            $OutputHash.NetbiosLogon             = $CurrentUserIdentity.Name
            $OutputHash.DisplayName              = $CurrentUserAccount.DisplayName
            $OutputHash.SamAccountName           = $CurrentUserAccount.SamAccountName
            $OutputHash.UserPrincipalName        = $CurrentUserAccount.UserPrincipalName
            $OutputHash.SID                      = $CurrentUserAccount.Sid
            $OutputHash.Guid                     = $CurrentUserAccount.Guid
            $OutputHash.DistinguishedName        = $CurrentUserAccount.DistinguishedName
            $OutputHash.AuthenticationType       = $CurrentUserIdentity.AuthenticationType
            $OutputHash.ImpersonationLevel       = $CurrentUserIdentity.ImpersonationLevel
            $OutputHash.IsAuthenticated          = $CurrentUserIdentity.IsAuthenticated
            $OutputHash.IsGuest                  = $CurrentUserIdentity.IsGuest
            $OutputHash.IsSystem                 = $CurrentUserIdentity.IsSystem
            $OutputHash.IsAnonymous              = $CurrentUserIdentity.IsAnonymous
            $OutputHash.Owner                    = $CurrentUserIdentity.Owner.Translate([System.Security.Principal.NTAccount]).Value
            $OutputHash.Token                    = $CurrentUserIdentity.Token
            $OutputHash.GivenName                = $CurrentUserAccount.GivenName
            $OutputHash.MiddleName               = $CurrentUserAccount.MiddleName
            $OutputHash.Surname                  = $CurrentUserAccount.Surname
            $OutputHash.EmailAddress             = $CurrentUserAccount.EmailAddress
            $OutputHash.VoiceTelephoneNumber     = $CurrentUserAccount.VoiceTelephoneNumber
            $OutputHash.EmployeeId               = $CurrentUserAccount.EmployeeId
            $OutputHash.Enabled                  = $CurrentUserAccount.Enabled
            $OutputHash.AccountLockoutTime       = $CurrentUserAccount.AccountLockoutTime
            $OutputHash.LastLogon                = $CurrentUserAccount.LastLogon
            $OutputHash.PermittedWorkstations    = $CurrentUserAccount.PermittedWorkstations
            $OutputHash.PermittedLogonTimes      = $CurrentUserAccount.PermittedLogonTimes
            $OutputHash.AccountExpirationDate    = $CurrentUserAccount.AccountExpirationDate
            $OutputHash.SmartcardLogonRequired   = $CurrentUserAccount.SmartcardLogonRequired
            $OutputHash.DelegationPermitted      = $CurrentUserAccount.DelegationPermitted
            $OutputHash.BadLogonCount            = $CurrentUserAccount.BadLogonCount
            $OutputHash.HomeDirectory            = $CurrentUserAccount.HomeDirectory
            $OutputHash.HomeDrive                = $CurrentUserAccount.HomeDrive
            $OutputHash.ScriptPath               = $CurrentUserAccount.ScriptPath
            $OutputHash.LastPasswordSet          = $CurrentUserAccount.LastPasswordSet
            $OutputHash.LastBadPasswordAttempt   = $CurrentUserAccount.LastBadPasswordAttempt
            $OutputHash.PasswordNotRequired      = $CurrentUserAccount.PasswordNotRequired
            $OutputHash.PasswordNeverExpires     = $CurrentUserAccount.PasswordNeverExpires
            $OutputHash.UserCannotChangePassword = $CurrentUserAccount.UserCannotChangePassword
            $OutputHash.AllowReversiblePasswordEncryption = $CurrentUserAccount.AllowReversiblePasswordEncryption
            $OutputHash.Certificates             = $CurrentUserAccount.Certificates
            $OutputHash.Context                  = $CurrentUserAccount.Context
            $OutputHash.ContextType              = $CurrentUserAccount.ContextType
            $OutputHash.Description              = $CurrentUserAccount.Description
            $OutputHash.StructuralObjectClass    = $CurrentUserAccount.StructuralObjectClass

            Write-Output (New-Object -TypeName psobject -Property $OutputHash)
        }

        'Groups' {
            $TokenLocalName = $CurrentUserIdentity.Groups.samaccountname 
            $TokenADName = $CurrentUserAccount.GroupsAuthorization.samaccountname 
            
            $compareResults = Compare-Object -ReferenceObject $TokenLocalName -DifferenceObject $TokenADName -IncludeEqual
            foreach($compareResult in $compareResults) { 
                switch ($compareResult.SideIndicator) {
                    '==' {
                        $Group = $CurrentUserIdentity.Groups | Where-Object -Property samaccountname -like $compareResult.InputObject
                        Add-Member -InputObject $Group -MemberType NoteProperty -Force -Name InfoSource -Value "LocalToken"
                    }

                    '=>' {
                        $Group = $CurrentUserAccount.GroupsAuthorization | Where-Object -Property samaccountname -like $compareResult.InputObject
                        Add-Member -InputObject $Group -MemberType NoteProperty -Force -Name InfoSource -Value "ActiveDirectory"
                    }

                    '<=' {
                        $Group = $CurrentUserIdentity.Groups | Where-Object -Property samaccountname -like $compareResult.InputObject
                        Add-Member -InputObject $Group -MemberType NoteProperty -Force -Name InfoSource -Value "LocalToken"
                    }
                }
                Add-Member -InputObject $Group -MemberType NoteProperty -Force -Name User -Value (.{if($CurrentUserIdentity.Name -match '\\') { $CurrentUserIdentity.Name.Split('\')[1] } else { $CurrentUserIdentity.Name }})
                Add-Member -InputObject $Group -MemberType NoteProperty -Force -Name UserNetbiosLogon -Value $CurrentUserIdentity.Name
                Add-Member -InputObject $Group -MemberType NoteProperty -Force -Name UserSID -Value $CurrentUserIdentity.User
                Write-Output $Group
            }
        }

        'Privileges' {
            foreach ($Item in $CurrentUserPrivileges) {
                Add-Member -InputObject $Item -MemberType NoteProperty -Force -Name Name -Value (.{if($CurrentUserIdentity.Name -match '\\') { $CurrentUserIdentity.Name.Split('\')[1] } else { $CurrentUserIdentity.Name }})
                Add-Member -InputObject $Item -MemberType NoteProperty -Force -Name NetbiosLogon -Value $CurrentUserIdentity.Name
                Add-Member -InputObject $Item -MemberType NoteProperty -Force -Name SID -Value $CurrentUserIdentity.User
                Write-Output $Item
            }
        }

        'All' {
            $OutputHash.Name                     = $CurrentUserAccount.Name
            $OutputHash.NetbiosLogon             = $CurrentUserIdentity.Name
            $OutputHash.DisplayName              = $CurrentUserAccount.DisplayName
            $OutputHash.SamAccountName           = $CurrentUserAccount.SamAccountName
            $OutputHash.UserPrincipalName        = $CurrentUserAccount.UserPrincipalName
            $OutputHash.Sid                      = $CurrentUserAccount.Sid
            $OutputHash.Guid                     = $CurrentUserAccount.Guid
            $OutputHash.DistinguishedName        = $CurrentUserAccount.DistinguishedName
            $OutputHash.AuthenticationType       = $CurrentUserIdentity.AuthenticationType
            $OutputHash.ImpersonationLevel       = $CurrentUserIdentity.ImpersonationLevel
            $OutputHash.IsAuthenticated          = $CurrentUserIdentity.IsAuthenticated
            $OutputHash.IsGuest                  = $CurrentUserIdentity.IsGuest
            $OutputHash.IsSystem                 = $CurrentUserIdentity.IsSystem
            $OutputHash.IsAnonymous              = $CurrentUserIdentity.IsAnonymous
            $OutputHash.Owner                    = $CurrentUserIdentity.Owner.Translate([System.Security.Principal.NTAccount]).Value
            $OutputHash.Token                    = $CurrentUserIdentity.Token
            $OutputHash.GivenName                = $CurrentUserAccount.GivenName
            $OutputHash.MiddleName               = $CurrentUserAccount.MiddleName
            $OutputHash.Surname                  = $CurrentUserAccount.Surname
            $OutputHash.EmailAddress             = $CurrentUserAccount.EmailAddress
            $OutputHash.VoiceTelephoneNumber     = $CurrentUserAccount.VoiceTelephoneNumber
            $OutputHash.EmployeeId               = $CurrentUserAccount.EmployeeId
            $OutputHash.Enabled                  = $CurrentUserAccount.Enabled
            $OutputHash.AccountLockoutTime       = $CurrentUserAccount.AccountLockoutTime
            $OutputHash.LastLogon                = $CurrentUserAccount.LastLogon
            $OutputHash.PermittedWorkstations    = $CurrentUserAccount.PermittedWorkstations
            $OutputHash.PermittedLogonTimes      = $CurrentUserAccount.PermittedLogonTimes
            $OutputHash.AccountExpirationDate    = $CurrentUserAccount.AccountExpirationDate
            $OutputHash.SmartcardLogonRequired   = $CurrentUserAccount.SmartcardLogonRequired
            $OutputHash.DelegationPermitted      = $CurrentUserAccount.DelegationPermitted
            $OutputHash.BadLogonCount            = $CurrentUserAccount.BadLogonCount
            $OutputHash.HomeDirectory            = $CurrentUserAccount.HomeDirectory
            $OutputHash.HomeDrive                = $CurrentUserAccount.HomeDrive
            $OutputHash.ScriptPath               = $CurrentUserAccount.ScriptPath
            $OutputHash.LastPasswordSet          = $CurrentUserAccount.LastPasswordSet
            $OutputHash.LastBadPasswordAttempt   = $CurrentUserAccount.LastBadPasswordAttempt
            $OutputHash.PasswordNotRequired      = $CurrentUserAccount.PasswordNotRequired
            $OutputHash.PasswordNeverExpires     = $CurrentUserAccount.PasswordNeverExpires
            $OutputHash.UserCannotChangePassword = $CurrentUserAccount.UserCannotChangePassword
            $OutputHash.AllowReversiblePasswordEncryption = $CurrentUserAccount.AllowReversiblePasswordEncryption
            $OutputHash.Certificates             = $CurrentUserAccount.Certificates
            $OutputHash.Context                  = $CurrentUserAccount.Context
            $OutputHash.ContextType              = $CurrentUserAccount.ContextType
            $OutputHash.Description              = $CurrentUserAccount.Description
            $OutputHash.StructuralObjectClass    = $CurrentUserAccount.StructuralObjectClass
            
            $OutputHash.GroupsLocalToken         = $CurrentUserIdentity.Groups
            $OutputHash.GroupsADMemberOf         = $CurrentUserAccount.Groups
            $OutputHash.GroupsADAuthorization    = $CurrentUserAccount.GroupsAuthorization

            $OutputHash.Privileges               = $CurrentUserPrivileges
            
            Write-Output [psobject]($OutputHash)
        }
    }
    
}
