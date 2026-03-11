function Get-GPOPermissions {
<#
.SYNOPSIS
    Audits GPO ACLs and reports principals with rights beyond read-only.

.PARAMETER Help
    Display usage information.

.PARAMETER GPOName
    GPO display name filter (wildcards accepted). Default: * (all GPOs).

.PARAMETER PageSize
    LDAP paging size (1-10000). Default: 200.

.PARAMETER Server
    Domain controller hostname or IP.

.PARAMETER Domain
    Target domain FQDN for automatic DC discovery.

.PARAMETER User
    Username for cross-domain authentication (DOMAIN\user or user@domain).

.PARAMETER Password
    Password for -User (prompted securely if omitted).

.EXAMPLE
    Get-GPOPermissions

.EXAMPLE
    Get-GPOPermissions -GPOName "Default*" | Export-Csv gpo_perms.csv -NoTypeInformation

.EXAMPLE
    Get-GPOPermissions -Domain demo.local -User demo\admintest

.EXAMPLE
    Get-GPOPermissions -Server dc01.demo.local -User admintest@demo.local -Password P@ssw0rd
#>

    [CmdletBinding()]
    param (
        [Alias('h')]
        [switch]$Help,

        [string]$GPOName = '*',
        [ValidateRange(1,10000)]
        [int]$PageSize = 200,

        [string]$Server,
        [string]$Domain,
        [string]$User,
        [string]$Password
    )

    # ---------------------------
    # Help
    # ---------------------------
    if ($Help) {
        Write-Host @"

USAGE
    Get-GPOPermissions.ps1 [[-GPOName] <string>] [-Server <string>] [-Domain <string>]
                           [-User <string>] [-Password <string>] [-PageSize <int>] [-Help]

PARAMETERS
    -GPOName    GPO display name filter (* wildcard). Default: * (all GPOs).
    -Server     Domain controller hostname or IP.
    -Domain     Target domain FQDN (e.g. demo.local) for automatic DC discovery.
    -User       Username: DOMAIN\user or user@domain.fqdn
    -Password   Password for -User (prompted securely if omitted).
    -PageSize   LDAP paging size 1-10000. Default: 200.
    -Help / -h  Show this help.

EXCLUSIONS
    SYSTEM (S-1-5-18), CREATOR OWNER (S-1-3-0), Domain Admins (RID 512),
    Enterprise Admins (RID 519), and the "Apply Group Policy" extended right.

EXAMPLES
    Get-GPOPermissions.ps1
    Get-GPOPermissions.ps1 -GPOName "Default*" | Export-Csv gpo_perms.csv -NoTypeInformation
    Get-GPOPermissions.ps1 -Domain demo.local -User demo\admintest
    Get-GPOPermissions.ps1 -Server dc01.demo.local -User admintest@demo.local -Password P@ssw0rd

"@
        return
    }

    # ---------------------------
    # Resolve credentials
    # ---------------------------
    $HasCreds = $PSBoundParameters.ContainsKey('User') -and ($User -ne '')
    $PlainPass = $null

    if ($PSBoundParameters.ContainsKey('Password') -and -not $HasCreds) {
        Write-Warning "-Password was specified without -User and will be ignored."
    }

    if ($HasCreds) {
        if (-not $PSBoundParameters.ContainsKey('Password')) {
            $SecurePass = Read-Host -Prompt "Password for '$User'" -AsSecureString
            $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)
            try {
                $PlainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Ptr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)
            }
        } else {
            $PlainPass = $Password
        }
    }

    # ---------------------------
    # Main — single try/catch/finally for clean disposal
    # ---------------------------
    $DomainEntry = $null
    $Searcher    = $null
    $GPOs        = $null

    try {
        # --- Connect to domain ---
        if ($Server -or $Domain) {
            $LdapHost = if ($Server) { $Server } else { $Domain }
            $RootDSE  = if ($HasCreds) {
                New-Object System.DirectoryServices.DirectoryEntry("LDAP://$LdapHost/RootDSE", $User, $PlainPass)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry("LDAP://$LdapHost/RootDSE")
            }
            try {
                $DefaultNC = $RootDSE.Properties['defaultNamingContext'][0]
                if (-not $DefaultNC) { throw "Could not retrieve the default naming context from '$LdapHost'." }
            } finally {
                $RootDSE.Dispose()
            }
            $DomainEntry = if ($HasCreds) {
                New-Object System.DirectoryServices.DirectoryEntry("LDAP://$LdapHost/$DefaultNC", $User, $PlainPass)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry("LDAP://$LdapHost/$DefaultNC")
            }
        } else {
            $DomainEntry = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry()
        }

        # --- Build exclusion SID list ---
        $DomainSID = (New-Object System.Security.Principal.SecurityIdentifier(
            $DomainEntry.objectSid[0], 0
        )).Value

        $ExcludedSIDs = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@(
                'S-1-5-18',        # SYSTEM
                'S-1-3-0',         # CREATOR OWNER
                "$DomainSID-512",  # Domain Admins
                "$DomainSID-519"   # Enterprise Admins
            ),
            [System.StringComparer]::OrdinalIgnoreCase
        )

        # Mask: any bit set other than GenericRead
        $BeyondReadMask = -bnot [System.DirectoryServices.ActiveDirectoryRights]::GenericRead

        # GUID for the "Apply Group Policy" extended right
        $ApplyGPOGuid = [guid]'edacfd8f-ffb3-11d1-b41d-00a0c968f939'

        # --- Search for GPOs ---
        # Escape LDAP filter special characters in GPOName (keep * as wildcard)
        $EscapedGPOName = $GPOName -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29'

        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot  = $DomainEntry
        $Searcher.Filter      = "(&(objectCategory=groupPolicyContainer)(displayName=$EscapedGPOName))"
        $Searcher.PageSize    = $PageSize
        $Searcher.SearchScope  = 'Subtree'
        $Searcher.CacheResults = $false  # stream results page-by-page rather than loading all into memory
        [void]$Searcher.PropertiesToLoad.Add('displayname')  # adspath always available via $gpo.Path

        try {
            $GPOs = $Searcher.FindAll()
        } catch {
            throw "LDAP search failed: $_"
        }

        foreach ($gpo in $GPOs) {

            $GpoPath        = $gpo.Path
            $GpoDisplayName = if ($gpo.Properties['displayname'].Count -gt 0) {
                $gpo.Properties['displayname'][0]
            } else { $GpoPath }

            # --- Read ACL ---
            $GpoEntry = $null
            try {
                $GpoEntry = if ($HasCreds) {
                    New-Object System.DirectoryServices.DirectoryEntry($GpoPath, $User, $PlainPass)
                } else {
                    New-Object System.DirectoryServices.DirectoryEntry($GpoPath)
                }
                $Acl = $GpoEntry.ObjectSecurity.Access
            } catch {
                Write-Warning "Could not read ACL for GPO '$GpoDisplayName': $_"
                continue
            } finally {
                if ($GpoEntry) { $GpoEntry.Dispose() }
            }

            # --- Emit one row per qualifying ACE ---
            foreach ($Ace in $Acl) {

                # Only Allow ACEs
                if ($Ace.AccessControlType -ne 'Allow') { continue }

                # Only ACEs with rights beyond GenericRead
                if (($Ace.ActiveDirectoryRights -band $BeyondReadMask) -eq 0) { continue }

                # Translate identity to SID (once)
                try {
                    $Sid = $Ace.IdentityReference.Translate(
                        [System.Security.Principal.SecurityIdentifier]
                    ).Value
                } catch {
                    Write-Warning "Could not translate identity '$($Ace.IdentityReference)' on GPO '$GpoDisplayName': $_"
                    continue
                }

                # Skip excluded SIDs
                if ($ExcludedSIDs.Contains($Sid)) { continue }

                # Skip "Apply Group Policy" extended right (any principal)
                if ($Ace.ObjectType -eq $ApplyGPOGuid) { continue }

                # Resolve SID to a name: try local translation first, then LDAP lookup
                $IdentityName = $Ace.IdentityReference.Value
                if ($IdentityName -match '^S-\d+-') {
                    $resolved = $null
                    try {
                        $resolved = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate(
                            [System.Security.Principal.NTAccount]
                        ).Value
                    } catch { }

                    if (-not $resolved) {
                        try {
                            $SidBytes = New-Object byte[] ([System.Security.Principal.SecurityIdentifier]$Sid).BinaryLength
                            ([System.Security.Principal.SecurityIdentifier]$Sid).GetBinaryForm($SidBytes, 0)
                            $OctetStr  = ($SidBytes | ForEach-Object { '\{0:x2}' -f $_ }) -join ''
                            $SidSearch = New-Object System.DirectoryServices.DirectorySearcher($DomainEntry)
                            $SidSearch.Filter = "(objectSid=$OctetStr)"
                            [void]$SidSearch.PropertiesToLoad.Add('sAMAccountName')
                            $SidResult = $SidSearch.FindOne()
                            $SidSearch.Dispose()
                            if ($SidResult -and $SidResult.Properties['sAMAccountName'].Count -gt 0) {
                                $resolved = $SidResult.Properties['sAMAccountName'][0]
                            }
                        } catch { }
                    }

                    if ($resolved) { $IdentityName = $resolved }
                }

                [PSCustomObject]@{
                    GPODisplayName        = $GpoDisplayName
                    ADSPath               = $GpoPath
                    IdentitySID           = $Sid
                    IdentityName          = $IdentityName
                    ActiveDirectoryRights = $Ace.ActiveDirectoryRights
                    IsInherited           = $Ace.IsInherited
                    ObjectType            = $Ace.ObjectType
                    InheritanceType       = $Ace.InheritanceType
                }
            }
        }

    } catch {
        Write-Error $_
    } finally {
        if ($GPOs)        { $GPOs.Dispose() }
        if ($Searcher)    { $Searcher.Dispose() }
        if ($DomainEntry) { $DomainEntry.Dispose() }
        $PlainPass = $null
    }
}

Get-GPOPermissions @args
