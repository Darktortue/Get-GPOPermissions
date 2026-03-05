function Get-GPOPermissions {
<#
.SYNOPSIS
    Finds users or groups that have more than Read permissions on GPO objects.

.DESCRIPTION
    Flags any ACL entry that grants rights beyond GenericRead while excluding
    default high-privilege accounts (Domain Admins, Enterprise Admins, SYSTEM, CREATOR OWNER).

.PARAMETER Help
    Display usage information.

.PARAMETER GPOName
    GPO display name to query (wildcards accepted). Default: * (all GPOs).

.PARAMETER PageSize
    LDAP paging size. Range: 1-10000. Default: 200.

.PARAMETER Server
    Domain controller to connect to (hostname or IP). Takes precedence over -Domain for
    DC selection. If omitted alongside -Domain, the current domain is queried.

.PARAMETER Domain
    FQDN of the target domain (e.g. demo.local). Used for automatic DC discovery via DNS
    SRV records when -Server is not specified.

.PARAMETER User
    Username for cross-domain authentication (e.g. demo\admintest or admintest@demo.local).

.PARAMETER Password
    Password for -User. If -User is specified and -Password is omitted, the script
    prompts securely (input is masked).

.EXAMPLE
    .\gpo_test.ps1

.EXAMPLE
    .\gpo_test.ps1 -GPOName "Default*"

.EXAMPLE
    .\gpo_test.ps1 -Domain demo.local -User demo\admintest

.EXAMPLE
    .\gpo_test.ps1 -Server dc01.demo.local -User admintest@demo.local -Password P@ssw0rd

.EXAMPLE
    .\gpo_test.ps1 -Domain demo.local -User demo\admintest | Export-Csv gpo_perms.csv -NoTypeInformation
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

SYNOPSIS
    Get-GPOPermissions
    Audits GPO permissions in Active Directory. Reports any principal granted more
    than read-only access on GPO objects, excluding built-in privileged accounts.

USAGE
    .\gpo_test.ps1 [[-GPOName] <string>] [-Server <string>] [-Domain <string>]
                   [-User <string>] [-Password <string>] [-PageSize <int>] [-Help]

PARAMETERS
    -GPOName <string>
        GPO display name filter. Wildcards (*) accepted. Default: * (all GPOs).

    -Server <string>
        Domain controller to connect to (hostname or IP). Takes precedence over
        -Domain for DC selection. If omitted alongside -Domain, the current
        domain is queried.

    -Domain <string>
        Target domain FQDN (e.g. demo.local). Used for automatic DC discovery
        via DNS SRV records when -Server is not specified.

    -User <string>
        Username for cross-domain authentication.
        Formats accepted:  DOMAIN\username   or   username@domain.fqdn

    -Password <string>
        Password for -User. If -User is specified and -Password is omitted,
        the script prompts securely (input is masked).

    -PageSize <int>
        LDAP paging size. Range: 1-10000. Default: 200.

    -Help / -h
        Display this help message.

EXCLUSIONS
    The following are always excluded from results:
      - SYSTEM          (S-1-5-18)
      - CREATOR OWNER   (S-1-3-0)
      - Domain Admins   (RID 512)
      - Enterprise Admins (RID 519)
      - Authenticated Users with "Apply Group Policy" right only

OUTPUT FIELDS
    GPODisplayName        Display name of the GPO
    ADSPath               LDAP path of the GPO object
    IdentitySID           SID of the identity holding the permission
    IdentityName          Resolved name of the identity
    ActiveDirectoryRights Rights granted (e.g. WriteProperty, WriteDacl)
    IsInherited           Whether the ACE is inherited
    ObjectType            GUID of the specific attribute or extended right
    InheritanceType       Inheritance scope of the ACE

EXAMPLES
    # Current domain - all GPOs
    .\gpo_test.ps1

    # Filter by GPO name
    .\gpo_test.ps1 -GPOName "Default*"

    # Cross-domain - prompts securely for password
    .\gpo_test.ps1 -Domain demo.local -User demo\admintest

    # Cross-domain - target a specific DC, password inline
    .\gpo_test.ps1 -Server dc01.demo.local -User admintest@demo.local -Password P@ssw0rd

    # Export to CSV
    .\gpo_test.ps1 -Domain demo.local -User demo\admintest | Export-Csv gpo_perms.csv -NoTypeInformation

NOTES
    -Server vs -Domain:
      Use -Server to target a specific DC (useful when DNS resolution fails or
      you need a particular DC). Use -Domain to let Windows auto-discover a DC
      via DNS SRV lookup. Both can be combined; -Server takes priority.

    Requires network access to the target domain controller on LDAP (TCP 389)
    and read access to the GPO objects in SYSVOL/Active Directory.

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

                # Skip default "Authenticated Users / Apply Group Policy" ACE
                if (
                    $Sid -eq 'S-1-5-11' -and
                    $Ace.ActiveDirectoryRights -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight -and
                    $Ace.ObjectType -eq $ApplyGPOGuid
                ) { continue }

                [PSCustomObject]@{
                    GPODisplayName        = $GpoDisplayName
                    ADSPath               = $GpoPath
                    IdentitySID           = $Sid
                    IdentityName          = $Ace.IdentityReference.Value
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
