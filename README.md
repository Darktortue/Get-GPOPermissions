# Get-GPOPermissions
Flags any ACL entry that grants rights beyond `GenericRead` while excluding default high-privilege accounts (`Domain Admins`, `Enterprise Admins`, `SYSTEM`, `CREATOR OWNER`).
It can be used in your current session or target another domain by using other credentials.


```ps1
.\Get-GPOPermissions.ps1 -h
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
```

NOTE:
- _2nd tool I made with Claude Code. It was not failproof but still helped a lot on the cross-domain part._
