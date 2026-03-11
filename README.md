# Get-GPOPermissions
Flags any ACL entry that grants rights beyond `GenericRead` while excluding default high-privilege accounts (`Domain Admins`, `Enterprise Admins`, `SYSTEM`, `CREATOR OWNER`).
It can be used in your current session or target another domain by using other credentials.


```ps1
.\Get-GPOPermissions.ps1 -h
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
    The following are always excluded from results:
      - SYSTEM          (S-1-5-18)
      - CREATOR OWNER   (S-1-3-0)
      - Domain Admins   (RID 512)
      - Enterprise Admins (RID 519)
      - "Apply Group Policy" extended right (edacfd8f-ffb3-11d1-b41d-00a0c968f939)

EXAMPLES
    Get-GPOPermissions.ps1
    Get-GPOPermissions.ps1 -GPOName "Default*" | Export-Csv gpo_perms.csv -NoTypeInformation
    Get-GPOPermissions.ps1 -Domain demo.local -User demo\admintest
    Get-GPOPermissions.ps1 -Server dc01.demo.local -User admintest@demo.local -Password P@ssw0rd

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
