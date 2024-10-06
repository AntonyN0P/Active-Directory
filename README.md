Reccoinessanse in network without creds and sessions:
responder -I "eth0" -A

enum4linux-ng.py -A

## find the PDC (Principal Domain Controller)
nslookup -type=srv _ldap._tcp.pdc._msdcs.$FQDN_DOMAIN

## find the DCs (Domain Controllers)
nslookup -type=srv _ldap._tcp.dc._msdcs.$FQDN_DOMAIN

## find the GC (Global Catalog, i.e. DC with extended data)
nslookup -type=srv gc._msdcs.$FQDN_DOMAIN

## Other ways to find services hosts that may be DCs 
nslookup -type=srv _kerberos._tcp.$FQDN_DOMAIN
nslookup -type=srv _kpasswd._tcp.$FQDN_DOMAIN
nslookup -type=srv _ldap._tcp.$FQDN_DOMAIN
nmap -v -sV -p 53 $SUBNET/$MASK
nmap -v -sV -sU -p 53 $SUBNET/$MASK

## Name lookup on a range
nbtscan -r $SUBNET/$MASK

## Find names and workgroup from an IP address
nmblookup -A $IPAdress


# Domain Recon

## Forest and Trusts

### Get Domain Forest
(Get-ADForest).Domains

### Get Domain Trusts

Get-DomainTrust \ Get-AdTrust

### Get all trusts in someone forest

Get-ADTrust -Filter 'intraForest -ne $True' -Server (Get-ADForest).Name



## Enumerate Restricted group

Get-DomainGpoLocalGroup

## Get AD Group members

Get-DomainGroupMember -Identity $groupname

### Get Domain OU

Get-DomainOU / Get-AdOrganizationUnit 

### Get list of child OU (subOU)

Get-ADObject -Filter 'objectClass -eq "organizationalUnit"' -SearchBase "distinguishedName of parent OU"


## Get All computers in OU 

*PowerView
(Get-DomainOU -Identity $OU).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name

*AdModule
Get-ADOrganizationalUnit -Identity 'OU=Students,DC=us,DC=techcorp,DC=local' | %{Get-ADComputer -SearchBase $_ -Filter *} | select name


## Get DomainGPO applied to OU

(Get-DomainOU -Identity $OU).gplink

Get-DomainGPO -Identity '{FCE16496-C744-4E46-AC89-2D01D76EAD68}'

or

Get-GPInheritance -Target 'OU=,DC,DC' | select-object -expandproperty InheritedGpoLinks 



## Get user's ACL for group

(Get-ACL "AD:$((Get-Group GroupName).distinguishedname)").access

## Find Interesting ACL for user or group. That your user has permission 
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'GROUPNAME or USERNAME'}

## Get-ACL for users in group
(Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local').Access | ?{$_.IdentityReference -match 'studentuser1'}

## Get all groups for specific user

function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName) {
$groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName | select -ExpandProperty distinguishedname)
   $groups
   if ($groups.count -gt 0)
   {
        foreach ($group in $groups)
        {
Get-ADPrincipalGroupMembershipRecursive $group }
}
}

Get-ADPrincipalGroupMembershipRecursive "USERNAME"

## Set SPN
Set-ADUser -Identity Support127User -ServicePrincipalNames @{Add='us/myspn127'} -Verbose

## Get LAPS password remotly
sudo crackmapexec ldap dc01.doamin.local -u 'uname' -p 'passwd' --kdcHost dc01.domain.local -M LAPS 


