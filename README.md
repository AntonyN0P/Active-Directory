Reccoinessanse in network without creds and sessions:
responder -I "eth0" -A

enum4linux-ng.py -A

# find the PDC (Principal Domain Controller)
nslookup -type=srv _ldap._tcp.pdc._msdcs.$FQDN_DOMAIN

# find the DCs (Domain Controllers)
nslookup -type=srv _ldap._tcp.dc._msdcs.$FQDN_DOMAIN

# find the GC (Global Catalog, i.e. DC with extended data)
nslookup -type=srv gc._msdcs.$FQDN_DOMAIN

# Other ways to find services hosts that may be DCs 
nslookup -type=srv _kerberos._tcp.$FQDN_DOMAIN
nslookup -type=srv _kpasswd._tcp.$FQDN_DOMAIN
nslookup -type=srv _ldap._tcp.$FQDN_DOMAIN
nmap -v -sV -p 53 $SUBNET/$MASK
nmap -v -sV -sU -p 53 $SUBNET/$MASK

# Name lookup on a range
nbtscan -r $SUBNET/$MASK

# Find names and workgroup from an IP address
nmblookup -A $IPAdress


##########
#ACL
##########
#Get user's ACL for group

(Get-ACL "AD:$((Get-Group GroupName).distinguishedname)").access

#Get-ACL for users in group
(Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local').Access | ?{$_.IdentityReference -match 'studentuser1'}
