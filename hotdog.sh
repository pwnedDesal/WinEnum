#!/bin/bash
# Check if the target IP is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip>  [-u=<username>] [-p=<password>] [-d=<domain>] [-b] [-v] "
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

while getopts "u:p:d:bv" opt; do
  case $opt in
    u) username=$OPTARG;;
    p) password=$OPTARG;;
    d) domain=$OPTARG;;
    b) bruteForceShares=true;;
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
# Display script header
verbose_message "Script started."
domainName=$(echo $domain | cut -d'.' -f1)
tld=$(echo $domain | cut -d'.' -f2)
WORDLIST="/usr/share/wordlists/rockyou.txt"
METASPLOIT_USERS="/usr/share/metasploit-framework/data/wordlists/unix_users.txt"
verbose_message "Creating directories."
mkdir -p nbtscan enum4linux smbclient rpcclient ldapsearch

# This usually abuses anon login
verbose_message "Running nbtscan and enum4linux."
nbtscan -r "$TARGET_IP" > nbtscan/clientNcomputer
enum4linux -a "$TARGET_IP" -u $username -p $password > enum4linux/index
#enum4linux -a "$TARGET_IP" -u $username -p $password | grep -i "User" > enum4linux/enumUser
#BRUTE FORCE HERE
verbose_message "Running smbclient & enum4linux"
verbose_message "Dicitionary attack shares using enum4linux"
if [ "$bruteForceShares" == "true" ]; then
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
if [ -z "$domain" ]; then
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
    verbose_message "Running ldapsearch\(anon bind\)"
    ldapsearch -x -H ldap://${TARGET_IP} -D ${username} -w ${password} > ldapsearch/index
fi
