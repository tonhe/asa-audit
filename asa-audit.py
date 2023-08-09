#!/usr/bin/env python3
import re
import argparse
import keyring
import getpass
from netmiko import Netmiko
from netmiko import NetMikoAuthenticationException
from datetime import datetime

# Our sole global variable
DEBUG=False

class ASAConfig:
    def __init__(self, items, config):
        self.items = items
        self.config= config
    def grp_count(self): # count usage of group-policy
        count = {}
        for policy_name in self.items:
            for line in self.config:
                if line.startswith('group-policy'):
                    if not policy_name in count:
                        count[policy_name] = 1
                    else:
                        continue
                elif f'default-group-policy {policy_name}' in line:
                    if not policy_name in count:
                        count[policy_name] = 1
                    else:
                        count[policy_name] += 1
        return count # return a dict of group policy objects with a count of how much they're seen in the config

    def acl_count(self): # count usage of ACLs
        count = {}
        conditions = [ # Regex, Default Value if found first, increment value
            ('^access-list', 1, 0), # Access List ACE's
            ('^access-group', 2, 1), # Access Group
            ('^\s*match access-list', 2, 1),  # class-map
            ('^\s*split-tunnel-network-list', 2, 1), # vpn split-tunnel ACL
            ('^\s*match ip address', 2, 1),  # route-map 
            ('^\s*vpn-filter value', 2, 1), # AnyConnect VPN filter
            #('', 1, 1) # Anything -- will probably leave disabled
        ]
        for acl_name in self.items:
            count[acl_name] = 0
            for line in self.config:
                for condition, default, increment in conditions:
                    if re.match(condition, line) and acl_name in line:
                        count[acl_name] += (default if count[acl_name] == 0 else increment)
                        break
        return count # return a dict of ACL names with a count of how much they're used

    def obj_count(self): # count usages of objects / objects-groups
        count = {}
        for type in self.items:
            count[type] = {}
            for name in self.items[type]:
                for line in self.config:
                    if name in line:  
                        if not name in count[type]:
                            count[type][name] = 1
                        else:
                            count[type][name] += 1
        return count # return a dict of objects with a count of how much they're used

##########################################################################################################################
##########################################################################################################################

def dprint(line):
    if DEBUG:
        print(f"(d) {line}")

def get_unique_items(config): # find all unique configuration types
    obj_names = {} # object names
    objgrp_names = {} #object-group names
    acl_names = [] # access-list names
    grp_names = [] # group-policy names
    
    for line in config:
        if line.startswith('object '):
            type = line.split().pop(1)
            name = line.split().pop(2)
            if type not in obj_names:
                obj_names[type] = [name]
            else:
                obj_names[type].append(name)
        if line.startswith('object-group'):
            type = line.split().pop(1)
            name = line.split().pop(2)
            if type not in objgrp_names:
                objgrp_names[type] = [name]
            else:
                objgrp_names[type].append(name)
        if line.startswith('access-list'):
            acl = (line.split()).pop(1)
            if not acl in acl_names:
                acl_names.append(acl)
        if line.startswith('group-policy'):
            gp = (line.split()).pop(1)
            if gp == 'DfltGrpPolicy':
                continue
            elif not gp in grp_names:
                grp_names.append(gp)
    return(obj_names, objgrp_names, acl_names, grp_names) # return names of unqiue items

def get_unsed_list_items(item_count): # generate a list of "list" items that aren't used
    config_list = []
    for item, count in list(item_count.items()):
        if count < 2:
            config_list.append(item)
    return config_list

def get_unused_dict_items(item_count): # generate a list of dict items that arne't used
    config_dict = {}
    for item in item_count:
        config_dict[item] = []
        for item_name, count in list(item_count[item].items()):
            if count < 2:
                config_dict[item].append(item_name)
    return config_dict

def generate_remove_list_config(lists, list_type): # generate the config to remove list items
    config = []
    if len(lists) > 0:
        config.append(f"\n--- {list_type} ---")
    for list in lists:
            config.append(f"clear configure {list_type} {list}")
    return config

def generate_remove_dict_config(dicts, dict_type): # generate the configu to remove dict items
    config = []
    if len(dicts) > 0:
        config.append(f"\n--- {dict_type} ---")
    for dict_type,names in list(dicts.items()):
        for name in names:
            config.append(f"no {dict_type} {dict_type} {name}")
    return config
        
def find_remark_task(hash,acl): # Find the remark above this ACE hash
    dead_ace=[]
    for acl_line in range(len(acl)):
        ace = acl[acl_line]
        if f'0x{hash}' in ace:
            remark_line=acl_line
            while True:
                if remark_line > 1:
                    remark_line -= 1
                else:
                    return  "Not Found", "--------------------------" # not found, lets return something
                try: 
                    ticket = ""
                    ticket = (re.search("(SCTASK|INC|CHG)\d+", acl[remark_line].upper()))
                    if ticket:
                        return ticket.group(0), acl[remark_line] # return TASK and remark line
                except Exception as e:
                    print(e)

def add_acl_to_dict(aged_acl_dict, ticket, remark, ace):  # Add an ACL to our aged_acl_dict 
    if ticket not in aged_acl_dict:
        aged_acl_dict[ticket] = [remark]
        aged_acl_dict[ticket].append(ace)
    else: 
        if remark not in aged_acl_dict[ticket]: 
            aged_acl_dict[ticket].append(remark)
        if ace not in aged_acl_dict[ticket]: 
            aged_acl_dict[ticket].append(ace)
    return aged_acl_dict

def get_aged_aces(aged_acl_dict, acl, acl_brief): # searches for ace's with zero hitcount, or 90 days since last hit
    for ace in acl: # loop through ACL
        if "(hitcnt=" in ace: # initial check to see if we will find a hash
            ace_hash = (re.findall("[0-9a-fA-F]+\s*$", ace))[0].strip()
        else:  # if there isn't a hitcnt on the ACE - we don't want to process this line
            continue

        if "(inactive)" in ace: # if inactive, I don't care about Last hit
            continue
        elif "(hitcnt=0)" in ace:  # if no hitcount, the hash won't up in show access-list NAME brief
            ticket, remark = find_remark_task(ace_hash, acl)
            aged_acl_dict = add_acl_to_dict(dict(aged_acl_dict), ticket, remark, ace)
            continue

        for hashes in acl_brief: # Loop through acl_brief
            if ace_hash == hashes.split(' ')[0]: # If ace_hash matches the current line's hash
                days_ago = 0
                last_hit = datetime.fromtimestamp(int(hashes.split(' ')[3], 16))
                days_ago =  datetime.today() - last_hit  
                if days_ago.days >= 10: 
                    ticket, remark = find_remark_task(ace_hash, acl)
                    aged_acl_dict = add_acl_to_dict(dict(aged_acl_dict), ticket, remark, ace)
                break 
    return aged_acl_dict

##########################################################################################################################
##########################################################################################################################

def main():
    VERSION = "0.1.2"
    KEYRING="asa-audit"
    DO_ACL_EVAL = True  # Do ACL evaluation of hits
    DO_UNUSED_EVAL = True # Do evaluation of unused configuraiton items
    SAVE_CREDS_TO_KEYRING = True # Do we save all of our creds to the keyring by default?
    AUTO_KEYCHAIN = True # Automagicallu try the keychain if no password supplied

    print(f"\n\n# ASA Audit v{VERSION} 2023 - Tony Mattke @tonhe")
    print("-----------------------------------------------------------\n")

    parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser(prog="python3 asa-audit.py", 
                                     description="Auditing of ASA Configurations ACE's and Config Items")
    parser.add_argument("host", help="Hostname or IP of the ASA", default="", nargs="*")
    parser.add_argument("-u", "--user", dest="user", help="User ID for login", default="")
    parser.add_argument("-k", "--keyring", dest="keyring", help="Pull password from local keyring (by hostname)", action="store_true")
    parser.add_argument("-p", "--password", dest="change_password", help="Change keyring password via interactive login", action="store_true")
    parser.add_argument("-d", dest="debug", help=argparse.SUPPRESS, action="store_true")
    args = parser.parse_args()

    username=args.user
    password=""

    if args.debug:
        global DEBUG 
        DEBUG = True
        print(">Debug ON")

    if args.host:
        hostname = args.host[0]
    if not hostname:
        hostname = input("Enter the ASA Management IP/Hostname: ")
    if "@" in args.host: # for those that username@hostname
        username=args.host.split('@')[0]
        hostname=args.host.split('@')[1]
    while not username:
        username = getpass.getuser('Username: ')
    if (args.keyring or AUTO_KEYCHAIN) and not args.change_password:
        print("Pulling password from local keyring.")
        password=keyring.get_password(KEYRING, hostname)
        dprint (f"password=keyring.get_password({KEYRING}, {hostname} )")
        if not password:
            print(f"Password for {hostname} not found in keyring\n")
    while not password: # Just in case we still don't have a password... 
        password = getpass.getpass('Password: ')

    notloggedin = True
    while notloggedin:
        try:
            print(f"Logging into {hostname}")
            ssh_connection = Netmiko(host=hostname, username=username, password=password, device_type='cisco_asa')
            notloggedin = False
        except NetMikoAuthenticationException as e: # Catch any authorization errors
            print ("\n!! Authorization Error\n")
            dprint (e)
            notloggedin = True
            password  = ""
            while not password: 
                password = getpass.getpass('Password: ')
        except Exception as e:                  # If login fails loops to begining displaying the error message
            print(e)
    
    if SAVE_CREDS_TO_KEYRING:
        keyring.set_password(KEYRING, hostname, password)

    ssh_connection.find_prompt()         # Expects to receive prompt back from the ASA
    ssh_connection.send_command('term pager 0')

    print("Retrieving show running-configuration")
    asa_config = ssh_connection.send_command('show run').split("\n")
    
    print("Evaluating Configuration Items....")
    # Find all unique names for Objects, Object-Groups, ACLs, Group-Policies
    obj_names, objgrp_names, acl_names, grp_names = get_unique_items(asa_config)

    if DO_ACL_EVAL:
        sh_acls = {}
        sh_briefs = {}
        #acl_names = [] # TESTING -- allows us to single out a single ACL 
        #acl_names.append("INSIDE-IN")
        print("Gathering all sh access-list / brief")
        for acl in acl_names:
            print(f" - {acl}.", end='')
            sh_acls[acl] = ssh_connection.send_command(f"show access-list {acl}").split("\n")
            print(".", end='')
            sh_briefs[acl] = ssh_connection.send_command(f"show access-list {acl} brief").split("\n")
            print(". done")

    ssh_connection.disconnect()
    print(f"-Disconecting from {hostname}...\n")

    if DO_ACL_EVAL:
        aged_acl_dict = {}
        print("Starting ACE Evaluations....")
        for acl in acl_names:
            print(f"> Processing ACL -  {acl}")
            aged_acl_dict = get_aged_aces(aged_acl_dict, sh_acls[acl], sh_briefs[acl])
        print("done\n")

        print("Writing aged_acls.txt to disk.", end="")
        file = open("aged_acls.txt", "w")
        for task in aged_acl_dict: 
            print(".", end="")
            file.write(f"\n------- {task} -------\n")
            for line in aged_acl_dict[task]:
                file.write(f">{line}\n")
        file.close()
        print(". done\n")

    if DO_UNUSED_EVAL: # Identify Unused Configurations, and generate the config to remove them
        print("Searching configuration for unused items")
        unused_items = []
        unused_items.extend(generate_remove_list_config(get_unsed_list_items(ASAConfig(grp_names, asa_config).grp_count()), "group-policy"))
        unused_items.extend(generate_remove_list_config(get_unsed_list_items(ASAConfig(acl_names, asa_config).acl_count()), "access-list"))
        unused_items.extend(generate_remove_dict_config(get_unused_dict_items(ASAConfig(objgrp_names, asa_config).obj_count()), "object-group"))
        unused_items.extend(generate_remove_dict_config(get_unused_dict_items(ASAConfig(obj_names, asa_config).obj_count()), "object"))
        print("done\n")

        print("Writing unused_items.txt to disk.", end="")
        file = open("unused_items.txt", "w")
        for line in unused_items: 
            print(".", end="")
            file.write(f"{line}\n")
        file.close()
        print(". done\n")

    print("\n\nAudit Complete - Exiting.")

##########################################################################################################################
##########################################################################################################################

if __name__ == '__main__':
    main()
