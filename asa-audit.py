#!/usr/bin/env python3
import sys
#import os
import re
#import time
import argparse
from getpass import getpass
from netmiko import Netmiko
from datetime import datetime

class ItemCount:
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
                elif 'default-group-policy ' + policy_name in line:
                    if not policy_name in count:
                        count[policy_name] = 1
                    else:
                        count[policy_name] += 1
        return count

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
        return count

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
        return count

##########################################################################################################################
##########################################################################################################################

def identify_items(config): # count all unique configuration types
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
    return(obj_names, objgrp_names, acl_names, grp_names)

def remove_list(item_count): # generate a list of "list" items that aren't used
    config_list = []
    for item, count in list(item_count.items()):
        if count < 2:
            config_list.append(item)
    return config_list

def remove_dict(item_count): # generate a list of dict items that arne't used
    config_dict = {}
    for item in item_count:
        config_dict[item] = []
        for item_name, count in list(item_count[item].items()):
            if count < 2:
                config_dict[item].append(item_name)
    return config_dict

def gen_rmlist_config(lists, list_type): # generate the config to remove list items
    config = []
    if len(lists) > 0:
        config.append("\n--- %s ---" % list_type)
    for list in lists:
            config.append("clear configure %s %s" % (list_type, list))
    return config

def gen_rmdict_config(dicts, dict_type): # generate the configu to remove dict items
    config = []
    if len(dicts) > 0:
        config.append("\n--- %s ---" % dict_type)
    for dict_type,names in list(dicts.items()):
        for name in names:
            config.append("no %s %s" % ((dict_type + " " + dict_type), name))
    return config
        
def find_remark_task(hash,acl):
    dead_ace=[]
    for acl_line in range(len(acl)):
        ace = acl[acl_line]
        if ("0x" + hash) in ace:
            remark_line=acl_line
            while True:
                if remark_line > 1:
                    remark_line -= 1
                else:
                    ticket = "Not Found"
                    remark = "----------------------------"
                    return  ticket, remark
                try: 
                    ticket = ""
                    ticket = (re.search("(SCTASK|INC|CHG)\d+", acl[remark_line].upper()))
                    if ticket:
                        return ticket.group(0), acl[remark_line]
                except Exception as e:
                    print(e)

def add_2acl_dict(acl_dict, ticket, remark, ace): 
    if ticket not in acl_dict:
        acl_dict[ticket] = [remark]
        acl_dict[ticket].append(ace)
    else: 
        if remark not in acl_dict[ticket]: 
            acl_dict[ticket].append(remark)
        if ace not in acl_dict[ticket]: 
            acl_dict[ticket].append(ace)
    return acl_dict

def get_aged_aces(acl_dict, acl, acl_brief): # searches for ace's with zero hitcount, or 90 days since last hit
    for ace in acl: # loop through ACL
        if "(hitcnt=" in ace: # initial check to see if we will find a hash
            ace_hash = (re.findall("[0-9a-fA-F]+\s*$", ace))[0].strip()
        else:  # if there isn't a hitcnt on the ACE - we don't want to process this line
            continue

        if "(inactive)" in ace: # if inactive, I don't care about Last hit
            continue
        elif "(hitcnt=0)" in ace:  # if no hitcount, the hash won't up in show access-list NAME brief
            ticket, remark = find_remark_task(ace_hash, acl)
            acl_dict = add_2acl_dict(dict(acl_dict), ticket, remark, ace)
            continue

        for hashes in acl_brief: # Loop through acl_brief
            if ace_hash == hashes.split(' ')[0]: # If ace_hash matches the current line's hash
                days_ago = 0
                last_hit = datetime.fromtimestamp(int(hashes.split(' ')[3], 16))
                days_ago =  datetime.today() - last_hit  
                if days_ago.days >= 10: 
                    ticket, remark = find_remark_task(ace_hash, acl)
                    acl_dict = add_2acl_dict(dict(acl_dict), ticket, remark, ace)
                break 
    return acl_dict

##########################################################################################################################
##########################################################################################################################

def main():
    DO_ACL_EVAL = False  # Do ACL evaluation of hits
    DO_UNUSED_EVAL = True # Do evaluation of unused configuraiton items
    DO_DUP_EVAL = False  # Do evaluation of duplicate items
    VERSION = "0.0.6"

    parser = argparse.ArgumentParser()

    parser.add_argument("host", metavar="hostname", help="Hostname or IP of the ASA")
    parser.add_argument("-k", "--key", dest="key", help="API key for Secret Server",default="")
    parser.add_argument("-s", "--secret", dest="secret", help="Secret ID for Secret Server", default="") 
    parser.add_argument("-u", "--user", dest="user", help="User ID to Login with", default="")
    parser.add_argument("-p", "--password", dest="password", help="Password for User ID (interactive login is default)", default="")
    parser.add_argument("-d", dest="debug", help=argparse.SUPPRESS, action="store_true")
    parser.add_argument("-f", dest="file", help=argparse.SUPPRESS, action="store_true")

    args = parser.parse_args()

    username=args.user
    password=args.password
    hostname = args.host

    if "@" in args.host: # for those that username@hostname
        username=args.host.split('@')[0]
        hostname=args.host.split('@')[1]
    if args.file:
        import config # Imports config.py for testing only
        username=config.username
        password=config.password
    if not password:
        password = getpass('Enter the ASA password: ')
    if args.key or args.secret:
        if not args.key and not args.secret:
            sys.exit("You must supply both an API key and secret ID to use this feature")
        else:  
            sys.exit("\nAPI Not implemented yet") # until we have this working
            #username, password = get_pwmcreds(args.key,args.secret)
    elif not username or not password:
        sys.exit("\nWe need username and password to continue...")
    if args.debug:
        print("DEBUG ON")

    print("\n\n# ASA Audit v%s 2023 - Tony Mattke @tonhe" % (VERSION))
    print("-----------------------------------------------------------\n\n")

    try:
        print("Logging into %s" % hostname)
        ssh_connection = Netmiko(host=hostname, username=username, password=password, device_type='cisco_asa')
        ssh_connection.find_prompt()         # Expects to receive prompt back from the ASA
        ssh_connection.send_command('term pager 0')

    except Exception as e:                  # If login fails loops to begining displaying the error message
        print(e)

    print("Retrieving show running-configuration")
    asa_config = ssh_connection.send_command('show run').split("\n")
    
    print("Evaluating Configuration Items....")
    # Find all unique names for Objects, Object-Groups, ACLs, Group-Policies
    obj_names, objgrp_names, acl_names, grp_names = identify_items(asa_config)

    if DO_ACL_EVAL:
        sh_acls = {}
        sh_briefs = {}
        # TESTING -- allows us to single out a single ACL 
        #acl_names = []
        #acl_names.append("INSIDE-IN")
        print("Gathering all sh access-list / brief")
        for acl in acl_names:
            print(" - " + acl + ".", end='')
            sh_acls[acl] = ssh_connection.send_command("show access-list %s " % acl).split("\n")
            print(".", end='')
            sh_briefs[acl] = ssh_connection.send_command("show access-list %s brief " % acl).split("\n")
            print(". done")

    ssh_connection.disconnect()
    print("-Disconecting from %s...\n" % hostname)

    if DO_ACL_EVAL:
        acl_dict = {}
        print("Starting ACE Evaluations....")
        for acl in acl_names:
            print("> Processing ACL -  %s" % acl)
            acl_dict = get_aged_aces(acl_dict, sh_acls[acl], sh_briefs[acl])
        print("done\n")

        print("Writing Aged ACLs to file.", end="")
        file = open("aged_acls.txt", "w")
        for task in acl_dict: 
            print(".", end="")
            file.write("\n------- %s -------\n" % task)
            for line in acl_dict[task]:
                file.write("> %s\n" % line)
        file.close()
        print(". done")

    if DO_UNUSED_EVAL: # Identify Unused Configurations, and generate the config to remove them
        print("Searching configuration for unused items")
        unused_items = []
        unused_items.extend(gen_rmlist_config(remove_list(ItemCount(grp_names, asa_config).grp_count()), "group-policy"))
        unused_items.extend(gen_rmlist_config(remove_list(ItemCount(acl_names, asa_config).acl_count()), "access-list"))
        unused_items.extend(gen_rmdict_config(remove_dict(ItemCount(objgrp_names, asa_config).obj_count()), "object-group"))
        unused_items.extend(gen_rmdict_config(remove_dict(ItemCount(obj_names, asa_config).obj_count()), "object"))
        print(*unused_items, sep="\n")
        print("done")

    print("\n\nAudit Complete - Exiting.")

##########################################################################################################################
##########################################################################################################################

if __name__ == '__main__':
    main()
