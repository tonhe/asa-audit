# asa-audit.py
Cisco ASA Audit Tool 

NAME

    ASA-Audit - Cisco ASA Auditing tool

SYNOPSIS

    usage: pythong3 asa-audit.py [-h] [-u USER] [-k] [-p] [host ...]

    Auditing of ASA Configurations ACE's and Config Items

    positional arguments:
    host                  Hostname or IP of the ASA

    options:
    -h, --help            show this help message and exit
    -u USER, --user USER  User ID for login
    -k, --keyring         Pull password from local keyring (by hostname)
    -p, --password        Change keyring password via interactive login


DESCRIPTION

    This script was created to provide a mechanism for auditing ASA Configurations.
    It looks at three different aspects of the configuration for improvements.

    Frist - this script analyizes each ACL for zero hitcount ACEs or ACEs that 
        have not been hit in 90+ days. (Using data from show access-list NAME brief)

    Second - This script analizes various objects types for usage. 
        This includes (Access-Lists, object, object-groups, and group-policy)

    Third - This script analizes objects and object groups for any duplicates (TBD)

