# asa-audit.py
Cisco ASA Audit Tool 

NAME

	ASA-Audit - Cisco ASA Auditing tool

SYNOPSIS

    usage: working_asa-audit.py [-h] [-k KEY] [-s SECRET] [-u USER] [-p PASSWORD] hostname

    positional arguments:
        hostname              Hostname or IP of the ASA

    options:
        -h, --help                          Show this help message and exit
        -k KEY, --key KEY                   API key for Secret Server
        -s SECRET, --secret SECRET          Secret ID for Secret Server
        -u USER, --user USER                User ID to Login with
        -p PASSWORD, --password PASSWORD    Password for User ID (interactive login is default)

DESCRIPTION

    This script was created to provide a mechanism for auditing ASA Configurations.
    It looks at three different aspects of the configuration for improvements.

    Frist - this script analyizes each ACL for zero hitcount ACEs or ACEs that 
        have not been hit in 90+ days. (Using data from show access-list NAME brief)

    Second - This script analizes various objects types for usage. 
        This includes (Access-Lists, object, object-groups, and group-policy)

    Third - This script analizes objects and object groups for any duplicates (TBD)

