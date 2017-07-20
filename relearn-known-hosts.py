#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# This file is subject to the terms and conditions defined in
# file 'LICENSE', which is part of this source code package.
#


import logging
import pprint
import subprocess

from util import read_hosts_config, config_file_name

logger = logging.getLogger()
pp = pprint.PrettyPrinter(indent=2)

ssh_timeout_secs = 5

# ------------------------------------ MAIN PROGRAM ------------------------------------ #
if __name__ == "__main__":

    hosts_config = read_hosts_config()

    logger.info('Removing known_hosts entries for all IPs in ...'.format(config_file_name))

    clear_backup_cmd_str = "rm -f ~/.ssh/known_hosts.old"

    subprocess.call(clear_backup_cmd_str, shell=True)

    for one_entry in hosts_config:

        if "ip" in one_entry.keys():
            one_ip = one_entry["ip"]
            cmd_str = "ssh-keygen -q -R " + one_ip + " > /dev/null 2>&1"

            subprocess.call(cmd_str, shell=True)
            subprocess.call(clear_backup_cmd_str, shell=True)

        if "name" in one_entry.keys():
            one_name = one_entry["name"]
            cmd_str = "ssh-keygen -q -R " + one_name + " > /dev/null 2>&1"

            subprocess.call(cmd_str, shell=True)
            subprocess.call(clear_backup_cmd_str, shell=True)

    logging.info('Removal complete')
    logging.info('Re-learning known_hosts entries for all active host IPs ...')

    for one_entry in hosts_config:

        if "ip" not in one_entry.keys():
            continue
        if "name" not in one_entry.keys():
            continue
        if "user" not in one_entry.keys():
            continue
        if "state" not in one_entry.keys():
            continue

        if one_entry["state"].lower() != "on":
            continue

        cmd_str = 'ssh  -o BatchMode=yes  -o ConnectTimeout={0} -o StrictHostKeyChecking=no -q '.format(
            ssh_timeout_secs)

        if one_entry["user"] != "SRCUSER":
            cmd_str += one_entry["user"] + "@"

        cmd_str1 = cmd_str + one_entry["ip"] + " hostname"
        cmd_str2 = cmd_str + one_entry["name"] + " hostname"

        subprocess.call(cmd_str1, shell=True)
        subprocess.call(clear_backup_cmd_str, shell=True)
        subprocess.call(cmd_str2, shell=True)
        subprocess.call(clear_backup_cmd_str, shell=True)
