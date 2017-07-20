#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# This file is subject to the terms and conditions defined in
# file 'LICENSE', which is part of this source code package.
#


import logging
import subprocess
import time

from util import read_hosts_config

ssh_timeout_secs = 5


def add_user_host_part(p_cmd_str, p_user, p_host_ip):
    """

    :param p_cmd_str:
    :param p_user:
    :param p_host_ip:
    :return:
    """
    if p_user == "SRCUSER":
        rc_cmd_str = p_cmd_str + p_host_ip
    else:
        rc_cmd_str = '{0}{1}@{2}'.format(p_cmd_str, p_user, p_host_ip)

    return rc_cmd_str


# ------------------------------------ MAIN PROGRAM ------------------------------------ #
if __name__ == "__main__":
    logger = logging.getLogger()
    logger.info('Starting IPtables backup script')
    logger.info('===============================')

    hosts_config = read_hosts_config()

    our_time = time.gmtime()
    our_time_str = time.strftime("%Y%m%d-%H%M%S", our_time)
    base_target_dir = './iptables-backup-{0}'.format(our_time_str)
    timeout_str = ' -o ConnectTimeout={0} '.format(ssh_timeout_secs)
    base_scp_str = 'scp {0} -q '.format(timeout_str)
    base_ssh_str = 'ssh {0} -q '.format(timeout_str)

    logger.info('Target directory for backup is {0}'.format(base_target_dir))

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

        logger.info('Attempting to get IPtables config for host "{0}" ...'.format(one_entry["name"]))

        target_dir = base_target_dir + "/" + one_entry["name"]

        cmd_str = "mkdir -p " + target_dir
        subprocess.call(cmd_str, shell=True)

        host_scp_str = '{0}:/etc/iptables/rules.v4 {1}/rules.v4 2> /dev/null' \
            .format(add_user_host_part(base_scp_str, one_entry["user"], one_entry["ip"]), target_dir)

        subprocess.call(host_scp_str, shell=True)

        host_ssh_str = '{0} \'sudo iptables -t filter --list-rules \' > {1}/rules-live-filter' \
            .format(add_user_host_part(base_ssh_str, one_entry["user"], one_entry["ip"]), target_dir)

        subprocess.call(host_ssh_str, shell=True)

        host_ssh_str = '{0} \'sudo iptables -t nat --list-rules \' > {1}/rules-live-nat' \
            .format(add_user_host_part(base_ssh_str, one_entry["user"], one_entry["ip"]), target_dir)

        subprocess.call(host_ssh_str, shell=True)
