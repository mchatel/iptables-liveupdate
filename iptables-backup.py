#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# This file is subject to the terms and conditions defined in
# file "LICENSE", which is part of this source code package.
#


import logging
import subprocess
import time

from util import parse_std_arguments, config_logger
from util import add_user_host_part, read_hosts_config

file_try_list = [["/etc/iptables/rules.v4", "debian-v4-rules"],
                 ["/etc/iptables/rules.v6", "debian-v6-rules"],
                 ["/etc/sysconfig/iptables", "centos-v4-rules"],
                 ["/etc/sysconfig/ip6tables", "centos-v6-rules"]]

live_try_list = [["iptables", "in-kernel-v4-rules"],
                 ["ip6tables", "in-kernel-v6-rules"]]


# -------------------------- MAIN PROGRAM -------------------------- #
if __name__ == "__main__":
    cmd_arguments = parse_std_arguments(
        """
        On a list of remote hosts, captures backups of 'stored' and
        'in-kernel' IPtables IPv4 and IPv6 configurations.
        For this to work, for each host, the username used must have
        SCP read-access to IPtables configuration files (without SUDO),
        and SUDO access to 'iptables' and 'ip6tables' commands.
        """)

    config_logger(cmd_arguments)
    log = logging.getLogger()

    log.info("Starting IPtables backup script")

    hosts_config = read_hosts_config(cmd_arguments.cfgfile)

    our_time = time.gmtime()
    our_time_str = time.strftime("%Y%m%d-%H%M%S", our_time)
    base_target_dir = "./iptables-backup-{0}".format(our_time_str)
    timeout_str = "-o ConnectTimeout={0}".format(cmd_arguments.timeout)
    base_scp_str = "scp {0} -q ".format(timeout_str)
    base_ssh_str = "ssh {0} -q ".format(timeout_str)

    log.info("Target directory for backup is %s ...", base_target_dir)

    for item in hosts_config:

        num_missing = 0

        for needed_field in ["ip", "name", "user", "state"]:
            if needed_field not in item.keys():
                log.warning(
                    "A config file entry misses field '%s'.", needed_field)
                num_missing += 1

        if num_missing > 0:
            log.warning("Skipping a config file entry that misses fields.")
            continue

        if item["state"].lower() != "on":
            log.debug("Ignoring host '%s' not in ON state", item["name"])
            continue

        log.info("Attempting to get IPtables config for host '%s' ...",
                 item["name"])

        target_dir = "{0}/{1}".format(base_target_dir, item["name"])
        cmd_str = "mkdir -p {0}".format(target_dir)
        subprocess.call(cmd_str, shell=True)

        part0 = add_user_host_part(base_scp_str, item["user"], item["ip"])

        for one_try in file_try_list:
            src_file = one_try[0]
            dst_file = one_try[1]

            log.debug("For host '%s', trying to get file %s ...",
                      item["name"], src_file)

            t_cmd = "{0}:{1} {2}/{3}".format(
                        part0, src_file, target_dir, dst_file)
            subprocess.call(t_cmd, shell=True)

        log.debug("For host '%s', trying to get in-kernel config...",
                  item["name"])

        part0 = add_user_host_part(base_ssh_str, item["user"], item["ip"])

        for one_try in live_try_list:
            cmd_name = one_try[0]
            dst_file_base = one_try[1]

            for one_table in ["filter", "nat", "mangle", "raw", "security"]:
                t_cmd = "{0} 'sudo {1} -t {2} {3}' > {4}/{5}-{6}".format(
                            part0, cmd_name, one_table, "--list-rules",
                            target_dir, dst_file_base, one_table)
                subprocess.call(t_cmd, shell=True)

