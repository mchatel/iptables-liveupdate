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

app_tmpdir = "~/tmp"
check_script_base = "iptables-liveupdate"


# -------------------------- MAIN PROGRAM -------------------------- #
if __name__ == "__main__":
    cmd_arguments = parse_std_arguments(
        """
        On a list of remote hosts, check differences between 'stored'
        and 'in-kernel' IPtables IPv4 and IPv6 configurations.
        For this to work, for each host, the username used must have
        SCP write-access to its home directory (without SUDO),
        and SUDO ALL access. If '--live-update' is specified, the
        script ALSO modifies the 'in-kernel' IPtables rules to make them
        satisfy the requirements of the 'stored' IPtables rules.
        """,
        p_add_live_update=1)

    config_logger(cmd_arguments)
    log = logging.getLogger()

    log.info("Starting IPtables liveupdate driver script...")

    hosts_config = read_hosts_config(cmd_arguments.cfgfile)

    our_time_str = str(int(time.time()))

    log.debug("Computed ephemeral time string = {0} ...".format(
                  our_time_str))

    src_script = "{0}.py".format(check_script_base)
    dest_script = "{0}-{1}.py".format(check_script_base, our_time_str)

    timeout_str = "-o ConnectTimeout={0}".format(cmd_arguments.timeout)

    ssh_opt_str = "-o BatchMode=yes {0} -q ".format(timeout_str)
    scp_opt_str = "{0} -q ".format(timeout_str)

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

        log.info("Acting on host '%s' with address '%s' ...",
                 item["name"], item["ip"])

        h_ssh_str = add_user_host_part(
                        ssh_opt_str, item["user"], item["ip"])

        h_scp_str = add_user_host_part(
                        "{0}{1} ".format(scp_opt_str, src_script),
                        item["user"], item["ip"])

        log.debug("Ensuring the tempdir exists on host '%s'.",
                  item["name"])

        cmd_str = "ssh {0} 'mkdir -p {1}'".format(h_ssh_str, app_tmpdir)
        subprocess.call(cmd_str, shell=True)

        log.debug("Sending the IPtables check script to host '%s'.",
                  item["name"])

        cmd_str = "scp {0}:{1}/{2}".format(
            h_scp_str, app_tmpdir, dest_script)

        subprocess.call(cmd_str, shell=True)

        log.debug("Running the IPtables check script on host '%s'.",
                  item["name"])

        cmd_str = "ssh {0} 'T_DIR={1} ; sudo $T_DIR/{2}".format(
                      h_ssh_str, app_tmpdir, dest_script)

        if cmd_arguments.live_update:
            cmd_str += " --live-update"

        cmd_str += " --loglevel=" + cmd_arguments.loglevel + "'"

        subprocess.call(cmd_str, shell=True)

        log.debug("Erasing the sent IPtables check script on host '%s'.",
                  item["name"])

        cmd_str = "ssh {0} 'rm -f {1}/{2}'".format(
                      h_ssh_str, app_tmpdir, dest_script)

        subprocess.call(cmd_str, shell=True)

