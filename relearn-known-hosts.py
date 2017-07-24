#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# This file is subject to the terms and conditions defined in
# file "LICENSE", which is part of this source code package.
#


import logging
import subprocess

from util import parse_std_arguments, config_logger
from util import add_user_host_part, read_hosts_config


# -------------------------- MAIN PROGRAM -------------------------- #
if __name__ == "__main__":
    cmd_arguments = parse_std_arguments(
        """
        Forget and re-learn destination SSH host keys.
        Useful in environments where the network is trusted and hosts
        are frequently re-created or re-installed, and there is no
        tracking of SSH host keys. USING THIS SCRIPT WITHOUT UNDERSTANDING
        AND CONTROLLING ITS SECURITY IMPLICATIONS BREAKS THE SSH
        MAN-IN-THE-MIDDLE ATTACK DETECTION SYSTEM!
        """)

    config_logger(cmd_arguments)
    log = logging.getLogger()

    hosts_config = read_hosts_config(cmd_arguments.cfgfile)

    log.info("Removing known_hosts SSH keys for all hosts in %s ...",
             cmd_arguments.cfgfile)

    clear_backup_cmd_str = "rm -f ~/.ssh/known_hosts.old"

    subprocess.call(clear_backup_cmd_str, shell=True)

    part0 = "ssh-keygen -q -R"
    part2 = "> /dev/null 2>&1"

    for item in hosts_config:
        for k in ["ip", "name"]:
            if k in item.keys():
                cmd_str = "{0} {1} {2}".format(part0, item[k], part2)
                subprocess.call(cmd_str, shell=True)
                subprocess.call(clear_backup_cmd_str, shell=True)

    log.info("Removal complete.")
    log.info(
        "Re-learning known_hosts entries for all active host IPs ...")
    log.debug("Setting SSH connection timeout to %d seconds.",
              cmd_arguments.timeout)

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

        opt1 = "-o BatchMode=yes"
        opt2 = "-o ConnectTimeout={0}".format(cmd_arguments.timeout)
        opt3 = "-o StrictHostKeyChecking=no"
        test_cmd = " echo -n"

        base_cmd = "ssh {0} {1} {2} -q ".format(opt1, opt2, opt3)

        for k in ["ip", "name"]:
            cmd_str = "{0} {1}".format(
                          add_user_host_part(
                              base_cmd, item["user"], item[k]), test_cmd)

            log.debug("Learning SSH host key (if possible) for '%s' ...",
                      item[k])
            subprocess.call(cmd_str, shell=True)
            subprocess.call(clear_backup_cmd_str, shell=True)

