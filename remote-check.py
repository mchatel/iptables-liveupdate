#!/usr/bin/python

import argparse
import logging
import pprint
import subprocess
import time

from util import read_hosts_config

logger = logging.getLogger()

pp = pprint.PrettyPrinter(indent=2)

ssh_timeout_secs = 5

app_tmpdir = "~/tmp"
check_script_base = "check-sendable"
do_live_update = 0


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
        rc_cmd_str = (p_cmd_str +
                      p_user + "@" + p_host_ip)

    return rc_cmd_str


def parse_arguments():
    """
    Parse command-line arguments.
    :return: the parsed arguments
    """
    message = """
    iptables live-update tool
    -------------------------------------------------------------------------------------------------------
    By default, the script just performs read-only checks on the host iptables configurations.

    If 'liveupdate' is specified, and the host has 'stored' iptables rules that are not 'live' in-kernel, 
    the script attempts to insert the rules 'live' in-kernel if it appears safe to do so.

    If 'debug' is specified, additional messages are shown.
    """
    parser = argparse.ArgumentParser(description=message)
    parser.add_argument('--debug', required=False, default=False)
    parser.add_argument('--live-update', required=False, default=False)
    args = parser.parse_args()
    return args


# ------------------------------------ MAIN PROGRAM ------------------------------------ #
if __name__ == "__main__":
    collected_arguments = parse_arguments()
    if collected_arguments.live_update:
        do_live_update = 1

    if collected_arguments.debug:
        logger.setLevel(logging.DEBUG)

    hosts_config = read_hosts_config()

    our_time_str = str(int(time.time()))

    logger.info('Computed ephemeral time string = {0} ...'.format(our_time_str))

    check_src_script = '{0}.py'.format(check_script_base)
    check_dest_script = '{0}-{0}.py'.format(check_script_base, our_time_str)
    timeout_str = ' -o ConnectTimeout={} '.format(ssh_timeout_secs)

    base_ssh_str = 'ssh  -o BatchMode=yes {0} -q '.format(timeout_str)
    base_scp_str = 'scp {0} -q '.format(timeout_str)

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

        logger.info('Performing actions for host "{0}" ...'.format(one_entry["name"]))

        logger.info('Ensuring the temporary directory exists.')

        host_ssh_str = add_user_host_part(base_ssh_str, one_entry["user"], one_entry["ip"])

        cmd_str = '{0} "mkdir -p {1}"'.format(host_ssh_str, app_tmpdir)

        subprocess.call(cmd_str, shell=True)

        logger.info('Copying the \'sendable\' check script.')

        cmd_str = add_user_host_part(base_scp_str + check_src_script + ' ', one_entry["user"], one_entry["ip"])
        cmd_str += ':{0}/{1}'.format(app_tmpdir, check_dest_script)

        subprocess.call(cmd_str, shell=True)

        logger.info('Running the check script on the target host.')

        '{0} \'T_DIR={1} ; sudo $T_DIR/{2}'.format(host_ssh_str, app_tmpdir, check_dest_script)

        if do_live_update != 0:
            cmd_str += ' liveupdate\''
        else:
            cmd_str += '\''

        subprocess.call(cmd_str, shell=True)

        logger.info('Erasing the \'sendable\' check script.')

        cmd_str = '{0} "rm -f {1}/{2}"'.format(host_ssh_str, app_tmpdir, check_dest_script)
        subprocess.call(cmd_str, shell=True)
