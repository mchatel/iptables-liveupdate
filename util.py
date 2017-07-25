#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# This file is subject to the terms and conditions defined in
# file "LICENSE", which is part of this source code package.
#

import argparse
import json
import logging
import sys


log_format = "%(asctime)-23s %(levelname)-8s %(message)s"


def early_log_setup():
    """
    Setup basic default logging without command-line arguments.
    This is used when errors occur so early that logging has not YET
    been configured based on command-line arguments.
    """
    logging.basicConfig(level=logging.INFO, format=log_format)


def parse_std_arguments(p_message):
    """
    Parse command line arguments.
    Do some application-level error-checking as well.
    If application-level errors occur, use the default-configuration
    logging system to report the error, show the command help,
    and force an exit.
    :param p_message: overall description of high-level command
    :return: parsed command line arguments
    """
    parser = argparse.ArgumentParser(description=p_message)

    # Specify optional arguments

    parser.add_argument(
        "--loglevel", required=False, default="INFO",
        choices=["ERROR", "WARNING", "INFO", "DEBUG"],
        help="set the log verbosity level, default=INFO")
    parser.add_argument(
        "--log", required=False, default="tty", metavar="DESTINATION",
        help="choose log destination: tty (DEFAULT), or a filename")
    parser.add_argument(
        "--timeout", required=False, default=5, type=int,
        help="set the SSH connection timeout in seconds, default=5")

    # Specify mandatory argument

    parser.add_argument(
        "cfgfile", metavar="json_config_file_name",
        help="filename of JSON configuration with host list")

    # Do the actual argument parsing

    args = parser.parse_args()

    if (args.timeout < 1) or (args.timeout > 60):
        early_log_setup()
        log = logging.getLogger()
        log.error("timeout should be within the range [1,60]")
        log.info("Now showing command syntax...")
        parser.print_help()
        sys.exit(1)

    try:
        try_file = open(args.cfgfile)
        try_file.close()

    except IOError, (strerror):
        early_log_setup()
        log = logging.getLogger()
        log.error("Cannot open file: %s", strerror)
        log.info("Now showing command syntax...")
        parser.print_help()
        sys.exit(1)

    return args


def config_logger(p_args):
    """
    Configure the logging system according to the passed command line
    arguments.
    :param p_args: command-line arguments as parsed
    :return:
    """
    loglevel_num = getattr(logging, p_args.loglevel)

    if p_args.log == "tty":
        logging.basicConfig(level=loglevel_num, format=log_format)
    else:
        logging.basicConfig(
            level=loglevel_num, filename=p_args.log, format=log_format)


def gen_no_unicode_data(p_data):
    """
    Convert Unicode strings within a data structure to their
    non-Unicode variant. Works recursively. To support a simplistic
    commenting feature, ignores dictionary keys that start with
    the pound/octothorpe character (#).
    :param p_data: data structure to convert
    :return: copy of the data structure with no Unicode strings
    """
    if isinstance(p_data, dict):
        rc_data = {}
        for k in p_data.keys():
            k_str = str(k)
            # Interpret a key that starts with a "#" as a
            # commented-out entry.
            if k_str[0] != "#":
                rc_data[k_str] = gen_no_unicode_data(p_data[k])
        return rc_data

    if isinstance(p_data, list):
        rc_data = []
        for i in p_data:
            rc_data.append(gen_no_unicode_data(i))
        return rc_data

    return str(p_data)


def read_hosts_config(p_config_file_name):
    """
    Reads an input configuration file in JSON format.
    :param p_config_file_name: the input file name
    :return: the data read, normally a list or dictionary
    """
    json_file = open(p_config_file_name)
    rc_data = gen_no_unicode_data(json.load(json_file))
    json_file.close()

    return rc_data


def add_user_host_part(p_cmd_str, p_user, p_host):
    """
    Add a destination specification to a partially built SSH command.
    The format for this depends on the value of p_user.
    :param p_cmd_str: already built SSH command prefix string
    :param p_user: remote SSH user, or SRCUSER
    :param p_host: target host address or name
    :return: Partially built SSH command string with destination spec
    """
    if p_user == "SRCUSER":
        rc_cmd_str = "{0} {1}".format(p_cmd_str, p_host)
    else:
        rc_cmd_str = "{0} {1}@{2}".format(p_cmd_str, p_user, p_host)

    return rc_cmd_str

