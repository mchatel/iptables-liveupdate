#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# This file is subject to the terms and conditions defined in
# file "LICENSE", which is part of this source code package.
#


import argparse
import logging

import string
import subprocess
import sys
import time

cmd_retry_count = 3
cmd_retry_delay = 1

filter_variants = [{"cmd": "iptables",
                    "desc": "IPv4",
                    "files": ["/etc/iptables/rules.v4",
                              "/etc/sysconfig/iptables"]},
                   {"cmd": "ip6tables",
                    "desc": "IPv6",
                    "files": ["/etc/iptables/rules.v6",
                              "/etc/sysconfig/ip6tables"]}]

supported_table_names = ["filter", "nat", "mangle", "raw", "security"]

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
        "--live-update", action="store_true",
        help="modify remote IPtables configuration on the fly")

    # Do the actual argument parsing

    args = parser.parse_args()
    return args


def config_logger(p_args):
    """
    Configure the logging system according to the passed command line
    arguments.
    :param p_args: command-line arguments as parsed
    :return:
    """
    loglevel_num = getattr(logging, p_args.loglevel)
    logging.basicConfig(level=loglevel_num, format=log_format)


def strip_white_space(p_str):
    """
    Take an input string, and return a copy of it, possibly modified:
    a) If there are tabs in the input string, they are replaced by spaces
       in the return string.
    b) Any carriage-return or line-feed characters are removed from the
       return string.
    c) The return string does not have any spaces at its end.

    :param p_str: The input string
    :return: A copy of the input string, possibly modified
    """

    if len(p_str) <= 0:
        return p_str

    rc_str = ""
    char_idx = 0

    while char_idx < len(p_str):

        one_char = p_str[char_idx]

        if (one_char == "\r") or (one_char == "\n"):
            char_idx += 1
            continue

        if one_char == "\t":
            one_char = " "

        rc_str += one_char
        char_idx += 1

    while len(rc_str) > 0:
        if rc_str[-1] != " ":
            break
        rc_str = rc_str[0:-1]

    return rc_str


def run_cmd_with_retry(p_cmd_str):
    """
    Run a command up to 'cmd_retry_count' times until
    its exit status is 0. For each non-zero case,
    sleep 'cmd_retry_delay' seconds before trying again.

    On older Linux distributions, the 'iptables' command does not
    support the '--wait' option, making the command susceptible
    to random failures due to mutual-exclusion locks. In those cases,
    using a retry is the best option available.

    :param p_cmd_str: Command to try to execute
    :return: 0 if all retries failed, 1 otherwise.
    """
    fn_rc = 0
    sys.stdout.flush()
    sys.stderr.flush()
    retry_attempt = 0

    while retry_attempt < cmd_retry_count:

        if retry_attempt != 0:
            log.info("Retrying command after failure.")
            time.sleep(cmd_retry_delay)

        cmd_rc = subprocess.call(p_cmd_str, shell=True)

        if cmd_rc == 0:
            if retry_attempt != 0:
                log.info("Command retry successful.")
            fn_rc = 1
            break

        retry_attempt += 1

    if fn_rc == 0:
        log.error("Command %s still fails after %s retries",
                  p_cmd_str, str(cmd_retry_count))

    sys.stdout.flush()
    sys.stderr.flush()
    return fn_rc


def check_iptable_wait_support():
    """
    Detect whether the current host has a version of 'iptables'
    that supports the option '--wait'. It is assumed that
    'iptables' and 'ip6tables' have the same support of '--wait'.

    :return: 1 if supported, otherwise 0
    """
    cmd_str = "iptables -h | fgrep -e --wait | wc -l"

    t_pipe = subprocess.Popen(cmd_str, shell=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)

    num_lines = 0
    rc_wait_support = 0

    for cur_line in t_pipe.stdout:

        num_lines += 1

        cur_number = int(cur_line)
        if cur_number > 0:
            rc_wait_support = 1
            opt_str = "supports"
        else:
            opt_str = "does not support"

        log.debug("IPtables version %s the --wait option.", opt_str)

    if num_lines != 1:
        log.error("IPtables version test command unexpected output!")
        sys.exit(1)

    return rc_wait_support


def read_rules_file(p_open_file, p_open_file_name):
    """
    Reads a text file in IPTables rules format,
    returns the data in a dictionary. Handles various conditions
    possible in text files:

    - ignores carriage returns (MS-DOS text conventions)
    - maps tab characters to spaces
    - if the last line in the file does not end with a linefeed character,
      still processes it OK.

    :param p_open_file: the open file
    :param p_open_file_name: its file name (for error messages)
    :return: a dictionary containing the lines from the file,
             indexed by line number
    """
    rc_rule_lines = dict()

    line_idx = 0
    at_least_one_cr = 0
    at_least_one_tab = 0
    line_with_no_lf = 0

    for one_line in p_open_file:

        line_idx += 1

        if len(one_line) > 0:
            if one_line[-1] == "\n":
                one_line = one_line[0:-1]
            else:
                line_with_no_lf = 1

        if len(one_line) > 0:
            if one_line[-1] == "\r":
                at_least_one_cr = 1
                one_line = one_line[0:-1]

        out_line = ""

        if len(one_line) > 0:

            char_idx = 0

            while char_idx < len(one_line):

                one_char = one_line[char_idx]

                if one_char == "\t":
                    at_least_one_tab = 1
                    one_char = " "

                out_line += one_char
                char_idx += 1

        rc_rule_lines[line_idx] = out_line

    if at_least_one_cr != 0:
        log.warning("File %s contains at least %s.", p_open_file_name,
                    "one carriage-return, which was silently filtered.")

    if line_with_no_lf != 0:
        log.warning("File %s has no linefeed %s.", p_open_file_name,
                    "after its last line, the line is processed anyway")

    if at_least_one_tab != 0:
        log.warning("File %s contains at least %s.", p_open_file_name,
                    "one tab, which was silently replaced by a space")

    return rc_rule_lines


def read_one_file_of(p_file_list):
    """
    Attempts to open and read EXACTLY ONE file based on a list of
    possible file names.

    :param p_file_list: a list of file names to attempt
    :return: If successful, returns 1 AND a dictionary containing the
             text lines. Otherwise, returns 0 and an empty dictionary.
    """
    rc_read_lines = dict()
    num_open_ok = 0

    if len(p_file_list) <= 0:
        log.error("No file names passed !")
        return num_open_ok, rc_read_lines

    if len(p_file_list) == 1:
        log.debug("Parsing IPtables file %s.", p_file_list[0])
    else:
        t_msg = "Parsing exactly one IPtables file out of: ["
        for one_file_name in p_file_list:
            t_msg += " {0}".format(one_file_name)
        t_msg += " ]"
        log.debug(t_msg)

    for one_file_name in p_file_list:

        try:
            one_file = open(one_file_name, mode="rb")
            open_ok = 1
        except IOError:
            open_ok = 0

        if open_ok == 1:
            num_open_ok += 1

            if num_open_ok > 1:
                log.error("More than one file is accessible !")
                rc_read_lines = dict()
                one_file.close()
                break

            rc_read_lines = read_rules_file(one_file, one_file_name)
            one_file.close()

    if num_open_ok == 0:
        log.error("None of the files are accessible !")
    else:
        if num_open_ok > 1:
            num_open_ok = 0

    return num_open_ok, rc_read_lines


def out_table_chain_stats(p_table_name, p_dict_chains):
    """
    Log summary information on a specific table in IPtables,
    based on supplied parameters.

    :param p_table_name: The name of a table in IPtables,
    :param p_dict_chains: a group of chains stored in dictionary format.
    :return:
    """
    log.debug("Rules for table '%s':", p_table_name)

    chain_name_list = []

    for one_chain_name in p_dict_chains.keys():
        chain_name_list.append(one_chain_name)

    chain_name_list.sort()

    for one_chain_name in chain_name_list:
        one_chain_data = p_dict_chains[one_chain_name]

        log.debug("Chain %s, policy %s, NumRules=%s",
                  one_chain_name, one_chain_data["policy"],
                  str(len(one_chain_data["rules"])))


def parse_rules(p_lines):
    """
    Read text lines (obtained from a file in 'iptables' input format),
    and load their contents in a dictionary to be returned.
    Also add to the returned dictionary new temporary IPtables chains.

    :param p_lines: dictionary with text input lines to process.
    :return: dictionary with resulting information
    """
    rc_parse_ok = 1
    line_idx = 1
    cur_tb_name = ""
    dict_chains = dict()
    rc_filter_data = dict()
    rc_filter_data["stored_rules"] = dict()

    while line_idx in p_lines.keys():

        line_to_delete = 0
        cur_line = p_lines[line_idx]
        line_idx += 1

        cur_tokens = cur_line.split()

        if len(cur_tokens) <= 0:
            continue

        if cur_tokens[0].upper() == "#DELETE#":

            line_to_delete = 1
            cur_tokens = cur_tokens[1:]
            cur_line = cur_line[8:]

            while len(cur_line) > 0 and cur_line[0] == " ":
                cur_line = cur_line[1:]

        if len(cur_tokens) <= 0:
            continue

        if cur_tokens[0][0] == "#":
            continue  # ignore comments

        if cur_tokens[0][0] == "*":

            if line_to_delete != 0:
                log.error("Line %s: Cannot request delete %s.",
                          str(line_idx), "of Table_name line")
                rc_parse_ok = 0
                break

            if len(cur_tokens) != 1:
                log.error("Line %s: Table_name line with %s.",
                          str(line_idx), "multiple tokens")
                rc_parse_ok = 0
                break

            in_tb_name = cur_tokens[0][1:]

            if in_tb_name not in supported_table_names:
                log.error("Line %s: Unknown Table_name '%s'.",
                          str(line_idx), in_tb_name)
                rc_parse_ok = 0
                break

            if cur_tb_name != "":
                out_table_chain_stats(cur_tb_name, dict_chains)

            cur_tb_name = in_tb_name
            dict_chains = dict()
            continue

        if cur_tokens[0][0] == ":":

            if line_to_delete != 0:
                log.error("Line %s: Cannot request delete %s.",
                          str(line_idx), "of Chain start line")
                rc_parse_ok = 0
                break

            if len(cur_tokens) != 3:
                log.error("Line %s: Chain start line %s.",
                          str(line_idx), "is not 3 tokens")
                rc_parse_ok = 0
                break

            if (cur_tokens[2][0] != "[") or (cur_tokens[2][-1] != "]"):
                log.error("Line %s: Chain start line %s.",
                          str(line_idx), "last token is not bracketed")
                rc_parse_ok = 0
                break

            t_chain_name = cur_tokens[0][1:]

            new_chain_2 = dict()

            new_chain_2["policy"] = cur_tokens[1]
            new_chain_2["rules"] = []
            new_chain_2["in_kernel"] = 0

            dict_chains[t_chain_name] = new_chain_2
            continue

        if cur_tokens[0][0] == "-":

            if len(cur_tokens[0]) != 2:
                log.error("Line %s: Rule line does not start %s.",
                          str(line_idx), "with a known dash code")
                rc_parse_ok = 0
                break

            if cur_tokens[0][1] != "A":
                log.error("Line %s: Rule line does not start %s.",
                          str(line_idx), "with a known dash code")
                rc_parse_ok = 0
                break

            if len(cur_tokens) < 3:
                log.error("Line %s: Rule line does not %s.",
                          str(line_idx), "have enough tokens")
                rc_parse_ok = 0
                break

            t_chain_name = cur_tokens[1]

            if t_chain_name in dict_chains.keys():

                new_rule_2 = dict()

                new_rule_2["line_no"] = line_idx
                new_rule_2["line"] = cur_line
                new_rule_2["delete"] = line_to_delete
                dict_chains[t_chain_name]["rules"].append(new_rule_2)

            else:
                log.error("Line %s: Rule line uses %s.",
                          str(line_idx), "an undefined chain name")
                rc_parse_ok = 0
                break

            continue

        if cur_tokens[0] == "COMMIT":

            if line_to_delete != 0:
                log.error("Line %s: Cannot request %s.",
                          str(line_idx), "delete of COMMIT line")
                rc_parse_ok = 0
                break

            if cur_tb_name == "":
                log.error("Line %s: COMMIT line with %s.",
                          str(line_idx), "no prior table name")
                rc_parse_ok = 0
                break

            rc_filter_data["stored_rules"][cur_tb_name] = dict_chains

            out_table_chain_stats(cur_tb_name, dict_chains)

            cur_tb_name = ""
            dict_chains = dict()
            continue

        log.error("Line %s: Starts with an unknown token.",
                  str(line_idx))
        rc_parse_ok = 0
        continue

    if cur_tb_name != "":
        rc_filter_data["stored_rules"][cur_tb_name] = dict_chains

        out_table_chain_stats(cur_tb_name, dict_chains)

    return rc_parse_ok, rc_filter_data


def confirm_chains_exist_in_kernel(p_filter_data, p_cmd_variant):
    """
    Go through all tables and all chains found in 'stored_rules'.
    Check whether all the chains exist in-kernel. If not, create them
    (even in read-only mode) to prevent run-time errors further
    in the script.
    :param p_filter_data: dictionary containing IPtables data
    :param p_cmd_variant: version of iptables command to use
    :return:1 if OK or 0 if ERROR,
            followed a possibly modified copy version of p_filter_data
    """
    overall_rc = 1

    log.debug("Verifying that all chains in stored rules %s.",
              "are 'at least' defined in the kernel")

    for tb in p_filter_data["stored_rules"].keys():

        cmd_str = "{0} --list-rules --table {1}".format(
                      p_cmd_variant, tb)

        if p_filter_data["supports_wait"] != 0:
            cmd_str += " --wait"

        t_pipe = subprocess.Popen(cmd_str, shell=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)

        for cur_line in t_pipe.stdout:
            cur_line = strip_white_space(cur_line)
            cur_tokens = cur_line.split()

            if len(cur_tokens) < 2:
                continue

            if (cur_tokens[0] != "-P") and (cur_tokens[0] != "-N"):
                continue

            one_c = cur_tokens[1]

            if one_c in p_filter_data["stored_rules"][tb].keys():
                p_filter_data["stored_rules"][tb][one_c]["in_kernel"] = 1

    # Scan all 'stored_rules' tables and chains.
    #
    # If any chain does not exist in-kernel, do AT LEAST a creation
    # of the chain, even in read-only mode, to avoid run-time errors
    # further in the script.

    for tb in p_filter_data["stored_rules"].keys():
        for one_c in p_filter_data["stored_rules"][tb].keys():

            one_c_data = p_filter_data["stored_rules"][tb][one_c]

            if one_c_data["in_kernel"] != 0:
                continue

            log.warning("Creating chain %s/%s in-kernel, %s.",
                        tb, one_c, "EVEN in read-only mode")

            cmd_str = "{0} --table {1} --new-chain {2}".format(
                          p_cmd_variant, tb, one_c)

            if run_cmd_with_retry(cmd_str) == 0:
                overall_rc = 0

    return overall_rc, p_filter_data


def calculate_test_rules(p_filter_data, p_time_str):
    """
    For all table names in p_filter_data['stored_rules'],
    and for all chains in such tables, build a modified copy of the
    chain in p_filter_data['test_rules'][table_name] where the
    chain name is modified to orig_chain_name concatenated with a '-'
    and the passed p_time_str. For each rule line in the chain, the
    1st occurrence of a string of the form ' orig_chain_name ' is
    replaced with ' new_chain_name '.
    :param p_filter_data: The IPtables dictionary structure
    :param p_time_str: time string used to generate unique names
                       (must not be too long, since IPtables chain names
                       are limited in length).
    :return: the modified p_filter_data dictionary
    """
    p_filter_data["test_rules"] = dict()

    for tb in p_filter_data["stored_rules"].keys():

        one_tb_data = p_filter_data["stored_rules"][tb]
        p_filter_data["test_rules"][tb] = dict()

        for one_chain_name in one_tb_data.keys():

            one_chain_data = one_tb_data[one_chain_name]
            new_chain_name = one_chain_name + "-" + p_time_str
            new_rules = []

            for one_rule in one_chain_data["rules"]:
                new_rule = dict()

                new_rule["line"] = string.replace(
                    one_rule["line"],
                    " " + one_chain_name + " ",
                    " " + new_chain_name + " ", 1)
                new_rules.append(new_rule)

            new_chain = dict()

            new_chain["rules"] = new_rules

            p_filter_data["test_rules"][tb][new_chain_name] = new_chain

    return p_filter_data


def add_test_rules_to_kernel(p_filter_data, p_cmd_variant):
    """
    For every table and each chain stored in p_filter_data['test_rules'],
    actually create the IPtables chain in the kernel and load rules in it.
    :param p_filter_data: The IPtables dictionary structure
    :param p_cmd_variant: version of iptables command to use
    :return: 1 if OK, 0 if ERROR
    """
    overall_rc = 1

    for tb in p_filter_data["test_rules"].keys():

        one_tb_data = p_filter_data["test_rules"][tb]

        for one_chain_name in one_tb_data.keys():

            one_chain_data = one_tb_data[one_chain_name]

            cmd_str = "{0} --table {1} --new-chain {2}".format(
                          p_cmd_variant, tb, one_chain_name)

            if run_cmd_with_retry(cmd_str) == 0:
                overall_rc = 0
                break

            for one_rule in one_chain_data["rules"]:

                cmd_str = "{0} --table {1} {2}".format(
                              p_cmd_variant, tb, one_rule["line"])

                if run_cmd_with_retry(cmd_str) == 0:
                    overall_rc = 0
                    break

            if overall_rc == 0:
                break

        if overall_rc == 0:
            break

    return overall_rc


def remove_test_rules_from_kernel(p_filter_data, p_cmd_variant):
    """
    Traverse all table/chain combinations in p_filter_data['test_rules'],
    empty and delete each such chain.
    :param p_filter_data: the dictionary containing IPtables data
    :param p_cmd_variant: version of iptables command to use
    :return:
    """
    for one_tb_name in p_filter_data["test_rules"].keys():

        one_tb_data = p_filter_data["test_rules"][one_tb_name]

        for one_chain_name in one_tb_data.keys():
            cmd_str = "{0} --table {1} --flush {2}".format(
                          p_cmd_variant, one_tb_name, one_chain_name)

            run_cmd_with_retry(cmd_str)

            cmd_str = "{0} --table {1} --delete-chain {2}".format(
                          p_cmd_variant, one_tb_name, one_chain_name)
            run_cmd_with_retry(cmd_str)


def analyze_in_kernel_chain_rules(p_filter_data, p_tb_name,
                                  p_chain_name, p_cmd_variant):
    """
    Access a specific chain/table combination of the in-kernel IPtables,
    parse it, and add its contents to a dictionary:

       dict['kernel_rules'][p_tb_name][p_chain_name] =
                 {
                    field 'policy': default policy for chain
                    field 'rules' : a list of dictionaries,
                                    with fields 'idx' and 'line'
                 }
    :param p_filter_data: Dictionary built so far
    :param p_tb_name: Table name to analyze
    :param p_chain_name: Chain name to analyze
    :param p_cmd_variant: version of iptables command to use
    :return: modified version of p_filter_data with additional data
    """
    t_msg = "Reading/Parsing in-kernel rules, chain {0} .".format(
               p_chain_name)

    if p_filter_data["supports_wait"] != 0:
        t_msg += "."

    log.debug(t_msg)

    if p_tb_name not in p_filter_data["kernel_rules"].keys():
        p_filter_data["kernel_rules"][p_tb_name] = dict()

    new_chain = dict()
    new_chain["policy"] = "-"
    new_chain["rules"] = []

    cmd_str = "{0} --table {1} --list {2} {3}".format(
                  p_cmd_variant, p_tb_name, p_chain_name,
                  "--verbose --numeric --exact")

    if p_filter_data["supports_wait"] != 0:
        cmd_str += " --wait"

    t_pipe = subprocess.Popen(cmd_str, shell=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)

    line_idx = 0
    in_error_case = 0

    for cur_line in t_pipe.stdout:

        line_idx += 1

        line_error_str = "Line {0} of iptables list output: ".format(
                             str(line_idx))

        if in_error_case != 0:
            log.error("Ignoring rest of output")
            continue

        cur_line = strip_white_space(cur_line)
        cur_tokens = cur_line.split()

        if line_idx == 1:

            # Should be a line of one of two forms:
            #
            # a) Chain P_CHAIN_NAME (nnn references)
            # b) Chain P_CHAIN_NAME (policy P_POLICY nnn packets ...

            if len(cur_tokens) < 4:
                log.error("{0}Not enough tokens".format(line_error_str))
                in_error_case = 1
                continue

            if cur_tokens[0].lower() != "chain":
                log.error("{0}Line does not start with Chain".format(
                    line_error_str))
                in_error_case = 1
                continue

            if cur_tokens[1] != p_chain_name:
                log.error("{0}Chain name mismatch".format(
                    line_error_str))
                in_error_case = 1
                continue

            if cur_tokens[2].lower() == "(policy":
                new_chain["policy"] = cur_tokens[3]

            continue

        if line_idx == 2:

            if len(cur_tokens) < 2:
                log.error("{0}Expected header line {1}".format(
                    line_error_str, "with more tokens"))
                in_error_case = 1
                continue

            if ((cur_tokens[0].lower() != "pkts") or
                    (cur_tokens[1].lower() != "bytes")):
                log.error("{0}Unrecognized header line".format(
                    line_error_str))
                in_error_case = 1
                continue
            continue

        if len(cur_tokens) < 3:
            log.error("{0}Not enough tokens in rule line".format(
                line_error_str))
            in_error_case = 1
            continue

        in_kernel_rule = cur_tokens[2]
        token_idx = 3

        while token_idx < len(cur_tokens):
            in_kernel_rule += " " + cur_tokens[token_idx]
            token_idx += 1

        rule_struct = dict()
        rule_struct["line"] = in_kernel_rule
        new_chain["rules"].append(rule_struct)

    p_filter_data["kernel_rules"][p_tb_name][p_chain_name] = new_chain

    return p_filter_data


def analyze_in_kernel_rules(p_filter_data, p_cmd_variant):
    """
    Go through all table/chain combinations in
    p_filter_data["test_rules"] and p_filter_data["stored_rules"],
    and call analyze_in_kernel_chain_rules() to read the in-kernel
    chain data and load it in p_filter_data["kernel_rules"].
    :param p_filter_data: the work-in-progress dictionary
    :param p_cmd_variant: version of iptables command to use
    :return: modified copy of p_filter_data with additional data
    """
    p_filter_data["kernel_rules"] = dict()

    # NOTE: calls to isinstance() and assert are only needed
    #       to eliminate warnings in PyCharm

    if isinstance(p_filter_data.get("test_rules"), dict):
        for one_tb_name in p_filter_data["test_rules"].keys():
            log.debug("Reading/Parsing in-kernel rules, table %s .",
                      one_tb_name)
            assert isinstance(p_filter_data, dict)
            one_tb_data = p_filter_data["test_rules"][one_tb_name]

            for one_chain_name in one_tb_data.keys():
                p_filter_data = analyze_in_kernel_chain_rules(
                    p_filter_data,
                    one_tb_name, one_chain_name, p_cmd_variant)

    if isinstance(p_filter_data.get("stored_rules"), dict):
        for one_tb_name in p_filter_data["stored_rules"].keys():
            log.debug("Reading/Parsing stored rules, table %s .",
                      one_tb_name)
            assert isinstance(p_filter_data, dict)
            one_tb_data = p_filter_data["stored_rules"][one_tb_name]

            for one_chain_name in one_tb_data.keys():
                p_filter_data = analyze_in_kernel_chain_rules(
                    p_filter_data,
                    one_tb_name, one_chain_name, p_cmd_variant)

    return p_filter_data


def determine_one_chain_diffs(p_filter_data, p_tb_name,
                              p_chain_name, p_tmpload_chain_name,
                              p_cmd_variant, p_filter_desc,
                              p_do_live_update):
    """
    For a specific table/chain name, do several verifications,
    taking into account that we now have data on THREE versions of the
    table/chain:

    a) Stored            - the table/chain as specified in the config file
    b) In-Kernel/TmpLoad - the Stored config that was freshly loaded
                           into a chain with a temporary name
    c) In-Kernel/Actual  - the current live config of the chain in-kernel

    The following categories of checks are performed:

    1- Differences between Stored and In-Kernel/TmpLoad
       (indicates problems when test-loading the chain)

    2- 'Unsafe' differences between In-Kernel/TmpLoad and
       In-Kernel/Actual (indicates that manual rule changes are required)

    3- 'Safe' differences between In-Kernel/TmpLoad and In-Kernel/Actual
       (that this script can actually fix in live-update sequence)

    :param p_filter_data: dictionary data accumulated so far
    :param p_tb_name: table name to analyze
    :param p_chain_name: chain name to analyze
    :param p_tmpload_chain_name: temporary chain name that corresponds
                                 to the 'stable' chain name
    :param p_cmd_variant: version of iptables command to use
    :param p_filter_desc: description of type of filter
    :param p_do_live_update: if 1 perform filtering live-update
    :return: updated version of p_filter_data
    """
    chain_text = "For chain {0}/{1}/{2},".format(
                 p_filter_desc, p_tb_name, p_chain_name)

    num_errors = 0
    k_table_data = p_filter_data["kernel_rules"][p_tb_name]

    tmpload_chain_data = k_table_data[p_tmpload_chain_name]
    in_k_actual_chain_data = k_table_data[p_chain_name]

    st_table_data = p_filter_data["stored_rules"][p_tb_name]
    st_chain_data = st_table_data[p_chain_name]

    # Between chain versions 'stored' and 'inkernel_actual',
    #    compare DEFAULT POLICY. If different, changes are UNSAFE!

    st_policy = "-"
    in_k_act_policy = "-"

    if "policy" in st_chain_data.keys():
        st_policy = st_chain_data["policy"]

    if "policy" in in_k_actual_chain_data.keys():
        in_k_act_policy = in_k_actual_chain_data["policy"]

    end_str = "for Stored vs. In-Kernel-Actual"

    if st_policy == in_k_act_policy:
        log.debug("%s default policy matches %s.", chain_text, end_str)
    else:
        log.error("%s default policy mismatch %s.", chain_text, end_str)
        num_errors += 1

    # Compare NUMBER OF RULES Between chain versions
    #     "stored" and "inkernel_tmpload",

    st_num_rules = -1
    tmpload_num_rules = -1
    actual_num_rules = -1

    if "rules" in st_chain_data.keys():
        st_num_rules = len(st_chain_data["rules"])

    if "rules" in tmpload_chain_data.keys():
        tmpload_num_rules = len(tmpload_chain_data["rules"])

    if "rules" in in_k_actual_chain_data.keys():
        actual_num_rules = len(in_k_actual_chain_data["rules"])

    end_str = "for Stored vs. In-Kernel-TmpLoad"

    if st_num_rules == tmpload_num_rules:
        log.debug("%s NumRules match %s.", chain_text, end_str)
    else:
        log.error("%s NumRules mismatch for %s.", chain_text, end_str)
        num_errors += 1
        log.error("Must skip further checks!")
        return p_filter_data

    if tmpload_num_rules == 0:
        log.debug("%s no rules in In-Kernel-TmpLoad, %s,",
                  chain_text, "no further checks needed.")
        return p_filter_data

    # Since the numbers of 'stored' and 'inkernel_tmpload' rules
    # are identical, we assume they match line for line, and we copy
    # the 'delete' field of each 'stored' rule to the
    # 'inkernel_tmpload' rule, and the rebuild important variables.

    rule_t_idx = 0
    repl_chain = []

    while rule_t_idx < tmpload_num_rules:
        new_rule = dict()
        new_rule["line"] = tmpload_chain_data["rules"][rule_t_idx]["line"]
        new_rule["delete"] = st_chain_data["rules"][rule_t_idx]["delete"]
        repl_chain.append(new_rule)
        rule_t_idx += 1

    x1 = "kernel_rules"
    x2 = p_tb_name
    x3 = p_tmpload_chain_name
    x4 = p_chain_name

    p_filter_data[x1][x2][x3]["rules"] = repl_chain
    k_table_data = p_filter_data[x1][x2]
    tmpload_chain_data = k_table_data[x3]
    in_k_actual_chain_data = k_table_data[x4]

    # For chain version "inkernel_tmpload", check that no two rules are
    # identical.

    found_dupl_lines = 0
    rule_1_idx = 0

    while rule_1_idx < (tmpload_num_rules - 1):

        rule_1_data = tmpload_chain_data["rules"][rule_1_idx]
        rule_2_idx = rule_1_idx + 1

        while rule_2_idx < tmpload_num_rules:

            rule_2_data = tmpload_chain_data["rules"][rule_2_idx]

            if rule_1_data["line"] == rule_2_data["line"]:
                found_dupl_lines = 1
                log.error(
                    "%s In-Kernel-TmpLoad rules, %s %s and %s.",
                    chain_text, "found identical lines at offsets",
                    str(rule_1_idx), str(rule_2_idx))

            rule_2_idx += 1
        rule_1_idx += 1

    if found_dupl_lines == 0:
        log.debug("%s Found no duplicates in In-Kernel-TmpLoad rules.",
                  chain_text)
    else:
        num_errors += 1
        log.error(chain_text + " found some duplicate lines"
                  + " in In-Kernel-TmpLoad rules.")
        log.error("Must skip further checks!")
        return p_filter_data

    # Traverse all In-Kernel-TmpLoad rules, and try to match
    # them in strictly increasing order to In-Kernel-Actual rules.

    last_matched_offset = -1
    new_tmpload_rules = []

    tmpload_offset = 0

    while tmpload_offset < tmpload_num_rules:

        tmpload_rule = tmpload_chain_data["rules"][tmpload_offset]

        new_rule = dict()
        new_rule["line"] = tmpload_rule["line"]
        new_rule["delete"] = tmpload_rule["delete"]
        new_rule["matched_offset"] = -1

        found_match = 0
        search_offset = last_matched_offset + 1

        while search_offset < actual_num_rules:

            actual_rule = in_k_actual_chain_data["rules"][search_offset]

            if actual_rule["line"] == new_rule["line"]:
                last_matched_offset = search_offset
                found_match = 1
                break

            search_offset += 1

        if found_match != 0:
            new_rule["matched_offset"] = last_matched_offset

        new_tmpload_rules.append(new_rule)

        tmpload_offset += 1

    # Overwrite the rule list for the chain with the new list
    # that contains additional information, and re-calculate
    # key "data" variables.

    x1 = "kernel_rules"
    x2 = p_tb_name
    x3 = p_tmpload_chain_name

    p_filter_data[x1][x2][x3]["rules"] = new_tmpload_rules
    k_table_data = p_filter_data[x1][x2]
    tmpload_chain_data = k_table_data[x3]

    # Check if all InKernel-TmpLoad rules were matched in InKernel-Actual,
    # and no rules to delete.
    # If YES, we have no further differences to check.

    all_matched = 1
    for one_rule in tmpload_chain_data["rules"]:
        if (one_rule["delete"] != 0) and (one_rule["matched_offset"] >= 0):
            all_matched = 0
            break
        elif (one_rule["delete"] == 0) and (one_rule["matched_offset"] < 0):
            all_matched = 0
            break

    if all_matched != 0:
        log.debug("%s all In-Kernel-TmpLoad rules matched %s, %s.",
                  chain_text, "in Actual",
                  "no rules to delete, no further checks needed")
        return p_filter_data

    # Scan all rules for delete requests that were matched.
    # These deletes will be executed one-by-one starting from the
    # beginning of the list, so matched_offset values must be reduced
    # by 1 for each prior delete.

    num_deleted_so_far = 0

    for one_rule in tmpload_chain_data["rules"]:

        if one_rule["matched_offset"] >= 0:

            new_val = one_rule["matched_offset"] - num_deleted_so_far

            if new_val < 0:
                num_errors += 1
                log.error("%s prior deletes would make %s %s...",
                          chain_text, "a matched offset go negative!",
                          "Stopping here")
                return p_filter_data

            one_rule["matched_offset"] = new_val

            if one_rule["delete"] != 0:
                num_deleted_so_far += 1

    already_inserted = 0

    # Test for "safe" insertion case 1:
    # ---------------------------------
    # If N contiguous rules are not-deletes and unmatched at the beginning,
    # and are either:
    #
    #    a) the only rules of concern since Kernel-Actual is empty
    #    b) followed immediately by a rule that matched at offset 0
    #       (whether it was a delete rule or not)
    #
    # The N rules are safe to insert at offsets 1 to N,
    # and variable already_inserted should be increased by N.
    #
    # Note: unmatched deletes can be present in the block and will be
    #       ignored in the calculation.

    case_1_applies = 1
    num_rules_applicable = 0
    num_rules_in_block = 0
    rule_idx = 0

    while rule_idx < tmpload_num_rules:

        t_rule = tmpload_chain_data["rules"][rule_idx]
        t_offset = t_rule["matched_offset"]

        if t_offset < 0:

            # An unmatched rule (DELETE or not)
            num_rules_in_block += 1

            if t_rule["delete"] == 0:
                # An unmatched NON-DELETE=INSERT rule
                num_rules_applicable += 1
        else:
            # A matched rule (DELETE or not)
            if t_offset > 0:
                # First matched rule found did not match at offset 0,
                # insertion case 1 does not apply.
                case_1_applies = 0
                num_rules_applicable = 0

            # We exit this loop at first matched rule (DELETE or not)
            break

        rule_idx += 1

    if num_rules_applicable == 0:
        case_1_applies = 0

    if case_1_applies != 0:

        rule_idx = 0
        applicable_rule_idx = 0

        while rule_idx < num_rules_in_block:

            t_rule = tmpload_chain_data["rules"][rule_idx]

            if t_rule["matched_offset"] < 0 and t_rule["delete"] == 0:
                # An unmatched NON-DELETE=INSERT rule
                applicable_rule_idx += 1
                t_rule["insert_pos"] = applicable_rule_idx

            rule_idx += 1

        already_inserted += num_rules_applicable

        if num_rules_applicable == 1:
            part_str = "new rule "
        else:
            part_str = str(num_rules_applicable) + " new rules "

        log.info("%s first %s in Stored config %s %s.",
                 chain_text, part_str,
                 "can be safely inserted live in-kernel",
                 "at the chain beginning")

    # Test for one or more occurrences of "safe" case 2:
    # --------------------------------------------------
    # one or more contiguous "Kernel-TmpLoad" rules are unmatched
    #    (the block of contiguous rules may contain zero or more
    #     DELETE-UNMATCHED rules),
    #
    # AND are immediately preceded by a matching rule matched at offset I,
    #    (if this rule is a DELETE/MATCH     rule then J=I,
    #     if this rule is a NON-DELETE/MATCH rule then J=I+1
    #
    # AND are immediately followed by a matching rule matched at offset J.

    last_matched_rule_idx = -1
    last_matched_offset = -1
    last_matched_was_delete = 0
    unmatched_grp_start_idx = -1
    rule_idx = 0

    while rule_idx < tmpload_num_rules:

        t_rule = tmpload_chain_data["rules"][rule_idx]
        t_offset = t_rule["matched_offset"]

        if t_offset < 0:

            # We have an "unmatched" line.
            # If it is a DELETE line, ignore it completely.
            # If it is a NON-DELETE=INSERT line, IGNORE it
            #   if we have not had a single matched line yet!

            if ((t_rule["delete"] == 0) and
                    (last_matched_rule_idx >= 0) and
                    ((last_matched_rule_idx + 1) == rule_idx)):
                # Could be the start of a valid case 2 group, otherwise
                # we are just staying inside the "unmatched" group.
                unmatched_grp_start_idx = rule_idx

            rule_idx += 1
            continue  # Continue WHILE loop

        # We have a MATCHED line since t_offset >= 0

        if unmatched_grp_start_idx < 0:

            # We are NOT within a possible "case 2" unmatched group,
            # just update the "matched" status.

            last_matched_rule_idx = rule_idx
            last_matched_offset = t_offset
            last_matched_was_delete = 0
            if t_rule["delete"] != 0:
                last_matched_was_delete = 1

            rule_idx += 1
            continue  # Continue WHILE loop

        # This is the first "matched" line after a possible
        # "case 2" unmatched group, test if valid case 2!
        # By definition, we have had at least one matched line
        # before...

        if ((last_matched_was_delete == 0 and
             (last_matched_offset + 1) == t_offset)
            or (last_matched_was_delete != 0 and
                last_matched_offset == t_offset)):

            # This is a valid case 2 "unmatched" group,
            # calculate insert positions for NON-DELETE=INSERT lines

            num_rules_applicable = 0
            rule_idx_2 = unmatched_grp_start_idx

            while rule_idx_2 < rule_idx:

                tmp_rule_2 = tmpload_chain_data["rules"][rule_idx_2]

                if tmp_rule_2["delete"] == 0:

                    target_offset = (last_matched_offset
                                     + already_inserted + 1)

                    if last_matched_was_delete == 0:
                        target_offset += 1

                    tmp_rule_2["insert_pos"] = target_offset

                    already_inserted += 1
                    num_rules_applicable += 1

                rule_idx_2 += 1

            if num_rules_applicable == 1:
                part_str = str(num_rules_applicable) + " rule"
            else:
                part_str = str(num_rules_applicable) + " rules"

            log.info("%s %s in Stored config can be safely %s %s.",
                     chain_text, part_str, "inserted live in-kernel",
                     "within other matched rules")

        # Valid or not, forget about the "case 2" unmatched group.

        unmatched_grp_start_idx = -1
        last_matched_rule_idx = rule_idx
        last_matched_offset = t_offset

        rule_idx += 1

    # Test for "safe" case 3:
    # -----------------------
    # If N contiguous Kernel-TmpLoad rules are unmatched at the end,
    # and are preceded immediately by a matched rule,
    # the N rules are safe to append at the end of the chain.
    # The contiguous rules in question can contain zero or more
    # DELETE/UNMATCHED rules.

    rule_idx = tmpload_num_rules - 1
    num_rules_applicable = 0
    num_rules_in_grp = 0

    while rule_idx >= 0:

        t_rule = tmpload_chain_data["rules"][rule_idx]

        if t_rule["matched_offset"] >= 0:
            break  # This is a MATCHED rule, we are finished

        if "insert_pos" in t_rule.keys():
            # UNMATCHED rule, but with a "solution" already found,
            # case 3 cannot apply
            num_rules_applicable = 0
            break

        num_rules_in_grp += 1

        if t_rule["delete"] == 0:
            num_rules_applicable += 1

        rule_idx -= 1

    if num_rules_applicable > 0:

        if num_rules_applicable == 1:
            part_str = "rule "
        else:
            part_str = str(num_rules_applicable) + " rules "

        log.info("%s last %s in Stored config can be safely %s.",
                 chain_text, part_str,
                 "appended live in-kernel to the chain's end")

        rule_idx = tmpload_num_rules - 1

        while num_rules_in_grp > 0:

            if tmpload_chain_data["rules"][rule_idx]["delete"] == 0:
                tmpload_chain_data["rules"][rule_idx]["append"] = 1

            rule_idx -= 1
            num_rules_in_grp -= 1

    # Display rule modification plan and overall status:
    #      OK: Plan possible to insert all rules
    #      ERROR: Not all rules can be resolved

    rule_idx = 0
    num_unknown_sol = 0
    num_known_sol = 0

    while rule_idx < tmpload_num_rules:

        t_rule = tmpload_chain_data["rules"][rule_idx]

        if (t_rule["delete"] == 0) and (t_rule["matched_offset"] >= 0):
            # Ignore any MATCHED NON-DELETE=INSERT rules
            rule_idx += 1
            continue

        if (t_rule["delete"] != 0) and (t_rule["matched_offset"] < 0):
            # Ignore any UNMATCHED DELETE rules
            rule_idx += 1
            continue

        # Other rule cases require a solution:
        #    (UNMATCHED NON-DELETE=INSERT, and MATCHED DELETE)

        if (num_unknown_sol + num_known_sol) == 0:
            log.warning("Plan %s for chain '%s/%s/%s' : %s",
                        "for rule modifications",
                        p_filter_desc, p_tb_name, p_chain_name,
                        "(ALL DELETEs will be performed first! )")

        # Remove the "-A chain_name" portion at the beginning
        # of the rule, and do so reasonably safely!

        target_line = st_chain_data["rules"][rule_idx]["line"]

        target_line = string.replace(target_line, "-A ", " ", 1)
        target_line = string.replace(target_line,
                                     " " + p_chain_name + " ",
                                     " ", 1)

        while target_line[0] == " ":
            target_line = target_line[1:]

        st_chain_data["rules"][rule_idx]["line"] = target_line

        # Display appropriate message for situation

        if (t_rule["delete"] != 0) and (t_rule["matched_offset"] >= 0):
            num_known_sol += 1
            log.warning("%s delete at position %s: '%s'",
                        chain_text, str(t_rule["matched_offset"] + 1),
                        st_chain_data["rules"][rule_idx]["line"])
            rule_idx += 1
            continue

        if "insert_pos" in t_rule.keys():
            num_known_sol += 1
            log.warning("%s insert at position %s: '%s'",
                        chain_text, str(t_rule["insert_pos"]),
                        st_chain_data["rules"][rule_idx]["line"])
            rule_idx += 1
            continue

        if "append" in t_rule.keys():
            num_known_sol += 1
            log.warning("%s append at end : '%s'",
                        chain_text,
                        st_chain_data["rules"][rule_idx]["line"])
            rule_idx += 1
            continue

        num_unknown_sol += 1

        log.error("%s unknown solution : '%s'",
                  chain_text, st_chain_data["rules"][rule_idx]["line"])

        rule_idx += 1

    if num_unknown_sol > 0:
        num_errors += 1
        log.error("Not all unmatched rules can be resolved!")
        return p_filter_data

    log.info("Solutions found for all unmatched Stored rules.")

    if p_do_live_update == 0:
        return p_filter_data

    log.warning("Starting live update for '%s/%s/%s' ...",
                p_filter_desc, p_tb_name, p_chain_name)
    rule_idx = 0

    while rule_idx < tmpload_num_rules:

        t_rule = tmpload_chain_data["rules"][rule_idx]

        if (t_rule["delete"] != 0) and (t_rule["matched_offset"] >= 0):

            del_offset = t_rule["matched_offset"] + 1

            cmd_str = "{0} -t {1} -D {2} {3}".format(
                          p_cmd_variant, p_tb_name, p_chain_name,
                          str(del_offset))

            cmd_rc = run_cmd_with_retry(cmd_str)

            if cmd_rc == 0:
                log.error("%s failed to delete rule '%s', %s",
                          chain_text,
                          st_chain_data["rules"][rule_idx]["line"],
                          "giving up on other updates!")
                return p_filter_data

        rule_idx += 1

    rule_idx = 0

    while rule_idx < tmpload_num_rules:

        t_rule = tmpload_chain_data["rules"][rule_idx]

        if "insert_pos" in t_rule.keys():

            cmd_str = "{0} -t {1} -I {2} {3} {4}".format(
                          p_cmd_variant, p_tb_name, p_chain_name,
                          str(t_rule["insert_pos"]),
                          st_chain_data["rules"][rule_idx]["line"])

            cmd_rc = run_cmd_with_retry(cmd_str)

            if cmd_rc == 0:
                log.error("%s failed to insert rule '%s', %s",
                          chain_text,
                          st_chain_data["rules"][rule_idx]["line"],
                          "giving up on other updates!")
                return p_filter_data
        else:
            if "append" in t_rule.keys():

                cmd_str = "{0} -t {1} -A {2} {3}".format(
                              p_cmd_variant, p_tb_name, p_chain_name,
                              st_chain_data["rules"][rule_idx]["line"])

                cmd_rc = run_cmd_with_retry(cmd_str)

                if cmd_rc == 0:
                    log.error("%s failed to append rule '%s', %s",
                              chain_text,
                              st_chain_data["rules"][rule_idx]["line"],
                              "giving up on other updates!")
                    return p_filter_data

        rule_idx += 1

    log.warning("Live update completed.")
    return p_filter_data


def determine_overall_diffs(p_filter_data, p_time_str,
                            p_cmd_variant, p_filter_desc,
                            p_do_live_update):
    """
    For all 'Stored' table/chain combinations , do several verifications,
    taking into account that we now have data on THREE versions
    of each table/chain:

    a) Stored            - the table/chain as specified in the config file
    b) In-Kernel/TmpLoad - the Stored config that was freshly loaded
                           into a chain with a temporary name
    c) In-Kernel/Actual  - the current live config of the chain in-kernel

    To do this reliably, the script actually parsed and read the 'rules'
    file, and did a temporary load of the rules into modified chain names
    (that include the time_str), and then read back the rules as stored
    in the kernel.
    :param p_filter_data: Dictionary with all the data acquired so far
    :param p_time_str: Time-based string to be used for temporary
                       chain names
    :param p_cmd_variant: version of iptables command to use
    :param p_filter_desc: description of type of filter
    :param p_do_live_update: if 1 perform filtering live-update
    :return: Updated copy of p_filter_data
    """
    # Main loop: go through all STORED table/chain combinations
    if isinstance(p_filter_data, dict):
        for one_tb_name in p_filter_data["stored_rules"].keys():

            st_tb_data = p_filter_data["stored_rules"][one_tb_name]

            if one_tb_name not in p_filter_data["kernel_rules"].keys():
                log.error("Cannot find table name '%s/%s' In-Kernel!",
                          p_filter_desc, one_tb_name)
                continue

            k_tb_data = p_filter_data["kernel_rules"][one_tb_name]

            for one_chain_name in st_tb_data.keys():

                tmpload_chain_name = one_chain_name + "-" + p_time_str

                log.debug("Checking %s diffs for chain '%s/%s/%s' :",
                          "Stored/In-kernel", p_filter_desc,
                          one_tb_name, one_chain_name)

                if ((one_chain_name not in k_tb_data.keys()) or
                        (tmpload_chain_name not in k_tb_data.keys())):

                    log.error("For chain %s/%s/%s, cannot find %s!",
                              p_filter_desc,
                              one_tb_name, one_chain_name,
                              "in-kernel actual or tmpload version")
                    continue

                p_filter_data = determine_one_chain_diffs(
                    p_filter_data, one_tb_name,
                    one_chain_name, tmpload_chain_name,
                    p_cmd_variant, p_filter_desc,
                    p_do_live_update)

    return p_filter_data


# -------------------------- MAIN PROGRAM -------------------------- #
if __name__ == "__main__":
    cmd_arguments = parse_std_arguments(
        """
        Performs checks on the host packet filtering configurations.
        By default, only read-only checks are performed.

        If 'live-update' is specified, and the host has 'stored' iptables
        rules that are not 'live' in-kernel, the script attempts to insert
        the rules 'live' in-kernel if it appears safe to do so.
        If 'stored' rules are commented out with the '#DELETE#' prefix
        and are found in-kernel, the script attempts to delete the rules.
        """)

    config_logger(cmd_arguments)
    log = logging.getLogger()

    log.info("Running IPtables analysis script on target host...")

    iptables_support_wait = check_iptable_wait_support()

    our_time_str = str(int(time.time()))
    log.debug("Computed ephemeral time string: {0}".format(
        our_time_str))

    for one_variant in filter_variants:

        read_ok, read_lines = read_one_file_of(one_variant["files"])

        if read_ok == 0:
            log.error("Failed to read exactly one %s config file.",
                      one_variant["desc"])
            sys.exit(1)

        parse_ok, main_filter_data = parse_rules(read_lines)

        if parse_ok == 0:
            log.error("Parsing of %s config file failed.",
                      one_variant["desc"])
            sys.exit(1)

        log.debug("Parsing of %s config file successful.",
                  one_variant["desc"])

        main_filter_data["supports_wait"] = iptables_support_wait

        conf_ok, main_filter_data = confirm_chains_exist_in_kernel(
            main_filter_data, one_variant["cmd"])

        if conf_ok == 0:
            log.error("%s chain existence confirmation check failed.",
                      one_variant["desc"])
            sys.exit(1)

        log.debug("Creating temporary %s filtering chains in-kernel.",
                  one_variant["desc"])

        main_filter_data = calculate_test_rules(main_filter_data,
                                                our_time_str)

        add_rc = add_test_rules_to_kernel(main_filter_data,
                                          one_variant["cmd"])

        if add_rc == 0:
            log.error("Some failure occurred...")
            log.error("Attempting to delete temporary %s %s.",
                      one_variant["desc"], "rules and exiting")
            remove_test_rules_from_kernel(main_filter_data,
                                          one_variant["cmd"])
            sys.exit(1)

        main_filter_data = analyze_in_kernel_rules(
            main_filter_data, one_variant["cmd"])

        log.debug("Removing temporary %s filtering chains from kernel.",
                  one_variant["desc"])

        remove_test_rules_from_kernel(main_filter_data,
                                      one_variant["cmd"])

        main_filter_data = determine_overall_diffs(
                               main_filter_data,
                               our_time_str,
                               one_variant["cmd"],
                               one_variant["desc"],
                               cmd_arguments.live_update)

    sys.exit(0)
