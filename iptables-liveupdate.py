#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# This file is subject to the terms and conditions defined in
# file 'LICENSE', which is part of this source code package.
#


import argparse
import logging
import string
import subprocess
import sys
import time
from pprint import pprint

logger = logging.getLogger()

retry_count = 3
retry_delay = 1

iptables_supports_wait = 0

supported_table_names = ["filter", "nat", "mangle", "raw", "security"]

do_live_update = 0


def strip_white_space(p_str):
    """
    Take an input string, and return a possibly modified copy of it:
    a) If there are tabs in the input string, they are replaced by spaces
       in the return string.
    b) Any carriage-return or line-feed characters are removed from the
       return string.
    c) The return string does not have any spaces at its end.
    :param p_str: The input string
    :return:
    """

    if len(p_str) <= 0:
        return p_str

    rc_str = ''
    char_idx = 0

    while char_idx < len(p_str):

        one_char = p_str[char_idx]

        if (one_char == '\r') or (one_char == '\n'):
            char_idx = char_idx + 1
            continue

        if one_char == '\t':
            one_char = ' '

        rc_str = rc_str + one_char
        char_idx = char_idx + 1

    while len(rc_str) > 0:
        if rc_str[-1] != ' ':
            break
        rc_str = rc_str[0:-1]

    return rc_str


def run_cmd_with_retry(cmd_str):
    """
    Run a command up to "retry_count" times until
    its exit status is 0. For each non-zero case,
    sleep "retry_delay" seconds before trying again.

    This is used to improve reliability for most "iptables"
    commands since older Linux systems do not support
    the iptables "--wait" option.
    :param cmd_str: Command to try to execute
    :return: 0 if all retries failed, 1 otherwise.
    """
    fn_rc = 0
    sys.stdout.flush()
    sys.stderr.flush()
    retry_attempt = 0

    while retry_attempt < retry_count:

        if retry_attempt != 0:
            logger.info('Retrying command after failure.')
            time.sleep(retry_delay)

        cmd_rc = subprocess.call(cmd_str, shell=True)

        if cmd_rc == 0:
            if retry_attempt != 0:
                logger.info('Command retry successful.')
            fn_rc = 1
            break

        retry_attempt = retry_attempt + 1

    if fn_rc == 0:
        logger.error('Command {0} still fails after {1} retries'.format(cmd_str, retry_count))

    return fn_rc


def check_iptable_wait_support():
    """
    Detect whether the current host has a version of "iptables"
    that supports the option "--wait".
    :return: yes, return 1, otherwise, return 0
    """
    cmd_str = "iptables -h | fgrep -e --wait | wc -l"

    t_pipe = subprocess.Popen(cmd_str, shell=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)

    num_lines = 0
    rc_wait_support = 0

    for cur_line in t_pipe.stdout:

        num_lines = num_lines + 1

        cur_number = int(cur_line)
        if cur_number > 0:
            rc_wait_support = 1
            opt_str = "supports"
        else:
            opt_str = "does not support"

        logger.debug('IPtables version {0} the --wait option.'.format(opt_str))

    if num_lines != 1:
        logger.error('IPtables version test command unexpected output!')
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
    :return:
    """
    rc_rule_lines = {}

    line_idx = 0
    at_least_one_cr = 0
    at_least_one_tab = 0
    line_with_no_lf = 0

    for one_line in p_open_file:

        line_idx = line_idx + 1

        if len(one_line) > 0:
            if one_line[-1] == '\n':
                one_line = one_line[0:-1]
            else:
                line_with_no_lf = 1

        if len(one_line) > 0:
            if one_line[-1] == '\r':
                at_least_one_cr = 1
                one_line = one_line[0:-1]

        out_line = ""

        if len(one_line) > 0:

            char_idx = 0

            while char_idx < len(one_line):

                one_char = one_line[char_idx]

                if one_char == '\t':
                    at_least_one_tab = 1
                    one_char = ' '

                out_line = out_line + one_char
                char_idx = char_idx + 1

        rc_rule_lines[line_idx] = out_line

    if at_least_one_cr != 0:
        logger.info('File {0} contains at least one carriage-return, which was silently filtered.'
                    .format(p_open_file_name))

    if line_with_no_lf != 0:
        logger.info('File {0} has no linefeed after its last line, the line is processed anyway.'
                    .format(p_open_file_name))

    if at_least_one_tab != 0:
        logger.info('File {0} contains at least one tab, which was silently replaced by a space.'
                    .format(p_open_file_name))

    return rc_rule_lines


def read_one_file_of(file_list):
    """
    Attempts to open and read EXACTLY ONE file based on a list of possible file names.
    :param file_list: a list of file names to attempt
    :return: If successful, returns 1 AND a dictionary containing the text lines.
             Otherwise, returns 0 and an empty dictionary.
    """
    rc_read_lines = dict()
    num_open_ok = 0

    if len(file_list) <= 0:
        logger.error('No file names passed !')
        return num_open_ok, rc_read_lines

    if len(file_list) == 1:
        logger.debug('Parsing IPtables file {0}.'.format(file_list[0]))
    else:
        t_msg = "Parsing exactly one IPtables file out of: ["
        for one_file_name in file_list:
            t_msg += ' {0}'.format(one_file_name)
        t_msg += " ]"
        logger.debug(t_msg)

    for one_file_name in file_list:

        with open(one_file_name, mode='rb') as one_file:
            num_open_ok += 1

            if num_open_ok > 1:
                logger.error('More than one file is accessible !')
                rc_read_lines = dict()
                one_file.close()
                break

            rc_read_lines = read_rules_file(one_file, one_file_name)
            one_file.close()

    if num_open_ok == 0:
        logger.error('None of the files are accessible !')
    else:
        if num_open_ok > 1:
            num_open_ok = 0

    return num_open_ok, rc_read_lines


def out_table_chain_stats(p_table_name, p_dict_chains):
    """

    :param p_table_name: The name of a table in IPtables,
    :param p_dict_chains: a group of chains stored in dictionary format.
    :return: summary information on an IPtables table, based on a supplied table name and group of IPtables chains
             stored in dictionary format.
    """
    logger.debug('Rules for table {0}:'.format(p_table_name))

    chain_name_list = []

    for one_chain_name in p_dict_chains.keys():
        chain_name_list.append(one_chain_name)

    chain_name_list.sort()

    for one_chain_name in chain_name_list:
        one_chain_data = p_dict_chains[one_chain_name]

        logger.debug('Chain {0}, policy {1}, NumRules={2}'
                     .format(one_chain_name, one_chain_data["policy"], str(len(one_chain_data["rules"]))))


def parse_rules(p_lines):
    """
    Read text lines (obtained from a file in "iptables" input format),
    and load their contents in a dictionary to be returned.
    Also generate temporary IPtables chains also placed in the dictionary.
    :param p_lines: Dictionary with text input lines to process.
    :return:
    """
    rc_parse_ok = 1
    line_idx = 1
    cur_table_name = ""
    dict_chains = {}

    rc_iptables_data = dict()
    rc_iptables_data["stored_rules"] = {}

    while line_idx in p_lines.keys():

        line_to_delete = 0
        cur_line = p_lines[line_idx]
        line_idx = line_idx + 1

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
                logger.error('Line {0}: Cannot request delete of Table_name line'.format(str(line_idx)))
                rc_parse_ok = 0
                break

            if len(cur_tokens) != 1:
                logger.error('Line {0}: Table_name line with multiple tokens.'.format(str(line_idx)))
                rc_parse_ok = 0
                break

            in_table_name = cur_tokens[0][1:]

            if in_table_name not in supported_table_names:
                logger.error('Line {0}: Unknown table_name "{1}".'.format(str(line_idx), in_table_name))
                rc_parse_ok = 0
                break

            if cur_table_name != "":
                out_table_chain_stats(cur_table_name, dict_chains)

            cur_table_name = in_table_name
            dict_chains = {}
            continue

        if cur_tokens[0][0] == ":":

            if line_to_delete != 0:
                logger.error('Line {0}: Cannot request delete of Chain start line'.format(str(line_idx)))
                rc_parse_ok = 0
                break

            if len(cur_tokens) != 3:
                logger.error('Line {0}: Chain start line is not 3 tokens.'.format(str(line_idx)))
                rc_parse_ok = 0
                break

            if (cur_tokens[2][0] != "[") or (cur_tokens[2][-1] != "]"):
                logger.error('Line {0}: Chain start line last token is not bracketed.'.format(str(line_idx)))
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
                logger.error('Line {0}: Rule line does not start with a known dash code.'.format(str(line_idx)))
                rc_parse_ok = 0
                break

            if cur_tokens[0][1] != "A":
                logger.error('Line {0}: Rule line does not start with a known dash code.'.format(str(line_idx)))
                rc_parse_ok = 0
                break

            if len(cur_tokens) < 3:
                logger.error('Line {0}: Rule line does not have enough tokens.'.format(str(line_idx)))
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
                logger.error('Line {0}: Rule line uses an undefined chain name.'.format(str(line_idx)))
                rc_parse_ok = 0
                break

            continue

        if cur_tokens[0] == "COMMIT":

            if line_to_delete != 0:
                logger.error('Line {0}: Cannot request delete of COMMIT line'.format(str(line_idx)))
                rc_parse_ok = 0
                break

            if cur_table_name == "":
                logger.error('Line {0}: COMMIT line with no prior table name.'.format(str(line_idx)))
                rc_parse_ok = 0
                break

            rc_iptables_data["stored_rules"][cur_table_name] = dict_chains

            out_table_chain_stats(cur_table_name, dict_chains)

            cur_table_name = ""
            dict_chains = {}
            continue

        logger.error('Line {0}: Starts with an unknown token.'.format(str(line_idx)))
        rc_parse_ok = 0
        continue

    if cur_table_name != "":
        rc_iptables_data["stored_rules"][cur_table_name] = dict_chains

        out_table_chain_stats(cur_table_name, dict_chains)

    return rc_parse_ok, rc_iptables_data


def confirm_chains_exist_in_kernel(iptables_data, wait_flag):
    """
    Go through all tables and all chains found in "stored_rules".
    Check whether all the chains exist in-kernel. If not, create them
    (even in read-only mode) to prevent run-time errors further
    in the script.
    :param iptables_data:
    :param wait_flag:
    :return:
    """
    overall_rc = 1

    logger.debug('Verifying that all chains in stored rules are "at least" defined in the kernel.')

    for one_tb in iptables_data["stored_rules"].keys():

        cmd_str = "iptables --list-rules --table " + one_tb

        if wait_flag != 0:
            cmd_str = cmd_str + " --wait"

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

            if one_c in iptables_data["stored_rules"][one_tb].keys():
                iptables_data["stored_rules"][one_tb][one_c]["in_kernel"] = 1

    # Scan all "stored_rules" tables and chains.
    #
    # If any chain does not exist in-kernel, do AT LEAST a creation
    # of the chain, even in read-only mode, to avoid run-time errors
    # further in the script.

    for one_tb in iptables_data["stored_rules"].keys():
        for one_c in iptables_data["stored_rules"][one_tb].keys():

            one_c_data = iptables_data["stored_rules"][one_tb][one_c]

            if one_c_data["in_kernel"] != 0:
                continue

            logger.info('Creating chain {0}/{1} in-kernel, EVEN in read-only mode.'.format(one_tb, one_c))

            cmd_str = "iptables --table " + one_tb + " --new-chain " + one_c

            if run_cmd_with_retry(cmd_str) == 0:
                overall_rc = 0

    return overall_rc, iptables_data


def calculate_test_rules(iptables_data, p_time_str):
    """
    For each IPtables chain stored in input dictionary iptables_data["stored_rules"][table_name], build a modified copy
    of the chain in iptables_data["test_rules"][table_name] where the chain name is modified to orig_chain_name
    concatenated with a "-" and the passed p_time_str. For each rule line in the chain, the 1st occurrence of a string
    of the form " orig_chain_name " is replaced with " new_chain_name ".
    :param iptables_data: The IPtables dictionary structure, the name of a table in IPtables
    :param p_time_str: time string used to generate unique names (must not be too long, since IPtables chain names
           are limited in length).
    :return:
    """
    iptables_data["test_rules"] = {}

    for one_table_name in iptables_data["stored_rules"].keys():

        one_table_data = iptables_data["stored_rules"][one_table_name]

        iptables_data["test_rules"][one_table_name] = {}

        for one_chain_name in one_table_data.keys():

            one_chain_data = one_table_data[one_chain_name]
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

            iptables_data["test_rules"][one_table_name][new_chain_name] = (
                new_chain)

    return iptables_data


def add_test_rules_to_kernel(iptables_data):
    """
    For each chain stored in iptables_data["test_rules"],
    actually create the IPtables chain in the kernel
    and add all rules to it.
    :param iptables_data: The IPtables dictionary structure
    :return:
    """
    overall_rc = 1

    for one_table_name in iptables_data["test_rules"].keys():

        one_table_data = iptables_data["test_rules"][one_table_name]

        for one_chain_name in one_table_data.keys():

            one_chain_data = one_table_data[one_chain_name]

            cmd_str = ("iptables --table " + one_table_name +
                       " --new-chain " + one_chain_name)

            if run_cmd_with_retry(cmd_str) == 0:
                overall_rc = 0
                break

            for one_rule in one_chain_data["rules"]:

                cmd_str = ("iptables --table " + one_table_name +
                           " " + one_rule["line"])

                if run_cmd_with_retry(cmd_str) == 0:
                    overall_rc = 0
                    break

            if overall_rc == 0:
                break

        if overall_rc == 0:
            break

    return overall_rc


def remove_test_rules_from_kernel(iptables_data):
    """
    Go through all table/chain combinations listed in
iptables_data["test_rules"], empty and delete each such chain.
    :param iptables_data: the dictionary containing all our IPtables data
    :return:
    """
    for one_table_name in iptables_data["test_rules"].keys():

        one_table_data = iptables_data["test_rules"][one_table_name]

        for one_chain_name in one_table_data.keys():
            cmd_str = ("iptables --table " + one_table_name +
                       " --flush " + one_chain_name)
            run_cmd_with_retry(cmd_str)

            cmd_str = ("iptables --table " + one_table_name +
                       " --delete-chain " + one_chain_name)
            run_cmd_with_retry(cmd_str)


def analyze_in_kernel_chain_rules(iptables_data, p_table_name,
                                  p_chain_name, wait_flag):
    """
    Access a specific in-kernel IPtables chain and table,
    parse it, and add its contents in a dictionary:

       dict["kernel_rules"][table_name][chain_name] =
                 {
                    field "policy": default policy for chain
                    field "rules" : a list of dictionaries,
                                    with fields "idx" and "line"
                 }
    :param iptables_data: Dictionary built so far, which is returned post additions
    :param p_table_name: The table
    :param p_chain_name: Chain name to analyze
    :param wait_flag: a flag to specify whether the iptables command supports the "--wait" option.
    :return:
    """
    t_msg = ("Reading/Parsing in-kernel rules, chain " +
             p_chain_name + " .")

    if wait_flag != 0:
        t_msg = t_msg + "."

    logger.debug(t_msg)

    if p_table_name not in iptables_data["kernel_rules"].keys():
        iptables_data["kernel_rules"][p_table_name] = {}

    new_chain = dict()

    new_chain["policy"] = "-"
    new_chain["rules"] = []

    cmd_str = ("iptables --table " + p_table_name +
               " --list " + p_chain_name +
               " --verbose --numeric --exact")

    if wait_flag != 0:
        cmd_str = cmd_str + " --wait"

    t_pipe = subprocess.Popen(cmd_str, shell=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)

    line_idx = 0
    in_error_case = 0

    for cur_line in t_pipe.stdout:

        line_idx = line_idx + 1

        line_error_str = ("Line " + str(line_idx) +
                          " of iptables list output: ")

        if in_error_case != 0:
            logger.error('Ignoring rest of output')
            continue

        cur_line = strip_white_space(cur_line)
        cur_tokens = cur_line.split()

        if line_idx == 1:

            # Should be a line of one of two forms:
            #
            # a)   Chain P_CHAIN_NAME (nnn references)
            # b)   Chain P_CHAIN_NAME (policy P_POLICY nnn packets ...

            if len(cur_tokens) < 4:
                logger.error('{0}Not enough tokens'.format(line_error_str))
                in_error_case = 1
                continue

            if cur_tokens[0].lower() != "chain":
                logger.error('{0}Line does not start with Chain'.format(line_error_str))
                in_error_case = 1
                continue

            if cur_tokens[1] != p_chain_name:
                logger.error('{0}Chain name mismatch'.format(line_error_str))
                in_error_case = 1
                continue

            if cur_tokens[2].lower() == "(policy":
                new_chain["policy"] = cur_tokens[3]

            continue

        if line_idx == 2:

            if len(cur_tokens) < 2:
                logger.error('{0}Expected header line with more tokens'.format(line_error_str))
                in_error_case = 1
                continue

            if ((cur_tokens[0].lower() != "pkts") or
                    (cur_tokens[1].lower() != "bytes")):
                logger.error('{0}Unrecognized header line'.format(line_error_str))
                in_error_case = 1
                continue

            continue

        if len(cur_tokens) < 3:
            logger.error('{0}Not enough tokens in rule line'.format(line_error_str))
            in_error_case = 1
            continue

        in_kernel_rule = cur_tokens[2]
        token_idx = 3

        while token_idx < len(cur_tokens):
            in_kernel_rule = in_kernel_rule + " " + cur_tokens[token_idx]
            token_idx = token_idx + 1

        rule_struct = dict()
        rule_struct["line"] = in_kernel_rule

        new_chain["rules"].append(rule_struct)

    iptables_data["kernel_rules"][p_table_name][p_chain_name] = new_chain

    return iptables_data


def analyze_in_kernel_rules(iptables_data, wait_flag):
    """
    Go through all table/chain combinations in iptables_data["test_rules"]
    and iptables_data["stored_rules"], and call
    analyze_in_kernel_chain_rules() to read the in-kernel chain data
    and load it in iptables_data["kernel_rules"]
    :param iptables_data: the work-in-progress dictionary
    :param wait_flag: a flag to specify whether the iptables command supports the "--wait" option.
    :return:
    """
    iptables_data['kernel_rules'] = dict()

    if isinstance(iptables_data.get('test_rules'), dict):
        for one_table_name in iptables_data.get('test_rules').keys():
            logger.debug('Reading/Parsing in-kernel rules, table {0} .'.format(one_table_name))
            assert isinstance(iptables_data, dict)
            one_table_data = iptables_data.get('test_rules').get(one_table_name)

            for one_chain_name in one_table_data.keys():
                iptables_data = analyze_in_kernel_chain_rules(iptables_data, one_table_name, one_chain_name, wait_flag)

    if isinstance(iptables_data.get('stored_rules'), dict):
        for one_table_name in iptables_data.get('stored_rules', dict()).keys():
            logger.debug('Reading/Parsing in-kernel rules, table {0} .'.format(one_table_name))

            one_table_data = iptables_data.get('stored_rules', dict()).get(one_table_name)

            for one_chain_name in one_table_data.keys():
                iptables_data = analyze_in_kernel_chain_rules(iptables_data, one_table_name, one_chain_name, wait_flag)

    return iptables_data


def determine_one_chain_diffs(p_iptables_data, p_table_name,
                              one_chain_name, tmpload_chain_name):
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

    2- "Unsafe" differences between In-Kernel/TmpLoad and
       In-Kernel/Actual (indicates that manual fix-ups are required)

    3- "Safe" differences between In-Kernel/TmpLoad and In-Kernel/Actual
       (that this script can actually fix)

    :param p_iptables_data: iptables dictionary data accumulated so far
    :param p_table_name: table name to analyze
    :param one_chain_name: chain name to analyze
    :param tmpload_chain_name: temporary chain name that corresponds to the "stable" chain name
    :return:
    """
    chain_text = "For chain " + p_table_name + "/" + one_chain_name + ", "

    num_errors = 0
    k_table_data = p_iptables_data["kernel_rules"][p_table_name]

    tmpload_chain_data = k_table_data[tmpload_chain_name]
    in_k_actual_chain_data = k_table_data[one_chain_name]

    st_table_data = p_iptables_data["stored_rules"][p_table_name]
    st_chain_data = st_table_data[one_chain_name]

    # Between chain versions "stored" and "inkernel_actual",
    #    compare DEFAULT POLICY. If different, changes are UNSAFE!

    st_policy = "-"
    in_k_act_policy = "-"

    if "policy" in st_chain_data.keys():
        st_policy = st_chain_data["policy"]

    if "policy" in in_k_actual_chain_data.keys():
        in_k_act_policy = in_k_actual_chain_data["policy"]

    if st_policy == in_k_act_policy:
        logger.debug('Default Policy match for Stored vs.In-Kernel-Actual.')
    else:
        logger.error('{0}Default policy mismatch for Stored vs. In-Kernel-Actual.'.format(chain_text))
        num_errors += 1

    # Between chain versions "stored" and "inkernel_tmpload",
    #    compare NUMBER OF RULES

    st_num_rules = -1
    tmpload_num_rules = -1
    actual_num_rules = -1

    if "rules" in st_chain_data.keys():
        st_num_rules = len(st_chain_data["rules"])

    if "rules" in tmpload_chain_data.keys():
        tmpload_num_rules = len(tmpload_chain_data["rules"])

    if "rules" in in_k_actual_chain_data.keys():
        actual_num_rules = len(in_k_actual_chain_data["rules"])

    if st_num_rules == tmpload_num_rules:
        logger.debug('NumRules match for Stored vs. In-Kernel-TmpLoad.')
    else:

        logger.error('{0}NumRules mismatch for Stored vs. In-Kernel-TmpLoad.'.format(chain_text))
        num_errors += 1
        logger.error('Must skip further checks!')
        return p_iptables_data

    if tmpload_num_rules == 0:
        logger.debug('No rules in In-Kernel-TmpLoad, no further checks needed.')
        return p_iptables_data

    # Since the numbers of "stored" and "inkernel_tmpload" rules
    # are identical, we assume they match line for line, and we copy
    # the "delete" field of each "stored" rule to the
    # "inkernel_tmpload" rule, and the rebuild important variables.

    rule_t_idx = 0
    repl_chain = []

    while rule_t_idx < tmpload_num_rules:
        new_rule = dict()
        new_rule["line"] = tmpload_chain_data["rules"][rule_t_idx]["line"]
        new_rule["delete"] = st_chain_data["rules"][rule_t_idx]["delete"]
        repl_chain.append(new_rule)
        rule_t_idx = rule_t_idx + 1

    x1 = "kernel_rules"
    x2 = p_table_name
    x3 = tmpload_chain_name
    x4 = one_chain_name

    p_iptables_data[x1][x2][x3]["rules"] = repl_chain
    k_table_data = p_iptables_data[x1][x2]
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
                logger.error('{0}In-Kernel-TmpLoad rules, found identical lines at offsets {1} and {2} '
                             .format(chain_text, rule_1_idx, rule_2_idx))

            rule_2_idx += 1
        rule_1_idx += 1

    if found_dupl_lines == 0:
        logger.debug('Found no duplicates in In-Kernel-TmpLoad rules.')
    else:
        num_errors += 1
        logger.error('{0}found some duplicate lines in In-Kernel-TmpLoad rules.'.format(chain_text))
        logger.error('Must skip further checks!')
        return p_iptables_data

    # Traverse all In-Kernel-TmpLoad rules, and try to match
    # them in strictly increasing order to In-Kernel-Actual rules.

    last_matched_offset = -1
    new_tmpload_rules = []

    tmpload_offset = 0

    while tmpload_offset < tmpload_num_rules:

        tmpload_rule = tmpload_chain_data["rules"][tmpload_offset]

        new_rule = dict()
        new_rule['line'] = tmpload_rule['line']
        new_rule['delete'] = tmpload_rule['delete']
        new_rule['matched_offset'] = -1

        found_match = 0
        search_offset = last_matched_offset + 1

        while search_offset < actual_num_rules:

            actual_rule = in_k_actual_chain_data["rules"][search_offset]

            if actual_rule["line"] == new_rule['line']:
                last_matched_offset = search_offset
                found_match = 1
                break

            search_offset = search_offset + 1

        if found_match != 0:
            new_rule['matched_offset'] = last_matched_offset

        new_tmpload_rules.append(new_rule)

        tmpload_offset = tmpload_offset + 1

    # Overwrite the rule list for the chain with the new list
    # that contains additional information, and re-calculate
    # key "data" variables.

    x1 = "kernel_rules"
    x2 = p_table_name
    x3 = tmpload_chain_name

    p_iptables_data[x1][x2][x3]["rules"] = new_tmpload_rules
    k_table_data = p_iptables_data[x1][x2]
    tmpload_chain_data = k_table_data[x3]

    # Check if all InKernel-TmpLoad rules were matched in InKernel-Actual,
    # and no rules to delete.
    # If YES, we have no further differences to check.

    all_matched = 1
    for one_rule in tmpload_chain_data["rules"]:
        if (one_rule["delete"] != 0) and (one_rule["matched_offset"] >= 0):
            all_matched = 0
            break
        else:
            if one_rule["matched_offset"] < 0:
                all_matched = 0
                break

    if all_matched != 0:
        logger.debug('All In-Kernel-TmpLoad rules matched in Actual, no rules to delete, no further checks needed.')
        return p_iptables_data

    # pp.pprint( p_iptables_data )

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
                logger.error('{0}prior deletes would make a matched offset go negative! Stopping here...'
                             .format(chain_text))
                return p_iptables_data

            one_rule["matched_offset"] = new_val

            if one_rule["delete"] != 0:
                num_deleted_so_far = num_deleted_so_far + 1

    # pp.pprint( p_iptables_data )

    already_inserted = 0

    # Test for "safe" insertion case 1:
    # ---------------------------------
    # If N contiguous rules are not-deletes and unmatched at the beginning,
    # and are either:
    #
    #       a) the only rules of concern since Kernel-Actual is empty
    #       b) followed immediately by a rule that matched at offset 0
    #          (whether it was a delete rule or not)
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
            num_rules_in_block = num_rules_in_block + 1

            if t_rule["delete"] == 0:
                # An unmatched NON-DELETE=INSERT rule
                num_rules_applicable = num_rules_applicable + 1
        else:
            # A matched rule (DELETE or not)
            if t_offset > 0:
                # First matched rule found did not match at offset 0,
                # insertion case 1 does not apply.
                case_1_applies = 0
                num_rules_applicable = 0

            # We exit this loop at first matched rule (DELETE or not)
            break

        rule_idx = rule_idx + 1

    if num_rules_applicable == 0:
        case_1_applies = 0

    if case_1_applies != 0:

        rule_idx = 0
        applicable_rule_idx = 0

        while rule_idx < num_rules_in_block:

            t_rule = tmpload_chain_data["rules"][rule_idx]

            if (t_rule["matched_offset"] < 0) and (t_rule["delete"] == 0):
                # An unmatched NON-DELETE=INSERT rule
                applicable_rule_idx = applicable_rule_idx + 1
                t_rule["insert_pos"] = applicable_rule_idx

            rule_idx = rule_idx + 1

        already_inserted = already_inserted + num_rules_applicable

        if num_rules_applicable == 1:
            part_str = "new rule "
        else:
            part_str = str(num_rules_applicable) + " new rules "

        logger.info('{0}first {1} in Stored config can be safely inserted live in-kernel at the chain beginning.'
                    .format(chain_text, part_str))

    # Test for one or more occurrences of "safe" case 2:
    # --------------------------------------------------
    # one or more contiguous "Kernel-TmpLoad" rules are unmatched
    #    (the block of contiguous rules may contain zero or more
    #     DELETE-UNMATCHED rules),
    #
    # are immediately preceded by a matching rule matched at offset I,
    #    (if this rule is a DELETE/MATCH     rule then J=I,
    #     if this rule is a NON-DELETE/MATCH rule then J=I+1
    #
    # and immediately followed by a matching rule matched at offset J.

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

            rule_idx = rule_idx + 1
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

            rule_idx = rule_idx + 1
            continue  # Continue WHILE loop

        # This is the first "matched" line after a possible
        # "case 2" unmatched group, test if valid case 2!
        # By definition, we have had at least one matched line
        # before...
        if (last_matched_was_delete == 0 and (last_matched_offset + 1) == t_offset) \
                or (last_matched_was_delete != 0 and last_matched_offset == t_offset):

            # This is a valid case 2 "unmatched" group,
            # calculate insert positions for NON-DELETE=INSERT lines

            num_rules_applicable = 0
            rule_idx_2 = unmatched_grp_start_idx

            while rule_idx_2 < rule_idx:

                tmp_rule_2 = tmpload_chain_data["rules"][rule_idx_2]

                if tmp_rule_2["delete"] == 0:

                    target_offset = last_matched_offset + already_inserted + 1

                    if last_matched_was_delete == 0:
                        target_offset = target_offset + 1

                    tmp_rule_2["insert_pos"] = target_offset

                    already_inserted = already_inserted + 1
                    num_rules_applicable = num_rules_applicable + 1

                rule_idx_2 = rule_idx_2 + 1

            if num_rules_applicable == 1:
                part_str = str(num_rules_applicable) + " rule "
            else:
                part_str = str(num_rules_applicable) + " rules "

            logger.info('{0}{1}in Stored config can be safely inserted live in-kernel within other matched rules.'
                        .format(chain_text, part_str))

        # Valid or not, forget about the "case 2" unmatched group.

        unmatched_grp_start_idx = -1
        last_matched_rule_idx = rule_idx
        last_matched_offset = t_offset

        rule_idx = rule_idx + 1

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

        num_rules_in_grp = num_rules_in_grp + 1

        if t_rule["delete"] == 0:
            num_rules_applicable = num_rules_applicable + 1

        rule_idx = rule_idx - 1

    if num_rules_applicable > 0:

        if num_rules_applicable == 1:
            part_str = "rule "
        else:
            part_str = str(num_rules_applicable) + " rules "

        logger.info('{0}last {1}in Stored config can be safely appended live in-kernel to the chain\'s end.'
                    .format(chain_text, part_str))

        rule_idx = tmpload_num_rules - 1

        while num_rules_in_grp > 0:

            if tmpload_chain_data["rules"][rule_idx]["delete"] == 0:
                tmpload_chain_data["rules"][rule_idx]["append"] = 1

            rule_idx = rule_idx - 1
            num_rules_in_grp = num_rules_in_grp - 1

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
            rule_idx = rule_idx + 1
            continue

        if (t_rule["delete"] != 0) and (t_rule["matched_offset"] < 0):
            # Ignore any UNMATCHED DELETE rules
            rule_idx = rule_idx + 1
            continue

        # Other rule cases require a solution:
        #    (UNMATCHED NON-DELETE=INSERT, and MATCHED DELETE)

        if (num_unknown_sol + num_known_sol) == 0:
            logger.info('Plan for rule modifications for chain "{0}/{1}" : (ALL DELETEs will be performed first! )'
                        .format(p_table_name, one_chain_name))

        # Remove the "-A chain_name" portion at the beginning
        # of the rule, and do so reasonably safely!

        target_line = st_chain_data["rules"][rule_idx]["line"]

        target_line = string.replace(target_line, "-A ", " ", 1)
        target_line = string.replace(target_line,
                                     " " + one_chain_name + " ",
                                     " ", 1)

        while target_line[0] == " ":
            target_line = target_line[1:]

        st_chain_data["rules"][rule_idx]["line"] = target_line

        # Display appropriate message for situation

        if (t_rule["delete"] != 0) and (t_rule["matched_offset"] >= 0):
            num_known_sol = num_known_sol + 1
            logger.info('Delete at position {0}: "{1}"'
                        .format(str(t_rule["matched_offset"] + 1), st_chain_data["rules"][rule_idx]["line"]))
            rule_idx = rule_idx + 1
            continue

        if "insert_pos" in t_rule.keys():
            num_known_sol = num_known_sol + 1
            logger.info('Insert at position {0}: "{1}"'
                        .format(str(t_rule["insert_pos"]), st_chain_data["rules"][rule_idx]["line"]))
            rule_idx = rule_idx + 1
            continue

        if "append" in t_rule.keys():
            num_known_sol = num_known_sol + 1
            logger.info('Append at end : "{0}"'.format(st_chain_data["rules"][rule_idx]["line"]))
            rule_idx = rule_idx + 1
            continue

        num_unknown_sol = num_unknown_sol + 1

        logger.error('Unknown solution : "{0}"'.format(st_chain_data["rules"][rule_idx]["line"]))

        rule_idx = rule_idx + 1

    if num_unknown_sol > 0:
        num_errors += 1
        logger.error('Not all unmatched rules can be resolved!')
        return p_iptables_data

    logger.info('Solutions found for all unmatched Stored rules.')

    if do_live_update == 0:
        return p_iptables_data

    logger.info('Starting live update for "{0}" ...'.format(p_table_name + "/" + one_chain_name))
    rule_idx = 0

    while rule_idx < tmpload_num_rules:

        t_rule = tmpload_chain_data["rules"][rule_idx]

        if (t_rule["delete"] != 0) and (t_rule["matched_offset"] >= 0):

            del_offset = t_rule["matched_offset"] + 1

            cmd_str = ("iptables -t " + p_table_name + " -D " +
                       one_chain_name + " " + str(del_offset))

            cmd_rc = run_cmd_with_retry(cmd_str)

            if cmd_rc == 0:
                logger.error('Failed to delete rule "{0}", giving up on other updates!'
                             .format(st_chain_data["rules"][rule_idx]["line"]))
                return p_iptables_data

        rule_idx = rule_idx + 1

    rule_idx = 0

    while rule_idx < tmpload_num_rules:

        t_rule = tmpload_chain_data["rules"][rule_idx]

        if "insert_pos" in t_rule.keys():

            cmd_str = ("iptables -t " + p_table_name +
                       " -I " + one_chain_name + " " +
                       str(t_rule["insert_pos"]) + " " +
                       st_chain_data["rules"][rule_idx]["line"])

            cmd_rc = run_cmd_with_retry(cmd_str)

            if cmd_rc == 0:
                logger.error('Failed to insert rule "{0}", giving up on other updates!'
                             .format(st_chain_data["rules"][rule_idx]["line"]))
                return p_iptables_data
        else:
            if "append" in t_rule.keys():

                cmd_str = ("iptables -t " + p_table_name +
                           " -A " + one_chain_name + " " +
                           st_chain_data["rules"][rule_idx]["line"])

                cmd_rc = run_cmd_with_retry(cmd_str)

                if cmd_rc == 0:
                    logger.error('Failed to append rule "{0}", giving up on other updates!'
                                 .format(st_chain_data["rules"][rule_idx]["line"]))
                    return p_iptables_data

        rule_idx = rule_idx + 1

    logger.info('Live update completed.')
    return p_iptables_data


def determine_overall_diffs(iptables_data, time_str):
    """
    For all "Stored" table/chain combinations , do several verifications,
    taking into account that we now have data on THREE versions
    of each table/chain:

    a) Stored            - the table/chain as specified in the config file
    b) In-Kernel/TmpLoad - the Stored config that was freshly loaded
                           into a chain with a temporary name
    c) In-Kernel/Actual  - the current live config of the chain in-kernel

    To do this reliably, the script actually parsed and read the "rules"
    file, and did a temporary load of the rules into modified chain names
    (that include the time_str), and then read back the rules as stored
    in the kernel.
    :param iptables_data: Dictionary with all the data acquired so far
    :param time_str: Time-based string to be used for temporary chain names
    :return:
    """
    # Main loop: go through all STORED table/chain combinations
    if isinstance(iptables_data, dict):
        for one_table_name in iptables_data["stored_rules"].keys():

            st_table_data = iptables_data["stored_rules"][one_table_name]

            if one_table_name not in iptables_data["kernel_rules"].keys():
                logger.error('Cannot find table name "{0}" In-Kernel!'.format(one_table_name))
                continue

            k_table_data = iptables_data["kernel_rules"][one_table_name]

            for one_chain_name in st_table_data.keys():

                tmpload_chain_name = one_chain_name + "-" + time_str
                logger.debug('Checking Stored/In-kernel diffs for chain "{0}/{1}:"'
                             .format(one_table_name, one_chain_name))

                if ((one_chain_name not in k_table_data.keys()) or
                        (tmpload_chain_name not in k_table_data.keys())):
                    logger.error('For chain {0}/{1}, cannot find in-kernel actual or tmpload version!'
                                 .format(one_table_name, one_chain_name))
                    continue

                iptables_data = determine_one_chain_diffs(
                    iptables_data, one_table_name,
                    one_chain_name, tmpload_chain_name)

    return iptables_data


def parse_arguments():
    """
    Parse command-line arguments.
    :return: the parsed arguments
    """
    message = """
    iptables live-update tool
    -------------------------------------------------------------------------------------------------------
    By default, the script just performs read-only checks on the host iptables configurations.

    If 'live-update' is specified, and the host has 'stored' iptables rules that are not 'live' in-kernel, 
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

    logger.info('Running IPtables analysis script on target host...')

    iptables_support_wait = check_iptable_wait_support()

    file_group = ["/etc/iptables/rules.v4", "/etc/sysconfig/iptables"]

    read_ok, read_lines = read_one_file_of(file_group)

    if read_ok == 0:
        logger.error('Failed to read exactly one file.')
        sys.exit(1)

    parse_ok, main_iptables_data = parse_rules(read_lines)

    if parse_ok == 0:
        logger.error('Parsing of file failed.')
        sys.exit(1)

    logger.debug('Parsing successful.')

    conf_ok, main_iptables_data = confirm_chains_exist_in_kernel(main_iptables_data, iptables_support_wait)

    if conf_ok == 0:
        logger.error('Chain existence confirmation check failed.')
        sys.exit(1)

    our_time_str = str(int(time.time()))
    logger.debug('Computed ephemeral time string: {0}'.format(our_time_str))
    logger.debug('Creating temporary filtering chains in-kernel.')

    main_iptables_data = calculate_test_rules(main_iptables_data, our_time_str)

    add_rc = add_test_rules_to_kernel(main_iptables_data)

    if add_rc == 0:
        logger.error('Some failure occurred...')
        logger.error('Attempting to delete temporary rules and exiting.')
        remove_test_rules_from_kernel(main_iptables_data)
        sys.exit(1)

    main_iptables_data = analyze_in_kernel_rules(main_iptables_data, iptables_support_wait)

    logger.debug('Removing temporary filtering chains from kernel.')

    remove_test_rules_from_kernel(main_iptables_data)

    main_iptables_data = determine_overall_diffs(main_iptables_data, our_time_str)
    logger.debug(pprint(main_iptables_data))

    sys.exit(0)
