#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# This file is subject to the terms and conditions defined in
# file 'LICENSE', which is part of this source code package.
#

import logging
import json


config_file_name = "./iptables-hostlist.json"


def gen_no_unicode_list(in_list):
    """

    :param in_list:
    :return: Returns a copy of the passed list where all Unicode string data has been converted to the plain
             non-Unicode variant. Works recursively!
    """
    rc_list = []

    for i in in_list:
        if isinstance(i, dict):
            rc_list.append(gen_no_unicode_dict(i))
        else:
            if isinstance(i, list):
                rc_list.append(gen_no_unicode_list(i))
            else:
                i_str = str(i)

                if len(i_str) > 0:
                    # Interpret a string list item that starts with a "#"
                    # as a commented-out entry.
                    if i_str[0] == "#":
                        continue

                rc_list.append(i_str)

    return rc_list


def gen_no_unicode_dict(in_dict):
    """

    :param in_dict:
    :return: Returns a copy of the passed dictionary where all Unicode string data has been converted to the
             plain non-Unicode variant. Ignore dictionary keys that start with "#" (supports comments).
             Works recursively!
    """
    rc_dict = {}

    for k in in_dict.keys():
        k_str = str(k)

        # Interpret a key that starts with a "#"
        # as a commented-out entry.
        if k_str[0] != "#":
            if isinstance(in_dict[k], dict):
                rc_dict[k_str] = gen_no_unicode_dict(in_dict[k])
            else:
                if isinstance(in_dict[k], list):
                    rc_dict[k_str] = gen_no_unicode_list(in_dict[k])
                else:
                    rc_dict[k_str] = str(in_dict[k])

    return rc_dict


def read_hosts_config():
    """

    :return:
    """
    json_file = open(config_file_name)
    config_data = gen_no_unicode_list(json.load(json_file))
    json_file.close()

    return config_data


def set_debug():
    """

    :return:
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    return
