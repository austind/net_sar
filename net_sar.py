#!/usr/bin/env python3

import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import os
import re
import copy
import orionsdk
import netmiko
import getpass
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint as pp
import logging
from datetime import datetime
import yaml


logging.getLogger("paramiko.transport").disabled = True
logging.getLogger("paramiko").setLevel(logging.WARNING)
root_log = logging.getLogger()
log = logging.getLogger("net_sar")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(name)s %(levelname)s: %(message)s")
handler.setFormatter(formatter)
root_log.addHandler(handler)


parser = argparse.ArgumentParser()
parser.add_argument(
    "--config",
    "-c",
    help="Path to YAML config file (defaults to ./config.yml)",
    type=str,
)
args = parser.parse_args()

if not args.config:
    config_file = "./config.yml"
else:
    config_file = args.config

class Struct:
    """ Converts dicts to objects """
    def __init__(self, **entries):
        self.__dict__.update(entries)

with open(config_file, "r") as fh:
    config = Struct(**yaml.safe_load(fh))
log.debug(f"Opened config file {config_file}")

log_level = getattr(logging, config.log_level.upper(), None)
if not isinstance(log_level, int):
    raise ValueError(f"Invalid log level: {log_level}")
else:
    log.setLevel(log_level)
    log.debug(f'Set log level: {config.log_level}')

if not config.validate_certs:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    log.debug(f'Ignoring cert warnings for {config.npm_server}')

# netmiko uses this environment variable for textfsm templates
os.environ["NET_TEXTFSM"] = config.ntc_templates_path

npm_client = orionsdk.SwisClient(
    config.npm_server, config.npm_username, config.npm_password
)
log.debug(f'Connected to {config.npm_server} as {config.npm_username}')
npm_results = npm_client.query(config.npm_query)["results"]
log.debug(f"Retrieved {len(npm_results)} NPM results")

net_device_dict = {
    "device_type": "cisco_ios",
    "username": config.net_username,
    "password": config.net_password,
    "secret": config.net_secret,
}
if config.ssh_config_file:
    net_device_dict.update({"ssh_config_file": config.ssh_config_file})
    log.debug(f'Using SSH config file {config.ssh_config_file}')

def in_npm_results(nbr):
    """ Whether or not a neighbor is in npm_results """
    in_results = False
    for result in npm_results:
        if result["hostname"].lower() == format_neighbor(
            nbr["destination_host"].lower()
        ):
            in_results = True
    return in_results


def i_care(hostname=None, nbr=None):
    """ Whether or not I care about a given host or neighbor """
    if hostname:
        for expr in config.ignore_hosts:
            if re.search(expr, hostname):
                log.debug(
                    f"Host {hostname} matches expression {expr} in ignore_hosts, ignoring"
                )
                return False
        return True

    if nbr:
        for expr in config.ignore_neighbors:
            if re.search(expr, nbr["destination_host"]):
                log.debug(
                    f"Neighbor {nbr['destination_host']} matches expression {expr} in ignore_neighbors, ignoring"
                )
                return False

        if "Router" in nbr["capabilities"] or "Switch" in nbr["capabilities"]:
            return True
        else:
            log.debug(
                f'Neighbor {nbr["destination_host"]} is neither router nor switch, ignoring'
            )
            return False


def get_cdp_neighbors(device):
    start_msg = "===> {} Connection: {}"
    received_msg = "<=== {} Received: {}"
    host = copy.copy(device["host"])
    log.debug(start_msg.format(datetime.now().time(), host))
    result = {host: {"success": False, "msg": None, "neighbors": None}}
    log_msg = "{}: {}"
    try:
        with netmiko.ConnectHandler(**device) as conn:
            cmd = "show cdp neighbors detail"
            output = conn.send_command(cmd, use_textfsm=True)
            log.debug(received_msg.format(datetime.now().time(), host))

        # cdp disabled
        if "not enabled" in output:
            msg = "CDP is disabled"
            log.warning(log_msg.format(host, msg))
            result[host]["msg"] = msg
            return result

        elif type(output) is str:
            msg = "Error parsing CDP output"
            log.warning(log_msg.format(host, msg))
            result[host]["msg"] = msg
            return result

        else:
            if len(output) == 1:
                s = ""
            else:
                s = "s"
            msg = f"Found {len(output)} CDP neighbor{s}"
            log.info(log_msg.format(host, msg))
            result[host]["success"] = True
            result[host]["msg"] = msg
            result[host]["neighbors"] = output
            return result

    except Exception as err:
        msg = err
        log.warning(log_msg.format(host, msg))
        result[host]["msg"] = msg
        return result


def get_all_cdp_neighbors(npm_results):
    """ Get CDP neighbors for all NPM hosts """
    net_devices = []
    for host in npm_results:
        if i_care(hostname=host["hostname"]):
            my_device_dict = copy.copy(net_device_dict)
            my_device_dict["host"] = host["hostname"]
            net_devices.append(my_device_dict)

    log.info(
        f'Gathering CDP neighbors from {len(net_devices)} devices with {config.max_threads} threads'
    )
    with ThreadPoolExecutor(max_workers=config.max_threads) as executor:
        return executor.map(get_cdp_neighbors, net_devices)


def find_lost_neighbors(cdp_results):
    """ Find lost_neighbors in CDP results """
    results = []

    for cdp_result in cdp_results:
        for hostname, status in cdp_result.items():
            if status["success"]:
                for nbr in status["neighbors"]:
                    if i_care(nbr=nbr):
                        nbr_hostname = format_neighbor(nbr["destination_host"])
                        nbr_port = nbr["local_port"]
                        nbr_ip = nbr["management_ip"]
                        nbr_platform = nbr["platform"]
                        if in_npm_results(nbr):
                            log.debug(f"Neighbor {nbr_hostname} is known")
                        else:
                            log.info(
                                f"Found lost neighbor: {nbr_hostname} ({nbr_ip}) on {hostname} port {nbr_port}"
                            )
                            results.append(
                                {
                                    "parent_hostname": hostname,
                                    "parent_port": nbr_port,
                                    "found_hostname": nbr_hostname,
                                    "found_ipaddress": nbr_ip,
                                    "found_platform": nbr_platform,
                                }
                            )
    return results


def save_results(lost_neighbors):
    """ Save results to CSV """
    with open(config.output_path, "w", newline="") as csvfile:
        fieldnames = [
            "parent_hostname",
            "parent_port",
            "found_hostname",
            "found_ipaddress",
            "found_platform",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for nbr in lost_neighbors:
            writer.writerow(nbr)


def format_neighbor(hostname):
    return hostname.split(".")[0]


def main():

    cdp_results = get_all_cdp_neighbors(npm_results)
    lost_neighbors = find_lost_neighbors(cdp_results)
    if config.output_path:
        save_results(lost_neighbors)


if __name__ == "__main__":
    main()
