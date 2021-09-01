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
logging.basicConfig(
    format="%(threadName)s %(name)s %(levelname)s: %(message)s", level=logging.INFO
)


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

with open("./config.yml", "r") as fh:
    config = yaml.safe_load(fh)

# netmiko uses this environment variable for textfsm templates
os.environ["NET_TEXTFSM"] = config["ntc_templates_path"]

npm_client = orionsdk.SwisClient(
    config["npm_server"], config["npm_username"], config["npm_password"]
)
npm_results = npm_client.query(config["npm_query"])["results"]
logging.info(f"Found {len(npm_results)} NPM results")

net_device_dict = {
    "device_type": "cisco_ios",
    "username": config["net_username"],
    "password": config["net_password"],
    "secret": config["net_secret"],
}
if config["ssh_config_file"]:
    net_device_dict.update({"ssh_config_file": config["ssh_config_file"]})


def in_npm_results(nbr):
    """ Whether or not a neighbor is in npm_results """
    in_results = False
    for result in npm_results:
        if result["hostname"].lower() == format_neighbor(
            nbr["destination_host"].lower()
        ):
            in_results = True
    return in_results


def i_care(hostname, nbr):
    """ Whether or not I care about a given host or neighbor """
    for expr in config["ignore_hosts"]:
        if re.search(expr, hostname):
            return False

    for expr in config["ignore_neighbors"]:
        if re.search(expr, nbr["destination_host"]):
            return False

    if "Router" in nbr["capabilities"] or "Switch" in nbr["capabilities"]:
        return True
    else:
        return False


def get_cdp_neighbors(device):
    start_msg = "===> {} Connection: {}"
    received_msg = "<=== {} Received: {}"
    host = copy.copy(device["host"])
    logging.debug(start_msg.format(datetime.now().time(), host))
    result = {host: {"success": False, "msg": None, "neighbors": None}}
    log_msg = "{}: {}"
    try:
        with netmiko.ConnectHandler(**device) as conn:
            cmd = "show cdp neighbors detail"
            output = conn.send_command(cmd, use_textfsm=True)
            logging.debug(received_msg.format(datetime.now().time(), host))

        # cdp disabled
        if "disabled" in output:
            msg = "CDP is disabled"
            logging.warning(log_msg.format(host, msg))
            result[host]["msg"] = msg
            return result

        elif type(output) is str:
            msg = "Error parsing CDP output"
            logging.warning(log_msg.format(host, msg))
            result[host]["msg"] = msg
            return result

        else:
            if len(output) == 1:
                plural = ''
            else:
                plural = 's'
            msg = f"Found {len(output)} CDP neighbor{plural}"
            logging.info(log_msg.format(host, msg))
            result[host]["success"] = True
            result[host]["msg"] = msg
            result[host]["neighbors"] = output
            return result

    except Exception as err:
        msg = err
        logging.warning(log_msg.format(host, msg))
        result[host]["msg"] = msg
        return result


def format_neighbor(hostname):
    return hostname.split(".")[0]


def main():

    # Build netmiko device connection dicts for all NPM hosts we care about
    net_devices = []
    for host in npm_results:
        for expr in config["ignore_hosts"]:
            if re.search(expr, host["hostname"]):
                logging.info(
                    f'Hostname {host["hostname"]} matches expression "{expr}" in ignore_hosts, ignoring'
                )
                continue
        my_device_dict = copy.copy(net_device_dict)
        my_device_dict["host"] = host["hostname"]
        net_devices.append(my_device_dict)

    cdp_results = {}
    logging.info(
        f'Gathering CDP neighbors from {len(net_devices)} devices with {config["max_threads"]} threads'
    )
    with ThreadPoolExecutor(max_workers=config["max_threads"]) as executor:
        cdp_results = executor.map(get_cdp_neighbors, net_devices[:20])

    results = []

    for cdp_result in cdp_results:
        for hostname, status in cdp_result.items():
            if status["success"]:
                for nbr in status["neighbors"]:
                    if i_care(hostname, nbr):
                        nbr_hostname = format_neighbor(nbr["destination_host"])
                        nbr_port = nbr["local_port"]
                        nbr_ip = nbr["management_ip"]
                        nbr_platform = nbr["platform"]
                        if not in_npm_results(nbr):
                            logging.info(
                                f"Found orphan: {nbr_hostname} ({nbr_ip}) on {hostname} port {nbr_port}"
                            )
                            results.append(
                                {
                                    "foster_hostname": hostname,
                                    "foster_port": nbr_port,
                                    "orphan_hostname": nbr_hostname,
                                    "orphan_ipaddress": nbr_ip,
                                    "orphan_platform": nbr_platform,
                                }
                            )

    with open(config["output_path"], "w", newline="") as csvfile:
        fieldnames = [
            "foster_hostname",
            "foster_port",
            "orphan_hostname",
            "orphan_ipaddress",
            "orphan_platform",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)


if __name__ == "__main__":
    main()
