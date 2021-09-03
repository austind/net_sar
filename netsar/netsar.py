from concurrent.futures import ThreadPoolExecutor
import csv
import os
import re
import copy
import netmiko
import getpass
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint as pp
import logging
from datetime import datetime
import yaml


class Struct:
    """ Converts dicts to objects """

    def __init__(self, **entries):
        self.__dict__.update(entries)


class Search(object):
    def __init__(self, config_file="./config.yml"):

        logging.getLogger("paramiko.transport").disabled = True
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        self.root_log = logging.getLogger()
        self.log = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(name)s %(levelname)s: %(message)s")
        handler.setFormatter(formatter)
        self.root_log.addHandler(handler)

        if os.path.exists(config_file):
            with open(config_file, "r") as fh:
                self.config = Struct(**yaml.safe_load(fh))
            self.log.debug(f"Loaded config file {config_file}")
        else:
            raise ValueError(f"Config file {config_file} does not exist")

        log_level = getattr(logging, self.config.log_level.upper(), None)
        if not isinstance(log_level, int):
            raise ValueError(f"Invalid log level: {self.config.log_level}")
        else:
            self.log.setLevel(log_level)
            self.log.debug(f"Set log level: {self.config.log_level}")

        self.net_device_dict = {
            "device_type": self.config.device_type,
            "username": self.config.net_username,
            "password": self.config.net_password,
            "secret": self.config.net_secret,
        }
        if self.config.ssh_config_file:
            self.net_device_dict.update({"ssh_config_file": self.config.ssh_config_file})
            self.log.debug(f"Using SSH config file {self.config.ssh_config_file}")

        # netmiko uses this environment variable for textfsm templates
        os.environ["NET_TEXTFSM"] = self.config.ntc_templates_path
        self.log.debug(
            f"Set environment variable NET_TEXTFSM to {self.config.ntc_templates_path}"
        )

    def _format_neighbor(self, hostname):
        return hostname.split(".")[0]


    def _in_inventory(self, nbr):
        """ Whether or not a neighbor is in self.inventory """
        in_inventory = False
        for item in self.inventory:
            if item["hostname"].lower() == self._format_neighbor(
                nbr["destination_host"].lower()
            ):
                in_inventory = True
        return in_inventory

    def _i_care(self, hostname=None, nbr=None):
        """ Whether or not I care about a given host or neighbor """
        if hostname:
            for expr in self.config.ignore_hosts:
                if re.search(expr, hostname):
                    self.log.debug(
                        f"Host {hostname} matches expression {expr} in ignore_hosts, ignoring"
                    )
                    return False
            return True

        if nbr:
            for expr in self.config.ignore_neighbors:
                if re.search(expr, nbr["destination_host"]):
                    self.log.debug(
                        f"Neighbor {nbr['destination_host']} matches expression {expr} in ignore_neighbors, ignoring"
                    )
                    return False

            if "Router" in nbr["capabilities"] or "Switch" in nbr["capabilities"]:
                return True
            else:
                self.log.debug(
                    f'Neighbor {nbr["destination_host"]} is neither router nor switch, ignoring'
                )
                return False

    def _get_textfsm_template(self, cmd=None):
        """ Gets textfsm filename based on cmd and device_type """
        if cmd is None:
            cmd = self.config.cmd
        return f"{self.config.ntc_templates_path}/" \
                f"{self.config.device_type}_" \
                f"{self.config.cmd.replace(' ', '_')}.textfsm"

    def get_inventory(self):

        import orionsdk

        if not self.config.validate_certs:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            self.log.debug(f"Ignoring cert warnings for {self.config.npm_server}")

        npm_client = orionsdk.SwisClient(
            self.config.npm_server, self.config.npm_username, self.config.npm_password
        )
        self.log.debug(
            f"Connected to {self.config.npm_server} as {self.config.npm_username}"
        )
        self.inventory = npm_client.query(self.config.npm_query)["results"]
        self.log.debug(f"Retrieved {len(self.inventory)} NPM results")


    def get_neighbors(self, device, protocol=None, cmd=None):
        """ Get neighbors for given device """
        if protocol is None:
            protocol = self.config.protocol
        if cmd is None:
            cmd = self.config.cmd
        
        textfsm_template = self._get_textfsm_template()
        if not os.path.exists(os.path.expanduser(textfsm_template)):
            raise ValueError(f"Could not find textfsm template: \n{textfsm_template}")
        self.log.debug(f"Using textfsm template: \n{textfsm_template}")
        start_msg = "===> {} Connection: {}"
        received_msg = "<=== {} Received: {}"
        host = copy.copy(device["host"])
        self.log.debug(start_msg.format(datetime.now().time(), host))
        result = {host: {"success": False, "msg": None, "neighbors": None}}
        log_msg = "{}: {}"
        try:
            with netmiko.ConnectHandler(**device) as conn:
                output = conn.send_command(cmd, use_textfsm=True)
                self.log.debug(received_msg.format(datetime.now().time(), host))
                self.log.debug(pp(output))

            if "not enabled" in output:
                msg = f"{protocol.upper()} is disabled"
                self.log.error(log_msg.format(host, msg))
                result[host]["msg"] = msg
                return result

            elif type(output) is str:
                msg = f"Error parsing {protocol.upper()} output"
                self.log.error(log_msg.format(host, msg))
                result[host]["msg"] = msg
                return result

            else:
                if len(output) == 1:
                    s = ""
                else:
                    s = "s"
                msg = f"Found {len(output)} {protocol.upper()} neighbor{s}"
                self.log.info(log_msg.format(host, msg))
                result[host]["success"] = True
                result[host]["msg"] = msg
                result[host]["neighbors"] = output
                return result

        except Exception as err:
            msg = err
            self.log.warning(log_msg.format(host, msg))
            result[host]["msg"] = msg
            return result

    def get_neighborhood(self, inventory=None):
        """ Get neighbors for all hosts """
        if inventory is None:
            inventory = self.inventory
        net_devices = []
        for host in inventory:
            if self._i_care(hostname=host["hostname"]):
                my_device_dict = copy.copy(self.net_device_dict)
                my_device_dict["host"] = host["hostname"]
                net_devices.append(my_device_dict)

        self.log.info(
            f"Getting all neighbors from {len(net_devices)} devices with {self.config.max_threads} threads"
        )
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            self.neighborhood = executor.map(self.get_neighbors, net_devices)

    def find_lost_neighbors(self, neighborhood=None):
        """ Find lost_neighbors in CDP results """
        if neighborhood is None:
            neighborhood = self.neighborhood
        results = []

        for resident in neighborhood:
            for hostname, status in resident.items():
                if status["success"]:
                    for nbr in status["neighbors"]:
                        if self._i_care(nbr=nbr):
                            nbr_hostname = self._format_neighbor(nbr["destination_host"])
                            nbr_port = nbr["local_port"]
                            nbr_ip = nbr["management_ip"]
                            nbr_platform = nbr["platform"]
                            if self._in_inventory(nbr):
                                self.log.debug(
                                    f"Neighbor {nbr_hostname} is in inventory"
                                )
                            else:
                                self.log.info(
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
        self.lost_neighbors = results

    def save_results(self, path=None, lost_neighbors=None):
        """ Save results to CSV """
        if path is None:
            path = self.config.output_path
        if lost_neighbors is None:
            lost_neighbors = self.lost_neighbors
        with open(path, "w", newline="") as csvfile:
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

def main():

    search = Search()
    search.get_inventory()
    search.get_neighborhood()
    search.find_lost_neighbors()
    pp(search.lost_neighbors)

if __name__ == "__main__":
    main()