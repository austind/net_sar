# Network Search and Rescue
Find lost CDP neighbors

1. Reads list of known hosts from Solarwinds Orion
1. For each host, finds all active CDP neighbors
1. Compares those neighbors to known hosts
1. Reports any unknown CDP neighbors

## Requirements

* Python 3.6+
* netmiko
* orionsdk
* pyyaml

## Usage

1. Install NTC templates: `git clone https://github.com/networktocode/ntc-templates.git ~/ntc-templates`
1. Rename `config.yml.example` to `config.yml` and match to your environment
1. Run `python3 net_sar.py`
