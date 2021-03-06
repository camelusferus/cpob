#!/usr/bin/env python3
# cpob - Captive Portal On a Budget
# a small and simple firewalling solution for isolation malicious hosts
#
# file: fw_setup.py
# |-- a configuration generator for iptables/ipset firewalls
#
# Copyright 2020-2021 Nils Trampel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
import time
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

### Construct ipset config

### ipset of config access
ipset_config = "create config_access hash:net\n"
for subnet in config['Main']['config_subnets'].split():
	if '/' in subnet:
		ipset_config += "add config_access " + subnet + "\n"
	else:
		ipset_config += "add config_access " + subnet + "/32\n"
# anti-lockout if none configured
if not len(config['Main']['config_subnets'].split()):
	ipset_config += "add config_access 0.0.0.0/1\nadd config_access 128.0.0.0/1\n"

## ipset of bogon nets
if config['Main']['bogon_nets']:
	ipset_config += "create bogon hash:net\n"
	for subnet in config['Main']['bogon_nets'].split():
		ipset_config += "add bogon " + subnet + "\n"

## ipset of blocked targets
blocked_targets = open(config['xml_api']['blocked_targets_file'],"r")
ipset_config += "create blocked_targets hash:ip\n"
for target in blocked_targets.readlines():
	line = "add blocked_targets " + target
	if line not in ipset_config:
		ipset_config += line


## ipset of quarantine devices mac address with enabled internet access
ipset_config += "create activated_quarantine_macs hash:mac\n"
activations = open(config['xml_api']['activated_macs_file'],"r")
for user in activations.readlines():
	if int(user.split()[1]) > int(time.time()):
		line = "add activated_quarantine_macs " + user.split()[0] + "\n"
		if line not in ipset_config:
			ipset_config += line

## ipset of importent sites accessible without activation
if config['Main']['important_sites']:
	ipset_config += "create important hash:ip\n"
	for subnet in config['Main']['important_sites'].split():
		ipset_config += "add important " + subnet + "\n"

## ipset of internal sites accessible after activation
if config['Main']['internal_sites']:
	ipset_config += "create internals hash:ip\n"
	for subnet in config['Main']['internal_sites'].split():
		ipset_config += "add internals " + subnet + "\n"

## ipset of ipspace which should be blocked while in quarantine
if config['Main']['public_space']:
	ipset_config += "create pub_net hash:net\n"
	for subnet in config['Main']['public_space'].split():
		ipset_config += "add pub_net " + subnet + "\n"

### Construct iptables config
## nat table

iptables_config = '# generated by fw_setup\n'
iptables_config += "*nat\n"
iptables_config += ":PREROUTING ALLOW [0:0]\n"
iptables_config += ":PREROUTING_DEACTIVATED_USERS - [0:0]\n"
iptables_config += ":INPUT ALLOW [0:0]\n"
iptables_config += ":POSTROUTING ALLOW [0:0]\n"
iptables_config += ":OUTPUT ACCEPT [0:0]\n"
if len(config['Main']['dns_server']):
	iptables_config += "-A PREROUTING -i " + config['Main']['quarantine_interface'] + " -p udp --dport 53 -j DNAT --to " + config['Main']['dns_server'] + ":53\n"
else:
	iptables_config += "-A PREROUTING -i " + config['Main']['quarantine_interface'] + " -p udp --dport 53 -j RETURN\n"
iptables_config += "-A PREROUTING -i " + config['Main']['quarantine_interface'] + " -m set ! --match-set activated_quarantine_macs src -j PREROUTING_DEACTIVATED_USERS\n"
iptables_config += "-A PREROUTING_DEACTIVATED_USERS -p tcp -m multiport --dports " + config['Main']['allowed_ports'] + " -m set --match-set important dst -j RETURN\n"
iptables_config += "-A PREROUTING_DEACTIVATED_USERS -p tcp -m multiport --dports 80,443 -d " + config['Main']['portal_server'] + " -j RETURN\n"
iptables_config += "-A PREROUTING_DEACTIVATED_USERS -p tcp --dport 80 -j DNAT --to " + config['Main']['quarantine_ip'] + ":80\n"
iptables_config += "-A POSTROUTING -s " +  config['Main']['quarantine_subnet'] + " -j MASQUERADE\n"
iptables_config += "COMMIT\n"

## filter table
iptables_config += "*filter\n"
iptables_config += ":INPUT DROP [0:0]\n"
iptables_config += ":FORWARD DROP [0:0]\n"
iptables_config += ":OUTPUT ACCEPT [0:0]\n"
iptables_config += ":FORWARD_DEACTIVATED_USERS - [0:0]\n"
iptables_config += ":FORWARD_ACTIVATED_USERS - [0:0]\n"
iptables_config += "-A INPUT -i lo -j ACCEPT\n"
iptables_config += "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
for cfg_int in config['Main']['config_interface'].split():
	iptables_config += "-A INPUT -i " + cfg_int + " -p tcp -m multiport --dports " + config['Main']['config_ports'] + " -m set --match-set config_access src -j ACCEPT\n"
	if config['Main'].getboolean('config_icmp'):
		iptables_config += "-A INPUT -i " + cfg_int + " -p icmp -m set --match-set config_access src -j ACCEPT\n"
# anti-lockout if none configured
if not len(config['Main']['config_interface'].split()):
	iptables_config += "-A INPUT -p tcp -m multiport --dports " + config['Main']['config_ports'] + " -m set --match-set config_access src -j ACCEPT\n"
	if config['Main'].getboolean('config_icmp'):
		iptables_config += "-A INPUT -p icmp -m set --match-set config_access src -j ACCEPT\n"
iptables_config += "-A INPUT -i " + config['Main']['quarantine_interface'] + " -p tcp --dport 80 -j ACCEPT\n"
iptables_config += "-A INPUT -i " + config['Main']['quarantine_interface'] + " -p udp --dport 67 -j ACCEPT\n"
iptables_config += "-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
iptables_config += "-A FORWARD -m state --state INVALID -j DROP\n"
iptables_config += "-A FORWARD ! -i " + config['Main']['quarantine_interface'] + " -j DROP\n"
iptables_config += "-A FORWARD -m set --match-set bogon dst -j DROP\n"
iptables_config += "-A FORWARD -p tcp -m multiport --dports 80,443 -d " + config['Main']['portal_server'] + " -j ACCEPT\n"
iptables_config += "-A FORWARD -m set --match-set blocked_targets dst -j DROP\n"
iptables_config += "-A FORWARD -p udp --dport 53 -j ACCEPT\n"
iptables_config += "-A FORWARD -m set --match-set activated_quarantine_macs src -j FORWARD_ACTIVATED_USERS\n"
iptables_config += "-A FORWARD -m set ! --match-set activated_quarantine_macs src -j FORWARD_DEACTIVATED_USERS\n"
iptables_config += "-A FORWARD_ACTIVATED_USERS -p tcp -m multiport --dports " + config['Main']['allowed_ports'] + " -m set --match-set internals dst -j ACCEPT\n"
iptables_config += "-A FORWARD_ACTIVATED_USERS -m set --match-set pub_net dst -j DROP\n"
iptables_config += "-A FORWARD_ACTIVATED_USERS -p tcp -m multiport --dports " + config['Main']['allowed_ports'] + " -j ACCEPT\n"
iptables_config += "-A FORWARD_DEACTIVATED_USERS -p tcp -m multiport --dports " + config['Main']['allowed_ports'] + " -m set --match-set important dst -j ACCEPT\n"
iptables_config += "COMMIT\n"

print("ipset_config:\n")
print(ipset_config)

print("iptables_config:\n")
print(iptables_config)

# clear all iptables to set ipsets
subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'])
subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'])
subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
subprocess.run(['iptables', '-t', 'mangle', '-F'])
subprocess.run(['iptables', '-t', 'nat', '-F'])
subprocess.run(['iptables', '-F'])
subprocess.run(['iptables', '-X'])

# Apply ipset config
subprocess.run(['ipset', 'destroy'])
subprocess.Popen(['ipset', 'restore'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE).communicate(input=ipset_config.encode())[0]

# Apply iptables config
subprocess.Popen(['iptables-restore'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE).communicate(input=iptables_config.encode())[0]
