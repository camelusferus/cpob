#!/usr/bin/env python3
# cpob - Captive Portal On a Budget
# a small and simple firewalling solution for isolation malicious hosts
#
# file: xmlrpcapi.py
# |-- an api for controlling network clients and remote targets
#
# Copyright 2020 Nils Trampel
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
import configparser
import time
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

config = configparser.ConfigParser()
config.read('config.ini')

class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

with SimpleXMLRPCServer(('0.0.0.0', int(config['xml_api']['port'])),
                        requestHandler=RequestHandler) as server:
    server.register_introspection_functions()

    # Trigger a firewall restart
    def reload_firewall():
        subprocess.run(['./fw_setup.py'])
        return True
    server.register_function(reload_firewall,'reload')

    # Activate User
    def add_time_restricted_access(mac_address, minutes):
        end_time = int(time.time()) + int(minutes) * 60
        file_object = open(config['xml_api']['activated_macs_file'], 'a')
        file_object.write(mac_address + " " + str(end_time) + "\n")
        file_object.close()
        return True
    server.register_function(add_time_restricted_access,'activate')

    # Clear List of Activated Users
    def clear_activated_users():
        file_object = open(config['xml_api']['activated_macs_file'], 'w')
        file_object.close()
        return True
    server.register_function(clear_activated_users(),'clear_activations')

    # Renew blocked ips
    def set_blocked_targets(addresses):
        target_list = addresses.split()
        file_object = open(config['xml_api']['blocked_targets_file'], 'w')
        for ip in target_list:
            file_object.write(ip + "\n")
        file_object.close()
        return True
    server.register_function(set_blocked_targets, 'block')

    # Run the server
    server.serve_forever()
