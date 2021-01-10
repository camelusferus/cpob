#!/usr/bin/env python3
# cpob - Captive Portal On a Budget
# a small and simple firewalling solution for isolation malicious hosts
#
# file: http_redirector.py
# |-- a http server for redirecting unactivated users to the captive portal
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


import configparser
import subprocess
import pyAesCrypt
import io
import base64
import urllib

from http.server import HTTPServer, BaseHTTPRequestHandler

config = configparser.ConfigParser()
config.read('config.ini')


class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            request_ip = self.client_address[0]
            p1 = subprocess.Popen(["ip", "-4", "n"], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["grep", request_ip + " "], stdin=p1.stdout, stdout=subprocess.PIPE)
            p1.stdout.close()
            neighbor_reply = p2.communicate()[0]
            neighbor_state = neighbor_reply.split()[3]
            if neighbor_state != b'lladdr':
                raise Exception("No layer2_connectivity for getting the MAC address")
            request_mac = neighbor_reply.split()[4]
            if config.has_option('Main', 'mac_encryption_key'):
                password = config['Main']['mac_encryption_key']
                crypto_in = io.BytesIO(request_mac)
                crypto_out = io.BytesIO()
                pyAesCrypt.encryptStream(crypto_in, crypto_out, password, 65536)
                self.send_response(302)
                self.send_header('Location', config['http_redirector']['portal_url_template'] + urllib.parse.quote(
                    base64.b64encode(crypto_out.getvalue()), safe=''))
            else:
                self.send_response(302)
                self.send_header('Location', config['http_redirector']['portal_url_template'] + request_mac)
            self.end_headers()
        except:
            self.send_response(500)

    def do_POST(self):
        self.do_GET()

    def do_HEAD(self):
        self.do_GET()


HTTPServer(("", 80), Redirect).serve_forever()
