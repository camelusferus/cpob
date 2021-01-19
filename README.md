# cpob - Captive Portal On a Budget
##### a small and simple gateway for captive portals

This software is a product of a practical course of my bachelor studies, the goal of which was to isolate malicious user devices in a data network, "quarantine" them by putting them in a different OSI Layer 2 domain to protect neighboring devices, while providing network access to users to allow them to fix their problems.

This software provides a routing solution for linux systems that uses iptables and ipset to firewall blocked devices in the style of a captive portal via HTTP 302 Redirect to the captive portal web interface and can be configured via an XML RPC API.

This software is released under [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

### Requirements 
a linux server with
- at least two network ports (uplink/configuration as well as quarantine)
- ipset (and iptables)
- python3 with the ``requirements.txt`` installed
- DHCP server running, handing out addresses from a RFC1918 pool

### Usage
- both the firewall setup and the API server are simple python script which can be run
- the http redirection is done using the _flask_ framework, so it needs an WSGI server

### Remarks
- There is no captive portal provided by the software, as you might want to have specific information for the user as well as some corporate design in it. You need to provide it and integrate it with the API so your users will be blocked or activated.
- The firewall script is destructive to the iptables firewall as well as ipset definitions each time it is running.
- Run the firewall setup script periodically (either by the API or locally, e.g. cron), so users with expired entitlements will be blocked
- No support for IPv6 (yet)
