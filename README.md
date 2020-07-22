Problem: 

Even though configuring the Cisco Meraki MX and Cisco Umbrella tunnel endpoint, it is a manual task and can be daunting when doing it for hundreds of sites. To accomplish the setup, you need to log in to the Cisco Umbrella dashboard; create a Network tunnel; and obtain a tunnel ID and passphrase.


Next, you log in to the Cisco Meraki dashboard. Then, go to MX’s Site-to-site VPN page, scroll down to Non-Meraki VPN and configure the settings manually for each site. 


Then, repeat, for each new site on each of the corresponding dashboards.

Objective:

Allow Cisco customers that have Cisco Meraki MXes and a subscription to Cisco Umbrella SIG to easily scale connections to both services in a supported manner today!

Requirements:

Cisco Umbrella Management API
Cisco Meraki API
Python script:
https://github.com/MitchellGulledge/Auto-Tunnel-Meraki/blob/master/Meraki-Tunnel.py


The Solution:

At a high level, the script will use the API keys provided to automate the entire process. On the Cisco Meraki dashboard, we leverage network tags to help identity target networks and match it to a specific Cisco Umbrella SIG datacenter. The tag structure should follow the form “SIG-{DC to use}-{any value you define}.”





The following table defines the expected DC each tag will configure for your tunnel setup.


Network Tag
IPv4
SIG-PA-XXXX
146.112.67.8
SIG-LA-XXXX
146.112.66.8
SIG-NY-XXXX
146.112.83.8
SIG-VA-XXXX
146.112.82.8
SIG-UK-XXXX
146.112.97.8
SIG-DE-XXXX
146.112.96.8
SIG-SG-XXXX
146.112.113.8
SIG-JP-XXXX
146.112.112.8
SIG-SYD-XXXX
146.112.118.8
SIG-ME-XXXX
146.112.119.8


A couple of things to remember:
The script also assumes VPN is already turned on for the specific MX.
For the tunnel to come up, interesting traffic needs to be generated.


Troubleshooting
Umbrella

To troubleshoot what policy you are hitting, use this debugger link:

http://policy-debug.checkumbrella.com/


Check out the following example:






Meraki

Check if the VPN tunnel is up.

Option 1: Graphical

Security & SD-WAN -> VPN status



Option 2: Logs

Network-wide -> Event log


