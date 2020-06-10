import requests, json, time
import meraki
from io import BytesIO
from operator import itemgetter
from passwordgenerator import pwgenerator
import logging
import re
import urllib.request
import os
import datetime as dt
from datetime import datetime, timedelta
import ast
import subprocess
import base64


# This code is for automation of tunnels between MX Security Appliances and Umbrella SIG

# Umbrella credentials are placed below
umbrella_config = {
    'umbrella_api_key': "",  # umbrella management API key
    'umbrella_orgId': ""
}

# Meraki credentials are placed below
meraki_config = {
	'api_key': "",
	'orgName': ""
}

# creating Umbrella access token


# writing function to obtain org ID via linking ORG name
mdashboard = meraki.DashboardAPI(meraki_config['api_key'])
result_org_id = mdashboard.organizations.getOrganizations()
for x in result_org_id:
    if x['name'] == meraki_config['orgName']:
        meraki_config['org_id'] = x['id']

# Generate random password for site to site VPN config, this needs to be updated to fit umbrellas PSK requirement
psk = pwgenerator.generate()
print(psk)

# branch subnets is a variable to display local branch site info
branchsubnets = []
# variable with new and existing s2s VPN config
merakivpns = []

# performing initial get to obtain all Meraki existing VPN info to add to merakivpns list above
originalvpn = mdashboard.organizations.getOrganizationThirdPartyVPNPeers(
    meraki_config['org_id']
)
merakivpns.append(originalvpn)

# Meraki call to obtain Network information
tagsnetwork = mdashboard.networks.getOrganizationNetworks(meraki_config['org_id'])

# loop that iterates through the variable tagsnetwork and matches networks with SIG- in the tag
for i in tagsnetwork:
    if i['tags'] is None or i['name'] == 'Tag-Placeholder':
        pass
    # searches for any network that has a tag beginning with SIG-, this is since each meraki network will need a unique identifier
    elif "SIG-" in i['tags']: 
        network_info = i['id'] # need network ID in order to obtain device/serial information
        netname = i['name'] # network name used to label Meraki VPN and Umbrella config
        nettag = i['tags']  # obtaining all tags for network as this will be placed in VPN config
        devices = mdashboard.devices.getNetworkDevices(network_info) # call to get device info
        xdevices = devices[0] # just parsing brackets
        up = xdevices['serial'] # serial number to later obtain the uplink information for the appliance
        firmwareversion = xdevices['firmware'] # now we obtained the firmware version, need to still add the validation portion
        firmwarecompliance = str(firmwareversion).startswith("wired-15") # validation to say True False if MX appliance is on 15 firmware
        if firmwarecompliance == True:
            print("firmware is compliant")
        else:
            break # if box isnt firmware compliant we break from the loop
        modelnumber = xdevices['model']

        primary_vpn_tunnel_ip = ''
        secondary_vpn_tunnel_ip = ''

        # detecting region to determine umbrella public IP addresses to place in IPsec config
        if "SIG-US1-" in i['tags']: # US West Region
            # primary tunnel will be built to the LA PoP
            primary_vpn_tunnel_ip = '146.112.67.8'
            # backup tunnel will be built to the Palo Alto PoP
            secondary_vpn_tunnel_ip = '146.112.66.8'
        elif "SIG-US2-" in i['tags']: # US East Region
            # primary tunnel will be built to the NY PoP
            primary_vpn_tunnel_ip = '146.112.83.8'
            # backup tunnel will be built to the Ashburn PoP
            secondary_vpn_tunnel_ip = '146.112.82.8'
        elif "SIG-EU-" in i['tags']: # EMEAR Region
            # primary tunnel will be built to the UK PoP
            primary_vpn_tunnel_ip = '146.112.97.8'
            # backup tunnel will be built to the DE PoP
            secondary_vpn_tunnel_ip = '146.112.96.8'
        elif "SIG-AU-" in i['tags']: # AUS Region
            # primary tunnel will be built to the SYD PoP
            primary_vpn_tunnel_ip = '146.112.118.8'
            # backup tunnel will be built to the Melbourn PoP
            secondary_vpn_tunnel_ip = '146.112.119.8'
        elif "SIG-AS-" in i['tags']: # ASIA Region
            # primary tunnel will be built to the SG PoP
            primary_vpn_tunnel_ip = '146.112.113.8'
            # backup tunnel will be built to the JP PoP
            secondary_vpn_tunnel_ip = '146.112.112.8'

        # need to do a post to umbrella with the netname variable as the tunnel name

        # below parses the for the specific network tag on the network that correlates with SIG-
        specifictag = re.findall(r'[S]+[I]+[G]+[-].*', str(nettag))
        specifictag1 = re.findall(r'^([\S]+)', str(specifictag[0]))
        print(specifictag1[0])

        # need to start building a dictionary (might be string for now) to append to the array of meraki vpns
        # sample IPsec template config that is later replaced with corresponding Azure variables (PSK pub IP, lan IP etc)

        primary_vpn_tunnel_template = '{"name":"placeholder","publicIp":"192.0.0.0","privateSubnets":["0.0.0.0/0"],"secret":"meraki123", "ipsecPolicies":{"ikeCipherAlgo":["aes256"],"ikeAuthAlgo":["sha1"],"ikeDiffieHellmanGroup":["group2"],"ikeLifetime":28800,"childCipherAlgo":["aes256"],"childAuthAlgo":["sha1"],"childPfsGroup":["group2"],"childLifetime":3600},"networkTags":["west"]}'
        primary_vpn_tunnel_tag = primary_vpn_tunnel_template.replace("west", specifictag[0]) # applies specific tag from org overview page to ipsec config
        primary_vpn_ip = primary_vpn_tunnel_tag.replace('192.0.0.0', primary_vpn_tunnel_ip)   # change variable to primary_vpn_tunnel_ip value
        primary_vpn_tunnel_name = primary_vpn_ip.replace('placeholder' , netname) # replaces placeholder value with dashboard network name
        add_vpn_psk = primary_vpn_tunnel_name.replace('meraki123', psk) # replace with pre shared key variable generated above
        newmerakivpns = merakivpns[0]

        # creating second data input to append instance 1 to the merakivpn list

        secondary_vpn_tunnel_template = '{"name":"theplaceholder","publicIp":"192.1.0.0","privateSubnets":["0.0.0.0/1"],"secret":"meraki223", "ipsecPolicies":{"ikeCipherAlgo":["aes256"],"ikeAuthAlgo":["sha1"],"ikeDiffieHellmanGroup":["group2"],"ikeLifetime":28800,"childCipherAlgo":["aes256"],"childAuthAlgo":["sha1"],"childPfsGroup":["group2"],"childLifetime":3600},"networkTags":["east"]}'
        secondary_vpn_name = str(netname) + "-sec" # adding the -sec to the netname variable to distinguish the 2 tunnels in Meraki dashboard
        secondary_vpn_tunnel_tag = secondary_vpn_tunnel_template.replace("east", specifictag[0] + "-sec") # applies specific tag from org overview page to ipsec config need to make this secondary
        secondary_vpn_ip = secondary_vpn_tunnel_tag.replace('192.1.0.0', secondary_vpn_tunnel_ip) # placing secondary tunnel public ip over placeholder
        secondary_vpn_tunnel_name = secondary_vpn_ip.replace('theplaceholder' , secondary_vpn_name) # replaces placeholder value with dashboard network name
        secondary_vpn_tunnel_psk = secondary_vpn_tunnel_name.replace('meraki223', psk) # replace with pre shared key variable generated above

        # obtaining list of current connectivity monitoring destinations for the network

        mx_destinations = mdashboard.connectivity_monitoring_destinations.getNetworkConnectivityMonitoringDestinations(str(network_info))
        print(mx_destinations['destinations'][0]['ip'])

        vpn_site_config = []

        # now build dictionary template to then later append to the list

        def newdestination(vpn_ipaddress):
                site_config = {"ip": vpn_ipaddress, "description": "primary vpn peer", "default": False}
                vpn_site_config.append(site_config)

        newdestination(primary_vpn_tunnel_ip) 

        # need to detect if vpn peer IPs are already contained in the connectivity monitoring destinations

        connectivity_monitor_updated = False

        for vpn_peer_ip in mx_destinations['destinations']: #  iterating through connectivity monitoring list of destinations
            if vpn_peer_ip['ip'] == primary_vpn_tunnel_ip:  #  matches vpn peer ip in merakivpns variable
                # creating new variable to indicate that dictionary should not be appended to connectivity monitoring list if this value is already contained
                connectivity_monitor_updated = True

        print("look below")
        print(vpn_site_config[0])
        print(mx_destinations['destinations'])


        if connectivity_monitor_updated == False:
            # appending new vpn site config to the original destination list
            original_destination_list = mx_destinations['destinations']
            original_destination_list.append(vpn_site_config[0])
            mx_destinations['destinations'] = original_destination_list
            print(original_destination_list)

        # updating connectivity monitoring destinations for tagged network

        if connectivity_monitor_updated == False:
            payload = ast.literal_eval(original_destination_list)
            # if payload == {'a': 1, 'b': 'c'}, then sending **payload will result in function call with (…, a=‘1’, ‘b’=‘c’) as arguments
            update_mx_destinations = mdashboard.connectivity_monitoring_destinations.updateNetworkConnectivityMonitoringDestinations(str(network_info), **payload)
