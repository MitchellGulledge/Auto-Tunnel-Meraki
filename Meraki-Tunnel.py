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
import sys

# This code is for automation of tunnels between MX Security Appliances and Umbrella SIG

# Meraki credentials are placed below
meraki_config = {
	'api_key': "",
	'orgName': ""
}

# writing function to obtain org ID via linking ORG name
mdashboard = meraki.DashboardAPI(meraki_config['api_key'])
result_org_id = mdashboard.organizations.getOrganizations()
for x in result_org_id:
    if x['name'] == meraki_config['orgName']:
        meraki_config['org_id'] = x['id']

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
        
        # Set basics to make an API call to Umbrella for tunnel creation
        url = '<a href="https://management.api.umbrella.com/v1/organizations/2506818/tunnels">https://management.api.umbrella.com/v1/organizations/2506818/tunnels</a>'
        umbrella_tunnel_name = {"name": netname}
        data = json.dumps(umbrella_tunnel_name)
        # Executed following command to yield base64 of API Key:Secret. 
        # Command -  echo -n 'secret:key' | base64
        headers = {'Authorization': 'Basic <base64 value>'}

        tunnel_already_made = False # placeholder variable that will get flipped true if Umbrella API indicates that the tunnel name already exists

        # Send HTTP req to Umbrella 
        req = requests.post('https://management.api.umbrella.com/v1/organizations/<Add umbrella org ID here>/tunnels', headers=headers, data=data)
        print(req.reason)
        if req.reason == 'Conflict': # if we obtain a reason code of Conflict meaning the tunnel is already made we will continue
            tunnel_already_made = True
            print("tunnel already made")
        else:
            tunnelRsp = json.loads(req.text)
            # Access tunnel ID
            tunnelId = tunnelRsp["id"]
            print(tunnelId)

            # Access PSK id:key
            client = tunnelRsp["client"]
            print(client["deviceType"])

            tunnelPSKFqdn = client["authentication"]["parameters"]["id"] # parsing the local id/fqdn for the meraki vpn config here
            tunnelPSKSecret = client["authentication"]["parameters"]["secret"] # parsing the pre shared key for the meraki vpn config here

        # need to do a post to umbrella with the netname variable as the tunnel name

        # below parses the for the specific network tag on the network that correlates with SIG-
        specifictag = re.findall(r'[S]+[I]+[G]+[-].*', str(nettag))
        specifictag1 = re.findall(r'^([\S]+)', str(specifictag[0]))
        print(specifictag1[0])

        # need to start building a dictionary (might be string for now) to append to the array of meraki vpns
        # sample IPsec template config that is later replaced with corresponding Azure variables (PSK pub IP, lan IP etc)

        if tunnel_already_made == False:
            primary_vpn_tunnel_template = '{"name":"placeholder","publicIp":"192.0.0.0","privateSubnets":["0.0.0.0/0"],"secret":"meraki123", "ipsecPolicies":{"ikeCipherAlgo":["aes256"],"ikeAuthAlgo":["sha1"],"ikeDiffieHellmanGroup":["group2"],"ikeLifetime":28800,"childCipherAlgo":["aes256"],"childAuthAlgo":["sha1"],"childPfsGroup":["disabled"],"childLifetime":28800},"networkTags":["west"], "myUserFqdn":"mitch@umbrella.com"}'
            primary_vpn_tunnel_tag = primary_vpn_tunnel_template.replace('west', specifictag1[0]) # applies specific tag from org overview page to ipsec config
            primary_vpn_ip = primary_vpn_tunnel_tag.replace('192.0.0.0', primary_vpn_tunnel_ip)   # change variable to primary_vpn_tunnel_ip value
            primary_vpn_tunnel_name = primary_vpn_ip.replace('placeholder' , netname) # replaces placeholder value with dashboard network name
            add_vpn_psk = primary_vpn_tunnel_name.replace('meraki123', tunnelPSKSecret) # replace with pre shared key variable generated above
            # need to add fqdn section
            print(add_vpn_psk)
            add_vpn_fqdn = add_vpn_psk.replace('mitch@umbrella.com',tunnelPSKFqdn)
            print(add_vpn_fqdn)
            newmerakivpns = merakivpns[0]

            # creating secondary VPN tunnel
            secondary_vpn_tunnel_template = '{"name":' + str(netname) + '"-sec","publicIp":' + str(secondary_vpn_tunnel_ip) + ',"privateSubnets":["0.0.0.0/0"],"secret":"' + str(tunnelPSKSecret) + ',"ipsecPolicies":{"ikeCipherAlgo":["aes256"],"ikeAuthAlgo":["sha1"],"ikeDiffieHellmanGroup":["group2"],"ikeLifetime":28800,"childCipherAlgo":["aes256"],"childAuthAlgo":["sha1"],"childPfsGroup":["group2"],"childLifetime":3600},"networkTags":["'+str(specifictag[0])+'"]}'

            # appending newly created tunnel config to original VPN list
            newmerakivpns.append(json.loads(add_vpn_fqdn)) # appending new vpn config with original vpn config
            #newmerakivpns.append(json.loads(secondary_vpn_tunnel_template)) # appending backup tunnel config to vpn list
            print(newmerakivpns)

        else:
            print("tunnel already created")

# final call to update Meraki VPN config
updatemvpn = mdashboard.organizations.updateOrganizationThirdPartyVPNPeers(
    meraki_config['org_id'], merakivpns[0]
    )
