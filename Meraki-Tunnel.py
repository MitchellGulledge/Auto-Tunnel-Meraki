import requests, json, time
import meraki
import re
from datetime import datetime, timedelta
import ast
import sys
import base64

# Author: Mitchell Gulledge

# class that contains all Meraki necessary config
class MerakiConfig:
    api_key = ''
    org_name = ''
    tag_prefix = 'SIG-'
    org_id = None

# class that contains all Umbrella necessary config
class UmbrellaConfig:
    # this is obtained from the api keys tab and specifically the umbrella management keys
    key = ''
    secret = ''
    # Command -  echo -n 'secret:key' | base64 in terminal
    base64_value = key + ':' + secret
    message_bytes = base64_value.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    tunnel_url = "https://management.api.umbrella.com/v1/organizations/2506818/tunnels"
    # creating header to authenticate API requests to Umbrella
    headers = {'Authorization': 'Basic ' + base64_message}

# writing function to obtain org ID via linking ORG name
mdashboard = meraki.DashboardAPI(MerakiConfig.api_key)
result_org_id = mdashboard.organizations.getOrganizations()
for x in result_org_id:
    if x['name'] == MerakiConfig.org_name:
        MerakiConfig.org_id = x['id']

# defining function that creates dictionary of IPsec config from Umbrella config
def get_meraki_ipsec_config(name, local_id, public_ip, secret, network_tags) -> dict:
    ipsec_config = {
        "name": name,
        "ikeVersion": "2",
        "myUserFqdn": local_id,
        "publicIp": public_ip,
        "privateSubnets": "0.0.0.0/0",
        "secret": secret,
        "ipsecPolicies": {
            "ikeCipherAlgo": ["aes256"],
            "ikeAuthAlgo": ["sha256"],
            "ikeDiffieHellmanGroup": ["group14"],
            "ikeLifetime": 28800,
            "childCipherAlgo": ["aes256"],
            "childAuthAlgo": ["sha256"],
            "childPfsGroup": ["group14"],
            "childLifetime": 3600
        },
        "networkTags": network_tags
    }
    return ipsec_config

# variable with new and existing s2s VPN config
merakivpns = []

# performing initial get to obtain all Meraki existing VPN info 
originalvpn = mdashboard.organizations.getOrganizationThirdPartyVPNPeers(
    MerakiConfig.org_id
)
# appending original vpn variable to the placeholder list merakivpns that was created above
merakivpns.append(originalvpn)

# Meraki call to obtain Network information
tags_network = mdashboard.networks.getOrganizationNetworks(MerakiConfig.org_id)

# loop that iterates through the variable tagsnetwork and matches networks with SIG- in the tag
for meraki_networks in tags_network:
    if meraki_networks['tags'] is None:
        print(meraki_networks['name'])
        pass
    # searches for any network that has a tag beginning with SIG-
    elif "SIG-" in meraki_networks['tags']: 
        # obtaining network ID in order to obtain device information
        network_info = meraki_networks['id'] 
        # network name used to label Meraki VPN and Umbrella ipsec config
        netname = meraki_networks['name'] 
        # obtaining all tags for network as this will be placed in VPN config
        nettag = meraki_networks['tags']  
        # call to get device info
        devices = mdashboard.devices.getNetworkDevices(network_info)[0]
        # validating firmware to ensure device is on 15
        firmwareversion = devices['firmware'] 
        # validation to say True False if MX appliance is on 15 firmware
        firmwarecompliance = str(firmwareversion).startswith("wired-15") 
        if firmwarecompliance == True:
            print("firmware is compliant")
        else:
            break # if box isnt firmware compliant we break from the loop

        primary_vpn_tunnel_ip = '' # variable for umbrella public IP
        # detecting region to determine umbrella public IP addresses to place in IPsec config
        if "SIG-PA-" in meraki_networks['tags']: # US West Region
            # primary tunnel will be built to the PA PoP
            primary_vpn_tunnel_ip = '146.112.67.8'
        elif "SIG-LA-" in meraki_networks['tags']: # US West Region
            # primary tunnel will be built to the LA PoP
            primary_vpn_tunnel_ip = '146.112.66.8'
        elif "SIG-NY-" in meraki_networks['tags']: # East US Region
            # primary tunnel will be built to the NY PoP
            primary_vpn_tunnel_ip = '146.112.83.8'
        elif "SIG-VA-" in meraki_networks['tags']: # East US Region
            # primary tunnel will be built to the VA PoP
            primary_vpn_tunnel_ip = '146.112.82.8'
        elif "SIG-UK-" in meraki_networks['tags']: # UK Region
            # primary tunnel will be built to the UK PoP
            primary_vpn_tunnel_ip = '146.112.97.8'
        elif "SIG-DE-" in meraki_networks['tags']: # Frankfurt Region
            # primary tunnel will be built to the Frankfurt PoP
            primary_vpn_tunnel_ip = '146.112.96.8'
        elif "SIG-SG-" in meraki_networks['tags']: # Singapore Region
            # primary tunnel will be built to the SG PoP
            primary_vpn_tunnel_ip = '146.112.113.8'
        elif "SIG-JP-" in meraki_networks['tags']: # Asia Region
            # primary tunnel will be built to the Tokyo PoP
            primary_vpn_tunnel_ip = '146.112.112.8'
        elif "SIG-SYD-" in meraki_networks['tags']: # Aus Region
            # primary tunnel will be built to the Sydney PoP
            primary_vpn_tunnel_ip = '146.112.118.8'
        elif "SIG-ME-" in meraki_networks['tags']: # Aus Region
            # primary tunnel will be built to the Melbourne PoP
            primary_vpn_tunnel_ip = '146.112.119.8'
        
        # creating umbrella ipsec config to be the data in the post, netname variable is tunnel name
        umbrella_tunnel_name = {"name": netname}
        umbrella_tunnel_data = json.dumps(umbrella_tunnel_name)

        # variable flipped true if Umbrella API indicates that the tunnel name already exists
        tunnel_already_made = False 

        # Send HTTP req to Umbrella to create tunnel
        req = requests.post(UmbrellaConfig.tunnel_url, headers=UmbrellaConfig.headers, \
            data=umbrella_tunnel_data)
         # if we obtain a reason code of Conflict meaning the tunnel is already made we will continue
        if req.reason == 'Conflict':
            tunnel_already_made = True
            print("tunnel already made")
        else:
            tunnelRsp = json.loads(req.text)
            # Access tunnel ID
            tunnelId = tunnelRsp["id"]

            # Access PSK id:key
            client = tunnelRsp["client"]

            # parsing the local id/fqdn for the meraki vpn config here
            tunnelPSKFqdn = client["authentication"]["parameters"]["id"] 
            # parsing the pre shared key for the meraki vpn config here
            tunnelPSKSecret = client["authentication"]["parameters"]["secret"] 

        # below parses the for the specific network tag on the network that correlates with SIG-
        specifictag = re.findall(r'[S]+[I]+[G]+[-].*', str(nettag))
        specifictag1 = re.findall(r'^([\S]+)', str(specifictag[0]))
        print(specifictag1[0])

        # sample IPsec template config that is later replaced with corresponding Azure variables (PSK pub IP, lan IP etc)

        if tunnel_already_made == False:
            # Build meraki config for IPsec configuration (using get_meraki_ipsec_config function)
            primary_vpn_tunnel_template = get_meraki_ipsec_config(netname, tunnelPSKFqdn, \
                primary_vpn_tunnel_ip, tunnelPSKSecret, specific_tag1[0])
          
            newmerakivpns = merakivpns[0]
            # appending newly created tunnel config to original VPN list
            newmerakivpns.append(json.loads(primary_vpn_tunnel_template)) # appending new vpn config with original vpn config
            print(newmerakivpns)

        else: 
            print("tunnel already created")

# final call to update Meraki VPN config
updatemvpn = mdashboard.organizations.updateOrganizationThirdPartyVPNPeers(
    MerakiConfig.org_id, merakivpns[0]
    )
    
