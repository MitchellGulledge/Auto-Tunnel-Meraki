import requests, json, time
import meraki
import re
import ast
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
    org_id = ''
    # Command -  echo -n 'secret:key' | base64 in terminal
    base64_value = key + ':' + secret
    message_bytes = base64_value.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    tunnel_url = "https://management.api.umbrella.com/v1/organizations/"+org_id+"/tunnels"
    # creating header to authenticate API requests to Umbrella
    headers = {'Authorization': 'Basic ' + base64_message}

# function to parse list of tags for an individual network
def strip_meraki_network_tags(meraki_network_tag):
    # below parses the for the specific network tag on the network that correlates with SIG-
    meraki_tag_strip_part1 = re.findall(r'[S]+[I]+[G]+[-].*', str(meraki_network_tag))
    meraki_tag_strip_part2 = re.findall(r'^([\S]+)', str(meraki_tag_strip_part1[0]))
    return meraki_tag_strip_part2[0]

# writing function to obtain org ID via linking ORG name
mdashboard = meraki.DashboardAPI(MerakiConfig.api_key)
result_org_id = mdashboard.organizations.getOrganizations()
for x in result_org_id:
    if x['name'] == MerakiConfig.org_name:
        MerakiConfig.org_id = x['id']

# defining function that creates dictionary of IPsec config from Umbrella config
def get_meraki_ipsec_config(name, public_ip, secret, network_tags, local_id) -> dict:
    ipsec_config = {
        "name": name,
        "publicIp": public_ip,
        "privateSubnets": ["0.0.0.0/0"],
        "secret": secret,
        "ikeVersion": "2",
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
        "networkTags": [ network_tags ],
        "myUserFqdn": local_id
    }
    return ipsec_config

# function to determine the vpn peer IP for the Meraki branch from network tags
def define_vpn_peer_ip(meraki_tag_list):
    primary_vpn_tunnel_ip = '' # variable for umbrella public IP

    # detecting region to determine umbrella public IP addresses to place in IPsec config
    if "SIG-PA-" in meraki_tag_list: # US West Region
        # primary tunnel will be built to the PA PoP
        primary_vpn_tunnel_ip = '146.112.67.8'

    elif "SIG-LA-" in meraki_tag_list: # US West Region
        # primary tunnel will be built to the LA PoP
        primary_vpn_tunnel_ip = '146.112.66.8'

    elif "SIG-NY-" in meraki_tag_list: # East US Region
        # primary tunnel will be built to the NY PoP
        primary_vpn_tunnel_ip = '146.112.83.8'

    elif "SIG-VA-" in meraki_tag_list: # East US Region
        # primary tunnel will be built to the VA PoP
        primary_vpn_tunnel_ip = '146.112.82.8'

    elif "SIG-UK-" in meraki_tag_list: # UK Region
        # primary tunnel will be built to the UK PoP
        primary_vpn_tunnel_ip = '146.112.97.8'

    elif "SIG-DE-" in meraki_tag_list: # Frankfurt Region
        # primary tunnel will be built to the Frankfurt PoP
        primary_vpn_tunnel_ip = '146.112.96.8'

    elif "SIG-SG-" in meraki_tag_list: # Singapore Region
        # primary tunnel will be built to the SG PoP
        primary_vpn_tunnel_ip = '146.112.113.8'

    elif "SIG-JP-" in meraki_tag_list: # Asia Region
        # primary tunnel will be built to the Tokyo PoP
        primary_vpn_tunnel_ip = '146.112.112.8'

    elif "SIG-SYD-" in meraki_tag_list: # Aus Region
        # primary tunnel will be built to the Sydney PoP
        primary_vpn_tunnel_ip = '146.112.118.8'

    elif "SIG-ME-" in meraki_tag_list: # Aus Region
        # primary tunnel will be built to the Melbourne PoP
        primary_vpn_tunnel_ip = '146.112.119.8'

    return primary_vpn_tunnel_ip

def delete_umbrella_tunnel(vpn_tunnel_name):
    # fetching list of umbrella tunnel config
    get_req = requests.get(UmbrellaConfig.tunnel_url, headers=UmbrellaConfig.headers)
    umbrella_tunnel_info = get_req.json()
    print("info" + str(umbrella_tunnel_info))

    for tunnel in umbrella_tunnel_info:
        # matching against tunnel name as conditional statement
        if vpn_tunnel_name == tunnel["name"]:

            # parsing umbrella tunnel config for id
            umb_tunnel_id = tunnel["id"]

            # umbrella URL class
            delUrl = 'https://management.api.umbrella.com/v1/organizations/'+ \
                UmbrellaConfig.org_id+'/tunnels/' + str(umb_tunnel_id)
            
            # deleting Umbrella tunnel
            delReq = requests.delete(delUrl, headers=UmbrellaConfig.headers)
            print(delReq.reason)

            if delReq.reason == 200:
                # if tunnel deleted successfully, swapping tunnel already made variable back to false
                tunnel_already_made = False

# function to update Meraki VPN config
def update_meraki_vpn(vpn_list):
    updatemvpn = mdashboard.organizations.updateOrganizationThirdPartyVPNPeers(
    MerakiConfig.org_id, vpn_list
    )

# function to validate that MX is on version 15 or greater
def validate_mx_firmware(branch_node):
    # call to get device info
    devices = mdashboard.devices.getNetworkDevices(branch_node)
    print(devices)
    # validating firmware to ensure device is on 15
    firmwareversion = devices[0]['firmware'] 
    # validation to say True False if MX appliance is on 15 firmware
    firmwarecompliance = str(firmwareversion).startswith("wired-15") 
    if firmwarecompliance == True:
        print("firmware is compliant")
    else:
        print("firmware is not compliant breaking loop")
        firmwarecompliance = False
    return firmwarecompliance

# this function creates an umbrella IPsec tunnel and return FQDN and Secret
def create_umbrella_tunnel(tunnel_name):
    # Post to create tunnel in SIG dashboard
    tunnel_response = requests.post(UmbrellaConfig.tunnel_url, headers=UmbrellaConfig.headers, \
         data=tunnel_name)
    umbrella_tunnel_info = tunnel_response.json()
    # parsing tunnel info for tunnel psk and id
    # Access tunnel ID
    tunnelId = umbrella_tunnel_info["id"]
    # Access PSK id:key
    client = umbrella_tunnel_info["client"]

    # parsing the local id/fqdn for the meraki vpn config here
    tunnelPSKFqdn = client["authentication"]["parameters"]["id"] 
    # parsing the pre shared key for the meraki vpn config here
    tunnelPSKSecret = client["authentication"]["parameters"]["secret"] 
    
    return tunnelPSKFqdn, tunnelPSKSecret

# this function performs initial get to obtain all Meraki existing VPN info 
def get_meraki_ipsec_tunnels():
    originalvpn = mdashboard.organizations.getOrganizationThirdPartyVPNPeers(
        MerakiConfig.org_id)  
    return originalvpn     

# variable with new and existing s2s VPN config
merakivpns = []

# performing initial get to obtain all Meraki existing VPN info 
original_meraki_tunnels = get_meraki_ipsec_tunnels()
print(original_meraki_tunnels)

# appending original vpn variable to the placeholder list merakivpns that was created above
merakivpns.append(original_meraki_tunnels)
merakivpns = merakivpns[0]

# Meraki call to obtain Network information
tags_network = mdashboard.networks.getOrganizationNetworks(MerakiConfig.org_id)

# loop that iterates through the variable tagsnetwork and matches networks with SIG- in the tag
for meraki_networks in tags_network:
    # need to account for Nonetype datatype when iterating through loop
    if meraki_networks['tags'] == None: 
        pass
    # searches for any network that has a tag beginning with SIG-
    elif "SIG-" in meraki_networks['tags']: 
        # obtaining network ID in order to obtain device information
        network_info = meraki_networks['id'] 
        # network name used to label Meraki VPN and Umbrella ipsec config
        netname = meraki_networks['name'] 
        # obtaining all tags for network as this will be placed in VPN config
        nettag = meraki_networks['tags']  

        # calling function to validate branch firmware version
        firmware_validate = validate_mx_firmware(network_info)

        if firmware_validate == False:
            # if the firmware validation returns as false the script will break from the loop
            break 

        # calling function to obtain the umbrella vpn IP determined from the tag placed on network
        meraki_branch_peer_ip = define_vpn_peer_ip(meraki_networks['tags'])

        # creating umbrella ipsec config to be the data in the post, netname variable is tunnel name
        umbrella_tunnel_name = {"name": netname, 'deviceType': 'Meraki MX'}
        umbrella_tunnel_data = json.dumps(umbrella_tunnel_name)

        # variable flipped true if Umbrella API indicates that the tunnel name already exists
        tunnel_already_made = False 

        # fetching list of umbrella tunnel config
        get_req = requests.get(UmbrellaConfig.tunnel_url, headers=UmbrellaConfig.headers)

        # converting get_req (list of umbrella vpn tunnels) from json response to dictionary
        umbrella_tunnel_dict = get_req.json()

        # creating placeholder variable for detecting whether the tunnel is created or not in umbrella
        tunnel_already_made = False

        # placeholder variable for detecting whether the tunnel is created in umbrella and not meraki
        in_umb_not_meraki = False 

        # now we can iterate through the loop and see if netname is contained within the get_req variable
        for tunnel_name in umbrella_tunnel_dict:
            if netname == tunnel_name['name']:
                tunnel_already_made = True
                print("tunnel detected in Umbrella config")
            else:
                print("tunnel not detected in Umbrella config")
        
        # if tunnel is built in umbrella already but not Meraki we need to detect and update config
        if tunnel_already_made == True:
            for meraki_tunnel_name in merakivpns:
                if netname == meraki_tunnel_name['name']:
                    print("tunnel config in umbrella matches Meraki for " + netname)
                else:
                    print("tunnel not built in Meraki config for " + netname)
                    # need to signal that config is in umbrella and not meraki
                    in_umb_not_meraki = True 

        # if tunnel is built in umbrella already but not Meraki we need to detect and update config
        if in_umb_not_meraki == True:

            # calling function to strip tag for network in umbrella config
            meraki_net_tag = strip_meraki_network_tags(nettag)

            # calling function to determine public vpn peer ip for Meraki config
            vpn_peer_ip = define_vpn_peer_ip(meraki_net_tag)

            # deleting umbrella tunnel config and set tunnel_already_made variable to False
            delete_umb_tun = delete_umbrella_tunnel(netname)
            print(delete_umb_tun)

        if tunnel_already_made == False:

            # calling function to create umbrella tunnel and return psk and fqdn
            umbrella_tunnel_information = create_umbrella_tunnel(umbrella_tunnel_data)

            # calling function to parse tags for SIG specific tag
            meraki_net_tag = strip_meraki_network_tags(nettag)

            # Build meraki config for IPsec configuration (using get_meraki_ipsec_config function)
            primary_vpn_tunnel_template = get_meraki_ipsec_config(netname,  \
            meraki_branch_peer_ip, umbrella_tunnel_information[1], meraki_net_tag, umbrella_tunnel_information[0])
            
            # creating variable to detect whether or not umbrella tunnel exists in Meraki config
            is_meraki_tunnel_updated = False

            for vpn_peer_name in merakivpns:
                # iterating through list of existing meraki vpn peers validating if tunnel is created
                if vpn_peer_name == merakivpns[0]['name']:
                    print("peer detected in the config already updating PSK")
                    is_meraki_tunnel_updated = True
                    # updating psk for meraki vpn tunnel to umbrella
                    print("updating psk for existing tunnel in Meraki to match Umbrella")
                    vpn_peer_name['secret'] = tunnelPSKSecret

            if is_meraki_tunnel_updated == False:
                # appending newly created tunnel config to original VPN list
                merakivpns.append(primary_vpn_tunnel_template)          

# final function performing update to Meraki VPN config
print(merakivpns)
update_meraki_vpn(merakivpns)
