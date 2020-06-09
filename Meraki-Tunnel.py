from ipwhois import IPWhois
import requests
import json
import time
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
from IPy import IP

netname2 = 'SIGbranch-sec' # temp cariable for now

# Meraki credentials are placed below
meraki_config = {
	'api_key': "",
	'orgName': "Cloud Test Org"
}

# writing function to obtain org ID via linking ORG name
mdashboard = meraki.DashboardAPI(meraki_config['api_key'])
result_org_id = mdashboard.organizations.getOrganizations()
for x in result_org_id:
    if x['name'] == meraki_config['orgName']:
        meraki_config['org_id'] = x['id']

# Generate random password for site to site VPN config
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

# loop that iterates through the variable tagsnetwork and matches networks with vWAN in the tag
for i in tagsnetwork:
    if i['tags'] is None or i['name'] == 'Tag-Placeholder':
        pass
    elif "SIG-" in i['tags']:
        network_info = i['id'] # need network ID in order to obtain device/serial information
        netname = i['name'] # network name used to label Meraki VPN and Azure config
        nettag = i['tags']  # obtaining all tags for network as this will be placed in VPN config
        va = mdashboard.networks.getNetworkSiteToSiteVpn(network_info) # gets branch local vpn subnets
        testextract = ([x['localSubnet'] for x in va['subnets']
						if x['useVpn'] == True])  # list comprehension to filter for subnets in vpn
        (testextract)
        privsub = str(testextract)[1:-1] # needed to parse brackets
        devices = mdashboard.devices.getNetworkDevices(network_info) # call to get device info
        xdevices = devices[0]
        # adding NAT detection for network device, need to complete

        meraki_local_uplink_ip = IP(xdevices['lanIp'])
        print(meraki_local_uplink_ip.iptype())
        if meraki_local_uplink_ip.iptype() == 'PRIVATE':
            print("nat detected")
            break

        up = xdevices['serial'] # serial number to later obtain the uplink information for the appliance
        firmwareversion = xdevices['firmware'] # now we obtained the firmware version, need to still add the validation portion
        firmwarecompliance = str(firmwareversion).startswith("wired-15") # validation to say True False if appliance is on 15 firmware
        if firmwarecompliance == True:
            print("firmware is compliant")
        else:
            break # if box isnt firmware compliant we break from the loop
        modelnumber = xdevices['model']

        uplinks = mdashboard.devices.getNetworkDeviceUplink(network_info, up) # obtains uplink information for branch

		# creating keys for dictionaries inside dictionaries
        uplinks_info = dict.fromkeys(['WAN1', 'WAN2', 'Cellular'])
        uplinks_info['WAN1'] = dict.fromkeys(
            ['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])
        uplinks_info['WAN2'] = dict.fromkeys(
            ['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])
        uplinks_info['Cellular'] = dict.fromkeys(
            ['interface', 'status', 'ip', 'provider', 'publicIp', 'model', 'connectionType'])

        for uplink in uplinks:
            if uplink['interface'] == 'WAN 1':
                for key in uplink.keys():
                    uplinks_info['WAN1'][key] = uplink[key]
            elif uplink['interface'] == 'WAN 2':
                for key in uplink.keys():
                    uplinks_info['WAN2'][key] = uplink[key]
            elif uplink['interface'] == 'Cellular':
                for key in uplink.keys():
                    uplinks_info['Cellular'][key] = uplink[key]

        # writing function to get ISP
        splist = []

        uplinksetting = mdashboard.uplink_settings.getNetworkUplinkSettings(network_info) # obtains meraki sd wan traffic shaping uplink settings
        secondaryuplinkindicator = 'False'
        for g in uplinks_info:
                # loops through the variable uplinks_info which reveals the value for each uplink key
                if (uplinks_info['WAN2']['status'] == "Active" or uplinks_info['WAN2']['status'] == "Ready") and (uplinks_info['WAN1']['status'] == "Active" or uplinks_info['WAN1']['status'] == "Ready"):
                    logging.info("both uplinks active")

                    pubs = uplinks_info['WAN1']['publicIp']
                    obj = IPWhois(pubs)
                    res=obj.lookup_whois()
                    localsp = res["nets"][0]['name']

                    pubssec = uplinks_info['WAN2']['publicIp']
                    secondaryuplinkindicator = 'True'
                    if(pubs == pubssec):
                        # This true section should be removed in favor of NAT-T detection at beginning of script
                        secip = "1.2.3.4"
                        secisp = localsp
                    else:
                        isp2obj = IPWhois(pubssec)
                        isp2res=obj.lookup_whois()
                        secisp = res["nets"][0]['name']

                    port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])/1000
                    wan2port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])/1000

                elif uplinks_info['WAN2']['status'] == "Active":
                    pubs = uplinks_info['WAN2']['publicIp']
                    port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])/1000
                    isp2obj = IPWhois(pubssec)
                    isp2res=obj.lookup_whois()
                    secisp = res["nets"][0]['name']

                elif uplinks_info['WAN1']['status'] == "Active":
                    pubs = uplinks_info['WAN1']['publicIp']
                    port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])/1000
                    obj = IPWhois(pubs)
                    res=obj.lookup_whois()
                    localsp = res["nets"][0]['name']

                else:
                    print("uplink info error")



# list for primary vpn public IP

primary_vpn_peer_ip = []

# updating preshared key for primary VPN tunnel

for vpnpeers in merakivpns[0]: # iterates through the list of VPNs from the original call
    if vpnpeers['name'] == netname: # matches against network name that is meraki network name variable
        if vpnpeers['secret'] != psk: # if statement for if password in VPN doesnt match psk variable
            vpnpeers['secret'] = psk # updates the pre shared key for the vpn dictionary

            # matching the IP address of primary vpn peer to add for connectivity monitoring later
            primary_vpn_peer_ip.append(vpnpeers['publicIp'])

print(primary_vpn_peer_ip)

# updating preshared key for backup VPN tunnel

for vpnpeers in merakivpns[0]: # iterates through the list of VPNs from the original call
    if vpnpeers['name'] == str(netname2) + '-sec': # matches against network name that is netname variable
        if vpnpeers['secret'] != psk: # if statement for if password in VPN doesnt match psk variable
            vpnpeers['secret'] = psk # updates the pre shared key for the vpn dictionary


# obtaining list of current connectivity monitoring destinations for the network

mx_destinations = mdashboard.connectivity_monitoring_destinations.getNetworkConnectivityMonitoringDestinations(str(network_info))
print(mx_destinations['destinations'][0]['ip'])

vpn_site_config = []

# now build dictionary template to then later append to the list

def newdestination(vpn_ipaddress):
        site_config = {"ip": vpn_ipaddress, "description": "primary vpn peer", "default": False}
        vpn_site_config.append(site_config)

newdestination(primary_vpn_peer_ip[0]) 

# need to detect if vpn peer IPs are already contained in the connectivity monitoring destinations

connectivity_monitor_updated = False

for vpn_peer_ip in mx_destinations['destinations']: #  iterating through connectivity monitoring list of destinations
    if vpn_peer_ip['ip'] == primary_vpn_peer_ip[0]:  #  matches vpn peer ip in merakivpns variable
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

print("above")


# updating connectivity monitoring destinations for tagged network

if connectivity_monitor_updated == False:
    payload = ast.literal_eval(original_destination_list)
    # if payload == {'a': 1, 'b': 'c'}, then sending **payload will result in function call with (…, a=‘1’, ‘b’=‘c’) as arguments
    update_mx_destinations = mdashboard.connectivity_monitoring_destinations.updateNetworkConnectivityMonitoringDestinations(str(network_info), **payload)

# creating sample list as skeleton for appending VPN peers list

vpn_site_peer = []

# now build dictionary template to then later append to the list if the tunnel is not configured

def add_newdestination(vpn_peer_public_ip, vpn_peer_connected_subnets, psk):
    new_vpn_peer_config = {"name":netname,"publicIp":vpn_peer_public_ip,"privateSubnets":vpn_peer_connected_subnets,"secret":psk, "ipsecPolicies":{"ikeCipherAlgo":["aes256"],"ikeAuthAlgo":["sha1"],"ikeDiffieHellmanGroup":["group2"],"ikeLifetime":28800,"childCipherAlgo":["aes256"],"childAuthAlgo":["sha1"],"childPfsGroup":["group2"],"childLifetime":3600},"networkTags":["east"]}        
    vpn_site_peer.append(new_vpn_peer_config)

for vpn_peers in merakivpns[0]: # iterates through the list of VPNs from the original call
    if vpnpeers['name'] != netname: # matches against network name that is meraki network name variable
        # then execute add_newdestinations function
        add_newdestination('1.1.1.1', "['1.1.1.1/32']", psk) # statically setting variables for now


