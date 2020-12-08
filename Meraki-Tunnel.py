import requests, json, time
import meraki
import re
import ast
import base64
from math import radians, cos, sin, asin, sqrt
import geonamescache
import pycountry_convert as pc
import os

# Author: Mitchell Gulledge


# class that contains all Meraki necessary config
class MerakiConfig:
    def __init__(self, api_key=None, org_name=None, tag_prefix='SIG-'):
        self.api_key = api_key
        self.org_name = org_name
        self.tag_prefix = tag_prefix
        self.org_id = None
        self.error = True

        if self.api_key and self.org_name:
            self.sdk_auth = meraki.DashboardAPI(api_key, suppress_logging=True)

            # writing function to obtain org ID via linking ORG name
            result_org_id = self.sdk_auth.organizations.getOrganizations()
            for x in result_org_id:
                if x['name'] == self.org_name:
                    self.org_id = x['id']
                    print(str(self.org_name) + " maps to " + str(self.org_id))

            # creating original list of Meraki VPNs to later append to
            self.meraki_vpn_list = []

            # obtaining original list of Meraki third party VPNs
            original_vpn = self.sdk_auth.appliance.getOrganizationApplianceVpnThirdPartyVPNPeers(self.org_id)
            print("response from Meraki SDK for obtaining original org wide peer settings: " + str(original_vpn))

            meraki_vpn_list = original_vpn['peers']

            # Meraki call to obtain Network information
            self.tags_network = self.sdk_auth.organizations.getOrganizationNetworks(self.org_id)
            print("sdk response for original list of Meraki networks in " + str(self.org_name) + " list below")
            print("Network list " + str(self.tags_network))

            # filtering None types from the list using filter
            self.res_tags_network = list(filter(None, self.tags_network))
            print("Filtering None data types from Network list: " + str(self.res_tags_network))
            self.error = False


# class that contains all Umbrella necessary config
class UmbrellaConfig:
    def __init__(self, key=None, secret=None, org_id=None):
        # this is obtained from the api keys tab and specifically the umbrella management keys
        self.key = key
        self.secret = secret
        self.org_id = org_id
        self.error = True

        if self.key and self.secret and self.org_id:
            # Command -  echo -n 'secret:key' | base64 in terminal
            base64_value = self.key + ':' + self.secret
            message_bytes = base64_value.encode('ascii')
            base64_bytes = base64.b64encode(message_bytes)
            base64_message = base64_bytes.decode('ascii')

            # url for network tunnels in umbrella dashboard
            self.tunnel_url = "https://management.api.umbrella.com/v1/organizations/"+self.org_id+"/tunnels"

            # url for listing umbrella DCs
            self.dc_url = 'https://management.api.umbrella.com/v1/service/tunnel/datacenters'

            # delete umbrella tunnel url
            self.delUrl = 'https://management.api.umbrella.com/v1/organizations/'+self.org_id+'/tunnels/'

            # creating header to authenticate API requests to Umbrella
            self.headers = {'Authorization': 'Basic ' + base64_message}
            self.error = False


# function to parse list of tags for an individual network
def strip_meraki_network_tags(meraki_network_tag):
    print("Raw list of network tags on network: " + str(meraki_network_tag))

    # below parses the for the specific network tag on the network that correlates with SIG-
    meraki_tag_strip_part1 = re.findall(r'[S]+[I]+[G]+[-].*', str(meraki_network_tag))
    meraki_tag_strip_part2 = re.findall(r'^([\S]+)', str(meraki_tag_strip_part1[0]))
    new_string = str(meraki_tag_strip_part2[0])
    new_string = new_string[0:-2]
    print("Parsing the specific tag beginning with SIG-: " + str(new_string))
    return new_string


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


# this function performs the haversine formula to calculate distance between two endpoints
# the variables being fed in are the long/lat of the Umbrella DC and MX site IP
def haversine(lon1, lat1, lon2, lat2):
    """
    Calculate the great circle distance between two points 
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians 
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])

    # haversine formula 
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    r = 6371    # Radius of earth in kilometers. Use 3956 for miles
    return c * r


# this function is intended to replace define_vpn_peer_ip function
def get_dc_ip(network_id, meraki_config, umbrella_config):
    # variables for the longitude/latitude for both sites
    lon1 = ''
    lat1 = ''
    lon2 = ''
    lat2 = ''
    site_continent = ''

    # creating variable to that contains branch IP of MX
    mx_branch_ip = ''

    # obtaining branch MXs public IP w/ org wide network devices call
    print("Obtaining list of Meraki device statuses")
    list_of_device_statuses = meraki_config.sdk_auth.organizations.getOrganizationDevicesStatuses(
        meraki_config.org_id)

    if str(network_id) in str(list_of_device_statuses):
        print("Successfully obtained list of Device statuses")
    else:
        print("Unable to obtain list of Meraki Network Device statuses")

    for device in list_of_device_statuses:
        # conditional statement to match based on network id variable
        if network_id == device['networkId']:
            # setting public ip for branch to later calculate long/lat
            mx_branch_ip = device['publicIp']
            print("public IP of Branch is: " + str(mx_branch_ip))
            # calculating long/lat of mx branch ip address
            geo_url = "https://ipinfo.io/" + mx_branch_ip 
            geo_response2 = requests.get(geo_url).json()
            print(geo_response2)
            
            print(f"Longitude/Lat for Branch is : {geo_response2['loc']}")

            x = geo_response2['loc']
            long_lat_tuple = tuple(x.split(','))

            lon1 = long_lat_tuple[0]
            lat1 = long_lat_tuple[1]

            print("branch longitude is " + str(lon1))
            print("branch latitude is " + str(lat1))

            # obtaining country name to later map to a continent
            branch_country = geo_response2['country']

            # creating continent variable so we can later iterate through smaller list of umbrella DCs
            continent_name = pc.country_alpha2_to_continent_code(branch_country)
            print("The branch site has been mapped to continent " + continent_name)

            # mapping continent code to continent name
            if continent_name == 'NA':
                site_continent = 'North America'
            elif continent_name == 'SA':
                site_continent = 'South America'
            elif continent_name == 'AS':
                site_continent = 'Asia'
            elif continent_name == 'OC':
                site_continent = 'Australia'
            elif continent_name == 'AF':
                site_continent = 'Africa'

    # variable for umbrella public IP
    primary_vpn_tunnel_ip = '' 

    # distance variable that will be used to select closest DC
    distance_to_dc = 999999

    # request to obtain list of DCs
    get_dc_req = requests.get(umbrella_config.dc_url, headers=umbrella_config.headers)
    print("Obtaining a list of all Umbrella Datacenters: " + str(get_dc_req.content))

    # creating list to hold all regional DCs 
    list_of_regional_dcs = []

    # iterating through list of DCs to match based on continent name
    for dc in get_dc_req.json()['continents']:
        if str(site_continent) in str(dc['name']):

            # appending DC to list of DCs in the same continent
            list_of_regional_dcs.append(dc)

    print("List of regional DCs: " + str(list_of_regional_dcs))

    # if response is successful begin building variables to feed into haversine formula
    if get_dc_req.status_code == 200:
        for datacenters in list_of_regional_dcs:
            print("matched site to corressponding continent for DC selection")
        
            for umb_datacenter in datacenters['cities']:
                if not umb_datacenter['range'].split('/')[0][-1] == '8':
                    continue
                print(umb_datacenter)
                # umbrella dc latitude
                lat2 = umb_datacenter['latitude']
                print("Latitude of potential Umbrella DC: " + str(lat2))

                # umbrella dc latitude
                lon2 = umb_datacenter['longitude']
                print("Longitude of potential Umbrella DC: " + str(lon2))

                # executing Haversine Formula
                haversince_result = haversine(float(lon1), float(lat1),
                                              float(lon2), float(lat2))
                print("Haversine result for branch to potential Umbrella DC: " + str(haversince_result))

                # setting haversine result to the absolute value
                haversince_result = abs(haversince_result)

                # when iterating through list if haversince_result is less than distance_to_dc
                # rewrite the distance_to_dc variable to the haversince_result
                if haversince_result < distance_to_dc:
                    distance_to_dc = haversince_result
                    print("Haversine Result (distance to DC) is: " + str(distance_to_dc))
                    primary_vpn_tunnel_ip = umb_datacenter['range']
                    primary_vpn_tunnel_ip = str(primary_vpn_tunnel_ip)[0:-3]
                    print("IP address for DC described above: " + str(primary_vpn_tunnel_ip))

        return primary_vpn_tunnel_ip


def delete_umbrella_tunnel(vpn_tunnel_name, umbrella_config):
    # fetching list of umbrella tunnel config
    get_req = requests.get(umbrella_config.tunnel_url, headers=umbrella_config.headers)
    umbrella_tunnel_info = get_req.json()
    print("Get request to Umbrella for current Network Tunnels: " + str(umbrella_tunnel_info))

    for tunnel in umbrella_tunnel_info:
        # matching against tunnel name as conditional statement
        if vpn_tunnel_name == tunnel["name"]:
            
            print("Meraki Network name detected in Umbrella Tunnel Configuration for: " + str(tunnel["name"]))

            # parsing umbrella tunnel config for id
            umb_tunnel_id = tunnel["id"]

            print("Tunnel ID for existing tunnel to be deleted: " + str(umb_tunnel_id))

            # crafting tunnel specific url to delete ipsec config in umbrella dashboard
            del_tunnel_url = str(umbrella_config.delUrl) + str(umb_tunnel_id)
            
            # deleting Umbrella tunnel
            delReq = requests.delete(del_tunnel_url, headers=umbrella_config.headers)
            print("deleting tunnel " + str(tunnel["name"]) + " reason code on deleting tunnel " + str(delReq.reason))

            if delReq.reason == 200:
                # if tunnel deleted successfully, swapping tunnel already made variable back to false
                tunnel_already_made_in_umb = False

                print("Successfully deleted: " + str(tunnel["name"]) +
                      " setting tunnel_already_made_in_umb variable to " + str(tunnel_already_made_in_umb))
                print("Now there should be no VPN config in Umbrella or Meraki for " + str(tunnel["name"]))


# function to update Meraki VPN config
def update_meraki_vpn(vpn_list, meraki_config):
    updatemvpn = meraki_config.sdk_auth.appliance.updateOrganizationApplianceVpnThirdPartyVPNPeers(
                 meraki_config.org_id, vpn_list
    )
    print("Updating Meraki Organization VPN Config : " + str(updatemvpn))


# function to validate that MX is on version 15 or greater
def validate_mx_firmware(branch_node, meraki_config):
    # call to get device info
    devices = meraki_config.sdk_auth.networks.getNetworkDevices(branch_node)
    print("MX Branch device information: " + str(devices))

    # validating firmware to ensure device is on 15
    firmwareversion = devices[0]['firmware'] 
    print("MX Appliance Firmware version: " + str(firmwareversion))

    # validation to say True False if MX appliance is on 15 firmware
    firmwarecompliance = str(firmwareversion).startswith("wired-15") 
    if firmwarecompliance:
        print("firmware is compliant")
    else:
        print("firmware is not compliant breaking loop")
        firmwarecompliance = False

    return firmwarecompliance


# this function creates an umbrella IPsec tunnel and return FQDN and Secret
def create_umbrella_tunnel(tunnel_name, umbrella_config):
    # Post to create tunnel in SIG dashboard
    tunnel_response = requests.post(umbrella_config.tunnel_url, headers=umbrella_config.headers,
                                    data=tunnel_name)
    print("Creating SIG tunnel with name: " + str(tunnel_name))

    umbrella_tunnel_info = tunnel_response.json()
    print("Response from Post to create Umbrella Tunnel: " + str(umbrella_tunnel_info))

    # parsing tunnel info for tunnel psk and id
    # Access tunnel ID
    tunnel_id = umbrella_tunnel_info["id"]
    print("the Tunnel ID for " + str(tunnel_name) + " is " + str(tunnel_id))

    # Access PSK id:key
    client = umbrella_tunnel_info["client"]

    # parsing the local id/fqdn for the meraki vpn config here
    tunnelPSKFqdn = client["authentication"]["parameters"]["id"] 
    print("the Tunnel FQD for " + str(tunnel_name) + " is " + str(tunnelPSKFqdn))

    # parsing the pre shared key for the meraki vpn config here
    tunnelPSKSecret = client["authentication"]["parameters"]["secret"] 
    
    return tunnelPSKFqdn, tunnelPSKSecret


def run(meraki_config, umbrella_config):
    # loop that iterates through the variable tagsnetwork and matches networks with SIG- in the tag
    for meraki_networks in meraki_config.res_tags_network:
        if meraki_config.tag_prefix in str(meraki_networks['tags']):

            print(str(meraki_config.tag_prefix) + " has been detected in the list of Networks")

            # obtaining network ID in order to obtain device information
            network_info = meraki_networks['id']
            print("Network ID for the matched MX network is: " + str(network_info))

            # network name used to label Meraki VPN and Umbrella ipsec config
            netname = meraki_networks['name']
            print("Network name for matched network is " + str(netname))

            # obtaining all tags for network as this will be placed in VPN config
            nettag = meraki_networks['tags']
            print("List of all tags for matched network is " + str(nettag))

            # calling function to validate branch firmware version
            print("executing validate_mx_firmware for network appliance: " + str(netname))
            firmware_validate = validate_mx_firmware(network_info, meraki_config)

            if firmware_validate == False:
                # if the firmware validation returns as false the script will break from the loop
                break

            # executing function to obtain the vpn peer ip for the meraki branch device
            print("executing function get_dc_ip to obtain Umbrella VPN peer address for Meraki VPN configuration")
            meraki_branch_peer_ip = get_dc_ip(network_info, meraki_config, umbrella_config)
            print("Post function output of Umbrella VPN peer address " + str(meraki_branch_peer_ip))

            # creating umbrella ipsec config to be the data in the post, netname variable is tunnel name
            umbrella_tunnel_name = {"name": netname, 'deviceType': 'Meraki MX'}
            umbrella_tunnel_data = json.dumps(umbrella_tunnel_name)
            print("Umbrella VPN config containing Meraki branch name and device type: " + str(umbrella_tunnel_data))

            # fetching list of umbrella tunnel config
            get_req = requests.get(umbrella_config.tunnel_url, headers=umbrella_config.headers)

            # converting get_req (list of umbrella vpn tunnels) from json response to dictionary
            umbrella_tunnel_dict = get_req.json()
            print("Request output for Umbrella Tunnels: " + str(umbrella_tunnel_dict))

            # creating placeholder variable for detecting whether the tunnel is created or not in umbrella
            tunnel_already_made_in_umb = False
            print("current placeholder for tunnel_already_made_in_umb and is set to: ")

            # placeholder variable for detecting whether the tunnel is created in umbrella and meraki
            in_umb_and_meraki_config = False
            print("Value in_umb_and_meraki_config variable determing if config is in both dashboards: "
                  + str(in_umb_and_meraki_config))

            # now we can iterate through the loop and see if netname is contained within the get_req variable
            print("iterating through list of umbrella tunnels to match based on umb tunnel/ Meraki network name")
            for tunnel_name in umbrella_tunnel_dict:
                if netname == tunnel_name['name']:
                    tunnel_already_made_in_umb = True
                    print("tunnel detected in Umbrella config for: " + str(tunnel_name['name']))
                else:
                    print("tunnel not detected in Umbrella config")

            print("Displaying current value for tunnel_already_made_in_umb: " + str(tunnel_already_made_in_umb))

            # if tunnel is built in umbrella already but not Meraki we need to detect and update config
            if tunnel_already_made_in_umb:
                # iterating through original list of vpn tunnels from Meraki to match on name
                print("iterating through Meraki VPN list: " + str(meraki_config.meraki_vpn_list) +
                      " to detect tunnel built in umbrella called: " + str(netname))
                for meraki_tunnel_name in meraki_config.meraki_vpn_list:
                    # we can match based on netname since we determined netname was already in the tunnel config
                    if netname == meraki_tunnel_name['name']:
                        print("tunnel config in umbrella matches Meraki for " + netname)
                        # changing variable for being detected in umbrella and meraki config
                        in_umb_and_meraki_config = True
                        print("Tunnel detected in both dashboards, new value for in_umb_and_meraki_config "
                              + str(in_umb_and_meraki_config))
                    else:
                        print("tunnel not built in Meraki config for " + netname)

            print("Current value for in_umb_and_meraki_config: " + str(in_umb_and_meraki_config))

            # if tunnel is built in umbrella already but not Meraki we need to detect and update config
            if not in_umb_and_meraki_config:
                # calling function to strip tag for network in umbrella config
                print("calling strip_meraki_network_tags function to strip tags for network: " + str(netname))
                meraki_net_tag = strip_meraki_network_tags(nettag)

                # calling function to determine public vpn peer ip for Meraki config
                print("since in_umb_and_meraki_config is False, we need to calculate umb VPN peer IP for"
                      + str(netname))
                vpn_peer_ip = get_dc_ip(network_info, meraki_config, umbrella_config)

                # deleting umbrella tunnel config and set tunnel_already_made_in_umb variable to False
                print("Deleting Umbrella Tunnel for " + str(netname) +
                      " resetting tunnel_already_made_in_umb variable w/ delete_umbrella_tunnel function")

                delete_umb_tun = delete_umbrella_tunnel(netname, umbrella_config)

                print("result from calling delete_umbrella_tunnel function: " + str(delete_umb_tun))

            if not tunnel_already_made_in_umb:
                print("tunnel_already_made_in_umb variable is being detected as: " + str(tunnel_already_made_in_umb))

                # calling function to create umbrella tunnel and return psk and fqdn
                print("executing function create_umbrella_tunnel for " + str(netname))
                umbrella_tunnel_information = create_umbrella_tunnel(umbrella_tunnel_data, umbrella_config)

                # calling function to parse tags for SIG specific tag
                print("Calling strip_meraki_network_tags function to detect SIG- tag w/ unique identifier")
                meraki_net_tag = strip_meraki_network_tags(nettag)

                # Build meraki config for IPsec configuration (using get_meraki_ipsec_config function)
                print("Building IPsec tunnel config for Meraki using the function get_meraki_ipsec_config")
                primary_vpn_tunnel_template = get_meraki_ipsec_config(netname, meraki_branch_peer_ip,
                                                                      umbrella_tunnel_information[1], meraki_net_tag,
                                                                      umbrella_tunnel_information[0])

                print("new Meraki IPsec tunnel config for " + str(netname) + " : " +
                      str(primary_vpn_tunnel_template))

                # creating variable to detect whether or not umbrella tunnel exists in Meraki config
                is_meraki_tunnel_updated = False
                print("variable is_meraki_tunnel_updated created for detecting if umbrella tunnel \
                      is in Meraki VPN config: " + str(is_meraki_tunnel_updated))

                print("iterating through list of existing VPN peers for Meraki: " +
                      str(meraki_config.meraki_vpn_list))
                for vpn_peer_name in meraki_config.meraki_vpn_list:
                    # iterating through list of existing meraki vpn peers validating if tunnel is created
                    if vpn_peer_name == str(meraki_config.meraki_vpn_list):
                        print("peer detected in the config already updating PSK")
                        is_meraki_tunnel_updated = True
                        print("since tunnel detected in existing config flipping variable \
                              is_meraki_tunnel_updated to: " + str(is_meraki_tunnel_updated))

                        # updating psk for meraki vpn tunnel to umbrella
                        print("updating psk for existing tunnel in Meraki to match Umbrella")
                        vpn_peer_name['secret'] = umbrella_config.tunnelPSKSecret

                if not is_meraki_tunnel_updated:
                    print("Listing is_meraki_tunnel_updated variable value: " +
                          str(is_meraki_tunnel_updated))
                    # appending newly created tunnel config to original VPN list
                    meraki_config.meraki_vpn_list.append(primary_vpn_tunnel_template)
                    print("is_meraki_tunnel_updated variable is False meaning we need to append: "
                        + str(primary_vpn_tunnel_template) + " to the Meraki VPN list")

    # final function performing update to Meraki VPN config
    print("Final Meraki Org VPN List: " + str(meraki_config.meraki_vpn_list))
    update_meraki_vpn(meraki_config.meraki_vpn_list, meraki_config)


if __name__ == "__main__":
    meraki_api_key = os.environ.get("MERAKI_API_KEY")
    meraki_org_name = os.environ.get("MERAKI_ORG_NAME")
    mc = MerakiConfig(api_key=meraki_api_key, org_name=meraki_org_name)
    umbrella_api_key = os.environ.get("UMBRELLA_API_KEY")
    umbrella_api_secret = os.environ.get("UMBRELLA_API_SECRET")
    umbrella_org_id = os.environ.get("UMBRELLA_ORG_ID")
    umb = UmbrellaConfig(key=umbrella_api_key, secret=umbrella_api_secret, org_id=umbrella_org_id)
    if mc.error or umb.error:
        print("Error loading Meraki or Umbrella configuration")
        exit()

    run(mc, umb)
