# Cisco Umbrella Hackathon Wining Solution

![Test Image 1](umbraki.png)

# Overview

This toolkit enables Meraki and Umbrella customers to streamline always on connectivity from a Cisco Meraki Branch site to Cisco Umbrella SIG. Extending secure and automated connectivity to the Umbrella Cloud Security Service. 

# Architecture

![Test Image 1](topology.png)


# Deployment Steps 

1) Obtain Cisco Meraki API Key and Org Name

    a) The API Key and Org Name will be needed for the script to configure your Meraki device. 

    b) To view your Organization name navigate to Organization > Settings, the name will be displayed at the top. (As seen below)
    
    ![Test Image 1](org_overview.png)
    
    c) For access to the API, first enable the API for your organization. 

    d) Navigate to Organization > Settings > Dashboard API access 

    e) Enable the API 
    
    ![Test Image 1](enable_meraki_api.png)
    
    f) Navigate to the my profile page and generate an API key 
    
    ![Test Image 1](generate_meraki_api.png)

      Note: The API key is associated with a Dashboard administrator account.   
      
2) Obtain Umbrella Management API Key and Secret 

    a) Download the Mgmt API keys from Umbrella Dashboard. 

    b) Login to Umbrella Dashboard, chose the Org

    c) Navigate to Admin->API Keys menu on Left hand side. 

    d) Once there click on ‘Umbrella Management’. You may need to refresh the keys to get a new set. 

    e) If you don’t find ‘Umbrella Management’ then click on ‘Create’ to create one.
    
      Note: You may follow the directions - https://docs.umbrella.com/umbrella-api/reference#rateauthentication-and-key-management-for-the-umbrella-api
      
3) Download Meraki-Tunnel.py file and set environment variables for the Meraki API key and Org name along with the Umbrella Org ID and Mangagement API information. 

```
export MERAKI_API_KEY=your_meraki_api_key_here
export MERAKI_ORG_NAME="Your Meraki Org Name"
export UMBRELLA_API_KEY=your_umbrella_api_key_here
export UMBRELLA_API_SECRET=your_umbrella_api_secret_here
export UMBRELLA_ORG_ID=your_umbrella_organization_id_here
```
      
Note: The toolkit also contains a firmware validation checker. One of the requirements for the solution is that the branch MX must be on firmware 15 or greater. This is due to the fact that connectivity to Umbrella SIG requires IKEv2 which is only supported in version 15 firmware. Checks have been placed in the script to ensure sites are on the appropriate firmware.

# Deploying to Azure 

To deploy the Azure Function, click on the deploy to Azure buttons below:

[![Deploy to Azure](https://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMitchellGulledge%2FUmbrakiServerless%2Fmain%2Fazuredeploy.json)

When logged in to the Azure Portal, fill out the required parameters and click Review + Create. 

Note: The Function App Name should not contain any special characters other than “-“.  The function app also needs to be unique globally within Azure, so please use a name that is unique to your organization. 

Tip: More information on each of the required parameters can be found by hovering over the  icon in the Azure Portal. 

Example Configuration 

![Test Image 1](func_app.png)

For Azure deployment code please refer to: https://github.com/MitchellGulledge/UmbrakiServerless


# Cisco Meraki Workflow 

Initially, there will be no tagged Meraki networks so the script will sleep and perform the same GET to obtain any networks with the relevant tag. In order to deploy a new branch, the user would navigate to Organization > Overview and select the checkbox next to the network that you wish to connect. 

![Test Image 1](tag_network.png)

Once the network is tagged appropriately, connectivity is then automatically established. A customer VPN tunnel in the Umbrella dashboard is created with a matching network name to that of the Meraki branch. Site1 will be named Site1 in both the Umbrella and Meraki dashboards. Additionally, a site to site VPN will appear on the site to site VPN page. (As seen below)

![Test Image 1](Meraki_vpn_config.png)

The script picks the closest datacenter based on the the closest geographic distance from the public IP. This does not solve the use case for SD WAN, however SD WAN to Umbrella is in the Meraki/Umbrella roadmap. 

Note: The script also assumes VPN is already turned on for the specific MX. For the tunnel to come up, interesting traffic needs to be generated.

Once interesting traffic has been generated, the tunnel will appear up in both the Meraki and Umbrella Dashboards:

![Test Image 1](meraki_status.png)

![Test Image 1](Umbrella_tunnel_status.png)

Additionally, in the Meraki Event Log, a event with a timestamp is generated when the tunnel becomes established:

![Test Image 1](event_log.png)

To troubleshoot what policy you are hitting, use this debugger link:

http://policy-debug.checkumbrella.com/

# Additional References 

https://documentation.meraki.com/zGeneral_Administration/Organizations_and_Networks/Organization_Menu/Manage_Tags 

https://documentation.meraki.com/zGeneral_Administration/Support/Contacting_Support
