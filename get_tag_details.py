#!/usr/bin/env python

'''
Testing
'''

import requests
from pprint import pprint
import json
import os



try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Enter all authentication info
USER = os.environ.get("USERNAME")
PASSWORD = os.environ.get("PASSWORD")
HOST = "10.101.191.40"
TENANT_ID = "311"
TAG_ID = "33"


# Network Analytics Constants
XSRF_HEADER_NAME = 'X-XSRF-TOKEN'

# Set the URL for login
url = "https://" + HOST + "/token/v2/authenticate"

# Let's create the login request data
login_request_data = {
    "username": USER,
    "password": PASSWORD
}

# Initialize the Requests session
api_session = requests.Session()

# Perform the POST request to login
response = api_session.request("POST", url, verify=False, data=login_request_data)


# If the login was successful
if(response.status_code == 200):

    # Set XSRF token for future requests
    for cookie in response.cookies:
        if cookie.name == 'XSRF-TOKEN':
            api_session.headers.update({XSRF_HEADER_NAME: cookie.value})
            break

    # Get the details of a given tag (host group) from the SMC
    url = 'https://' + HOST + '/smc-configuration/rest/v1/tenants/' + TENANT_ID + '/tags/' + TAG_ID
    response = api_session.request("GET", url, verify=False)

    # If successfully able to get list of tags (host groups)
    if (response.status_code == 200):

        # Grab the tag details and check if the malicious IP is associated with this tag
        tag_details = json.loads(response.content)
        pprint(tag_details)

    # If unable to fetch details of a given tag (host group)
    else:
        print("An error has ocurred, while fetching tags (host groups), with the following code {}".format(response.status_code))

    uri = 'https://' + HOST + '/token'
    response = api_session.delete(uri, timeout=30, verify=False)
    api_session.headers.update({XSRF_HEADER_NAME: None})

# If the login was unsuccessful
else:
        print("An error has ocurred, while logging in, with the following code {}".format(response.status_code))


