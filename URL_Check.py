import requests
#ensure to pip install whois
import whois
#set environment variables within .bashrc on debian based linux
import os
from datetime import datetime
import simplejson

"""
This code will display any alerts from virus total and urlvoid
along with how long the domain has been registered and who it
is registered to ex. godaddy or google domains.
"""

VIRUSTOTAL_API_KEY = os.environ.get("virustotal_API_key")
URLVOID_API_KEY = os.environ.get("urlvoid_API_key")
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
URLVOID_URL = 'https://endpoint.apivoid.com/urlinfo/'

def calculate_registration_duration(creation_date):
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    current_date = datetime.now()
    delta = current_date - creation_date
    years = delta.days // 365
    months = (delta.days % 365) // 30
    return f"{years} years/{months} months"

def get_registrar_info(whois_info):
    registrar = whois_info.get('registrar')
    if registrar:
        return f"Registrar: {registrar}"

def check_url(url):
    if not VIRUSTOTAL_API_KEY:
        print("Please provide a valid VirusTotal API key.")
        return

    # Check against VirusTotal
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    response_vt = requests.get(VIRUSTOTAL_URL, params=params).json()

    # Output the results for VirusTotal
    print("Results:")
    if response_vt['response_code'] == 1:
        print("\nVirusTotal: No issues found.\n")
    else:
        print("VirusTotal: Issues found.")
        print("Reputation checking sites that flagged this domain:")
        for scan in response_vt['scans']:
            if response_vt['scans'][scan]['detected']:
                print(f"{scan}: {response_vt['scans'][scan]['result']}")

    # Check against URLVoid
    try:
        response_uv = requests.get(f"{URLVOID_URL}/{url}/")

        # Check for non-JSON response
        if response_uv.text.startswith("<"):
            print("Non-JSON response from URLVoid API. Handling it separately.")
            # Handle the non-JSON response here, or you can choose to ignore it.
        else:
            response_uv_json = response_uv.json()
            print("\nResults from URLVoid:")
            if 'data' in response_uv_json:
                if 'blacklists' in response_uv_json['data']:
                    print("URLVoid: Issues found.")
                    print("Reputation checking sites that flagged this domain:")
                    for blacklist in response_uv_json['data']['blacklists']:
                        print(f"{blacklist['name']}: {blacklist['result']}")
                else:
                    print("URLVoid: No issues found.")
            else:
                print("URLVoid: Unexpected response format. Check the raw response.")

    except simplejson.JSONDecodeError:
        print("JSONDecodeError: Unable to decode JSON response from URLVoid API.")
        # Handle the JSONDecodeError here.

    # WHOIS information
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if creation_date:
            registration_duration = calculate_registration_duration(creation_date)
            print(f"\nWHOIS: Domain registration duration: {registration_duration}\n")
            
            # Get and print registrar information
            registrar_info = get_registrar_info(domain_info)
            if registrar_info:
                print(registrar_info)

    except whois.parser.PywhoisError as e:
        print(f"\nWHOIS: Unable to retrieve WHOIS information - {e}")

if __name__ == "__main__":
    user_url = input("Enter the URL to check: ").strip()
    check_url(user_url)
