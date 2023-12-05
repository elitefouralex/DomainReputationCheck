"""
Authored by Alex Oliveira made freely available under the
GNU General Public License v3
https://github.com/elitefouralex
"""
import requests
import whois
import os
from datetime import datetime

"""
For the developers' and authors' protection, the GPL clearly explains
that there is no warranty for this free software.  For both users' and
authors' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions. -per the GNU GPLv3
"""

VIRUSTOTAL_API_KEY = os.environ.get("virustotal_API_key")
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

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
        return f"{registrar}"

def check_url(url):
    if not VIRUSTOTAL_API_KEY:
        print("Please provide a valid VirusTotal API key.")
        return

    # Check against VirusTotal
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    response_vt = requests.get(VIRUSTOTAL_URL, params=params).json()

    # Output the results for VirusTotal
    print("*Results*")
    if response_vt['response_code'] == 1:
        print("\nVirusTotal: No issues found.\n")
    else:
        print("VirusTotal: Issues found.")
        print("Reputation checking sites that flagged this domain:")
        for scan in response_vt.get('scans', {}):
            if response_vt['scans'][scan]['detected']:
                print(f"{scan}: {response_vt['scans'][scan]['result']}")

    # WHOIS information
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if creation_date:
            registration_duration = calculate_registration_duration(creation_date)

            # Get registrar information
            registrar_info = get_registrar_info(domain_info)
            if registrar_info:
                print(f"\nWHOIS: Registered with {registrar_info} {registration_duration} ago.\n")

    except whois.parser.PywhoisError as e:
        print(f"\nWHOIS: Unable to retrieve WHOIS information - {e}")

if __name__ == "__main__":
    user_url = input("Enter the URL to check: ").strip()
    check_url(user_url)
