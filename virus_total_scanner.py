import requests
import configparser

# Read the configuration file
config = configparser.ConfigParser()
config.read('config.ini')

# Get the VirusTotal API key from the config file
VIRUSTOTAL_API_KEY = config['settings']['api_key']

# VirusTotal API base URL
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"

# Headers for VirusTotal API requests
headers = {
    "x-apikey": VIRUSTOTAL_API_KEY
}

def scan_iocs(iocs):
    """
    Scans a list of IOCs (domains, IPs, hashes) using the VirusTotal API.
    Returns the results as a dictionary.
    """
    results = {}
    for ioc in iocs:
        # Checking if the IOC is a domain, IP, or hash
        if is_domain(ioc):
            results[ioc] = scan_domain(ioc)
        elif is_ip(ioc):
            results[ioc] = scan_ip(ioc)
        else:
            results[ioc] = scan_hash(ioc)
    return results

def is_domain(ioc):
    return '.' in ioc

def is_ip(ioc):
    return ioc.replace('.', '').isdigit()  # Basic check for IPs

def scan_domain(domain):
    """Scans a domain using VirusTotal."""
    url = f"{VIRUSTOTAL_API_URL}/domains/{domain}"
    response = requests.get(url, headers=headers)
    return response.json()

def scan_ip(ip):
    """Scans an IP address using VirusTotal."""
    url = f"{VIRUSTOTAL_API_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=headers)
    return response.json()

def scan_hash(file_hash):
    """Scans a file hash using VirusTotal."""
    url = f"{VIRUSTOTAL_API_URL}/files/{file_hash}"
    response = requests.get(url, headers=headers)
    return response.json()
