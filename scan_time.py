import argparse
import json
import time
import subprocess
import requests
import urllib3
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_http(domain):
    try:
        link = f"https://{domain}"
        response = requests.get(link, timeout = 5, verify=False)

        header = response.headers.get("Server")
        if header:
            return header
        else:
            return None
        
    except requests.exceptions.RequestException as e:
        print(f"Error getting header for {domain} -- {e}")
        return None
    
def insecure_http(domain):
    try:
        with socket.create_connection((domain, 80), timeout = 5):
            print(f"Insecure HTTP detected for {domain}")
            return True
    except socket.error:
        return False

def get_hts(domain):
    try:
        link = f"http://{domain}"
        response = requests.get(link, timeout = 5, verify=False, allow_redirects = True)

        if 'Strict-Transport-Security' in response.headers:
            return True
        else:
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"Error with HSTS for {domain} -- {e}")
        return False
    
def redirect_http(domain):
    try:
        link = f"http://{domain}"
        response = requests.get(link, timeout = 5, verify=False, allow_redirects = True)

        if response.url.startswith("https://"):
            print(f"HTTP redirect for {domain}")
            return True
        else:
            print(f"No HTTPS redirection for {domain}")
            return False
    except requests.exceptions.RequestsWarning as e:
        print(f"Error with redirect {domain} -- {e}")
        return False

def validate_resolvers(resolvers):
    valid = []
    for resolver in resolvers:
        try: 
            subprocess.check_output(["nslookup", "example.com", resolver,], stderr = subprocess.STDOUT, timeout= 2)
            valid.append(resolver)
            
        except Exception as e:
            print(f"Resolver is not valid {resolver}")
    return valid

def get_ipv4_address(domain, resolvers):
    address = set()
    for resolver in resolvers:
        try:
            result = subprocess.check_output(["nslookup", domain, resolver,], stderr = subprocess.STDOUT, timeout= 2).decode("utf-8")
            for line in result.splitlines():
                if "Address:" in line:
                    if "." in line:
                        ip = line.split("Address:")[-1].strip()
                        address.add(ip)
        except subprocess.TimeoutExpired:
            print(f"TimeOut for domain {resolver}")
        except Exception as e:
            print(f"Error querying {domain} with resolver {resolver}: {e}")
    
    return list(address)



def get_ipv6_address(domain, resolvers):
    address = set()
    for resolver in resolvers:
        try:
            result = subprocess.check_output(["nslookup", domain, resolver,], stderr = subprocess.STDOUT, timeout= 2).decode("utf-8")
            for line in result.splitlines():
                if "Address:" in line:
                    if ":" in line:
                        ip = line.split("Address:")[-1].strip()
                        address.add(ip)
        except subprocess.TimeoutExpired:
            print(f"Time out for getting ip6 {domain} with {resolver}")
        except Exception as e:
            print(f"Error querting {domain} with {resolver}")

    return list(address)

def load_resolvers_from_file():
    try:
        resolver_file = "public_dns_resolvers.txt"
        with open(resolver_file, 'r') as file:
            resolvers = []
            for line in file:
                strip_line = line.strip()
                if strip_line and not strip_line.startswith('#'):
                    resolver = strip_line.split('#')[0].strip()
                    resolvers.append(resolver)

        return resolvers
    except FileNotFoundError:
        print("Error with getting file")
        return []

# Function to process the input file and save to JSON
def process_domains(input_file, output_file):
    resolvers = load_resolvers_from_file()
    if not resolvers:
        print("No resolvers")
        return 
    print("validating resolvers")
    resolvers = validate_resolvers(resolvers)
    if not resolvers:
        print("No valid resolver found")
        return
    # Read the file and process each line
    with open(input_file, 'r') as file:
        lines = file.readlines()
    
    # Create a dictionary with domains as keys
    domains_dict = {}
    for domain in lines:
        domain = domain.strip()
        if not domain:
            continue
        start_time = time.time()

        ipv4_address = get_ipv4_address(domain, resolvers)
        ipv6_address = get_ipv6_address(domain, resolvers)
        http = get_http(domain)
        insecure = insecure_http(domain)
        redirect_https = redirect_http(domain)
        hts = get_hts(domain)

        domains_dict[domain] = {"scan_time" : start_time,
                                "ipv4_addresses": ipv4_address,
                                "ipv6_addresses": ipv6_address,
                                "http_server": http,
                                "insecure_http": insecure,
                                "redirect_to_https": redirect_https,
                                "hsts": hts,
                                
                                }
    
    # Write the dictionary to a JSON file
    with open(output_file, 'w') as json_file:
        json.dump(domains_dict, json_file, indent=4)

    print(f"JSON file '{output_file}' has been created.")

# Main entry point
if __name__ == '__main__':
    # Set up argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', type=str)
    parser.add_argument('output_file', type=str)
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Process the files
    process_domains(args.input_file, args.output_file)
