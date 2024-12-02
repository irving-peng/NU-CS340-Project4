import argparse
import json
import time
import subprocess
import requests
import urllib3
import socket
import maxminddb


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
        
    except requests.exceptions.ReadTimeout:
        print(f"Timeout for redirecting {domain}")
        return False
        
    except requests.exceptions.RequestException as e:
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

def get_tls_version(domain):
    tls_versions = {
        "SSLv2": "ssl2",
        "SSLv3": "ssl3",
        "TLSv1.0": "tls1",
        "TLSv1.1": "tls1_1",
        "TLSv1.2": "tls1_2",
        "TLSv1.3": "tls1_3"
    }
    all_versions = []

    for version, option in tls_versions.items():
        try:
            result = subprocess.check_output(["openssl", "s_client", f"-{option}", "-connect", f"{domain}:443"], stderr = subprocess.STDOUT, timeout= 2, input = b"").decode("utf-8")
            if "CONNECTED" in result:
                all_versions.append(version)
        except subprocess.CalledProcessError as e:
            print(f"{version} not support {domain} -- {e}")
        
        except subprocess.TimeoutExpired:
            print(f"Time out for verstion for {domain} with {version}")
        except FileNotFoundError:
            print("Error: openssl not found")
            break
        except Exception as e:
            print(f"Error testing {domain} with {version} -- {e}")


    return all_versions

def get_root_ca(domain):
    try:
        command = ["openssl", "s_client", "-connect", f"{domain}:443"]
        result = subprocess.check_output(command, input=b"\n", timeout=10, stderr=subprocess.STDOUT).decode("utf-8")
        root_ca = None
        for line in result.splitlines():
            if "O =" in line:
                parts = line.split(",")
                for part in parts:
                    if "O =" in part:
                        root_ca = part.split("O =")[1].strip()
                        break
                if root_ca:
                    break 
        return root_ca if root_ca else None
    except subprocess.TimeoutExpired:
        print(f"Timeout occurred while connecting to {domain}.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while processing {domain}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error for {domain}: {e}")
        return None
    
def get_rdns_names(ipv4_addresses):
    rdns_names = []
    for ip in ipv4_addresses:
        try:
            clean_ip = ip.split("#")[0].strip()
            # Perform reverse DNS lookup
            hostname, _, _ = socket.gethostbyaddr(clean_ip)
            rdns_names.append(hostname)
        except socket.herror:
            print(f"No reverse DNS found for IP {ip}")
        except Exception as e:
            print(f"Error performing reverse DNS lookup for IP {ip}: {e}")
    return rdns_names

def get_rtt_range(ipv4_addresses, port=443):
    rtt_times = []

    for ip in ipv4_addresses:
        try:
            start_time = time.time()
            with socket.create_connection((ip, port), timeout=5):
                pass  # Connection successful
            end_time = time.time()
            rtt = (end_time - start_time) * 1000  # Convert seconds to milliseconds
            rtt_times.append(rtt)
        
        except socket.error:
            print(f"Unable to reach {ip} on port {port}")
            continue
        except Exception as e:
            print(f"Unexpected error while measuring RTT for {ip}: {e}")
            continue

    if rtt_times:
        return [round(min(rtt_times)), round(max(rtt_times))]
    else:
        return None  # No IPs were reachable

def get_geo_locations(ipv4_addresses, db_path="GeoLite2-City.mmdb"):
    geo_locations = set()  # Use a set to ensure unique locations
    try:
        with maxminddb.open_database(db_path) as reader:
            for ip in ipv4_addresses:
                try:
                    response = reader.get(ip)
                    if response:
                        city = response.get("city", {}).get("names", {}).get("en", "Unknown")
                        subdivision = response.get("subdivisions", [{}])[0].get("names", {}).get("en", "Unknown")
                        country = response.get("country", {}).get("names", {}).get("en", "Unknown")
                        location = f"{city}, {subdivision}, {country}"
                        geo_locations.add(location)
                except Exception as e:
                    print(f"Error looking up geolocation for IP {ip}: {e}")
    except FileNotFoundError:
        print(f"MaxMind database not found at {db_path}")
        return []
    return list(geo_locations)

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
        tls_verions = get_tls_version(domain)
        root_ca = get_root_ca(domain)
        rdns_names = get_rdns_names(ipv4_address)
        rtt_range = get_rtt_range(ipv4_address)
        geo_locations = get_geo_locations(ipv4_address)

        domains_dict[domain] = {"scan_time" : start_time,
                                "ipv4_addresses": ipv4_address,
                                "ipv6_addresses": ipv6_address,
                                "http_server": http,
                                "insecure_http": insecure,
                                "redirect_to_https": redirect_https,
                                "hsts": hts,
                                "tls_versions": tls_verions,
                                "root_ca": root_ca,
                                "rdns_names":rdns_names,
                                "rtt_range": rtt_range,
                                "geo_locations": geo_locations
                                
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