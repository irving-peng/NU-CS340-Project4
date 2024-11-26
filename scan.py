import argparse
import json
import time

# Function to process the input file and save to JSON
def process_domains(input_file, output_file):
    # Read the file and process each line
    with open(input_file, 'r') as file:
        lines = file.readlines()
    
    # Create a dictionary with domains as keys
    domains_dict = {}
    for domain in lines:
        domains_dict[domain] = {
            "scan_time": time.time(),
            # Belows are all placeholder values for now
            "ipv4_addresses": ["192.0.2.1", "198.51.100.1"],  
            "ipv6_addresses": ["2001:db8::1"],  
            "http_server": "example-server",  
            "insecure_http": True,
            "redirect_to_https":False,
            "htts": False,
            "tls_versions": ["TLSv1.2", "TLSv1.1", "TLSv1.0"],
            "root_ca": "Digital Signature Trust Co.",
            "rdns_names": ["ord37s03 -in-f110.1e100.net", "ord37s03 -in-f14.1e100. net",
                        "ord30s25 -in-f14.1e100.net", 
                        "ord30s25 -in-f206.1e100.net", 
                        "ord37s07 -in-f14.1e100.net", 
                        "ord37s07 -in-f46.1e100.net"],
            "rtt_range":[4,20],
            "geo_locations": ["Evanston, Illinois, United States", "New York,New York, United States"],
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
