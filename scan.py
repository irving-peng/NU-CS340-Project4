import argparse
import json

# Function to process the input file and save to JSON
def process_domains(input_file, output_file):
    # Read the file and process each line
    with open(input_file, 'r') as file:
        lines = file.readlines()
    
    # Create a dictionary with domains as keys
    domains_dict = {line.strip(): None for line in lines if line.strip()}
    
    # Write the dictionary to a JSON file
    with open(output_file, 'w') as json_file:
        json.dump(domains_dict, json_file, indent=4)

    print(f"JSON file '{output_file}' has been created.")

# Main entry point
if __name__ == '__main__':
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Convert a list of domains from a text file to a JSON file.')
    parser.add_argument('input_file', type=str, help='Path to the input text file containing domains')
    parser.add_argument('output_file', type=str, help='Path to the output JSON file')
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Process the files
    process_domains(args.input_file, args.output_file)
