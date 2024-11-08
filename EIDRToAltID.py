import sys
import base64
import argparse
import logging
import os
import xml.etree.ElementTree as ET
import hashlib
import uuid
import requests
import locale
from urllib import request          # For making HTTP requests
import ssl
import json
from xml.dom import minidom

global registryToUse
global requestPagesize
global debug
global file
global showCount
global opLog
global query
global IDList
global REGISTRY_KEY
global maxCount
global maxErrors

# API URL


# EIDRTOALTID credentials
REGISTRY_KEY = 'resolve'
EIDRTOALTID_LOGIN = '10.5238/tblalack'
EIDRTOALTID_PARTYID = '10.5237/FFDA-9947'
EIDRTOALTID_PASSWORD = 'tNy!LEX~jBxk'

API_URL = 'https://{REGISTRY_KEY}.eidr.org/EIDR/'

verbose = False                     # If TRUE, send progress messages to the console
debug = False                       # If TRUE, send diagnostic data to the console
showCount = True                    # If TRUE, show show counts of records processed / errors while running
requestPagesize = 100              # Number of records to retrieve per round
QueryPageOffset = 1                 # Page offset for repeated query rounds
opLog = 'EIDRToAlt.oplog'            # Operation log filename.   Set to '' to suppress
maxErrors = 0                       # If non-zero, abort after this many errors
maxCount = 0  


IDList = []                                                                             # List of EIDR IDs to process this round
DefaultQuery = '/FullMetadata/BaseObjectData/AlternateID@type "TYPE" EXISTS AND  /FullMetadata/BaseObjectData EXISTS' # Default for Type
DomainQuery = '/FullMetadata/BaseObjectData/AlternateID@domain ' # For the domain
globCnt = 0                     # Count of records processed
globErrCnt = 0                  # Count of errors encountered
tmpFileName = 'EIDRTOALTID_' + str(uuid.uuid4().hex) + '.xml'          # Temporary file name for gChange configuration


# List of valid Alt ID types
VALID_ID_TYPES = [
    "Ad-ID", "AFT", "AMG", "Baseline", "BFI", "cIDF",
    "CRID", "DOI", "EAN", "GRid", "GTIN", "IMDB", "ISAN",
    "ISRC", "ISTC", "IVA", "Lumire", "MUZE", "Proprietary",
    "ShortDOI", "SMPTE_UMID", "TRIB", "TVG", "UPC", "URI", "URN", "UUID",
]

class CustomHelpFormatter(argparse.HelpFormatter):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def _format_action(self, action):
        # Get the default formatted action
            action_str = super()._format_action(action)

        # Add horizontal spacing using a delimiter (number of spaces)
        # For example, using 5 spaces as the delimiter
            delimiter = ' ' * 25  # 5 spaces
            if action.help:
                action_str = action_str.replace(action.help, f'{delimiter}{action.help}')

            return action_str
#used to load values from a config file

def load_config_from_xml(file_path):
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Extract values from XML, using .findtext() to ensure None is returned if the element is missing
        config = {
            "URL": root.findtext('url'),
            "PartyID": root.findtext('party'),
            "Login": root.findtext('user'),
            "Password": root.findtext('password'),
            "Pagesize": root.findtext('pagesize'),
        }

        return config

# Add debugging before the request

# This function is responsible for writing the output data to a file

# added an open and close output file function with a global output file
def open_output_file(output_path):
    global output_file
    try:
        output_file = open(output_path, 'r', encoding='utf-8')
        if verbose:
            print(f"Output file {output_path} opened successfully.")
    except Exception as e:
        print(f"Error opening file: {e}")
        parser.print_help()
        sys.exit(1)

def write_output_file(output_file,data):
    if output_file is None:
        print("Error: Output file is not open.")
        return
    
    try:
        output_file.write(f"EIDR ID: {data['ID']}\n")
        
        # Check if AlternateIDs exist and write them
        if 'AlternateIDs' in data and data['AlternateIDs']:
            for alt_id in data['AlternateIDs']:
                # Get value and type, they should always be present
                alt_type = alt_id.get('type', 'N/A') 
                alt_value = alt_id.get('value', 'N/A')
                alt_id_relation = alt_id.get('relation', 'N/A')
                
                # If the type is Proprietary, we must include the domain
                if alt_type == 'Proprietary':
                    domain = alt_id.get('domain')
                    if not domain:
                        raise ValueError(f"Domain missing for Proprietary AlternateID: {alt_value}")
                    output_file.write(f"Type: {alt_type}, Alternate ID: {alt_value}, Domain: {domain}, Relation: {alt_id_relation}\n")
                else:
                    # Write other non-Proprietary AlternateIDs
                    output_file.write(f"Type: {alt_type}, Alternate ID: {alt_value}, Relation: {alt_id_relation}\n")
        
        output_file.write("\n")  # Add a newline for separation between records
        print("Data successfully written.")
    except Exception as e:
        print(f"Error writing data: {e}")
    
def setup_logging(logfile=None):
    """
    Set up logging configuration. Log to the specified file or the console if no file is provided.
    """
    if not logfile:
            logfile = "default_logfile1.log"  # Default log file if no filename is provided
    logging.basicConfig(
        filename=logfile,
        filemode='a',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.info("Logging initialized.")

def makeHeader():
    try:
        # Generate the hashed password and base64-encoded value
        pwBytes = bytes(EIDRTOALTID_PASSWORD, 'utf-8')
        hash = hashlib.sha256(pwBytes)  # Change to MD5 as per request
        pwShadow = base64.b64encode(hash.digest())
        
        # Create the authorization string
        authStr = f'Eidr {EIDRTOALTID_LOGIN}:{EIDRTOALTID_PARTYID}:{pwShadow.decode("utf-8")}'
        return authStr
    except Exception as e:
        print('ERR! ' + str(e))
        raise
# Initialize the global AUTH_HEADER
AUTH_HEADER = {
    "Authorization": makeHeader(),
    "Content-Type": "application/json"
}
def fetch_xml(eidr_id, verbose=False):
    #Tests to see if the id inputted is a valid eidr id of length 34
    if len(eidr_id) != 34 or not eidr_id.startswith("10.5240/"):
       print(f"Invalid EIDR ID: {eidr_id}")
       return None
    
    # Construct the EIDR URL using the provided ID
    url = f"https://resolve.eidr.org/EIDR/object/{eidr_id}?type=AlternateID"
    print(f"Constructed URL: {url}")

    # Make a request to fetch the XML data with the global AUTH_HEADER
    response = requests.get(url, headers=AUTH_HEADER)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the XML content
        xml_data = response.text
        root = ET.fromstring(xml_data)
        
        # Parse and return alternate ID information
        alt_id = parse_alternate_ids(root, verbose)
        return alt_id
    else:
        print(f"Failed to fetch XML for {eidr_id}, Status Code: {response.status_code}, Response content: {response.text}")
        return None

def parse_alternate_ids(root, target_type, verbose=False):
    # This function writes to the output
    result = {}

    # Handle the ID element and add it to the result if it exists
    id_elem = root.find('{http://www.eidr.org/schema}ID')
    if id_elem is not None:
        eidr_id = id_elem.text
        # Check if the ID length is valid (should be 34 characters)
        if len(eidr_id) != 34 or not eidr_id.startswith("10.5240/"):
            print(f"Invalid EIDR ID: {eidr_id}")
            return result  # Return an empty result or handle as needed
        result['ID'] = eidr_id
    else:
        print("No ID element found")
        return result

    # Initialize a list to store alternate IDs
    result['AlternateIDs'] = []

    # Iterate over AlternateID elements
    for alt_id in root.findall('{http://www.eidr.org/schema}AlternateID'):
        alt_id_info = {}

        # Add the 'value', which is the text content of the element
        alt_id_info['value'] = alt_id.text

        # Add 'type' if it exists
        alt_id_type = alt_id.attrib.get('{http://www.w3.org/2001/XMLSchema-instance}type')
        if alt_id_type:
            alt_id_info['type'] = alt_id_type

        # Add 'domain' if it exists
        alt_id_domain = alt_id.attrib.get('domain')
        if alt_id_domain:
            alt_id_info['domain'] = alt_id_domain

        # Add 'relation' only if it exists
        alt_id_relation = alt_id.attrib.get('relation')
        if alt_id_relation:
            alt_id_info['relation'] = alt_id_relation

        # Check if this alternate ID matches the target type
        if alt_id_type == target_type:
            # Add the filtered AlternateID info to the result
            result['AlternateIDs'].append(alt_id_info)

            # Display information depending on the presence of 'domain'
            domain_text = f", Domain: {alt_id_info['domain']}" if 'domain' in alt_id_info else ""
            relation_text = f", Relation: {alt_id_info['relation']}" if 'relation' in alt_id_info else ""
            print(f"Processing Alternate ID: {alt_id_info['value']} with type {alt_id_info['type']}{domain_text}{relation_text}")

    # If no alternate IDs match the target type, return an empty list
    if not result['AlternateIDs']:
        print(f"No alternate IDs found for type '{target_type}'")

    return result

import os
import json

def process_alternate_ids(xml_record, domain_filter=None, verbose=False):
    output_data = {
        "ID": xml_record.get('ID'),
        "AlternateIDs": []
    }

    output_lines = []  # For the string output
    count = 0  # Initialize the count

    for alt_id in xml_record.get('AlternateIDs', []):
        alt_type = alt_id.get('type', 'N/A')
        alt_value = alt_id.get('value', 'N/A')
        domain = alt_id.get('domain', 'N/A')
        alt_relation = alt_id.get('relation')  # None if no relation is present
        
        # If a domain filter is specified, skip alternate IDs that don't match the filter
        if domain_filter and domain_filter not in domain:
            continue
        
        # Set type to "Proprietary" if domain filter is provided and matches
        if domain_filter:
            alt_type = "Proprietary"

        # Build the formatted ID for JSON-like output
        formatted_id = {
            "type": alt_type,
            "value": alt_value,
        }

        # Add the domain only if the type is Proprietary
        if alt_type == "Proprietary":
            formatted_id["domain"] = domain

        # Add the relation only if it exists
        if alt_relation:
            formatted_id["relation"] = alt_relation

        # Append the formatted ID to the JSON-like output
        output_data["AlternateIDs"].append(formatted_id)
        count += 1  # Increment count

        # Build the string output
        string_format = f"Type: {alt_type}, Value: {alt_value}"

        # If the type is Proprietary, add the domain
        if alt_type == "Proprietary":
            string_format += f", Domain: {domain}"

        # Append relation to string output if it exists
        if alt_relation:
            string_format += f", Relation: {alt_relation}"

        # Append the formatted ID to the string output lines
        output_lines.append(string_format)

        # If verbose mode is enabled, print each alternate ID as it is processed
        if verbose:
            print(string_format)

    # Print the number of alternate IDs processed in the terminal (not in the output)
    print(f"Number of Alternate IDs processed: {count}")

    # Return output_data and output_lines
    return output_data, output_lines
def process_eidr_ids_from_file(eidr_ids, args, verbose):
    """Process EIDR IDs from an input file using the same logic as a single EIDR ID."""
    all_output_data = []

    for eidr_id in eidr_ids:
        if verbose:
            print(f"Processing EIDR ID: {eidr_id}")
        
        # Determine whether we are processing by type or domain
        if args.type:
            alt_id_type = args.type
            if verbose:
                print(f"Processing EIDR ID: {eidr_id} with type: {alt_id_type}")
            xml_record = fetch_xml(eidr_id, alt_id_type)
        elif args.domain:
            alt_id_domain = args.domain
            if verbose:
                print(f"Processing EIDR ID: {eidr_id} with domain: {alt_id_domain}")
            xml_record = fetch_xml(eidr_id, "Proprietary")
        else:
            print("Error: Please provide either --type or --domain.")
            #parser.print_help()
            sys.exit(1)

        if xml_record:
            # Process the alternate IDs for this EIDR ID
            processed_data = process_alternate_ids(xml_record, domain_filter=args.domain, verbose=verbose)
            
            if processed_data:
                all_output_data.append(processed_data)
            else:
                print(f"No alternate IDs found for EIDR ID {eidr_id}")
        else:
            print(f"No valid XML record found for EIDR ID {eidr_id}")

    # Write or print the collected data for all IDs
    write_output(args.output, all_output_data)
def get_help_message(keyword):
    messages = {
        'help': 'Show this help message and exit',
        'version': 'Print current Tool/SDK version',
        'showconfig': 'Shows current connection credentials',
        'eidr_id': 'Lets a user query a single EIDR ID',
        'domain': 'AltIDs must be in DOMAIN (exclusive with --type)',
        'type': 'AltIDs must be in TYPE (exclusive with --domain)',
        'output': 'Path to the output file',
        'config': 'Path to the XML configuration file',
        'pagesize': 'Number of records to retrieve per round',
        'verbose': 'Display progress and status reporting',
        'showcount': 'Show counts of records processed',
        'maxCount': 'Number of threads to use',
        'maxErrors': 'Maximum number of errors to tolerate before aborting',
        'file': 'File from which to load IDs',
        'query': 'XPath query to select IDs',
        'input': 'Path to the input file containing EIDR IDs',
        'logfile': 'Log file for operation history'
    }
    return messages.get(keyword, "No help message available")

def main():
    global EIDRTOALTID_LOGIN, EIDRTOALTID_PARTYID, EIDRTOALTID_PASSWORD, REGISTRY_KEY, requestPagesize, IDList
    global eidr_id, alt_id_domain, alt_id_type,verbose,output_file

    SDK_VERSION = '2.7.1'
    REGISTRY_KEY = 'resolve'
    requestPagesize = 100
    IDList = []

    VALID_ID_TYPES = [
    "Ad-ID", "AFT", "AMG", "Baseline", "BFI", "cIDF", "CRID", "DOI", "EAN",
    "GRid", "GTIN", "IMDB", "ISAN", "ISRC", "ISTC", "IVA", "Lumire", "MUZE",
    "ShortDOI", "SMPTE_UMID", "TRIB", "TVG", "UPC", "URI", "URN", "UUID",
]

    # Create parser and set the custom formatter with adjustable spacing
    parser = argparse.ArgumentParser(formatter_class=CustomHelpFormatter, add_help=False)
    #processes on their own
    #action: The basic type of action to be taken when this argument is encountered at the command line.
    #help - A brief description of what the argument does.
    #required - Whether or not the command-line option may be omitted (optionals only).
    #dest - The name of the attribute to be added to the object returned by parse_args().
    #type - The type to which the command-line argument should be converted.
    parser.add_argument('-h', '--help', action='help', help=get_help_message('help'))
    parser.add_argument('-v', '--verbose', action="store_true", default=False, dest="verbose", help=get_help_message('verbose'))
    parser.add_argument('--version', action='store_true', help=get_help_message('version'))
    parser.add_argument('-c', '--config', required=False, help=get_help_message('config'))
    parser.add_argument('--showconfig', action='store_true', help=get_help_message('showconfig'))
    parser.add_argument('-p', type=int, default=100, dest="pagesize", help=get_help_message('pagesize'))
    #store true merely means True or False just like a boolean flag (not sure if should be include4d on own)
    parser.add_argument('-id', '--eidr_id', type=str, help=get_help_message('eidr_id'))
    parser.add_argument('-o', '--output', required=False, help=get_help_message('output'))
    parser.add_argument('--count', type=int, dest="maxCount", help=get_help_message('showcount'))
    parser.add_argument('-x', '--maxerrs', type=int, default=10, dest="maxErrors", help=get_help_message('maxErrors'))
    parser.add_argument('-l', '--logfile', nargs="?", const='default_logfile.log', help=get_help_message('logfile'))
    # initialize the opLog parameter if it's used or not clean up by next meeting
    parser.add_argument('-i', '--input', required=False, help=get_help_message('input'))
    group = parser.add_argument_group()
    group.add_argument('-dom', '--domain', required=False, help=get_help_message('domain'))
    group.add_argument('-t', '--type', required=False, help=get_help_message('type'))
    args = parser.parse_args()
    #sys argv holds command line arguments
    #Only the script name is present, meaning no additional arguments were provided.
    # needs to be at least one because if the length was zero, it wouldn't exist
    if len(sys.argv) == 1:
        print("No arguments provided. Displaying help options.")
        parser.print_help()
        sys.exit(1)
    verbose = args.verbose
    # The help and verbose parameters don't need to be initialized
    if args.version:
        print(f"EIDR SDK Version: {SDK_VERSION}")
        sys.exit(1)

    # Load configuration
    try:
        if args.config:
            config = load_config_from_xml(args.config)
            if verbose:
                print(f"Loaded config from file: {args.config}")
        else:
            config = {
                "URL": f"https://resolve.eidr.org/EIDR",
                "EIDR_PARTYID": EIDRTOALTID_PARTYID,
                "EIDR_LOGIN": EIDRTOALTID_LOGIN,
                "EIDR_PASSWORD": EIDRTOALTID_PASSWORD,
                "PAGESIZE": requestPagesize,
            }
    except Exception as e:
        print(f"Failed to load configuration: {e}", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    if  args.showconfig:
        print("Config loaded from XML file:")
        print(f"URL: {config.get('URL')}")
        print(f"Party ID: {config.get('PartyID')}")
        print(f"Login: {config.get('Login')}")
        print(f"Page Size: {config.get('Pagesize', requestPagesize)}")
    
    if args.pagesize < 1 or args.pagesize > 100000:
        print("Error: Page size must be between 1 and 100000.")
        sys.exit(1)
    else:
        requestPagesize = args.pagesize

    if not (args.type or args.domain):
        
        print("Error: You must also provide either a type (-t) or a domain (-dom).")
        parser.print_help()
        sys.exit(1)
    
    if  args.type and args.domain:
        print("Error: You cannot provide a type and domain.")
        parser.print_help()
        sys.exit(1)


    if args.input and args.eidr_id:
        print("Error: You cannot provide an id and input file.")
        parser.print_help()
        sys.exit(1)

    if args.input:
        if not os.path.isfile(args.input):
            print(f"Error: Input file {args.input} does not exist.")
            parser.print_help()
            sys.exit(1)

        elif os.path.getsize(args.input) == 0:
            print(f"Error: Input file {args.input} is empty.")
            
            parser.print_help()
            sys.exit(1)

        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                eidr_ids = f.read().splitlines()
            if verbose:
                print(f"Loaded {len(eidr_ids)} EIDR IDs from input file.")
            process_eidr_ids_from_file(eidr_ids, args, verbose)

            for eidr_id in eidr_ids:
                print(eidr_id)
                # if not (args.type or args.domain):
                #     print("Error: You must provide either a type (-t) or a domain (-dom) when processing an input file.")
                #     parser.print_help()
                #     sys.exit(1)
        except:
            #need error when trying to read file
            sys.exit(1)
    if args.type:
        if args.type in VALID_ID_TYPES:
            alt_id_type = args.type
        else:
            print(f"Error: Invalid type '{args.type}'. Valid types are: {', '.join(VALID_ID_TYPES)}")
            parser.print_help()
            sys.exit(1)
    else:
        if args.domain.find(".") >= 2 and len(args.domain) >= 5:
            alt_id_domain = args.domain
        else:
            print(f"Error: Invalid domain '{args.domain}'.")
            parser.print_help()
            sys.exit(1)

    #is not none checks for zero otherwise the valid numbers are 1-100000
    if args.maxCount:
        if args.maxCount < 1 or args.maxCount > 100000:
            print("Error: maxCount must be between 1 and 100000.")
            parser.print_help()
            sys.exit(1)
        else:
            if verbose:
                print(f"Processing up to {args.maxCount} EIDR records.")
    if args.maxErrors:
        if args.maxErrors < 1 or args.maxErrors > 100:
            print("Error: Max errors must be between 1 and 100.")
            parser.print_help()
            sys.exit(1)
        else:
            if verbose:
                print(f"Processing up to {args.maxErrors} EIDR errors.")
    if args.logfile:
        setup_logging(args.logfile)
        if verbose:
            print(f"Logging to: {args.logfile}")
    else:
         if args.logfile:
            logging.info(f"Arguments after parsing: {vars(args)}")
    # if it's between 1-100 do nothing but if greater than 100 print max errors allowed
    # sys.exit(1)
    # Process input EIDR ID or file
    if args.eidr_id:
        eidr_id = args.eidr_id
        if args.type:
            alt_id_type = args.type
            if verbose:
                print(f"Processing EIDR ID: {eidr_id} with type: {alt_id_type}")
            xml_record = fetch_xml(eidr_id, alt_id_type)
        elif args.domain:
            alt_id_domain = args.domain
            if verbose:
                print(f"Processing EIDR ID: {eidr_id} with domain: {alt_id_domain}")
            xml_record = fetch_xml(eidr_id, "Proprietary")
        else:
            print("Error: Please provide either --type or --domain.")
            parser.print_help()
            sys.exit(1)
        if xml_record:
            output_data = process_alternate_ids(xml_record, domain_filter=args.domain,verbose=False)
            if args.output:
                write_output(args.output, output_data)
            else:
                if verbose:
                    print(f"XML Record for EIDR ID {eidr_id}:\n{xml_record}")
                else:
                    print(f"Successfully found record for EIDR ID {eidr_id}")
        else:
            print(f"No valid XML record found for EIDR ID {eidr_id}")


            for eidr_id in eidr_ids:
                xml_record = fetch_xml(eidr_id,args.domain)
                if xml_record:
                    output_data = {'ID': eidr_id, 'AlternateIDs': xml_record.get('AlternateIDs', [])}
                    
                    if args.output:
                        file_mode = 'r' if os.path.exists(args.output) else 'w'
                        with open(args.output, file_mode, encoding='utf-8') as output_file:
                            output_file.write(json.dumps(output_data, indent=4) + '\n')
                    else:
                        print(f"XML Record for EIDR ID {eidr_id}:\n{xml_record}:\n{json.dumps(output_data, indent=4)}")
                if FileNotFoundError:
                    print(f"Input file {args.input} not found.")
                    sys.exit(1)
    else:
        print("No EIDR ID or input file provided.")


def write_output(output_file, data):
    """Writes the output data to a specified file, or to the console if no file is provided."""
    output = json.dumps(data, indent=4)
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output + '\n')
        print(f"Output saved to {output_file}")
    else:
        print("Output:\n", output)
    
if __name__ == "__main__":
    main()