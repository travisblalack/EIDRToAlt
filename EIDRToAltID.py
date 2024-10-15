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
global verbose
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
def get_eidr_xml(eidr_id):
    API_URL = f'https://resolve.eidr.org/EIDR/object/resolve/{eidr_id}?type=AlternateID'
    
    try:
        # Make the HTTP request
        response = requests.get(API_URL)
        
        if response.status_code == 200:
            # Parse the response into XML
            xml_data = response.content

            # Pretty print the XML data using minidom
            xml_parsed = minidom.parseString(xml_data)
            pretty_xml = xml_parsed.toprettyxml(indent="  ")
            
            # Return the pretty XML
            return pretty_xml
        else:
            raise Exception(f"Failed to retrieve data: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error: {e}")
        return None

# Add debugging before the request
def get_query_body(query, eidr_login, eidr_partyid, eidr_password, registry_key):
    global QueryPageOffset

    if not query:
        raise ValueError("Query is empty")

    req_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
              '<Request xmlns="http://www.eidr.org/schema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n' \
              '<Operation>\n' \
              '  <Query>\n' +  \
              f'     <Expression>({query})</Expression>\n ' \
              f'     <PageNumber>{QueryPageOffset}</PageNumber> <PageSize>{requestPagesize}</PageSize>\n' \
              '  </Query>\n' \
              '</Operation>\n' \
              '</Request>'

    try:
        pwBytes = bytes(eidr_password, 'utf-8')
        hash = hashlib.sha256(pwBytes) if registry_key == 'sandbox2' else hashlib.md5(pwBytes)

        pwShadow = base64.b64encode(hash.digest())
        authStr = f'Eidr {eidr_login}:{eidr_partyid}:{str(pwShadow, encoding="utf-8")}'

        hdr = {'Content-Type': 'text/xml', 'Authorization': authStr, 'Accept': 'text/xml'}
        body = bytes(req_xml, 'utf-8')

        # Validate the URL
        if not registry_key:
            raise ValueError("Registry key is not provided")

        # Disable SSL verification for testing
        context = ssl._create_unverified_context()

        # Validate request data
        if not body:
            raise ValueError("Request body is None")
        
        #r = requests.Request(url, headers=hdr, data=body)
        #print("Request data sent successfully")  # Debugging
        QueryPageOffset += 1  # Advance page offset for next round

        # Make the actual request (you'll need to uncomment this line)
        # 9/17/24 changed to post to post the data was formerely get
        resp = requests.post(url, headers=hdr, data=body)
        #print(f"Response Status: {resp.status_code}")
        #print(f"Response Body: {resp.text}")

        #return resp.read()  # Return the response
    except Exception as e:
        print(f'Error in request: {e}', file=sys.stderr)
        raise

#May need to query registry
def query_registry_for_eidr_id(eidr_id):
    global EIDRTOALTID_LOGIN, EIDRTOALTID_PARTYID, EIDRTOALTID_PASSWORD, REGISTRY_KEY
    
    if not eidr_id:
        raise ValueError("EIDR ID is required")
    

    query = f"/FullMetadata/BaseObjectData/AlternateID[@type='ShortDOI']/@value='{eidr_id}'"

    try:
        response = get_query_body(query, EIDRTOALTID_LOGIN, EIDRTOALTID_PARTYID, EIDRTOALTID_PASSWORD, REGISTRY_KEY)
        if response.status_code != 200:
            raise Exception(f"Failed to query registry: {response.status_code} - {response.text}")
        
        # Parse the XML response
        response_text = response.text
        results = doc.getElementsByTagName('SimpleMetadata')
        
        if len(results) == 0:
            print("No results found for the given EIDR ID")
            return None

        # Process the XML response to extract relevant information
        metadata = {}
        for elem in results.item(0).getElementsByTagName('AlternateID'):
            alt_id_type = elem.getAttribute('type')
            alt_id_value = elem.firstChild.nodeValue
            metadata[alt_id_type] = alt_id_value
        
        return metadata
    
    except Exception as e:
        print(f"Error querying registry: {e}")
        return None
#used to write output to a file, not working as of 9/24/24


# This function is responsible for writing the output data to a file
def write_output_file(output_path, data):
    try:
        with open(output_path, 'a', encoding='utf-8') as f:  # 'a' for append mode
            f.write(f"EIDR ID: {data['ID']}\n")
            
            # Check if AlternateIDs exist and write them
            if 'AlternateIDs' in data and data['AlternateIDs']:
                for alt_id in data['AlternateIDs']:
                    # Get value and type, they should always be present
                    alt_value = alt_id.get('value', 'N/A')  # Default to 'N/A' if missing
                    alt_type = alt_id.get('type', 'N/A')  # Default to 'N/A' if missing
                    
                    # If the type is Proprietary, we must include the domain
                    if alt_type == 'Proprietary':
                        domain = alt_id.get('domain')  # No default here, it MUST exist
                        if not domain:
                            raise ValueError(f"Domain missing for Proprietary AlternateID: {alt_value}")
                        f.write(f"Alternate ID: {alt_value}, Type: {alt_type}, Domain: {domain}\n")
                    else:
                        # Write other non-Proprietary AlternateIDs
                        f.write(f"Alternate ID: {alt_value}, Type: {alt_type}\n")
            
            f.write("\n")  # Add a newline for separation between records
            
        print(f"Data successfully written to {output_path}")
    except Exception as e:
        print(f"Failed to write to {output_path}: {e}")



               
def setup_logging(logfile):
    """
    Set up logging configuration. Log to the specified file.
    """
    logging.basicConfig(
        filename=logfile,          # Log file specified by opLog
        filemode='a',              # Append to the log file
        level=logging.INFO,        # Log level (INFO)
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
locale.setlocale(locale.LC_ALL, '')

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

def fetch_xml(eidr_id):
    try:
        # Construct the EIDR URL using the provided ID
        url = f"https://resolve.eidr.org/EIDR/object/{eidr_id}?type=AlternateID"
        
        # Generate the authorization header
        auth_header = makeHeader()
        
        # Prepare headers with the authorization information
        headers = {
            'Authorization': auth_header
        }

        # Make a request to fetch the XML data
        response = requests.get(url, headers=headers)
        
        # Check if the request was successful
        if response.status_code == 200:
            # Parse the XML content
            xml_data = response.text
            root = ET.fromstring(xml_data)

            # Check if the request was valid by inspecting the Status/Code in the XML
            namespaces = {'ns': 'http://www.eidr.org/schema'}  # Define namespace for parsing
            status_code_elem = root.find('.//ns:Code', namespaces)
            status_text_elem = root.find('.//ns:Type', namespaces)
            
            # Check the response code in the XML
            if status_code_elem is not None and status_code_elem.text != "0":
                # If the code is not "0", it indicates an error
                print(f"Failed to fetch valid data for {eidr_id}, Status Code: {status_code_elem.text}, Error: {status_text_elem.text}")
                return None

            # If the code is "0", proceed with parsing
            print(f"Successfully fetched XML for {eidr_id}")
            
            # Parse and inspect the XML structure if needed
            print("Inspecting the XML structure:")
            
            return parse_alternate_ids(root)
        else:
            print(f"Failed to fetch XML for {eidr_id}, Status Code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching XML: {e}")
        return None
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None
    # Also log to the console
# displays help messages via a function.
def parse_alternate_ids(root):
    namespaces = {'ns': 'http://www.eidr.org/schema'}
    
    result = {}
    
    # First, handle the ID element
    id_elem = root.find('{http://www.eidr.org/schema}ID')
    if id_elem is not None:
        result['ID'] = id_elem.text
    
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
        
        # Add 'domain' if it exists, even for non-proprietary types
        alt_id_domain = alt_id.attrib.get('domain',' ')
        if alt_id_domain:
            alt_id_info['domain'] = alt_id_domain
        
        # Add 'relation' if it exists, otherwise add a default (N/A or blank space)
        alt_id_relation = alt_id.attrib.get('relation', ' ')  # Use blank space if no relation
        alt_id_info['relation'] = alt_id_relation
        
        # Append the constructed dictionary for this AlternateID
        result['AlternateIDs'].append(alt_id_info)
    
    return result


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
    global eidr_id, alt_id_domain, alt_id_type, alt_id_relation

    SDK_VERSION = '2.7.1'
    eidr_id = ' '
    alt_id_domain = ' '
    alt_id_type = ' '
    alt_id_relation = ' '
    REGISTRY_KEY = 'resolve'
    requestPagesize = 100

    # Create parser and set the custom formatter with adjustable spacing
    parser = argparse.ArgumentParser(formatter_class=CustomHelpFormatter, add_help=False)
    parser.add_argument('-h', '--help', action='help', help=get_help_message('help'))
    parser.add_argument('--version', action='store_true', help=get_help_message('version'))
    parser.add_argument('--showconfig', action='store_true', help=get_help_message('showconfig'))

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-dom', '--domain', required=False, help=get_help_message('domain'))
    group.add_argument('-t', '--type', required=False, help=get_help_message('type'))
    parser.add_argument('-id', '--eidr_id', type=str, help=get_help_message('eidr_id'))
    group.add_argument('-i', '--input', required=False, help=get_help_message('input'))
    parser.add_argument('-o', '--output', required=False, help=get_help_message('output'))

    parser.add_argument('-c', '--config', required=False, help=get_help_message('config'))
    parser.add_argument('-p', type=int, default=100, dest="pagesize", help=get_help_message('pagesize'))
    parser.add_argument('-v', '--verbose', action="store_true", default=False, dest="verbose", help=get_help_message('verbose'))
    parser.add_argument('--count', type=int, dest="maxCount", help=get_help_message('showcount'))
    parser.add_argument('-x', '--maxerrs', type=int, default=10, dest="maxErrors", help=get_help_message('maxErrors'))
    parser.add_argument('-l', '--logfile', default=None, dest="opLog", help=get_help_message('logfile'))

    args = parser.parse_args()

    if args.version:
        print(f"EIDR SDK Version: {SDK_VERSION}")
        sys.exit(1)

    if len(sys.argv) == 1:
        print("No arguments provided. Displaying help options.")
        parser.print_help()
        sys.exit(1)
    if args.eidr_id and not (args.type or args.domain):
        print("Error: When providing an EIDR ID, you must also provide either a type (--type) or a domain (--domain).")
        parser.print_help()
        sys.exit(1)

    try:
        if args.config:
            config = load_config_from_xml(args.config)
            if args.verbose:
                print(f"Loaded config from file: {args.config}")
            if config and args.showconfig:
                print("Config loaded from XML file:")
                print(f"URL: {config.get('URL')}")
                print(f"Party ID: {config.get('PartyID')}")
                print(f"Login: {config.get('Login')}")
                print(f"Page Size: {config.get('Pagesize', requestPagesize)}")
                return
        else:
            config = {
                "URL": f"https://resolve.eidr.org/EIDR", # changed to resolve as of 10/1/24
                "EIDR_PARTYID": EIDRTOALTID_PARTYID,
                "EIDR_LOGIN": EIDRTOALTID_LOGIN,
                "EIDR_PASSWORD": EIDRTOALTID_PASSWORD,
                "PAGESIZE": requestPagesize,
            }
            if args.showconfig:
                print("Default configuration:")
                print(f"URL: {config['URL']}")
                print(f"Party ID: {config['EIDR_PARTYID']}")
                print(f"Login: {config['EIDR_LOGIN']}")
                print(f"Page Size: {config['PAGESIZE']}")
                return
    except Exception as e:
        print(f"Failed to load configuration: {e}", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    if args.pagesize:
        print(f"Page size set to: {requestPagesize}")

    if args.showconfig and 'pagesize' in args:
        print("Configuration with custom page size:")
        print(f"Page size: {config['pagesize']}")
        print(f"URL: {config['URL']}")
        print(f"Party ID: {config['EIDR_PARTYID']}")
        print(f"Login: {config['EIDR_LOGIN']}")
        return

    # Fetch the XML for the given EIDR ID
    if args.eidr_id:
        eidr_id = args.eidr_id
        print(f"Processing EIDR ID: {eidr_id}")

        # Fetch the XML record using the fetch_xml function
        xml_record = fetch_xml(eidr_id)

        # Output the XML record or save it to a file if output is provided
        if xml_record:
            output_data = {
                "ID": eidr_id,
                "AlternateIDs": []
                
            }

            for alt_id in xml_record['AlternateIDs']:
                alt_type = alt_id.get('type', 'N/A')
                alt_id_relation = alt_id.get('relation', ' ')
                # If the type is "Proprietary", include both type and domain (mandatory)
                if alt_type == 'Proprietary':
                    
                    output_data["AlternateIDs"].append({
                        "value": alt_id.get('value', 'N/A'),
                        "type": alt_type,
                        "domain": alt_id.get('domain', 'N/A'),  # Mandatory domain for Proprietary type
                        "relation": alt_id_relation
                    })
                else:
                    # For other types, just include type and value
                    output_data["AlternateIDs"].append({
                        "value": alt_id.get('value', 'N/A'),
                        "type": alt_type,
                        "relation": alt_id_relation
                    })

            if args.output:
                file_mode = 'a' if os.path.exists(args.output) else 'w'
                with open(args.output, file_mode, encoding='utf-8') as output_file:
                # Convert the output data to JSON and write it
                    output_file.write(json.dumps(output_data, indent=4) + '\n')
                print(f"Output saved to {args.output}")
            else:
                print(f"XML Record for EIDR ID {eidr_id}:\n{xml_record}")
        else:
            print(f"No valid XML record found for EIDR ID {eidr_id}")
    elif args.input:
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                eidr_ids = f.read().splitlines()
            print(f"Loaded {len(eidr_ids)} EIDR IDs from input file.")
            
            for eidr_id in eidr_ids:
                print(f"Processing EIDR ID: {eidr_id}")
                xml_record = fetch_xml(eidr_id)

                if xml_record:
                    output_data = {
                    "ID": eidr_id,
                    "AlternateIDs": []
                }

                for alt_id in xml_record['AlternateIDs']:
                    alt_type = alt_id.get('type', ' ')
                    alt_id_relation = alt_id.get('relation', ' ')
                    if alt_type == 'Proprietary':
                        output_data["AlternateIDs"].append({
                            "value": alt_id.get('value', ' '),
                            "type": alt_type,
                            "domain": alt_id.get('domain', ' '),
                            "relation": alt_id_relation
                        })
                    else:
                        output_data["AlternateIDs"].append({
                            "value": alt_id.get('value', ' '),
                            "type": alt_type,
                            "relation": alt_id_relation
                        })
                print(f"XML Record for EIDR ID {eidr_id}:\n{xml_record}")
            
                
        except FileNotFoundError:
            print(f"Input file {args.input} not found.")
            parser.print_help()
            sys.exit(1)
    else:
        print("No EIDR ID or input file provided. Running default query.")


    if args.opLog:
        setup_logging(args.opLog)
        logging.info(f"Logging initialized. Log file: {args.opLog}")
        logging.info(f"Arguments after parsing: {vars(args)}")

    if args.maxErrors != 10:
        print(f"Max errors allowed: {args.maxErrors}")

    if args.maxCount:
        print(f"Count provided: Processing {args.maxCount} EIDR records.")

    # Create the query XML, including EIDR-ID only if provided

    # Fill ID list
    if args.eidr_id != '':
        IDList.append(args.eidr_id)

    # Fetch and write data
    write_output_file(args.output, output_data)

if __name__ == "__main__":
    main()