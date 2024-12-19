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
import certifi
import urllib.request


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
QUERY_API_URL = 'https://{REGISTRY_KEY}.eidr.org/EIDR/query?type=id'

verbose = False                     # If TRUE, send progress messages to the console
debug = False                       # If TRUE, send diagnostic data to the console
showCount = True                    # If TRUE, show show counts of records processed / errors while running
requestPagesize = 100              # Number of records to retrieve per round
QueryPageOffset = 1                 # Page offset for repeated query rounds
opLog = 'EIDRToAlt.oplog'            # Operation log filename.   Set to '' to suppress
maxErrors = 0                       # If non-zero, abort after this many errors
maxCount = 0  


IDList = []                                                                             # List of EIDR IDs to process this round
DefaultQuery = '/FullMetadata/BaseObjectData/AlternateID@type "TYPE"'   # Default for Type
DomainQuery = '/FullMetadata/BaseObjectData/AlternateID@domain "DOMAIN"' # For the domain
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
        
        """
    A custom help formatter for argparse that adjusts the spacing for help messages.

    This class overrides the default formatting of argparse to add horizontal spacing
    between arguments and their help descriptions for better readability.

    Methods:
        _format_action(action):
            Formats the action string by adding horizontal spacing.
    """

        def __init__(self, *args, **kwargs):
            """
            Initializes the CustomHelpFormatter instance with any provided arguments.
            

            Args:
                *args: Positional arguments passed to argparse.HelpFormatter.
                **kwargs: Keyword arguments passed to argparse.HelpFormatter.
            """
            super().__init__(*args, **kwargs)

        def _format_action(self, action):
            """
        Formats an action by adding horizontal spacing to its help message.

        Args:
            action (argparse.Action): The argparse action being formatted.

        Returns:
            str: The formatted action string with additional spacing.
        """
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
        """
    Loads configuration values from an XML file.

    Parses the XML file to extract configuration settings such as URL, PartyID,
    Login, Password, and Pagesize. Missing elements are returned as None.

    Args:
        file_path (str): The path to the XML configuration file.

    Returns:
        dict: A dictionary containing the extracted configuration values.
            Keys: 'URL', 'PartyID', 'Login', 'Password', 'Pagesize'
            Values: Corresponding values or None if the element is missing.
    """
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
    """
    Opens an output file for writing.

    Sets a global `output_file` variable and opens the specified file in write mode.
    Displays a success message if verbose mode is enabled. Exits the program on failure.

    Args:
        output_path (str): The path to the output file.

    Raises:
        SystemExit: If the file cannot be opened.
    """
    global output_file
    try:
        output_file = open(output_path, 'r', encoding='utf-8')
        if verbose:
            print(f"Output file {output_path} opened successfully.")
    except Exception as e:
        print(f"Error opening file: {e}")
        sys.exit(1)

def write_output_file(output_file, data):
    """
    Writes data to the output file in a formatted structure.

    Writes the EIDR ID and its associated Alternate IDs to the output file.
    Handles validation and formatting for Proprietary IDs requiring a domain.

    Args:
        output_file (file): The file object to write data to.
        data (dict): A dictionary containing the EIDR ID and Alternate IDs.

    Raises:
        ValueError: If a Proprietary Alternate ID is missing a domain.
        Exception: If any error occurs during writing.
    """
    if output_file is None:
        print("Error: Output file is not open.")
        return
    
    try:
        output_file.write(f"EIDR ID: {data['ID']}\n")

        # Check if AlternateIDs exist and write them
        if 'AlternateIDs' in data and data['AlternateIDs']:
            for alt_id in data['AlternateIDs']:
                alt_type = alt_id.get('type', 'N/A')
                alt_value = alt_id.get('value', 'N/A')
                alt_id_relation = alt_id.get('relation', 'N/A')

                if alt_type == 'Proprietary':
                    domain = alt_id.get('domain')
                    if not domain:
                        raise ValueError(f"Domain missing for Proprietary AlternateID: {alt_value}")
                    output_file.write(f"Type: {alt_type}, Alternate ID: {alt_value}, Domain: {domain}, Relation: {alt_id_relation}\n")
                else:
                    output_file.write(f"Type: {alt_type}, Alternate ID: {alt_value}, Relation: {alt_id_relation}\n")

        output_file.write("\n")  # Add a newline for separation between records
        print("Data successfully written.")
    except Exception as e:
        print(f"Error writing data: {e}")

    
def setup_logging(logfile=None):
    """
    Configures logging for the script.

    Logs messages to the specified log file if provided, otherwise logs to a default file named "default_logfile.log".

    Parameters:
    logfile (str, optional): The path to the log file. Defaults to None.

    Returns:
    None
    """
    if not logfile:
            logfile = "default_logfile.log"  # Default log file if no filename is provided
    logging.basicConfig(
        filename=logfile,
        filemode='a',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.info("Logging initialized.")

def makeHeader():
    """
    Generates an authorization header for API requests.

    Constructs the header using the login credentials, hashed password, and Base64 encoding.

    Returns:
    str: The authorization header string.

    Raises:
    Exception: If an error occurs during header construction.
    """
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

counter = 0  # Global counter to keep track of processed EIDR IDs

def fetch_xml(eidr_id, verbose=False):
    """
    Fetches XML data for a given EIDR ID from the EIDR registry.

    Constructs the URL based on the EIDR ID and sends an HTTP GET request to retrieve the XML record.

    Parameters:
    eidr_id (str): The EIDR ID to fetch data for.
    verbose (bool, optional): Enables verbose logging of the URL and response status. Defaults to False.

    Returns:
    dict or None: Parsed alternate ID information if successful, or None if the request fails.
    """

    # Construct the EIDR URL using the provided ID
 
    global counter  # Use the global counter variable

    # Construct the EIDR URL using the provided ID
    url = f"https://{REGISTRY_KEY}.eidr.org/EIDR/object/{eidr_id}?type=AlternateID"
    if verbose:
        print(f"Constructed URL: {url}")

    # Make a request to fetch the XML data
    response = requests.get(url, headers=AUTH_HEADER)

    if response.status_code == 200:
        # Parse the XML content
        xml_data = response.text
        root = ET.fromstring(xml_data)
        result = parse_alternate_ids(root, verbose)

        # Increment the counter for each successful EIDR ID
        counter += 1
        return result
    else:
        print(f"Failed to fetch XML for {eidr_id}, Status Code: {response.status_code}, Response content: {response.text}")
        return None

def run_query_api(query='', verbose=False):
    """
    Executes a query against the EIDR API and returns results.
    """
    global QueryPageOffset, requestPagesize,debug


    url = f"https://{REGISTRY_KEY}.eidr.org/EIDR/query?type=id"  # Define the URL

    req_xml = '<?xml version="1.0" encoding="UTF-8"?>' \
              '<Request xmlns="http://www.eidr.org/schema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n' \
              '<Operation>\n' \
              '  <Query>\n' + \
              f'     <Expression>({query})</Expression>\n ' \
              f'     <PageNumber>{QueryPageOffset}</PageNumber> <PageSize>{requestPagesize}</PageSize>\n' \
              '  </Query>\n' \
              '</Operation>\n' \
              '</Request>'
    try:
        if query == '':
            return None

        pwBytes = bytes(EIDRTOALTID_PASSWORD, 'utf-8')
        if REGISTRY_KEY == 'resolve':
            hash = hashlib.sha256(pwBytes)
        else:
            hash = hashlib.md5(pwBytes)
        
        pwShadow = base64.b64encode(hash.digest())
        authStr = f'Eidr {EIDRTOALTID_LOGIN}:{EIDRTOALTID_PARTYID}:{str(pwShadow, encoding="utf-8")}'

        hdr = {
            'Content-Type': 'text/xml',
            'Authorization': authStr,
            'Accept': 'text/xml'
        }
        
        body = bytes(req_xml, 'utf-8')
        r = requests.post(url, headers=hdr, data=body, verify=certifi.where())

        if r.status_code != 200:
            print(f"Unexpected response: {r.status_code}")
            return None

        QueryPageOffset += 1  # Advance page offset for next round

        return r.text  # Return the response body to the caller

    except Exception as e:
        if debug:
            print(f'ERR! {e}')
        raise


#This processes a single ID
def parse_alternate_ids(root, target_type=None, target_domain=None, verbose=False):
    """
    Parses the AlternateID elements from the given XML root.

    Filters alternate IDs based on the target type and/or domain, and collects metadata such as type, value, domain, and relation.

    Parameters:
    root (xml.etree.ElementTree.Element): The root element of the XML record.
    target_type (str, optional): The type of alternate IDs to filter. Defaults to None.
    target_domain (str, optional): The domain of alternate IDs to filter. Defaults to None.
    verbose (bool, optional): Enables verbose logging of alternate ID processing. Defaults to False.

    Returns:
    dict: Contains the primary EIDR ID and a list of matching alternate IDs.
    """
    result = {}
    id_elem = root.find('{http://www.eidr.org/schema}ID')
    if id_elem is not None:
        eidr_id = id_elem.text
        if len(eidr_id) != 34 or not eidr_id.startswith("10.5240/"):
            print(f"Invalid EIDR ID: {eidr_id}")
            return result  # Return an empty result or handle as needed
        result['ID'] = eidr_id
    else:
        print("No ID element found")
        return result

    result['AlternateIDs'] = []

    for alt_id in root.findall('{http://www.eidr.org/schema}AlternateID'):
        alt_id_info = {
            'value': alt_id.text,
            'type': alt_id.attrib.get('{http://www.w3.org/2001/XMLSchema-instance}type', None),
            'domain': alt_id.attrib.get('domain', None),
            'relation': alt_id.attrib.get('relation', None),
        }

        # Debugging prints
        if verbose:
            tab_formatted = (
                f"{alt_id_info.get('value', '')}\t"
                f"{alt_id_info.get('type', '')}\t"
                f"{alt_id_info.get('domain', '')}\t"
                f"{alt_id_info.get('relation', '')}"
            )
            print(f"Checking Alternate ID:\t{tab_formatted}")
            print(f"Target Type:\t{target_type}\tTarget Domain:\t{target_domain}")

        # Apply filtering logic
        if target_type and alt_id_info['type'] != target_type:
            continue  # Skip if type doesn't match
        if target_domain and alt_id_info['domain'] != target_domain:
            continue  # Skip if domain doesn't match

        # Add the alternate ID to the results if it passes the filters
        result['AlternateIDs'].append(alt_id_info)

        # Verbose logging
        if verbose:
            tab_formatted = (
        f"{alt_id_info.get('value', '') or ''}\t"
        f"{alt_id_info.get('type', '') or ''}\t"
        f"{alt_id_info.get('domain', '') or ''}\t"
        f"{alt_id_info.get('relation', '') or ''}"
            )
            print(f"Accepted Alternate ID:\t{tab_formatted}")

    # Final verbose output
    if verbose and not result['AlternateIDs']:
        print(f"No alternate IDs found for type '{target_type}' and domain '{target_domain}'.")

    return result


import os
import json

total_count = 0
def process_alternate_ids(xml_record, output_file, verbose=False):
    """
    Processes alternate IDs from an XML record.

    Formats the alternate IDs for both structured data output and string-based output, adding metadata for proprietary types.

    Parameters:
    xml_record (dict): Contains the EIDR ID and its alternate IDs.
    verbose (bool, optional): Enables verbose logging of processed alternate IDs. Defaults to False.

    Returns:
    list: A list of formatted string outputs for the processed records.
    """
    global total_count  # Access the global counter
    count = 0
    record_id = xml_record.get('ID', 'Unknown')
    processed_data = []

    if not xml_record.get('AlternateIDs'):
        print(f"No alternate IDs found for EIDR ID {record_id}")
        return processed_data  # Return early if no AlternateIDs are present

    # Check if output_file is provided, otherwise print to console
    if output_file:
        with open(output_file, 'a') as file:
            for alt_id in xml_record.get('AlternateIDs', []):
                alt_type = alt_id.get('type', '') or ''
                alt_value = alt_id.get('value', '') or ''
                domain = alt_id.get('domain', '') or ''
                alt_relation = alt_id.get('relation', '') or ''

                # Only process if alt_value is valid
                if alt_value.strip():  # Skip if alt_value is empty or just whitespace
                    string_format = f"{record_id}\t{alt_type}\t{alt_value}\t{domain}\t{alt_relation}"

                    file.write(string_format + '\n')  # Write the formatted string directly
                    processed_data.append(string_format)  # Keep the processed strings as a list of strings
                    count += 1
                    if verbose:
                        print(string_format)  # Print the string directly, not a list

    else:
        # If output_file is None, print to the console
        for alt_id in xml_record.get('AlternateIDs', []):
            alt_type = alt_id.get('type', '') or ''
            alt_value = alt_id.get('value', '') or ''
            domain = alt_id.get('domain', '') or ''
            alt_relation = alt_id.get('relation', '') or ''

            # Only process if alt_value is valid
            if alt_value.strip():  # Skip if alt_value is empty or just whitespace
                string_format = f"{record_id}\t{alt_type}\t{alt_value}\t{domain}\t{alt_relation}"
                processed_data.append(string_format)  # Keep the processed strings as a list of strings
                count += 1
                if verbose:
                    print(string_format)  # Print the string directly, not a list

    total_count += count  # Update the global counter
    if verbose:
        print(f"Total Records processed: {total_count}")
    return processed_data


# This formats the eidr ids from an input file
def process_eidr_ids(eidr_ids, verbose, alt_id_type=None, alt_id_domain=None, output_file=None):
    """
    Processes a list of EIDR IDs from an input file.

    Fetches XML data for each ID, validates the IDs, and extracts alternate ID information.

    Parameters:
    eidr_ids (list of str): A list of EIDR IDs to process.
    verbose (bool): Enables verbose logging of processing steps.
    alt_id_type (str, optional): The type to filter alternate IDs by.
    alt_id_domain (str, optional): The domain to filter alternate IDs by.

    Returns:
    list of dict: Collected data for all valid EIDR IDs.
    """
    all_output_data = []

    for eidr_id in eidr_ids:
        if not eidr_id or len(eidr_id) != 34 or not eidr_id.startswith("10.5240/"):
            print(f"Invalid EIDR ID: {eidr_id}")
            continue
        
        if alt_id_type:
            if verbose:
                print(f"Processing EIDR ID: {eidr_id} with type: {alt_id_type}")
            xml_record = fetch_xml(eidr_id, alt_id_type)
        elif alt_id_domain:
            if verbose:
                print(f"Processing EIDR ID: {eidr_id} with domain: {alt_id_domain}")
            xml_record = fetch_xml(eidr_id, "Proprietary")
            if xml_record:
                # Filter the alternate IDs by the domain after fetching the XML
                xml_record = filter_by_domain(xml_record, alt_id_domain)
        else:
            sys.exit(1)

        if xml_record:
            processed_data = process_alternate_ids(xml_record, output_file, verbose=verbose)
            if processed_data:
                all_output_data.extend(processed_data)  # Add the individual formatted strings, not a list of lists
            else:
                print(f"No alternate IDs found for EIDR ID {eidr_id}")
        else:
            print(f"No valid XML record found for EIDR ID {eidr_id}")

    # Return the list of processed strings (not lists)
    return all_output_data

def write_output(output_file, data):
    """
    Writes the processed output data to a specified file or the console.

    Parameters:
    output_file (str or None): The path to the output file. If None, prints to the console.
    data (list): The data to write. This can be a list of strings or lists of strings.

    Returns:
    None
    """
    # Flatten the list if it's a list of lists
    if isinstance(data, list):
        # Flatten the list into a single list of strings
        flattened_data = []
        for item in data:
            if isinstance(item, list):
                flattened_data.extend(item)  # Add the elements of the inner list
            else:
                flattened_data.append(item)  # Add the string directly
        output = "\n".join(flattened_data)  # Join all items into a single string separated by newlines
    else:
        output = str(data)  # If data is not a list, convert it directly to a string
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output + '\n')
        print(f"Output saved to {output_file}")
    else:
        print("Output:\n", output)


def filter_by_domain(xml_record, domain):
    """
    Filters the XML record to only include Proprietary Alternate IDs that match the specified domain.

    Args:
        xml_record (dict): The parsed XML record containing alternate IDs.
        domain (str): The domain to filter alternate IDs by.

    Returns:
        dict: A filtered XML record with only matching domain Alternate IDs.
    """
    filtered_ids = []
    # Loop through alternate IDs and filter by domain
    for alt_id in xml_record.get('AlternateIDs', []):
        if alt_id.get('type') == 'Proprietary' and alt_id.get('domain') == domain:
            filtered_ids.append(alt_id)

    # Update the XML record to contain only the filtered alternate IDs
    xml_record['AlternateIDs'] = filtered_ids
    return xml_record

import re

def format_query_results(query_results, verbose=False):
    """
    Formats query results by extracting and cleaning IDs from XML.

    Parameters:
    query_results (str): Raw XML query result as a string.
    verbose (bool): Enables verbose logging of processing steps.

    Returns:
    list of str: A list of cleaned IDs.
    """
    # Use a regex to extract all IDs between <ID>...</ID> tags
    ids = re.findall(r"<ID>(.*?)</ID>", query_results)
    
    if verbose:
        print(f"Extracted {len(ids)} IDs from the query results.")
    
    return ids


def get_help_message(keyword):
    """
    Retrieves a help message corresponding to a specific keyword.

    Looks up a predefined dictionary of help messages and returns the message associated with the provided keyword. 
    If the keyword does not exist, returns a default message.

    Parameters:
    keyword (str): The keyword for which to retrieve the help message.

    Returns:
    str: The help message associated with the keyword, or "No help message available" if the keyword is not found.

    Example:
    >>> get_help_message('help')
    'Show this help message and exit'

    Supported Keywords:
    - 'help': Show this help message and exit
    - 'version': Print current Tool/SDK version
    - 'showconfig': Shows current connection credentials
    - 'eidr_id': Lets a user query a single EIDR ID
    - 'domain': AltIDs must be in DOMAIN (exclusive with --type)
    - 'type': AltIDs must be in TYPE (exclusive with --domain)
    - 'output': Path to the output file
    - 'config': Path to the XML configuration file
    - 'pagesize': Number of records to retrieve per round
    - 'verbose': Display progress and status reporting
    - 'showcount': Show counts of records processed
    - 'maxCount': Number of threads to use
    - 'maxErrors': Maximum number of errors to tolerate before aborting
    - 'file': File from which to load IDs
    - 'query': XPath query to select IDs
    - 'input': Path to the input file containing EIDR IDs
    - 'logfile': Log file for operation history
    """
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
    global alt_id_type,alt_id_domain
 
    
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
    
    if len(sys.argv) == 1:
        print("No arguments provided. Displaying help options.")
        parser.print_help()
        sys.exit(1)
        query = '' 
        query_results = run_query_api(query,verbose=args.verbose)
        if query_results:
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(query_results)
                print(f"Query results written to {args.output}")
            else:
                print(query_results)
        else:
            print("No results found from the query API.")
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
        """Validates command-line arguments and exits with errors if invalid."""
    if args.pagesize < 1 or args.pagesize > 100000:
        print("Error: Page size must be between 1 and 100000.")
        sys.exit(1)
    else:
        requestPagesize = args.pagesize

    if args.type:
        if args.type in VALID_ID_TYPES:
            alt_id_type = args.type
        else:
            print(f"Error: Invalid type '{args.type}'. Valid types are: {', '.join(VALID_ID_TYPES)}")
            parser.print_help()
            sys.exit(1)

    elif args.domain:
        if args.domain.find(".") >= 2 and len(args.domain) >= 5:
            alt_id_domain = args.domain
        else:
            print(f"Error: Invalid domain '{args.domain}'.")
            parser.print_help()
            sys.exit(1)

    if not (args.type or args.domain):      
        print("Error: You must provide either a type (-t) or a domain (-dom).")
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
        #is not none checks for zero otherwise the valid numbers are 1-100000
    if args.maxCount:
        if args.maxCount < 1 or args.maxCount > 100000:
            print("Error: maxCount must be between 1 and 100000.")
            parser.print_help()
            sys.exit(1)
        else:
            if verbose:
                print(f"Processing up to {args.maxCount} EIDR records.")
            #counts the max allowed errors
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

            eidr_ids = []

    # Check if a single EIDR ID is provided

    output_data = []

 # Inside main function, when processing EIDR IDs from the file:
    if args.input:
        # Read and process EIDR IDs from file
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                eidr_ids = f.read().splitlines()
            if verbose:
                print(f"Loaded {len(eidr_ids)} EIDR IDs from input file.")
            output_data = process_eidr_ids(
                eidr_ids, 
                verbose=args.verbose, 
                alt_id_type=args.type, 
                alt_id_domain=args.domain,
                output_file=args.output
            )
        except Exception as e:
            print(f"Error reading input file: {e}")
            sys.exit(1)


    elif args.eidr_id:
        # Process single EIDR ID
        eidr_id = args.eidr_id
        if verbose:
            print(f"Processing single EIDR ID: {eidr_id}")

        # Validate and fetch XML data for the ID
        if not eidr_id.startswith("10.5240/") or len(eidr_id) != 34:
            print(f"Invalid EIDR ID: {eidr_id}")
            sys.exit(1)

        if args.type:
            alt_id_type = args.type
            xml_record = fetch_xml(eidr_id, alt_id_type)
        elif args.domain:
            alt_id_domain = args.domain
            xml_record = fetch_xml(eidr_id, "Proprietary")
            if xml_record:
                # Filter the alternate IDs by the domain after fetching the XML
                xml_record = filter_by_domain(xml_record, alt_id_domain)
        else:
            print("Error: Please provide either --type or --domain.")
            sys.exit(1)

        # Process XML and collect data
        if xml_record:
            processed_data = process_alternate_ids(xml_record, args.output, verbose=verbose)
            if processed_data:
                output_data = processed_data  # Wrap in list for consistency
            else:
                print(f"No alternate IDs found for EIDR ID {eidr_id}")
                sys.exit(1)
        else:
            print(f"No valid XML record found for EIDR ID {eidr_id}")
            sys.exit(1)
    else:
            # No ID or input file provided, construct and run a query
            try:
                if args.type or args.domain:
                    # Determine query parameters based on provided arguments
                    if args.type:
                        query = DefaultQuery.replace("TYPE", args.type)
                    elif args.domain:
                        query = DomainQuery.replace("DOMAIN", args.domain)

                    if verbose:
                        print(f"Constructed query: {query}")
                        print(f"Running query with parameters: {query}")
                    
                    # Call the function to run the query
                    query_results = run_query_api(query, verbose=verbose)
                    
                    if query_results:
                        # Format the query results
                        formatted_ids = format_query_results(query_results, verbose=verbose)
                        
                        if args.output:
                            with open(args.output, "w") as file:
                                file.write("\n".join(formatted_ids))
                            if verbose:
                                print(f"Results written to {args.output}")
                        else:
                            print("\n".join(formatted_ids))
                    else:
                        print("No results found from the query API.")
                        sys.exit(1)
                else:
                    raise ValueError("No EIDR ID, input file, type, or domain provided. Cannot proceed.")
            except Exception as e:
                print(f"Error: {e}")
                sys.exit(1)


    # If no output file is provided, print results to the console
    if args.output is None:
    # If output is None, print the output to the console
        for data in output_data:
            print("".join(data))  # Join list items into a single string
    else:
    # Otherwise, write output to the specified file
        write_output(args.output, output_data)

    
if __name__ == "__main__":
    main()