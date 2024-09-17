import sys
import base64
import argparse
import xml.etree.ElementTree as ET
import hashlib
import uuid
import requests
import ssl
from xml.dom import minidom

global registryToUse
global requestPagesize
global verbose
global debug
global fileName
global showCount
global opLog
global query
global IDList
global REGISTRY_KEY
global maxCount
global maxErrors

# API URL


# ShortDOI credentials
REGISTRY_KEY = 'sandbox1'
SHORTDOI_LOGIN = '10.5238/shortdoi'
SHORTDOI_PARTYID = '10.5237/superparty'
SHORTDOI_PASSWORD = 'RZ1td!FZP}qB53yAdK7V'

API_URL = 'https://{REGISTRY_KEY}.eidr.org/EIDR/query/?type=ID'
API_URL = 'https://sandbox1.eidr.org/EIDR/query/?type=ID'

verbose = False                     # If TRUE, send progress messages to the console
debug = False                       # If TRUE, send diagnostic data to the console
showCount = True                    # If TRUE, show show counts of records processed / errors while running
requestPagesize = 1000              # Number of records to retrieve per round
QueryPageOffset = 1                 # Page offset for repeated query rounds
opLog = 'EIDRToAlt.oplog'            # Operation log filename.   Set to '' to suppress
maxErrors = 0                       # If non-zero, abort after this many errors
maxCount = 0  


IDList = []                                                                             # List of EIDR IDs to process this round
DefaultQuery = 'NOT /FullMetadata/BaseObjectData/AlternateID@type ShortDOI EXISTS AND  /FullMetadata/BaseObjectData EXISTS'      # Default query to use for ID list (i.e. no other ID source specified = 'W:\\Projects\\Libraries\\EidrSDK\\Legacy\\EIDR-SDK 2.7.0 .NET RC3\\Utilities\\Gchange.exe'
gchange = 'W:\\Projects\\Libraries\\EidrSDK\\Legacy\\EIDR-SDK 2.7.0 .NET RC2\\Tools\\Gchange.exe'
query = ''                      # Query to use for ID list  (use DefaultQuery if no other ID source specified)
globCnt = 0                     # Count of records processed
globErrCnt = 0                  # Count of errors encountered
tmpFileName = 'SHORTDOI_' + str(uuid.uuid4().hex) + '.xml'          # Temporary file name for gChange configuration


# List of valid Alt ID types
VALID_ID_TYPES = [
    "Ad-ID", "AFT", "AMG", "Baseline", "BFI", "cIDF",
    "CRID", "DOI", "EAN", "GRid", "GTIN", "IMDB", "ISAN",
    "ISRC", "ISTC", "IVA", "Lumire", "MUZE", "Proprietary",
    "ShortDOI", "SMPTE_UMID", "TRIB", "TVG", "UPC", "URI", "URN", "UUID",
]

# Global variables for paging
QueryPageOffset = 1
requestPagesize = 100
AliasList = []  # List to store aliases
DefaultQuery = "/FullMetadata/BaseObjectData/AlternateID 10/gttxdr"  # Default query

def load_config_from_xml(config_file):
    if not config_file:
        raise ValueError("Config file path is None")

    try:
        tree = ET.parse(config_file)
        root = tree.getroot()

        # Extract the credentials and config elements from the XML
        url = root.find('url')
        pagesize = root.find('pagesize')
        certpath = root.find('certpath')
        keypath = root.find('keypath')

        if None in (url, certpath, keypath):
            raise ValueError("Missing one or more required elements (url, certpath, keypath) in the XML config")

        # Return the configuration as a dictionary, overriding credentials with ShortDOI
        return {
            "URL": url.text,
            "EIDR_PARTYID": SHORTDOI_PARTYID,
            "EIDR_LOGIN": SHORTDOI_LOGIN,
            "EIDR_PASSWORD": SHORTDOI_PASSWORD,
            "PAGESIZE": pagesize.text if pagesize is not None else "100",
            "CERT_PATH": certpath.text,
            "KEY_PATH": keypath.text
        }
    except Exception as e:
        print(f"Failed to load configuration: {e}", file=sys.stderr)
        sys.exit(1)

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

        url = f'https://{registry_key}.eidr.org/EIDR/query/?type=ID'
        print(f"Request URL: {url}")  # Debugging

        # Disable SSL verification for testing
        context = ssl._create_unverified_context()

        # Validate request data
        if not body:
            raise ValueError("Request body is None")
        
        r = requests.Request(url, headers=hdr, data=body)
        print("Request data sent successfully")  # Debugging

        QueryPageOffset += 1  # Advance page offset for next round

        # Make the actual request (you'll need to uncomment this line)
        # resp = requests.urlopen(r, context=context)
        # return resp.read()  # Return the response
    except Exception as e:
        print(f'Error in request: {e}', file=sys.stderr)
        raise

def get_more_ids():
    global AliasList
    global QueryPageOffset

    cnt = 0
    
    # Use DefaultQuery and credentials
    query = DefaultQuery
    eidr_login = SHORTDOI_LOGIN
    eidr_partyid = SHORTDOI_PARTYID
    eidr_password = SHORTDOI_PASSWORD
    registry_key = REGISTRY_KEY

    s = get_query_body(query,eidr_login,eidr_partyid,eidr_password,registry_key).decode('utf-8')
    doc = minidom.parseString(s)
    results = doc.getElementsByTagName('QueryResults')
    print(results)  # debug
    if len(results)==0:
        print("Nothing found")
        return
    for elem in results.item(0).getElementsByTagName('SimpleMetadata'):
        alias_from = ''
        alias_to = ''
        for node in elem.childNodes:
            if node.nodeType == node.ELEMENT_NODE:
                if node.tagName == 'ID':
                    alias_from = node.firstChild.nodeValue
                if node.tagName == 'ResourceName':
                    alias_to = node.firstChild.nodeValue
        if alias_from and alias_to:
            AliasList.append(aliasRec(alias_from, alias_to))
            cnt += 1
    return cnt

def write_output_file(output_file):
    with open(output_file, 'w') as f:
        for alias in AliasList:
            eidr_id = alias['alias_from']
            id_value = alias['alias_to']
            id_type = ""  # Assuming all are proprietary; adjust as needed
            id_domain = ""  # Placeholder; adjust based on actual data if applicable
            id_relation = ''  # Placeholder; adjust as needed
            
            line = f"{eidr_id}\t{id_type}\t{id_value}\t{id_domain}\t{id_relation}\n"
            f.write(line)

def main():
 #   global DefaultQuery
    global SHORTDOI_LOGIN, SHORTDOI_PARTYID, SHORTDOI_PASSWORD, REGISTRY_KEY,requestPagesize
    global registryToUse
    global requestPagesize
    global verbose
    global debug
    global fileName
    global showCount
    global opLog
    global query
    global IDList
    global REGISTRY_KEY
    global maxCount
    global maxErrors
    global eidr_id, alt_id_domain,alt_id_type, alt_id_relation


    eidr_id=" "
    alt_id_domain=" "
    alt_id_type=" "
    alt_id_relation=" "
    REGISTRY_KEY = 'sandbox1'

    parser = argparse.ArgumentParser(description="Query EIDR and output alternate IDs")

    # Original arguments
    parser.add_argument('-r',  default=REGISTRY_KEY, dest="registry",help="Registry to query for party list")
    parser.add_argument('--version', action='store_true', help='Print current Tool/SDK version')
    parser.add_argument('-oenc', '--oencoding', default='UTF-8', required=False, help='Set output file encoding to ENC. Defaults to UTF-8.')
    parser.add_argument('--showconfig', action='store_true', help='Print current connection credentials')
    # Optional EIDR ID
    parser.add_argument("--eidr_id", help="Optional EIDR ID to query")

    # Mutually exclusive group for domain and type
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-dom', '--domain', required=False, help='AltIDs must be in DOMAIN (exclusive with --type)')
    group.add_argument('-t', '--type', required=False, help='AltIDs must be in TYPE (exclusive with --domain)')

    # Output file and config file arguments
    parser.add_argument('-o', '--output', required=False, help='Path to the output file')
    parser.add_argument('-c', '--config', required=False, help='Path to the XML configuration file')  # Keep -c for config

    # Additional arguments you provided
    parser.add_argument('-p', type=int, default=requestPagesize, dest="pagesize", help="Number of records to retrieve per round")
    parser.add_argument('-v', '--verbose', action="store_true", default=False, dest="verbose", help="Display progress and status reporting")
    parser.add_argument('-d', '--debug', action="store_true", dest="debug", default=False, help="Show debugging information")
    parser.add_argument('--count', action="store_true", dest="showcount", default=False, help="Show counts of records processed")  # Use --count
    parser.add_argument('-m', '--max', type=int, default=maxCount, dest="maxCount", help="Number of threads to use")
    parser.add_argument('-x', '--maxerrs', type=int, default=maxErrors, dest="maxErrors", help="Maximum number of errors to tolerate before aborting")
    parser.add_argument('-f', '--filename', default='', dest="fileName", help="File from which to load IDs")
    parser.add_argument('-q', '--query', default='', dest="query", help="XPath query to select IDs")
    parser.add_argument('-e', '--eidr', default='', dest="eidrID", help="Single EIDR to process")
    parser.add_argument('-l', '--logfile', dest="opLog", default=opLog, help="Log file for operation history")

    
    args = parser.parse_args()
    if debug:
        print('Arguments: ' + str(args))
   
    REGISTRY_KEY = args.registry
    requestPagesize = args.pagesize
    verbose = args.verbose
    debug = args.debug
    opLog = args.opLog
    fileName = args.fileName
    showCount = args.showcount
    maxCount = args.maxCount
    maxErrors = args.maxErrors
    if debug:
        verbose = True                          # If debugging, include "verbose" messages
    if args.registry != '':
        REGISTRY_KEY = args.registry

    # If a query was specified, use it instead of the default query
    #if args.query != '':
    #    query = args.query
    #else:
    #    query = DefaultQuery

    # Create the query XML, including EIDR-ID only if provided
    query = f"""
    <query>
        <criteria>
            {f"<EIDR-ID>{eidr_id}</EIDR-ID>" if eidr_id else ""}
            <IDType>{alt_id_type}</IDType>
            {'<Domain>{alt_id_domain}</Domain>' if alt_id_domain else ''}
            {'<Relation>{alt_id_relation}</Relation>' if alt_id_relation else ''}
        </criteria>
    </query>
    """
    API_URL = 'https://sandbox1.eidr.org/EIDR/query/?type=ID'
     # Use DefaultQuery and credentials
    query = DefaultQuery
    eidr_login = SHORTDOI_LOGIN
    eidr_partyid = SHORTDOI_PARTYID
    eidr_password = SHORTDOI_PASSWORD
    registry_key = REGISTRY_KEY

    s = get_query_body(query,eidr_login,eidr_partyid,eidr_password,registry_key)

    print(s)

    # execute the query.
    response= requests.get(API_URL)
    print(response.text)
    print(response.headers)
    print("Content:", response.content)  # To get the response as JSON



    # Fill ID list
    if args.eidrID != '':
        IDList.append(args.eidrID)      # If an EIDR ID was specified, add it to the list
        query = ''                      # If an EIDR ID was specified, ignore the query
    if args.fileName != '':
        try:
            query = ''                  # If a file was specified, ignore the query
            text_file = open(fileName, "r")
            IDList = text_file.readlines()
            for i in range(0, len(IDList)):
                IDList[i] = IDList[i].strip(' \t\n')
            text_file.close()
        except Exception as e:
            print(f'Error loading ID file {fileName}: {e}')
            exit(1)
    # Load configuration
    # will need to replace when using actual user config file
     # Update credentials and API settings from config if needed
    
    if 1 != 1:
        config = load_config_from_xml(args.config)
        SHORTDOI_LOGIN = config["EIDR_LOGIN"]
        SHORTDOI_PARTYID = config["EIDR_PARTYID"]
        SHORTDOI_PASSWORD = config["EIDR_PASSWORD"]
        REGISTRY_KEY = config["URL"].split('/')[2]  # Extract registry key from URL

    # Fetch and write data
   # get_more_ids()
    write_output_file(args.output)

if __name__ == "__main__":
    main()

