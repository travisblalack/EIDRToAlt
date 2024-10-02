Basic commands created 10/1/24

#For creating and setting an output file

python3 EIDRToAltID.py -o output.txt

#For config file 

python3 EIDRToAltID.py -c eidr-config.xml

#shows config with a file

python3 EIDRToAltID.py -c eidr-config.xml --showconfig

#shows config from the system if the user does not provide a config file

python3 EIDRToAltID.py  --showconfig

# displays current version

python3 EIDRToAltID.py --version

#shows the basic command switches

python3 EIDRToAltID.py --help or python3 EIDRToAltID.py --h

#9/24/23 python3 EIDRToAltID.py -h also works, tested it and got the help options.

#sets an eidr id and displays an output

python3 EIDRToAltID.py --eidr_id 10.5240/7A11-2421-8C83-1B6C-AFC4-T -t ShortDOI --o output.txt

# or for id

python3 EIDRToAltID.py -id 10.5240/7A11-2421-8C83-1B6C-AFC4-T -t ShortDOI -o output.txt

#lods from a list of EIDR IDs and displays output

python3 EIDRToAltID.py -i IDs.txt -o output.txt

#limits number of records to process

python3 EIDRToAltID.py --eidr_id 10.5240/ECC7-613E-D693-6233-0BA0-U -t ShortDOI --count 5

#This will display command line history and its date, time, etc to a log
python3 EIDRToAltID.py -l log.txt -o output.txt

How to run a domain name when user inputs proprietary
python3 EIDRToAltID.py --eidr_id 10.5240/ECC7-613E-D693-6233-0BA0-U -dom disney.com

How to run a type for all valid EIDR types but proprietary

python3 EIDRToAltID.py --eidr_id 10.5240/7A11-2421-8C83-1B6C-AFC4-T -t ShortDOI

#Same as above but with an input list

python3 EIDRToAltID.py -i IDs.txt -t ShortDOI

# to put a config and output
python3 EIDRToAltID.py --config eidr-config.xml --eidr_id 10.5240/ECC7-613E-D693-6233-0BA0-U -dom disney.com -o output.txt

#display verbose options with config file

python3 EIDRToAltID.py --config eidr-config.xml --eidr_id 10.5240/ECC7-613E-D693-6233-0BA0-U -t ShortDOI -v

#sets the page size other than 100

python3 EIDRToAltID.py -c eidr-config.xml -p 10

#same as above without config file

python3 EIDRToAltID.py -p 10

#Displays the maximum allowed errors before program aborts

python3 EIDRToAltID.py --eidr_id 10.5240/7A11-2421-8C83-1B6C-AFC4-T -t ShortDOI --o output.txt -x 3

#Displays custom page size

python3 EIDRToAltID.py -c eidr-config.xml -p 11
