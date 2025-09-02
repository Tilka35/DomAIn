# Welcome to the "DomAIn" v 1.0 script tool, written in Python 3.10.1 by Attila Nagy.

# This is an AI-powered threat intelligence/security scanning tool that queries the VirusTotal API based on a 'netstat' scan that was completed on the local machine. 
# This response from the VirusTotal API is then fed to the LLM through the HuggingFace Endpoint, LangSmith, LangChain to query and processes the data, and produces a
# response to determine whether the scan returned a malicious domain, and the trained LLM advises on the next steps for the threat intelligence procedure.

# Code inspiration came from John Hammond, Gordon Lyon, H.D. Moore, Julio Canto and Bernardo Quintero.

# Take environment variables from .env.
from dotenv import load_dotenv
load_dotenv() 

# Imports and Libraries
import requests, os, subprocess, platform, constant, csv, time, sys
from nested_lookup import nested_lookup
from datetime import datetime
from colorama import init, Fore, Style

# LangChain and HuggingFace imports
from langchain_community.llms import HuggingFaceEndpoint
from langchain_core.prompts import PromptTemplate

from typing import List
from langchain_core.pydantic_v1 import BaseModel, Field
from langchain_core.output_parsers import JsonOutputParser

# Format for Starting message and colours
def green_output(text, color=Fore.GREEN, delay=0.01):
    for char in text:
        sys.stdout.write(color + char)
        sys.stdout.flush()
        time.sleep(delay)
    print(Style.RESET_ALL)
    #time.sleep(2.5)

# Format for 
def format_output(text, delay=0.01):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print(Style.RESET_ALL)
    #time.sleep(0.5)

# Method to Check what Operating System the tool is running on
def check_system_run_netstat():
    
    # Reset colour after print
    init(autoreset=True)
    
    print("""
                    
░███████                                 ░███    ░██████           
░██   ░██                               ░██░██     ░██             
░██    ░██  ░███████  ░█████████████   ░██  ░██    ░██  ░████████  
░██    ░██ ░██    ░██ ░██   ░██   ░██ ░█████████   ░██  ░██    ░██ 
░██    ░██ ░██    ░██ ░██   ░██   ░██ ░██    ░██   ░██  ░██    ░██ 
░██   ░██  ░██    ░██ ░██   ░██   ░██ ░██    ░██   ░██  ░██    ░██ 
░███████    ░███████  ░██   ░██   ░██ ░██    ░██ ░██████░██    ░██ 
                                                                   """)
    print("written by @Tilka35")
    print("https://github.com/Tilka35/DomAIn\n")
    
    ## Display starting message
    green_output("Starting DomAIn Connection Scanner...\n") #test
    green_output("Loading LLM Modules...\n") #test
    #time.sleep(10)
    
    # Perform System Check
    system_os = platform.system()
    netstat_command = ['netstat', '-ano']
    # Check if platform is Windows or Linux
    if system_os in ["Windows", "Linux"]:
        # Run tool and capture the output for later use
        try:
            green_output("Running Scan...\n")
            netstat_command_output = subprocess.run(netstat_command, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running Netstat command {netstat_command}: ", e)
    else:
        print("Unsupported operating system")
        return None
        
    output = netstat_command_output.stdout       
    # Print netstat command result
    #test change
    return output

# Method to parse netstat output
def parse_output(output):
    # Initialise list
    active_connections = []
    
    # Split the output by lines
    lines = output.split('\n')

    # Iterate over each line in the output
    for line in lines:
        # Output each line to the cli - comment to reduce output
        #print("Processing Line: ", line)
        # Split by whitespace
        fields = line.split()
        # TCP connections
        if len(fields) >= 5:
            conn_protocol = fields[0]
            conn_localadd = fields[1]
            conn_foreignadd = fields[2]
            conn_state = fields[3]
            conn_pid = fields[4]
            
            # Add to list under active connections headings
            active_connections.append({'Protocol': conn_protocol, "LocalAddress": conn_localadd, "ForeignAddress": conn_foreignadd, "State": conn_state, "PID": conn_pid})
        # UDP connections
        elif len(fields) >= 4:
            conn_protocol = fields[0]
            conn_localadd = fields[1]
            conn_foreignadd = fields[2]
            conn_state = fields[3]
            active_connections.append({'Protocol': conn_protocol, "LocalAddress": conn_localadd, "ForeignAddress": conn_foreignadd, "State": '', "PID": conn_pid})
        
    return active_connections

# Write connection information to CSV file
def write_to_csv(active_connections):
    # Check if file exists
    existing_file = [file for file in os.listdir(".") if file.startswith("netstat_output_")]
    
    # If file does not exist, generate a new csv file
    if not existing_file:
        filename = generate_filename()
    else:
        # If file exists, delete it and make a new one
        for file in existing_file:
            os.remove(file)
        # Generate new CSV file
        filename = generate_filename()
    
    # Write the netstat command output to a CSV file
    with open(filename, 'w', newline='') as csv_file:
        # Write the column headers
        fieldnames = ['Protocol', 'LocalAddress', 'ForeignAddress', 'State', 'PID']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        
        # Write each row of data to the CSV file and add spaces for readability
        for row in active_connections:
            format_row = {k: f" {v}" for k, v in row.items()}
            writer.writerow(format_row)
            
        print("Wrote {} rows to {}".format(len(active_connections), filename))

# Generate filename
def generate_filename():
    # Timestamp the CSV file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = f"netstat_output_{timestamp}.csv"
    return filename

# Read IP addresses from CSV file, using CSV file in directory.
def read_ip_address(filename):
    # List
    ip_addresses = []
    # Addresses to ignore
    reserved_address = "0.0.0.0"
    localhost_address = "127.0.0.1"
    ipv6_address = "[::]"
    any_any_address = "*:*"
    
    # Find CSV file in current directory
    filepath = os.path.join(os.path.dirname(__file__), filename)
    
    # Open and read CSV file
    with open(filepath, 'r') as file:
        reader = csv.reader(file)
        next(reader) # skip first line
        for row in reader:
            if row: # Check row is not empty
                # Strip port numbers and colons
                ip_and_port = row[2].strip()
                # Exclude ignored IP addresses
                if not ip_and_port.startswith((reserved_address, localhost_address, ipv6_address, any_any_address)):
                    # Split IP and port and add to list
                    stripped_ip_address = ip_and_port.split(":")[0]
                    ip_addresses.append(stripped_ip_address)
                    ip_addresses.append("31.28.27.105")     # Test for malicious address
    # Return list
    return ip_addresses

# Query VirusTotal API
def virustotal_query(ip_address):
    
    # IP Address Report
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": constant.VT_API_KEY, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    #time.sleep(2) # Waiiiittttt
    #print(response.status_code)
    
    # Check if there is a response
    if response.status_code == 200:
        print("Response Status Code: ", response.status_code, "- Successful!")
        #time.sleep(0.5)
        print("\n")
        return response.json()
    # Not Successful, print error message
    elif response.status_code == 404:
        error_message = response.json().get("Error", {}).get("Message")
        if error_message == "Resource not found.":
            print(f"No information found on IP Address from VirusTotal about: {ip_address}")
        # Unknown Error
        else:
            print(f"Unknown Error: {error_message}")
        return None
    # API Error and response code
    else:
        print(f"Error accessing VirusTotal API for IP Address {ip_address}. Status Code: {response.status_code}")
        return None

# Main Method
def main():
    # Run Netstat        
    netstat_output = check_system_run_netstat()
    
    # Parse netstat output
    parsed_output = parse_output(netstat_output)
    
    # Write output to CSV
    write_to_csv(parsed_output)
    
    # Get List of IP addresses from CSV file
    filename = [file for file in os.listdir(".") if file.startswith("netstat_output")][0]
    
    # Check for malicious IP addresses
    ip_addresses = read_ip_address(filename)
    # Loop through each address
    for ip in ip_addresses:
        green_output(f"Checking IP address: {ip} ...")
        # ANSI escape sequences for formatting
        BOLD = '\033[1m'
        RESET = '\033[0m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        CYAN = '\033[96m'
        # Query VT with each address
        response = virustotal_query(ip)
        filtered_results = {}
        if response:
            print(f"{BOLD}VirusTotal report for IP:{RESET} {CYAN}{ip}{RESET}\n")
            
            selected_attributes = [
                "whois","whois_date","last_analysis_date", "as_owner", "regional_internet_registry", "asn", "continent", "country", "cert_signature", "subject_alternative_name", "public_key", "thumbprint_sha256", "issuer", "subject", "last_analysis_stats"
            ]
            
            attributes_data = response["data"]["attributes"] #
            #filtered_results = {}
            for attribute in selected_attributes:
                value = nested_lookup(attribute, attributes_data)
                filtered_results[attribute] = value
                #Threat levels
                if attribute == "last_analysis_stats":
                    stats = value[0] if value else {}
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    if malicious > 0:
                        threat_colour = RED
                        threat_label = "MALICIOUS"
                    elif suspicious > 0:
                        threat_colour = YELLOW
                        threat_label = "SUSPICIOUS, ANALYSE FURTHER"
                    else:
                        threat_colour = GREEN
                        threat_label = "CLEAN"
                    
                    print(f"{BOLD}{attribute}:{RESET} {threat_colour}{threat_label}{RESET}")
                    print(f"{BOLD}Stats{RESET} {stats}")
                else:
                    formatted_value = value[0] if isinstance(value, list) and value else value
                    print(f"{BOLD}{attribute}:{RESET} {value}")
                    
                # print(attribute, nested_lookup(attribute, response["data"]["attributes"]))
                # filtered_results[attribute]=nested_lookup(attribute, response["data"]["attributes"])
            print("\n")    
    
    # Call model to parse and explain data from VirusTotal API
    hub = HuggingFaceEndpoint(repo_id="mistralai/Mistral-7B-Instruct-v0.2")

    # Prompt to generate response and provide information to LLM
    tasks_template = """<s>[INST]
    You are a seasoned cybersecurity expert that specializes in threat hunting and threat intelligence.
    The script that runs in this program checks the current connected addresses to this host with a netstat command, and then checks if they are malicious or benign through the VirusTotal API.
    Your job is to take each output that is returned from the API and make it perfectly human readable, while very briefly explaining each section.
    This output should be short and legible, easy for humans to see and aesthetically pleasing.
    If a malicious domain is found, highlight this find, and recommend to do another scan and to double check for true positives.
    Here is the list of information from the VirusTotal API about the scan that requires to be explained in short but comprehensive detail. These are the most important parts of the scan received from VirusTotal.
    Please make a legible and well laid-out description of the scan results, and if there are any domains that are flagged as malicious in this list, please make a suggestion on how to proceed with mitigating the threat.
    If there are no malicious domains, please still advise for a secondary scan for safety, and advise on next steps.
    Here is the list, and the information for each domain:
    {domain_list}
    Please make this list extremely easy to read, and highlight the malicious domains that are found.
    Give a list of tasks that can be done to negate the risk of being connected to a malicious domain.[/INST]
    </s>
    
    """

    # # Create own class with tasks that returns a list of objects
    # class Tasks(BaseModel):
    #     tasks: List = Field(description="list of malicious domains")

    # # Parse output to fit task format given
    # parser = JsonOutputParser(pydantic_object=Tasks) #Specific details

    # Outputs the information
    tasks_prompt_json = PromptTemplate( # prompt template instance
        template=tasks_template, # template to generate prompt
        input_variables=["malicious_domains"] # 
    )

    # LangChain expression language - variables to prompt template| prompt to model | model to json parser -> output
    tasks_chain = tasks_prompt_json | hub 

    # Print the output response, relative to key information provided
    print(tasks_chain.invoke(
        {
            "domain_list" : filtered_results
        }
    ))

if __name__ == "__main__":
    main()
    print("test")