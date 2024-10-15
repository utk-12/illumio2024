from collections import defaultdict
import csv
import logging
import os
import argparse

"""
This function loads the csv file with the assumption the first line has the 
header for the lookup table and parses the rest of the lines and stores them 
into a dictionary( hash map)

Assumptions:
1. Since, a given key, say '25,tcp' could have more
one tag. The lookup dictionary values is set as a list(array)
by default using defaultdict 

Args:
    filename : Name of the lookup table file.
Returns:
    lookup table dictionary

"""
def load_lookup_table(filename):
    lookup_dict = defaultdict(list)
    try:
        with open(filename, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) == 3:
                    dstport, protocol, tag = row
                    if dstport.isdigit() and protocol in ('tcp', 'udp'):
                        key = (int(dstport), protocol.lower())
                        lookup_dict[key].append(tag.lower())
    except FileNotFoundError:
        logging.error(f"The file '{filename}' was not found.")
    except PermissionError:
        logging.error(f"Permission denied when trying to read '{filename}'.")
    except csv.Error as e:
        logging.error(f"An issue occurred while parsing the CSV file: {e}")
    except IOError as e:
        logging.error(f"An I/O error occurred: {e}")
    return lookup_dict


"""
This function is used in tag_lines to read lines efficiently without loading
the entire file into memory instead using an iterator to read it line by line

Assumptions:
1. File is too big to be read using .read() /readlines()

Args:
    filename : Name of the flow log file.
Returns:
    line from the flow log file.

"""
def line_generator(filename):
    if not os.path.exists(filename):
        logging.error(f"The file '{filename}' does not exist.")
        return

    try:
        with open(filename, 'r') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line:  # dont include blank lines if they are present
                    yield stripped_line
    except FileNotFoundError:
        logging.error(f"The file '{filename}' was not found.")
    except PermissionError:
        logging.error(f"Permission denied when trying to read '{filename}'.")
    except IOError as e:
        logging.error(f"An I/O error occurred: {e}")



"""
This function contains the main logic of counting the tags required by the 
problem statement. It performs multiple validations to skip processing log
lines that are incompatible for the problem at hand.

Assumptions:
1. A given log line can have multiple tags
2. A correct log line has 14 fields. If it has different number for fileds, 
   this logic of parsing will not be sufficient as specific indices are used
   to assume the value held in them ex: dstport = fields[5].
3. protocol version number 6 is tcp and 17 is udp.   
4.
Args:
    filename : Name of the flow log file.
Returns:
    tag_counts: a dictionary/map of the counts of a given tag
    port_protocol_counts: a dictionary/map of the counts of a port:protocal

"""
def tag_lines(input_file, lookup_dict):
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)
    untagged_count = 0

    for line in line_generator(input_file):
        fields = line.split()
        if len(fields) != 14:
            logging.warning(f"Invalid line with insufficient fields: {line}")
            continue

        try:
            version = int(fields[0])
            if version != 2:
                logging.warning(f"Unsupported log version: {version} in line: {line}")
                continue

            dstport = fields[5]
            protocol = fields[7]
            log_status = fields[13]

            if not dstport.isdigit() or not (0 <= int(dstport) <= 65535):
                logging.warning(f"Invalid port number: {dstport} in line: {line}")
                continue

            if protocol not in ('6', '17'):  # 6 for TCP, 17 for UDP
                logging.warning(f"Unsupported protocol: {protocol} in line: {line}")
                continue

            if log_status != 'OK':
                logging.warning(f"Log status not OK: {log_status} in line: {line}")
                continue

            # Map the protocol number to string
            protocol_str = 'tcp' if protocol == '6' else 'udp'

            key = (int(dstport), protocol_str)

            port_protocol_key = key
            port_protocol_counts[port_protocol_key] += 1

            tags = lookup_dict.get(key, [])
            if tags:
                for tag in tags:
                    logging.debug(f"Tag found: {tag} for key: {key}")
                    tag_counts[tag] += 1
            else:
                logging.debug(f"No tag found for key: {key}")
                untagged_count += 1

        except (ValueError, IndexError) as e:
            logging.error(f"Error parsing line: {line}. Error: {e}")

    tag_counts['untagged'] = untagged_count
    return tag_counts, port_protocol_counts



"""
This is the main funciton which parses the arguments passed to the program for
the input flow log file and lookup table.

Assumptions:
1. This program will be run multiple times with different input files and 
   we should delete the older output file before overwriting it. 
2. Input/ Output file names are assumed if not provided.

Returns:
    Only output files are generated

"""
def main():
    parser = argparse.ArgumentParser(description='Process flow logs and generate tag counts.')
    # Defaults for command line arguments
    parser.add_argument('--lookup-file', default='lookup_table.csv', help='Lookup table CSV file')
    parser.add_argument('--log-file', default='flow.log', help='Input log file')
    parser.add_argument('--tag-output', default='tag_counts_output.csv', help='Output file for tag counts')
    parser.add_argument('--port-output', default='port_protocol_counts_output.csv', help='Output file for port/protocol counts')

    args = parser.parse_args()

    lookup_file = args.lookup_file
    input_file = args.log_file
    tag_output_file = args.tag_output
    port_output_file = args.port_output
    
    lookup_dict = load_lookup_table(lookup_file)
    
    tag_counts, port_protocol_counts = tag_lines(input_file, lookup_dict)
    output_files = [tag_output_file, port_output_file]
    
    for output_file in output_files:
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
                logging.info(f"Deleted old output file: {output_file}")
            except OSError as e:
                logging.error(f"Error deleting file {output_file}: {e}")

    try:
        with open(tag_output_file, 'w') as tag_file:
            tag_file.write("Tag,Count\n")
            for tag, count in tag_counts.items():
                tag_file.write(f"{tag},{count}\n")
    except IOError as e:
        logging.error(f"An error occurred while writing to {tag_output_file}: {e}")

    try:
        with open(port_output_file, 'w') as port_file:
            port_file.write("Port,Protocol,Count\n")
            for (port, protocol), count in port_protocol_counts.items():
                port_file.write(f"{port},{protocol},{count}\n")
    except IOError as e:
        logging.error(f"An error occurred while writing to {port_output_file}: {e}")

if __name__ == "__main__":
    main()
