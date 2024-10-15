# illumio2024
LogParsing

**Steps to run:**

python logparser.py --help

usage: logparser.py [-h] [--lookup-file LOOKUP_FILE] [--log-file LOG_FILE] [--tag-output TAG_OUTPUT] [--port-output PORT_OUTPUT]

If no arguments are provided defaults are applied, where:
    1. the log file name is assumed to be flow.log
    2. the lookup table file is lookup_table.csv
    3. the output file names are tag_counts_output.csv and port_protocol_counts_output.csv

The files are lookup table file, the flow log file, and the output files are all present in same directory.

The main file to be run is logparser.py as shown above.



