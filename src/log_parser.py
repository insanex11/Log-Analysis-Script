import re

def parse_log_file(file_path):
    log_entries = []
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(r'(?P<ip>\S+) - - \[.*\] "(?P<method>\S+) (?P<endpoint>\S+) HTTP/\S+" (?P<status>\d+) .*', line)
            if match:
                log_entries.append(match.groupdict())
    return log_entries
