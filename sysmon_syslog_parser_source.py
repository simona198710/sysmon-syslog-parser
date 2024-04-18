import re
import sys
from collections import defaultdict, Counter

def parse_log_entry(line):
    """
    Parse a single log entry for relevant data (process name, destination IP, destination port, and optionally destination hostname).
    Entries without 'DestinationIp' are ignored.
    """
    line = line.replace('#015#012', ' ').replace('#011', ' ')  # Normalize delimiters to spaces
    if 'SourceIp' not in line:
        return None

    # Regex to capture the full path, Source IP, and Source port
    match = re.search(r'Image:\s*(.+?)\s+User:', line)
    ip_match = re.search(r".*?SourceIp:\s*(?P<ip>[a-fA-F0-9:\.]+)", line)
    port_match = re.search(r'SourcePort:\s*(\d+)', line)
    hostname_match = re.search(r'SourceHostname:\s*([^\s]+)?', line)

    if match and ip_match and port_match:
        process_name = match.group(1).strip()
        dest_ip = ip_match.group('ip').strip()
        dest_port = port_match.group(1).strip()
        dest_hostname = hostname_match.group(1).strip() if hostname_match and hostname_match.group(1) else ""
        if dest_hostname == "SourcePort:":
            dest_hostname = ""
        return (process_name, dest_ip, dest_port, dest_hostname)
    else:
        print("Debug: No match found - ", line)
    return None

def read_logs(filename):
    connections = defaultdict(lambda: defaultdict(lambda: defaultdict(Counter)))
    with open(filename, 'r', encoding='utf-8', errors='replace') as file:
        for line in file:
            result = parse_log_entry(line)
            if result:
                process_name, dest_ip, dest_port, dest_hostname = result
                connections[process_name][dest_ip][dest_port][dest_hostname] += 1
    return connections

def report(connections):
    for process, ips in connections.items():
        print(process)
        for ip, ports in ips.items():
            for port, hostnames in ports.items():
                for hostname, count in hostnames.items():
                    print(f"  {ip}:{port} ({hostname}) - {count} times")
        print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <log_filename>")
        sys.exit(1)
    
    log_filename = sys.argv[1]  # Get the log file name from command line arguments
    connections = read_logs(log_filename)
    report(connections)

if __name__ == "__main__":
    main()
