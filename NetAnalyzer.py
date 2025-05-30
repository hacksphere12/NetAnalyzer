
#!/usr/bin/env python3

import socket
import subprocess
import argparse
import platform
import re
import json
try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: 'requests' library not found. Please install it: pip install requests")
    exit(1)
try:
    import psutil
except ImportError:
    print("Error: 'psutil' library not found. Please install it: pip install psutil")
    exit(1)
try:
    import whois
except ImportError:
    print("Error: 'python-whois' library not found. Please install it: pip install python-whois")
    exit(1)

# --- Utility Functions ---

def resolve_host(target_host):
    """Resolves hostname to IP address, returns IP or None if error."""
    try:
        ip_address = socket.gethostbyname(target_host)
        return ip_address
    except socket.gaierror:
        print(f"Error: Could not resolve hostname: {target_host}")
        return None

# --- Core Functionalities ---

def ping_host(target_host, count=4):
    """
    Pings a host to check for reachability.
    """
    print(f"\n[+] Pinging {target_host}...")
    ip_address = resolve_host(target_host)
    if not ip_address:
        return

    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, str(count), ip_address]

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=15) # 15 seconds timeout for the whole ping process

        if process.returncode == 0:
            print(f"Host {target_host} ({ip_address}) is reachable.")
            print("--- Ping Output ---")
            print(stdout)
            print("-------------------")
        else:
            print(f"Host {target_host} ({ip_address}) is unreachable or request timed out.")
            if stderr:
                print(f"Error details: {stderr}")
            elif stdout: # Some systems put error messages on stdout for ping
                print(f"Output: {stdout}")


    except subprocess.TimeoutExpired:
        print(f"Error: Ping command for {target_host} timed out.")
        if process: process.kill() # Ensure process is killed
    except FileNotFoundError:
        print("Error: 'ping' command not found. Is it in your system's PATH?")
    except Exception as e:
        print(f"An unexpected error occurred during ping: {e}")


def port_scan(target_host, ports_str):
    """
    Scans specified TCP ports on a target host.
    ports_str can be a single port, comma-separated ports, or a range (e.g., "80,443,8080-8090").
    """
    ip_address = resolve_host(target_host)
    if not ip_address:
        return

    print(f"\n[+] Scanning ports on {target_host} ({ip_address})...")

    ports_to_scan = []
    try:
        port_parts = ports_str.split(',')
        for part in port_parts:
            part = part.strip()
            if '-' in part:
                start_port, end_port = map(int, part.split('-'))
                if not (0 < start_port <= 65535 and 0 < end_port <= 65535 and start_port <= end_port):
                    raise ValueError("Invalid port range.")
                ports_to_scan.extend(range(start_port, end_port + 1))
            else:
                port = int(part)
                if not (0 < port <= 65535):
                    raise ValueError("Invalid port number.")
                ports_to_scan.append(port)
        ports_to_scan = sorted(list(set(ports_to_scan))) # Remove duplicates and sort
    except ValueError as e:
        print(f"Error: Invalid port specification: {ports_str}. {e}")
        print("Use comma-separated values (e.g., 80,443) or ranges (e.g., 8000-8010).")
        return

    if not ports_to_scan:
        print("No ports specified for scanning.")
        return

    open_ports = []
    default_timeout = 1 # seconds

    for port in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(default_timeout)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                service_name = "unknown"
                try:
                    service_name = socket.getservbyport(port, "tcp")
                except OSError: # Service not found in local services file
                    pass
                except Exception: # Other potential socket errors
                    pass
                print(f"Port {port}/tcp ({service_name}) is open")
                open_ports.append(port)
            # else:
            #     print(f"Port {port}/tcp is closed or filtered")
            sock.close()
        except socket.error as e:
            print(f"Error connecting to {ip_address}:{port} - {e}")
        except KeyboardInterrupt:
            print("\nUser interrupted port scan.")
            return
        except Exception as e:
            print(f"An unexpected error occurred scanning port {port}: {e}")


    if open_ports:
        print(f"\nSummary: Found {len(open_ports)} open port(s): {', '.join(map(str, open_ports))}")
    else:
        print("\nSummary: No open TCP ports found in the specified range.")


def dns_lookup(hostname):
    """
    Performs a DNS lookup for a hostname.
    """
    print(f"\n[+] Performing DNS lookup for {hostname}...")
    ip_address = resolve_host(hostname)
    if ip_address:
        print(f"Hostname: {hostname}\nIP Address: {ip_address}")

def reverse_dns_lookup(ip_address):
    """
    Performs a reverse DNS lookup for an IP address.
    """
    print(f"\n[+] Performing reverse DNS lookup for {ip_address}...")
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        print(f"IP Address: {ip_address}\nHostname: {hostname}")
    except socket.herror:
        print(f"Error: Could not resolve hostname for IP: {ip_address}")
    except socket.gaierror: # Can happen for invalid IP format
        print(f"Error: Invalid IP address format or address-related error for {ip_address}")

def get_local_ips():
    """
    Displays local IP addresses and MAC addresses for all interfaces.
    """
    print("\n[+] Local Network Interface Information:")
    try:
        hostname = socket.gethostname()
        print(f"  Hostname: {hostname}")
        # This gets an IP that can connect to the internet, might not be all local IPs
        # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # s.connect(("8.8.8.8", 80))
        # print(f"  Primary IP (external routing): {s.getsockname()[0]}")
        # s.close()
    except Exception as e:
        print(f"  Could not determine hostname or primary IP: {e}")

    try:
        interfaces = psutil.net_if_addrs()
        for interface_name, interface_addresses in interfaces.items():
            print(f"\n  Interface: {interface_name}")
            for addr in interface_addresses:
                if addr.family == socket.AF_INET:
                    print(f"    IP Address (IPv4): {addr.address}")
                    print(f"    Netmask (IPv4)   : {addr.netmask}")
                    if addr.broadcast:
                        print(f"    Broadcast (IPv4) : {addr.broadcast}")
                elif addr.family == socket.AF_INET6:
                    print(f"    IP Address (IPv6): {addr.address}")
                    print(f"    Netmask (IPv6)   : {addr.netmask}") # Often None or derived
                elif addr.family == psutil.AF_LINK: # This constant name is platform dependent
                    print(f"    MAC Address      : {addr.address}")
    except Exception as e:
        print(f"Error retrieving interface information: {e}")

def get_mac_address():
    """
    A more focused function to display MAC addresses.
    This is largely covered by get_local_ips, but provided for direct access.
    """
    print("\n[+] MAC Addresses for local interfaces:")
    found_mac = False
    try:
        interfaces = psutil.net_if_addrs()
        for interface_name, interface_addresses in interfaces.items():
            mac_addresses = []
            for addr in interface_addresses:
                if addr.family == psutil.AF_LINK: # psutil.AF_LINK is for MAC addresses
                    mac_addresses.append(addr.address)
            if mac_addresses:
                found_mac = True
                print(f"  Interface: {interface_name}")
                for mac in mac_addresses:
                    print(f"    MAC Address: {mac}")
        if not found_mac:
            print("  No MAC addresses found (or psutil couldn't retrieve them).")
    except Exception as e:
        print(f"Error retrieving MAC addresses: {e}")


def traceroute_host(target_host):
    """
    Traces the route to a host using system's traceroute/tracert.
    """
    ip_address = resolve_host(target_host)
    if not ip_address:
        return

    print(f"\n[+] Tracing route to {target_host} ({ip_address})...")

    command_name = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
    command = [command_name, ip_address]

    try:
        # Use Popen for real-time output if desired, or run for simplicity
        # process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        # for line in iter(process.stdout.readline, ''):
        #     print(line, end='')
        # process.stdout.close()
        # return_code = process.wait()
        # if return_code != 0:
        #     print(f"\nTraceroute command finished with exit code {return_code}")

        # Simpler approach: run and wait
        process = subprocess.run(command, capture_output=True, text=True, timeout=180) # 3 min timeout
        print("--- Traceroute Output ---")
        if process.stdout:
            print(process.stdout)
        if process.stderr:
            print("--- Errors ---")
            print(process.stderr)
        print("-----------------------")
        if process.returncode != 0:
            print(f"Traceroute command may have encountered issues (exit code: {process.returncode}).")

    except subprocess.TimeoutExpired:
        print(f"Error: Traceroute command for {target_host} timed out.")
    except FileNotFoundError:
        print(f"Error: '{command_name}' command not found. Is it in your system's PATH?")
    except Exception as e:
        print(f"An unexpected error occurred during traceroute: {e}")

def http_get_request(url):
    """
    Performs an HTTP GET request to a URL and displays status and headers.
    """
    print(f"\n[+] Performing HTTP GET request to {url}...")
    if not (url.startswith('http://') or url.startswith('https://')):
        print("Warning: URL does not start with http:// or https://. Prepending https://")
        url = 'https://' + url

    try:
        response = requests.get(url, timeout=10, allow_redirects=True, headers={'User-Agent': 'NetAnalyzerTool/1.0'})
        print(f"Status Code: {response.status_code} {response.reason}")
        print("\nHeaders:")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")

        # Optionally print a snippet of the content
        # content_snippet = response.text[:200]
        # print("\nContent Snippet (first 200 chars):")
        # print(content_snippet + "..." if len(response.text) > 200 else content_snippet)

    except RequestException as e:
        print(f"Error during HTTP GET request: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def whois_lookup(domain_or_ip):
    """
    Performs a WHOIS lookup for a domain or IP address.
    """
    print(f"\n[+] Performing WHOIS lookup for {domain_or_ip}...")
    try:
        # The python-whois library can sometimes return a string or a dict
        # depending on the TLD and server. We'll try to handle both.
        w = whois.whois(domain_or_ip)

        if w:
            if hasattr(w, 'text') and w.text and not isinstance(w.text, (dict, list)): # If raw text is prominent
                print(w.text)
            elif isinstance(w, dict): # If it's already a dictionary
                for key, value in w.items():
                    if value: # Only print if there's a value
                        print(f"{str(key).replace('_', ' ').title()}: {value}")
            else: # Fallback for other structures or if w is a complex object
                # Attempt to print common attributes, this might need adjustment
                # based on what python-whois typically returns for various inputs.
                attributes_to_check = ['domain_name', 'registrar', 'whois_server', 'referral_url',
                                       'updated_date', 'creation_date', 'expiration_date',
                                       'name_servers', 'status', 'emails', 'dnssec',
                                       'name', 'org', 'address', 'city', 'state', 'zipcode', 'country']
                printed_something = False
                for attr in attributes_to_check:
                    if hasattr(w, attr):
                        value = getattr(w, attr)
                        if value: # Only print if attribute exists and has a value
                            print(f"{attr.replace('_', ' ').title()}: {value}")
                            printed_something = True
                if not printed_something:
                    print("WHOIS data received, but in an unexpected format. Raw object:")
                    print(w)
        else:
            print(f"No WHOIS information found for {domain_or_ip} or the query failed silently.")

    except whois.parser.WhoisCommandFailed as e:
        print(f"Error: WHOIS command failed: {e}")
    except whois.parser.WhoisPrivateRegistry as e:
        print(f"Error: WHOIS information is private or restricted for {domain_or_ip}: {e}")
    except Exception as e:
        print(f"An error occurred during WHOIS lookup for {domain_or_ip}: {e}")
        print("This could be due to network issues, rate limiting by WHOIS servers, or an unsupported TLD/IP.")


# --- Main Execution & Argument Parsing ---
def main():
    parser = argparse.ArgumentParser(
        description="Network Analysis Tool - A collection of common network utilities.",
        formatter_class=argparse.RawTextHelpFormatter  # Allows for better formatting in help
    )
    subparsers = parser.add_subparsers(dest='command', title='Available commands',
                                       help='Run "net_analyzer.py <command> -h" for more help on a specific command.')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')

    # Ping command
    parser_ping = subparsers.add_parser('ping', help='Ping a host to check reachability.')
    parser_ping.add_argument('host', help='The hostname or IP address to ping.')
    parser_ping.add_argument('-c', '--count', type=int, default=4, help='Number of ping packets to send (default: 4).')

    # Port scan command
    parser_scan = subparsers.add_parser('scan', help='Scan TCP ports on a host.')
    parser_scan.add_argument('host', help='The hostname or IP address to scan.')
    parser_scan.add_argument('ports', help='Ports to scan. E.g., "80", "80,443", "1-1024", "22,80,443,8000-8010".')

    # DNS lookup command
    parser_dns = subparsers.add_parser('dns', help='Resolve hostname to IP address.')
    parser_dns.add_argument('hostname', help='The hostname to resolve.')

    # Reverse DNS lookup command
    parser_rdns = subparsers.add_parser('rdns', help='Resolve IP address to hostname.')
    parser_rdns.add_argument('ip_address', help='The IP address for reverse lookup.')

    # Get local IPs command
    parser_localip = subparsers.add_parser('localinfo', help='Display local machine\'s network interface information (IPs, MACs).')

    # Get MAC address command (can be part of localinfo, but direct access might be useful)
    # parser_mac = subparsers.add_parser('mac', help='Display MAC addresses of local interfaces.')

    # Traceroute command
    parser_trace = subparsers.add_parser('trace', help='Trace the route to a host.')
    parser_trace.add_argument('host', help='The hostname or IP address to trace.')

    # HTTP GET command
    parser_http = subparsers.add_parser('httpget', help='Perform an HTTP GET request to a URL.')
    parser_http.add_argument('url', help='The URL to fetch (e.g., example.com or http://example.com).')

    # WHOIS command
    parser_whois = subparsers.add_parser('whois', help='Perform a WHOIS lookup for a domain or IP.')
    parser_whois.add_argument('domain_or_ip', help='The domain name or IP address for WHOIS lookup.')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == 'ping':
            ping_host(args.host, args.count)
        elif args.command == 'scan':
            port_scan(args.host, args.ports)
        elif args.command == 'dns':
            dns_lookup(args.hostname)
        elif args.command == 'rdns':
            reverse_dns_lookup(args.ip_address)
        elif args.command == 'localinfo':
            get_local_ips()
        # elif args.command == 'mac': # Covered by localinfo
        #     get_mac_address()
        elif args.command == 'trace':
            traceroute_host(args.host)
        elif args.command == 'httpget':
            http_get_request(args.url)
        elif args.command == 'whois':
            whois_lookup(args.domain_or_ip)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting.")
    except Exception as e:
        print(f"An unexpected global error occurred: {e}")


if __name__ == "__main__":
    main()
