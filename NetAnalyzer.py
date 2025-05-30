#!/usr/bin/env python3

import socket
import subprocess
import argparse
import platform
import re
import json

# Attempt to import and initialize colorama for colored output
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True) # autoreset=True ensures color resets after each print
    # Define color constants for convenience
    C_TITLE = Style.BRIGHT + Fore.CYAN
    C_SUCCESS = Fore.GREEN
    C_ERROR = Fore.RED
    C_WARN = Fore.YELLOW
    C_INFO = Fore.BLUE
    C_ACCENT = Fore.MAGENTA # For hostnames, IPs, important values
    C_RESET = Style.RESET_ALL
except ImportError:
    print("Warning: 'colorama' library not found. Output will not be colored. Install it: pip install colorama")
    # Define dummy color constants if colorama is not available
    class DummyColor:
        def __getattr__(self, name):
            return "" # Return empty string for Fore.RED, Style.BRIGHT etc.
        def __add__(self, other): # Support concatenation like Style.BRIGHT + Fore.CYAN
            return ""
    C_TITLE = C_SUCCESS = C_ERROR = C_WARN = C_INFO = C_ACCENT = C_RESET = DummyColor()


try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print(f"{C_ERROR}Error: 'requests' library not found. Please install it: pip install requests{C_RESET}")
    exit(1)
try:
    import psutil
except ImportError:
    print(f"{C_ERROR}Error: 'psutil' library not found. Please install it: pip install psutil{C_RESET}")
    exit(1)
try:
    import whois
except ImportError:
    print(f"{C_ERROR}Error: 'python-whois' library not found. Please install it: pip install python-whois{C_RESET}")
    exit(1)

# --- Utility Functions ---

def resolve_host(target_host):
    """Resolves hostname to IP address, returns IP or None if error."""
    try:
        ip_address = socket.gethostbyname(target_host)
        return ip_address
    except socket.gaierror:
        print(f"{C_ERROR}Error: Could not resolve hostname: {C_ACCENT}{target_host}{C_RESET}")
        return None

# --- Core Functionalities ---

def ping_host(target_host, count=4):
    """
    Pings a host to check for reachability.
    """
    print(f"\n{C_TITLE}[+] Pinging {C_ACCENT}{target_host}{C_TITLE}...{C_RESET}")
    ip_address = resolve_host(target_host)
    if not ip_address:
        return

    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, str(count), ip_address]

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True)
        stdout, stderr = process.communicate(timeout=15)

        if process.returncode == 0:
            print(f"{C_SUCCESS}Host {C_ACCENT}{target_host}{C_SUCCESS} ({C_ACCENT}{ip_address}{C_SUCCESS}) is reachable.{C_RESET}")
            print(f"{C_WARN}--- Ping Output ---{C_RESET}")
            # Print stdout line by line to allow for future selective coloring if desired
            for line in stdout.splitlines():
                print(line)
            print(f"{C_WARN}-------------------{C_RESET}")
        else:
            print(f"{C_ERROR}Host {C_ACCENT}{target_host}{C_ERROR} ({C_ACCENT}{ip_address}{C_ERROR}) is unreachable or request timed out.{C_RESET}")
            if stderr:
                print(f"{C_ERROR}Error details: {stderr.strip()}{C_RESET}")
            elif stdout:
                print(f"{C_INFO}Output: {stdout.strip()}{C_RESET}")

    except subprocess.TimeoutExpired:
        print(f"{C_ERROR}Error: Ping command for {C_ACCENT}{target_host}{C_ERROR} timed out.{C_RESET}")
        if process: process.kill()
    except FileNotFoundError:
        print(f"{C_ERROR}Error: 'ping' command not found. Is it in your system's PATH?{C_RESET}")
    except Exception as e:
        print(f"{C_ERROR}An unexpected error occurred during ping: {e}{C_RESET}")


def port_scan(target_host, ports_str):
    """
    Scans specified TCP ports on a target host.
    """
    ip_address = resolve_host(target_host)
    if not ip_address:
        return

    print(f"\n{C_TITLE}[+] Scanning ports on {C_ACCENT}{target_host}{C_TITLE} ({C_ACCENT}{ip_address}{C_TITLE})...{C_RESET}")

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
        ports_to_scan = sorted(list(set(ports_to_scan)))
    except ValueError as e:
        print(f"{C_ERROR}Error: Invalid port specification: {C_ACCENT}{ports_str}{C_ERROR}. {e}{C_RESET}")
        print(f"{C_INFO}Use comma-separated values (e.g., 80,443) or ranges (e.g., 8000-8010).{C_RESET}")
        return

    if not ports_to_scan:
        print(f"{C_WARN}No ports specified for scanning.{C_RESET}")
        return

    open_ports = []
    default_timeout = 1

    for port in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(default_timeout)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                service_name = "unknown"
                try:
                    service_name = socket.getservbyport(port, "tcp")
                except OSError: pass
                except Exception: pass
                print(f"Port {C_WARN}{port}{C_RESET}/tcp ({C_INFO}{service_name}{C_RESET}) is {C_SUCCESS}open{C_RESET}")
                open_ports.append(port)
            sock.close()
        except socket.error as e:
            print(f"{C_ERROR}Error connecting to {C_ACCENT}{ip_address}{C_ERROR}:{C_WARN}{port}{C_ERROR} - {e}{C_RESET}")
        except KeyboardInterrupt:
            print(f"\n{C_WARN}User interrupted port scan.{C_RESET}")
            return
        except Exception as e:
            print(f"{C_ERROR}An unexpected error occurred scanning port {C_WARN}{port}{C_ERROR}: {e}{C_RESET}")

    if open_ports:
        print(f"\n{C_SUCCESS}Summary: Found {len(open_ports)} open port(s): {C_WARN}{', '.join(map(str, open_ports))}{C_RESET}")
    else:
        print(f"\n{C_INFO}Summary: No open TCP ports found in the specified range.{C_RESET}")


def dns_lookup(hostname):
    """
    Performs a DNS lookup for a hostname.
    """
    print(f"\n{C_TITLE}[+] Performing DNS lookup for {C_ACCENT}{hostname}{C_TITLE}...{C_RESET}")
    ip_address = resolve_host(hostname)
    if ip_address:
        print(f"{C_INFO}Hostname:   {C_ACCENT}{hostname}{C_RESET}")
        print(f"{C_INFO}IP Address: {C_ACCENT}{ip_address}{C_RESET}")

def reverse_dns_lookup(ip_address):
    """
    Performs a reverse DNS lookup for an IP address.
    """
    print(f"\n{C_TITLE}[+] Performing reverse DNS lookup for {C_ACCENT}{ip_address}{C_TITLE}...{C_RESET}")
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        print(f"{C_INFO}IP Address: {C_ACCENT}{ip_address}{C_RESET}")
        print(f"{C_INFO}Hostname:   {C_ACCENT}{hostname}{C_RESET}")
    except socket.herror:
        print(f"{C_ERROR}Error: Could not resolve hostname for IP: {C_ACCENT}{ip_address}{C_RESET}")
    except socket.gaierror:
        print(f"{C_ERROR}Error: Invalid IP address format or address-related error for {C_ACCENT}{ip_address}{C_RESET}")

def get_local_ips():
    """
    Displays local IP addresses and MAC addresses for all interfaces.
    """
    print(f"\n{C_TITLE}[+] Local Network Interface Information:{C_RESET}")
    try:
        system_hostname = socket.gethostname()
        print(f"  {C_INFO}System Hostname: {C_ACCENT}{system_hostname}{C_RESET}")
    except Exception as e:
        print(f"  {C_WARN}Could not determine hostname: {e}{C_RESET}")

    try:
        interfaces = psutil.net_if_addrs()
        for interface_name, interface_addresses in interfaces.items():
            print(f"\n  {C_INFO}Interface: {C_ACCENT}{interface_name}{C_RESET}")
            for addr in interface_addresses:
                if addr.family == socket.AF_INET:
                    print(f"    {C_INFO}IP Address (IPv4): {C_ACCENT}{addr.address}{C_RESET}")
                    if addr.netmask: print(f"    {C_INFO}Netmask (IPv4)   : {C_ACCENT}{addr.netmask}{C_RESET}")
                    if addr.broadcast: print(f"    {C_INFO}Broadcast (IPv4) : {C_ACCENT}{addr.broadcast}{C_RESET}")
                elif addr.family == socket.AF_INET6:
                    # IPv6 addresses can be long, ensure proper display
                    addr_str = addr.address.split('%')[0] # Remove scope ID for cleaner display
                    print(f"    {C_INFO}IP Address (IPv6): {C_ACCENT}{addr_str}{C_RESET}")
                    # Netmask for IPv6 is often represented by prefix length, psutil might give it directly or not
                    if addr.netmask: print(f"    {C_INFO}Netmask (IPv6)   : {C_ACCENT}{addr.netmask}{C_RESET}")
                elif hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK:
                    print(f"    {C_INFO}MAC Address      : {C_ACCENT}{addr.address}{C_RESET}")
    except Exception as e:
        print(f"{C_ERROR}Error retrieving interface information: {e}{C_RESET}")

def traceroute_host(target_host):
    """
    Traces the route to a host using system's traceroute/tracert.
    """
    ip_address = resolve_host(target_host)
    if not ip_address:
        return

    print(f"\n{C_TITLE}[+] Tracing route to {C_ACCENT}{target_host}{C_TITLE} ({C_ACCENT}{ip_address}{C_TITLE})...{C_RESET}")

    command_name = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
    command = [command_name, ip_address]

    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=180, universal_newlines=True)
        print(f"{C_WARN}--- Traceroute Output ({command_name}) ---{C_RESET}")
        if process.stdout:
            for line in process.stdout.splitlines():
                print(line) # Print raw output from command
        if process.stderr:
            print(f"{C_WARN}--- Errors ---{C_RESET}")
            for line in process.stderr.splitlines():
                print(f"{C_ERROR}{line}{C_RESET}")
        print(f"{C_WARN}------------------------------------{C_RESET}")
        if process.returncode != 0:
            print(f"{C_WARN}Traceroute command may have encountered issues (exit code: {process.returncode}).{C_RESET}")

    except subprocess.TimeoutExpired:
        print(f"{C_ERROR}Error: Traceroute command for {C_ACCENT}{target_host}{C_ERROR} timed out.{C_RESET}")
    except FileNotFoundError:
        print(f"{C_ERROR}Error: '{command_name}' command not found. Is it in your system's PATH?{C_RESET}")
    except Exception as e:
        print(f"{C_ERROR}An unexpected error occurred during traceroute: {e}{C_RESET}")

def http_get_request(url):
    """
    Performs an HTTP GET request to a URL and displays status and headers.
    """
    print(f"\n{C_TITLE}[+] Performing HTTP GET request to {C_ACCENT}{url}{C_TITLE}...{C_RESET}")
    original_url = url
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://' + url
        print(f"{C_WARN}Warning: URL did not start with http(s)://. Prepended 'https://'. Using: {C_ACCENT}{url}{C_RESET}")


    try:
        response = requests.get(url, timeout=10, allow_redirects=True, headers={'User-Agent': 'NetAnalyzerTool/1.0'})
        status_color = C_SUCCESS if 200 <= response.status_code < 300 else C_WARN if 300 <= response.status_code < 400 else C_ERROR
        print(f"{C_INFO}Status Code: {status_color}{response.status_code} {response.reason}{C_RESET}")
        if response.url != url and response.url != original_url : # Check if redirected
             print(f"{C_INFO}Redirected to: {C_ACCENT}{response.url}{C_RESET}")


        print(f"\n{C_WARN}Headers:{C_RESET}")
        for key, value in response.headers.items():
            print(f"  {C_INFO}{key}{C_RESET}: {value}")

    except RequestException as e:
        print(f"{C_ERROR}Error during HTTP GET request: {e}{C_RESET}")
    except Exception as e:
        print(f"{C_ERROR}An unexpected error occurred: {e}{C_RESET}")

def whois_lookup(domain_or_ip):
    """
    Performs a WHOIS lookup for a domain or IP address.
    """
    print(f"\n{C_TITLE}[+] Performing WHOIS lookup for {C_ACCENT}{domain_or_ip}{C_TITLE}...{C_RESET}")
    try:
        w = whois.whois(domain_or_ip)

        if w and (w.text or any(getattr(w, attr, None) for attr in w.__dict__ if not attr.startswith('_'))):
            # Prefer structured data if available, otherwise print text
            printed_structured = False
            if isinstance(w, dict): # Some TLDs might return a simple dict
                for key, value in w.items():
                    if value:
                        print(f"{C_INFO}{str(key).replace('_', ' ').title()}{C_RESET}: {value}")
                        printed_structured = True
            else: # Standard whois object
                # Common attributes to prioritize and format nicely
                common_attributes = [
                    'domain_name', 'registrar', 'whois_server', 'referral_url',
                    'updated_date', 'creation_date', 'expiration_date',
                    'name_servers', 'status', 'emails', 'dnssec',
                    'name', 'org', 'address', 'city', 'state', 'zipcode', 'country'
                ]
                for attr in common_attributes:
                    value = getattr(w, attr, None)
                    if value:
                        label = attr.replace('_', ' ').title()
                        if isinstance(value, list):
                            print(f"{C_INFO}{label}{C_RESET}:")
                            for item in value:
                                print(f"  - {item}")
                        else:
                            print(f"{C_INFO}{label}{C_RESET}: {value}")
                        printed_structured = True

                # Print any other non-empty, non-private attributes not covered above
                if not printed_structured and not w.text: # Only if we haven't printed common ones
                    print(f"{C_WARN}--- Other Attributes ---{C_RESET}")
                    for key, value in w.__dict__.items():
                        if not key.startswith('_') and value and key not in common_attributes:
                            print(f"{C_INFO}{key.replace('_', ' ').title()}{C_RESET}: {value}")
                            printed_structured = True


            if not printed_structured and w.text: # Fallback to raw text
                print(f"{C_WARN}--- Raw WHOIS Text ---{C_RESET}")
                print(w.text)
            elif not printed_structured and not w.text:
                 print(f"{C_WARN}WHOIS data received, but it appears to be empty or in an unrecognized format.{C_RESET}")


        else:
            print(f"{C_WARN}No WHOIS information found for {C_ACCENT}{domain_or_ip}{C_WARN} or the query failed silently.{C_RESET}")

    except whois.parser.WhoisCommandFailed as e:
        print(f"{C_ERROR}Error: WHOIS command failed: {e}{C_RESET}")
    except whois.parser.WhoisPrivateRegistry as e:
        print(f"{C_WARN}Notice: WHOIS information is private or restricted for {C_ACCENT}{domain_or_ip}{C_WARN}: {e}{C_RESET}")
    except Exception as e:
        print(f"{C_ERROR}An error occurred during WHOIS lookup for {C_ACCENT}{domain_or_ip}{C_ERROR}: {e}{C_RESET}")
        print(f"{C_INFO}This could be due to network issues, rate limiting, or an unsupported TLD/IP.{C_RESET}")


# --- Main Execution & Argument Parsing ---
def main():
    parser = argparse.ArgumentParser(
        description=f"{C_TITLE}Network Analysis Tool{C_RESET} - A collection of common network utilities.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', title='Available commands',
                                       help=f'Run "{C_ACCENT}net_analyzer.py <command> -h{C_RESET}" for more help.')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {C_SUCCESS}1.1 (Colorized){C_RESET}')

    # Ping command
    parser_ping = subparsers.add_parser('ping', help='Ping a host to check reachability.')
    parser_ping.add_argument('host', help='The hostname or IP address to ping.')
    parser_ping.add_argument('-c', '--count', type=int, default=4, help='Number of ping packets (default: 4).')

    # Port scan command
    parser_scan = subparsers.add_parser('scan', help='Scan TCP ports on a host.')
    parser_scan.add_argument('host', help='The hostname or IP address to scan.')
    parser_scan.add_argument('ports', help='Ports: "80", "80,443", "1-1024", "22,80,443,8000-8010".')

    # DNS lookup command
    parser_dns = subparsers.add_parser('dns', help='Resolve hostname to IP address.')
    parser_dns.add_argument('hostname', help='The hostname to resolve.')

    # Reverse DNS lookup command
    parser_rdns = subparsers.add_parser('rdns', help='Resolve IP address to hostname.')
    parser_rdns.add_argument('ip_address', help='The IP address for reverse lookup.')

    # Get local IPs command
    parser_localip = subparsers.add_parser('localinfo', help='Display local network interface info (IPs, MACs).')

    # Traceroute command
    parser_trace = subparsers.add_parser('trace', help='Trace the route to a host.')
    parser_trace.add_argument('host', help='The hostname or IP address to trace.')

    # HTTP GET command
    parser_http = subparsers.add_parser('httpget', help='Perform an HTTP GET request to a URL.')
    parser_http.add_argument('url', help='URL (e.g., example.com or http://example.com).')

    # WHOIS command
    parser_whois = subparsers.add_parser('whois', help='Perform WHOIS lookup for a domain or IP.')
    parser_whois.add_argument('domain_or_ip', help='Domain name or IP address for WHOIS.')

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
        elif args.command == 'trace':
            traceroute_host(args.host)
        elif args.command == 'httpget':
            http_get_request(args.url)
        elif args.command == 'whois':
            whois_lookup(args.domain_or_ip)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print(f"\n{C_WARN}Process interrupted by user. Exiting.{C_RESET}")
    except Exception as e:
        print(f"{C_ERROR}An unexpected global error occurred: {e}{C_RESET}")


if __name__ == "__main__":
    main()
