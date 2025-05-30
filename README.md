# Python Network Analysis Tool (NetAnalyzer)

NetAnalyzer is a command-line tool written in Python for performing common network analysis and utility tasks. It's designed to be cross-platform (Windows, macOS, Linux) and easy to use.

## Features

*   **Ping:** Check host reachability.
*   **Port Scan:** Scan for open TCP ports on a target host. Supports single ports, comma-separated lists, and ranges.
*   **DNS Lookup:** Resolve a hostname to its IP address.
*   **Reverse DNS Lookup:** Resolve an IP address to its hostname.
*   **Local Network Info:** Display IP addresses, netmasks, and MAC addresses for all local network interfaces.
*   **Traceroute:** Trace the network path to a remote host (uses the system's `traceroute` or `tracert` command).
*   **HTTP GET Request:** Fetch a URL and display the HTTP status code and response headers.
*   **WHOIS Lookup:** Retrieve WHOIS registration information for a domain name or IP address.

## Prerequisites

*   Python 3.7+
*   `pip` (Python package installer)
*   For `ping` and `traceroute` functionalities, the respective system commands (`ping`, `tracert`/`traceroute`) must be installed and accessible in the system's PATH. This is usually the case by default on most operating systems.

## Installation

1.  **Clone the repository (or download the files):**

    git clone <https://github.com/hacksphere12/NetAnalyzer.git>

    cd NetAnalyzer

3.  **Create a virtual environment (recommended):**

    python -m venv venv
    # On Windows
    venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate

4.  **Install dependencies:**

        pip install -r requirements.txt
        pkg install traceroute


## Usage

The tool uses a command-line interface. You can get help by running:

    python NetAnalyzer.py -h
