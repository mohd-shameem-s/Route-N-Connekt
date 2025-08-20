import os
import socket
import subprocess
import json
import csv
import requests
import asyncio
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
import networkx as nx
import plotly.graph_objects as go
from scapy.all import ARP, Ether, srp, sniff
from pysnmp.hlapi import *
from mac_vendor_lookup import MacLookup
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict, is_dataclass
from typing import List, Dict, Any, Tuple
import wmi
import psutil
import logging
import numpy as np
import networkx as nx
import plotly.graph_objects as go


from mac_vendor_data import MAC_PREFIXES, VENDOR_DEVICE_MAPPING

# Directory for storing images
IMAGE_FOLDER = "./images/"


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str
    vendor: str
    device_type: str
    ip_details: Dict[str, Any]
    bandwidth: int
    latency: int

# Initialize logging
logging.basicConfig(
    filename='vendor_fetch_errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Cache for vendors
VENDOR_CACHE = {}


# def fetch_vendor_from_mac(mac: str) -> str:
#     """
#     Fetch the vendor name for a given MAC address using mac_vendor_lookup or fallback APIs.
#     """
#     mac_prefix = mac.upper().replace(":", "")[:6]

#     # Check the cache first
#     if mac_prefix in VENDOR_CACHE:
#         return VENDOR_CACHE[mac_prefix]

#     # Try the mac_vendor_lookup library
#     try:
#         vendor = MacLookup().lookup(mac)
#         if vendor:
#             VENDOR_CACHE[mac_prefix] = vendor
#             return vendor
#     except Exception as e:
#         logging.error(f"Error using mac_vendor_lookup for {mac}: {e}")

#     # Try a fallback API
#     api_url = f"https://api.macvendors.com/{mac}"
#     try:
#         response = requests.get(api_url, timeout=5)
#         if response.status_code == 200:
#             vendor = response.text.strip()
#             if vendor:
#                 VENDOR_CACHE[mac_prefix] = vendor
#                 return vendor
#     except Exception as e:
#         logging.error(f"Error using macvendors API for {mac}: {e}")

#     # Final fallback
#     VENDOR_CACHE[mac_prefix] = "Unknown Vendor"
#     return "Unknown Vendor"
    
# Get gateway IP
def get_ip_gateway() -> str:
    try:
        result = subprocess.check_output("ipconfig", shell=True).decode()
        for line in result.splitlines():
            if "Default Gateway" in line:
                gateway = line.split(":")[-1].strip()
                if gateway:
                    return gateway
    except Exception as e:
        print(f"Error detecting gateway: {e}")
    return None

# Construct IP range for scanning
def construct_ip_range(gateway: str) -> str:
    if gateway:
        base_ip = ".".join(gateway.split(".")[:-1]) + ".0"
        return f"{base_ip}/24"
    return None

# Resolve hostname
async def get_hostname(ip: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: resolve_hostname(ip))

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip  # Return the IP address if hostname cannot be resolved

# Function to identify vendor and device type
def identify_vendor_and_type(mac: str) -> Tuple[str, str]:
    """
    Identify the vendor and device type based on the MAC address using a mapping.
    """
    # Fetch the vendor
    vendor = fetch_vendor_from_mac(mac)

    # Determine the device type based on the vendor
    device_type = VENDOR_DEVICE_MAPPING.get(vendor, "Unknown Device Type")

    return vendor, device_type


def fetch_device_type_from_api(mac: str) -> str:
    """
    Fetch the device type based on the MAC address using external APIs.
    This implementation is a placeholder for real-world device type mapping APIs.
    """
    try:
        # Use an appropriate API if available (e.g., custom endpoint or database)
        # Placeholder: Returning "Unknown Device Type" for simplicity
        return "Unknown Device Type"
    except Exception as e:
        logging.error(f"Error fetching device type for {mac}: {e}")
        return "Unknown Device Type"
    
def fetch_vendor_from_mac(mac: str) -> str:
    """
    Fetch the vendor name for a given MAC address using external APIs or local cache.
    """
    mac_prefix = mac.upper().replace(":", "")[:6]

    # Check the cache first
    if mac_prefix in VENDOR_CACHE:
        return VENDOR_CACHE[mac_prefix]

    # Try the macvendors.com API
    try:
        api_url = f"https://api.macvendors.com/{mac}"
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            vendor = response.text.strip()
            VENDOR_CACHE[mac_prefix] = vendor
            return vendor
    except Exception as e:
        logging.error(f"Error using macvendors API for {mac}: {e}")

    # Fall back to parsing the OUI file
    try:
        oui_url = "https://standards-oui.ieee.org/oui/oui.txt"
        oui_response = requests.get(oui_url, timeout=10)
        if oui_response.status_code == 200:
            lines = oui_response.text.splitlines()
            for line in lines:
                if mac_prefix in line:
                    vendor = line.split("\t")[-1].strip()
                    VENDOR_CACHE[mac_prefix] = vendor
                    return vendor
    except Exception as e:
        logging.error(f"Error parsing OUI data for {mac}: {e}")

    # Final fallback
    VENDOR_CACHE[mac_prefix] = "Unknown Vendor"
    return "Unknown Vendor"

# Function to fetch device information in parallel
def fetch_device_info_in_parallel(macs: List[str]) -> List[Tuple[str, str]]:
    """
    Fetch vendor and device type information for a list of MAC addresses in parallel.

    Parameters:
        macs (List[str]): List of MAC addresses.

    Returns:
        List[Tuple[str, str]]: List of tuples containing (Vendor Name, Device Type).
    """
    results = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(identify_vendor_and_type, mac): mac for mac in macs}
        for future in futures:
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                mac = futures[future]
                logging.error(f"Error fetching device info for {mac}: {e}")
    return results

# Fetch subnet mask and default gateway
def get_ip_details(ip: str) -> Dict[str, str]:
    try:
        result = subprocess.check_output(["ipconfig"], shell=True).decode()
        details = {"Subnet Mask": None, "Default Gateway": None}
        
        # Split the output into lines for easier processing
        lines = result.splitlines()
        for line in lines:
            if ip in line:
                # Look for the next lines to find Subnet Mask and Default Gateway
                for next_line in lines[lines.index(line):]:
                    if "Subnet Mask" in next_line:
                        details["Subnet Mask"] = next_line.split(":")[-1].strip()
                    if "Default Gateway" in next_line:
                        details["Default Gateway"] = next_line.split(":")[-1].strip()
                    # Break if both details are found
                    if details["Subnet Mask"] and details["Default Gateway"]:
                        break
                break

        # If Subnet Mask and Default Gateway are not found, try to find them in the output
        if not details["Subnet Mask"] or not details["Default Gateway"]:
            for line in lines:
                if "Subnet Mask" in line:
                    details["Subnet Mask"] = line.split(":")[-1].strip()
                if "Default Gateway" in line:
                    details["Default Gateway"] = line.split(":")[-1].strip()

        return details
    except Exception as e:
        print(f"Error fetching IP details: {e}")
        return {"Subnet Mask": "Unknown", "Default Gateway": "Unknown"}

# Scan network for devices
async def async_scan_network(ip_range: str) -> List[Device]:
    """
    Scan the network for devices using ARP requests.
    
    Parameters:
        ip_range (str): IP range to scan (e.g., "192.168.1.0/24").
    
    Returns:
        List[Device]: List of detected devices with details.
    """
    try:
        devices = []
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as pool:
            results = await loop.run_in_executor(pool, lambda: srp(packet, timeout=3, verbose=False)[0])

        tasks = [fetch_device_info(received) for _, received in results]
        devices = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out any errors from the results
        devices = [device for device in devices if isinstance(device, Device)]
        return devices
    except Exception as e:
        print(f"Error scanning network: {e}")
        return []


async def fetch_device_info(received) -> Device:
    mac = received.hwsrc
    ip = received.psrc
    hostname = await get_hostname(ip)
    vendor, device_type = identify_vendor_and_type(mac)
    ip_details = get_ip_details(ip)

    return Device(
        ip=ip,
        mac=mac,
        hostname=hostname,
        vendor=vendor,
        device_type=device_type,
        ip_details=ip_details,
        bandwidth=np.random.randint(1, 100),
        latency=np.random.randint(1, 50)
    )


# Capture LLDP packets
def capture_lldp(interface: str = "Ethernet") -> List[Dict[str, str]]:
    print("Capturing LLDP packets...")
    try:
        packets = sniff(iface=interface, filter="ether proto 0x88cc", timeout=5, count=10)
        neighbors = []
        for packet in packets:
            if packet.haslayer(Ether):
                neighbors.append({
                    "Neighbor MAC": packet[Ether].src,
                    "Neighbor Info": packet.summary(),
                })
        if not neighbors:
            print("No LLDP neighbors found.")
        return neighbors if neighbors else [{"status": "No LLDP neighbors found."}]
    except Exception as e:
        print(f"Error capturing LLDP packets: {e}")
        return [{"status": "Error capturing LLDP packets."}]


# Get ARP table
def get_arp_table() -> str:
    """
    Retrieve the current ARP table of the system.
    
    Returns:
        str: The ARP table output as a string.
    """
    try:
        arp_table = subprocess.check_output("arp -a", shell=True).decode()
        return arp_table
    except subprocess.CalledProcessError as e:
        print(f"Error fetching ARP table: {e}")
        return ""


import asyncio
import wmi
from typing import List, Dict, Any


async def check_ports_concurrently(ip: str, ports: List[int]) -> List[Dict[str, Any]]:
    """
    Check multiple ports concurrently to determine if they are open.

    Parameters:
        ip (str): The IP address to check.
        ports (List[int]): List of ports to check.

    Returns:
        List[Dict[str, Any]]: List of dictionaries containing port status.
    """
    async def check_port(ip: str, port: int) -> Dict[str, Any]:
        """Check if a specific port is open."""
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            writer.close()
            await writer.wait_closed()
            return {"Port": port, "Status": "Open", "Description": f"RPC service running on port {port}"}
        except Exception:
            return {"Port": port, "Status": "Closed"}

    tasks = [check_port(ip, port) for port in ports]
    return await asyncio.gather(*tasks)

#RPC Endpoints
def get_rpc_endpoints() -> List[Dict[str, Any]]:
    rpc_endpoints = []
    try:
        # Use WMI to fetch running processes
        c = wmi.WMI()
        processes = c.Win32_Process()
        
        if not processes:
            rpc_endpoints.append({"status": "No active processes found."})
        
        for process in processes:
            user = process.GetOwner()[0] if process.GetOwner() else "Unknown"
            rpc_endpoints.append({
                "ProcessID": process.ProcessId,
                "Name": process.Name,
                "CommandLine": process.CommandLine,
                "User ": user  # Get the owner of the process
            })

        # Check specific RPC-related ports
        rpc_ports = [135, 593]
        port_results = asyncio.run(check_ports_concurrently("localhost", rpc_ports))
        rpc_endpoints.extend(port_results)

    except Exception as e:
        print(f"Error fetching RPC endpoints: {e}")
        rpc_endpoints.append({"status": "Error fetching RPC endpoints."})

    return rpc_endpoints if rpc_endpoints else [{"status": "No RPC endpoints found."}]


#Open Ports Detection
async def check_port(ip, port):
    """Check if a port is open."""
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

async def scan_open_ports(ip, port_range=(1, 1024)):
    """Scan open ports within a range."""
    tasks = [check_port(ip, port) for port in range(port_range[0], port_range[1] + 1)]
    results = await asyncio.gather(*tasks)
    return [port for port in results if port]

#System Interface Connectors
def get_system_interfaces():
    """Retrieve physical and virtual interface details."""
    interfaces = []
    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        for iface, addrs in net_if_addrs.items():
            stats = net_if_stats.get(iface, None)
            interfaces.append({
                "Interface": iface,
                "Addresses": [addr.address for addr in addrs],
                "IsUp": stats.isup if stats else None,
                "Speed (Mbps)": stats.speed if stats else None,
                "MTU": stats.mtu if stats else None
            })
    except Exception as e:
        print(f"Error fetching interfaces: {e}")
    return interfaces

#Device-Specific Integration (SNMP Querying)
def snmp_query(ip, oid, community="public", port=161):
    """Perform an SNMP GET query."""
    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, port)),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
        )
        if error_indication or error_status:
            print(f"SNMP error: {error_indication or error_status.prettyPrint()}")
            return None
        for var_bind in var_binds:
            return f"{var_bind.prettyPrint()}"
    except Exception as e:
        print(f"Error performing SNMP query: {e}")
        return None

# Get DNS cache entries
def get_dns_cache() -> List[str]:
    try:
        # Use ipconfig to fetch DNS cache entries
        dns_cache_output = subprocess.check_output("ipconfig /displaydns", shell=True).decode()
        # Parse the output to extract DNS entries
        dns_entries = []
        for line in dns_cache_output.splitlines():
            if line.strip() and not line.startswith("Windows IP Configuration"):
                dns_entries.append(line.strip())
        return dns_entries if dns_entries else ["No DNS entries found."]
    except Exception as e:
        print(f"Error fetching DNS cache: {e}")
        return ["Error fetching DNS cache."]

# Get Windows network profiles
def get_network_profiles() -> str:
    try:
        profiles = subprocess.check_output("netsh wlan show profiles", shell=True).decode()
        return profiles
    except Exception as e:
        print(f"Error fetching network profiles: {e}")
        return ""
    
# Get network shares
def get_network_shares():
    try:
        shares = subprocess.check_output("net share", shell=True).decode()
        return shares
    except Exception as e:
        print(f"Error fetching network shares: {e}")
        return ""

# Get current TCP and UDP connections
def get_connections() -> List[Dict[str, Any]]:
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        connections.append({
            "local_address": conn.laddr,
            "remote_address": conn.raddr,
            "status": conn.status,
            "pid": conn.pid
        })
    return connections

# Generate network topology graph
def generate_topology(devices: List[Device]) -> nx.Graph:
    graph = nx.Graph()
    central_node = "Router"
    graph.add_node(central_node, type="central", device_type="Router")

    for device in devices:
        label = f"{device.hostname} ({device.ip})\n{device.mac}\n{device.vendor}"
        graph.add_node(
            label,
            type="device",
            device_type=device.device_type if device.device_type else "Unknown"
        )
        graph.add_edge(central_node, label)
    
    return graph


# Detect network topology based on connections
def detect_topology(devices, graph):
    try:
        degrees = [deg for _, deg in graph.degree()]
        num_nodes = len(degrees)

        if degrees.count(max(degrees)) == 1 and degrees.count(1) == num_nodes - 1:
            return "Star"
        elif all(deg <= 2 for deg in degrees):
            return "Bus"
        elif all(deg == num_nodes - 1 for deg in degrees):
            return "Mesh"
        elif degrees.count(2) == num_nodes:
            return "Ring"
        elif degrees.count(1) == num_nodes - 1 and degrees.count(max(degrees)) == 1:
            return "Tree"
        elif any(deg > 2 for deg in degrees) and any(deg == 1 for deg in degrees):
            return "Hybrid"

        return "Complex"
    except Exception as e:
        print(f"Error detecting topology: {e}")
        return "Unknown"


# Apply layout based on detected topology
def apply_topology_layout(graph, topology_type):
    if topology_type == "Star":
        layout = nx.shell_layout(graph)
    elif topology_type == "Bus":
        layout = nx.spring_layout(graph, k=0.5)
    elif topology_type == "Ring":
        layout = nx.circular_layout(graph)
    elif topology_type == "Mesh":
        layout = nx.spring_layout(graph, k=0.15)
    elif topology_type == "Hybrid":
        layout = nx.spring_layout(graph)
    else:
        layout = nx.spring_layout(graph)
    
    nx.set_node_attributes(graph, layout, "pos")
    

# Load icons based on device type
def load_icon(device_type):
    icon_map = {
        "Router": "router.png",
        "Laptop": "laptop.png",
        "Mobile": "mobile.png",
        "Tower": "tower.png",
        "Unknown": "laptop.png"  # Default unknown = laptop.png
    }
    
    icon_file = icon_map.get(device_type, "laptop.png")
    path = os.path.join(IMAGE_FOLDER, icon_file)
    
    if os.path.exists(path):
        return OffsetImage(plt.imread(path), zoom=0.1)
    else:
        print(f"Icon file not found: {path}. Using laptop.png as default.")
        return OffsetImage(plt.imread(os.path.join(IMAGE_FOLDER, "laptop.png")), zoom=0.1)


# Draw matplotlib network
def draw_network(graph, devices, topology_type):
    pos = nx.spring_layout(graph, k=0.8)
    fig, ax = plt.subplots(figsize=(12, 8))

    # Central node
    central_node = max(graph.nodes, key=graph.degree)
    central_device_type = graph.nodes[central_node].get("device_type", "Router")

    central_icon = load_icon(central_device_type)
    if central_icon:
        ab = AnnotationBbox(central_icon, pos[central_node], frameon=False)
        ax.add_artist(ab)
    ax.text(pos[central_node][0], pos[central_node][1], central_node,
            fontsize=6, ha="center")

    # Other nodes
    for node, (x, y) in pos.items():
        if node == central_node:
            continue
        node_type = graph.nodes[node].get("device_type", "Unknown")
        icon = load_icon(node_type)
        if icon:
            ab = AnnotationBbox(icon, (x, y), frameon=False)
            ax.add_artist(ab)
        ax.text(x, y, node, fontsize=6, ha="center")

    # Edge coloring rules
    edge_colors = []
    for source, target in graph.edges():
        src_type = graph.nodes[source].get("device_type", "Unknown")
        tgt_type = graph.nodes[target].get("device_type", "Unknown")

        if src_type == "Router" and tgt_type == "Router":
            edge_colors.append("red")
        elif "Router" in (src_type, tgt_type) and "Mobile" in (src_type, tgt_type):
            edge_colors.append("blue")
        elif "Router" in (src_type, tgt_type) and "Laptop" in (src_type, tgt_type):
            edge_colors.append("green")
        elif "Router" in (src_type, tgt_type) and "Unknown" in (src_type, tgt_type):
            edge_colors.append("yellow")
        else:
            edge_colors.append("lightgray")

    # Draw edges
    nx.draw_networkx_edges(graph, pos, edge_color=edge_colors, width=1.5, ax=ax)

    # Add dark green dots at edge midpoints
    for source, target in graph.edges():
        x_values, y_values = zip(pos[source], pos[target])
        mid_x, mid_y = (x_values[0] + x_values[1]) / 2, (y_values[0] + y_values[1]) / 2
        ax.plot(mid_x, mid_y, "o", color="darkgreen", markersize=5)

    # Titles
    plt.suptitle("Route-N-Connekt", fontsize=24, fontweight='bold',
                 color='navy', fontname='Atc Garnet')
    plt.title(f"Network Topology: {topology_type}", fontsize=14, color='gray')
    plt.axis("off")
    plt.savefig("network_topology.jpg", dpi=300, bbox_inches='tight')
    plt.show()




# Interactive visualization in Plotly
class Device:
    def __init__(self, hostname, ip, mac, vendor, ip_details, device_type, bandwidth, latency):
        self.hostname = hostname
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.ip_details = ip_details
        self.device_type = device_type
        self.bandwidth = bandwidth
        self.latency = latency

import plotly.graph_objects as go
import numpy as np
import networkx as nx
import os

def interactive_visualization_3d(devices, topology_type):
    fig = go.Figure()
    edges = []
    nodes = []

    if topology_type == "Star":
        central_node = devices[0]
        nodes.append(go.Scatter3d(
            x=[0], y=[0], z=[0],
            mode='markers+text',
            text=[f"{central_node.hostname}"],
            hovertemplate=(f"Hostname: {central_node.hostname}<br>"
                           f"IP: {central_node.ip}<br>"
                           f"MAC: {central_node.mac}<br>"
                           f"Vendor: {central_node.vendor}<br>"
                           f"IP Details: {central_node.ip_details}<br>"
                           f"Device Type: {central_node.device_type}<br>"
                           f"Bandwidth: {central_node.bandwidth}<br>"
                           f"Latency: {central_node.latency} ms"),
            marker=dict(size=20, color='red', opacity=0.8, symbol='diamond'),
            name=f"{central_node.hostname}"
        ))

        num_devices = len(devices) - 1
        angles = np.linspace(0, 2 * np.pi, num_devices, endpoint=False)
        radius = 3

        for i, device in enumerate(devices[1:]):
            x = radius * np.cos(angles[i]) + np.random.uniform(-0.5, 0.5)
            y = radius * np.sin(angles[i]) + np.random.uniform(-0.5, 0.5)
            z = np.random.uniform(-1, 1)

            edge_color = 'rgba(144,238,144,0.8)' if device.device_type in ["Laptop", "Mobile"] else 'pink'

            edges.append(go.Scatter3d(
                x=[0, x], y=[0, y], z=[0, z],
                mode='lines',
                line=dict(color=edge_color, width=2),
                showlegend=False
            ))

            node_color = {
                "Laptop": 'rgb(138,43,226)',
                "Mobile": 'rgb(255,255,0)',
                "Router": 'rgb(255,69,0)',
                "Unknown": 'rgb(255,165,0)'
            }.get(device.device_type, 'rgb(30,144,255)')

            nodes.append(go.Scatter3d(
                x=[x], y=[y], z=[z],
                mode='markers+text',
                text=[f"{device.hostname}"],
                hovertemplate=(f"Hostname: {device.hostname}<br>"
                               f"IP: {device.ip}<br>"
                               f"MAC: {device.mac}<br>"
                               f"Vendor: {device.vendor}<br>"
                               f"IP Details: {device.ip_details}<br>"
                               f"Device Type: {device.device_type}<br>"
                               f"Bandwidth: {device.bandwidth}<br>"
                               f"Latency: {device.latency} ms"),
                marker=dict(size=12, color=node_color, opacity=0.9, symbol='circle'),
                name=f"{device.hostname}"
            ))

    elif topology_type == "Mesh":
        G = nx.Graph()
        G.add_nodes_from([device.ip for device in devices])
        for i in range(len(devices)):
            for j in range(i + 1, len(devices)):
                G.add_edge(devices[i].ip, devices[j].ip)

        pos = nx.spring_layout(G, dim=3, seed=42)

        for edge in G.edges:
            device1 = next(device for device in devices if device.ip == edge[0])
            device2 = next(device for device in devices if device.ip == edge[1])
            edge_color = 'rgba(144,238,144,0.8)' if "Laptop" in {device1.device_type, device2.device_type} or "Mobile" in {device1.device_type, device2.device_type} else 'pink'

            edges.append(go.Scatter3d(
                x=[pos[edge[0]][0], pos[edge[1]][0]],
                y=[pos[edge[0]][1], pos[edge[1]][1]],
                z=[pos[edge[0]][2], pos[edge[1]][2]],
                mode='lines',
                line=dict(color=edge_color, width=2),
                showlegend=False
            ))

        for device in devices:
            node_color = {
                "Laptop": 'rgb(138,43,226)',
                "Mobile": 'rgb(255,255,0)',
                "Router": 'rgb(255,69,0)',
                "Unknown": 'rgb(255,165,0)'
            }.get(device.device_type, 'rgb(30,144,255)')

            nodes.append(go.Scatter3d(
                x=[pos[device.ip][0]],
                y=[pos[device.ip][1]],
                z=[pos[device.ip][2]],
                mode='markers+text',
                text=[f"{device.hostname}"],
                hovertemplate=(f"Hostname: {device.hostname}<br>"
                               f"IP: {device.ip}<br>"
                               f"MAC: {device.mac}<br>"
                               f"Vendor: {device.vendor}<br>"
                               f"IP Details: {device.ip_details}<br>"
                               f"Device Type: {device.device_type}<br>"
                               f"Bandwidth: {device.bandwidth}<br>"
                               f"Latency: {device.latency} ms"),
                marker=dict(size=12, color=node_color),
                name=f"{device.hostname}"
            ))

    # Add edges and nodes
    for edge in edges:
        fig.add_trace(edge)
    for node in nodes:
        fig.add_trace(node)

    # Apply layout and UI updates
    fig.update_layout(
        title={
            "text": "Route–N–Connekt<br><sup>Network Topology: " + topology_type + "</sup>",
            "y": 0.95,
            "x": 0.5,
            "xanchor": "center",
            "yanchor": "top",
            "font": dict(size=24, color="white", family="Atc Garnet")
        },
        paper_bgcolor="#1e1e1e",
        plot_bgcolor="#1e1e1e",
        font=dict(color="white"),
        scene=dict(
            xaxis=dict(showbackground=True, backgroundcolor="#1e1e1e", color="white", gridcolor="lightblue"),
            yaxis=dict(showbackground=True, backgroundcolor="#1e1e1e", color="white", gridcolor="lightblue"),
            zaxis=dict(showbackground=True, backgroundcolor="#1e1e1e", color="white", gridcolor="lightblue"),
        ),
        showlegend=True,
        hovermode="closest",
        legend=dict(
            title="Hostnames",
            orientation="v",
            x=1.02,
            y=1,
            xanchor="left",
            yanchor="top",
            font=dict(color="white"),
            bgcolor="rgba(0,0,0,0)"
        ),
        updatemenus=[
            dict(
                type="buttons",
                showactive=True,
                buttons=[
                    dict(
                        label="Rotate",
                        method="animate",
                        args=[None, {"frame": {"duration": 200, "redraw": True}, "fromcurrent": True}]
                    )
                ],
                x=0.05,
                y=0.95,
                bgcolor="white",
                bordercolor="black",
                font=dict(color="black")
            )
        ]
    )

    os.makedirs("results", exist_ok=True)
    fig.write_html("results/interactive_topology.html")
    fig.show()



# Save results
def save_results(devices: List):
    if not devices:
        print("No devices found to save.")
        return

    # Ensure all items are valid dataclass instances
    valid_devices = [device for device in devices if is_dataclass(device)]
    if len(valid_devices) != len(devices):
        print("⚠️  Warning: Some items in the devices list are not valid dataclass instances. They were skipped.")

    if not valid_devices:
        print("No valid device dataclass instances to save.")
        return

    os.makedirs("results", exist_ok=True)

    # Save to JSON
    json_path = os.path.join("results", "network_devices.json")
    with open(json_path, "w") as json_file:
        json.dump({"devices": [asdict(device) for device in valid_devices]}, json_file, indent=4)

    # Save to CSV
    csv_path = os.path.join("results", "network_devices.csv")
    with open(csv_path, "w", newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=valid_devices[0].__dict__.keys())
        writer.writeheader()
        writer.writerows([asdict(device) for device in valid_devices])

    print("Devices and topology type saved as JSON and CSV files in the 'results' directory.")



# Function to save additional network information to a JSON file
def save_additional_network_info(arp_table, dns_cache, network_profiles, network_shares, connections):
    additional_info = {
        "arp_table": arp_table,
        "dns_cache": dns_cache,
        "network_profiles": network_profiles,
        "network_shares": network_shares,
        "connections": connections
    }

    os.makedirs("results", exist_ok=True)
    with open("results/additional_network_info.json", "w") as json_file:
        json.dump(additional_info, json_file, indent=4)

    print("Additional network information saved in results/additional_network_info.json.")


def save_terminal_output_to_json(terminal_data, existing_data_file="results/network_devices.json"):
    try:
        with open(existing_data_file, "r") as json_file:
            existing_data = json.load(json_file)
            existing_devices = {device['mac'] for device in existing_data.get('devices', [])}
    except FileNotFoundError:
        existing_devices = set()

    new_data = [entry for entry in terminal_data if entry['mac'] not in existing_devices]

    if new_data:
        os.makedirs("results", exist_ok=True)
        structured_data = {"devices": new_data}
        with open("results/terminal_output.json", "w") as json_file:
            json.dump(structured_data, json_file, indent=4)
        print("Terminal output saved in results/terminal_output.json.")
    else:
        print("No new data to save from terminal output.")




# Main function
async def main():
    # Get local machine's hostname and IP address
    local_hostname = socket.gethostname()
    local_ip = socket.gethostbyname(local_hostname)
    
    print("Welcome to Route-N-Connekt!")
    print(f"Running on Hostname: {local_hostname}")
    print(f"Local IP Address: {local_ip}")
    print(f"Scanning Devices... Please Wait...!")

    # Initialize network information dictionary
    network_info = {
        "hostname": local_hostname,
        "local_ip": local_ip,
        "devices": [],
        "arp_table": "",
        "dns_cache": [],
        "network_profiles": "",
        "network_shares": "",
        "connections": [],
        "rpc_endpoints": [],
        "open_ports": [],
        "interface_connectors": [],
        "lldp_neighbors": [],
    }

    # Fetch gateway and construct IP range
    gateway = get_ip_gateway()
    if not gateway:
        print("No active gateway detected.")
        return

    ip_range = construct_ip_range(gateway)
    if not ip_range:
        print("Failed to construct IP range.")
        return

    # 1. Scan the network for devices
    devices = await async_scan_network(ip_range)
    network_info["devices"] = devices

    # Display device information
    print(f"Devices Found: {len(devices)}")
    for idx, device in enumerate(devices, 1):
        if isinstance(device, Device):
            print(f"{idx}. IP: {device.ip}, MAC: {device.mac}, Hostname: {device.hostname}, "
                  f"Vendor: {device.vendor}, Device Type: {device.device_type}, "
                  f"Bandwidth: {device.bandwidth} Mbps , Latency: {device.latency} ms")
        else:
            print(f"{idx}. Invalid device: {device}")

    # 2. Fetch additional network information
    network_info["arp_table"] = get_arp_table() or "No ARP entries found."
    network_info["dns_cache"] = get_dns_cache() or ["No DNS entries found."]
    network_info["network_profiles"] = get_network_profiles() or "No network profiles found."
    network_info["network_shares"] = get_network_shares() or "No network shares found."
    network_info["connections"] = get_connections() or [{"status": "No connections found."}]
    network_info["rpc_endpoints"] = get_rpc_endpoints() or [{"status": "No RPC endpoints found."}]

    print("ARP Table:", network_info["arp_table"])
    print("DNS Cache Entries:", network_info["dns_cache"])
    print("Network Profiles:", network_info["network_profiles"])
    print("Network Shares:", network_info["network_shares"])
    print("TCP/UDP Connections:", network_info["connections"])
    print("RPC Endpoints:", network_info["rpc_endpoints"])

    # 3. Port Scanning
    open_ports = await scan_open_ports(local_ip)
    network_info["open_ports"] = open_ports or [0]  # Default to a list with a single entry if no open ports are found
    print(f"Open Ports on {local_ip}: {network_info['open_ports']}")

    # 4. Interface Connectors
    interfaces = get_system_interfaces()
    network_info["interface_connectors"] = interfaces or [{"status": "No interfaces found."}]
    print("System Interfaces:", network_info["interface_connectors"])

    # 5. LLDP Connections
    lldp_neighbors = capture_lldp()
    network_info["lldp_neighbors"] = lldp_neighbors or [{"status": "No LLDP neighbors found."}]
    print("LLDP Neighbors:", network_info["lldp_neighbors"])

    # 6. Network Topology and Visualization
    graph = generate_topology(devices)
    topology_type = detect_topology(devices, graph)
    print(f"Topology Type: {topology_type}")

    apply_topology_layout(graph, topology_type)
    draw_network(graph, devices, topology_type)  # Static visualization

    interactive_visualization_3d(devices, topology_type)  # Interactive visualization

    # Ensure the 'results' directory exists
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)
    
    # Save devices to a JSON file
    with open(os.path.join(results_dir, "devices.json"), "w") as devices_file:
        json.dump([device.__dict__ for device in devices if isinstance(device, Device)], devices_file, indent=4)
    
    # Save topology type to a JSON file
    with open(os.path.join(results_dir, "topology_type.json"), "w") as topology_file:
        json.dump({"topology_type": topology_type}, topology_file, indent=4)
    
    print("Devices and topology type saved as JSON files in the 'results' directory.")

    # 7. Save results
    save_results(devices)
    save_additional_network_info(
        network_info["arp_table"],
        network_info["dns_cache"],
        network_info["network_profiles"],
        network_info["network_shares"],
        network_info["connections"]
    )

    print("Network information saved successfully.")

if __name__ == "__main__":
    asyncio.run(main())
    
    
    
    
    
    