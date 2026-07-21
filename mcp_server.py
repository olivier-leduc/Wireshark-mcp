#!/usr/bin/env python3
import argparse
import os
import tempfile
import subprocess
import logging
from typing import List, Dict, Any, Optional

from fastmcp import FastMCP

# Import our Wireshark MCP functionality
from wireshark_mcp import WiresharkMCP, Protocol

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("wireshark-mcp")

mcp = FastMCP(name="wireshark-mcp-server")

# Bump when fixing runtime bugs so responses prove which build Claude loaded.
SERVER_BUILD = "2026-07-21-bgp-analyzer-v1"


@mcp.tool
def capture_live_traffic(
    interface: str = "any",
    duration: int = 10,
    filter: str = "",
    max_packets: int = 100
) -> Dict[str, Any]:
    """
    Capture live network traffic using tshark (Wireshark CLI)

    Args:
        interface: Network interface to capture from (default: "any")
        duration: Capture duration in seconds (default: 10)
        filter: Wireshark display filter (default: "")
        max_packets: Maximum number of packets to capture (default: 100)

    Returns:
        Dict containing the analysis results
    """
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pcap')
    temp_file.close()

    try:
        cmd = [
            "tshark",
            "-i", interface,
            "-a", f"duration:{duration}",
            "-w", temp_file.name,
            "-c", str(max_packets)
        ]

        if filter:
            cmd.extend(["-f", filter])

        logger.info(f"Starting packet capture with command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)

        analyzer = WiresharkMCP(temp_file.name)
        context = analyzer.generate_context(
            max_packets=max_packets,
            include_statistics=True
        )

        return {
            "packet_count": context.get("summary", {}).get("total_packets", 0),
            "protocols": list(context.get("summary", {}).get("protocols", {}).keys()),
            "statistics": context.get("statistics", {}),
            "summary": context.get("summary", {})
        }

    finally:
        if os.path.exists(temp_file.name):
            os.unlink(temp_file.name)


@mcp.tool
def analyze_pcap(
    file_path: str,
    max_packets: int = 100,
    focus_protocols: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Analyze an existing pcap file

    Args:
        file_path: Path to the pcap file
        max_packets: Maximum number of packets to analyze
        focus_protocols: List of protocols to focus on (e.g., ["HTTP", "DNS", "TLS", "ARP", "BGP"])

    Returns:
        Dict containing the analysis results. For ARP/BGP, include focus_protocols=["ARP"]
        or ["BGP"] to populate protocol_data with decoded message fields.
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    protocol_enums = None
    if focus_protocols:
        protocol_enums = []
        for p in focus_protocols:
            try:
                protocol_enums.append(Protocol[p.upper()])
            except KeyError:
                return {"error": f"Unknown protocol: {p}"}
    else:
        # Auto-focus when the filename implies a specific protocol deep-dive.
        lower_name = os.path.basename(file_path).lower()
        if "arp" in lower_name:
            protocol_enums = [Protocol.ARP]
            max_packets = max(max_packets, 5000)
        elif "bgp" in lower_name:
            protocol_enums = [Protocol.BGP]
            max_packets = max(max_packets, 5000)

    try:
        analyzer = WiresharkMCP(file_path)
        context = analyzer.generate_context(
            max_packets=max_packets,
            focus_protocols=protocol_enums,
            include_statistics=True
        )
    except Exception as e:
        logger.exception("Failed to analyze pcap %s", file_path)
        return {"error": f"{type(e).__name__}: {e}", "file_path": file_path}

    protocols = context.get("summary", {}).get("protocols", {})
    if isinstance(protocols, dict):
        protocol_names = list(protocols.keys())
    elif isinstance(protocols, list):
        protocol_names = protocols
    else:
        protocol_names = []

    return {
        "server_build": SERVER_BUILD,
        "file_path": file_path,
        "packet_count": context.get("summary", {}).get("total_packets", 0),
        "protocols": protocol_names,
        "statistics": context.get("statistics", {}),
        "summary": context.get("summary", {}),
        "protocol_data": context.get("protocol_data", {}),
    }


@mcp.tool
def analyze_arp(
    file_path: str,
    max_packets: int = 5000,
) -> Dict[str, Any]:
    """
    Analyze ARP who-has / is-at traffic and report unanswered (lost) requests.

    Decodes opcode, sender/target MAC+IP, matches replies to requests by target IP,
    and lists targets that were queried with no reply.

    Args:
        file_path: Path to the pcap/pcapng file
        max_packets: Maximum ARP packets to examine (default 5000)

    Returns:
        ARP summary including unanswered_requests and answered_requests
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}", "server_build": SERVER_BUILD}

    try:
        analyzer = WiresharkMCP(file_path)
        arp_context = analyzer.extract_protocol(
            Protocol.ARP,
            max_conversations=50,
            max_packets=max_packets,
        )
    except Exception as e:
        logger.exception("Failed ARP analysis for %s", file_path)
        return {
            "error": f"{type(e).__name__}: {e}",
            "file_path": file_path,
            "server_build": SERVER_BUILD,
        }

    return {
        "server_build": SERVER_BUILD,
        "file_path": file_path,
        "protocol": "ARP",
        **arp_context,
    }


@mcp.tool
def analyze_bgp(
    file_path: str,
    max_packets: int = 5000,
) -> Dict[str, Any]:
    """
    Analyze BGP OPEN/UPDATE/NOTIFICATION/KEEPALIVE messages.

    Decodes message types, peer sessions, OPEN parameters (AS/hold/router-id),
    NOTIFICATION major/minor codes, and UPDATE NLRI/withdrawals when present.

    Args:
        file_path: Path to the pcap/pcapng file
        max_packets: Maximum BGP packets to examine (default 5000)

    Returns:
        BGP summary including sessions, notifications, opens, and findings
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}", "server_build": SERVER_BUILD}

    try:
        analyzer = WiresharkMCP(file_path)
        bgp_context = analyzer.extract_protocol(
            Protocol.BGP,
            max_conversations=50,
            max_packets=max_packets,
        )
    except Exception as e:
        logger.exception("Failed BGP analysis for %s", file_path)
        return {
            "error": f"{type(e).__name__}: {e}",
            "file_path": file_path,
            "server_build": SERVER_BUILD,
        }

    return {
        "server_build": SERVER_BUILD,
        "file_path": file_path,
        "protocol": "BGP",
        **bgp_context,
    }


@mcp.tool
def get_protocol_list() -> List[str]:
    """
    Get a list of supported protocols for filtering

    Returns:
        List of protocol names
    """
    return [p.name for p in Protocol]


def main():
    parser = argparse.ArgumentParser(description="Wireshark MCP Server - Direct integration with Claude through Model Context Protocol")
    parser.add_argument("--host", default="127.0.0.1", help="Hostname to bind to (for HTTP transport)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to (for HTTP transport)")
    parser.add_argument("--stdio", action="store_true", help="Use stdio transport instead of HTTP")

    args = parser.parse_args()

    logger.info("Wireshark MCP server build %s (pid=%s)", SERVER_BUILD, os.getpid())
    if args.stdio:
        logger.info("Starting Wireshark MCP server with stdio transport")
        mcp.run()
    else:
        logger.info(f"Starting Wireshark MCP server with HTTP transport on {args.host}:{args.port}")
        mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
