"""
tshark extractor for Wireshark MCP.

This module provides packet extraction using tshark, 
the command-line version of Wireshark.
"""

import subprocess
import json
import os
import tempfile
import logging
from typing import List, Dict, Any, Optional, Union

from .base import BaseExtractor

logger = logging.getLogger(__name__)

class TsharkExtractor(BaseExtractor):
    """
    Packet extractor using tshark.
    
    This extractor uses tshark (command-line Wireshark) to extract
    packet data from capture files in various formats.
    """
    
    def __init__(self, tshark_path: str):
        """
        Initialize the tshark extractor.
        
        Args:
            tshark_path: Path to the tshark executable
            
        Raises:
            ValueError: If tshark executable is not found or not executable
        """
        super().__init__()
        self.tshark_path = tshark_path
        
        # Verify tshark is available
        if not os.path.exists(tshark_path) and tshark_path != "tshark":
            raise ValueError(f"tshark executable not found at {tshark_path}")
        
        # Test that tshark can be executed
        try:
            result = subprocess.run(
                [tshark_path, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
            logger.debug(f"tshark version: {result.stdout.splitlines()[0]}")
        except (subprocess.SubprocessError, OSError) as e:
            raise ValueError(f"Error executing tshark: {e}")
    
    def extract_packets(self, 
                       capture_file: str, 
                       filter_str: Optional[str] = None,
                       max_packets: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Extract packets from a capture file using tshark.
        
        Args:
            capture_file: Path to the capture file
            filter_str: Optional Wireshark display filter
            max_packets: Maximum number of packets to extract
            
        Returns:
            List of packet dictionaries
            
        Raises:
            ValueError: If tshark execution fails
        """
        if not os.path.exists(capture_file):
            raise ValueError(f"Capture file not found: {capture_file}")
        
        # Build tshark command
        # NOTE: do NOT pass -x. Hex dumps add companion "*_raw" layers that are
        # lists (not field dicts) and historically crashed packet processing.
        command = [
            self.tshark_path,
            "-r", capture_file,  # Read from file
            "-T", "json",        # Output as JSON
        ]
        
        # Add packet limit if specified
        if max_packets is not None:
            command.extend(["-c", str(max_packets)])
        
        # Add filter if specified
        if filter_str:
            command.extend(["-Y", filter_str])
        
        # Run tshark
        try:
            logger.debug(f"Running tshark command: {' '.join(command)}")
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else "Unknown error"
            raise ValueError(f"tshark execution failed: {error_msg}")
        
        # Parse JSON output
        try:
            packets_json = result.stdout
            if not packets_json:
                return []
                
            packets = json.loads(packets_json)
            
            # Handle different tshark JSON formats
            if isinstance(packets, dict) and "packets" in packets:
                # Newer tshark versions wrap in a "packets" array
                packets = packets["packets"]
            
            # Process and clean up the packet data
            processed_packets = self._process_packets(packets)
            
            return processed_packets
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tshark JSON output: {e}")
            logger.debug(f"tshark stdout: {result.stdout[:500]}...")
            logger.debug(f"tshark stderr: {result.stderr}")
            raise ValueError(f"Failed to parse tshark output: {e}")
            
    @staticmethod
    def _normalize_layer(layer_data: Any) -> Dict[str, Any]:
        """
        Normalize tshark layer data to a dict.

        Newer tshark JSON can emit a layer as a list of objects (e.g. repeated
        protocol instances) instead of a single dict.
        """
        if isinstance(layer_data, dict):
            return layer_data
        if isinstance(layer_data, list):
            merged: Dict[str, Any] = {}
            for item in layer_data:
                if isinstance(item, dict):
                    merged.update(item)
            return merged
        return {}

    @staticmethod
    def _field_value(layer_data: Dict[str, Any], key: str, default: Any = "") -> Any:
        """Return the first value for a tshark field (list or scalar)."""
        value = layer_data.get(key, default)
        if isinstance(value, list):
            return value[0] if value else default
        return default if value is None else value

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[float]:
        """Parse tshark timestamp fields into epoch seconds."""
        if value is None or value == "":
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        # Numeric epoch (possibly with fractional seconds)
        try:
            return float(text)
        except ValueError:
            pass
        # ISO-8601 style (e.g. 2026-06-23T22:09:32.204373000Z)
        try:
            from datetime import datetime
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            # Trim oversized fractional seconds to microseconds
            if "." in text:
                head, rest = text.split(".", 1)
                frac = ""
                tz = ""
                for i, ch in enumerate(rest):
                    if ch.isdigit():
                        frac += ch
                    else:
                        tz = rest[i:]
                        break
                text = f"{head}.{frac[:6]}{tz}"
            return datetime.fromisoformat(text).timestamp()
        except Exception:
            return None

    def _process_packets(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process and clean up packet data from tshark.
        
        Args:
            packets: Raw packet data from tshark
            
        Returns:
            Processed packet data
        """
        processed = []
        
        for packet in packets:
            # Extract layers first so we can pull timestamp from frame fields
            layers = {}
            timestamp = None
            if "_source" in packet and "timestamp" in packet["_source"]:
                timestamp = packet["_source"]["timestamp"]

            if "_source" in packet and "layers" in packet["_source"]:
                raw_layers = packet["_source"]["layers"]
                if not isinstance(raw_layers, dict):
                    processed.append({
                        "timestamp": timestamp or 0.0,
                        "length": 0,
                        "layers": [],
                    })
                    continue
                
                # Process each layer
                for layer_name, layer_data in raw_layers.items():
                    # Skip hex-dump companion layers and any non-dict layer payload.
                    # tshark -x emits e.g. frame_raw as a list; calling .items()
                    # on that raises: 'list' object has no attribute 'items'.
                    if layer_name.endswith("_raw") or isinstance(layer_data, list):
                        continue
                    if not isinstance(layer_data, dict):
                        layers[layer_name] = {"protocol": layer_name.upper()}
                        continue

                    layer_data = self._normalize_layer(layer_data)
                    if not layer_data and layer_name not in ("frame", "eth", "ip", "tcp", "udp", "http"):
                        layers[layer_name] = {"protocol": layer_name.upper()}
                        continue

                    if layer_name == "frame":
                        # Get basic frame information
                        layers["frame"] = {
                            "number": self._field_value(layer_data, "frame.number", "0"),
                            "length": self._field_value(layer_data, "frame.len", "0"),
                            "protocols": self._field_value(layer_data, "frame.protocols", ""),
                        }
                        # Prefer epoch seconds; fall back to relative time
                        epoch = self._field_value(layer_data, "frame.time_epoch", None)
                        relative = self._field_value(layer_data, "frame.time_relative", None)
                        if timestamp is None:
                            timestamp = self._parse_timestamp(epoch) or self._parse_timestamp(relative)
                    elif layer_name == "eth":
                        # Ethernet layer
                        layers["eth"] = {
                            "src": self._field_value(layer_data, "eth.src"),
                            "dst": self._field_value(layer_data, "eth.dst"),
                            "type": self._field_value(layer_data, "eth.type"),
                        }
                    elif layer_name == "ip":
                        # IP layer
                        layers["ip"] = {
                            "src": self._field_value(layer_data, "ip.src"),
                            "dst": self._field_value(layer_data, "ip.dst"),
                            "version": self._field_value(layer_data, "ip.version"),
                            "ttl": self._field_value(layer_data, "ip.ttl"),
                            "protocol": self._field_value(layer_data, "ip.proto"),
                        }
                    elif layer_name == "tcp":
                        # TCP layer
                        flags = {}
                        for flag_name in ["syn", "ack", "fin", "rst", "psh", "urg"]:
                            flag_key = f"tcp.flags.{flag_name}"
                            if flag_key in layer_data:
                                flags[flag_name] = self._field_value(layer_data, flag_key)
                        
                        layers["tcp"] = {
                            "srcport": self._field_value(layer_data, "tcp.srcport"),
                            "dstport": self._field_value(layer_data, "tcp.dstport"),
                            "seq": self._field_value(layer_data, "tcp.seq"),
                            "ack": self._field_value(layer_data, "tcp.ack"),
                            "flags": flags,
                        }
                    elif layer_name == "udp":
                        # UDP layer
                        layers["udp"] = {
                            "srcport": self._field_value(layer_data, "udp.srcport"),
                            "dstport": self._field_value(layer_data, "udp.dstport"),
                            "length": self._field_value(layer_data, "udp.length"),
                        }
                    elif layer_name == "arp":
                        opcode = str(self._field_value(layer_data, "arp.opcode", ""))
                        opcode_name = {
                            "1": "request",
                            "2": "reply",
                        }.get(opcode, f"unknown({opcode})")
                        layers["arp"] = {
                            "protocol": "ARP",
                            "opcode": opcode,
                            "opcode_name": opcode_name,
                            "sender_mac": self._field_value(layer_data, "arp.src.hw_mac"),
                            "sender_ip": self._field_value(layer_data, "arp.src.proto_ipv4"),
                            "target_mac": self._field_value(layer_data, "arp.dst.hw_mac"),
                            "target_ip": self._field_value(layer_data, "arp.dst.proto_ipv4"),
                            "hw_type": self._field_value(layer_data, "arp.hw.type"),
                            "proto_type": self._field_value(layer_data, "arp.proto.type"),
                        }
                    elif layer_name == "bgp":
                        raw_type = self._field_value(layer_data, "bgp.type", "")
                        if isinstance(raw_type, list):
                            types = [str(t) for t in raw_type]
                        else:
                            types = [t.strip() for t in str(raw_type).split(",") if t.strip()]
                        type_names = [
                            {"1": "OPEN", "2": "UPDATE", "3": "NOTIFICATION",
                             "4": "KEEPALIVE", "5": "ROUTE-REFRESH"}.get(t, f"unknown({t})")
                            for t in types
                        ]
                        layers["bgp"] = {
                            "protocol": "BGP",
                            "type": ",".join(types),
                            "types": types,
                            "type_names": type_names,
                            "open_version": self._field_value(layer_data, "bgp.open.version"),
                            "open_my_as": self._field_value(layer_data, "bgp.open.myas"),
                            "open_hold_time": self._field_value(layer_data, "bgp.open.holdtime"),
                            "open_identifier": self._field_value(layer_data, "bgp.open.identifier"),
                            "notify_major": self._field_value(layer_data, "bgp.notify.major_error"),
                            "notify_minor": self._field_value(layer_data, "bgp.notify.minor_error"),
                            "notify_minor_open": self._field_value(layer_data, "bgp.notify.minor_error_open"),
                            "notify_minor_cease": self._field_value(layer_data, "bgp.notify.minor_error_cease"),
                            "notify_communication": self._field_value(layer_data, "bgp.notify.communication"),
                            "nlri_prefix": self._field_value(layer_data, "bgp.nlri_prefix"),
                            "withdrawn_prefix": self._field_value(layer_data, "bgp.withdrawn_prefix"),
                            "next_hop": self._field_value(
                                layer_data, "bgp.update.path_attribute.next_hop"
                            ),
                        }
                    elif layer_name == "http":
                        # HTTP layer - special handling for request/response
                        http_data = {}
                        
                        # Check if this is a request or response
                        if "http.request" in layer_data:
                            http_data["type"] = "request"
                            http_data["method"] = self._field_value(layer_data, "http.request.method")
                            http_data["uri"] = self._field_value(layer_data, "http.request.uri")
                            http_data["version"] = self._field_value(layer_data, "http.request.version")
                        elif "http.response" in layer_data:
                            http_data["type"] = "response"
                            http_data["code"] = self._field_value(layer_data, "http.response.code")
                            http_data["phrase"] = self._field_value(layer_data, "http.response.phrase")
                        
                        # Extract headers
                        headers = {}
                        for key, value in layer_data.items():
                            if not key.startswith("http."):
                                continue
                            header_name = key.replace("http.", "")
                            if header_name in ["request", "response", "request.method",
                                               "request.uri", "request.version",
                                               "response.code", "response.phrase"]:
                                continue
                            first = value[0] if isinstance(value, list) and value else value
                            if first not in (None, ""):
                                headers[header_name] = first
                        
                        http_data["headers"] = headers
                        layers["http"] = http_data
                    else:
                        # Generic layer handling for other protocols
                        # Just store basic info
                        layers[layer_name] = {
                            "protocol": layer_name.upper()
                        }
                        
                        # Add some key layer data without overloading
                        layer_fields = {}
                        for key, value in layer_data.items():
                            if key.startswith("_"):
                                continue
                            first = value[0] if isinstance(value, list) and value else value
                            if first in (None, ""):
                                continue
                            if len(layer_fields) < 10:  # Limit fields per layer
                                layer_fields[key] = first
                        
                        layers[layer_name].update(layer_fields)
            
            # Build final packet structure
            processed_packet = {
                "timestamp": timestamp,
                "length": int(layers.get("frame", {}).get("length", 0) or 0),
                "layers": [],
            }
            
            # Add layer data to the packet
            for layer_name, layer_data in layers.items():
                processed_packet[layer_name] = layer_data
                
                # Also add to layers array for consistent access
                processed_packet["layers"].append({
                    "name": layer_name,
                    "protocol": layer_name.upper(),
                    "data": layer_data
                })
            
            processed.append(processed_packet)
        
        return processed
