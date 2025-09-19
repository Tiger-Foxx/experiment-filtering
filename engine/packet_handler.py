#!/usr/bin/env python3
"""
Packet Handler for NFQUEUE
Handles real packet processing and decision making
"""

import time
import logging
from typing import Dict, Any, List, Tuple
import netfilterqueue
import scapy.all as scapy

from engine.rule_engine import FilterEngine
from engine.metrics import MetricsCollector
from rules.rule_loader import Rule

logger = logging.getLogger(__name__)


class PacketHandler:
    def __init__(self, rules_by_layer: Dict[int, List[Rule]], mode: str, metrics: MetricsCollector):
        self.rules_by_layer = rules_by_layer
        self.mode = mode  # 'sequential' or 'hybrid'
        self.metrics = metrics
        
        # Initialize components
        self.filter_engine = FilterEngine(rules_by_layer, max_workers=8)
        
        # Stats
        self.packet_count = 0
        self.drop_count = 0
        self.accept_count = 0
        
        logger.info(f"PacketHandler initialized in {mode} mode")
    
    def process_packet(self, packet: netfilterqueue.NetfilterPacket):
        """
        Main packet processing function called by NFQUEUE
        This is where the REAL network filtering happens
        """
        start_time = time.perf_counter()
        self.packet_count += 1
        
        try:
            # Get raw packet data
            raw_packet = packet.get_payload()
            
            # Parse packet using Scapy (optimized for NFQUEUE)
            parsed_packet = self._parse_packet_scapy(raw_packet)
            
            # Apply filtering based on mode
            if self.mode == 'sequential':
                action, rule_id, decision_time = self.filter_engine.filter_sequential(parsed_packet)
            elif self.mode == 'hybrid':
                action, rule_id, decision_time = self.filter_engine.filter_hybrid(parsed_packet)
            else:
                logger.error(f"Unknown mode: {self.mode}")
                packet.accept()
                return
            
            # Execute decision
            if action == 'drop':
                packet.drop()
                self.drop_count += 1
                logger.debug(f"DROPPED packet #{self.packet_count} by rule {rule_id} in {decision_time*1000:.2f}ms")
            else:
                packet.accept()
                self.accept_count += 1
                logger.debug(f"ACCEPTED packet #{self.packet_count} in {decision_time*1000:.2f}ms")
            
            # Update metrics
            total_time = time.perf_counter() - start_time
            if self.metrics:
                self.metrics.record_packet(
                    action=action,
                    rule_id=rule_id,
                    decision_time=decision_time,
                    total_time=total_time,
                    packet_size=len(raw_packet)
                )
            
            # Log progress every 100 packets
            if self.packet_count % 100 == 0:
                drop_rate = (self.drop_count / self.packet_count) * 100
                avg_time = decision_time * 1000
                logger.info(f"Processed {self.packet_count} packets, "
                           f"dropped {self.drop_count} ({drop_rate:.1f}%), "
                           f"avg time: {avg_time:.2f}ms")
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            # On error, accept packet to avoid breaking network flow
            packet.accept()
    
    def _parse_packet_scapy(self, raw_packet: bytes) -> Dict[str, Any]:
        """
        Parse packet using Scapy - optimized for performance
        Returns structured data for rule evaluation
        """
        try:
            # Parse with Scapy
            pkt = scapy.IP(raw_packet)
            
            parsed_data = {
                'layer3': self._extract_l3_scapy(pkt),
                'layer4': self._extract_l4_scapy(pkt),
                'layer7': self._extract_l7_scapy(pkt)
            }
            
            return parsed_data
            
        except Exception as e:
            logger.debug(f"Parse error: {e}")
            return {
                'layer3': {},
                'layer4': {},
                'layer7': {}
            }
    
    def _extract_l3_scapy(self, pkt) -> Dict[str, Any]:
        """Extract Layer 3 (IP) data using Scapy"""
        l3_data = {}
        
        if pkt.haslayer(scapy.IP):
            ip_layer = pkt[scapy.IP]
            l3_data.update({
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'ttl': ip_layer.ttl,
                'length': ip_layer.len
            })
        elif pkt.haslayer(scapy.IPv6):
            ipv6_layer = pkt[scapy.IPv6]
            l3_data.update({
                'src_ip': ipv6_layer.src,
                'dst_ip': ipv6_layer.dst,
                'protocol': ipv6_layer.nh,
                'hop_limit': ipv6_layer.hlim
            })
        
        return l3_data
    
    def _extract_l4_scapy(self, pkt) -> Dict[str, Any]:
        """Extract Layer 4 (TCP/UDP) data using Scapy"""
        l4_data = {}
        
        if pkt.haslayer(scapy.TCP):
            tcp_layer = pkt[scapy.TCP]
            l4_data.update({
                'protocol': 'tcp',
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'flags': str(tcp_layer.flags),
                'seq': tcp_layer.seq,
                'ack': tcp_layer.ack,
                'window': tcp_layer.window
            })
        elif pkt.haslayer(scapy.UDP):
            udp_layer = pkt[scapy.UDP]
            l4_data.update({
                'protocol': 'udp',
                'src_port': udp_layer.sport,
                'dst_port': udp_layer.dport,
                'length': udp_layer.len
            })
        
        return l4_data
    
    def _extract_l7_scapy(self, pkt) -> Dict[str, Any]:
        """Extract Layer 7 (Application) data using Scapy"""
        l7_data = {}
        
        # Check for HTTP traffic (TCP port 80/443/8080)
        if pkt.haslayer(scapy.TCP):
            tcp_layer = pkt[scapy.TCP]
            if tcp_layer.dport in [80, 443, 8080] or tcp_layer.sport in [80, 443, 8080]:
                # Try to extract HTTP data from payload
                if pkt.haslayer(scapy.Raw):
                    payload = bytes(pkt[scapy.Raw])
                    if payload:
                        http_data = self._parse_http_payload(payload)
                        l7_data.update(http_data)
        
        # Check for DNS traffic (UDP port 53)
        elif pkt.haslayer(scapy.UDP):
            udp_layer = pkt[scapy.UDP]
            if udp_layer.dport == 53 or udp_layer.sport == 53:
                if pkt.haslayer(scapy.DNS):
                    dns_layer = pkt[scapy.DNS]
                    l7_data.update({
                        'protocol': 'dns',
                        'query_name': dns_layer.qd.qname.decode('utf-8', errors='ignore') if dns_layer.qd else '',
                        'query_type': dns_layer.qd.qtype if dns_layer.qd else 0
                    })
        
        # Add raw payload if available for other protocols
        if pkt.haslayer(scapy.Raw):
            raw_payload = bytes(pkt[scapy.Raw])
            l7_data['payload'] = raw_payload.decode('utf-8', errors='ignore')[:200]  # Limit to first 200 chars
        
        return l7_data
    
    def _parse_http_payload(self, payload: bytes) -> Dict[str, Any]:
        """Simple HTTP parsing from raw payload"""
        http_data = {'protocol': 'http'}
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\r\n')
            
            if lines and len(lines) > 0:
                # Parse first line (request/response)
                first_line = lines[0]
                
                # HTTP Request
                if any(method in first_line for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']):
                    parts = first_line.split(' ')
                    if len(parts) >= 3:
                        http_data['method'] = parts[0]
                        http_data['uri'] = parts[1]
                        
                        # Parse headers
                        headers = {}
                        for line in lines[1:]:
                            if ':' in line and line.strip():
                                key, value = line.split(':', 1)
                                headers[key.strip().lower()] = value.strip()
                        
                        http_data['headers'] = headers
                        http_data['host'] = headers.get('host', '')
                        http_data['user_agent'] = headers.get('user-agent', '')
                
                # HTTP Response
                elif 'HTTP/' in first_line:
                    parts = first_line.split(' ')
                    if len(parts) >= 2:
                        try:
                            http_data['response_code'] = int(parts[1])
                        except ValueError:
                            http_data['response_code'] = 0
        
        except Exception:
            # If parsing fails, just mark as HTTP
            pass
        
        return http_data
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return {
            'total_packets': self.packet_count,
            'dropped_packets': self.drop_count,
            'accepted_packets': self.accept_count,
            'drop_rate': (self.drop_count / max(1, self.packet_count)) * 100,
            'engine_stats': self.filter_engine.get_thread_safe_stats()
        }
    
    def shutdown(self):
        """Shutdown the packet handler"""
        logger.info("Shutting down packet handler")
        if hasattr(self, 'filter_engine'):
            self.filter_engine.shutdown()