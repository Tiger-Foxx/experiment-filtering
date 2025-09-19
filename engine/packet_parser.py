import scapy.all as scapy
from typing import Dict, Any
import time

class PacketParser:
    def __init__(self):
        # Cache pour éviter re-parsing
        self._parse_cache = {}
        
    def parse_packet(self, raw_packet: bytes) -> Dict[str, Any]:
        """Parse packet avec Scapy - optimisé pour NFQUEUE"""
        start_time = time.perf_counter()
        
        # Cache check (simple hash)
        packet_hash = hash(raw_packet[:100])  # Hash des premiers 100 bytes
        if packet_hash in self._parse_cache:
            return self._parse_cache[packet_hash]
        
        try:
            # Scapy parsing depuis bytes bruts (NFQUEUE)
            pkt = scapy.IP(raw_packet)
            
            parsed_data = {
                'parse_time': 0,
                'layer3': self._extract_l3_scapy(pkt),
                'layer4': self._extract_l4_scapy(pkt), 
                'layer7': self._extract_l7_scapy(pkt)
            }
            
            parsed_data['parse_time'] = time.perf_counter() - start_time
            
            # Cache result (LRU simple - max 1000 entries)
            if len(self._parse_cache) > 1000:
                self._parse_cache.pop(next(iter(self._parse_cache)))
            self._parse_cache[packet_hash] = parsed_data
            
            return parsed_data
            
        except Exception as e:
            return {
                'parse_time': time.perf_counter() - start_time,
                'error': str(e),
                'layer3': {}, 'layer4': {}, 'layer7': {}
            }
    
    def _extract_l3_scapy(self, pkt) -> Dict[str, Any]:
        """Extraction L3 (IP) avec Scapy"""
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
        """Extraction L4 (TCP/UDP) avec Scapy"""
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
        """Extraction L7 (HTTP/Apps) avec Scapy"""
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
        
        # Add raw payload if available
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
        
        except Exception:
            pass
        
        return http_data