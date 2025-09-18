import pyshark
import io
from typing import Optional, Dict, Any
import time

class PacketParser:
    def __init__(self):
        # Cache pour éviter re-parsing
        self._parse_cache = {}
        
    def parse_packet(self, raw_packet: bytes) -> Dict[str, Any]:
        """Parse packet avec pyshark - extraction L3/L4/L7 optimisée"""
        start_time = time.perf_counter()
        
        # Cache check (simple hash)
        packet_hash = hash(raw_packet[:100])  # Hash des premiers 100 bytes
        if packet_hash in self._parse_cache:
            return self._parse_cache[packet_hash]
        
        try:
            # Pyshark parsing depuis bytes
            packet_io = io.BytesIO(raw_packet)
            capture = pyshark.FileCapture(packet_io, display_filter=None)
            packet = next(iter(capture))
            
            parsed_data = {
                'parse_time': 0,
                'layer3': self._extract_l3(packet),
                'layer4': self._extract_l4(packet), 
                'layer7': self._extract_l7(packet)
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
    
    def _extract_l3(self, packet) -> Dict[str, Any]:
        """Extraction L3 (IP) ultra-rapide"""
        l3_data = {}
        
        if hasattr(packet, 'ip'):
            l3_data.update({
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
                'protocol': packet.ip.proto,
                'ttl': int(packet.ip.ttl),
                'length': int(packet.ip.len)
            })
        elif hasattr(packet, 'ipv6'):
            l3_data.update({
                'src_ip': packet.ipv6.src,
                'dst_ip': packet.ipv6.dst, 
                'protocol': packet.ipv6.nxt,
                'hop_limit': int(packet.ipv6.hlim)
            })
        
        return l3_data
    
    def _extract_l4(self, packet) -> Dict[str, Any]:
        """Extraction L4 (TCP/UDP) ultra-rapide"""
        l4_data = {}
        
        if hasattr(packet, 'tcp'):
            l4_data.update({
                'protocol': 'tcp',
                'src_port': int(packet.tcp.srcport),
                'dst_port': int(packet.tcp.dstport),
                'flags': packet.tcp.flags,
                'seq': int(packet.tcp.seq),
                'ack': int(packet.tcp.ack) if hasattr(packet.tcp, 'ack') else 0,
                'window': int(packet.tcp.window)
            })
        elif hasattr(packet, 'udp'):
            l4_data.update({
                'protocol': 'udp',
                'src_port': int(packet.udp.srcport),
                'dst_port': int(packet.udp.dstport),
                'length': int(packet.udp.length)
            })
        
        return l4_data
    
    def _extract_l7(self, packet) -> Dict[str, Any]:
        """Extraction L7 (HTTP/Apps) avec reassembly automatique"""
        l7_data = {}
        
        # HTTP detection et parsing
        if hasattr(packet, 'http'):
            l7_data['protocol'] = 'http'
            
            # HTTP Request
            if hasattr(packet.http, 'request_method'):
                l7_data.update({
                    'method': packet.http.request_method,
                    'uri': packet.http.request_uri if hasattr(packet.http, 'request_uri') else '',
                    'host': packet.http.host if hasattr(packet.http, 'host') else '',
                    'user_agent': packet.http.user_agent if hasattr(packet.http, 'user_agent') else '',
                    'referer': packet.http.referer if hasattr(packet.http, 'referer') else ''
                })
                
                # Headers parsing complet
                l7_data['headers'] = {}
                for field_name in packet.http.field_names:
                    if field_name.startswith('http.'):
                        header_name = field_name.replace('http.', '').replace('_', '-')
                        l7_data['headers'][header_name] = getattr(packet.http, field_name.split('.')[-1])
            
            # HTTP Response  
            elif hasattr(packet.http, 'response_code'):
                l7_data.update({
                    'response_code': int(packet.http.response_code),
                    'content_type': packet.http.content_type if hasattr(packet.http, 'content_type') else '',
                    'content_length': packet.http.content_length if hasattr(packet.http, 'content_length') else ''
                })
        
        # DNS detection
        elif hasattr(packet, 'dns'):
            l7_data.update({
                'protocol': 'dns',
                'query_name': packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else '',
                'query_type': packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else ''
            })
        
        # Raw payload si disponible
        if hasattr(packet, 'data'):
            l7_data['payload'] = packet.data.data if hasattr(packet.data, 'data') else ''
        
        return l7_data