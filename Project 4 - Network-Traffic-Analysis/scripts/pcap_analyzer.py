#!/usr/bin/env python3
"""
Custom PCAP/PCAPNG Packet Analyzer
Author: InlighnTech Cybersecurity Division (Blue Team)
Date: June 15, 2026

Description:
    A pure Python implementation to parse packet capture files (.pcap / .pcapng)
    without third-party dependencies (like Scapy or PyShark). It extracts:
      - Host protocol distributions
      - Plaintext HTTP GET/POST queries on TCP Port 80
      - DNS requests and query domains on UDP Port 53
      - IP Conversions and WHOIS-ready destination logs
"""

import os
import sys
import struct
import socket
import logging

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("PCAP_Analyzer")

class PacketAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.total_packets = 0
        self.ipv4_count = 0
        self.ipv6_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.dns_queries = set()
        self.http_requests = []
        self.external_ips = set()

    def parse(self):
        if not os.path.exists(self.file_path):
            logger.error(f"Target capture file not found: {self.file_path}")
            return False

        logger.info(f"Opening network capture file: {os.path.basename(self.file_path)}")
        try:
            with open(self.file_path, 'rb') as f:
                magic = f.read(4)
                if len(magic) < 4:
                    logger.error("Empty or invalid packet capture file.")
                    return False
                
                f.seek(0)
                # Detect format: PCAP vs PCAPNG
                if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                    logger.info("Format detected: Standard PCAP (Classic)")
                    self._parse_pcap(f, magic)
                elif magic == b'\x0a\x0d\x0d\x0a':
                    logger.info("Format detected: PCAP Next Generation (PCAPNG)")
                    self._parse_pcapng(f)
                else:
                    logger.error("Unsupported file header. Must be standard PCAP or PCAPNG.")
                    return False
            return True
        except Exception as e:
            logger.critical(f"Critical error parsing capture file: {e}", exc_info=True)
            return False

    def _parse_pcap(self, f, magic):
        # Read PCAP global header (24 bytes total, we already read 4)
        global_header = f.read(20)
        if len(global_header) < 20:
            return

        # Parse Snaplen & Network (link type)
        # Network link type: 1 = Ethernet
        endian = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
        _, _, _, _, snaplen, link_type = struct.unpack(f'{endian}HHIIII', magic + global_header)
        
        if link_type != 1:
            logger.warning(f"Unsupported link type: {link_type}. Only Ethernet captures are parsed.")

        while True:
            # Read Packet Header (16 bytes)
            header = f.read(16)
            if len(header) < 16:
                break
            
            # ts_sec, ts_usec, incl_len, orig_len
            _, _, incl_len, _ = struct.unpack(f'{endian}IIII', header)
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                break
            
            self.total_packets += 1
            self._decode_ethernet(packet_data)

    def _parse_pcapng(self, f):
        # PCAPNG uses blocks. Read blocks sequentially
        # Block structure: Block Type (4 bytes), Block Total Length (4 bytes), Block Body, Block Total Length (4 bytes)
        while True:
            header = f.read(8)
            if len(header) < 8:
                break
            
            block_type, block_len = struct.unpack('<II', header)
            if block_len < 12:
                break  # Prevent infinite loop on corrupted length
            
            body_len = block_len - 12
            body_data = f.read(body_len)
            trailer = f.read(4)  # Block Total Length repeated

            # Type 6 = Enhanced Packet Block (EPB)
            # Type 3 = Simple Packet Block (SPB)
            if block_type == 0x00000006:
                # Parse EPB Header (Interface ID (4B), Timestamp High (4B), Timestamp Low (4B), CapLen (4B), OrigLen (4B))
                if len(body_data) >= 20:
                    _, _, _, cap_len, _ = struct.unpack('<IIIII', body_data[:20])
                    packet_data = body_data[20:20+cap_len]
                    self.total_packets += 1
                    self._decode_ethernet(packet_data)
            elif block_type == 0x00000003:
                # Simple Packet Block
                if len(body_data) >= 4:
                    cap_len = struct.unpack('<I', body_data[:4])[0]
                    packet_data = body_data[4:4+cap_len]
                    self.total_packets += 1
                    self._decode_ethernet(packet_data)

    def _decode_ethernet(self, data):
        # Ethernet Header is 14 bytes: Dest MAC (6B), Src MAC (6B), EtherType (2B)
        if len(data) < 14:
            return
        ethertype = struct.unpack('>H', data[12:14])[0]
        
        # 0x0800 = IPv4, 0x86dd = IPv6
        if ethertype == 0x0800:
            self.ipv4_count += 1
            self._decode_ipv4(data[14:])
        elif ethertype == 0x86dd:
            self.ipv6_count += 1
            self._decode_ipv6(data[14:])

    def _decode_ipv4(self, ip_data):
        if len(ip_data) < 20:
            return
        
        version_ihl = ip_data[0]
        ihl = version_ihl & 0x0F
        ip_header_len = ihl * 4
        
        protocol = ip_data[9]
        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        if self._is_external_ip(src_ip):
            self.external_ips.add(src_ip)
        if self._is_external_ip(dst_ip):
            self.external_ips.add(dst_ip)

        # Decapsulate Protocol: 6 = TCP, 17 = UDP
        if protocol == 6:
            self.tcp_count += 1
            self._decode_tcp(ip_data[ip_header_len:], src_ip, dst_ip)
        elif protocol == 17:
            self.udp_count += 1
            self._decode_udp(ip_data[ip_header_len:], src_ip, dst_ip)

    def _decode_ipv6(self, ipv6_data):
        # IPv6 Header is 40 bytes. Src IP (offset 8), Dst IP (offset 24), Next Header (offset 6)
        if len(ipv6_data) < 40:
            return
        
        next_header = ipv6_data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, ipv6_data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ipv6_data[24:40])

        # Protocols: 6 = TCP, 17 = UDP
        if next_header == 6:
            self.tcp_count += 1
            self._decode_tcp(ipv6_data[40:], src_ip, dst_ip)
        elif next_header == 17:
            self.udp_count += 1
            self._decode_udp(ipv6_data[40:], src_ip, dst_ip)

    def _decode_tcp(self, tcp_data, src_ip, dst_ip):
        # TCP Header minimum 20 bytes
        if len(tcp_data) < 20:
            return
        
        src_port, dst_port = struct.unpack('>HH', tcp_data[:4])
        data_offset = (tcp_data[12] >> 4) * 4
        payload = tcp_data[data_offset:]

        # Port 80 = HTTP plaintext analysis
        if dst_port == 80 and len(payload) > 0:
            try:
                decoded_payload = payload.decode('utf-8', errors='ignore')
                if any(x in decoded_payload for x in ("GET ", "POST ", "HTTP/1.")):
                    first_line = decoded_payload.split('\r\n')[0]
                    self.http_requests.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "request": first_line
                    })
            except Exception:
                pass

    def _decode_udp(self, udp_data, src_ip, dst_ip):
        # UDP Header is 8 bytes: Src Port (2B), Dst Port (2B), Length (2B), Checksum (2B)
        if len(udp_data) < 8:
            return
        
        src_port, dst_port = struct.unpack('>HH', udp_data[:4])
        payload = udp_data[8:]

        # Port 53 = DNS query analysis
        if dst_port == 53 and len(payload) > 12:
            self._decode_dns_query(payload, src_ip)

    def _decode_dns_query(self, dns_payload, src_ip):
        # DNS header is 12 bytes. Questions Count is bytes 4-5
        qd_count = struct.unpack('>H', dns_payload[4:6])[0]
        if qd_count == 0:
            return
        
        # Start of query section is byte offset 12
        offset = 12
        try:
            for _ in range(qd_count):
                labels = []
                while True:
                    length = dns_payload[offset]
                    if length == 0:
                        offset += 1
                        break
                    if (length & 0xC0) == 0xC0:
                        # Compression pointer, not fully parsed here for simplicity
                        offset += 2
                        break
                    offset += 1
                    labels.append(dns_payload[offset:offset+length].decode('utf-8', errors='ignore'))
                    offset += length
                
                domain = ".".join(labels)
                if domain:
                    self.dns_queries.add(domain)
                offset += 4  # skip Type and Class fields (2 bytes each)
        except Exception:
            pass

    def _is_external_ip(self, ip_str):
        # Filter out loopback and local RFC 1918 addresses
        if ip_str.startswith(("127.", "192.168.", "10.", "fc00::", "fe80::", "::1")):
            return False
        if ip_str.startswith("172."):
            try:
                parts = ip_str.split('.')
                second_octet = int(parts[1])
                return not (16 <= second_octet <= 31)
            except Exception:
                pass
        return True

    def generate_report(self):
        print("="*60)
        print("         INLIGHNTECH NETWORK TRAFFIC ANALYSIS REPORT")
        print("="*60)
        print(f"Target PCAP File:     {os.path.basename(self.file_path)}")
        print(f"Total Packets Read:   {self.total_packets}")
        print(f"IPv4 Packets:         {self.ipv4_count}")
        print(f"IPv6 Packets:         {self.ipv6_count}")
        print(f"TCP Conversations:    {self.tcp_count}")
        print(f"UDP Conversations:    {self.udp_count}")
        print("-"*60)
        
        print("\n[*] OSINT Target IP Discoveries:")
        if self.external_ips:
            for ip in sorted(self.external_ips):
                print(f"  [+] External Host Connected: {ip}")
        else:
            print("  No external IP addresses found.")
            
        print("\n[*] DNS Domain Resolution Queries:")
        if self.dns_queries:
            for domain in sorted(self.dns_queries):
                if domain.strip():
                    print(f"  [+] Domain Queried: {domain}")
        else:
            print("  No DNS queries resolved.")

        print("\n[!] Plaintext HTTP (Port 80) Transmissions:")
        if self.http_requests:
            for req in self.http_requests:
                print(f"  [!] HTTP Session Alert from {req['src_ip']} to {req['dst_ip']}:")
                print(f"      Request Path: {req['request']}")
        else:
            print("  No unencrypted HTTP sessions detected (All traffic secure).")
        print("="*60)

if __name__ == '__main__':
    default_pcap = r"C:\Users\abdxl\OneDrive\Documents\packet_captures\traffic_capture.pcapng"
    # Fallback to local project folder if first choice doesn't exist
    if not os.path.exists(default_pcap):
        default_pcap = r"C:\Users\abdxl\.gemini\antigravity\scratch\Project 4 - Network-Traffic-Analysis\packet_captures\traffic_capture.pcapng"
        
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else default_pcap
    
    analyzer = PacketAnalyzer(pcap_path)
    if analyzer.parse():
        analyzer.generate_report()
    else:
        sys.exit(1)
