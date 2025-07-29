#!/usr/bin/env python3
"""
Simple DNS Server
A basic DNS server implementation that can handle common DNS queries.
"""

import socket
import struct
import threading
import json
import logging
from typing import Dict, List, Tuple, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DNSRecord:
    """Represents a DNS record"""

    def __init__(self, domain: str, record_type: str, value: str, ttl: int = 300):
        self.domain = domain.lower()
        self.record_type = record_type.upper()
        self.value = value
        self.ttl = ttl


class DNSServer:
    """Simple DNS Server implementation"""

    def __init__(self, host: str = '0.0.0.0', port: int = 53, config_file: str = 'dns_records.json',
                 upstream_dns: List[str] = None):
        self.host = host
        self.port = port
        self.config_file = config_file
        self.upstream_dns = upstream_dns or [
            '8.8.8.8', '8.8.4.4']  # Google DNS as default
        self.records: Dict[str, List[DNSRecord]] = {}
        self.load_records()

    def load_records(self):
        """Load DNS records from configuration file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)

            self.records = {}
            for record_data in config.get('records', []):
                domain = record_data['domain'].lower()
                if domain not in self.records:
                    self.records[domain] = []

                record = DNSRecord(
                    domain=record_data['domain'],
                    record_type=record_data['type'],
                    value=record_data['value'],
                    ttl=record_data.get('ttl', 300)
                )
                self.records[domain].append(record)

            logger.info(
                f"Loaded {sum(len(recs) for recs in self.records.values())} DNS records")

        except FileNotFoundError:
            logger.warning(
                f"Configuration file {self.config_file} not found. Using default records.")
            self.create_default_records()
        except Exception as e:
            logger.error(f"Error loading records: {e}")
            self.create_default_records()

    def create_default_records(self):
        """Create some default DNS records for testing"""
        self.records = {
            'example.local': [
                DNSRecord('example.local', 'A', '192.168.1.100'),
                DNSRecord('example.local', 'AAAA', '::1')
            ],
            'test.local': [
                DNSRecord('test.local', 'A', '10.0.0.1')
            ],
            'ns.local': [
                DNSRecord('ns.local', 'A', '127.0.0.1')
            ]
        }
        logger.info("Created default DNS records")

    def parse_dns_query(self, data: bytes) -> Tuple[Optional[str], Optional[int], Optional[int]]:
        """Parse DNS query packet and extract domain name and query type"""
        try:
            # DNS Header is 12 bytes
            if len(data) < 12:
                return None, None, None

            # Parse header
            header = struct.unpack('!HHHHHH', data[:12])
            query_id = header[0]
            flags = header[1]
            questions = header[2]

            if questions != 1:
                return None, None, None

            # Parse question section
            offset = 12
            domain_parts = []

            while offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if length > 63:  # Domain label too long
                    return None, None, None

                offset += 1
                if offset + length > len(data):
                    return None, None, None

                domain_parts.append(
                    data[offset:offset + length].decode('utf-8'))
                offset += length

            if offset + 4 > len(data):
                return None, None, None

            domain = '.'.join(domain_parts).lower()
            query_type, query_class = struct.unpack(
                '!HH', data[offset:offset + 4])

            return domain, query_type, query_id

        except Exception as e:
            logger.error(f"Error parsing DNS query: {e}")
            return None, None, None

    def encode_domain(self, domain: str) -> bytes:
        """Encode domain name for DNS packet"""
        encoded = b''
        for part in domain.split('.'):
            if len(part) > 63:
                raise ValueError("Domain label too long")
            encoded += bytes([len(part)]) + part.encode('utf-8')
        encoded += b'\x00'  # End of domain
        return encoded

    def query_upstream_dns(self, query_data: bytes, timeout: float = 5.0) -> Optional[bytes]:
        """Query upstream DNS servers for resolution"""
        for upstream_server in self.upstream_dns:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)

                logger.debug(
                    f"Forwarding query to upstream server: {upstream_server}")
                sock.sendto(query_data, (upstream_server, 53))

                response_data, _ = sock.recvfrom(512)
                sock.close()

                logger.debug(
                    f"Received response from upstream server: {upstream_server}")
                return response_data

            except (socket.timeout, socket.error) as e:
                logger.warning(
                    f"Failed to query upstream DNS {upstream_server}: {e}")
                if sock:
                    sock.close()
                continue

        logger.error("All upstream DNS servers failed to respond")
        return None

    def create_dns_response(self, query_id: int, domain: str, query_type: int, client_addr: Tuple[str, int]) -> bytes:
        """Create DNS response packet"""
        try:
            # DNS Header
            flags = 0x8180  # Response, Authoritative, No error
            questions = 1
            answers = 0
            authority = 0
            additional = 0

            # Find matching records
            matching_records = []
            if domain in self.records:
                for record in self.records[domain]:
                    if query_type == 1 and record.record_type == 'A':  # A record
                        matching_records.append(record)
                    elif query_type == 28 and record.record_type == 'AAAA':  # AAAA record
                        matching_records.append(record)
                    elif query_type == 255:  # ANY record
                        matching_records.append(record)

            if not matching_records:
                # Try to resolve via upstream DNS servers
                logger.info(
                    f"No local record found for {domain}, forwarding to upstream DNS")

                # Create the original query packet to forward
                original_query = struct.pack(
                    '!HHHHHH', query_id, 0x0100, 1, 0, 0, 0)  # Standard query
                original_query += self.encode_domain(domain)
                # Type and Class
                original_query += struct.pack('!HH', query_type, 1)

                upstream_response = self.query_upstream_dns(original_query)
                if upstream_response:
                    logger.info(
                        f"Successfully forwarded {domain} to upstream DNS")
                    return upstream_response
                else:
                    logger.warning(
                        f"Upstream DNS failed for {domain}, returning NXDOMAIN")
                    flags = 0x8183  # Response, Name Error (NXDOMAIN)
            else:
                answers = len(matching_records)

            # Build response
            response = struct.pack(
                '!HHHHHH', query_id, flags, questions, answers, authority, additional)

            # Question section (echo the question)
            response += self.encode_domain(domain)
            response += struct.pack('!HH', query_type, 1)  # Type and Class

            # Answer section
            for record in matching_records:
                # Name (use compression pointer to question)
                response += b'\xc0\x0c'  # Pointer to domain name in question

                # Type and Class
                if record.record_type == 'A':
                    response += struct.pack('!HH', 1, 1)
                elif record.record_type == 'AAAA':
                    response += struct.pack('!HH', 28, 1)

                # TTL
                response += struct.pack('!I', record.ttl)

                # Data length and data
                if record.record_type == 'A':
                    ip_bytes = socket.inet_aton(record.value)
                    response += struct.pack('!H', 4) + ip_bytes
                elif record.record_type == 'AAAA':
                    ip_bytes = socket.inet_pton(socket.AF_INET6, record.value)
                    response += struct.pack('!H', 16) + ip_bytes

            logger.info(
                f"Resolved {domain} (type {query_type}) for {client_addr[0]}:{client_addr[1]} - {len(matching_records)} records")
            return response

        except Exception as e:
            logger.error(f"Error creating DNS response: {e}")
            # Return error response
            flags = 0x8182  # Response, Server Error
            return struct.pack('!HHHHHH', query_id, flags, 1, 0, 0, 0) + \
                self.encode_domain(domain) + struct.pack('!HH', query_type, 1)

    def handle_client(self, data: bytes, client_addr: Tuple[str, int], sock: socket.socket):
        """Handle individual DNS query"""
        domain, query_type, query_id = self.parse_dns_query(data)

        if domain is None or query_type is None or query_id is None:
            logger.warning(
                f"Invalid DNS query from {client_addr[0]}:{client_addr[1]}")
            return

        response = self.create_dns_response(
            query_id, domain, query_type, client_addr)
        sock.sendto(response, client_addr)

    def start(self):
        """Start the DNS server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            # Allow address reuse
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))

            logger.info(f"DNS Server started on {self.host}:{self.port}")
            logger.info("Press Ctrl+C to stop the server")

            while True:
                try:
                    # DNS UDP packets are typically <= 512 bytes
                    data, client_addr = sock.recvfrom(512)

                    # Handle request in a separate thread for better performance
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(data, client_addr, sock)
                    )
                    thread.daemon = True
                    thread.start()

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error(f"Error handling request: {e}")

        except PermissionError:
            logger.error(
                "Permission denied. Try running with sudo for port 53.")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            sock.close()
            logger.info("DNS Server stopped")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Simple DNS Server')
    parser.add_argument('--host', default='0.0.0.0',
                        help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=53,
                        help='Port to bind to (default: 53)')
    parser.add_argument('--config', default='dns_records.json',
                        help='Configuration file (default: dns_records.json)')
    parser.add_argument('--upstream', nargs='+', default=['8.8.8.8', '8.8.4.4'],
                        help='Upstream DNS servers (default: 8.8.8.8 8.8.4.4)')

    args = parser.parse_args()

    server = DNSServer(host=args.host, port=args.port,
                       config_file=args.config, upstream_dns=args.upstream)
    server.start()


if __name__ == '__main__':
    main()
