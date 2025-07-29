#!/usr/bin/env python3
"""
DNS Server Test Script
Tests the functionality of the simple DNS server.
"""

import socket
import struct
import time
import sys


def create_dns_query(domain: str, query_type: int = 1) -> bytes:
    """Create a DNS query packet"""
    # DNS Header
    query_id = 0x1234
    flags = 0x0100  # Standard query
    questions = 1
    answers = 0
    authority = 0
    additional = 0

    header = struct.pack('!HHHHHH', query_id, flags,
                         questions, answers, authority, additional)

    # Question section
    query = b''
    for part in domain.split('.'):
        query += bytes([len(part)]) + part.encode('utf-8')
    query += b'\x00'  # End of domain
    query += struct.pack('!HH', query_type, 1)  # Type and Class

    return header + query


def parse_dns_response(data: bytes) -> dict:
    """Parse DNS response packet"""
    try:
        # Parse header
        header = struct.unpack('!HHHHHH', data[:12])
        query_id, flags, questions, answers, authority, additional = header

        # Check if it's a response
        if not (flags & 0x8000):
            return {"error": "Not a DNS response"}

        # Check for errors
        rcode = flags & 0x000F
        if rcode != 0:
            error_codes = {
                1: "Format Error",
                2: "Server Failure",
                3: "Name Error (NXDOMAIN)",
                4: "Not Implemented",
                5: "Refused"
            }
            return {"error": f"DNS Error: {error_codes.get(rcode, f'Unknown error {rcode}')}"}

        result = {
            "query_id": query_id,
            "answers": answers,
            "records": []
        }

        # Skip question section
        offset = 12
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1 + length
        offset += 4  # Skip type and class

        # Parse answer section
        for _ in range(answers):
            if offset >= len(data):
                break

            # Skip name (assuming compression)
            if data[offset] & 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1

            if offset + 10 > len(data):
                break

            # Parse type, class, TTL, and data length
            record_type, record_class, ttl, data_length = struct.unpack(
                '!HHIH', data[offset:offset+10])
            offset += 10

            if offset + data_length > len(data):
                break

            # Parse data based on type
            if record_type == 1 and data_length == 4:  # A record
                ip = socket.inet_ntoa(data[offset:offset+4])
                result["records"].append(
                    {"type": "A", "value": ip, "ttl": ttl})
            elif record_type == 28 and data_length == 16:  # AAAA record
                ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
                result["records"].append(
                    {"type": "AAAA", "value": ip, "ttl": ttl})

            offset += data_length

        return result

    except Exception as e:
        return {"error": f"Parse error: {e}"}


def test_dns_query(server_ip: str, server_port: int, domain: str, query_type: int = 1) -> dict:
    """Test a DNS query"""
    try:
        # Create DNS query
        query = create_dns_query(domain, query_type)

        # Send query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)

        start_time = time.time()
        sock.sendto(query, (server_ip, server_port))

        # Receive response
        data, addr = sock.recvfrom(512)
        response_time = (time.time() - start_time) * 1000  # ms

        sock.close()

        # Parse response
        result = parse_dns_response(data)
        result["response_time_ms"] = round(response_time, 2)
        result["server"] = f"{addr[0]}:{addr[1]}"

        return result

    except socket.timeout:
        return {"error": "Timeout - no response from DNS server"}
    except Exception as e:
        return {"error": f"Connection error: {e}"}


def main():
    """Main test function"""
    import argparse

    parser = argparse.ArgumentParser(description='Test DNS Server')
    parser.add_argument('--server', default='127.0.0.1',
                        help='DNS server IP (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5353,
                        help='DNS server port (default: 53)')
    parser.add_argument(
        '--domain', help='Domain to query (if not specified, runs all tests)')

    args = parser.parse_args()

    print(f"Testing DNS server at {args.server}:{args.port}")
    print("-" * 50)

    if args.domain:
        # Test specific domain
        test_domains = [(args.domain, 1), (args.domain, 28)]
    else:
        # Test default domains
        test_domains = [
            ("example.local", 1),     # A record (local)
            ("example.local", 28),    # AAAA record (local)
            ("test.local", 1),        # A record (local)
            ("ns.local", 1),          # A record (local)
            ("web.local", 1),         # A record (local)
            ("google.com", 1),        # A record (should forward to upstream)
            ("github.com", 1),        # A record (should forward to upstream)
            ("nonexistent.local", 1),  # Should return NXDOMAIN
        ]

    success_count = 0
    total_tests = len(test_domains)

    for domain, query_type in test_domains:
        type_name = "A" if query_type == 1 else "AAAA" if query_type == 28 else str(
            query_type)
        print(f"\nTesting {domain} ({type_name} record):")

        result = test_dns_query(args.server, args.port, domain, query_type)

        if "error" in result:
            print(f"  ❌ ERROR: {result['error']}")
        else:
            print(
                f"  ✅ SUCCESS: {result['answers']} answer(s) in {result['response_time_ms']}ms")
            for record in result.get("records", []):
                print(
                    f"     {record['type']}: {record['value']} (TTL: {record['ttl']})")
            if result['answers'] == 0:
                print("     No records returned (NXDOMAIN)")
            success_count += 1

    print("\n" + "=" * 50)
    print(f"Test Results: {success_count}/{total_tests} tests passed")

    if success_count == total_tests:
        print("🎉 All tests passed! DNS server is working correctly.")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed. Check the DNS server configuration.")
        sys.exit(1)


if __name__ == '__main__':
    main()
