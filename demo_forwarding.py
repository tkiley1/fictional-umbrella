#!/usr/bin/env python3
"""
DNS Forwarding Demo
Demonstrates the new DNS forwarding functionality of the simple DNS server.
"""

import subprocess
import time
import sys
import socket


def test_dns_resolution(domain, dns_server="127.0.0.1", port=5353):
    """Test DNS resolution using dig command"""
    try:
        result = subprocess.run(
            ['dig', '+short', f'@{dns_server}', '-p', str(port), domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split('\n')
        else:
            return None

    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fallback to nslookup if dig is not available
        try:
            # Note: nslookup doesn't support custom ports easily, so we'll warn about this
            if port != 53:
                print(
                    f"⚠️  Note: nslookup fallback testing against port 53, not {port}")
            result = subprocess.run(
                ['nslookup', domain, dns_server],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Parse nslookup output for IP addresses
                lines = result.stdout.split('\n')
                ips = []
                for line in lines:
                    line = line.strip()
                    if line.startswith('Address:') and ':' in line:
                        ip = line.split(':')[1].strip()
                        if ip != dns_server:  # Skip the server IP
                            ips.append(ip)
                return ips if ips else None
            else:
                return None

        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("❌ Neither 'dig' nor 'nslookup' commands are available")
            return None


def main():
    """Main demo function"""
    import argparse

    parser = argparse.ArgumentParser(description='DNS Forwarding Demo')
    parser.add_argument('--port', type=int, default=5353,
                        help='DNS server port to test (default: 5353)')
    parser.add_argument('--server', default='127.0.0.1',
                        help='DNS server address (default: 127.0.0.1)')

    args = parser.parse_args()

    print("🚀 DNS Forwarding Demo")
    print("=" * 50)
    print(f"Testing DNS server at {args.server}:{args.port}")
    print()

    # Test domains
    test_cases = [
        ("Local record", "example.local", "Should resolve to 192.168.1.100"),
        ("Public domain", "google.com", "Should forward to upstream DNS"),
        ("Public domain", "github.com", "Should forward to upstream DNS"),
        ("Another local", "test.local", "Should resolve to 10.0.0.1"),
        ("Non-existent", "thisdoesnotexist.com", "Should return no results"),
    ]

    print("Testing DNS resolution with forwarding enabled...")
    print(
        f"(Make sure the DNS server is running on {args.server}:{args.port})")
    print(f"Start with: python3 dns_server.py --port {args.port}")
    print()

    for test_type, domain, description in test_cases:
        print(f"🔍 Testing {test_type}: {domain}")
        print(f"   Expected: {description}")

        result = test_dns_resolution(
            domain, dns_server=args.server, port=args.port)

        if result:
            print(f"   ✅ Resolved to: {', '.join(result)}")
        else:
            print(f"   ❌ No resolution (NXDOMAIN or timeout)")

        print()
        time.sleep(1)  # Small delay between tests

    print("Demo complete! 🎉")
    print()
    print("Key observations:")
    print("• Local domains (*.local) resolve from local configuration")
    print("• Public domains forward to upstream DNS servers (8.8.8.8)")
    print("• Non-existent domains return appropriate responses")
    print(
        f"• Server running on port {args.port} ({'non-privileged' if args.port != 53 else 'privileged'} port)")
    print()
    print("This demonstrates how the DNS server acts as both:")
    print("  1. Authoritative server for local domains")
    print("  2. Recursive resolver for external domains")
    print()
    print("💡 To use this as your system DNS:")
    if args.port != 53:
        print(
            f"   Configure your network settings to use {args.server}:{args.port}")
        print("   Or run on port 53: sudo python3 dns_server.py")
    else:
        print(f"   Configure your network settings to use {args.server}")
    print()
    print("💡 Demo usage:")
    print(f"   python3 demo_forwarding.py --port {args.port}")
    print("   python3 demo_forwarding.py --port 53 --server 192.168.1.100")


if __name__ == '__main__':
    main()
