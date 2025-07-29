#!/usr/bin/env python3
"""
DNS Port Troubleshooting Script
Helps diagnose and resolve port 53 conflicts for the DNS server.
"""

import subprocess
import sys
import socket
import os


def run_command(cmd, shell=True):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return "", str(e), 1


def check_port_usage():
    """Check what's using port 53"""
    print("🔍 Checking what's using port 53...")
    print("=" * 50)

    # Check with netstat
    stdout, stderr, code = run_command("netstat -tulpn | grep :53")
    if stdout:
        print("📋 Active connections on port 53:")
        for line in stdout.split('\n'):
            if line.strip():
                print(f"  {line}")

    # Check with lsof if available
    stdout, stderr, code = run_command("lsof -i :53")
    if code == 0 and stdout:
        print("\n📋 Processes using port 53 (lsof):")
        for line in stdout.split('\n'):
            if line.strip() and not line.startswith('COMMAND'):
                print(f"  {line}")

    # Check with ss (modern replacement for netstat)
    stdout, stderr, code = run_command("ss -tulpn | grep :53")
    if stdout:
        print("\n📋 Socket statistics (ss) for port 53:")
        for line in stdout.split('\n'):
            if line.strip():
                print(f"  {line}")


def check_systemd_resolved():
    """Check if systemd-resolved is running"""
    print("\n🔍 Checking systemd-resolved status...")
    print("=" * 50)

    stdout, stderr, code = run_command("systemctl is-active systemd-resolved")
    if code == 0 and stdout.strip() == "active":
        print("⚠️  systemd-resolved is ACTIVE and likely using port 53")

        # Check its configuration
        stdout, stderr, code = run_command("systemctl status systemd-resolved")
        if code == 0:
            print("\n📋 systemd-resolved status:")
            lines = stdout.split('\n')[:10]  # First 10 lines
            for line in lines:
                print(f"  {line}")

        return True
    else:
        print("✅ systemd-resolved is not active")
        return False


def check_other_dns_services():
    """Check for other common DNS services"""
    print("\n🔍 Checking other DNS services...")
    print("=" * 50)

    services = ['dnsmasq', 'bind9', 'named', 'unbound', 'pihole-FTL']

    for service in services:
        stdout, stderr, code = run_command(f"systemctl is-active {service}")
        if code == 0 and stdout.strip() == "active":
            print(f"⚠️  {service} is ACTIVE")
        else:
            print(f"✅ {service} is not active")


def test_port_availability():
    """Test if we can bind to port 53"""
    print("\n🧪 Testing port 53 availability...")
    print("=" * 50)

    try:
        # Try to bind to port 53
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', 53))
        sock.close()
        print("✅ Port 53 is available!")
        return True
    except PermissionError:
        print("❌ Permission denied - need sudo to bind to port 53")
        return False
    except OSError as e:
        if e.errno == 98:  # Address already in use
            print("❌ Port 53 is already in use")
        else:
            print(f"❌ Error binding to port 53: {e}")
        return False


def provide_solutions():
    """Provide solutions to resolve port conflicts"""
    print("\n🛠️  SOLUTIONS")
    print("=" * 50)

    print("\n1️⃣  OPTION 1: Stop systemd-resolved (if running)")
    print("   sudo systemctl stop systemd-resolved")
    print("   sudo systemctl disable systemd-resolved")
    print("   ⚠️  Warning: This will disable system DNS resolution!")

    print("\n2️⃣  OPTION 2: Configure systemd-resolved to not bind to port 53")
    print("   Edit /etc/systemd/resolved.conf:")
    print("   sudo nano /etc/systemd/resolved.conf")
    print("   Add or modify: DNSStubListener=no")
    print("   Then restart: sudo systemctl restart systemd-resolved")

    print("\n3️⃣  OPTION 3: Run DNS server on different port")
    print("   python3 dns_server.py --port 5353")
    print("   Test with: dig @localhost -p 5353 example.local")

    print("\n4️⃣  OPTION 4: Stop other DNS services")
    print("   sudo systemctl stop dnsmasq")
    print("   sudo systemctl stop bind9")
    print("   (Replace with the service that's running)")

    print("\n5️⃣  OPTION 5: Use authbind (allows non-root port 53 binding)")
    print("   sudo apt install authbind")
    print("   sudo touch /etc/authbind/byport/53")
    print("   sudo chmod 500 /etc/authbind/byport/53")
    print("   sudo chown $(whoami) /etc/authbind/byport/53")
    print("   authbind --deep python3 dns_server.py")


def main():
    """Main troubleshooting function"""
    print("🚨 DNS Server Port 53 Troubleshooting")
    print("=" * 50)
    print()

    if os.geteuid() != 0:
        print("ℹ️  Note: Running without root privileges")
        print("   Some diagnostic commands may have limited output")
        print()

    # Run diagnostics
    check_port_usage()
    systemd_resolved_active = check_systemd_resolved()
    check_other_dns_services()
    port_available = test_port_availability()

    print()
    provide_solutions()

    # Provide specific recommendation
    print("\n🎯 RECOMMENDED ACTION:")
    print("=" * 30)

    if systemd_resolved_active:
        print("systemd-resolved is likely the culprit.")
        print("Try OPTION 2 (configure systemd-resolved) or OPTION 3 (different port)")
    elif not port_available:
        print("Port 53 is in use by another service.")
        print("Check the process list above and stop the conflicting service,")
        print("or use OPTION 3 (run on different port)")
    else:
        print("Port 53 appears to be available.")
        print("Try running the DNS server with sudo:")
        print("sudo python3 dns_server.py")

    print("\n📚 For more help, check the README.md troubleshooting section")


if __name__ == '__main__':
    main()
