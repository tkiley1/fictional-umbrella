# Simple DNS Server

A lightweight, configurable DNS server implementation in Python that can handle inbound requests from anywhere. Perfect for local development, testing, or simple DNS resolution needs.

## Features

- **Lightweight**: Pure Python implementation using only standard library modules
- **Configurable**: JSON-based configuration for DNS records
- **Multi-threaded**: Handles multiple concurrent requests
- **IPv4 & IPv6 Support**: Supports both A and AAAA records
- **DNS Forwarding**: Forwards unknown queries to upstream DNS servers (Google DNS by default)
- **Logging**: Comprehensive logging for monitoring and debugging
- **Cross-platform**: Works on Linux, macOS, and Windows

## Supported Record Types

- A records (IPv4 addresses)
- AAAA records (IPv6 addresses)
- ANY queries (returns all available records)

## Quick Start

### Prerequisites

- Python 3.6 or higher
- Root/sudo access (required for binding to port 53)

### Installation

1. Clone or download the DNS server files:
   ```bash
   # If you have git
   git clone <repository-url>
   cd DNS
   
   # Or create the directory and copy files
   mkdir dns-server && cd dns-server
   # Copy dns_server.py and dns_records.json to this directory
   ```

2. Make the script executable:
   ```bash
   chmod +x dns_server.py
   ```

### Basic Usage

1. **Start the DNS server** (requires sudo for port 53):
   ```bash
   sudo python3 dns_server.py
   ```

2. **Test the DNS server**:
   ```bash
   # Test local records
   dig @localhost example.local
   
   # Test DNS forwarding (public domains)
   dig @localhost google.com
   
   # Test with nslookup
   nslookup example.local localhost
   
   # Run comprehensive tests
   python3 test_dns.py
   
   # Run forwarding demo (uses port 5353 by default)
   python3 demo_forwarding.py
   
   # Test on port 5353 to avoid conflicts
   python3 dns_server.py --port 5353 &
   python3 demo_forwarding.py --port 5353
   ```

### Configuration

Edit the `dns_records.json` file to add your own DNS records:

```json
{
  "records": [
    {
      "domain": "mysite.local",
      "type": "A",
      "value": "192.168.1.100",
      "ttl": 300
    },
    {
      "domain": "mysite.local",
      "type": "AAAA",
      "value": "2001:db8::1",
      "ttl": 300
    }
  ]
}
```

### Advanced Usage

#### Custom Port and Host

Run on a different port (useful for testing without sudo):
```bash
python3 dns_server.py --port 5353 --host 127.0.0.1
```

#### Custom Configuration File

Use a different configuration file:
```bash
sudo python3 dns_server.py --config /path/to/custom_records.json
```

#### Command Line Options

```bash
python3 dns_server.py --help
```

Options:
- `--host`: Host to bind to (default: 0.0.0.0)
- `--port`: Port to bind to (default: 53)
- `--config`: Configuration file path (default: dns_records.json)
- `--upstream`: Upstream DNS servers for forwarding (default: 8.8.8.8 8.8.4.4)

#### DNS Forwarding

The server automatically forwards queries for domains not found in the local configuration to upstream DNS servers. This allows it to function as both a local DNS server and a DNS forwarder.

**Configure upstream DNS servers:**
```bash
# Use custom upstream servers
sudo python3 dns_server.py --upstream 1.1.1.1 1.0.0.1

# Use multiple upstream servers (fallback)
sudo python3 dns_server.py --upstream 8.8.8.8 8.8.4.4 1.1.1.1
```

**How it works:**
1. Client queries for a domain (e.g., `google.com`)
2. Server checks local records first
3. If no local record exists, forwards query to upstream DNS
4. Returns the upstream response to the client

## Production Deployment

### Systemd Service (Linux)

Create a systemd service file for automatic startup:

```bash
sudo cp dns-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dns-server
sudo systemctl start dns-server
```

Check status:
```bash
sudo systemctl status dns-server
```

### Firewall Configuration

Ensure DNS port is accessible:

**UFW (Ubuntu/Debian):**
```bash
sudo ufw allow 53/udp
```

**iptables:**
```bash
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
```

**firewalld (CentOS/RHEL):**
```bash
sudo firewall-cmd --permanent --add-port=53/udp
sudo firewall-cmd --reload
```

## Security Considerations

- **Network Access**: This server binds to `0.0.0.0` by default, making it accessible from any network interface
- **Rate Limiting**: Consider implementing rate limiting for production use
- **Access Control**: Add IP-based access controls if needed
- **Validation**: Input validation is implemented, but additional security measures may be needed for production
- **Monitoring**: Monitor logs for suspicious activity

## Troubleshooting

### Permission Denied (Port 53)

Port 53 requires root privileges. Either:
1. Run with sudo: `sudo python3 dns_server.py`
2. Use a different port: `python3 dns_server.py --port 5353`
3. Grant capabilities: `sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3`

### Address Already in Use (Port 53)

If you get "Address already in use" error:
1. **Quick solution**: Use port 5353: `python3 dns_server.py --port 5353`
2. **Check what's using port 53**: `sudo netstat -tulpn | grep :53`
3. **Stop systemd-resolved**: `sudo systemctl stop systemd-resolved`
4. **Run troubleshooting**: `python3 troubleshoot_port.py`

Note: All test scripts now support custom ports:
- `python3 test_dns.py --port 5353`
- `python3 demo_forwarding.py --port 5353`

### Testing DNS Resolution

Test your DNS server:

```bash
# Local test
dig @127.0.0.1 example.local

# Remote test (replace IP with your server's IP)
dig @YOUR_SERVER_IP example.local

# Test with specific record type
dig @127.0.0.1 AAAA example.local

# Verbose output
dig @127.0.0.1 example.local +trace
```

### Checking Logs

The server outputs logs to stdout. For production, redirect to a file:

```bash
sudo python3 dns_server.py 2>&1 | tee dns_server.log
```

### Configuration Issues

If the configuration file has errors:
1. Check JSON syntax with: `python3 -m json.tool dns_records.json`
2. Verify record format matches the example
3. Check file permissions: `ls -la dns_records.json`

## Development

### Adding New Record Types

To add support for new DNS record types:

1. Update the `create_dns_response` method in `dns_server.py`
2. Add the new record type constant
3. Implement encoding for the new record type

### Extending Functionality

Common extensions:
- CNAME record support
- MX record support
- TXT record support
- Zone file format support
- Dynamic record updates via API
- Web interface for management

## License

This project is open source. Feel free to modify and distribute according to your needs.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests. 