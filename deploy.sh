#!/bin/bash

# Simple DNS Server Deployment Script
# This script helps deploy the DNS server on a Linux system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR="/opt/dns-server"
SERVICE_NAME="dns-server"
USER_MODE=false

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 && $USER_MODE == false ]]; then
        return 0
    else
        return 1
    fi
}

# Function to show help
show_help() {
    cat << EOF
Simple DNS Server Deployment Script

Usage: $0 [OPTIONS]

OPTIONS:
    --user-mode     Install in user directory instead of system-wide
    --install-dir   Custom installation directory (default: /opt/dns-server)
    --help          Show this help message

EXAMPLES:
    # System-wide installation (requires sudo)
    sudo $0
    
    # User installation
    $0 --user-mode --install-dir ~/dns-server
    
    # Custom directory
    sudo $0 --install-dir /usr/local/dns-server

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --user-mode)
            USER_MODE=true
            INSTALL_DIR="$HOME/dns-server"
            shift
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main deployment function
deploy_dns_server() {
    print_status "Starting DNS Server deployment..."
    
    # Check if Python 3 is installed
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3 first."
        exit 1
    fi
    
    print_success "Python 3 found: $(python3 --version)"
    
    # Create installation directory
    print_status "Creating installation directory: $INSTALL_DIR"
    if [[ $USER_MODE == true ]]; then
        mkdir -p "$INSTALL_DIR"
    else
        if ! check_root; then
            print_error "System-wide installation requires root privileges. Run with sudo or use --user-mode"
            exit 1
        fi
        mkdir -p "$INSTALL_DIR"
    fi
    
    # Copy files
    print_status "Copying DNS server files..."
    cp dns_server.py "$INSTALL_DIR/"
    cp dns_records.json "$INSTALL_DIR/"
    cp test_dns.py "$INSTALL_DIR/"
    
    # Make scripts executable
    chmod +x "$INSTALL_DIR/dns_server.py"
    chmod +x "$INSTALL_DIR/test_dns.py"
    
    print_success "Files copied successfully"
    
    # Install systemd service (only for system-wide installation)
    if [[ $USER_MODE == false ]]; then
        print_status "Installing systemd service..."
        
        # Update service file with correct paths
        sed "s|/opt/dns-server|$INSTALL_DIR|g" dns-server.service > /tmp/dns-server.service
        cp /tmp/dns-server.service /etc/systemd/system/
        rm /tmp/dns-server.service
        
        # Reload systemd and enable service
        systemctl daemon-reload
        systemctl enable $SERVICE_NAME
        
        print_success "Systemd service installed and enabled"
    fi
    
    # Set up firewall (if ufw is available)
    if command -v ufw &> /dev/null && [[ $USER_MODE == false ]]; then
        print_status "Configuring firewall..."
        if ufw status | grep -q "Status: active"; then
            ufw allow 53/udp
            print_success "Firewall rule added for DNS (port 53/udp)"
        else
            print_warning "UFW is installed but not active. You may need to manually configure firewall rules."
        fi
    fi
    
    print_success "DNS Server deployment completed!"
    
    # Show usage instructions
    echo
    echo "=========================="
    echo "USAGE INSTRUCTIONS"
    echo "=========================="
    echo
    
    if [[ $USER_MODE == true ]]; then
        echo "To start the DNS server:"
        echo "  cd $INSTALL_DIR"
        echo "  python3 dns_server.py --port 5353  # Non-privileged port"
        echo
        echo "To test the DNS server:"
        echo "  python3 test_dns.py --port 5353"
        echo
        echo "Note: User mode runs on port 5353 by default (port 53 requires root)"
    else
        echo "To start the DNS server:"
        echo "  systemctl start $SERVICE_NAME"
        echo
        echo "To check service status:"
        echo "  systemctl status $SERVICE_NAME"
        echo
        echo "To test the DNS server:"
        echo "  cd $INSTALL_DIR && python3 test_dns.py"
        echo
        echo "To view logs:"
        echo "  journalctl -u $SERVICE_NAME -f"
        echo
        echo "To stop the DNS server:"
        echo "  systemctl stop $SERVICE_NAME"
    fi
    
    echo
    echo "Configuration file: $INSTALL_DIR/dns_records.json"
    echo "Edit this file to add your own DNS records, then restart the service."
    echo
    
    # Test installation
    print_status "Testing installation..."
    if [[ $USER_MODE == true ]]; then
        print_warning "Skipping automatic test in user mode. Please test manually with:"
        print_warning "  cd $INSTALL_DIR && python3 dns_server.py --port 5353 &"
        print_warning "  python3 test_dns.py --port 5353"
    else
        print_status "Starting DNS server for testing..."
        systemctl start $SERVICE_NAME
        sleep 2
        
        if systemctl is-active --quiet $SERVICE_NAME; then
            print_success "DNS server started successfully"
            
            # Run quick test
            cd "$INSTALL_DIR"
            if python3 test_dns.py --domain example.local &> /dev/null; then
                print_success "DNS server test passed!"
            else
                print_warning "DNS server test failed. Check the logs: journalctl -u $SERVICE_NAME"
            fi
        else
            print_error "Failed to start DNS server. Check logs: journalctl -u $SERVICE_NAME"
        fi
    fi
}

# Run deployment
deploy_dns_server

print_success "Deployment complete! 🎉" 