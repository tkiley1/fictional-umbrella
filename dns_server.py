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
import time
import os
from typing import Dict, List, Tuple, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import html

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variable to store the DNS server instance
_global_dns_server = None

# Simple authentication - you can change these credentials
AUTH_USERNAME = "tkiley"
AUTH_PASSWORD = "test"

# Store active sessions (in a real app, you'd use a database)
active_sessions = {}


class DNSRecord:
    """Represents a DNS record"""

    def __init__(self, domain: str, record_type: str, value: str, ttl: int = 300):
        self.domain = domain.lower()
        self.record_type = record_type.upper()
        self.value = value
        self.ttl = ttl


class ConfigFileHandler(FileSystemEventHandler):
    """Handler for config file changes"""

    def __init__(self, dns_server):
        self.dns_server = dns_server
        self.last_modified = 0

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(self.dns_server.config_file):
            # Debounce rapid file changes
            current_time = time.time()
            if current_time - self.last_modified > 1.0:  # Wait at least 1 second between reloads
                self.last_modified = current_time
                logger.info(
                    f"Config file {self.dns_server.config_file} changed, reloading records...")
                self.dns_server.load_records()


class DNSWebHandler(BaseHTTPRequestHandler):
    """HTTP request handler for DNS management web interface"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Get the DNS server from the global variable
        global _global_dns_server
        self.dns_server = _global_dns_server

    def setup(self):
        """Called before handle_one_request"""
        super().setup()
        # Ensure dns_server is set in case __init__ wasn't called properly
        if not hasattr(self, 'dns_server') or self.dns_server is None:
            global _global_dns_server
            self.dns_server = _global_dns_server

    def do_GET(self):
        """Handle GET requests"""
        # Ensure dns_server is available
        if not hasattr(self, 'dns_server') or self.dns_server is None:
            global _global_dns_server
            self.dns_server = _global_dns_server

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == '/':
            # Check authentication for main page
            if not self.is_authenticated():
                self.send_login_page()
                return
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_main_page().encode())
        elif path == '/login':
            self.send_login_page()
        elif path == '/logout':
            self.logout()
            self.send_login_page()
        elif path == '/api/records':
            # Check authentication for API endpoints
            if not self.is_authenticated():
                self.send_unauthorized_response()
                return
            try:
                records_json = self.get_records_json()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(records_json.encode('utf-8'))
            except Exception as e:
                logger.error(f"Error serving /api/records: {e}")
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                error_response = json.dumps(
                    {'error': 'Internal server error', 'details': str(e)})
                self.wfile.write(error_response.encode('utf-8'))
        elif path == '/api/debug':
            # Check authentication for debug endpoint
            if not self.is_authenticated():
                self.send_unauthorized_response()
                return
            # Debug endpoint to check server state
            try:
                debug_info = {
                    'records_count': len(self.dns_server.records),
                    'domains': list(self.dns_server.records.keys()),
                    'server_type': str(type(self.dns_server)),
                    'records_type': str(type(self.dns_server.records)),
                    'records_content': str(self.dns_server.records),
                    'config_file_exists': os.path.exists(self.dns_server.config_file) if hasattr(self.dns_server, 'config_file') else False
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(
                    debug_info, ensure_ascii=False).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                error_response = json.dumps(
                    {'error': 'Debug error', 'details': str(e)})
                self.wfile.write(error_response.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def do_POST(self):
        """Handle POST requests for adding/editing records"""
        # Ensure dns_server is available
        if not hasattr(self, 'dns_server') or self.dns_server is None:
            global _global_dns_server
            self.dns_server = _global_dns_server

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == '/login':
            self.handle_login()
            return
        elif path == '/api/change-password':
            # Check authentication for password change
            if not self.is_authenticated():
                self.send_unauthorized_response()
                return
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.handle_change_password(post_data)
        elif path == '/api/records/add':
            # Check authentication for API endpoints
            if not self.is_authenticated():
                self.send_unauthorized_response()
                return
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.handle_add_record(post_data)
        elif path == '/api/records/edit':
            # Check authentication for API endpoints
            if not self.is_authenticated():
                self.send_unauthorized_response()
                return
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.handle_edit_record(post_data)
        elif path == '/api/records/delete':
            # Check authentication for API endpoints
            if not self.is_authenticated():
                self.send_unauthorized_response()
                return
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.handle_delete_record(post_data)
        elif path == '/api/records/reset':
            # Check authentication for API endpoints
            if not self.is_authenticated():
                self.send_unauthorized_response()
                return
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.handle_reset_records(post_data)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def handle_add_record(self, post_data):
        """Handle adding a new DNS record"""
        try:
            data = json.loads(post_data)
            domain = data.get('domain', '').strip()
            record_type = data.get('type', '').strip().upper()
            value = data.get('value', '').strip()
            ttl = int(data.get('ttl', 300))

            if not all([domain, record_type, value]):
                self.send_error_response("All fields are required")
                return

            # Add record to DNS server
            record = DNSRecord(domain, record_type, value, ttl)
            if domain not in self.dns_server.records:
                self.dns_server.records[domain] = []
            self.dns_server.records[domain].append(record)

            # Save to file
            try:
                self.dns_server.save_records()
                self.send_success_response("Record added successfully")
            except Exception as save_error:
                # Remove the record if save failed
                self.dns_server.records[domain].remove(record)
                if not self.dns_server.records[domain]:
                    del self.dns_server.records[domain]
                self.send_error_response(
                    f"Error saving record: {str(save_error)}")

        except json.JSONDecodeError:
            self.send_error_response("Invalid JSON data received")
        except ValueError as e:
            self.send_error_response(f"Invalid data format: {str(e)}")
        except Exception as e:
            self.send_error_response(f"Error adding record: {str(e)}")

    def handle_edit_record(self, post_data):
        """Handle editing an existing DNS record"""
        try:
            data = json.loads(post_data)
            old_domain = data.get('old_domain', '').strip()
            old_type = data.get('old_type', '').strip().upper()
            old_value = data.get('old_value', '').strip()

            new_domain = data.get('new_domain', '').strip()
            new_type = data.get('new_type', '').strip().upper()
            new_value = data.get('new_value', '').strip()
            new_ttl = int(data.get('new_ttl', 300))

            if not all([old_domain, old_type, old_value, new_domain, new_type, new_value]):
                self.send_error_response("All fields are required")
                return

            # Find and update record
            if old_domain in self.dns_server.records:
                for record in self.dns_server.records[old_domain]:
                    if (record.domain == old_domain and
                        record.record_type == old_type and
                            record.value == old_value):

                        # Remove old record
                        self.dns_server.records[old_domain].remove(record)
                        if not self.dns_server.records[old_domain]:
                            del self.dns_server.records[old_domain]

                        # Add new record
                        new_record = DNSRecord(
                            new_domain, new_type, new_value, new_ttl)
                        if new_domain not in self.dns_server.records:
                            self.dns_server.records[new_domain] = []
                        self.dns_server.records[new_domain].append(new_record)

                        # Save to file
                        try:
                            self.dns_server.save_records()
                            self.send_success_response(
                                "Record updated successfully")
                        except Exception as save_error:
                            # Revert changes if save failed
                            if new_domain in self.dns_server.records:
                                self.dns_server.records[new_domain].remove(
                                    new_record)
                                if not self.dns_server.records[new_domain]:
                                    del self.dns_server.records[new_domain]

                            # Restore old record
                            if old_domain not in self.dns_server.records:
                                self.dns_server.records[old_domain] = []
                            self.dns_server.records[old_domain].append(record)

                            self.send_error_response(
                                f"Error saving record: {str(save_error)}")
                        return

            self.send_error_response("Record not found")

        except json.JSONDecodeError:
            self.send_error_response("Invalid JSON data received")
        except ValueError as e:
            self.send_error_response(f"Invalid data format: {str(e)}")
        except Exception as e:
            self.send_error_response(f"Error updating record: {str(e)}")

    def handle_delete_record(self, post_data):
        """Handle deleting a DNS record"""
        try:
            data = json.loads(post_data)
            domain = data.get('domain', '').strip()
            record_type = data.get('type', '').strip().upper()
            value = data.get('value', '').strip()

            if not all([domain, record_type, value]):
                self.send_error_response("All fields are required")
                return

            # Find and remove record
            if domain in self.dns_server.records:
                for record in self.dns_server.records[domain]:
                    if (record.domain == domain and
                        record.record_type == record_type and
                            record.value == value):

                        self.dns_server.records[domain].remove(record)
                        if not self.dns_server.records[domain]:
                            del self.dns_server.records[domain]

                        # Save to file
                        try:
                            self.dns_server.save_records()
                            self.send_success_response(
                                "Record deleted successfully")
                        except Exception as save_error:
                            # Restore the record if save failed
                            if domain not in self.dns_server.records:
                                self.dns_server.records[domain] = []
                            self.dns_server.records[domain].append(record)
                            self.send_error_response(
                                f"Error saving record: {str(save_error)}")
                        return

            self.send_error_response("Record not found")

        except json.JSONDecodeError:
            self.send_error_response("Invalid JSON data received")
        except Exception as e:
            self.send_error_response(f"Error deleting record: {str(e)}")

    def handle_reset_records(self, post_data):
        """Handle resetting DNS records to default"""
        try:
            # Create default records
            self.dns_server.create_default_records()

            # Save to file
            try:
                self.dns_server.save_records()
                self.send_success_response(
                    "Records reset to default successfully")
            except Exception as save_error:
                self.send_error_response(
                    f"Error saving default records: {str(save_error)}")

        except Exception as e:
            self.send_error_response(f"Error resetting records: {str(e)}")

    def handle_change_password(self, post_data):
        """Handle changing the user password"""
        global AUTH_PASSWORD
        try:
            data = json.loads(post_data)
            current_password = data.get('current_password', '').strip()
            new_password = data.get('new_password', '').strip()
            confirm_password = data.get('confirm_password', '').strip()

            if not all([current_password, new_password, confirm_password]):
                self.send_error_response("All fields are required")
                return

            # Verify current password
            if current_password != AUTH_PASSWORD:
                self.send_error_response("Current password is incorrect")
                return

            # Check if new passwords match
            if new_password != confirm_password:
                self.send_error_response("New passwords do not match")
                return

            # Check password length
            if len(new_password) < 4:
                self.send_error_response(
                    "New password must be at least 4 characters long")
                return

            # Update password
            AUTH_PASSWORD = new_password
            self.send_success_response("Password changed successfully")

        except json.JSONDecodeError:
            self.send_error_response("Invalid JSON data received")
        except Exception as e:
            self.send_error_response(f"Error changing password: {str(e)}")

    def send_success_response(self, message):
        """Send a success response"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = json.dumps({'success': True, 'message': message})
        self.wfile.write(response.encode())

    def send_error_response(self, message):
        """Send an error response"""
        self.send_response(400)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = json.dumps({'success': False, 'message': message})
        self.wfile.write(response.encode())

    def get_records_json(self):
        """Get DNS records as JSON"""
        try:
            # Ensure dns_server is available
            if not hasattr(self, 'dns_server') or self.dns_server is None:
                global _global_dns_server
                self.dns_server = _global_dns_server

            records_list = []
            logger.debug(f"Serializing {len(self.dns_server.records)} domains")

            for domain, domain_records in self.dns_server.records.items():
                logger.debug(
                    f"Processing domain: {domain} with {len(domain_records)} records")
                for record in domain_records:
                    try:
                        # Ensure we're only serializing primitive data types
                        record_dict = {
                            'domain': str(record.domain),
                            'type': str(record.record_type),
                            'value': str(record.value),
                            'ttl': int(record.ttl)
                        }
                        records_list.append(record_dict)
                    except Exception as record_error:
                        logger.error(
                            f"Error processing record {record}: {record_error}")
                        continue

            logger.debug(
                f"Successfully serialized {len(records_list)} records")
            return json.dumps(records_list, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error serializing records: {e}")
            if hasattr(self, 'dns_server') and self.dns_server:
                logger.error(
                    f"Records object type: {type(self.dns_server.records)}")
                logger.error(f"Records content: {self.dns_server.records}")
            # Return empty array as fallback
            return json.dumps([], ensure_ascii=False)

    def is_authenticated(self):
        """Check if the user is authenticated"""
        global active_sessions
        cookie_header = self.headers.get('Cookie', '')
        if 'session_id=' in cookie_header:
            session_id = cookie_header.split('session_id=')[1].split(';')[0]
            if session_id in active_sessions:
                # Check if session is still valid (24 hours)
                if time.time() - active_sessions[session_id] < 86400:
                    return True
                else:
                    # Session expired, remove it
                    del active_sessions[session_id]
        return False

    def generate_session_id(self):
        """Generate a unique session ID"""
        import secrets
        return secrets.token_hex(16)

    def handle_login(self):
        """Handle login form submission"""
        global active_sessions, AUTH_USERNAME, AUTH_PASSWORD

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        try:
            # Parse form data
            form_data = {}
            for item in post_data.split('&'):
                if '=' in item:
                    key, value = item.split('=', 1)
                    form_data[key] = value

            username = form_data.get('username', '')
            password = form_data.get('password', '')

            if username == AUTH_USERNAME and password == AUTH_PASSWORD:
                # Login successful
                session_id = self.generate_session_id()
                active_sessions[session_id] = time.time()

                self.send_response(302)  # Redirect
                self.send_header('Location', '/')
                self.send_header(
                    'Set-Cookie', f'session_id={session_id}; Path=/; HttpOnly')
                self.end_headers()
            else:
                # Login failed
                self.send_login_page("Invalid username or password")
        except Exception as e:
            logger.error(f"Login error: {e}")
            self.send_login_page("Login error occurred")

    def logout(self):
        """Handle logout"""
        global active_sessions
        cookie_header = self.headers.get('Cookie', '')
        if 'session_id=' in cookie_header:
            session_id = cookie_header.split('session_id=')[1].split(';')[0]
            if session_id in active_sessions:
                del active_sessions[session_id]

        self.send_response(302)  # Redirect
        self.send_header('Location', '/login')
        self.send_header(
            'Set-Cookie', 'session_id=; Path=/; HttpOnly; Max-Age=0')
        self.end_headers()

    def send_login_page(self, error_message=""):
        """Send the login page"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.get_login_page(error_message).encode())

    def send_unauthorized_response(self):
        """Send unauthorized response"""
        self.send_response(401)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        error_response = json.dumps(
            {'error': 'Unauthorized', 'message': 'Authentication required'})
        self.wfile.write(error_response.encode())

    def get_login_page(self, error_message=""):
        """Get the login HTML page"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Records Manager - Login</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .login-container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }}
        h1 {{
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #333;
        }}
        input[type="text"], input[type="password"] {{
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 16px;
        }}
        button {{
            background-color: #007bff;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
            margin-top: 10px;
        }}
        button:hover {{
            background-color: #0056b3;
        }}
        .error {{
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
        }}
        .info {{
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <h1>DNS Records Manager</h1>
        
        
        
        {f'<div class="error">{error_message}</div>' if error_message else ''}
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
        """

    def get_main_page(self):
        """Get the main HTML page"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Records Manager</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .form-section {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: #fafafa;
        }
        .form-section h2 {
            margin-top: 0;
            color: #555;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #333;
        }
        input[type="text"], input[type="number"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
        }
        button:hover {
            background-color: #0056b3;
        }
        button.delete {
            background-color: #dc3545;
        }
        button.delete:hover {
            background-color: #c82333;
        }
        .records-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .records-table th, .records-table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        .records-table th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .records-table tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .action-buttons {
            display: flex;
            gap: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <h1 style="margin: 0;">DNS Records Manager</h1>
            <div style="display: flex; gap: 10px;">
                <button onclick="showChangePasswordForm()" style="background-color: #28a745; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer;">Change Password</button>
                <a href="/logout" style="background-color: #6c757d; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px;">Logout</a>
            </div>
        </div>
        
        <div id="message"></div>
        
        <!-- Add Record Form -->
        <div class="form-section">
            <h2>Add New DNS Record</h2>
            <form id="addForm">
                <div class="form-group">
                    <label for="addDomain">Domain:</label>
                    <input type="text" id="addDomain" name="domain" required placeholder="example.com">
                </div>
                <div class="form-group">
                    <label for="addType">Type:</label>
                    <input type="text" id="addType" name="type" required placeholder="A" value="A">
                </div>
                <div class="form-group">
                    <label for="addValue">Value:</label>
                    <input type="text" id="addValue" name="value" required placeholder="192.168.1.100">
                </div>
                <div class="form-group">
                    <label for="addTtl">TTL:</label>
                    <input type="number" id="addTtl" name="ttl" value="300" min="1">
                </div>
                <button type="submit">Add Record</button>
            </form>
        </div>
        
        <!-- Edit Record Form -->
        <div class="form-section">
            <h2>Edit DNS Record</h2>
            <form id="editForm">
                <div class="form-group">
                    <label for="editOldDomain">Current Domain:</label>
                    <input type="text" id="editOldDomain" name="oldDomain" required>
                </div>
                <div class="form-group">
                    <label for="editOldType">Current Type:</label>
                    <input type="text" id="editOldType" name="oldType" required>
                </div>
                <div class="form-group">
                    <label for="editOldValue">Current Value:</label>
                    <input type="text" id="editOldValue" name="oldValue" required>
                </div>
                <hr>
                <div class="form-group">
                    <label for="editNewDomain">New Domain:</label>
                    <input type="text" id="editNewDomain" name="newDomain" required>
                </div>
                <div class="form-group">
                    <label for="editNewType">New Type:</label>
                    <input type="text" id="editNewType" name="newType" required>
                </div>
                <div class="form-group">
                    <label for="editNewValue">New Value:</label>
                    <input type="text" id="editNewValue" name="newValue" required>
                </div>
                <div class="form-group">
                    <label for="editNewTtl">New TTL:</label>
                    <input type="number" id="editNewTtl" name="newTtl" value="300" min="1">
                </div>
                <button type="submit">Update Record</button>
            </form>
        </div>
        
        <!-- Records Table -->
        <div class="form-section">
            <h2>Current DNS Records</h2>
            <button onclick="loadRecords()">Refresh Records</button>
            <button onclick="resetRecords()" style="background-color: #ffc107; color: #000;">Reset to Default</button>
            <button onclick="debugServer()" style="background-color: #17a2b8; color: #fff;">Debug Server</button>
            <table class="records-table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Type</th>
                        <th>Value</th>
                        <th>TTL</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="recordsTableBody">
                </tbody>
                         </table>
         </div>
         
         <!-- Change Password Form (Hidden by default) -->
         <div id="changePasswordForm" class="form-section" style="display: none;">
             <h2>Change Password</h2>
             <form id="passwordForm">
                 <div class="form-group">
                     <label for="currentPassword">Current Password:</label>
                     <input type="password" id="currentPassword" name="currentPassword" required>
                 </div>
                 <div class="form-group">
                     <label for="newPassword">New Password:</label>
                     <input type="password" id="newPassword" name="newPassword" required minlength="4">
                 </div>
                 <div class="form-group">
                     <label for="confirmPassword">Confirm New Password:</label>
                     <input type="password" id="confirmPassword" name="confirmPassword" required minlength="4">
                 </div>
                 <button type="submit">Change Password</button>
                 <button type="button" onclick="hideChangePasswordForm()" style="background-color: #6c757d;">Cancel</button>
             </form>
         </div>
     </div>

     <script>
        // Load records on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadRecords();
        });
        
        // Add record form handler
        document.getElementById('addForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = {
                domain: formData.get('domain'),
                type: formData.get('type'),
                value: formData.get('value'),
                ttl: parseInt(formData.get('ttl'))
            };
            
            fetch('/api/records/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                showMessage(data.message, data.success);
                if (data.success) {
                    e.target.reset();
                    loadRecords();
                }
            })
            .catch(error => {
                showMessage('Error: ' + error.message, false);
            });
        });
        
        // Edit record form handler
        document.getElementById('editForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = {
                old_domain: formData.get('oldDomain'),
                old_type: formData.get('oldType'),
                old_value: formData.get('oldValue'),
                new_domain: formData.get('newDomain'),
                new_type: formData.get('newType'),
                new_value: formData.get('newValue'),
                new_ttl: parseInt(formData.get('newTtl'))
            };
            
            fetch('/api/records/edit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                showMessage(data.message, data.success);
                if (data.success) {
                    e.target.reset();
                    loadRecords();
                }
            })
            .catch(error => {
                showMessage('Error: ' + error.message, false);
            });
        });
        
        function loadRecords() {
            fetch('/api/records')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                // Check if we got an error response
                if (data.error) {
                    throw new Error(data.error + (data.details ? ': ' + data.details : ''));
                }
                
                // Ensure records is an array
                const records = Array.isArray(data) ? data : [];
                
                const tbody = document.getElementById('recordsTableBody');
                tbody.innerHTML = '';
                
                if (records.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #666;">No DNS records found</td></tr>';
                    return;
                }
                
                records.forEach(record => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${record.domain}</td>
                        <td>${record.type}</td>
                        <td>${record.value}</td>
                        <td>${record.ttl}</td>
                        <td class="action-buttons">
                            <button onclick="editRecord('${record.domain}', '${record.type}', '${record.value}', ${record.ttl})">Edit</button>
                            <button class="delete" onclick="deleteRecord('${record.domain}', '${record.type}', '${record.value}')">Delete</button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            })
            .catch(error => {
                console.error('Error loading records:', error);
                showMessage('Error loading records: ' + error.message, false);
                const tbody = document.getElementById('recordsTableBody');
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #dc3545;">Failed to load records</td></tr>';
            });
        }
        
        function editRecord(domain, type, value, ttl) {
            document.getElementById('editOldDomain').value = domain;
            document.getElementById('editOldType').value = type;
            document.getElementById('editOldValue').value = value;
            document.getElementById('editNewDomain').value = domain;
            document.getElementById('editNewType').value = type;
            document.getElementById('editNewValue').value = value;
            document.getElementById('editNewTtl').value = ttl;
        }
        
        function deleteRecord(domain, type, value) {
            if (confirm('Are you sure you want to delete this record?')) {
                const data = { domain, type, value };
                
                fetch('/api/records/delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                })
                .then(response => response.json())
                .then(data => {
                    showMessage(data.message, data.success);
                    if (data.success) {
                        loadRecords();
                    }
                })
                .catch(error => {
                    showMessage('Error: ' + error.message, false);
                });
            }
        }
        
        function resetRecords() {
            if (confirm('Are you sure you want to reset all records to default? This will delete all current records.')) {
                fetch('/api/records/reset', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({})
                })
                .then(response => response.json())
                .then(data => {
                    showMessage(data.message, data.success);
                    if (data.success) {
                        loadRecords();
                    }
                })
                .catch(error => {
                    showMessage('Error: ' + error.message, false);
                });
            }
        }
        
        function debugServer() {
            fetch('/api/debug')
            .then(response => response.json())
            .then(data => {
                console.log('Debug info:', data);
                showMessage('Debug info logged to console. Check browser developer tools.', true);
            })
            .catch(error => {
                console.error('Debug error:', error);
                showMessage('Debug error: ' + error.message, false);
            });
        }
        
                 function showMessage(message, isSuccess) {
             const messageDiv = document.getElementById('message');
             messageDiv.className = 'message ' + (isSuccess ? 'success' : 'error');
             messageDiv.textContent = message;
             
             setTimeout(() => {
                 messageDiv.textContent = '';
                 messageDiv.className = 'message';
             }, 5000);
         }
         
         // Change password form handler
         document.getElementById('passwordForm').addEventListener('submit', function(e) {
             e.preventDefault();
             const formData = new FormData(e.target);
             const data = {
                 current_password: formData.get('currentPassword'),
                 new_password: formData.get('newPassword'),
                 confirm_password: formData.get('confirmPassword')
             };
             
             fetch('/api/change-password', {
                 method: 'POST',
                 headers: {
                     'Content-Type': 'application/json',
                 },
                 body: JSON.stringify(data)
             })
             .then(response => response.json())
             .then(data => {
                 showMessage(data.message, data.success);
                 if (data.success) {
                     e.target.reset();
                     hideChangePasswordForm();
                 }
             })
             .catch(error => {
                 showMessage('Error: ' + error.message, false);
             });
         });
         
         function showChangePasswordForm() {
             document.getElementById('changePasswordForm').style.display = 'block';
             document.getElementById('currentPassword').focus();
         }
         
         function hideChangePasswordForm() {
             document.getElementById('changePasswordForm').style.display = 'none';
             document.getElementById('passwordForm').reset();
         }
     </script>
 </body>
 </html>
        """


class DNSServer:
    """Simple DNS Server implementation"""

    def __init__(self, host: str = '0.0.0.0', port: int = 53, config_file: str = 'dns_records.json',
                 upstream_dns: List[str] = None, web_port: int = 80):
        self.host = host
        self.port = port
        self.web_port = web_port
        self.config_file = config_file
        self.upstream_dns = upstream_dns or [
            '8.8.8.8', '8.8.4.4']  # Google DNS as default
        self.records: Dict[str, List[DNSRecord]] = {}
        self.file_observer = None
        self.web_server = None
        self.load_records()
        self.start_file_watcher()
        self.start_web_server()

    def start_file_watcher(self):
        """Start watching the config file for changes"""
        try:
            self.file_observer = Observer()
            event_handler = ConfigFileHandler(self)
            self.file_observer.schedule(
                event_handler, path='.', recursive=False)
            self.file_observer.start()
            logger.info(f"Started watching {self.config_file} for changes")
        except Exception as e:
            logger.warning(f"Could not start file watcher: {e}")

    def stop_file_watcher(self):
        """Stop watching the config file"""
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
            logger.info("Stopped file watcher")

    def start_web_server(self):
        """Start the web server for DNS management"""
        try:
            # Set the global DNS server instance
            global _global_dns_server
            _global_dns_server = self

            # Create the HTTP server with the handler
            self.web_server = HTTPServer(
                (self.host, self.web_port), DNSWebHandler)

            web_thread = threading.Thread(
                target=self.web_server.serve_forever, daemon=True)
            web_thread.start()
            logger.info(
                f"Web interface started on http://{self.host}:{self.web_port}")
        except Exception as e:
            logger.error(f"Could not start web server: {e}")

    def stop_web_server(self):
        """Stop the web server"""
        if self.web_server:
            self.web_server.shutdown()
            logger.info("Web server stopped")

    def backup_corrupted_file(self):
        """Create a backup of the corrupted config file"""
        try:
            import shutil
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{self.config_file}.backup_{timestamp}"
            shutil.copy2(self.config_file, backup_name)
            logger.info(f"Created backup: {backup_name}")
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")

    def save_records(self):
        """Save DNS records to configuration file"""
        try:
            records_list = []
            for domain, domain_records in self.records.items():
                for record in domain_records:
                    records_list.append({
                        'domain': record.domain,
                        'type': record.record_type,
                        'value': record.value,
                        'ttl': record.ttl
                    })

            config = {'records': records_list}

            # Write to a temporary file first, then rename to avoid corruption
            import tempfile
            import os

            temp_file = tempfile.NamedTemporaryFile(
                mode='w', delete=False, dir='.')
            try:
                json.dump(config, temp_file, indent=2)
                temp_file.close()

                # Atomic rename to avoid corruption
                os.replace(temp_file.name, self.config_file)

                logger.info(
                    f"Saved {len(records_list)} DNS records to {self.config_file}")
            except Exception as e:
                # Clean up temp file if something went wrong
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
                raise e

        except Exception as e:
            logger.error(f"Error saving records: {e}")
            raise

    def load_records(self):
        """Load DNS records from configuration file"""
        try:
            with open(self.config_file, 'r') as f:
                content = f.read().strip()

            if not content:
                logger.warning(
                    f"Configuration file {self.config_file} is empty. Using default records.")
                self.create_default_records()
                return

            config = json.loads(content)

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
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {self.config_file}: {e}")
            logger.info(
                "Creating backup of corrupted file and using default records.")
            self.backup_corrupted_file()
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
            self.stop_file_watcher()
            self.stop_web_server()
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
    parser.add_argument('--web-port', type=int, default=80,
                        help='Web interface port (default: 80)')
    parser.add_argument('--config', default='dns_records.json',
                        help='Configuration file (default: dns_records.json)')
    parser.add_argument('--upstream', nargs='+', default=['8.8.8.8', '8.8.4.4'],
                        help='Upstream DNS servers (default: 8.8.8.8 8.8.4.4)')

    args = parser.parse_args()

    server = DNSServer(host=args.host, port=args.port, web_port=args.web_port,
                       config_file=args.config, upstream_dns=args.upstream)
    server.start()


if __name__ == '__main__':
    main()
