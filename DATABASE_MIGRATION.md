# DNS Server Database Migration Guide

## Overview

The DNS server has been updated to use SQLite database storage instead of JSON files for better reliability, performance, and data integrity.

## What Changed

### Storage System
- **Before**: DNS records stored in `dns_records.json` file
- **After**: DNS records stored in `dns_records.db` SQLite database

### New Features
- **Database Storage**: Reliable SQLite database with ACID compliance
- **Web Interface**: Built-in web management interface (port 80)
- **Migration Tools**: Scripts to migrate from JSON to database
- **Better Performance**: Faster lookups and concurrent access
- **Data Integrity**: Built-in constraints and validation

### Removed Features
- **File Watching**: No longer needed with database storage
- **JSON Configuration**: Replaced with database management

## Migration Steps

### 1. Backup Your Data
```bash
# Create a backup of your JSON file
cp dns_records.json dns_records.json.backup
```

### 2. Run Migration Script
```bash
# Migrate with automatic backup
python3 migrate_to_database.py --backup

# Or migrate with custom paths
python3 migrate_to_database.py --json dns_records.json --db dns_records.db
```

### 3. Verify Migration
```bash
# Test the database functionality
python3 quick_test.py

# Check database contents
sqlite3 dns_records.db "SELECT * FROM dns_records;"
```

### 4. Start the Updated Server
```bash
# Start with database storage
sudo python3 dns_server.py

# Or use custom database path
sudo python3 dns_server.py --db /path/to/custom.db
```

## New Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--db` | Database file path | `dns_records.db` |
| `--web-port` | Web interface port | `80` |
| `--host` | Host to bind to | `0.0.0.0` |
| `--port` | DNS server port | `53` |
| `--upstream` | Upstream DNS servers | `8.8.8.8 8.8.4.4` |

## Web Interface

### Access
- URL: `http://localhost:80`
- Default credentials: `tkiley` / `test`

### Features
- Add, edit, and delete DNS records
- View all records in a table format
- Reset to default records
- Change password
- Debug server information

## Database Schema

```sql
CREATE TABLE dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER DEFAULT 300,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain, record_type, value)
);
```

## API Endpoints

The web interface provides these API endpoints:

- `GET /api/records` - Get all DNS records
- `POST /api/records/add` - Add a new record
- `POST /api/records/edit` - Edit an existing record
- `POST /api/records/delete` - Delete a record
- `POST /api/records/reset` - Reset to default records
- `GET /api/debug` - Get server debug information

## Database Management

### Direct Database Access
```python
from dns_database import DNSDatabase

# Initialize database
db = DNSDatabase('dns_records.db')

# Add record
db.add_record('example.local', 'A', '192.168.1.100', 300)

# Get records
records = db.get_all_records()

# Delete record
db.delete_record('example.local', 'A', '192.168.1.100')
```

### Backup and Restore
```bash
# Create backup
sqlite3 dns_records.db ".backup backup.db"

# Restore from backup
sqlite3 dns_records.db ".restore backup.db"
```

## Troubleshooting

### Migration Issues
1. **JSON file not found**: Ensure the JSON file exists and is readable
2. **Database already exists**: Use `--force` flag or delete existing database
3. **Permission errors**: Check file permissions and ownership

### Database Issues
1. **Corrupted database**: Use backup or recreate from JSON
2. **Lock errors**: Ensure no other process is using the database
3. **Disk space**: Check available disk space

### Web Interface Issues
1. **Port 80 in use**: Use `--web-port` to specify different port
2. **Authentication fails**: Reset password through web interface
3. **Records not showing**: Check database connectivity

## Rollback Plan

If you need to rollback to JSON storage:

1. **Export from database**:
   ```bash
   python3 -c "
   from dns_database import DNSDatabase
   import json
   db = DNSDatabase('dns_records.db')
   records = db.get_all_records()
   with open('dns_records.json', 'w') as f:
       json.dump({'records': records}, f, indent=2)
   "
   ```

2. **Use old server version** with JSON file

## Performance Improvements

- **Faster lookups**: Database indexes for domain and type queries
- **Concurrent access**: Multiple processes can read/write safely
- **Reduced memory usage**: Records loaded on-demand
- **Better scalability**: Handles thousands of records efficiently

## Security Considerations

- **Database file permissions**: Ensure proper file permissions
- **Web interface security**: Change default credentials
- **Network access**: Web interface accessible on all interfaces by default
- **SQL injection**: All queries use parameterized statements

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review server logs for error messages
3. Test with the provided test scripts
4. Verify database integrity with SQLite tools
