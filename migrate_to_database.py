#!/usr/bin/env python3
"""
Migration script to convert JSON DNS records to SQLite database
"""

import json
import os
import sys
from dns_database import DNSDatabase


def migrate_json_to_database(json_file_path: str, db_path: str = 'dns_records.db'):
    """Migrate DNS records from JSON file to SQLite database"""
    
    print(f"Starting migration from {json_file_path} to {db_path}")
    
    # Check if JSON file exists
    if not os.path.exists(json_file_path):
        print(f"Error: JSON file {json_file_path} not found")
        return False
    
    try:
        # Initialize database
        database = DNSDatabase(db_path)
        
        # Read JSON file
        with open(json_file_path, 'r') as f:
            data = json.load(f)
        
        records = data.get('records', [])
        if not records:
            print("No records found in JSON file")
            return True
        
        print(f"Found {len(records)} records to migrate")
        
        # Import records to database
        success_count = 0
        for record_data in records:
            try:
                domain = record_data['domain']
                record_type = record_data['type']
                value = record_data['value']
                ttl = record_data.get('ttl', 300)
                
                if database.add_record(domain, record_type, value, ttl):
                    success_count += 1
                    print(f"  ✓ Migrated: {domain} {record_type} {value}")
                else:
                    print(f"  ✗ Failed: {domain} {record_type} {value}")
                    
            except KeyError as e:
                print(f"  ✗ Invalid record format: {record_data} - missing {e}")
            except Exception as e:
                print(f"  ✗ Error migrating record {record_data}: {e}")
        
        print(f"\nMigration completed: {success_count}/{len(records)} records migrated successfully")
        
        # Verify migration
        db_records = database.get_all_records()
        print(f"Database now contains {len(db_records)} records")
        
        return success_count == len(records)
        
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {json_file_path}: {e}")
        return False
    except Exception as e:
        print(f"Error during migration: {e}")
        return False


def backup_json_file(json_file_path: str):
    """Create a backup of the JSON file"""
    try:
        import shutil
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{json_file_path}.backup_{timestamp}"
        
        shutil.copy2(json_file_path, backup_path)
        print(f"Created backup: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"Warning: Could not create backup: {e}")
        return None


def main():
    """Main migration function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Migrate DNS records from JSON to SQLite database')
    parser.add_argument('--json', default='dns_records.json',
                        help='JSON file to migrate from (default: dns_records.json)')
    parser.add_argument('--db', default='dns_records.db',
                        help='Database file to migrate to (default: dns_records.db)')
    parser.add_argument('--backup', action='store_true',
                        help='Create backup of JSON file before migration')
    parser.add_argument('--force', action='store_true',
                        help='Overwrite existing database file')
    
    args = parser.parse_args()
    
    # Check if database already exists
    if os.path.exists(args.db) and not args.force:
        print(f"Database {args.db} already exists. Use --force to overwrite.")
        response = input("Do you want to continue? (y/N): ")
        if response.lower() != 'y':
            print("Migration cancelled")
            return
    
    # Create backup if requested
    if args.backup:
        backup_path = backup_json_file(args.json)
        if not backup_path:
            print("Backup failed. Aborting migration.")
            return
    
    # Perform migration
    success = migrate_json_to_database(args.json, args.db)
    
    if success:
        print("\n✅ Migration completed successfully!")
        print(f"Your DNS server will now use the database: {args.db}")
        print("You can safely remove the JSON file if desired.")
    else:
        print("\n❌ Migration failed!")
        print("Please check the errors above and try again.")


if __name__ == '__main__':
    main()
