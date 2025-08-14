#!/usr/bin/env python3
"""
DNS Database Module
Handles SQLite database operations for DNS records storage.
"""

import sqlite3
import logging
import os
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class DNSDatabase:
    """SQLite database handler for DNS records"""

    def __init__(self, db_path: str = 'dns_records.db'):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize the database with required tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create DNS records table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS dns_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        record_type TEXT NOT NULL,
                        value TEXT NOT NULL,
                        ttl INTEGER DEFAULT 300,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(domain, record_type, value)
                    )
                ''')
                
                # Create index for faster lookups
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_domain_type 
                    ON dns_records(domain, record_type)
                ''')
                
                # Create index for domain lookups
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_domain 
                    ON dns_records(domain)
                ''')
                
                conn.commit()
                logger.info(f"Database initialized: {self.db_path}")
                
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise

    def add_record(self, domain: str, record_type: str, value: str, ttl: int = 300) -> bool:
        """Add a new DNS record to the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO dns_records 
                    (domain, record_type, value, ttl, updated_at) 
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (domain.lower(), record_type.upper(), value, ttl))
                conn.commit()
                logger.info(f"Added record: {domain} {record_type} {value}")
                return True
        except Exception as e:
            logger.error(f"Error adding record: {e}")
            return False

    def update_record(self, old_domain: str, old_type: str, old_value: str,
                     new_domain: str, new_type: str, new_value: str, new_ttl: int = 300) -> bool:
        """Update an existing DNS record"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE dns_records 
                    SET domain = ?, record_type = ?, value = ?, ttl = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE domain = ? AND record_type = ? AND value = ?
                ''', (new_domain.lower(), new_type.upper(), new_value, new_ttl,
                      old_domain.lower(), old_type.upper(), old_value))
                
                if cursor.rowcount > 0:
                    conn.commit()
                    logger.info(f"Updated record: {old_domain} {old_type} {old_value} -> {new_domain} {new_type} {new_value}")
                    return True
                else:
                    logger.warning(f"Record not found for update: {old_domain} {old_type} {old_value}")
                    return False
        except Exception as e:
            logger.error(f"Error updating record: {e}")
            return False

    def delete_record(self, domain: str, record_type: str, value: str) -> bool:
        """Delete a DNS record from the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM dns_records 
                    WHERE domain = ? AND record_type = ? AND value = ?
                ''', (domain.lower(), record_type.upper(), value))
                
                if cursor.rowcount > 0:
                    conn.commit()
                    logger.info(f"Deleted record: {domain} {record_type} {value}")
                    return True
                else:
                    logger.warning(f"Record not found for deletion: {domain} {record_type} {value}")
                    return False
        except Exception as e:
            logger.error(f"Error deleting record: {e}")
            return False

    def get_records_by_domain(self, domain: str) -> List[Dict]:
        """Get all records for a specific domain"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT domain, record_type, value, ttl, created_at, updated_at
                    FROM dns_records 
                    WHERE domain = ?
                    ORDER BY record_type, value
                ''', (domain.lower(),))
                
                records = []
                for row in cursor.fetchall():
                    records.append({
                        'domain': row[0],
                        'type': row[1],
                        'value': row[2],
                        'ttl': row[3],
                        'created_at': row[4],
                        'updated_at': row[5]
                    })
                return records
        except Exception as e:
            logger.error(f"Error getting records for domain {domain}: {e}")
            return []

    def get_records_by_domain_and_type(self, domain: str, record_type: str) -> List[Dict]:
        """Get records for a specific domain and record type"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT domain, record_type, value, ttl, created_at, updated_at
                    FROM dns_records 
                    WHERE domain = ? AND record_type = ?
                    ORDER BY value
                ''', (domain.lower(), record_type.upper()))
                
                records = []
                for row in cursor.fetchall():
                    records.append({
                        'domain': row[0],
                        'type': row[1],
                        'value': row[2],
                        'ttl': row[3],
                        'created_at': row[4],
                        'updated_at': row[5]
                    })
                return records
        except Exception as e:
            logger.error(f"Error getting records for {domain} {record_type}: {e}")
            return []

    def get_all_records(self) -> List[Dict]:
        """Get all DNS records from the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT domain, record_type, value, ttl, created_at, updated_at
                    FROM dns_records 
                    ORDER BY domain, record_type, value
                ''')
                
                records = []
                for row in cursor.fetchall():
                    records.append({
                        'domain': row[0],
                        'type': row[1],
                        'value': row[2],
                        'ttl': row[3],
                        'created_at': row[4],
                        'updated_at': row[5]
                    })
                return records
        except Exception as e:
            logger.error(f"Error getting all records: {e}")
            return []

    def get_all_domains(self) -> List[str]:
        """Get all unique domains in the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT DISTINCT domain 
                    FROM dns_records 
                    ORDER BY domain
                ''')
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting domains: {e}")
            return []

    def clear_all_records(self) -> bool:
        """Clear all DNS records from the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM dns_records')
                conn.commit()
                logger.info("Cleared all DNS records")
                return True
        except Exception as e:
            logger.error(f"Error clearing records: {e}")
            return False

    def record_exists(self, domain: str, record_type: str, value: str) -> bool:
        """Check if a specific record exists"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM dns_records 
                    WHERE domain = ? AND record_type = ? AND value = ?
                ''', (domain.lower(), record_type.upper(), value))
                return cursor.fetchone()[0] > 0
        except Exception as e:
            logger.error(f"Error checking record existence: {e}")
            return False

    def get_record_count(self) -> int:
        """Get the total number of DNS records"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM dns_records')
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error getting record count: {e}")
            return 0

    def get_domain_count(self) -> int:
        """Get the total number of unique domains"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(DISTINCT domain) FROM dns_records')
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error getting domain count: {e}")
            return 0

    def backup_database(self, backup_path: str = None) -> bool:
        """Create a backup of the database"""
        try:
            if backup_path is None:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"{self.db_path}.backup_{timestamp}"
            
            with sqlite3.connect(self.db_path) as source_conn:
                with sqlite3.connect(backup_path) as backup_conn:
                    source_conn.backup(backup_conn)
            
            logger.info(f"Database backed up to: {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Error backing up database: {e}")
            return False

    def import_from_json(self, json_file_path: str) -> bool:
        """Import DNS records from a JSON file"""
        try:
            import json
            with open(json_file_path, 'r') as f:
                data = json.load(f)
            
            records = data.get('records', [])
            success_count = 0
            
            for record_data in records:
                if self.add_record(
                    domain=record_data['domain'],
                    record_type=record_data['type'],
                    value=record_data['value'],
                    ttl=record_data.get('ttl', 300)
                ):
                    success_count += 1
            
            logger.info(f"Imported {success_count}/{len(records)} records from {json_file_path}")
            return success_count == len(records)
        except Exception as e:
            logger.error(f"Error importing from JSON: {e}")
            return False

    def export_to_json(self, json_file_path: str) -> bool:
        """Export DNS records to a JSON file"""
        try:
            import json
            records = self.get_all_records()
            
            # Convert to the expected format
            export_data = {
                'records': [
                    {
                        'domain': record['domain'],
                        'type': record['type'],
                        'value': record['value'],
                        'ttl': record['ttl']
                    }
                    for record in records
                ]
            }
            
            with open(json_file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Exported {len(records)} records to {json_file_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            return False
