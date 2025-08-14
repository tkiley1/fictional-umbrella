#!/usr/bin/env python3
"""
Test script for DNS database functionality
"""

import os
import tempfile
import unittest
from dns_database import DNSDatabase


class TestDNSDatabase(unittest.TestCase):
    """Test cases for DNS database functionality"""

    def setUp(self):
        """Set up test database"""
        # Create a temporary database file
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        self.db = DNSDatabase(self.temp_db.name)

    def tearDown(self):
        """Clean up test database"""
        self.db = None
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_add_record(self):
        """Test adding a DNS record"""
        result = self.db.add_record('test.local', 'A', '192.168.1.100', 300)
        self.assertTrue(result)
        
        # Verify record exists
        records = self.db.get_records_by_domain('test.local')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['domain'], 'test.local')
        self.assertEqual(records[0]['type'], 'A')
        self.assertEqual(records[0]['value'], '192.168.1.100')
        self.assertEqual(records[0]['ttl'], 300)

    def test_add_duplicate_record(self):
        """Test adding duplicate records (should replace)"""
        # Add first record
        self.db.add_record('test.local', 'A', '192.168.1.100', 300)
        
        # Add duplicate with different TTL
        result = self.db.add_record('test.local', 'A', '192.168.1.100', 600)
        self.assertTrue(result)
        
        # Should only have one record
        records = self.db.get_records_by_domain('test.local')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['ttl'], 600)

    def test_update_record(self):
        """Test updating a DNS record"""
        # Add initial record
        self.db.add_record('test.local', 'A', '192.168.1.100', 300)
        
        # Update record
        result = self.db.update_record(
            'test.local', 'A', '192.168.1.100',
            'test.local', 'A', '192.168.1.200', 600
        )
        self.assertTrue(result)
        
        # Verify update
        records = self.db.get_records_by_domain('test.local')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['value'], '192.168.1.200')
        self.assertEqual(records[0]['ttl'], 600)

    def test_delete_record(self):
        """Test deleting a DNS record"""
        # Add record
        self.db.add_record('test.local', 'A', '192.168.1.100', 300)
        
        # Delete record
        result = self.db.delete_record('test.local', 'A', '192.168.1.100')
        self.assertTrue(result)
        
        # Verify deletion
        records = self.db.get_records_by_domain('test.local')
        self.assertEqual(len(records), 0)

    def test_get_records_by_domain(self):
        """Test getting records by domain"""
        # Add multiple records
        self.db.add_record('test.local', 'A', '192.168.1.100', 300)
        self.db.add_record('test.local', 'AAAA', '::1', 300)
        self.db.add_record('other.local', 'A', '10.0.0.1', 300)
        
        # Get records for test.local
        records = self.db.get_records_by_domain('test.local')
        self.assertEqual(len(records), 2)
        
        # Check record types
        record_types = [r['type'] for r in records]
        self.assertIn('A', record_types)
        self.assertIn('AAAA', record_types)

    def test_get_records_by_domain_and_type(self):
        """Test getting records by domain and type"""
        # Add multiple records
        self.db.add_record('test.local', 'A', '192.168.1.100', 300)
        self.db.add_record('test.local', 'A', '192.168.1.101', 300)
        self.db.add_record('test.local', 'AAAA', '::1', 300)
        
        # Get A records only
        a_records = self.db.get_records_by_domain_and_type('test.local', 'A')
        self.assertEqual(len(a_records), 2)
        
        # Get AAAA records only
        aaaa_records = self.db.get_records_by_domain_and_type('test.local', 'AAAA')
        self.assertEqual(len(aaaa_records), 1)

    def test_get_all_records(self):
        """Test getting all records"""
        # Add multiple records
        self.db.add_record('test1.local', 'A', '192.168.1.100', 300)
        self.db.add_record('test2.local', 'A', '192.168.1.101', 300)
        
        # Get all records
        all_records = self.db.get_all_records()
        self.assertEqual(len(all_records), 2)
        
        # Check domains
        domains = [r['domain'] for r in all_records]
        self.assertIn('test1.local', domains)
        self.assertIn('test2.local', domains)

    def test_get_all_domains(self):
        """Test getting all unique domains"""
        # Add records for multiple domains
        self.db.add_record('test1.local', 'A', '192.168.1.100', 300)
        self.db.add_record('test1.local', 'AAAA', '::1', 300)
        self.db.add_record('test2.local', 'A', '192.168.1.101', 300)
        
        # Get all domains
        domains = self.db.get_all_domains()
        self.assertEqual(len(domains), 2)
        self.assertIn('test1.local', domains)
        self.assertIn('test2.local', domains)

    def test_clear_all_records(self):
        """Test clearing all records"""
        # Add some records
        self.db.add_record('test1.local', 'A', '192.168.1.100', 300)
        self.db.add_record('test2.local', 'A', '192.168.1.101', 300)
        
        # Clear all records
        result = self.db.clear_all_records()
        self.assertTrue(result)
        
        # Verify all records are gone
        all_records = self.db.get_all_records()
        self.assertEqual(len(all_records), 0)

    def test_record_exists(self):
        """Test checking if record exists"""
        # Add a record
        self.db.add_record('test.local', 'A', '192.168.1.100', 300)
        
        # Check if it exists
        self.assertTrue(self.db.record_exists('test.local', 'A', '192.168.1.100'))
        self.assertFalse(self.db.record_exists('test.local', 'A', '192.168.1.101'))
        self.assertFalse(self.db.record_exists('nonexistent.local', 'A', '192.168.1.100'))

    def test_get_record_count(self):
        """Test getting record count"""
        # Initially should be 0
        self.assertEqual(self.db.get_record_count(), 0)
        
        # Add records
        self.db.add_record('test1.local', 'A', '192.168.1.100', 300)
        self.db.add_record('test2.local', 'A', '192.168.1.101', 300)
        
        # Should be 2
        self.assertEqual(self.db.get_record_count(), 2)

    def test_get_domain_count(self):
        """Test getting domain count"""
        # Initially should be 0
        self.assertEqual(self.db.get_domain_count(), 0)
        
        # Add records for multiple domains
        self.db.add_record('test1.local', 'A', '192.168.1.100', 300)
        self.db.add_record('test1.local', 'AAAA', '::1', 300)
        self.db.add_record('test2.local', 'A', '192.168.1.101', 300)
        
        # Should be 2 unique domains
        self.assertEqual(self.db.get_domain_count(), 2)

    def test_case_insensitive(self):
        """Test that domain and type are case insensitive"""
        # Add record with mixed case
        self.db.add_record('TEST.LOCAL', 'a', '192.168.1.100', 300)
        
        # Should be stored in lowercase
        records = self.db.get_records_by_domain('test.local')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['domain'], 'test.local')
        self.assertEqual(records[0]['type'], 'A')

    def test_backup_database(self):
        """Test database backup functionality"""
        # Add some records
        self.db.add_record('test.local', 'A', '192.168.1.100', 300)
        
        # Create backup
        result = self.db.backup_database()
        self.assertTrue(result)
        
        # Check if backup file exists
        backup_files = [f for f in os.listdir('.') if f.startswith(self.db.db_path) and 'backup' in f]
        self.assertGreater(len(backup_files), 0)
        
        # Clean up backup files
        for backup_file in backup_files:
            os.unlink(backup_file)


def run_tests():
    """Run all tests"""
    print("Running DNS Database Tests...")
    unittest.main(verbosity=2)


if __name__ == '__main__':
    run_tests()
