#!/usr/bin/env python3
"""
Quick test for DNS database functionality
"""

from dns_database import DNSDatabase
import os

def test_database():
    """Quick test of database functionality"""
    print("Testing DNS Database...")
    
    # Use a test database file
    test_db = "test_dns.db"
    
    try:
        # Initialize database
        db = DNSDatabase(test_db)
        print("✓ Database initialized")
        
        # Add a test record
        result = db.add_record('test.local', 'A', '192.168.1.100', 300)
        if result:
            print("✓ Record added successfully")
        else:
            print("✗ Failed to add record")
            return False
        
        # Get all records
        records = db.get_all_records()
        print(f"✓ Retrieved {len(records)} records")
        
        # Check record count
        count = db.get_record_count()
        print(f"✓ Record count: {count}")
        
        # Get records by domain
        domain_records = db.get_records_by_domain('test.local')
        print(f"✓ Found {len(domain_records)} records for test.local")
        
        # Update record
        update_result = db.update_record(
            'test.local', 'A', '192.168.1.100',
            'test.local', 'A', '192.168.1.200', 600
        )
        if update_result:
            print("✓ Record updated successfully")
        else:
            print("✗ Failed to update record")
        
        # Delete record
        delete_result = db.delete_record('test.local', 'A', '192.168.1.200')
        if delete_result:
            print("✓ Record deleted successfully")
        else:
            print("✗ Failed to delete record")
        
        # Verify deletion
        final_count = db.get_record_count()
        print(f"✓ Final record count: {final_count}")
        
        print("\n✅ All database tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ Error during testing: {e}")
        return False
    finally:
        # Clean up test database
        if os.path.exists(test_db):
            os.unlink(test_db)
            print("✓ Test database cleaned up")

if __name__ == '__main__':
    test_database()
