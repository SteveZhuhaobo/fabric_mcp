#!/usr/bin/env python3
"""Quick test for SQL endpoint connection."""

import os
import pyodbc

# Test direct ODBC connection
server = "2mzfwn2wkhxe7o7l3ahcbhjxqi-fhwc4marthnedjvjt62u3dfo3e.datawarehouse.fabric.microsoft.com"

conn_str = (
    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
    f"SERVER={server};"

    f"Encrypt=yes;"
    f"TrustServerCertificate=no;"
    f"Connection Timeout=30;"
)

print(f"Testing connection to: {server}")
print(f"Connection string: {conn_str}")

try:
    connection = pyodbc.connect(conn_str)
    print("✅ Connection successful!")
    
    cursor = connection.cursor()
    cursor.execute("SELECT 1 as test")
    result = cursor.fetchone()
    print(f"✅ Query successful: {result}")
    
    # Try to list tables
    cursor.execute("""
        SELECT 
            SCHEMA_NAME(t.schema_id) as schema_name,
            t.name as table_name
        FROM sys.tables t
        WHERE t.is_ms_shipped = 0
    """)
    
    tables = cursor.fetchall()
    print(f"✅ Found {len(tables)} tables:")
    for table in tables:
        print(f"  - {table[0]}.{table[1]}")
    
    cursor.close()
    connection.close()
    
except Exception as e:
    print(f"❌ Connection failed: {e}")