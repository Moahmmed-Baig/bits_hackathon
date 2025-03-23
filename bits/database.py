import os
import psycopg2
from psycopg2 import pool

# Get database URL from environment
database_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/darkweb.db')

# Create connection pool
connection_pool = None

def init_pool():
    global connection_pool
    if database_url.startswith('sqlite'):
        return None
    
    # Use connection pooling for PostgreSQL
    pooled_url = database_url.replace('.us-east-2', '-pooler.us-east-2')
    connection_pool = pool.SimpleConnectionPool(1, 10, pooled_url)
    return connection_pool

def get_connection():
    if connection_pool:
        return connection_pool.getconn()
    if database_url.startswith('sqlite'):
        return psycopg2.connect('sqlite:///instance/darkweb.db')
    return psycopg2.connect(database_url)

def return_connection(conn):
    if connection_pool:
        connection_pool.putconn(conn)
    else:
        conn.close()

def execute_query(query, params=None):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        results = cur.fetchall()
        conn.commit()
        return results
    finally:
        cur.close()
        return_connection(conn)
