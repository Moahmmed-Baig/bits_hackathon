
import os
import logging
import sqlite3
import psycopg2
from psycopg2 import pool

# Set up logger
logger = logging.getLogger(__name__)

# Get database URL from environment
database_url = os.environ.get('DATABASE_URL')

# Use SQLite if no database URL or URL contains specific disabled endpoint
if not database_url or "ep-curly-paper-a6athvd0" in database_url:
    database_url = 'sqlite:///darkweb.db'  # Simplified path in the root directory
    logger.warning("Using SQLite database in root directory")

# Create connection pool
connection_pool = None

def init_pool():
    """Initialize database connection pool if using PostgreSQL"""
    global connection_pool
    
    # Use SQLite as fallback 
    if database_url.startswith('sqlite'):
        logger.info("Using SQLite database")
        # No need for connection pooling with SQLite
        return None
    
    try:
        # Use connection pooling for PostgreSQL
        logger.info("Initializing PostgreSQL connection pool")
        connection_pool = pool.SimpleConnectionPool(1, 10, database_url)
        logger.info("PostgreSQL connection pool initialized successfully")
        return connection_pool
    except Exception as e:
        logger.error(f"Error initializing PostgreSQL connection pool: {e}")
        logger.warning("Falling back to SQLite database")
        return None

def get_connection():
    """Get a database connection either from pool or directly"""
    if connection_pool:
        try:
            return connection_pool.getconn()
        except Exception as e:
            logger.error(f"Error getting connection from pool: {e}")
    
    # Fallback for SQLite or if pool fails
    if database_url.startswith('sqlite'):
        logger.info("Using SQLite connection (SQLAlchemy will handle this)")
        return None
    
    # Direct connection without pooling
    try:
        return psycopg2.connect(database_url)
    except Exception as e:
        logger.error(f"Error connecting to database: {e}")
        # We can't fallback to SQLite with psycopg2, let SQLAlchemy handle it
        logger.info("Falling back to SQLAlchemy-managed connection")
        return None

def return_connection(conn):
    """Return connection to pool or close it"""
    try:
        if connection_pool and conn:
            connection_pool.putconn(conn)
        elif conn:
            conn.close()
    except Exception as e:
        logger.error(f"Error returning connection: {e}")

def execute_query(query, params=None):
    """Execute a SQL query with optional parameters"""
    conn = None
    cur = None
    try:
        conn = get_connection()
        if not conn:
            logger.error("No database connection available")
            return []
            
        cur = conn.cursor()
        cur.execute(query, params)
        results = cur.fetchall()
        conn.commit()
        return results
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception as rollback_error:
                logger.error(f"Error rolling back transaction: {rollback_error}")
        logger.error(f"Error executing query: {e}")
        return []
    finally:
        if cur:
            try:
                cur.close()
            except Exception as cur_error:
                logger.error(f"Error closing cursor: {cur_error}")
        if conn:
            return_connection(conn)
