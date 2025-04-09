import os
import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "darkweb-monitoring-dev-key")

# Configure the database - ignore any old Neon database connection
database_url = os.environ.get("DATABASE_URL") 

# Use SQLite if no database URL or if URL contains the specific disabled endpoint
if not database_url or "ep-curly-paper-a6athvd0" in database_url:
    database_url = "sqlite:///darkweb.db"  # Simplified path in the root directory
    logger.warning("Using SQLite database in root directory")

# PostgreSQL URLs should start with postgresql://, not postgres://
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

logger.info(f"Using database type: {'PostgreSQL' if 'postgresql' in database_url else 'SQLite'}")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
# Different connection parameters depending on database type
if 'postgresql' in database_url:
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "connect_args": {"connect_timeout": 15}
    }
else:
    # SQLite doesn't support connect_timeout
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True
    }
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# email settings
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@darkwebmonitor.com")

# initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# initialize the app with the extension, flask-sqlalchemy >= 3.0.x
db.init_app(app)

# Initialize database resources in the correct order
with app.app_context():
    # Import models first
    import models  # noqa: F401
    
    # Initialize database connection pool after models
    from database import init_pool
    init_pool()
    
    try:
        # Create database tables
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
    
    # Import routes after models and database initialization
    try:
        import routes
        logger.info("Routes initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing routes: {e}")
