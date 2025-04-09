
# Dark Web Monitor

A sophisticated dark web monitoring system that helps organizations detect potential data leaks and security breaches by scanning the dark web using AI-powered analysis.

## Features

- **Dark Web Scanning**: Anonymously crawl the dark web using Tor
- **AI Detection**: Machine learning model identifies potential data leaks
- **Instant Alerts**: Real-time email notifications when breaches are detected
- **Monitoring Dashboard**: Visualize and track potential threats
- **Custom Detection Rules**: Create and manage custom patterns for leak detection
- **Target Management**: Configure scan targets and monitor specific .onion sites
- **Keyword Tracking**: Monitor organization-specific keywords and sensitive terms

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite/PostgreSQL with SQLAlchemy ORM
- **Frontend**: Bootstrap, Chart.js
- **ML/AI**: scikit-learn for leak detection
- **Network**: Tor integration via SOCKS proxy
- **Security**: Flask-Login for authentication

## Getting Started

1. Install dependencies
2. Configure environment variables:
   - `SESSION_SECRET`: Secret key for session management
   - `MAIL_USERNAME`: Email for notifications
   - `MAIL_PASSWORD`: Email password
   - `MAIL_SERVER`: SMTP server (default: smtp.gmail.com)
   - `MAIL_PORT`: SMTP port (default: 587)

3. Click the "Run" button to start the application
4. Access the application through the provided URL
5. Register an account and log in
6. Configure your organization's keywords and scan targets

## Usage

1. **Dashboard**: View recent scans, breaches, and analytics
2. **Keywords**: Add sensitive terms to monitor
3. **Targets**: Configure dark web sites to scan
4. **Scans**: Run manual scans or set up automated scanning
5. **Rules**: Create custom detection patterns
6. **Alerts**: Configure email notifications for breaches

## Security Considerations

- All sensitive data is stored securely in the database
- Passwords are hashed using secure algorithms
- Dark web access is anonymized through Tor
- Custom detection rules for organization-specific threats
- Real-time monitoring and alerting

## License

This project is for demonstration and educational purposes only. Use responsibly and ensure compliance with applicable laws and regulations.
