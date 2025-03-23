import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional, Any
from flask import render_template_string
from models import DataBreach, ScanResult, User, NotificationSetting
from app import app

# Set up logger
logger = logging.getLogger(__name__)

class EmailNotifier:
    """Handles sending email notifications for data breach alerts"""
    
    def __init__(self, 
                 mail_server: str = None,
                 mail_port: int = None,
                 mail_username: str = None,
                 mail_password: str = None,
                 mail_use_tls: bool = True,
                 default_sender: str = None):
        """
        Initialize the email notifier with mail server settings.
        If any settings are None, they will be loaded from app config.
        
        Args:
            mail_server: SMTP server address
            mail_port: SMTP server port
            mail_username: SMTP username
            mail_password: SMTP password
            mail_use_tls: Whether to use TLS
            default_sender: Default sender email address
        """
        self.mail_server = mail_server or app.config.get('MAIL_SERVER')
        self.mail_port = mail_port or app.config.get('MAIL_PORT')
        self.mail_username = mail_username or app.config.get('MAIL_USERNAME')
        self.mail_password = mail_password or app.config.get('MAIL_PASSWORD')
        self.mail_use_tls = mail_use_tls or app.config.get('MAIL_USE_TLS', True)
        self.default_sender = default_sender or app.config.get('MAIL_DEFAULT_SENDER')
        
    def send_email(self, 
                   to_addresses: List[str], 
                   subject: str, 
                   html_content: str,
                   text_content: Optional[str] = None) -> Dict[str, Any]:
        """
        Send an email to one or more recipients.
        
        Args:
            to_addresses: List of recipient email addresses
            subject: Email subject
            html_content: HTML content of the email
            text_content: Plain text content of the email (optional)
            
        Returns:
            Dictionary with success status and any error message
        """
        if not self.mail_server or not self.mail_username:
            logger.warning("Email settings not configured, cannot send emails")
            return {
                'success': False,
                'error': 'Email settings not configured'
            }
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.default_sender
            msg['To'] = ', '.join(to_addresses)
            
            # Add text part if provided
            if text_content:
                msg.attach(MIMEText(text_content, 'plain'))
            
            # Add HTML part
            msg.attach(MIMEText(html_content, 'html'))
            
            # Connect to mail server and send
            with smtplib.SMTP(self.mail_server, self.mail_port) as server:
                if self.mail_use_tls:
                    server.starttls()
                
                if self.mail_username and self.mail_password:
                    server.login(self.mail_username, self.mail_password)
                
                server.sendmail(
                    self.default_sender,
                    to_addresses,
                    msg.as_string()
                )
            
            logger.info(f"Email sent to {', '.join(to_addresses)}")
            return {
                'success': True
            }
            
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def send_breach_alert(self, breach: DataBreach, scan: ScanResult) -> Dict[str, Any]:
        """
        Send an alert about a detected data breach to relevant users.
        
        Args:
            breach: The DataBreach instance
            scan: The ScanResult instance
            
        Returns:
            Dictionary with success status and any error message
        """
        try:
            # Get user who initiated the scan
            user = User.query.get(scan.user_id)
            if not user:
                logger.error(f"User not found for scan {scan.id}")
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            # Get notification settings for user
            settings = NotificationSetting.query.filter_by(user_id=user.id).first()
            
            # Check if user wants email alerts and breach meets confidence threshold
            if not settings or not settings.email_alerts:
                logger.info(f"Email alerts disabled for user {user.id}")
                return {
                    'success': True,
                    'message': 'Email alerts disabled'
                }
            
            if breach.confidence_score < settings.min_confidence_threshold:
                logger.info(f"Breach confidence {breach.confidence_score} below threshold {settings.min_confidence_threshold}")
                return {
                    'success': True,
                    'message': 'Breach confidence below threshold'
                }
            
            # Set up email content
            breach_type_display = breach.breach_type.replace('_', ' ').title()
            
            subject = f"ALERT: Potential Data Breach Detected - {breach_type_display}"
            
            # Use a template string for the HTML email
            html_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                    }
                    .header {
                        background-color: #ff5252;
                        color: white;
                        padding: 15px;
                        text-align: center;
                        font-weight: bold;
                        font-size: 24px;
                    }
                    .content {
                        padding: 20px;
                        background-color: #f9f9f9;
                    }
                    .footer {
                        text-align: center;
                        font-size: 12px;
                        color: #777;
                        padding: 10px;
                    }
                    .data-table {
                        width: 100%;
                        border-collapse: collapse;
                        margin: 15px 0;
                    }
                    .data-table th, .data-table td {
                        border: 1px solid #ddd;
                        padding: 8px;
                        text-align: left;
                    }
                    .data-table th {
                        background-color: #f2f2f2;
                    }
                    .confidence {
                        font-weight: bold;
                        color: {{ confidence_color }};
                    }
                    .content-snippet {
                        background-color: #efefef;
                        padding: 10px;
                        border-left: 4px solid #ccc;
                        font-family: monospace;
                        margin: 15px 0;
                        white-space: pre-wrap;
                        word-wrap: break-word;
                    }
                    .button {
                        display: inline-block;
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 20px;
                        text-align: center;
                        text-decoration: none;
                        font-weight: bold;
                        border-radius: 4px;
                        margin: 15px 0;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    Potential Data Breach Detected
                </div>
                <div class="content">
                    <p>A potential data breach has been detected during scan #{{ scan_id }}.</p>
                    
                    <table class="data-table">
                        <tr>
                            <th>Detection Time</th>
                            <td>{{ discovery_time }}</td>
                        </tr>
                        <tr>
                            <th>Breach Type</th>
                            <td>{{ breach_type }}</td>
                        </tr>
                        <tr>
                            <th>Confidence Score</th>
                            <td class="confidence">{{ confidence_score }}%</td>
                        </tr>
                        <tr>
                            <th>Source URL</th>
                            <td>{{ source_url }}</td>
                        </tr>
                    </table>
                    
                    <h3>Content Snippet:</h3>
                    <div class="content-snippet">{{ content_snippet }}</div>
                    
                    <p>
                        <a href="{{ dashboard_url }}" class="button">View in Dashboard</a>
                    </p>
                    
                    <p>This is an automated alert from your Dark Web Monitoring System. Please review the potential breach in the dashboard.</p>
                </div>
                <div class="footer">
                    &copy; Dark Web Monitor. Do not reply to this email.
                </div>
            </body>
            </html>
            """
            
            # Format confidence as percentage and set color
            confidence_pct = int(breach.confidence_score * 100)
            confidence_color = "#ff0000"  # Red for high confidence
            if confidence_pct < 85:
                confidence_color = "#ff9900"  # Orange for medium confidence
            if confidence_pct < 70:
                confidence_color = "#ffcc00"  # Yellow for lower confidence
            
            # Prepare content for the email
            html_content = render_template_string(
                html_template,
                scan_id=scan.id,
                discovery_time=breach.discovery_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                breach_type=breach_type_display,
                confidence_score=confidence_pct,
                confidence_color=confidence_color,
                source_url=breach.source_url or "Unknown",
                content_snippet=breach.content_snippet or "No content available",
                dashboard_url=f"http://localhost:5000/breach/{breach.id}"
            )
            
            # Plain text version
            text_content = f"""
            ALERT: Potential Data Breach Detected
            
            A potential data breach has been detected during scan #{scan.id}.
            
            Detection Time: {breach.discovery_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
            Breach Type: {breach_type_display}
            Confidence Score: {confidence_pct}%
            Source URL: {breach.source_url or 'Unknown'}
            
            Content Snippet:
            {breach.content_snippet or 'No content available'}
            
            Please review the potential breach in the dashboard:
            http://localhost:5000/breach/{breach.id}
            
            This is an automated alert from your Dark Web Monitoring System.
            """
            
            # Send the email
            return self.send_email(
                to_addresses=[user.email],
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )
            
        except Exception as e:
            logger.error(f"Error sending breach alert: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def send_test_email(self, to_address: str) -> Dict[str, Any]:
        """
        Send a test email to verify the email configuration.
        
        Args:
            to_address: Recipient email address
            
        Returns:
            Dictionary with success status and any error message
        """
        subject = "Test Email from Dark Web Monitor"
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }
                .header {
                    background-color: #4a4a4a;
                    color: white;
                    padding: 10px;
                    text-align: center;
                    border-radius: 4px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Test Email</h2>
                </div>
                <p>This is a test email from your Dark Web Monitoring System.</p>
                <p>If you received this email, your notification system is working correctly.</p>
                <p>No action is required.</p>
            </div>
        </body>
        </html>
        """
        
        text_content = """
        Test Email from Dark Web Monitor
        
        This is a test email from your Dark Web Monitoring System.
        If you received this email, your notification system is working correctly.
        No action is required.
        """
        
        return self.send_email(
            to_addresses=[to_address],
            subject=subject,
            html_content=html_content,
            text_content=text_content
        )
