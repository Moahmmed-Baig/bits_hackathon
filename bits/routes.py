import logging
import os
import re
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from app import app, db
from models import (
    User, ScanResult, DataBreach, TargetKeyword, 
    ScanTarget, NotificationSetting, DetectionRule, RuleMatch
)
from tor_connection import TorConnection
from ml_classifier import DataLeakClassifier
from scanner import DarkWebScanner
from email_notifier import EmailNotifier

# Setup logging
logger = logging.getLogger(__name__)

# Initialize components
try:
    tor_connection = TorConnection(
        socks_port=9050,  # Default Tor SOCKS port
        control_port=9051  # Default Tor control port
    )
    logger.info("TorConnection initialized")
except Exception as e:
    logger.warning(f"Failed to initialize TorConnection: {e}")
    tor_connection = None

try:
    classifier = DataLeakClassifier()
    logger.info("DataLeakClassifier initialized")
except Exception as e:
    logger.warning(f"Failed to initialize DataLeakClassifier: {e}")
    classifier = None

try:
    email_notifier = EmailNotifier()
    logger.info("EmailNotifier initialized")
except Exception as e:
    logger.warning(f"Failed to initialize EmailNotifier: {e}")
    email_notifier = None

try:
    scanner = DarkWebScanner(
        tor_connection=tor_connection,
        classifier=classifier,
        notifier=email_notifier
    )
    logger.info("DarkWebScanner initialized")
except Exception as e:
    logger.warning(f"Failed to initialize DarkWebScanner: {e}")
    scanner = None

# Seed the database with initial data
def initialize_app():
    try:
        # Initialize scanner default data if scanner is available
        if scanner:
            scanner.initialize_default_data()
        
        # Create admin user if no users exist
        if User.query.count() == 0:
            admin_user = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin_user.set_password('admin')
            db.session.add(admin_user)
            db.session.commit()
            
            # Create notification settings for admin
            settings = NotificationSetting(
                user_id=admin_user.id,
                email_alerts=True,
                min_confidence_threshold=0.7
            )
            db.session.add(settings)
            db.session.commit()
            
            # Create default target keywords if none exist
            if TargetKeyword.query.count() == 0:
                default_keywords = [
                    TargetKeyword(keyword="password", category="credentials", active=True),
                    TargetKeyword(keyword="secret", category="credentials", active=True),
                    TargetKeyword(keyword="api key", category="credentials", active=True),
                    TargetKeyword(keyword="confidential", category="document", active=True),
                    TargetKeyword(keyword="internal only", category="document", active=True)
                ]
                db.session.add_all(default_keywords)
                db.session.commit()
            
            # Create default scan targets if none exist
            if ScanTarget.query.count() == 0:
                default_targets = [
                    ScanTarget(url="https://pastehub.net", description="Pastebin alternative", active=True),
                    ScanTarget(url="https://github.com/topics/data-breach", description="GitHub data breach repositories", active=True),
                    ScanTarget(url="https://reddit.com/r/security", description="Reddit security community", active=True)
                ]
                db.session.add_all(default_targets)
                db.session.commit()
            
            logger.info("Created default admin user, keywords, and targets")
    except Exception as e:
        logger.error(f"Error initializing app: {e}")

# Call initialize_app during application startup
with app.app_context():
    initialize_app()
    
# Add template context processor to provide common variables
@app.context_processor
def inject_now():
    from datetime import datetime
    return {'now': datetime.utcnow()}

# Home route
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# User authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        # Make the first user an admin
        if User.query.count() == 0:
            user.is_admin = True
        
        db.session.add(user)
        db.session.commit()
        
        # Create notification settings
        settings = NotificationSetting(
            user_id=user.id,
            email_alerts=True,
            min_confidence_threshold=0.7
        )
        db.session.add(settings)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent scans
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id) \
                          .order_by(ScanResult.scan_time.desc()) \
                          .limit(5).all()
    
    # Get recent breaches
    recent_breaches = DataBreach.query \
        .join(ScanResult) \
        .filter(ScanResult.user_id == current_user.id) \
        .order_by(DataBreach.discovery_time.desc()) \
        .limit(5).all()
    
    # Get counts for dashboard stats
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    total_breaches = DataBreach.query \
        .join(ScanResult) \
        .filter(ScanResult.user_id == current_user.id) \
        .count()
    
    # Get active scan targets count
    targets_count = ScanTarget.query.filter_by(active=True).count()
    
    # Get active keywords count
    keywords_count = TargetKeyword.query.filter_by(active=True).count()
    
    # Get data for breach types chart
    breach_types = db.session.query(
        DataBreach.breach_type, 
        db.func.count(DataBreach.id)
    ).join(ScanResult) \
    .filter(ScanResult.user_id == current_user.id) \
    .group_by(DataBreach.breach_type).all()
    
    breach_type_labels = [t[0].capitalize() for t in breach_types] if breach_types else ["No Data"]
    breach_type_values = [t[1] for t in breach_types] if breach_types else [1]
    
    # Get data for scan activity chart (last 7 days)
    today = datetime.utcnow().date()
    seven_days_ago = today - timedelta(days=6)
    
    scan_dates = []
    scan_counts = []
    breach_counts = []
    
    for i in range(7):
        date = seven_days_ago + timedelta(days=i)
        next_date = date + timedelta(days=1)
        
        # Format the label as "Mon 15" format
        formatted_date = date.strftime("%b %d")
        scan_dates.append(formatted_date)
        
        # Count scans on this day
        day_scans = ScanResult.query.filter(
            ScanResult.user_id == current_user.id,
            ScanResult.scan_time >= date,
            ScanResult.scan_time < next_date
        ).count()
        scan_counts.append(day_scans)
        
        # Count breaches on this day
        day_breaches = DataBreach.query.join(ScanResult).filter(
            ScanResult.user_id == current_user.id,
            DataBreach.discovery_time >= date,
            DataBreach.discovery_time < next_date
        ).count()
        breach_counts.append(day_breaches)
    
    # Calculate system status metrics
    monitoring_status = {}
    
    # Determine if tor is reachable
    tor_status = "Active" if scanner and hasattr(scanner, 'tor_connection') and scanner.tor_connection else "Inactive"
    monitoring_status["tor_status"] = tor_status
    
    # Last successful scan time
    last_successful_scan = ScanResult.query.filter_by(
        user_id=current_user.id, 
        status="completed"
    ).order_by(ScanResult.scan_time.desc()).first()
    
    monitoring_status["last_scan_time"] = last_successful_scan.scan_time if last_successful_scan else None
    
    # Get keywords with high alert counts
    alert_keywords = db.session.query(
        TargetKeyword.keyword,
        db.func.count(DataBreach.id).label('breach_count')
    ).join(
        DataBreach,
        db.and_(
            DataBreach.content_snippet.like(db.func.concat('%', TargetKeyword.keyword, '%')),
            ~DataBreach.status.in_(['false_positive'])
        )
    ).join(
        ScanResult, DataBreach.scan_id == ScanResult.id
    ).filter(
        ScanResult.user_id == current_user.id,
        TargetKeyword.active == True
    ).group_by(TargetKeyword.keyword) \
    .order_by(db.desc('breach_count')) \
    .limit(5).all()
    
    # Generate security news (simplified for demo)
    security_news = [
        {
            "title": "New Phishing Campaign Targeting Financial Institutions",
            "summary": "Security researchers detected a new wave of sophisticated phishing attacks.",
            "date": (datetime.utcnow() - timedelta(days=2)).strftime("%b %d, %Y"),
            "source": "CyberSecurity News"
        },
        {
            "title": "Critical Vulnerability in Popular Web Framework",
            "summary": "A severe security flaw was discovered that could lead to remote code execution.",
            "date": (datetime.utcnow() - timedelta(days=4)).strftime("%b %d, %Y"),
            "source": "Security Weekly"
        },
        {
            "title": "Data Breach Affects Millions of Healthcare Records",
            "summary": "A major healthcare provider announced a significant data breach incident.",
            "date": (datetime.utcnow() - timedelta(days=7)).strftime("%b %d, %Y"),
            "source": "Breach Monitor"
        }
    ]
    
    # Check if a scan is currently running
    is_scanning = scanner and getattr(scanner, 'is_scanning', False)
    current_scan_id = scanner and getattr(scanner, 'current_scan', None) and getattr(scanner.current_scan, 'id', None) if is_scanning else None
    
    return render_template(
        'dashboard.html',
        recent_scans=recent_scans,
        recent_breaches=recent_breaches,
        total_scans=total_scans,
        total_breaches=total_breaches,
        targets_count=targets_count,
        keywords_count=keywords_count,
        is_scanning=is_scanning,
        current_scan_id=current_scan_id,
        breach_type_labels=breach_type_labels,
        breach_type_values=breach_type_values,
        scan_dates=scan_dates,
        scan_counts=scan_counts,
        breach_counts=breach_counts,
        monitoring_status=monitoring_status,
        alert_keywords=alert_keywords,
        security_news=security_news
    )

# Scan history route
@app.route('/scans')
@login_required
def scan_history():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    scans = ScanResult.query.filter_by(user_id=current_user.id) \
                     .order_by(ScanResult.scan_time.desc()) \
                     .paginate(page=page, per_page=per_page)
    
    return render_template('scan_history.html', scans=scans)

# Scan detail route
@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    
    # Check if user has permission to view this scan
    if scan.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this scan', 'danger')
        return redirect(url_for('scan_history'))
    
    # Get breaches for this scan
    breaches = DataBreach.query.filter_by(scan_id=scan_id) \
                        .order_by(DataBreach.confidence_score.desc()) \
                        .all()
    
    return render_template('scan_detail.html', scan=scan, breaches=breaches)

# Breach detail route
@app.route('/breach/<int:breach_id>')
@login_required
def breach_detail(breach_id):
    breach = DataBreach.query.get_or_404(breach_id)
    scan = ScanResult.query.get(breach.scan_id)
    
    # Check if user has permission to view this breach
    if scan.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this breach', 'danger')
        return redirect(url_for('scan_history'))
    
    return render_template('breach_detail.html', breach=breach, scan=scan)

# Settings route
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    # Get user's notification settings
    settings = NotificationSetting.query.filter_by(user_id=current_user.id).first()
    
    if not settings:
        # Create default settings if not exist
        settings = NotificationSetting(
            user_id=current_user.id,
            email_alerts=True,
            min_confidence_threshold=0.7
        )
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        # Update email settings
        settings.email_alerts = 'email_alerts' in request.form
        
        # Update confidence threshold
        try:
            threshold = float(request.form.get('min_confidence_threshold', 0.7))
            settings.min_confidence_threshold = max(0.0, min(1.0, threshold))
        except ValueError:
            flash('Invalid confidence threshold value', 'danger')
            return redirect(url_for('settings'))
        
        # Update password if provided
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if current_password and new_password and confirm_password:
            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('settings'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('settings'))
            
            current_user.set_password(new_password)
        
        # Save changes
        db.session.commit()
        
        flash('Settings updated successfully', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings.html', settings=settings)

# API for starting a scan
@app.route('/api/scan/start', methods=['POST'])
@login_required
def start_scan():
    # Check if custom targets were provided
    targets = request.form.get('targets')
    target_list = None
    
    if targets:
        target_list = [url.strip() for url in targets.split('\n') if url.strip()]
    
    # Start the scan
    result = scanner.start_scan(user_id=current_user.id, targets=target_list)
    
    if result['success']:
        flash('Scan started successfully', 'success')
    else:
        flash(f"Failed to start scan: {result.get('error', 'Unknown error')}", 'danger')
    
    return redirect(url_for('dashboard'))

# API for checking scan status
@app.route('/api/scan/status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    
    # Check if user has permission to view this scan
    if scan.user_id != current_user.id and not current_user.is_admin:
        return jsonify({
            'success': False,
            'error': 'Permission denied'
        }), 403
    
    result = scanner.get_scan_status(scan_id)
    return jsonify(result)

# API for marking breach status
@app.route('/api/breach/<int:breach_id>/status', methods=['POST'])
@login_required
def update_breach_status(breach_id):
    breach = DataBreach.query.get_or_404(breach_id)
    scan = ScanResult.query.get(breach.scan_id)
    
    # Check if user has permission
    if scan.user_id != current_user.id and not current_user.is_admin:
        return jsonify({
            'success': False,
            'error': 'Permission denied'
        }), 403
    
    status = request.form.get('status')
    if not status:
        return jsonify({
            'success': False,
            'error': 'Status not provided'
        }), 400
    
    result = scanner.mark_breach_status(breach_id, status)
    return jsonify(result)

# Keywords management
@app.route('/keywords', methods=['GET', 'POST'])
@login_required
def manage_keywords():
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        keyword = request.form.get('keyword')
        category = request.form.get('category')
        
        if keyword:
            new_keyword = TargetKeyword(
                keyword=keyword,
                category=category,
                active=True
            )
            db.session.add(new_keyword)
            db.session.commit()
            flash('Keyword added successfully', 'success')
        
        return redirect(url_for('manage_keywords'))
    
    keywords = TargetKeyword.query.all()
    return render_template('keywords.html', keywords=keywords)

# Delete keyword
@app.route('/keyword/<int:keyword_id>/delete', methods=['POST'])
@login_required
def delete_keyword(keyword_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard'))
    
    keyword = TargetKeyword.query.get_or_404(keyword_id)
    db.session.delete(keyword)
    db.session.commit()
    
    flash('Keyword deleted successfully', 'success')
    return redirect(url_for('manage_keywords'))

# Toggle keyword active status
@app.route('/keyword/<int:keyword_id>/toggle', methods=['POST'])
@login_required
def toggle_keyword(keyword_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard'))
    
    keyword = TargetKeyword.query.get_or_404(keyword_id)
    keyword.active = not keyword.active
    db.session.commit()
    
    status = 'activated' if keyword.active else 'deactivated'
    flash(f'Keyword {status} successfully', 'success')
    return redirect(url_for('manage_keywords'))

# Scan targets management
@app.route('/targets', methods=['GET', 'POST'])
@login_required
def manage_targets():
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        url = request.form.get('url')
        description = request.form.get('description')
        
        if url:
            new_target = ScanTarget(
                url=url,
                description=description,
                active=True
            )
            db.session.add(new_target)
            db.session.commit()
            flash('Target added successfully', 'success')
        
        return redirect(url_for('manage_targets'))
    
    targets = ScanTarget.query.all()
    return render_template('targets.html', targets=targets)

# Delete target
@app.route('/target/<int:target_id>/delete', methods=['POST'])
@login_required
def delete_target(target_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard'))
    
    target = ScanTarget.query.get_or_404(target_id)
    db.session.delete(target)
    db.session.commit()
    
    flash('Target deleted successfully', 'success')
    return redirect(url_for('manage_targets'))

# Toggle target active status
@app.route('/target/<int:target_id>/toggle', methods=['POST'])
@login_required
def toggle_target(target_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard'))
    
    target = ScanTarget.query.get_or_404(target_id)
    target.active = not target.active
    db.session.commit()
    
    status = 'activated' if target.active else 'deactivated'
    flash(f'Target {status} successfully', 'success')
    return redirect(url_for('manage_targets'))

# Custom Detection Rules Management
@app.route('/rules', methods=['GET'])
@login_required
def manage_rules():
    # Get all rules for the current user or organization
    rules = DetectionRule.query.filter_by(created_by=current_user.id).order_by(DetectionRule.created_at.desc()).all()
    
    return render_template('detection_rules.html', rules=rules)

# Create a new detection rule
@app.route('/rule/create', methods=['POST'])
@login_required
def create_rule():
    name = request.form.get('name')
    description = request.form.get('description', '')
    pattern_type = request.form.get('pattern_type')
    pattern_value = request.form.get('pattern_value')
    severity = request.form.get('severity', 'medium')
    category = request.form.get('category', 'custom')
    is_enabled = 'is_enabled' in request.form
    
    # Basic validation
    if not name or not pattern_type or not pattern_value:
        flash('Name, pattern type, and pattern value are required', 'danger')
        return redirect(url_for('manage_rules'))
    
    # Validate pattern based on type
    if pattern_type == 'regex':
        try:
            import re
            re.compile(pattern_value)
        except re.error:
            flash('Invalid regular expression pattern', 'danger')
            return redirect(url_for('manage_rules'))
    
    # Create the rule
    new_rule = DetectionRule(
        name=name,
        description=description,
        pattern_type=pattern_type,
        pattern_value=pattern_value,
        severity=severity,
        category=category,
        is_enabled=is_enabled,
        created_by=current_user.id
    )
    
    db.session.add(new_rule)
    db.session.commit()
    
    flash('Detection rule created successfully', 'success')
    return redirect(url_for('manage_rules'))

# Update an existing detection rule
@app.route('/rule/update', methods=['POST'])
@login_required
def update_rule():
    rule_id = request.form.get('rule_id')
    rule = DetectionRule.query.get_or_404(rule_id)
    
    # Check if user has permission to edit this rule
    if rule.created_by != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this rule', 'danger')
        return redirect(url_for('manage_rules'))
    
    # Update rule fields
    rule.name = request.form.get('name')
    rule.description = request.form.get('description', '')
    rule.pattern_type = request.form.get('pattern_type')
    rule.pattern_value = request.form.get('pattern_value')
    rule.severity = request.form.get('severity', 'medium')
    rule.category = request.form.get('category', 'custom')
    rule.is_enabled = 'is_enabled' in request.form
    rule.updated_at = datetime.utcnow()
    
    # Validate regex pattern if applicable
    if rule.pattern_type == 'regex':
        try:
            import re
            re.compile(rule.pattern_value)
        except re.error:
            flash('Invalid regular expression pattern', 'danger')
            return redirect(url_for('manage_rules'))
    
    db.session.commit()
    
    flash('Detection rule updated successfully', 'success')
    return redirect(url_for('manage_rules'))

# Delete a detection rule
@app.route('/rule/delete', methods=['POST'])
@login_required
def delete_rule():
    rule_id = request.form.get('rule_id')
    rule = DetectionRule.query.get_or_404(rule_id)
    
    # Check if user has permission to delete this rule
    if rule.created_by != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this rule', 'danger')
        return redirect(url_for('manage_rules'))
    
    # Delete all matches first
    RuleMatch.query.filter_by(rule_id=rule.id).delete()
    
    # Delete the rule
    db.session.delete(rule)
    db.session.commit()
    
    flash('Detection rule deleted successfully', 'success')
    return redirect(url_for('manage_rules'))

# Toggle rule active status
@app.route('/rule/<int:rule_id>/toggle', methods=['GET'])
@login_required
def toggle_rule(rule_id):
    rule = DetectionRule.query.get_or_404(rule_id)
    
    # Check if user has permission to toggle this rule
    if rule.created_by != current_user.id and not current_user.is_admin:
        flash('You do not have permission to modify this rule', 'danger')
        return redirect(url_for('manage_rules'))
    
    rule.is_enabled = not rule.is_enabled
    db.session.commit()
    
    status = 'enabled' if rule.is_enabled else 'disabled'
    flash(f'Rule "{rule.name}" has been {status}', 'success')
    return redirect(url_for('manage_rules'))

# Test email notification
@app.route('/test-email', methods=['POST'])
@login_required
def test_email():
    result = email_notifier.send_test_email(current_user.email)
    
    if result['success']:
        flash('Test email sent successfully', 'success')
    else:
        flash(f"Failed to send test email: {result.get('error', 'Unknown error')}", 'danger')
    
    return redirect(url_for('settings'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message='Page not found'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, error_message='Server error'), 500
