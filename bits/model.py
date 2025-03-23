from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('ScanResult', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)  # 'completed', 'in_progress', 'failed'
    urls_scanned = db.Column(db.Integer, default=0)
    breaches_detected = db.relationship('DataBreach', backref='scan_result', lazy='dynamic')
    
    def __repr__(self):
        return f'<ScanResult {self.id} by {self.user.username}>'

class DataBreach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=False)
    discovery_time = db.Column(db.DateTime, default=datetime.utcnow)
    source_url = db.Column(db.String(500), nullable=True)
    content_snippet = db.Column(db.Text, nullable=True)
    breach_type = db.Column(db.String(50), nullable=False)  # 'credentials', 'financial', 'personal', etc.
    confidence_score = db.Column(db.Float, nullable=False)  # ML confidence score (0-1)
    status = db.Column(db.String(20), default='new')  # 'new', 'reviewed', 'false_positive', 'confirmed'
    
    def __repr__(self):
        return f'<DataBreach {self.id} type={self.breach_type} score={self.confidence_score}>'

class TargetKeyword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    keyword = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=True)  # 'company_name', 'domain', 'product', etc.
    active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<TargetKeyword {self.keyword}>'

class ScanTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    last_scan = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<ScanTarget {self.url}>'

class NotificationSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email_alerts = db.Column(db.Boolean, default=True)
    min_confidence_threshold = db.Column(db.Float, default=0.7)
    
    def __repr__(self):
        return f'<NotificationSetting for user_id={self.user_id}>'

class DetectionRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    pattern_type = db.Column(db.String(50), nullable=False)  # 'regex', 'keyword', 'ml_pattern'
    pattern_value = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='medium')  # 'low', 'medium', 'high', 'critical'
    category = db.Column(db.String(50), nullable=True)  # 'credentials', 'financial', 'personal', etc.
    is_enabled = db.Column(db.Boolean, default=True)
    organization_id = db.Column(db.Integer, nullable=True)  # For multi-tenant support
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to match counts
    matches = db.relationship('RuleMatch', backref='detection_rule', lazy='dynamic')
    user = db.relationship('User', backref='detection_rules')
    
    def __repr__(self):
        return f'<DetectionRule {self.name}>'
        
class RuleMatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('detection_rule.id'), nullable=False)
    breach_id = db.Column(db.Integer, db.ForeignKey('data_breach.id'), nullable=False)
    match_text = db.Column(db.Text, nullable=True)
    match_position = db.Column(db.Integer, nullable=True)
    match_context = db.Column(db.Text, nullable=True)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    breach = db.relationship('DataBreach', backref='rule_matches')
    
    def __repr__(self):
        return f'<RuleMatch {self.id}>'
