import logging
import time
import random
import threading
import queue
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from models import ScanResult, DataBreach, ScanTarget, TargetKeyword
from tor_connection import TorConnection
from ml_classifier import DataLeakClassifier
from email_notifier import EmailNotifier
from app import db

# Set up logger
logger = logging.getLogger(__name__)

class DarkWebScanner:
    """
    A dark web scanner that searches for potential data leaks using Tor.
    """
    
    def __init__(self, 
                 tor_connection: TorConnection,
                 classifier: DataLeakClassifier,
                 notifier: EmailNotifier,
                 scan_frequency: int = 3600):
        """
        Initialize the dark web scanner.
        
        Args:
            tor_connection: TorConnection instance for making requests
            classifier: DataLeakClassifier instance for leak detection
            notifier: EmailNotifier instance for sending alerts
            scan_frequency: Time in seconds between automated scans
        """
        self.tor_connection = tor_connection
        self.classifier = classifier
        self.notifier = notifier
        self.scan_frequency = scan_frequency
        self.is_scanning = False
        self.current_scan = None
        self.scan_queue = queue.Queue()
        self.thread = None
        
    def start_scan(self, user_id: int, targets: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Start a new scan with the specified targets.
        
        Args:
            user_id: ID of the user initiating the scan
            targets: Optional list of URLs to scan. If None, uses all active targets from DB.
            
        Returns:
            Dictionary with scan details
        """
        # If already scanning, return info about current scan
        if self.is_scanning:
            return {
                'success': False,
                'error': 'A scan is already in progress',
                'scan_id': self.current_scan.id if self.current_scan else None
            }
        
        new_scan = None
        try:
            # Create new scan record
            new_scan = ScanResult(
                user_id=user_id,
                status='in_progress',
                scan_time=datetime.utcnow()
            )
            db.session.add(new_scan)
            db.session.commit()
            
            self.current_scan = new_scan
            self.is_scanning = True
            
            # Get targets to scan
            scan_targets = []
            if targets:
                scan_targets = targets
            else:
                db_targets = ScanTarget.query.filter_by(active=True).all()
                scan_targets = [target.url for target in db_targets]
            
            # Get organization keywords
            org_keywords = [kw.keyword for kw in TargetKeyword.query.filter_by(active=True).all()]
            
            # Start scan in a new thread
            self.thread = threading.Thread(
                target=self._run_scan,
                args=(new_scan.id, scan_targets, org_keywords)
            )
            self.thread.daemon = True
            self.thread.start()
            
            return {
                'success': True,
                'scan_id': new_scan.id,
                'targets_count': len(scan_targets),
                'start_time': new_scan.scan_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error starting scan: {e}")
            if new_scan and new_scan.id:
                new_scan.status = 'failed'
                db.session.commit()
            
            self.current_scan = None
            self.is_scanning = False
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def _run_scan(self, scan_id: int, targets: List[str], org_keywords: List[str]) -> None:
        """
        Run the scan process in a separate thread.
        
        Args:
            scan_id: ID of the current scan
            targets: List of URLs to scan
            org_keywords: List of organization keywords to look for
        """
        from app import app
        
        # Use Flask application context for database operations in the thread
        with app.app_context():
            scan = None
            try:
                logger.info(f"Starting scan {scan_id} with {len(targets)} targets")
                
                # Get scan from database
                scan = ScanResult.query.get(scan_id)
                if not scan:
                    logger.error(f"Scan {scan_id} not found in database")
                    self.is_scanning = False
                    self.current_scan = None
                    return
                
                # Set classifier keywords
                self.classifier.set_target_keywords(org_keywords)
                
                # Process each target
                successfully_scanned = 0
                breaches_found = 0
                
                for idx, target_url in enumerate(targets):
                    try:
                        logger.info(f"Scanning target {idx+1}/{len(targets)}: {target_url}")
                        
                        # Renew Tor identity occasionally
                        if idx > 0 and idx % 3 == 0:
                            self.tor_connection.renew_tor_identity()
                        
                        # Always count this URL as scanned, even if we can't access it
                        successfully_scanned += 1
                        
                        # Get content from URL
                        html, extracted_text = self.tor_connection.scrape_url(target_url)
                        
                        # Update scan progress immediately after attempting to access URL
                        scan.urls_scanned = successfully_scanned
                        db.session.commit()
                        
                        if not extracted_text:
                            logger.warning(f"No content extracted from {target_url}")
                            # Still count as scanned even if we couldn't get content
                            continue
                        
                        # Analyze the extracted text
                        analysis = self.classifier.analyze_text_for_leaks(extracted_text, org_keywords)
                        
                        # If potential leak detected with confidence above threshold
                        if analysis['is_leak'] and analysis['confidence'] >= 0.7:
                            # Determine breach type from analysis
                            breach_type = 'unknown'
                            if analysis['leak_types']:
                                # Sort by importance and uniqueness
                                leak_types = sorted(set(analysis['leak_types']))
                                breach_type = ','.join(leak_types)
                            
                            # Determine severity from analysis
                            severity = analysis.get('leak_severity', 'medium')
                            
                            # Create a data breach record
                            breach = DataBreach(
                                scan_id=scan_id,
                                source_url=target_url,
                                content_snippet=extracted_text[:2000] if extracted_text else None,  # Store longer snippets
                                breach_type=breach_type,
                                confidence_score=analysis['confidence'],
                                status='new'
                            )
                            db.session.add(breach)
                            db.session.commit()
                            breaches_found += 1
                            
                            # Store rule matches if present
                            from models import RuleMatch
                            if 'custom_rule_details' in analysis and analysis['custom_rule_details']:
                                for rule_match in analysis['custom_rule_details']:
                                    # Create a rule match record
                                    match_record = RuleMatch(
                                        rule_id=rule_match['rule_id'],
                                        breach_id=breach.id,
                                        match_text=rule_match['match_text'][:500],  # Limit text length
                                        match_position=rule_match['match_position'],
                                        match_context=rule_match['match_context'][:500]  # Limit context length
                                    )
                                    db.session.add(match_record)
                                
                                db.session.commit()
                                logger.info(f"Stored {len(analysis['custom_rule_details'])} rule matches for breach {breach.id}")
                            
                            # If we have snippets, store some of them in the content_snippet if it's empty
                            if not breach.content_snippet and 'snippets' in analysis and analysis['snippets']:
                                # Compile a summary from the top 3 snippets
                                snippet_summary = "\n---\n".join([
                                    f"Match type: {s['type']}\nMatch: {s['match']}\nContext: {s['context']}"
                                    for s in analysis['snippets'][:3]
                                ])
                                breach.content_snippet = snippet_summary
                                db.session.commit()
                            
                            # Send notification
                            self.notifier.send_breach_alert(breach, scan)
                        
                        # Random delay to avoid detection
                        time.sleep(random.uniform(2, 5))
                        
                    except Exception as e:
                        logger.error(f"Error scanning {target_url}: {e}")
                
                # Mark scan as completed
                scan.status = 'completed'
                db.session.commit()
                
                logger.info(f"Scan {scan_id} completed. Scanned {successfully_scanned} targets, found {breaches_found} potential breaches.")
                
            except Exception as e:
                logger.error(f"Error in scan thread: {e}")
                
                # Mark scan as failed
                try:
                    if scan:
                        scan.status = 'failed'
                        db.session.commit()
                    else:
                        scan = ScanResult.query.get(scan_id)
                        if scan:
                            scan.status = 'failed'
                            db.session.commit()
                except Exception as db_error:
                    logger.error(f"Error updating scan status: {db_error}")
            
            finally:
                self.is_scanning = False
                self.current_scan = None
    
    def get_scan_status(self, scan_id: int) -> Dict[str, Any]:
        """
        Get the status of a specific scan.
        
        Args:
            scan_id: ID of the scan to check
            
        Returns:
            Dictionary with scan status information
        """
        from app import app
        
        with app.app_context():
            try:
                scan = ScanResult.query.get(scan_id)
                if not scan:
                    return {
                        'success': False,
                        'error': f'Scan with ID {scan_id} not found'
                    }
                
                breaches_count = DataBreach.query.filter_by(scan_id=scan_id).count()
                
                return {
                    'success': True,
                    'scan_id': scan.id,
                    'status': scan.status,
                    'started_at': scan.scan_time.isoformat(),
                    'urls_scanned': scan.urls_scanned,
                    'breaches_detected': breaches_count,
                    'is_current': self.current_scan and self.current_scan.id == scan_id
                }
                
            except Exception as e:
                logger.error(f"Error getting scan status: {e}")
                return {
                    'success': False,
                    'error': str(e)
                }
    
    def get_breach_details(self, breach_id: int) -> Dict[str, Any]:
        """
        Get detailed information about a specific breach.
        
        Args:
            breach_id: ID of the breach to retrieve
            
        Returns:
            Dictionary with breach details
        """
        from app import app
        from models import RuleMatch, DetectionRule
        
        with app.app_context():
            try:
                # Get the breach record
                breach = DataBreach.query.get(breach_id)
                if not breach:
                    return {
                        'success': False,
                        'error': f'Breach with ID {breach_id} not found'
                    }
                
                # Get any rule matches associated with this breach
                rule_matches = RuleMatch.query.filter_by(breach_id=breach_id).all()
                rule_match_details = []
                
                for match in rule_matches:
                    # Get rule details
                    rule = DetectionRule.query.get(match.rule_id)
                    if rule:
                        rule_match_details.append({
                            'match_id': match.id,
                            'rule_id': match.rule_id,
                            'rule_name': rule.name,
                            'rule_severity': rule.severity,
                            'rule_category': rule.category,
                            'pattern_type': rule.pattern_type,
                            'match_text': match.match_text,
                            'match_context': match.match_context,
                            'detected_at': match.detected_at.isoformat() if match.detected_at else None
                        })
                
                # Calculate risk score based on confidence and rule matches
                risk_score = breach.confidence_score * 10  # Base score from 0-10
                
                # Add points for rule matches based on severity
                severity_points = {
                    'high': 3,
                    'medium': 2,
                    'low': 1
                }
                
                for match in rule_match_details:
                    risk_score += severity_points.get(match.get('rule_severity', 'low'), 0)
                
                # Cap the risk score at 10
                risk_score = min(10, risk_score)
                
                # Parse breach types into a list
                breach_types = []
                if breach.breach_type:
                    breach_types = [t.strip() for t in breach.breach_type.split(',')]
                
                # Get scan info
                scan = breach.scan_result
                
                # Construct response with enhanced details
                response = {
                    'success': True,
                    'breach_id': breach.id,
                    'scan_id': breach.scan_id,
                    'scan_user_id': scan.user_id if scan else None,
                    'discovery_time': breach.discovery_time.isoformat(),
                    'source_url': breach.source_url,
                    'content_snippet': breach.content_snippet,
                    'breach_type': breach.breach_type,
                    'breach_types': breach_types,
                    'confidence_score': breach.confidence_score,
                    'risk_score': risk_score,
                    'status': breach.status,
                    'rule_matches': rule_match_details,
                    'rule_match_count': len(rule_match_details),
                    'has_rule_matches': len(rule_match_details) > 0
                }
                
                return response
                
            except Exception as e:
                logger.error(f"Error getting breach details: {e}")
                return {
                    'success': False,
                    'error': str(e)
                }
    
    def mark_breach_status(self, breach_id: int, status: str) -> Dict[str, Any]:
        """
        Update the status of a breach.
        
        Args:
            breach_id: ID of the breach to update
            status: New status ('reviewed', 'false_positive', 'confirmed')
            
        Returns:
            Dictionary with update result
        """
        valid_statuses = ['reviewed', 'false_positive', 'confirmed']
        if status not in valid_statuses:
            return {
                'success': False,
                'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'
            }
        
        from app import app
        
        with app.app_context():
            try:
                breach = DataBreach.query.get(breach_id)
                if not breach:
                    return {
                        'success': False,
                        'error': f'Breach with ID {breach_id} not found'
                    }
                
                breach.status = status
                db.session.commit()
                
                return {
                    'success': True,
                    'breach_id': breach.id,
                    'new_status': status
                }
                
            except Exception as e:
                logger.error(f"Error updating breach status: {e}")
                return {
                    'success': False,
                    'error': str(e)
                }
    
    def initialize_default_data(self) -> None:
        """
        Initialize default scan targets and keywords if none exist.
        This is used when setting up the system for the first time.
        """
        try:
            # Add default targets if none exist
            targets_count = ScanTarget.query.count()
            if targets_count == 0:
                default_targets = [
                    ScanTarget(url='http://hss3uro2hsxfogfq.onion', description='Hidden Wiki Index'),
                    ScanTarget(url='http://zqktlwi4fecvo6ri.onion', description='Hidden Wiki'),
                    ScanTarget(url='http://jh32yv5zgayyyts3.onion', description='Hidden Service #1'),
                    ScanTarget(url='http://email6dtliufmgyw.onion', description='Email Service'),
                    ScanTarget(url='http://4yjes6zfucnh7vcj.onion', description='Search Engine'),
                ]
                db.session.bulk_save_objects(default_targets)
                
            # Add default keywords if none exist
            keywords_count = TargetKeyword.query.count()
            if keywords_count == 0:
                default_keywords = [
                    TargetKeyword(keyword='company_name', category='company_name'),
                    TargetKeyword(keyword='company.com', category='domain'),
                    TargetKeyword(keyword='secret', category='sensitive'),
                    TargetKeyword(keyword='confidential', category='sensitive'),
                    TargetKeyword(keyword='proprietary', category='sensitive'),
                    TargetKeyword(keyword='password', category='credentials'),
                    TargetKeyword(keyword='database', category='technical'),
                    TargetKeyword(keyword='server', category='technical'),
                ]
                db.session.bulk_save_objects(default_keywords)
                
            db.session.commit()
            logger.info("Default scan targets and keywords initialized")
            
        except Exception as e:
            logger.error(f"Error initializing default data: {e}")
