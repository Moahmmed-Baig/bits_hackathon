import re
import logging
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
import joblib
import os
from typing import Dict, List, Optional, Tuple, Any, Union

# Set up logger
logger = logging.getLogger(__name__)

class DataLeakClassifier:
    """
    Machine learning classifier to detect potential data leaks in text.
    Uses TF-IDF features and a Random Forest classifier.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the classifier, loading a pre-trained model if provided.
        
        Args:
            model_path: Path to a pre-trained model file (.joblib)
        """
        self.model_path = model_path
        self.target_keywords = []
        self.sensitive_patterns = self._compile_patterns()
        self.pipeline = None
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self._initialize_pipeline()
            
    def _initialize_pipeline(self) -> None:
        """Initialize the classification pipeline with default parameters."""
        self.pipeline = Pipeline([
            ('vectorizer', TfidfVectorizer(
                max_features=5000,
                min_df=2,
                max_df=0.85,
                ngram_range=(1, 2),
                stop_words='english'
            )),
            ('classifier', RandomForestClassifier(
                n_estimators=100,
                max_depth=None,
                min_samples_split=2,
                random_state=42
            ))
        ])
        
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """
        Compile regex patterns for detecting various types of sensitive data.
        
        Returns:
            Dict of compiled regex patterns
        """
        return {
            # Personal Identifiable Information
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'),
            'ssn': re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
            'phone_number': re.compile(r'\b(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'),
            'date_of_birth': re.compile(r'\b(?:(?:0?[1-9]|1[0-2])[\/.-](?:0?[1-9]|[12][0-9]|3[01])[\/.-](?:19|20)\d{2}|(?:19|20)\d{2}[\/.-](?:0?[1-9]|1[0-2])[\/.-](?:0?[1-9]|[12][0-9]|3[01]))\b'),
            
            # Credentials and Authentication
            'password': re.compile(r'\b(?:password|passwd|pwd)[\s:=]+[\w\d\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\\;\"\'\<\>\,\.\?\/]{6,}\b', re.IGNORECASE),
            'auth_token': re.compile(r'\b(?:auth\s?token|access\s?token|api\s?token|bearer\s?token|oauth\s?token)[\s:=]+[\w\d\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\\;\"\'\<\>\,\.\?\/]{8,}\b', re.IGNORECASE),
            'api_key': re.compile(r'\b(?:api[_\-\s]?key|api[_\-\s]?secret|client[_\-\s]?secret|app[_\-\s]?key|app[_\-\s]?secret)[\s:=]+[\w\d\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\\;\"\'\<\>\,\.\?\/]{16,}\b', re.IGNORECASE),
            
            # Technical Information
            'ip_address': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            'mac_address': re.compile(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b'),
            'aws_access_key': re.compile(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b'),
            'aws_secret_key': re.compile(r'\b[0-9a-zA-Z/+]{40}\b'),
            'private_key': re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'),
            'jwt_token': re.compile(r'eyJ[a-zA-Z0-9_=-]+\.eyJ[a-zA-Z0-9_=-]+\.[a-zA-Z0-9_=-]+'),
            
            # Database Information
            'database_conn_string': re.compile(r'\b(?:jdbc|mysql|postgresql|mongodb|redis):\/\/[^\s]+'),
            'sql_dump': re.compile(r'\bINSERT INTO\s+`?\w+`?\s+\([^)]+\)\s+VALUES\s+\([^)]+\)'),
            
            # Code and Secrets
            'github_token': re.compile(r'\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b'),
            'generic_secret': re.compile(r'\b(?:secret|confidential|private|sensitive)[\s:=]+[\w\d\!\@\#\$\%\^\&\*\(\)\-\+\=\{\}\[\]\|\:\\;\"\'\<\>\,\.\?\/]{8,}\b', re.IGNORECASE),
            'bitcoin_address': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            
            # Document Classification
            'confidential_doc': re.compile(r'\b(?:confidential|top\s*secret|restricted|sensitive|internal\s*use\s*only|not\s*for\s*distribution)\b', re.IGNORECASE)
        }
    
    def extract_features_from_text(self, text: str) -> Dict[str, Union[int, float]]:
        """
        Extract manual features from text to enhance classification.
        
        Args:
            text: The text to analyze
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Check for sensitive patterns
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(text)
            features[f'{pattern_name}_count'] = len(matches)
        
        # Check for target keywords
        keyword_matches = 0
        for keyword in self.target_keywords:
            if re.search(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
                keyword_matches += 1
        features['keyword_matches'] = keyword_matches
        
        # Text length and entropy features
        features['text_length'] = len(text)
        
        # Simple entropy calculation (information density)
        if text:
            char_counts = {}
            for char in text:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            entropy = 0
            for count in char_counts.values():
                prob = count / len(text)
                entropy -= prob * np.log2(prob)
            
            features['entropy'] = entropy
        else:
            features['entropy'] = 0
            
        return features
    
    def set_target_keywords(self, keywords: List[str]) -> None:
        """
        Set the list of target keywords to match against in texts.
        
        Args:
            keywords: List of keywords to search for
        """
        self.target_keywords = keywords
        logger.info(f"Set {len(keywords)} target keywords for detection")
    
    def train(self, texts: List[str], labels: List[int]) -> Dict[str, Any]:
        """
        Train the classifier on a labeled dataset.
        
        Args:
            texts: List of text samples
            labels: List of corresponding labels (1 for leak, 0 for not leak)
            
        Returns:
            Dictionary with training results and metrics
        """
        try:
            logger.info(f"Training classifier with {len(texts)} samples")
            
            # Split data into training and testing sets
            X_train, X_test, y_train, y_test = train_test_split(
                texts, labels, test_size=0.2, random_state=42
            )
            
            # Train the model
            self.pipeline.fit(X_train, y_train)
            
            # Evaluate the model
            accuracy = self.pipeline.score(X_test, y_test)
            logger.info(f"Model trained with accuracy: {accuracy:.4f}")
            
            return {
                'accuracy': accuracy,
                'train_samples': len(X_train),
                'test_samples': len(X_test),
                'success': True
            }
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def predict(self, text: str) -> Dict[str, Any]:
        """
        Predict if a text contains a data leak.
        
        Args:
            text: The text to analyze
            
        Returns:
            Dictionary with prediction results and confidence scores
        """
        if not self.pipeline:
            logger.error("Model not initialized or trained")
            return {
                'is_leak': False,
                'confidence': 0.0,
                'error': 'Model not trained'
            }
        
        try:
            # Extract manual features to help classification
            extracted_features = self.extract_features_from_text(text)
            
            # Make prediction with ML model
            prediction_proba = self.pipeline.predict_proba([text])[0]
            is_leak = prediction_proba[1] > 0.5
            confidence = prediction_proba[1] if is_leak else 1 - prediction_proba[1]
            
            # Rule-based pattern severity categorization
            pattern_severities = {
                # High severity patterns (very likely to represent a data leak)
                'high': [
                    'credit_card', 'ssn', 'password', 'auth_token', 'api_key', 
                    'aws_access_key', 'aws_secret_key', 'private_key', 'jwt_token',
                    'github_token', 'database_conn_string'
                ],
                # Medium severity patterns (might indicate a data leak)
                'medium': [
                    'email', 'phone_number', 'date_of_birth', 'sql_dump',
                    'confidential_doc', 'mac_address', 'bitcoin_address', 'generic_secret'
                ],
                # Low severity patterns (less likely to be critical)
                'low': [
                    'ip_address'
                ]
            }
            
            # Count pattern matches by severity
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            pattern_matches_by_type = {}
            
            # Detect patterns and categorize by severity
            for pattern_name, count in extracted_features.items():
                if pattern_name.endswith('_count') and count > 0:
                    pattern_type = pattern_name.replace('_count', '')
                    pattern_matches_by_type[pattern_type] = count
                    
                    # Assign severity
                    if pattern_type in pattern_severities['high']:
                        severity_counts['high'] += count
                    elif pattern_type in pattern_severities['medium']:
                        severity_counts['medium'] += count
                    elif pattern_type in pattern_severities['low']:
                        severity_counts['low'] += count
            
            # Calculate total pattern matches
            pattern_matches = sum(severity_counts.values())
            
            # Get keyword matches
            keyword_matches = extracted_features.get('keyword_matches', 0)
            
            # Calculate confidence based on a weighted approach
            base_confidence = confidence
            
            # Apply weights based on severity
            if pattern_matches > 0:
                # High severity matches have the most impact
                if severity_counts['high'] > 0:
                    high_factor = min(0.4, severity_counts['high'] * 0.1)
                    base_confidence = min(0.99, base_confidence + high_factor)
                
                # Medium severity has moderate impact
                if severity_counts['medium'] > 0:
                    medium_factor = min(0.25, severity_counts['medium'] * 0.05)
                    base_confidence = min(0.95, base_confidence + medium_factor)
                
                # Low severity has minimal impact
                if severity_counts['low'] > 0:
                    low_factor = min(0.1, severity_counts['low'] * 0.02)
                    base_confidence = min(0.9, base_confidence + low_factor)
            
            # Keywords matching increases confidence
            if keyword_matches > 0:
                keyword_factor = min(0.3, keyword_matches * 0.08)
                base_confidence = min(0.99, base_confidence + keyword_factor)
            
            # Context-aware adjustment: multiple pattern types indicate high likelihood
            unique_pattern_types = len(pattern_matches_by_type)
            if unique_pattern_types > 1:
                context_factor = min(0.15, unique_pattern_types * 0.05)
                base_confidence = min(0.99, base_confidence + context_factor)
            
            # Density of sensitive information - if there are many matches in a small text, it's more likely a leak
            text_length = extracted_features.get('text_length', 1)
            if text_length > 0 and pattern_matches > 0:
                density = pattern_matches / (text_length / 1000)  # patterns per 1000 chars
                if density > 0.5:  # High density
                    density_factor = min(0.2, density * 0.05)
                    base_confidence = min(0.99, base_confidence + density_factor)
            
            # Determine leak type based on patterns detected
            leak_types = list(pattern_matches_by_type.keys())
            
            # Categorize severity of the leak based on the patterns
            leak_severity = "low"
            if severity_counts['high'] > 0:
                leak_severity = "high"
            elif severity_counts['medium'] > 0:
                leak_severity = "medium"
            
            # Classification: determine if this is a leak
            # If we detected high-severity patterns or medium patterns with keywords, it's a leak
            is_leak_detected = (severity_counts['high'] > 0 or 
                               (severity_counts['medium'] > 0 and keyword_matches > 0) or
                               base_confidence >= 0.7)
            
            return {
                'is_leak': is_leak_detected,
                'confidence': base_confidence,
                'original_confidence': confidence,
                'leak_types': leak_types,
                'leak_severity': leak_severity,
                'pattern_matches': pattern_matches,
                'severity_counts': severity_counts,
                'keyword_matches': keyword_matches,
                'unique_pattern_types': unique_pattern_types
            }
            
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            return {
                'is_leak': False,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def save_model(self, path: str) -> bool:
        """
        Save the trained model to disk.
        
        Args:
            path: Path to save the model
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.pipeline:
                joblib.dump(self.pipeline, path)
                logger.info(f"Model saved to {path}")
                return True
            else:
                logger.error("No model to save")
                return False
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def load_model(self, path: str) -> bool:
        """
        Load a trained model from disk.
        
        Args:
            path: Path to the model file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if os.path.exists(path):
                self.pipeline = joblib.load(path)
                logger.info(f"Model loaded from {path}")
                return True
            else:
                logger.error(f"Model file not found at {path}")
                return False
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self._initialize_pipeline()  # Initialize a new pipeline on failure
            return False
    
    def _check_custom_detection_rules(self, text: str) -> List[Dict[str, Any]]:
        """
        Check the text against custom detection rules from the database.
        
        Args:
            text: The text to analyze
            
        Returns:
            List of dictionaries containing rule matches
        """
        from app import app, db
        from models import DetectionRule, RuleMatch
        
        rule_matches = []
        
        # Import inside the function to avoid circular imports
        try:
            with app.app_context():
                # Get all enabled detection rules
                enabled_rules = DetectionRule.query.filter_by(is_enabled=True).all()
                
                for rule in enabled_rules:
                    try:
                        # Check pattern against text based on pattern type
                        if rule.pattern_type == 'regex':
                            pattern = re.compile(rule.pattern_value, re.IGNORECASE)
                            matches = list(pattern.finditer(text))
                            
                            if matches:
                                for match in matches:
                                    # Extract surrounding context
                                    start = max(0, match.start() - 50)
                                    end = min(len(text), match.end() + 50)
                                    context = text[start:end]
                                    
                                    rule_matches.append({
                                        'rule_id': rule.id,
                                        'rule_name': rule.name,
                                        'severity': rule.severity,
                                        'category': rule.category,
                                        'match_text': match.group(),
                                        'match_position': match.start(),
                                        'match_context': context,
                                        'pattern_type': 'regex'
                                    })
                                    
                        elif rule.pattern_type == 'keyword':
                            # Simple keyword search (case insensitive)
                            keyword = rule.pattern_value.lower()
                            text_lower = text.lower()
                            
                            # Find all occurrences
                            start_pos = 0
                            while True:
                                pos = text_lower.find(keyword, start_pos)
                                if pos == -1:
                                    break
                                
                                # Extract surrounding context
                                context_start = max(0, pos - 50)
                                context_end = min(len(text), pos + len(keyword) + 50)
                                context = text[context_start:context_end]
                                
                                rule_matches.append({
                                    'rule_id': rule.id,
                                    'rule_name': rule.name,
                                    'severity': rule.severity,
                                    'category': rule.category,
                                    'match_text': text[pos:pos+len(keyword)],
                                    'match_position': pos,
                                    'match_context': context,
                                    'pattern_type': 'keyword'
                                })
                                
                                start_pos = pos + len(keyword)
                        
                        elif rule.pattern_type == 'ml_pattern':
                            # Handle ML-based patterns (simplified for now)
                            # The pattern value is expected to be a comma-separated list of terms
                            terms = [term.strip() for term in rule.pattern_value.split(',')]
                            
                            # Check if a minimum number of terms appear in the text
                            matches = 0
                            for term in terms:
                                if term.lower() in text.lower():
                                    matches += 1
                            
                            # If at least half of the terms match, consider it a hit
                            if matches >= max(1, len(terms) // 2):
                                rule_matches.append({
                                    'rule_id': rule.id,
                                    'rule_name': rule.name,
                                    'severity': rule.severity,
                                    'category': rule.category,
                                    'match_text': ', '.join(terms),
                                    'match_position': 0,  # Not applicable for ML patterns
                                    'match_context': text[:200] + "..." if len(text) > 200 else text,
                                    'pattern_type': 'ml_pattern'
                                })
                    
                    except Exception as e:
                        logger.error(f"Error checking rule '{rule.name}' (ID: {rule.id}): {e}")
        
        except Exception as e:
            logger.error(f"Error accessing detection rules: {e}")
        
        return rule_matches
        
    def analyze_text_for_leaks(self, text: str, organization_keywords: List[str]) -> Dict[str, Any]:
        """
        Analyze text to check for potential data leaks related to an organization.
        
        Args:
            text: The text to analyze
            organization_keywords: Keywords related to the organization
            
        Returns:
            Dictionary with analysis results
        """
        # Set the organization keywords before prediction
        self.set_target_keywords(organization_keywords)
        
        # Make prediction using built-in patterns and ML model
        prediction = self.predict(text)
        
        # Extract snippets around matched patterns and keywords
        snippets = []
        
        if text:
            # Extract snippets for each pattern match
            for pattern_name, pattern in self.sensitive_patterns.items():
                for match in pattern.finditer(text):
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    snippet = text[start:end]
                    snippets.append({
                        'type': pattern_name,
                        'match': match.group(),
                        'context': f"...{snippet}...",
                        'source': 'built_in_pattern'
                    })
            
            # Extract snippets for each keyword match
            for keyword in organization_keywords:
                for match in re.finditer(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    snippet = text[start:end]
                    snippets.append({
                        'type': 'keyword',
                        'match': match.group(),
                        'context': f"...{snippet}...",
                        'source': 'organization_keyword'
                    })
            
            # Check custom detection rules
            custom_rule_matches = self._check_custom_detection_rules(text)
            
            # Add custom rule matches to snippets
            for rule_match in custom_rule_matches:
                snippets.append({
                    'type': rule_match['pattern_type'],
                    'match': rule_match['match_text'],
                    'context': f"...{rule_match['match_context']}...",
                    'rule_name': rule_match['rule_name'],
                    'rule_id': rule_match['rule_id'],
                    'severity': rule_match['severity'],
                    'category': rule_match['category'],
                    'source': 'custom_rule'
                })
            
            # If custom rules matched, increase the confidence and mark as leak
            if custom_rule_matches:
                # Count matches by severity
                high_severity = sum(1 for match in custom_rule_matches if match['severity'] == 'high')
                medium_severity = sum(1 for match in custom_rule_matches if match['severity'] == 'medium')
                
                # Adjust confidence based on custom rule matches
                if high_severity > 0:
                    prediction['confidence'] = min(0.99, prediction['confidence'] + 0.3)
                    prediction['is_leak'] = True
                elif medium_severity > 0:
                    prediction['confidence'] = min(0.95, prediction['confidence'] + 0.2)
                    prediction['is_leak'] = True
                else:
                    prediction['confidence'] = min(0.9, prediction['confidence'] + 0.1)
                
                # Add custom rule types to leak types
                custom_categories = set(match['category'] for match in custom_rule_matches)
                prediction['leak_types'].extend(list(custom_categories))
                
                # Add custom rule information
                prediction['custom_rule_matches'] = len(custom_rule_matches)
                prediction['custom_rule_details'] = custom_rule_matches
        
        # Sort snippets by match type importance
        def snippet_sort_key(snippet):
            source_priority = {
                'custom_rule': 0,
                'built_in_pattern': 1,
                'organization_keyword': 2
            }
            severity_priority = {
                'high': 0,
                'medium': 1,
                'low': 2,
                None: 3
            }
            return (
                source_priority.get(snippet.get('source'), 999),
                severity_priority.get(snippet.get('severity'), 999)
            )
        
        # Sort snippets with the most important ones first
        sorted_snippets = sorted(snippets, key=snippet_sort_key)
        
        # Deduplicate and limit snippets
        unique_snippets = []
        snippet_texts = set()
        for snippet in sorted_snippets:
            if snippet['match'] not in snippet_texts:
                unique_snippets.append(snippet)
                snippet_texts.add(snippet['match'])
            if len(unique_snippets) >= 10:
                break
        
        return {
            **prediction,
            'snippets': unique_snippets,
            'organization_keywords': organization_keywords,
            'total_snippets': len(snippets)
        }
