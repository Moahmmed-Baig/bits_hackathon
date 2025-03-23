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
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'credit_card': re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
            'ssn': re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            'api_key': re.compile(r'\b[A-Za-z0-9_\-]{20,40}\b'),
            'password': re.compile(r'\b(password|pwd|passwd)[\s:=]+\S+\b', re.IGNORECASE),
            'auth_token': re.compile(r'\b(auth|token|api|secret|key)[\s:=]+\S{8,}\b', re.IGNORECASE),
            'phone_number': re.compile(r'\b(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b')
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
            
            # Make prediction
            prediction_proba = self.pipeline.predict_proba([text])[0]
            is_leak = prediction_proba[1] > 0.5
            confidence = prediction_proba[1] if is_leak else 1 - prediction_proba[1]
            
            # Adjust confidence based on extracted features
            adjusted_confidence = confidence
            
            # Increase confidence if we detected sensitive patterns
            pattern_matches = sum(v for k, v in extracted_features.items() if k.endswith('_count'))
            if pattern_matches > 0:
                # Increase confidence but cap at 0.98
                adjusted_confidence = min(0.98, adjusted_confidence + (pattern_matches * 0.05))
            
            # Increase confidence if we matched target keywords
            keyword_matches = extracted_features.get('keyword_matches', 0)
            if keyword_matches > 0:
                # Increase confidence but cap at 0.99
                adjusted_confidence = min(0.99, adjusted_confidence + (keyword_matches * 0.07))
            
            # Determine leak type based on patterns
            leak_types = []
            for pattern_name, count in extracted_features.items():
                if pattern_name.endswith('_count') and count > 0:
                    leak_type = pattern_name.replace('_count', '')
                    leak_types.append(leak_type)
            
            return {
                'is_leak': is_leak or pattern_matches > 0,  # Consider it a leak if patterns detected
                'confidence': adjusted_confidence,
                'original_confidence': confidence,
                'leak_types': leak_types,
                'pattern_matches': pattern_matches,
                'keyword_matches': keyword_matches
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
        
        # Make prediction
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
                        'context': f"...{snippet}..."
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
                        'context': f"...{snippet}..."
                    })
        
        return {
            **prediction,
            'snippets': snippets[:10],  # Limit to 10 snippets
            'organization_keywords': organization_keywords
        }
