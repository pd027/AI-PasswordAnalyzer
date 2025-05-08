# Password Strength Analyzer - Core Architecture

from dataclasses import dataclass
import hashlib
import re
import time
import random
import math
from typing import List, Dict, Tuple, Optional
# import numpy as np

@dataclass
class PasswordStrengthResult:
    """Data class to store password strength analysis results"""
    score: int  # 0-100 score
    time_to_crack: str  # Human readable time
    time_to_crack_seconds: float  # Raw seconds
    vulnerability_factors: List[str]  # List of vulnerability reasons
    suggestions: List[str]  # List of improvement suggestions
    patterns_detected: List[str]  # Patterns found in password
    entropy: float  # Shannon entropy
    is_compromised: bool  # If found in leaked datasets
    attack_vector: str  # Most likely successful attack vector
    
class PasswordAnalyzer:
    """Core password analysis engine"""
    
    def __init__(self, ml_model_path: str, leaked_password_db_path: str):
        """Initialize the password analyzer with ML model and leaked password database"""
        self.ml_model_path = ml_model_path
        self.leaked_db_path = leaked_password_db_path
        self.common_words = self._load_common_words()
        self.ml_model = self._load_ml_model()
        self.leaked_passwords_hash_set = self._load_leaked_password_hashes()
        
    def _load_common_words(self) -> List[str]:
        """Load dictionary of common words"""
        # In a real implementation, load from file
        return ["password", "123456", "qwerty", "admin", "welcome", 
                "summer", "winter", "spring", "fall", "letmein"]
    
    def _load_ml_model(self):
        """Load the ML model for pattern recognition"""
        # In a real implementation, load pretrained model
        return "ML_MODEL_PLACEHOLDER"
    
    def _load_leaked_password_hashes(self) -> set:
        """Load hashed versions of leaked passwords"""
        # In a real implementation, load from database
        return {self._hash_password(pwd) for pwd in self.common_words}
    
    def _hash_password(self, password: str) -> str:
        """Create a hash of the password for comparison"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy of password"""
        if not password:
            return 0.0
        
        char_count = {}
        for char in password:
            if char in char_count:
                char_count[char] += 1
            else:
                char_count[char] = 1
                
        entropy = 0.0
        length = len(password)
        for count in char_count.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
            
        return entropy * length  # Multiply by length for total entropy
    
    def _detect_patterns(self, password: str) -> List[str]:
        """Detect common patterns in the password"""
        patterns = []
        
        # Check for sequential characters
        if any(str(i) + str(i+1) + str(i+2) in password for i in range(8)):
            patterns.append("sequential_numbers")
            
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            patterns.append("repeated_characters")
            
        # Check for keyboard patterns (simplified)
        keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn"]
        if any(pattern in password.lower() for pattern in keyboard_patterns):
            patterns.append("keyboard_pattern")
            
        # Check for common words
        if any(word in password.lower() for word in self.common_words):
            patterns.append("common_word")
            
        # Check for date patterns
        if re.search(r'19\d{2}|20\d{2}', password):
            patterns.append("year")
        if re.search(r'(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])', password):
            patterns.append("date")
            
        return patterns
    
    def _estimate_crack_time(self, password: str, patterns: List[str]) -> Tuple[float, str]:
        """Estimate time to crack based on complexity and detected patterns"""
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Calculate character set size
        char_set_size = 0
        if has_lower: char_set_size += 26
        if has_upper: char_set_size += 26
        if has_digit: char_set_size += 10
        if has_special: char_set_size += 33  # Common special characters
        
        # Base calculation (brute force approach)
        combinations = char_set_size ** length
        
        # Adjust for patterns (each pattern reduces security)
        pattern_penalty = 1.0
        for pattern in patterns:
            pattern_penalty *= 0.7  # Reduce by 30% for each pattern
            
        # Adjust combinations based on patterns
        adjusted_combinations = combinations * pattern_penalty
        
        # Assuming 10 billion attempts per second for a powerful attacker
        seconds_to_crack = adjusted_combinations / (10 * 10**9)
        
        # Format the time in human readable format
        if seconds_to_crack < 60:
            time_str = f"{seconds_to_crack:.2f} seconds"
        elif seconds_to_crack < 3600:
            time_str = f"{seconds_to_crack/60:.2f} minutes"
        elif seconds_to_crack < 86400:
            time_str = f"{seconds_to_crack/3600:.2f} hours"
        elif seconds_to_crack < 31536000:
            time_str = f"{seconds_to_crack/86400:.2f} days"
        elif seconds_to_crack < 31536000*100:
            time_str = f"{seconds_to_crack/31536000:.2f} years"
        else:
            time_str = "centuries"
            
        return seconds_to_crack, time_str
    
    def _determine_attack_vector(self, patterns: List[str], is_leaked: bool) -> str:
        """Determine the most likely successful attack vector"""
        if is_leaked:
            return "credential stuffing (using leaked passwords)"
        elif "common_word" in patterns:
            return "dictionary attack"
        elif any(p in patterns for p in ["sequential_numbers", "keyboard_pattern", "year", "date"]):
            return "rule-based attack"
        elif "repeated_characters" in patterns:
            return "mask attack"
        else:
            return "brute force attack"
    
    def _generate_suggestions(self, password: str, patterns: List[str]) -> List[str]:
        """Generate improvement suggestions based on detected issues"""
        suggestions = []
        
        # Add length suggestion if too short
        if len(password) < 12:
            suggestions.append("Increase password length to at least 12 characters")
            
        # Suggest character diversity
        if not any(c.isupper() for c in password):
            suggestions.append("Add uppercase letters")
        if not any(c.islower() for c in password):
            suggestions.append("Add lowercase letters")
        if not any(c.isdigit() for c in password):
            suggestions.append("Add numeric digits")
        if not any(not c.isalnum() for c in password):
            suggestions.append("Add special characters (!@#$%^&*)")
            
        # Suggest mitigations for detected patterns
        if "sequential_numbers" in patterns:
            suggestions.append("Avoid sequential numbers (like '123')")
        if "repeated_characters" in patterns:
            suggestions.append("Avoid repeated characters (like 'aaa')")
        if "keyboard_pattern" in patterns:
            suggestions.append("Avoid keyboard patterns (like 'qwerty')")
        if "common_word" in patterns:
            suggestions.append("Avoid dictionary words")
        if "year" in patterns or "date" in patterns:
            suggestions.append("Avoid using dates, especially birth years")
            
        # Add a concrete example of improved password
        improved = self._generate_improved_version(password, patterns)
        if improved:
            suggestions.append(f"Consider something like: {improved}")
            
        return suggestions
    
    def _generate_improved_version(self, password: str, patterns: List[str]) -> str:
        """Generate an improved version of the password"""
        # This would be handled by the GenAI component in a real implementation
        # For now, implement a simple transformation
        
        if len(password) < 8:
            # Too short to work with
            return "P@$$w0rd!" + password
            
        # Make simple substitutions
        improved = password
        
        # Add complexity
        improved = improved.replace('a', '@').replace('e', '3').replace('i', '!').replace('o', '0')
        
        # Add special characters if none
        if not any(not c.isalnum() for c in improved):
            improved += '#$*'
            
        # Add uppercase if none
        if not any(c.isupper() for c in improved):
            improved = improved[0].upper() + improved[1:]
            
        # Add digit if none
        if not any(c.isdigit() for c in improved):
            improved += '2024'
            
        # Ensure it's different from original
        if improved == password:
            improved += '!Secure#'
            
        return improved
        
    def analyze_password(self, password: str) -> PasswordStrengthResult:
        """Analyze password strength and return comprehensive results"""
        # Check for empty password
        if not password:
            return PasswordStrengthResult(
                score=0,
                time_to_crack="instant",
                time_to_crack_seconds=0,
                vulnerability_factors=["Empty password"],
                suggestions=["Create a password"],
                patterns_detected=[],
                entropy=0,
                is_compromised=False,
                attack_vector="instant guess"
            )
            
        # Calculate entropy
        entropy = self._calculate_entropy(password)
        
        # Detect patterns
        patterns = self._detect_patterns(password)
        
        # Check if password is compromised
        is_compromised = self._hash_password(password) in self.leaked_passwords_hash_set
        
        # Estimate crack time
        time_to_crack_seconds, time_to_crack = self._estimate_crack_time(password, patterns)
        
        # Determine likely attack vector
        attack_vector = self._determine_attack_vector(patterns, is_compromised)
        
        # Generate vulnerability factors
        vulnerability_factors = []
        if is_compromised:
            vulnerability_factors.append("Password found in leaked database")
        if len(password) < 8:
            vulnerability_factors.append("Password too short")
        if patterns:
            for pattern in patterns:
                vulnerability_factors.append(f"Contains {pattern.replace('_', ' ')}")
            
        # Generate improvement suggestions
        suggestions = self._generate_suggestions(password, patterns)
        
        # Calculate overall score (0-100)
        base_score = min(100, max(0, entropy * 5))  # Base on entropy
        
        # Adjust score based on other factors
        if is_compromised:
            base_score *= 0.2  # Severely reduce score if compromised
        
        # Adjust for patterns
        pattern_penalty = max(0, 1.0 - (len(patterns) * 0.15))
        score = int(base_score * pattern_penalty)
        
        # Return comprehensive results
        return PasswordStrengthResult(
            score=score,
            time_to_crack=time_to_crack,
            time_to_crack_seconds=time_to_crack_seconds,
            vulnerability_factors=vulnerability_factors,
            suggestions=suggestions,
            patterns_detected=patterns,
            entropy=entropy,
            is_compromised=is_compromised,
            attack_vector=attack_vector
        )