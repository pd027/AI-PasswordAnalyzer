# GenAI Component for Password Suggestions
# This module would interface with an LLM to generate better password suggestions

import re
import random
from typing import List, Dict, Tuple

class PasswordGenAI:
    """
    Class to handle GenAI-based password improvement suggestions
    In a production environment, this would interface with an actual LLM model
    """
    
    def __init__(self, model_name: str = "gpt-3.5-turbo"):
        """Initialize the GenAI component"""
        self.model_name = model_name
        # Dictionary of common substitutions for character replacements
        self.substitutions = {
            'a': ['@', '4'],
            'b': ['8', '6'],
            'e': ['3', '€'],
            'i': ['1', '!', '|'],
            'l': ['1', '|', '/'],
            'o': ['0', 'ø', '()'],
            's': ['5', '$'],
            't': ['7', '+'],
            'g': ['9', '&'],
            'z': ['2', '%']
        }
        
    def _identify_patterns(self, password: str) -> Dict[str, bool]:
        """Identify various patterns in the password"""
        patterns = {
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digit': bool(re.search(r'[0-9]', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'has_word': bool(re.search(r'[a-zA-Z]{4,}', password)),
            'has_sequence': bool(re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)', password.lower())),
            'has_repetition': bool(re.search(r'(.)\1{2,}', password)),
            'has_year': bool(re.search(r'19\d{2}|20\d{2}', password)),
            'has_date': bool(re.search(r'(0[1-9]|1[0-2])[/.-](0[1-9]|[12]\d|3[01])', password))
        }
        return patterns
    
    def _extract_recognizable_words(self, password: str) -> List[str]:
        """Extract potential words from the password"""
        # This is a simplified implementation
        # In a real scenario, this would use more sophisticated word recognition
        words = []
        current_word = ""
        
        for char in password:
            if char.isalpha():
                current_word += char
            else:
                if len(current_word) >= 3:  # Consider sequences of 3+ letters as potential words
                    words.append(current_word)
                current_word = ""
                
        if len(current_word) >= 3:
            words.append(current_word)
            
        return words
    
    def _generate_replacement_for_word(self, word: str) -> str:
        """Generate a replacement for a recognized word"""
        result = ""
        for char in word:
            if char.lower() in self.substitutions and random.random() > 0.5:
                replacement = random.choice(self.substitutions[char.lower()])
                result += replacement
            else:
                # Randomly capitalize some letters
                if random.random() > 0.7:
                    result += char.upper()
                else:
                    result += char
        return result
    
    def _insert_special_chars(self, password: str) -> str:
        """Insert special characters at random positions"""
        special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
        positions = random.sample(range(len(password) + 1), min(3, len(password) + 1))
        
        result = ""
        for i in range(len(password) + 1):
            if i in positions:
                result += random.choice(special_chars)
            if i < len(password):
                result += password[i]
                
        return result
    
    def generate_suggestion(self, password: str) -> str:
        """Generate an improved password suggestion based on the input"""
        patterns = self._identify_patterns(password)
        words = self._extract_recognizable_words(password)
        
        # Start with the original password
        improved = password
        
        # If we have recognizable words, transform them
        if words:
            for word in words:
                if len(word) >= 4:  # Only transform substantial words
                    replacement = self._generate_replacement_for_word(word)
                    improved = improved.replace(word, replacement)
        
        # Ensure improved password has required character types
        if not patterns['has_uppercase']:
            # Add uppercase if none exists
            pos = random.randint(0, len(improved) - 1)
            improved = improved[:pos] + improved[pos].upper() + improved[pos+1:]
            
        if not patterns['has_digit']:
            # Add digits if none exist
            improved += str(random.randint(0, 999))
            
        if not patterns['has_special']:
            # Add special characters if none exist
            improved = self._insert_special_chars(improved)
            
        # Ensure minimum length
        while len(improved) < 12:
            additions = ["!", "@", "#", "$", "%", "^", "&", "*", 
                        str(random.randint(0, 9)), 
                        chr(random.randint(65, 90)),  # Uppercase
                        chr(random.randint(97, 122))]  # Lowercase
            improved += random.choice(additions)
            
        # Generate natural language explanation for improvements
        explanation = self._generate_improvement_explanation(password, improved, patterns)
            
        return improved, explanation
    
    def _generate_improvement_explanation(self, original: str, improved: str, patterns: Dict[str, bool]) -> str:
        """Generate a natural language explanation of the improvements made"""
        explanations = []
        
        # Analyze what was improved
        if len(improved) > len(original):
            explanations.append(f"I increased the length from {len(original)} to {len(improved)} characters")
            
        # Check for character type improvements
        if not patterns['has_uppercase'] and bool(re.search(r'[A-Z]', improved)):
            explanations.append("I added uppercase letters")
            
        if not patterns['has_digit'] and bool(re.search(r'[0-9]', improved)):
            explanations.append("I added numeric digits")
            
        if not patterns['has_special'] and bool(re.search(r'[^a-zA-Z0-9]', improved)):
            explanations.append("I added special characters")
            
        if patterns['has_word']:
            explanations.append("I transformed dictionary words with character substitutions")
            
        if patterns['has_sequence']:
            explanations.append("I broke up sequential characters that are easy to guess")
            
        if patterns['has_repetition']:
            explanations.append("I eliminated repeated characters that weaken your password")
            
        if patterns['has_year'] or patterns['has_date']:
            explanations.append("I modified predictable date patterns")
            
        # Combine explanations into readable text
        if not explanations:
            return "I made your password stronger while maintaining its structure."
            
        explanation_text = "I improved your password by: " + ", ".join(explanations[:-1])
        if len(explanations) > 1:
            explanation_text += f", and {explanations[-1]}."
        else:
            explanation_text += "."
            
        return explanation_text
    
    def generate_reason_for_weakness(self, password: str, time_to_crack: str, attack_vector: str) -> str:
        """Generate a natural language explanation of why the password is weak"""
        patterns = self._identify_patterns(password)
        words = self._extract_recognizable_words(password)
        
        reasons = []
        
        # Length check
        if len(password) < 8:
            reasons.append(f"Your password is only {len(password)} characters long. Shorter passwords are significantly easier to crack.")
        elif len(password) < 12:
            reasons.append(f"While your password has {len(password)} characters, modern security standards recommend at least 12 characters.")
            
        # Check for missing character types
        missing_types = []
        if not patterns['has_uppercase']:
            missing_types.append("uppercase letters")
        if not patterns['has_lowercase']:
            missing_types.append("lowercase letters")
        if not patterns['has_digit']:
            missing_types.append("numbers")
        if not patterns['has_special']:
            missing_types.append("special characters")
            
        if missing_types:
            if len(missing_types) == 1:
                reasons.append(f"Your password lacks {missing_types[0]}, which reduces its complexity.")
            else:
                reasons.append(f"Your password lacks {', '.join(missing_types[:-1])} and {missing_types[-1]}, which significantly reduces its complexity.")
        
        # Pattern checks
        if patterns['has_sequence']:
            reasons.append("Your password contains sequential characters (like 'abc' or '123'), which are easily guessable patterns.")
            
        if patterns['has_repetition']:
            reasons.append("Your password contains repeated characters, which reduces its unpredictability.")
            
        if patterns['has_year']:
            reasons.append("Your password contains what appears to be a year, which is a common and predictable element.")
            
        if patterns['has_date']:
            reasons.append("Your password contains what appears to be a date, which is a common and predictable element.")
            
        if words and len(words[0]) >= 4:
            reasons.append(f"Your password contains recognizable words (like '{words[0]}'), which makes it vulnerable to dictionary attacks.")
            
        # Time to crack context
        time_context = f"Based on these factors, your password could be cracked in approximately {time_to_crack} using a {attack_vector}."
        
        # Combine all reasons
        if not reasons:
            # This should rarely happen but just in case
            return f"Your password has some structural weaknesses. {time_context}"
            
        reason_text = " ".join(reasons) + " " + time_context
        
        return reason_text