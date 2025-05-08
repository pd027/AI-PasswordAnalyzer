# app.py - Flask Demo Application for Password Strength Analyzer

from flask import Flask, render_template, request, jsonify
import json
import os
from models.password_analyzer import PasswordAnalyzer
from models.genai import PasswordGenAI


app = Flask(__name__)

# Initialize components
analyzer = PasswordAnalyzer(
    ml_model_path="models/password_strength_model.pkl", 
    leaked_password_db_path="data/leaked_passwords.db"
)
genai = PasswordGenAI()

@app.route('/')
def index():
    """Render the main application page"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_password():
    """Analyze password strength and return results"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({
            'score': 0,
            'time_to_crack': 'instant',
            'vulnerability_factors': ['Empty password'],
            'suggestions': ['Please enter a password'],
            'reasoning': 'An empty password provides no security.'
        })
        
    # Analyze using core engine
    result = analyzer.analyze_password(password)
    
    # Generate GenAI reasoning and improved suggestion
    improved_password, improvement_explanation = genai.generate_suggestion(password)
    weakness_reasoning = genai.generate_reason_for_weakness(
        password, 
        result.time_to_crack,
        result.attack_vector
    )
    
    # Prepare response
    response = {
        'score': result.score,
        'time_to_crack': result.time_to_crack,
        'vulnerability_factors': result.vulnerability_factors,
        'patterns_detected': result.patterns_detected,
        'is_compromised': result.is_compromised,
        'attack_vector': result.attack_vector,
        'suggestions': result.suggestions,
        'improved_password': improved_password,
        'reasoning': weakness_reasoning,
        'improvement_explanation': improvement_explanation
    }
    
    return jsonify(response)

@app.route('/generate', methods=['POST'])
def generate_password():
    """Generate a strong password based on time-to-crack threshold"""
    data = request.get_json()
    min_score = data.get('min_score', 80)
    time_threshold_days = data.get('time_threshold_days', 365 * 100)  # Default: 100 years
    
    # Generate candidate passwords until we meet the criteria
    max_attempts = 10
    for _ in range(max_attempts):
        # In a real app, we'd use a more sophisticated generation mechanism
        # For demo, we'll use a simple approach
        candidate = genai.generate_suggestion("")[0]  # Get just the password
        result = analyzer.analyze_password(candidate)
        
        time_to_crack_days = result.time_to_crack_seconds / (60 * 60 * 24)
        
        if result.score >= min_score and time_to_crack_days >= time_threshold_days:
            return jsonify({
                'password': candidate,
                'score': result.score,
                'time_to_crack': result.time_to_crack
            })
    
    # If we couldn't meet criteria, return the best candidate
    candidate = "Tr0ub4dor&3"  # A reasonably strong fallback
    result = analyzer.analyze_password(candidate)
    
    return jsonify({
        'password': candidate,
        'score': result.score,
        'time_to_crack': result.time_to_crack,
        'note': "Could not meet exact criteria, but this password is reasonably strong."
    })

if __name__ == '__main__':
    app.run(debug=True)