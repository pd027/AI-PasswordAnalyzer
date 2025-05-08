document.addEventListener('DOMContentLoaded', function() {
    // DOM elements
    const passwordInput = document.getElementById('password');
    const togglePasswordBtn = document.getElementById('togglePassword');
    const resultsContainer = document.getElementById('results');
    const strengthMeter = document.getElementById('strengthMeter');
    const strengthText = document.getElementById('strengthText');
    const timeToCrack = document.getElementById('timeToCrack');
    const attackVector = document.getElementById('attackVector');
    const vulnerabilityList = document.getElementById('vulnerabilityList');
    const patternsList = document.getElementById('patternsList');
    const compromisedAlert = document.getElementById('compromisedAlert');
    const aiReasoning = document.getElementById('aiReasoning');
    const suggestionsList = document.getElementById('suggestionsList');
    const improvedPassword = document.getElementById('improvedPassword');
    const copyImprovedBtn = document.getElementById('copyImprovedBtn');
    const improvementExplanation = document.getElementById('improvementExplanation');
    const improvedPasswordContainer = document.getElementById('improvedPasswordContainer');

    const minScoreSlider = document.getElementById('minScore');
    const minScoreValue = document.getElementById('minScoreValue');
    const timeThreshold = document.getElementById('timeThreshold');
    const generatePasswordBtn = document.getElementById('generatePasswordBtn');
    const generatedPasswordContainer = document.getElementById('generatedPasswordContainer');
    const generatedPassword = document.getElementById('generatedPassword');
    const copyGeneratedBtn = document.getElementById('copyGeneratedBtn');
    const generatedStrength = document.getElementById('generatedStrength');
    const generatedCrackTime = document.getElementById('generatedCrackTime');

    // Toggle password visibility
    togglePasswordBtn.addEventListener('click', function() {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        this.querySelector('i').classList.toggle('bi-eye');
        this.querySelector('i').classList.toggle('bi-eye-slash');
    });

    // Update min score value display
    minScoreSlider.addEventListener('input', function() {
        minScoreValue.textContent = this.value;
    });

    // Password input handler with debounce
    let debounceTimer;
    passwordInput.addEventListener('input', function() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            if (this.value.length > 0) {
                analyzePassword(this.value);
            } else {
                resultsContainer.classList.add('d-none');
            }
        }, 500); // 500ms debounce
    });

    // Copy improved password
    copyImprovedBtn.addEventListener('click', function() {
        copyToClipboard(improvedPassword.value);
        showCopyFeedback(this);
    });

    // Copy generated password
    copyGeneratedBtn.addEventListener('click', function() {
        copyToClipboard(generatedPassword.value);
        showCopyFeedback(this);
    });

    // Generate password button
    generatePasswordBtn.addEventListener('click', function() {
        const minScore = minScoreSlider.value;
        const years = parseInt(timeThreshold.value);
        
        // Convert years to days for the API
        const days = years * 365;
        
        generateSecurePassword(minScore, days);
    });

    // Function to analyze password
    function analyzePassword(password) {
        // Show loading state
        showLoadingState();
        
        fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password }),
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            displayResults(data);
        })
        .catch(error => {
            console.error('Error analyzing password:', error);
            // Fallback to mock data for demo purposes or during development
            const mockData = getMockAnalysisResult(password);
            displayResults(mockData);
        });
    }

    // Function to generate secure password
    function generateSecurePassword(minScore, timeThresholdDays) {
        // Show loading state for generated password
        generatedPasswordContainer.classList.remove('d-none');
        generatedPassword.value = "Generating...";
        generatedStrength.textContent = "--";
        generatedCrackTime.textContent = "--";
        
        fetch('/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                min_score: minScore,
                time_threshold_days: timeThresholdDays
            }),
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            generatedPassword.value = data.password;
            generatedStrength.textContent = `${data.score}/100`;
            generatedCrackTime.textContent = data.time_to_crack;
            
            // Optionally analyze the generated password to show its details
            analyzePassword(data.password);
        })
        .catch(error => {
            console.error('Error generating password:', error);
            // Mock data for demo or development
            const mockGeneratedPassword = generateMockPassword();
            generatedPassword.value = mockGeneratedPassword;
            generatedStrength.textContent = "92/100";
            generatedCrackTime.textContent = "10,000+ years";
        });
    }

    // Function to display results
    function displayResults(data) {
        resultsContainer.classList.remove('d-none');
        
        // Update strength meter
        const score = data.score;
        let color;
        
        if (score < 30) color = "#ff4d4d"; // Red
        else if (score < 60) color = "#ffa64d"; // Orange
        else if (score < 80) color = "#ffff4d"; // Yellow
        else color = "#4CAF50"; // Green
        
        strengthMeter.style.width = `${score}%`;
        strengthMeter.style.backgroundColor = color;
        strengthText.textContent = `${score}%`;
        
        // Update time to crack and attack vector
        timeToCrack.textContent = data.time_to_crack;
        attackVector.textContent = data.attack_vector;
        
        // Populate vulnerability list
        vulnerabilityList.innerHTML = '';
        if (data.vulnerability_factors && data.vulnerability_factors.length > 0) {
            data.vulnerability_factors.forEach(factor => {
                const li = document.createElement('li');
                li.innerHTML = `<i class="bi bi-x-circle text-danger me-2"></i>${factor}`;
                vulnerabilityList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.innerHTML = '<i class="bi bi-check-circle text-success me-2"></i>No critical vulnerabilities detected';
            vulnerabilityList.appendChild(li);
        }
        
        // Populate patterns list
        patternsList.innerHTML = '';
        if (data.patterns_detected && data.patterns_detected.length > 0) {
            data.patterns_detected.forEach(pattern => {
                const li = document.createElement('li');
                li.innerHTML = `<i class="bi bi-shield-exclamation text-warning me-2"></i>${pattern.replace(/_/g, ' ')}`;
                patternsList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.innerHTML = '<i class="bi bi-check-circle text-success me-2"></i>No concerning patterns detected';
            patternsList.appendChild(li);
        }
        
        // Show compromised alert if needed
        if (data.is_compromised) {
            compromisedAlert.classList.remove('d-none');
        } else {
            compromisedAlert.classList.add('d-none');
        }
        
        // Update AI reasoning
        aiReasoning.innerHTML = data.reasoning || 'No AI analysis available for this password.';
        
        // Update suggestions list
        if (data.suggestions && data.suggestions.length > 0) {
            let suggestionsHtml = '<ul class="mb-0">';
            data.suggestions.forEach(suggestion => {
                suggestionsHtml += `<li>${suggestion}</li>`;
            });
            suggestionsHtml += '</ul>';
            suggestionsList.innerHTML = suggestionsHtml;
        } else {
            suggestionsList.innerHTML = '<p class="mb-0">No specific suggestions - this password appears to be strong!</p>';
        }
        
        // Update improved password
        if (data.improved_password) {
            improvedPassword.value = data.improved_password;
            improvementExplanation.textContent = data.improvement_explanation || 'AI-enhanced password with improved security characteristics.';
            improvedPasswordContainer.classList.remove('d-none');
        } else {
            improvedPasswordContainer.classList.add('d-none');
        }
    }

    // Show loading state when analyzing
    function showLoadingState() {
        resultsContainer.classList.remove('d-none');
        
        // Show loading indication in the strength meter
        strengthMeter.style.width = '100%';
        strengthMeter.style.backgroundColor = '#6c757d';
        strengthText.textContent = 'Analyzing...';
        
        // Set loading states for other elements
        timeToCrack.textContent = 'Calculating...';
        attackVector.textContent = 'Analyzing...';
        
        // Clear previous results
        vulnerabilityList.innerHTML = '<li><i class="bi bi-hourglass-split text-secondary me-2"></i>Analyzing vulnerabilities...</li>';
        patternsList.innerHTML = '<li><i class="bi bi-hourglass-split text-secondary me-2"></i>Detecting patterns...</li>';
        aiReasoning.innerHTML = '<p><i class="bi bi-cpu"></i> AI is analyzing your password...</p>';
        suggestionsList.innerHTML = '<p><i class="bi bi-hourglass-split text-secondary me-2"></i>Generating suggestions...</p>';
        
        // Hide compromised alert during loading
        compromisedAlert.classList.add('d-none');
    }

    // Utility function to copy to clipboard
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).catch(err => {
            console.error('Could not copy text: ', err);
            // Fallback method for browsers that don't support clipboard API
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
        });
    }

    // Show feedback after copying
    function showCopyFeedback(button) {
        const originalHtml = button.innerHTML;
        button.innerHTML = '<i class="bi bi-check"></i> Copied!';
        button.disabled = true;
        
        setTimeout(() => {
            button.innerHTML = originalHtml;
            button.disabled = false;
        }, 2000);
    }

    // For demo purposes - mock data functions
    // These will be used as fallbacks if the API is not available
    function getMockAnalysisResult(password) {
        // Simple mock result for demo
        const length = password.length;
        const hasUppercase = /[A-Z]/.test(password);
        const hasLowercase = /[a-z]/.test(password);
        const hasDigits = /[0-9]/.test(password);
        const hasSpecial = /[^A-Za-z0-9]/.test(password);
        
        const characterTypes = [hasUppercase, hasLowercase, hasDigits, hasSpecial].filter(Boolean).length;
        
        let score = 0;
        // Base score on length (up to 40 points)
        score += Math.min(length * 4, 40);
        
        // Add points for character diversity (up to 40 points)
        score += characterTypes * 10;
        
        // Check for common patterns and adjust score
        const hasCommonWord = /password|admin|welcome|123456|qwerty/i.test(password);
        const hasSequential = /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789/i.test(password);
        const hasRepeated = /(.)\1{2,}/i.test(password); // Same character repeated 3+ times
        
        if (hasCommonWord) score = Math.max(score - 30, 10);
        if (hasSequential) score = Math.max(score - 15, 10);
        if (hasRepeated) score = Math.max(score - 10, 10);
        
        // Cap score at 100
        score = Math.min(score, 100);
        
        // Determine time to crack based on score
        let timeToCrack;
        if (score < 30) timeToCrack = "seconds to minutes";
        else if (score < 50) timeToCrack = "hours to days";
        else if (score < 70) timeToCrack = "weeks to months";
        else if (score < 90) timeToCrack = "years";
        else timeToCrack = "centuries";
        
        // Vulnerability factors
        const vulnerabilityFactors = [];
        if (length < 8) vulnerabilityFactors.push("Too short (less than 8 characters)");
        if (!hasUppercase) vulnerabilityFactors.push("No uppercase letters");
        if (!hasLowercase) vulnerabilityFactors.push("No lowercase letters");
        if (!hasDigits) vulnerabilityFactors.push("No numbers");
        if (!hasSpecial) vulnerabilityFactors.push("No special characters");
        if (hasCommonWord) vulnerabilityFactors.push("Contains common words or patterns");
        if (hasSequential) vulnerabilityFactors.push("Contains sequential characters");
        if (hasRepeated) vulnerabilityFactors.push("Contains repeated characters");
        
        // Patterns detected
        const patternsDetected = [];
        if (hasCommonWord) patternsDetected.push("common_word");
        if (hasSequential) patternsDetected.push("sequential_characters");
        if (hasRepeated) patternsDetected.push("repeated_characters");
        if (/19\d\d|20\d\d/.test(password)) patternsDetected.push("year_pattern");
        if (/[a-zA-Z]+\d+/.test(password)) patternsDetected.push("word_followed_by_number");
        
        // Determine attack vector
        let attackVector;
        if (hasCommonWord) attackVector = "dictionary attack";
        else if (characterTypes <= 2) attackVector = "brute force (limited character set)";
        else attackVector = "brute force attack";
        
        // Generate suggestions
        const suggestions = [];
        if (length < 12) suggestions.push("Increase password length to at least 12 characters");
        if (characterTypes < 4) suggestions.push("Use a mix of uppercase, lowercase, numbers, and special characters");
        if (hasCommonWord) suggestions.push("Avoid using common words or patterns");
        if (hasSequential) suggestions.push("Avoid sequential characters like 'abc' or '123'");
        if (hasRepeated) suggestions.push("Avoid repeating the same character multiple times");
        
        // Generate an improved password suggestion
        let improvedPassword = password;
        
        // If it's weak, create a stronger alternative
        if (score < 70) {
            // Start with the original if it's not too weak
            if (score < 40) {
                // For very weak passwords, generate something completely new
                improvedPassword = generateMockPassword();
            } else {
                // For moderately weak passwords, try to improve the existing one
                if (!hasUppercase) improvedPassword = improvedPassword.replace(/[a-z]/, c => c.toUpperCase());
                if (!hasLowercase) improvedPassword = improvedPassword.replace(/[A-Z]/, c => c.toLowerCase());
                if (!hasDigits) improvedPassword += Math.floor(Math.random() * 10);
                if (!hasSpecial) improvedPassword += "!@#$%^&*"[Math.floor(Math.random() * 8)];
                if (length < 12) improvedPassword += generateMockPassword().substring(0, 12 - length);
            }
        }
        
        return {
            score: score,
            time_to_crack: timeToCrack,
            vulnerability_factors: vulnerabilityFactors,
            patterns_detected: patternsDetected,
            is_compromised: password === "password123" || password === "admin123" || password === "qwerty123", // Mock check
            attack_vector: attackVector,
            suggestions: suggestions,
            improved_password: improvedPassword,
            reasoning: `This password ${score < 50 ? 'is weak' : 'has moderate strength'}. ${
                vulnerabilityFactors.length > 0 
                    ? 'Key issues include: ' + vulnerabilityFactors.join(', ').toLowerCase() + '.' 
                    : 'It has good complexity and length.'
            } ${
                patternsDetected.length > 0
                    ? 'It contains predictable patterns that reduce security.' 
                    : 'It does not contain obvious predictable patterns.'
            } With current computing power, this password could be cracked in ${timeToCrack}.`,
            improvement_explanation: "The improved password adds complexity while maintaining memorability where possible."
        };
    }

    function generateMockPassword() {
        const lowercase = "abcdefghijklmnopqrstuvwxyz";
        const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const numbers = "0123456789";
        const special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        
        const allChars = lowercase + uppercase + numbers + special;
        let result = "";
        
        // Ensure at least one of each character type
        result += lowercase.charAt(Math.floor(Math.random() * lowercase.length));
        result += uppercase.charAt(Math.floor(Math.random() * uppercase.length));
        result += numbers.charAt(Math.floor(Math.random() * numbers.length));
        result += special.charAt(Math.floor(Math.random() * special.length));
        
        // Add remaining characters randomly
        for (let i = 0; i < 12; i++) {
            result += allChars.charAt(Math.floor(Math.random() * allChars.length));
        }
        
        // Shuffle the result
        return result.split('').sort(() => 0.5 - Math.random()).join('');
    }
});