#!/usr/bin/env python3
"""
Password Strength Checker
Analyzes password strength and provides security recommendations.
"""


import re
import math

class PasswordStrengthChecker:
    """Class to analyze password strength and security."""
    
    # Common weak passwords
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321',
        'superman', 'qazwsx', 'michael', 'football', 'password1'
    ]
    
    def __init__(self, password):
        """Initialize password checker."""
        self.password = password
        self.length = len(password)
        self.score = 0
        self.feedback = []
        
    def check_length(self):
        """Check password length and add to score."""
        if self.length < 6:
            self.feedback.append("❌ Password too short (minimum 8 characters recommended)")
            return 0
        elif self.length < 8:
            self.feedback.append("⚠️  Password is short (8-12 characters recommended)")
            self.score += 1
            return 1
        elif self.length < 12:
            self.feedback.append("✓ Good password length")
            self.score += 2
            return 2
        else:
            self.feedback.append("✓ Excellent password length")
            self.score += 3
            return 3
    
    def check_character_variety(self):
        """Check for variety in character types."""
        has_lower = bool(re.search(r'[a-z]', self.password))
        has_upper = bool(re.search(r'[A-Z]', self.password))
        has_digit = bool(re.search(r'\d', self.password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', self.password))
        
        variety_score = sum([has_lower, has_upper, has_digit, has_special])
        
        if variety_score == 1:
            self.feedback.append("❌ Uses only one character type (very weak)")
            return 0
        elif variety_score == 2:
            self.feedback.append("⚠️  Uses two character types (add more variety)")
            self.score += 1
            return 1
        elif variety_score == 3:
            self.feedback.append("✓ Uses three character types (good)")
            self.score += 2
            return 2
        else:
            self.feedback.append("✓ Uses all four character types (excellent)")
            self.score += 3
            return 3
    
    def check_common_patterns(self):
        """Check for common weak patterns."""
        weak_patterns = []
        
        # Check for common passwords
        if self.password.lower() in self.COMMON_PASSWORDS:
            weak_patterns.append("Common password")
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '12345', 'abcde']
        for pattern in keyboard_patterns:
            if pattern in self.password.lower():
                weak_patterns.append(f"Keyboard pattern: {pattern}")
        
        # Check for repeated characters
        for char in set(self.password):
            if self.password.count(char) > 3:
                weak_patterns.append(f"Repeated character: '{char}'")
                break
        
        # Check for sequences
        if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde)', self.password.lower()):
            weak_patterns.append("Sequential pattern detected")
        
        if weak_patterns:
            self.feedback.append(f"❌ Weak patterns: {', '.join(weak_patterns)}")
            return 0
        else:
            self.feedback.append("✓ No common weak patterns detected")
            self.score += 2
            return 2
    
    def calculate_entropy(self):
        """Calculate password entropy (measure of randomness)."""
        # Determine character space
        char_space = 0
        if re.search(r'[a-z]', self.password):
            char_space += 26
        if re.search(r'[A-Z]', self.password):
            char_space += 26
        if re.search(r'\d', self.password):
            char_space += 10
        if re.search(r'[^a-zA-Z0-9]', self.password):
            char_space += 32
        
        # Entropy = log2(char_space^length)
        if char_space > 0:
            entropy = self.length * math.log2(char_space)
        else:
            entropy = 0
        
        if entropy < 28:
            self.feedback.append(f"❌ Very low entropy ({entropy:.1f} bits) - highly predictable")
        elif entropy < 36:
            self.feedback.append(f"⚠️  Low entropy ({entropy:.1f} bits) - somewhat predictable")
        elif entropy < 60:
            self.feedback.append(f"✓ Moderate entropy ({entropy:.1f} bits) - reasonably secure")
            self.score += 1
        else:
            self.feedback.append(f"✓ High entropy ({entropy:.1f} bits) - very secure")
            self.score += 2
        
        return entropy
    
    def get_strength_rating(self):
        """Get overall password strength rating."""
        if self.score < 3:
            return "VERY WEAK", "🔴"
        elif self.score < 5:
            return "WEAK", "🟠"
        elif self.score < 7:
            return "MODERATE", "🟡"
        elif self.score < 9:
            return "STRONG", "🟢"
        else:
            return "VERY STRONG", "🟢"
    
    def get_crack_time_estimate(self):
        """Estimate time to crack password using brute force."""
        # Determine character space
        char_space = 0
        if re.search(r'[a-z]', self.password):
            char_space += 26
        if re.search(r'[A-Z]', self.password):
            char_space += 26
        if re.search(r'\d', self.password):
            char_space += 10
        if re.search(r'[^a-zA-Z0-9]', self.password):
            char_space += 32
        
        if char_space == 0:
            return "Instant"
        
        # Calculate possible combinations
        combinations = char_space ** self.length
        
        # Assume 1 billion attempts per second (modern GPU)
        attempts_per_second = 1_000_000_000
        seconds = combinations / attempts_per_second / 2  # Average case
        
        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.0f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.0f} years"
        else:
            return "Centuries"
    
    def analyze(self):
        """Perform complete password analysis."""
        print("\n" + "=" * 60)
        print("PASSWORD STRENGTH ANALYSIS")
        print("=" * 60)
        
        # Run all checks
        self.check_length()
        self.check_character_variety()
        self.check_common_patterns()
        entropy = self.calculate_entropy()
        
        # Get strength rating
        rating, emoji = self.get_strength_rating()
        crack_time = self.get_crack_time_estimate()
        
        # Display results
        print(f"\nPassword: {'*' * len(self.password)}")
        print(f"Length: {self.length} characters")
        print(f"Entropy: {entropy:.1f} bits")
        print(f"\nStrength: {emoji} {rating}")
        print(f"Score: {self.score}/10")
        print(f"Estimated crack time: {crack_time}")
        
        print("\nDetailed Feedback:")
        for i, msg in enumerate(self.feedback, 1):
            print(f"  {i}. {msg}")
        
        # Recommendations
        print("\n" + "-" * 60)
        print("RECOMMENDATIONS:")
        recommendations = []
        
        if self.length < 12:
            recommendations.append("Use at least 12 characters")
        if not re.search(r'[a-z]', self.password):
            recommendations.append("Add lowercase letters")
        if not re.search(r'[A-Z]', self.password):
            recommendations.append("Add uppercase letters")
        if not re.search(r'\d', self.password):
            recommendations.append("Add numbers")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', self.password):
            recommendations.append("Add special characters")
        
        if not recommendations:
            recommendations.append("Your password is strong! ✓")
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        print("=" * 60 + "\n")
        
        return {
            'strength': rating,
            'score': self.score,
            'entropy': entropy,
            'crack_time': crack_time,
            'feedback': self.feedback
        }

def main():
    """Main function to run password strength checker."""
    print("\n" + "=" * 60)
    print("PASSWORD STRENGTH CHECKER")
    print("=" * 60)
    print("\nTest your password strength and get security recommendations.\n")
    
    while True:
        password = input("Enter password to test (or 'quit' to exit): ")
        
        if password.lower() == 'quit':
            print("\nThank you for using Password Strength Checker!")
            break
        
        if not password:
            print("Error: Please enter a password")
            continue
        
        checker = PasswordStrengthChecker(password)
        checker.analyze()
        
        print("\n" + "-" * 60)
        again = input("Test another password? (y/n): ").lower()
        if again != 'y':
            print("\nThank you for using Password Strength Checker!")
            break

if __name__ == "__main__":
    main()