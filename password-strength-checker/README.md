# Password Strength Checker

Advanced password security analyzer that evaluates password strength and provides detailed feedback.

## Features

- ✅ Length analysis
- ✅ Character variety checking (lowercase, uppercase, digits, special characters)
- ✅ Common password detection
- ✅ Weak pattern identification (keyboard patterns, sequences, repetitions)
- ✅ Entropy calculation (measure of randomness)
- ✅ Crack time estimation
- ✅ Detailed security recommendations

## Usage
```bash
python password_checker.py
```

### Example Output
```
==============================================================
PASSWORD STRENGTH ANALYSIS
==============================================================

Password: ************
Length: 12 characters
Entropy: 71.2 bits

Strength: 🟢 VERY STRONG
Score: 10/10
Estimated crack time: 2.3 million years

Detailed Feedback:
  1. ✓ Excellent password length
  2. ✓ Uses all four character types (excellent)
  3. ✓ No common weak patterns detected
  4. ✓ High entropy (71.2 bits) - very secure

--------------------------------------------------------------
RECOMMENDATIONS:
  1. Your password is strong! ✓
==============================================================
```

## How It Works

The tool analyzes passwords based on:

1. **Length**: Longer passwords are exponentially harder to crack
2. **Character Variety**: Mix of lowercase, uppercase, numbers, and symbols
3. **Pattern Detection**: Identifies common weaknesses like "password123"
4. **Entropy**: Mathematical measure of password randomness
5. **Brute Force Resistance**: Estimates crack time using modern GPUs

## Scoring System

- **0-2**: Very Weak 🔴
- **3-4**: Weak 🟠  
- **5-6**: Moderate 🟡
- **7-8**: Strong 🟢
- **9-10**: Very Strong 🟢

## Best Practices

- ✅ Use at least 12 characters
- ✅ Mix uppercase and lowercase letters
- ✅ Include numbers and special characters
- ✅ Avoid common words and patterns
- ✅ Don't reuse passwords across sites
- ✅ Use a password manager

## Requirements

- Python 3.6+
- No external dependencies

## Disclaimer

⚠️ **For educational purposes only.**

## Author

Arman Bin Tahir - Cybersecurity Engineer
```

