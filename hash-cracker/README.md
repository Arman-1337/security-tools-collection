# Hash Cracker

Advanced password hash cracker supporting multiple hash algorithms and attack methods.

## Features

- 🔐 **Multiple Hash Types** - MD5, SHA-1, SHA-256, SHA-512
- 📖 **Dictionary Attack** - Fast password cracking using wordlists
- 💪 **Brute Force Attack** - Guaranteed cracking for short passwords
- ⚡ **High Performance** - Optimized hashing with progress tracking
- 🎯 **Hash Identification** - Automatic hash type detection
- 📊 **Statistics** - Attack metrics and success rates
- 🧪 **Hash Generator** - Create example hashes for testing

## Usage

### Interactive Mode (Recommended)
```bash
python hash_cracker.py
```

Follow the interactive prompts to:
1. Enter hash to crack
2. Select hash type (auto-detected)
3. Choose attack method
4. Configure attack parameters

### Command Line Mode
```bash
python hash_cracker.py <hash> <hash_type>
```

**Example:**
```bash
python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 md5
```

### Generate Example Hashes
```bash
python hash_cracker.py --generate-examples
```

## Example Session
```
==============================================================
HASH CRACKER - Security Tools Collection
==============================================================
Supports: MD5, SHA-1, SHA-256, SHA-512
Methods: Dictionary Attack, Brute Force
==============================================================

📋 MENU:
  1. Crack a hash
  2. Generate example hashes
  3. Exit

Select option (1-3): 1

--------------------------------------------------------------
Enter hash to crack: 5f4dcc3b5aa765d61d8327deb882cf99

Hash length: 32 characters
Suggested hash type: MD5
Hash type (default: md5): 

--------------------------------------------------------------
ATTACK METHODS:
  1. Dictionary Attack (fast, requires common password)
  2. Brute Force (slow, guaranteed for short passwords)
  3. Both (try dictionary first, then brute force)

Select attack method (1-3): 1

🔍 Starting Dictionary Attack...
--------------------------------------------------------------
Using built-in common passwords (50 words)
Testing 50 passwords...

  Tried 1 passwords...

✅ HASH CRACKED!
Password: password
Attempts: 1
Time: 0.01 seconds
Rate: 100 hashes/second

✅ SUCCESS!
```

## Attack Methods

### 1. Dictionary Attack

**Best for:** Common passwords, real-world hashes

**Speed:** Very fast (thousands/second)

**Success Rate:** ~60% for common passwords

**How it works:**
- Tests passwords from a wordlist
- Uses built-in common passwords or custom wordlist
- Stops immediately when match found

### 2. Brute Force Attack

**Best for:** Short passwords (1-5 characters)

**Speed:** Slow (depends on length and charset)

**Success Rate:** 100% (eventually)

**How it works:**
- Tests all possible combinations
- Configurable character sets
- Exponentially slower with length

**Time Estimates:**
- Length 3 (lowercase): < 1 second
- Length 4 (lowercase): < 30 seconds
- Length 5 (lowercase): ~10 minutes
- Length 6 (lowercase): ~5 hours
- Length 7+ (lowercase): Days/weeks/years

## Supported Hash Types

| Hash Type | Length | Example |
|-----------|--------|---------|
| MD5 | 32 chars | `5f4dcc3b5aa765d61d8327deb882cf99` |
| SHA-1 | 40 chars | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` |
| SHA-256 | 64 chars | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` |
| SHA-512 | 128 chars | `b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86` |

## Example Hashes

Test your skills with these example hashes:

**Easy (Common Passwords):**
```
MD5: 5f4dcc3b5aa765d61d8327deb882cf99  (password)
MD5: 21232f297a57a5a743894a0e4a801fc3  (admin)
MD5: e10adc3949ba59abbe56e057f20f883e  (123456)
```

**Medium (Short Passwords):**
```
MD5: 098f6bcd4621d373cade4e832627b4f6  (test)
MD5: 5ebe2294ecd0e0f08eab7690d2a6ee69  (secret)
```

## Character Sets

- **lowercase**: a-z (26 chars)
- **lowercase+digits**: a-z0-9 (36 chars)
- **all**: a-zA-Z0-9 + symbols (94 chars)

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## Performance Tips

1. **Use Dictionary First**: Always try dictionary attack before brute force
2. **Limit Brute Force Length**: Keep under 5 characters for reasonable time
3. **Choose Smaller Charsets**: Start with lowercase before trying all
4. **Use Custom Wordlists**: Add domain-specific words for better success

## Security Implications

**This tool demonstrates:**
- Why strong passwords matter
- How password hashing works
- The importance of salting hashes
- Time-memory tradeoffs in cryptography

**Password Security Best Practices:**
- ✅ Use 12+ character passwords
- ✅ Mix character types
- ✅ Use unique passwords per site
- ✅ Use a password manager
- ✅ Enable two-factor authentication
- ❌ Never use common passwords
- ❌ Don't reuse passwords

## Ethical Use Only

⚠️ **FOR EDUCATIONAL AND AUTHORIZED USE ONLY**

**Legal Uses:**
- Password recovery for your own accounts
- Security testing with authorization
- Educational demonstrations
- CTF competitions and practice

**NEVER:**
- Crack passwords without authorization
- Use for malicious purposes
- Access others' accounts
- Violate terms of service

**Unauthorized password cracking is illegal and punishable by law.**

## Limitations

- No rainbow table support
- Single-threaded (can be improved with multiprocessing)
- No GPU acceleration
- Limited to unsalted hashes
- Educational tool, not production-grade

## Author

Arman Bin Tahir - Cybersecurity Engineer

## License

MIT License - Educational Use Only
