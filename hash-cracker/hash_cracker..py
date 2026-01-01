#!/usr/bin/env python3
"""
Hash Cracker Tool
Cracks password hashes using dictionary and brute force attacks.
"""

import hashlib
import itertools
import string
import time
from datetime import datetime
import sys

class HashCracker:
    """Password hash cracker with multiple attack methods."""
    
    def __init__(self, hash_to_crack, hash_type='md5'):
        """
        Initialize hash cracker.
        
        Args:
            hash_to_crack: The hash to crack
            hash_type: Type of hash (md5, sha1, sha256)
        """
        self.hash_to_crack = hash_to_crack.lower().strip()
        self.hash_type = hash_type.lower()
        self.attempts = 0
        self.start_time = None
        
        # Supported hash types
        self.hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
    
    def hash_password(self, password):
        """
        Hash a password using the specified algorithm.
        
        Args:
            password: Password to hash
            
        Returns:
            Hashed password as hexadecimal string
        """
        if self.hash_type not in self.hash_functions:
            raise ValueError(f"Unsupported hash type: {self.hash_type}")
        
        hash_func = self.hash_functions[self.hash_type]
        return hash_func(password.encode()).hexdigest()
    
    def identify_hash_type(self):
        """Attempt to identify the hash type based on length."""
        length = len(self.hash_to_crack)
        
        hash_lengths = {
            32: 'MD5',
            40: 'SHA-1',
            64: 'SHA-256',
            128: 'SHA-512'
        }
        
        if length in hash_lengths:
            return hash_lengths[length]
        return 'Unknown'
    
    def dictionary_attack(self, wordlist_path=None, custom_words=None):
        """
        Perform dictionary attack on the hash.
        
        Args:
            wordlist_path: Path to wordlist file
            custom_words: List of custom words to try
            
        Returns:
            Cracked password or None
        """
        print("\n🔍 Starting Dictionary Attack...")
        print("-" * 60)
        
        self.start_time = time.time()
        self.attempts = 0
        
        # Use custom words if provided
        if custom_words:
            wordlist = custom_words
        elif wordlist_path:
            try:
                with open(wordlist_path, 'r', encoding='latin-1') as f:
                    wordlist = [line.strip() for line in f]
            except FileNotFoundError:
                print(f"❌ Wordlist file not found: {wordlist_path}")
                return None
        else:
            # Use common passwords if no wordlist provided
            wordlist = self.get_common_passwords()
            print(f"Using built-in common passwords ({len(wordlist)} words)")
        
        print(f"Testing {len(wordlist)} passwords...")
        print()
        
        # Try each password
        for password in wordlist:
            self.attempts += 1
            
            # Show progress every 1000 attempts
            if self.attempts % 1000 == 0:
                elapsed = time.time() - self.start_time
                rate = self.attempts / elapsed if elapsed > 0 else 0
                print(f"  Tried {self.attempts:,} passwords ({rate:.0f} attempts/sec)...", end='\r')
            
            # Hash and compare
            hashed = self.hash_password(password)
            
            if hashed == self.hash_to_crack:
                elapsed = time.time() - self.start_time
                print(f"\n\n✅ HASH CRACKED!")
                print(f"Password: {password}")
                print(f"Attempts: {self.attempts:,}")
                print(f"Time: {elapsed:.2f} seconds")
                print(f"Rate: {self.attempts/elapsed:.0f} hashes/second")
                return password
        
        elapsed = time.time() - self.start_time
        print(f"\n\n❌ Password not found in dictionary")
        print(f"Total attempts: {self.attempts:,}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        return None
    
    def brute_force_attack(self, max_length=4, charset='lowercase'):
        """
        Perform brute force attack on the hash.
        
        Args:
            max_length: Maximum password length to try
            charset: Character set to use (lowercase, uppercase, digits, all)
            
        Returns:
            Cracked password or None
        """
        print("\n🔍 Starting Brute Force Attack...")
        print("-" * 60)
        
        # Define character sets
        charsets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'lowercase+digits': string.ascii_lowercase + string.digits,
            'all': string.ascii_letters + string.digits + string.punctuation
        }
        
        if charset not in charsets:
            charset = 'lowercase'
        
        chars = charsets[charset]
        
        print(f"Character set: {charset} ({len(chars)} characters)")
        print(f"Max length: {max_length}")
        print(f"⚠️  This may take a VERY long time!")
        print()
        
        self.start_time = time.time()
        self.attempts = 0
        
        # Try each length
        for length in range(1, max_length + 1):
            print(f"\nTrying length {length}...")
            
            # Generate all combinations
            for combo in itertools.product(chars, repeat=length):
                password = ''.join(combo)
                self.attempts += 1
                
                # Show progress every 10000 attempts
                if self.attempts % 10000 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed if elapsed > 0 else 0
                    print(f"  Tried {self.attempts:,} combinations ({rate:.0f}/sec)...", end='\r')
                
                # Hash and compare
                hashed = self.hash_password(password)
                
                if hashed == self.hash_to_crack:
                    elapsed = time.time() - self.start_time
                    print(f"\n\n✅ HASH CRACKED!")
                    print(f"Password: {password}")
                    print(f"Attempts: {self.attempts:,}")
                    print(f"Time: {elapsed:.2f} seconds")
                    print(f"Rate: {self.attempts/elapsed:.0f} hashes/second")
                    return password
        
        elapsed = time.time() - self.start_time
        print(f"\n\n❌ Password not found")
        print(f"Total attempts: {self.attempts:,}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        return None
    
    def get_common_passwords(self):
        """Get list of common passwords."""
        return [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'shadow', '123123', '654321', 'superman',
            'qazwsx', 'michael', 'football', 'welcome', 'jesus',
            'ninja', 'mustang', 'password1', 'password123', '123456789',
            'admin', 'root', 'toor', 'pass', 'test',
            'guest', 'oracle', 'sql', 'demo', 'temp',
            'charlie', 'donald', 'harley', 'rangers', 'jordan',
            'robert', 'matthew', 'daniel', 'michelle', 'john'
        ]
    
    def generate_hash_examples(self):
        """Generate example hashes for common passwords."""
        print("\n" + "=" * 60)
        print("EXAMPLE HASH GENERATION")
        print("=" * 60)
        
        test_passwords = ['password', 'admin', '123456', 'letmein']
        
        for password in test_passwords:
            print(f"\nPassword: {password}")
            for hash_type in ['md5', 'sha1', 'sha256']:
                self.hash_type = hash_type
                hashed = self.hash_password(password)
                print(f"  {hash_type.upper():10s}: {hashed}")

def print_banner():
    """Print hash cracker banner."""
    print("\n" + "=" * 60)
    print("HASH CRACKER - Security Tools Collection")
    print("=" * 60)
    print("Supports: MD5, SHA-1, SHA-256, SHA-512")
    print("Methods: Dictionary Attack, Brute Force")
    print("=" * 60)

def interactive_mode():
    """Run hash cracker in interactive mode."""
    print_banner()
    
    print("\n📋 MENU:")
    print("  1. Crack a hash")
    print("  2. Generate example hashes")
    print("  3. Exit")
    
    choice = input("\nSelect option (1-3): ").strip()
    
    if choice == '2':
        cracker = HashCracker('', 'md5')
        cracker.generate_hash_examples()
        return
    
    if choice == '3':
        print("\nGoodbye!")
        sys.exit(0)
    
    if choice != '1':
        print("❌ Invalid option")
        return
    
    # Get hash to crack
    print("\n" + "-" * 60)
    hash_input = input("Enter hash to crack: ").strip()
    
    if not hash_input:
        print("❌ No hash provided")
        return
    
    # Identify hash type
    hash_length = len(hash_input)
    print(f"\nHash length: {hash_length} characters")
    
    hash_types = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        128: 'sha512'
    }
    
    if hash_length in hash_types:
        suggested_type = hash_types[hash_length]
        print(f"Suggested hash type: {suggested_type.upper()}")
        hash_type = input(f"Hash type (default: {suggested_type}): ").strip().lower() or suggested_type
    else:
        print("⚠️  Unknown hash length")
        hash_type = input("Enter hash type (md5/sha1/sha256/sha512): ").strip().lower()
    
    if hash_type not in hash_types.values():
        print(f"❌ Unsupported hash type: {hash_type}")
        return
    
    # Create cracker
    cracker = HashCracker(hash_input, hash_type)
    
    # Choose attack method
    print("\n" + "-" * 60)
    print("ATTACK METHODS:")
    print("  1. Dictionary Attack (fast, requires common password)")
    print("  2. Brute Force (slow, guaranteed for short passwords)")
    print("  3. Both (try dictionary first, then brute force)")
    
    attack_method = input("\nSelect attack method (1-3): ").strip()
    
    result = None
    
    # Dictionary attack
    if attack_method in ['1', '3']:
        result = cracker.dictionary_attack()
        
        if result:
            print("\n✅ SUCCESS!")
            return
        
        if attack_method == '1':
            print("\n❌ Failed to crack hash")
            return
    
    # Brute force attack
    if attack_method in ['2', '3']:
        if attack_method == '3':
            print("\n" + "=" * 60)
            print("Dictionary attack failed. Trying brute force...")
            print("=" * 60)
        
        print("\n⚠️  Brute force can take a VERY long time!")
        print("    Recommended: max length 4-5 for reasonable time")
        
        try:
            max_length = int(input("\nMax password length to try (1-6): ").strip() or "4")
            max_length = min(max_length, 6)  # Limit to 6
        except ValueError:
            max_length = 4
        
        print("\nCharacter sets:")
        print("  1. lowercase (a-z)")
        print("  2. lowercase + digits (a-z0-9)")
        print("  3. all (a-zA-Z0-9 + symbols)")
        
        charset_choice = input("\nSelect charset (1-3, default: 1): ").strip() or "1"
        
        charset_map = {
            '1': 'lowercase',
            '2': 'lowercase+digits',
            '3': 'all'
        }
        
        charset = charset_map.get(charset_choice, 'lowercase')
        
        result = cracker.brute_force_attack(max_length, charset)
        
        if result:
            print("\n✅ SUCCESS!")
        else:
            print("\n❌ Failed to crack hash")

def main():
    """Main function to run hash cracker."""
    if len(sys.argv) > 1:
        # Command line mode
        if sys.argv[1] == '--generate-examples':
            cracker = HashCracker('', 'md5')
            cracker.generate_hash_examples()
            return
        
        if len(sys.argv) < 3:
            print("Usage: python hash_cracker.py <hash> <hash_type>")
            print("       python hash_cracker.py --generate-examples")
            sys.exit(1)
        
        hash_input = sys.argv[1]
        hash_type = sys.argv[2].lower()
        
        cracker = HashCracker(hash_input, hash_type)
        cracker.dictionary_attack()
    else:
        # Interactive mode
        try:
            interactive_mode()
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted by user")
            sys.exit(0)

if __name__ == "__main__":
    main()
