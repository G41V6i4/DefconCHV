#!/usr/bin/env python3
"""
Admin password generator for DefCon CHV Manager

This script generates a secure password hash for the admin user.
The generated hash should be set as the ADMIN_PASSWORD_HASH environment variable.

Usage:
    python generate_admin_password.py
"""

import secrets
import string
from werkzeug.security import generate_password_hash
import sys

def generate_secure_password(length=16):
    """Generate a cryptographically secure password"""
    # Character set: uppercase, lowercase, digits, and safe special characters
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    
    # Ensure at least one character from each category
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase), 
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*")
    ]
    
    # Fill the rest randomly
    for _ in range(length - 4):
        password.append(secrets.choice(characters))
    
    # Shuffle to avoid predictable pattern
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def main():
    print("=== DefCon CHV Manager - Admin Password Generator ===\n")
    
    choice = input("Choose an option:\n1. Generate a random secure password\n2. Use your own password\nEnter choice (1 or 2): ").strip()
    
    if choice == "1":
        password = generate_secure_password()
        print(f"\n🔐 Generated secure password: {password}")
    elif choice == "2":
        password = input("\nEnter your password: ").strip()
        if len(password) < 8:
            print("❌ Password must be at least 8 characters long!")
            sys.exit(1)
    else:
        print("❌ Invalid choice!")
        sys.exit(1)
    
    # Generate hash
    password_hash = generate_password_hash(password)
    
    print(f"\n✅ Password hash generated successfully!")
    print(f"\n📋 Set this environment variable:")
    print(f"export ADMIN_PASSWORD_HASH='{password_hash}'")
    
    print(f"\n📋 Or add to your .env file:")
    print(f"ADMIN_PASSWORD_HASH={password_hash}")
    
    print(f"\n🔒 Security Notes:")
    print(f"• Store the password hash securely")
    print(f"• Never commit the password or hash to version control")
    print(f"• Use different passwords for different environments")
    print(f"• Change the password regularly")
    
    # Write to .env file option
    write_env = input(f"\nWrite to .env file? (y/N): ").strip().lower()
    if write_env == 'y':
        with open('.env', 'a') as f:
            f.write(f"\n# Admin password hash (generated {secrets.token_hex(8)})\n")
            f.write(f"ADMIN_PASSWORD_HASH={password_hash}\n")
        print("✅ Written to .env file")

if __name__ == "__main__":
    main()