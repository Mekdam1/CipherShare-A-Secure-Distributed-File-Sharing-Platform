import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import argon2

# Get desktop path in a cross-platform way
if os.name == 'nt':  # Windows
    DESKTOP_PATH = os.path.join(os.environ['USERPROFILE'], 'Desktop')
else:  # Mac and Linux
    DESKTOP_PATH = os.path.join(os.path.expanduser('~'), 'Desktop')

HASHED_USERS_FILE = os.path.join(DESKTOP_PATH, 'hashed_users.txt')
USER_DB_FILE = 'secure_users.json'

# Initialize Argon2 hasher
ph = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

def hash_password(password):
    """Hash password using Argon2"""
    return ph.hash(password)

def verify_password(username, password):
    """Verify password against stored hash"""
    users = load_users()
    if username not in users:
        return False
    
    stored_hash = users[username]
    try:
        return ph.verify(stored_hash, password)
    except (argon2.exceptions.VerifyMismatchError, 
            argon2.exceptions.InvalidHash):
        return False

def load_users():
    """Load existing users from JSON database"""
    if os.path.exists(USER_DB_FILE):
        try:
            with open(USER_DB_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_users(users):
    """Save users to JSON database"""
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def append_to_hashed_users(username, hashed_pw):
    """Append new user to the hashed_users.txt file on desktop"""
    try:
        with open(HASHED_USERS_FILE, 'a') as f:
            f.write(f"Username: {username}\n")
            f.write(f"Hashed Password: {hashed_pw}\n")
            f.write("-" * 50 + "\n")
        print(f"[*] User credentials saved to {HASHED_USERS_FILE}")
    except IOError as e:
        print(f"[-] Error writing to hashed users file: {str(e)}")

def signup():
    """Handle user signup process"""
    users = load_users()
    
    while True:
        username = input("Choose a username: ").strip()
        if not username:
            print("[-] Username cannot be empty.")
            continue
        
        if username in users:
            print("[-] Username already exists.")
            continue
        
        password = input("Choose a password: ").strip()
        if not password:
            print("[-] Password cannot be empty.")
            continue
        
        try:
            hashed_pw = hash_password(password)
            users[username] = hashed_pw
            save_users(users)
            append_to_hashed_users(username, hashed_pw)
            print("[+] Sign up successful!")
            return True
        except Exception as e:
            print(f"[-] Error during signup: {str(e)}")
            return False

def login(username, password):
    """Handle user login process"""
    return verify_password(username, password)

def get_derived_fernet(password: str) -> Fernet:
    """Derive encryption key from password"""
    salt = b'static_salt_for_demo'  # In production, use unique salt per user
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def display_hashed_users():
    """Display contents of the hashed_users.txt file"""
    if not os.path.exists(HASHED_USERS_FILE):
        print("No hashed users file found yet.")
        return
    
    try:
        with open(HASHED_USERS_FILE, 'r') as f:
            print("\nContents of hashed_users.txt:")
            print("-" * 60)
            print(f.read())
            print("-" * 60)
    except IOError as e:
        print(f"[-] Error reading hashed users file: {str(e)}")