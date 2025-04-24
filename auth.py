import hashlib
import os

USERS_FILE = 'users.txt'
DEBUG_FILE = 'users_hashed_debug.txt'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def save_user(username, hashed_password):
    with open(USERS_FILE, 'a') as f:
        f.write(f"{username},{hashed_password}\n")

    with open(DEBUG_FILE, 'a') as debug:
        debug.write(f"{username} => {hashed_password}\n")

def user_exists(username):
    if not os.path.exists(USERS_FILE):
        return False
    with open(USERS_FILE, 'r') as f:
        for line in f:
            saved_user, _ = line.strip().split(',', 1)
            if username == saved_user:
                return True
    return False

def signup():
    username = input("Choose a username: ").strip()
    password = input("Choose a password: ").strip()

    if user_exists(username):
        print("[-] Username already exists.")
        return False

    hashed = hash_password(password)
    save_user(username, hashed)
    print("[+] Signup successful.")
    return True

def login():
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    hashed_input = hash_password(password)

    if not os.path.exists(USERS_FILE):
        print("[-] No users registered yet.")
        return False

    with open(USERS_FILE, 'r') as f:
        for line in f:
            saved_user, saved_hash = line.strip().split(',', 1)
            if username == saved_user and hashed_input == saved_hash:
                print("[+] Login successful.")
                return True

    print("[-] Invalid username or password.")
    return False
