import os
import pymongo
import pyotp
import b64
import secrets
from getpass import getpass
from password_checker import check_password_strength
import encrypt_aes256
import datetime

password_expiry_date = 30

# MongoDB Connection Setup
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["password_manager"]
users_collection = db["users"]
passwords_collection = db["passwords"]

AES_BLOCK_SIZE = 16

PASSWORD_EXPIRY_DAYS = 30  # Set password expiration time

def is_password_expired(user):
    last_updated = user.get("password_last_updated")

    if not last_updated:
        return True  
    
    # Convert the stored timestamp to a datetime object
    last_updated = datetime.datetime.strptime(last_updated, "%Y-%m-%d")

    return (datetime.datetime.now() - last_updated).days > PASSWORD_EXPIRY_DAYS

# Self-implemented PBKDF2 Function
def pbkdf2(password, salt, iterations=500000, key_len=32):
    password_bytes = password.encode("utf-8")
    key = bytearray(salt)
    
    for _ in range(iterations):
        new_key = bytearray(key_len)
        for i in range(key_len):
            new_key[i] = (password_bytes[i % len(password_bytes)] ^ key[i % len(key)]) & 0xFF
        key = new_key
    
    return bytes(key)


# AES Encryption
def encrypt_aes(plaintext, key):
    iv = os.urandom(16)  # Generate a random IV
    cipher = encrypt_aes256.new(key, encrypt_aes256.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES_BLOCK_SIZE))
    return b64.b64encode(iv + ciphertext).decode()


# AES Decryption
def decrypt_aes(encrypted, key):
    encrypted_bytes = b64.b64decode(encrypted)
    iv = encrypted_bytes[:16]  # Extract IV
    ciphertext = encrypted_bytes[16:]  # Extract ciphertext
    cipher = encrypt_aes256.new(key, encrypt_aes256.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)
    return decrypted.decode()


# User Registration
def register_user():
    username = input("Enter username: ").strip()
    
    if users_collection.find_one({"username": username}):
        print("\u274c Username already exists. Choose another.")
        return
    
    while True:
        password = getpass("Enter password: ").strip()
        is_valid, message = check_password_strength(username, password)
        
        if is_valid:
            break
        else:
            print(f"\u274c Weak password: {message}")
    
    # Generate random salt (16 bytes)
    salt = secrets.token_bytes(16)
    
    # Hash password using PBKDF2
    key = pbkdf2(password, salt)
    encrypted_password = encrypt_aes(password, key)
    
    # Generate OTP secret and encrypt it
    otp_secret = pyotp.random_base32()
    encrypted_otp = encrypt_aes(otp_secret, key)
    
    # Store user data in MongoDB
    users_collection.insert_one({
        "username": username,
        "password": encrypted_password,
        "salt": b64.b64encode(salt).decode("utf-8"),
        "otp_secret": encrypted_otp
    })
    
    print("✅ User registered successfully!")
    print(f"\U0001F511 Save this OTP secret for login: {otp_secret}")

# Function to view passwords
# Function to view passwords
def view_passwords(user, key):
    print("\nChoose an option to view passwords:")
    print("1) View all stored passwords")
    print("2) View password for a specific website")
    
    choice = input("Choose an option: ").strip()
    
    if choice == '1':
        passwords = passwords_collection.find({"username": user["username"]})
        
        # Check if there are any passwords for the user
        if passwords_collection.count_documents({"username": user["username"]}) > 0:
            print("\nStored passwords:\n")
            for password_entry in passwords:
                website_name = password_entry["website_name"]
                encrypted_username = password_entry["encrypted_username"]
                encrypted_password = password_entry["encrypted_password"]
                
                # Decrypt the website username and password
                decrypted_username = decrypt_aes(encrypted_username, key)
                decrypted_password = decrypt_aes(encrypted_password, key)
                
                print(f"Website: {website_name}")
                print(f"Username: {decrypted_username}")
                print(f"Password: {decrypted_password}\n")
        else:
            print("No stored passwords found.")
    
    elif choice == '2':
        website_name = input("Enter the website name: ").strip()
        
        password_entry = passwords_collection.find_one({"username": user["username"], "website_name": website_name})
        
        if password_entry:
            decrypted_username = decrypt_aes(password_entry["encrypted_username"], key)
            decrypted_password = decrypt_aes(password_entry["encrypted_password"], key)
            
            print(f"\nWebsite: {website_name}")
            print(f"Username: {decrypted_username}")
            print(f"Password: {decrypted_password}\n")
        else:
            print("No password found for the specified website.")
    else:
        print("Invalid option. Exiting.")


# Modified User Login function
def login_user():
    username = input("Enter username: ").strip()
    user = users_collection.find_one({"username": username})
    
    if not user:
        print(" Username does not exist.")
        return
    
    password = getpass("Enter password: ").strip()
    
    # Rehash the entered password and compare with stored hash
    salt = b64.b64decode(user["salt"])
    key = pbkdf2(password, salt)
    
    try:
        decrypted_password = decrypt_aes(user["password"], key)
    except:
        print(" Incorrect password.")
        return
    
    if password != decrypted_password:
        print("Incorrect password.")
        return
    
    # Decrypt OTP secret
    try:
        decrypted_otp = decrypt_aes(user["otp_secret"], key)
    except:
        print("OTP decryption failed. Possible data corruption.")
        return

    # Verify OTP
    totp = pyotp.TOTP(decrypted_otp)
    otp = input("Enter OTP: ").strip()
    
    if totp.verify(otp, valid_window=10):
        print(" Login successful!")
        store_website_password(user, key)  # Allow user to store website passwords
        view_passwords(user, key)  # Allow user to view stored passwords
    else:
        print(" Invalid OTP or OTP has expired. Please try again.")




# Function to store website credentials securely
# Function to store website credentials securely
def store_website_password(user, key):
    print("\nWelcome to the Secure Password Manager!")
    
    while True:
        website_name = input("Enter the website name: ").strip()
        website_username = input("Enter your username for the website: ").strip()
        
        while True:
            website_password = getpass("Enter your password for the website: ").strip()
            
            # Check the strength of the website password using the check_password_strength from password_checker.py
            is_valid, message = check_password_strength(website_username, website_password)
            
            if is_valid:
                break
            else:
                print(f"\u274c Weak password: {message}. Please enter a stronger password.")
        
        # Encrypt the website password and username
        encrypted_username = encrypt_aes(website_username, key)
        encrypted_password = encrypt_aes(website_password, key)
        
        # Store encrypted details in the database
        passwords_collection.insert_one({
            "username": user["username"],
            "website_name": website_name,
            "encrypted_username": encrypted_username,
            "encrypted_password": encrypted_password
        })
        
        print(f"✅ Password for {website_name} stored successfully!\n")
        
        # Ask if the user wants to store another password
        another = input("Do you want to store another password? (y/n): ").strip().lower()
        if another != 'y':
            break



# Main Menu
def main_menu():
    print("Welcome to the Password Manager!")
    print("1) Register a new user")
    print("2) Login")
    
    choice = input("Choose an option: ").strip()
    
    if choice == '1':
        register_user()
    elif choice == '2':
        login_user()
    else:
        print(" Invalid option. Exiting.")
        exit()


# Run the application
if __name__ == "__main__":
    main_menu()
